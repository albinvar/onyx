//! Per-connection handler for the hub.
//!
//! Generic over the stream type — the tests use `tokio::io::duplex`
//! pairs to exercise the protocol without spinning Tor; the binary
//! passes in a `TorStream` from arti.

use std::sync::Arc;

use onyx_core::crypto::IdentitySecret;
use onyx_core::transport::{Session, handshake_responder, read_frame, write_frame};
use onyx_core::wire::{FRAME_DELIVER, FRAME_SUBSCRIBE, InnerFrame};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::state::{HubState, PER_CONN_MAILBOX, RoutingId};

/// Drive the hub side of one client connection. Runs Noise XK as
/// responder, then a `select!` loop that interleaves frames coming
/// from the client (SUBSCRIBE / DELIVER) and frames coming from the
/// hub state (live deliveries to write back to the client).
///
/// On exit (peer disconnect or fatal error), cleans up the
/// connection's subscriptions before returning.
pub async fn hub_handle_connection<S>(
    mut stream: S,
    hub_x25519: &IdentitySecret,
    state: Arc<Mutex<HubState>>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut session = handshake_responder(&mut stream, hub_x25519)
        .await
        .map_err(|e| anyhow::anyhow!("hub: noise handshake failed: {e}"))?;
    info!("hub: noise XK complete, awaiting frames");

    // Per-connection mailbox. The state pushes here when something
    // arrives for us; we drain in the select loop and write out.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(PER_CONN_MAILBOX);
    let conn_id = {
        let mut s = state.lock().await;
        s.register_conn(tx)
    };

    let result = serve_frames(&mut stream, &mut session, &state, conn_id, &mut rx).await;

    // Always clean up subscriptions on exit.
    {
        let mut s = state.lock().await;
        s.unregister_conn(conn_id);
    }
    info!(conn = conn_id, "hub: connection closed");

    result
}

async fn serve_frames<S>(
    stream: &mut S,
    session: &mut Session,
    state: &Arc<Mutex<HubState>>,
    conn_id: u64,
    rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            // Frame from the client.
            read_result = read_frame(stream, session) => {
                // Peer closed (or wire error mid-frame): treat as a
                // clean disconnect — the caller will unregister us.
                let Ok(frame) = read_result else { return Ok(()) };
                match frame.frame_type {
                    FRAME_SUBSCRIBE => {
                        let ids = parse_routing_ids(&frame.payload)?;
                        if ids.is_empty() {
                            warn!(conn = conn_id, "hub: empty SUBSCRIBE frame; ignoring");
                            continue;
                        }
                        let drained = {
                            let mut s = state.lock().await;
                            s.subscribe(conn_id, &ids)
                        };
                        info!(
                            conn = conn_id,
                            ids = ids.len(),
                            queued_drained = drained.len(),
                            "hub: client subscribed"
                        );
                        // Flush any queued payloads to the client right away.
                        for payload in drained {
                            write_frame(stream, session, &InnerFrame {
                                frame_type: FRAME_DELIVER,
                                payload,
                            }).await
                                .map_err(|e| anyhow::anyhow!("hub: write drained: {e}"))?;
                        }
                    }
                    FRAME_DELIVER => {
                        // The hub reads the 16-byte target prefix to decide
                        // *where* to route, but forwards the entire payload
                        // (prefix included) to subscribers so they can tell
                        // *which* of their subscriptions matched. The
                        // recipient strips the prefix before decrypting.
                        let target = parse_target_prefix(&frame.payload)?;
                        let delivered = {
                            let mut s = state.lock().await;
                            s.deliver(target, frame.payload)
                        };
                        info!(
                            conn = conn_id,
                            live_subscribers = delivered,
                            "hub: deliver routed"
                        );
                    }
                    other => {
                        warn!(
                            conn = conn_id,
                            frame_type = format!("{other:#06x}"),
                            "hub: ignoring unsupported frame type"
                        );
                    }
                }
            }
            // Live message from the state — write it out as DELIVER.
            Some(payload) = rx.recv() => {
                write_frame(stream, session, &InnerFrame {
                    frame_type: FRAME_DELIVER,
                    payload,
                }).await
                    .map_err(|e| anyhow::anyhow!("hub: write live: {e}"))?;
            }
        }
    }
}

/// SUBSCRIBE payload is concatenated 16-byte routing IDs.
fn parse_routing_ids(payload: &[u8]) -> anyhow::Result<Vec<RoutingId>> {
    // (Not `is_multiple_of` — that's only stable in Rust 1.87 and
    // our workspace MSRV is 1.85.)
    if payload.len() % 16 != 0 {
        anyhow::bail!(
            "hub: SUBSCRIBE payload length {} is not a multiple of 16",
            payload.len()
        );
    }
    Ok(payload
        .chunks_exact(16)
        .map(|chunk| {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(chunk);
            arr
        })
        .collect())
}

/// Peek the 16-byte target prefix from a DELIVER payload without
/// allocating a separate body buffer.
fn parse_target_prefix(payload: &[u8]) -> anyhow::Result<RoutingId> {
    if payload.len() < 16 {
        anyhow::bail!("hub: DELIVER payload too short for target prefix");
    }
    let mut target = [0u8; 16];
    target.copy_from_slice(&payload[..16]);
    Ok(target)
}

/// Test/recipient helper: split a forwarded DELIVER payload back into
/// `(target, body)`. Used by tests; recipients can also call this.
#[cfg(test)]
fn split_deliver_payload(payload: &[u8]) -> anyhow::Result<(RoutingId, Vec<u8>)> {
    let target = parse_target_prefix(payload)?;
    let body = payload[16..].to_vec();
    Ok((target, body))
}

// ── Integration tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use onyx_core::crypto::IdentitySecret;
    use onyx_core::transport::handshake_initiator;

    /// Spawn the hub side of one tokio::io::duplex pair, returning its
    /// JoinHandle.
    fn spawn_hub<S>(
        stream: S,
        hub_sk: IdentitySecret,
        state: Arc<Mutex<HubState>>,
    ) -> tokio::task::JoinHandle<anyhow::Result<()>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        tokio::spawn(async move { hub_handle_connection(stream, &hub_sk, state).await })
    }

    /// Alice subscribes; bob delivers; alice receives over the wire.
    #[allow(clippy::similar_names)]
    #[tokio::test]
    async fn subscribe_then_deliver_round_trip() {
        let hub_sk = IdentitySecret::generate();
        let hub_pk = hub_sk.public();
        let alice_sk = IdentitySecret::generate();
        let bob_sk = IdentitySecret::generate();

        let state = Arc::new(Mutex::new(HubState::new()));

        // Two duplex pairs: one for alice<->hub, one for bob<->hub.
        let (alice_client, alice_hub) = tokio::io::duplex(65_536);
        let (bob_client, bob_hub) = tokio::io::duplex(65_536);

        // Hub-side tasks.
        let _alice_hub_task = spawn_hub(alice_hub, hub_sk_clone(&hub_sk), state.clone());
        let _bob_hub_task = spawn_hub(bob_hub, hub_sk_clone(&hub_sk), state.clone());

        // Routing id alice will subscribe to.
        let alice_inbox: RoutingId = [0xA1; 16];

        // Alice: handshake + SUBSCRIBE + then read one DELIVER.
        let hub_pk_for_alice = hub_pk;
        let alice_task = tokio::spawn(async move {
            let mut stream = alice_client;
            let mut session = handshake_initiator(&mut stream, &alice_sk, &hub_pk_for_alice)
                .await
                .expect("alice handshake");
            write_frame(
                &mut stream,
                &mut session,
                &InnerFrame {
                    frame_type: FRAME_SUBSCRIBE,
                    payload: alice_inbox.to_vec(),
                },
            )
            .await
            .expect("alice subscribe");

            // Receive the DELIVER bob will send.
            let f = read_frame(&mut stream, &mut session)
                .await
                .expect("alice read");
            assert_eq!(f.frame_type, FRAME_DELIVER);
            f.payload
        });

        // Give alice's SUBSCRIBE a moment to land before bob delivers,
        // otherwise the deliver might land in the queue rather than
        // live-route. (Both work — the test exercises live-route.)
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Bob: handshake + DELIVER to alice's inbox.
        let hub_pk_for_bob = hub_pk;
        let bob_task = tokio::spawn(async move {
            let mut stream = bob_client;
            let mut session = handshake_initiator(&mut stream, &bob_sk, &hub_pk_for_bob)
                .await
                .expect("bob handshake");
            let mut payload = Vec::with_capacity(16 + 5);
            payload.extend_from_slice(&alice_inbox);
            payload.extend_from_slice(b"hello");
            write_frame(
                &mut stream,
                &mut session,
                &InnerFrame {
                    frame_type: FRAME_DELIVER,
                    payload,
                },
            )
            .await
            .expect("bob deliver");
        });

        bob_task.await.unwrap();
        let alice_payload = alice_task.await.unwrap();
        // Alice receives the body without the target prefix (the hub
        // strips it before forwarding — wait, currently the hub
        // forwards the WHOLE payload including target. That's a
        // design choice. Document with the assertion.)
        let (target_echo, body) = split_deliver_payload(&alice_payload).unwrap();
        assert_eq!(target_echo, alice_inbox);
        assert_eq!(body, b"hello");
    }

    /// Bob delivers before alice subscribes; alice subscribes and
    /// the queued message is flushed immediately.
    #[allow(clippy::similar_names)]
    #[tokio::test]
    async fn deliver_then_subscribe_drains_queue_over_wire() {
        let hub_sk = IdentitySecret::generate();
        let hub_pk = hub_sk.public();
        let alice_sk = IdentitySecret::generate();
        let bob_sk = IdentitySecret::generate();

        let state = Arc::new(Mutex::new(HubState::new()));

        let (alice_client, alice_hub) = tokio::io::duplex(65_536);
        let (bob_client, bob_hub) = tokio::io::duplex(65_536);

        let _alice_hub_task = spawn_hub(alice_hub, hub_sk_clone(&hub_sk), state.clone());
        let _bob_hub_task = spawn_hub(bob_hub, hub_sk_clone(&hub_sk), state.clone());

        let alice_inbox: RoutingId = [0xB2; 16];

        // Bob delivers first — goes to queue.
        let hub_pk_for_bob = hub_pk;
        let bob_task = tokio::spawn(async move {
            let mut stream = bob_client;
            let mut session = handshake_initiator(&mut stream, &bob_sk, &hub_pk_for_bob)
                .await
                .expect("bob handshake");
            let mut payload = Vec::new();
            payload.extend_from_slice(&alice_inbox);
            payload.extend_from_slice(b"queued msg");
            write_frame(
                &mut stream,
                &mut session,
                &InnerFrame {
                    frame_type: FRAME_DELIVER,
                    payload,
                },
            )
            .await
            .expect("bob deliver");
        });
        bob_task.await.unwrap();

        // Give the hub a moment to process bob's deliver and queue it.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(state.lock().await.queue_len(&alice_inbox), 1);

        // Alice subscribes after the fact — should get the queued message.
        let hub_pk_for_alice = hub_pk;
        let alice_task = tokio::spawn(async move {
            let mut stream = alice_client;
            let mut session = handshake_initiator(&mut stream, &alice_sk, &hub_pk_for_alice)
                .await
                .expect("alice handshake");
            write_frame(
                &mut stream,
                &mut session,
                &InnerFrame {
                    frame_type: FRAME_SUBSCRIBE,
                    payload: alice_inbox.to_vec(),
                },
            )
            .await
            .expect("alice subscribe");
            let f = read_frame(&mut stream, &mut session)
                .await
                .expect("alice read");
            assert_eq!(f.frame_type, FRAME_DELIVER);
            f.payload
        });

        let payload = alice_task.await.unwrap();
        let (target_echo, body) = split_deliver_payload(&payload).unwrap();
        assert_eq!(target_echo, alice_inbox);
        assert_eq!(body, b"queued msg");
        // Queue is now empty.
        assert_eq!(state.lock().await.queue_len(&alice_inbox), 0);
    }

    /// Helper: clone the hub's secret by serialising + deserialising
    /// (IdentitySecret deliberately doesn't impl Clone).
    fn hub_sk_clone(sk: &IdentitySecret) -> IdentitySecret {
        IdentitySecret::from_bytes(*sk.to_bytes())
    }
}
