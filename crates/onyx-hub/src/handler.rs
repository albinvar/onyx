//! Per-connection handler for the hub.
//!
//! Generic over the stream type — the tests use `tokio::io::duplex`
//! pairs to exercise the protocol without spinning Tor; the binary
//! passes in a `TorStream` from arti.

use std::sync::Arc;

use onyx_core::crypto::IdentitySecret;
use onyx_core::transport::{Session, handshake_responder, read_frame, write_frame};
use onyx_core::wire::{
    FRAME_DELIVER, FRAME_KP_FETCH, FRAME_KP_PUBLISH, FRAME_KP_RESPONSE, FRAME_SUBSCRIBE, InnerFrame,
};
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

// `serve_frames` is one linear `select!`-loop dispatcher; the body is
// long because each branch handles a complete protocol verb inline.
// Splitting per-verb helpers would just rename code into call sites
// without making the dispatch easier to follow.
#[allow(clippy::too_many_lines)]
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
                    FRAME_KP_PUBLISH => {
                        // Store-and-forget. Latest-wins. Hub does NOT
                        // verify the publisher owns the routing id; the
                        // recipient must verify the KP's embedded
                        // signing key against the expected fingerprint
                        // before trusting (`SECURITY.md` carry-forward).
                        //
                        // What routing id to store under? For T6.1 the
                        // convention is: the publisher's introduction-
                        // inbox routing id. The hub doesn't know that
                        // mapping (it'd need the publisher's signing
                        // key, which Noise XK doesn't surface). So the
                        // publisher embeds it implicitly: the KP at
                        // `inbox_id` is the KP for the holder of the
                        // fingerprint that derives `inbox_id`. To make
                        // this concrete and testable, the protocol
                        // requires the publish payload to be prefixed
                        // with the 16-byte routing id, followed by the
                        // KP bytes — same shape as DELIVER.
                        if frame.payload.len() < 16 {
                            warn!(
                                conn = conn_id,
                                payload_len = frame.payload.len(),
                                "hub: KP_PUBLISH payload missing routing-id prefix; ignoring"
                            );
                            continue;
                        }
                        let routing_id = parse_target_prefix(&frame.payload)?;
                        let kp_bytes = frame.payload[16..].to_vec();
                        let kp_len = kp_bytes.len();
                        let dir_size = {
                            let mut s = state.lock().await;
                            s.publish_keypackage(routing_id, kp_bytes);
                            s.keypackage_count()
                        };
                        info!(
                            conn = conn_id,
                            kp_bytes = kp_len,
                            directory_size = dir_size,
                            "hub: KeyPackage published"
                        );
                    }
                    FRAME_KP_FETCH => {
                        // Payload = exactly 16 bytes routing id. Respond
                        // with FRAME_KP_RESPONSE: status (1 B) + body.
                        if frame.payload.len() != 16 {
                            warn!(
                                conn = conn_id,
                                payload_len = frame.payload.len(),
                                "hub: KP_FETCH payload must be exactly 16 bytes; ignoring"
                            );
                            continue;
                        }
                        let mut routing_id = [0u8; 16];
                        routing_id.copy_from_slice(&frame.payload);
                        let kp_opt = state.lock().await.fetch_keypackage(&routing_id);
                        let found = kp_opt.is_some();
                        let response_payload = match kp_opt {
                            Some(kp_bytes) => {
                                let mut out = Vec::with_capacity(1 + kp_bytes.len());
                                out.push(0u8); // status: found
                                out.extend_from_slice(&kp_bytes);
                                out
                            }
                            None => vec![1u8], // status: not-found, no body
                        };
                        write_frame(stream, session, &InnerFrame {
                            frame_type: FRAME_KP_RESPONSE,
                            payload: response_payload,
                        }).await
                            .map_err(|e| anyhow::anyhow!("hub: write KP_RESPONSE: {e}"))?;
                        info!(
                            conn = conn_id,
                            found,
                            "hub: KP_FETCH answered"
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

    /// T6.1: publish + fetch round-trip over the wire.
    #[allow(clippy::similar_names)]
    #[tokio::test]
    async fn keypackage_publish_then_fetch_round_trip() {
        use onyx_core::transport::handshake_initiator;

        let hub_sk = IdentitySecret::generate();
        let hub_pk = hub_sk.public();
        let alice_sk = IdentitySecret::generate();
        let bob_sk = IdentitySecret::generate();

        let state = Arc::new(Mutex::new(HubState::new()));

        let (alice_client, alice_hub) = tokio::io::duplex(65_536);
        let (bob_client, bob_hub) = tokio::io::duplex(65_536);

        let _alice_hub_task = spawn_hub(alice_hub, hub_sk_clone(&hub_sk), state.clone());
        let _bob_hub_task = spawn_hub(bob_hub, hub_sk_clone(&hub_sk), state.clone());

        // The directory key alice publishes under.
        let alice_kp_id: RoutingId = [0xE1; 16];
        let alice_kp_bytes = b"opaque-mls-keypackage-bytes-from-alice".to_vec();

        // Alice publishes her KP.
        let hub_pk_for_alice = hub_pk;
        let alice_kp_bytes_clone = alice_kp_bytes.clone();
        let alice_task = tokio::spawn(async move {
            let mut stream = alice_client;
            let mut session = handshake_initiator(&mut stream, &alice_sk, &hub_pk_for_alice)
                .await
                .expect("alice handshake");
            // Payload layout per T6.1 wire spec:
            // 16-byte routing id ‖ KP bytes.
            let mut payload = Vec::with_capacity(16 + alice_kp_bytes_clone.len());
            payload.extend_from_slice(&alice_kp_id);
            payload.extend_from_slice(&alice_kp_bytes_clone);
            write_frame(
                &mut stream,
                &mut session,
                &InnerFrame {
                    frame_type: FRAME_KP_PUBLISH,
                    payload,
                },
            )
            .await
            .expect("alice KP publish");
            // Hold the stream open briefly so the hub processes the
            // publish before bob's fetch races against it. (Without
            // some ordering signal the two tasks could interleave —
            // fine for protocol correctness, awkward for the test.)
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });
        alice_task.await.unwrap();

        // Bob fetches and verifies he gets back exactly what alice published.
        let hub_pk_for_bob = hub_pk;
        let bob_task = tokio::spawn(async move {
            let mut stream = bob_client;
            let mut session = handshake_initiator(&mut stream, &bob_sk, &hub_pk_for_bob)
                .await
                .expect("bob handshake");
            write_frame(
                &mut stream,
                &mut session,
                &InnerFrame {
                    frame_type: FRAME_KP_FETCH,
                    payload: alice_kp_id.to_vec(),
                },
            )
            .await
            .expect("bob KP fetch");

            let resp = read_frame(&mut stream, &mut session)
                .await
                .expect("bob read");
            assert_eq!(resp.frame_type, FRAME_KP_RESPONSE);
            // Payload: 1-byte status + KP bytes.
            assert!(
                !resp.payload.is_empty(),
                "response must include status byte"
            );
            assert_eq!(resp.payload[0], 0, "status 0 = found");
            assert_eq!(&resp.payload[1..], alice_kp_bytes.as_slice());
        });
        bob_task.await.unwrap();

        // Hub state side-channel: directory has exactly one entry.
        assert_eq!(state.lock().await.keypackage_count(), 1);
    }

    /// T6.1: fetch with no prior publish returns status=not-found.
    #[allow(clippy::similar_names)]
    #[tokio::test]
    async fn keypackage_fetch_missing_returns_not_found() {
        use onyx_core::transport::handshake_initiator;

        let hub_sk = IdentitySecret::generate();
        let hub_pk = hub_sk.public();
        let alice_sk = IdentitySecret::generate();

        let state = Arc::new(Mutex::new(HubState::new()));
        let (alice_client, alice_hub) = tokio::io::duplex(65_536);
        let _alice_hub_task = spawn_hub(alice_hub, hub_sk_clone(&hub_sk), state.clone());

        let missing_id: RoutingId = [0xE2; 16];

        let mut stream = alice_client;
        let mut session = handshake_initiator(&mut stream, &alice_sk, &hub_pk)
            .await
            .expect("alice handshake");
        write_frame(
            &mut stream,
            &mut session,
            &InnerFrame {
                frame_type: FRAME_KP_FETCH,
                payload: missing_id.to_vec(),
            },
        )
        .await
        .expect("write fetch");

        let resp = read_frame(&mut stream, &mut session).await.expect("read");
        assert_eq!(resp.frame_type, FRAME_KP_RESPONSE);
        assert_eq!(resp.payload.len(), 1, "not-found has no body");
        assert_eq!(resp.payload[0], 1, "status 1 = not-found");
    }

    /// T6.1: latest-wins on republish.
    #[allow(clippy::similar_names)]
    #[tokio::test]
    async fn keypackage_republish_overwrites() {
        use onyx_core::transport::handshake_initiator;

        let hub_sk = IdentitySecret::generate();
        let hub_pk = hub_sk.public();
        let alice_sk = IdentitySecret::generate();
        let bob_sk = IdentitySecret::generate();

        let state = Arc::new(Mutex::new(HubState::new()));
        let (alice_client, alice_hub) = tokio::io::duplex(65_536);
        let (bob_client, bob_hub) = tokio::io::duplex(65_536);
        let _alice_hub_task = spawn_hub(alice_hub, hub_sk_clone(&hub_sk), state.clone());
        let _bob_hub_task = spawn_hub(bob_hub, hub_sk_clone(&hub_sk), state.clone());

        let id: RoutingId = [0xE3; 16];

        // Alice publishes twice; the second publish must replace, not append.
        let hub_pk_for_alice = hub_pk;
        let alice_task = tokio::spawn(async move {
            let mut stream = alice_client;
            let mut session = handshake_initiator(&mut stream, &alice_sk, &hub_pk_for_alice)
                .await
                .expect("alice handshake");
            for (label, body) in [("v1", b"kp-v1".as_slice()), ("v2", b"kp-v2".as_slice())] {
                let mut payload = Vec::with_capacity(16 + body.len());
                payload.extend_from_slice(&id);
                payload.extend_from_slice(body);
                write_frame(
                    &mut stream,
                    &mut session,
                    &InnerFrame {
                        frame_type: FRAME_KP_PUBLISH,
                        payload,
                    },
                )
                .await
                .unwrap_or_else(|e| panic!("publish {label}: {e}"));
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });
        alice_task.await.unwrap();

        // Bob fetches; must get v2 only.
        let hub_pk_for_bob = hub_pk;
        let bob_task = tokio::spawn(async move {
            let mut stream = bob_client;
            let mut session = handshake_initiator(&mut stream, &bob_sk, &hub_pk_for_bob)
                .await
                .expect("bob handshake");
            write_frame(
                &mut stream,
                &mut session,
                &InnerFrame {
                    frame_type: FRAME_KP_FETCH,
                    payload: id.to_vec(),
                },
            )
            .await
            .expect("bob fetch");
            let resp = read_frame(&mut stream, &mut session).await.expect("read");
            assert_eq!(resp.payload[0], 0, "found");
            assert_eq!(&resp.payload[1..], b"kp-v2");
        });
        bob_task.await.unwrap();
    }
}
