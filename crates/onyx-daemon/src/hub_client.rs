//! Long-lived authenticated session from `onyxd` to an `onyx-hub`.
//!
//! Bidirectional as of T5.2.b: subscribes to our inbox, reads incoming
//! `FRAME_DELIVER` frames, and writes outbound `FRAME_DELIVER` frames
//! popped from an mpsc the caller supplies. The receive side hands
//! deliveries off via callback (still not wired into the conversation
//! registry — that comes in T5.2.c/d after the sealed-sender envelope
//! lands on the daemon path).
//!
//! ## Why a single shared session
//!
//! Each hub-client connection is one Tor circuit. We don't want to
//! pay circuit-build cost per delivery, so we keep a long-lived
//! session open. On disconnect the calling task reconnects with
//! backoff — that loop lives in `main.rs`, not here.
//!
//! ## Outbound queue ownership
//!
//! The caller (typically `main.rs`) constructs the mpsc and holds the
//! `Sender` side in `DaemonState` so the API server can push outbound
//! deliveries. We take the `Receiver` here and drain it inside the
//! `tokio::select!`. Bounded at [`OUTBOUND_QUEUE_CAPACITY`]; the API
//! server's `Send`-via-hub handler `try_send`s and surfaces backpressure
//! as `ApiErrorCode::NotReady`.

use anyhow::Context;
use onyx_core::crypto::{IdentityPublic, IdentitySecret};
use onyx_core::routing::RoutingId;
use onyx_core::tor::TorRuntime;
use onyx_core::transport::{Session, handshake_initiator, read_frame, write_frame};
use onyx_core::wire::{FRAME_DELIVER, FRAME_SUBSCRIBE, InnerFrame};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Bounded outbound-queue depth. Sized to absorb a brief burst (CLI
/// user typing fast / app reconnecting + flushing) without being so
/// large that a hung hub eats unbounded daemon memory.
pub const OUTBOUND_QUEUE_CAPACITY: usize = 64;

/// One outbound action the daemon wants the hub-client task to take.
///
/// Single channel for both deliveries and KP fetches keeps the
/// serialisation order well-defined: requests are processed in the
/// order they're pushed, which matters for `FRAME_KP_FETCH` —
/// `FRAME_KP_RESPONSE` has no request id, so we rely on FIFO ordering
/// to match a response to the right pending fetch.
#[derive(Debug)]
pub enum HubOutbound {
    /// Push a `FRAME_DELIVER` to the hub. Body is opaque to
    /// `hub_client` — typically a sealed-sender envelope.
    Deliver { target: RoutingId, body: Vec<u8> },
    /// Push a `FRAME_KP_FETCH` to the hub and route the matching
    /// `FRAME_KP_RESPONSE` back through `responder`. `Some(bytes)` on
    /// found, `None` on not-found, channel closed if the session
    /// ended before a response arrived.
    FetchKp {
        routing_id: RoutingId,
        responder: tokio::sync::oneshot::Sender<Option<Vec<u8>>>,
    },
    /// Push an additional `FRAME_SUBSCRIBE` (T6.3.g) so the hub starts
    /// routing the supplied routing ids to our connection without
    /// requiring a full reconnect. Used when a new room is created or
    /// joined and the per-epoch session token comes into scope, and
    /// when an existing room's epoch advances after a commit.
    /// Subscriptions are additive at the hub layer — see
    /// `onyx_hub::state::ConnState::subscribe`.
    Subscribe(Vec<RoutingId>),
    /// Push a `FRAME_PAD` cover-traffic frame to the hub (T-cover.2).
    /// The hub silently discards it. Sent at Poisson intervals by the
    /// cover-traffic task when `--cover-traffic-mean-secs` is set, to
    /// blunt the timing-correlation signal a hub-watching adversary
    /// gets from observing when alice publishes vs idles.
    Pad,
}

/// Backwards-compat helper so existing call sites that built a
/// "deliver this body" outbound don't need to change shape.
impl HubOutbound {
    #[must_use]
    pub fn deliver(target: RoutingId, body: Vec<u8>) -> Self {
        Self::Deliver { target, body }
    }
}

/// Run one hub session: dial → handshake → subscribe → bidirectional loop.
///
/// The loop `tokio::select!`s between:
///
///   * `read_frame` — inbound `FRAME_DELIVER` → `on_deliver(target, body)`.
///   * `outbound_rx.recv()` — outbound delivery → write `FRAME_DELIVER`
///     with payload `target ‖ body` to the hub.
///
/// Returns `Ok(())` on clean peer-closed disconnect **or** when the
/// outbound channel closes (caller dropped the sender — typically
/// daemon shutdown). Returns `Err(...)` on any setup failure (dial,
/// handshake, initial subscribe, write error mid-session). The
/// reconnect loop in `main.rs` treats `Err` as a cue to backoff + retry.
///
/// `on_deliver` is invoked for every inbound `FRAME_DELIVER`. Bodies
/// still carry the 16-byte target prefix (the hub preserves it so a
/// multi-subscribed client can demultiplex) — the callback receives
/// `(target, body_after_prefix)`.
/// One self-publication parcel: the routing id under which to file
/// our KP in the hub's directory + the KP bytes themselves. Built
/// by `main.rs` from `state.identity.fingerprint()` and a fresh
/// `MlsParty::key_package_bytes` call.
#[derive(Debug, Clone)]
pub struct SelfPublish {
    pub routing_id: RoutingId,
    pub kp_bytes: Vec<u8>,
}

// 9-arg signature is intentional: every parameter names a distinct
// piece of session context (Tor runtime, host, port, hub static key,
// our static key, subscriptions, outbound queue, deliver callback,
// optional self-publish). Bundling them into a struct would just
// trade one readable function for the same arguments rewritten as
// fields.
#[allow(clippy::too_many_arguments)]
pub async fn run_hub_session<F, Fut>(
    tor: &TorRuntime,
    host: &str,
    port: u16,
    hub_pubkey: &IdentityPublic,
    our_identity_sk: &IdentitySecret,
    subscribe_to: &[RoutingId],
    outbound_rx: &mut mpsc::Receiver<HubOutbound>,
    on_deliver: F,
    self_publish: Option<&SelfPublish>,
) -> anyhow::Result<()>
where
    F: FnMut(RoutingId, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    info!(
        host = %host,
        port = port,
        subscriptions = subscribe_to.len(),
        "hub: dialling"
    );
    let mut stream = tor
        .dial(host, port)
        .await
        .map_err(|e| anyhow::anyhow!("hub dial failed: {e}"))?;
    info!("hub: Tor circuit established, starting Noise XK handshake");

    let mut session = handshake_initiator(&mut stream, our_identity_sk, hub_pubkey)
        .await
        .map_err(|e| anyhow::anyhow!("hub Noise handshake failed: {e}"))?;
    info!("hub: Noise XK complete; sending SUBSCRIBE");

    write_subscribe(&mut stream, &mut session, subscribe_to)
        .await
        .map_err(|e| anyhow::anyhow!("hub SUBSCRIBE write failed: {e}"))?;
    info!("hub: subscription registered");

    if let Some(sp) = self_publish {
        write_kp_publish(&mut stream, &mut session, &sp.routing_id, &sp.kp_bytes)
            .await
            .map_err(|e| anyhow::anyhow!("hub KP_PUBLISH write failed: {e}"))?;
        info!(
            kp_bytes = sp.kp_bytes.len(),
            "hub: our KeyPackage published"
        );
    }

    info!("hub: entering bidirectional loop");
    serve_session(&mut stream, &mut session, outbound_rx, on_deliver).await
}

/// Write one `FRAME_KP_PUBLISH` carrying `routing_id ‖ kp_bytes`.
/// Split out so the test harness + future re-publish triggers can
/// call it without dragging in the full dial path.
async fn write_kp_publish<S>(
    stream: &mut S,
    session: &mut Session,
    routing_id: &RoutingId,
    kp_bytes: &[u8],
) -> onyx_core::error::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut payload = Vec::with_capacity(16 + kp_bytes.len());
    payload.extend_from_slice(routing_id);
    payload.extend_from_slice(kp_bytes);
    write_frame(
        stream,
        session,
        &InnerFrame {
            frame_type: onyx_core::wire::FRAME_KP_PUBLISH,
            payload,
        },
    )
    .await
}

/// T-cover.2: write a single `FRAME_PAD` cover-traffic frame.
/// Empty payload; the wire layer pads it to bucket::SMALL so it's
/// size-indistinguishable from a real small frame. Errors surface
/// as session-end (caller treats it as a reconnect cue) — silently
/// dropping a PAD would defeat the cadence the privacy property
/// relies on.
async fn write_cover_pad<S>(stream: &mut S, session: &mut Session) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    write_frame(
        stream,
        session,
        &InnerFrame {
            frame_type: onyx_core::wire::FRAME_PAD,
            payload: Vec::new(),
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("hub: PAD write failed: {e}"))?;
    tracing::trace!("hub: PAD sent");
    Ok(())
}

/// T6.3.g: thin wrapper around `write_subscribe` for the
/// mid-session incremental-subscribe path. Extracted so
/// `serve_session`'s match block stays under the clippy
/// `too_many_lines` budget. Empty `ids` is a no-op (defensive —
/// the caller in [`crate::announce_room_subscribe`] never sends
/// an empty list, but the hub-side handler rejects it too).
async fn write_incremental_subscribe<S>(
    stream: &mut S,
    session: &mut Session,
    ids: &[RoutingId],
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if ids.is_empty() {
        return Ok(());
    }
    let id_count = ids.len();
    write_subscribe(stream, session, ids)
        .await
        .map_err(|e| anyhow::anyhow!("hub: incremental SUBSCRIBE write failed: {e}"))?;
    debug!(
        id_count,
        "hub: incremental SUBSCRIBE sent (T6.3.g room session-token)"
    );
    Ok(())
}

/// Write one `FRAME_SUBSCRIBE` carrying the concatenated routing ids.
/// Split out so the test harness can call it without dragging in
/// the full dial path.
async fn write_subscribe<S>(
    stream: &mut S,
    session: &mut Session,
    subscribe_to: &[RoutingId],
) -> onyx_core::error::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut payload = Vec::with_capacity(subscribe_to.len() * 16);
    for id in subscribe_to {
        payload.extend_from_slice(id);
    }
    write_frame(
        stream,
        session,
        &InnerFrame {
            frame_type: FRAME_SUBSCRIBE,
            payload,
        },
    )
    .await
}

/// Bidirectional post-handshake loop. Generic over the stream type
/// so the integration test can drive it via `tokio::io::duplex`
/// without requiring a Tor circuit.
///
/// FIFO ordering invariant: `FRAME_KP_RESPONSE` carries no request
/// id, so the loop pairs the *Nth* response received with the *Nth*
/// `FetchKp` we sent. Concurrent `FetchKp`s from multiple API tasks
/// are serialised at the API-handler level (see
/// `handle_fetch_peer_keypackage` in `api_server.rs`) so this loop
/// only ever has at most one outstanding fetch.
async fn serve_session<S, F, Fut>(
    stream: &mut S,
    session: &mut Session,
    outbound_rx: &mut mpsc::Receiver<HubOutbound>,
    mut on_deliver: F,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(RoutingId, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    // Queue of pending KP-fetch oneshots, FIFO. Bounded only by the
    // higher-level serialisation in handle_fetch_peer_keypackage —
    // see this function's doc-comment.
    let mut pending_fetches: std::collections::VecDeque<
        tokio::sync::oneshot::Sender<Option<Vec<u8>>>,
    > = std::collections::VecDeque::new();

    loop {
        tokio::select! {
            // Inbound frame from the hub.
            read_res = read_frame(stream, session) => {
                let frame = match read_res {
                    Ok(f) => f,
                    Err(e) => {
                        info!(error = %e, "hub: receive ended (peer closed?)");
                        // Any still-pending fetches will get None on
                        // channel close — drop the senders here.
                        drop(pending_fetches);
                        return Ok(());
                    }
                };
                match frame.frame_type {
                    FRAME_DELIVER => {
                        if frame.payload.len() < 16 {
                            warn!(
                                payload_len = frame.payload.len(),
                                "hub: DELIVER payload too short to carry a routing-id prefix; ignoring"
                            );
                            continue;
                        }
                        let mut target = [0u8; 16];
                        target.copy_from_slice(&frame.payload[..16]);
                        let body = frame.payload[16..].to_vec();
                        on_deliver(target, body).await;
                    }
                    onyx_core::wire::FRAME_KP_RESPONSE => {
                        // Payload: 1-byte status (0=found, 1=not-found)
                        // ‖ optional KP bytes. Resolve the head of the
                        // FIFO queue.
                        let Some(responder) = pending_fetches.pop_front() else {
                            warn!("hub: KP_RESPONSE arrived but no pending fetch; dropping");
                            continue;
                        };
                        let answer = if frame.payload.is_empty() {
                            None
                        } else if frame.payload[0] == 0 {
                            Some(frame.payload[1..].to_vec())
                        } else {
                            None
                        };
                        // Receiver may have given up if its handler
                        // task was cancelled; that's fine.
                        let _ = responder.send(answer);
                    }
                    other => {
                        warn!(
                            frame_type = format!("{other:#06x}"),
                            "hub: unexpected frame type from hub"
                        );
                    }
                }
            }
            // Outbound action from the daemon.
            Some(outbound) = outbound_rx.recv() => {
                match outbound {
                    HubOutbound::Deliver { target, body } => {
                        let mut wire_payload = Vec::with_capacity(16 + body.len());
                        wire_payload.extend_from_slice(&target);
                        wire_payload.extend_from_slice(&body);
                        if let Err(e) = write_frame(
                            stream,
                            session,
                            &InnerFrame {
                                frame_type: FRAME_DELIVER,
                                payload: wire_payload,
                            },
                        ).await {
                            return Err(anyhow::anyhow!("hub: outbound DELIVER write failed: {e}"));
                        }
                        debug!(body_bytes = body.len(), "hub: outbound DELIVER sent");
                    }
                    HubOutbound::FetchKp { routing_id, responder } => {
                        // Push the oneshot onto the FIFO BEFORE we
                        // write the frame, so a fast response can't
                        // race ahead and find an empty queue.
                        pending_fetches.push_back(responder);
                        if let Err(e) = write_frame(
                            stream,
                            session,
                            &InnerFrame {
                                frame_type: onyx_core::wire::FRAME_KP_FETCH,
                                payload: routing_id.to_vec(),
                            },
                        ).await {
                            return Err(anyhow::anyhow!("hub: outbound KP_FETCH write failed: {e}"));
                        }
                        debug!("hub: outbound KP_FETCH sent");
                    }
                    HubOutbound::Subscribe(ids) => {
                        write_incremental_subscribe(stream, session, &ids).await?;
                    }
                    HubOutbound::Pad => write_cover_pad(stream, session).await?,
                }
            }
            // Outbound channel closed → daemon shutting down.
            else => {
                info!("hub: outbound channel closed; ending session");
                return Ok(());
            }
        }
    }
}

/// Parse `host:port` or just `host` (defaults to `default_port`).
/// Used by the CLI flag and exposed here for unit tests.
pub fn parse_host_port(s: &str, default_port: u16) -> anyhow::Result<(String, u16)> {
    match s.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().with_context(|| format!("bad port in {s:?}"))?;
            Ok((h.to_string(), port))
        }
        None => Ok((s.to_string(), default_port)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_port_with_explicit_port() {
        let (h, p) = parse_host_port("abc.onion:42", 99).unwrap();
        assert_eq!(h, "abc.onion");
        assert_eq!(p, 42);
    }

    #[test]
    fn parse_host_port_uses_default_when_missing() {
        let (h, p) = parse_host_port("abc.onion", 1).unwrap();
        assert_eq!(h, "abc.onion");
        assert_eq!(p, 1);
    }

    #[test]
    fn parse_host_port_rejects_garbage_port() {
        assert!(parse_host_port("abc.onion:notnum", 1).is_err());
    }

    /// End-to-end behavioural test of the bidirectional loop.
    ///
    /// Spawns a fake "hub-side" task on one end of a `tokio::io::duplex`
    /// pair: it runs the Noise XK responder, reads our SUBSCRIBE,
    /// pushes one inbound DELIVER, then reads our outbound DELIVER and
    /// asserts the wire payload.
    ///
    /// We run `write_subscribe` + `serve_session` on the client end
    /// and validate that (a) inbound deliveries reach the callback and
    /// (b) outbound deliveries pushed into the mpsc reach the wire.
    #[tokio::test]
    #[allow(clippy::similar_names)] // hub_sk / client_sk + hub_side / client_side are intentional
    async fn bidirectional_session_round_trip_over_duplex() {
        use onyx_core::transport::{handshake_responder, write_frame};

        let hub_sk = IdentitySecret::generate();
        let hub_pk = hub_sk.public();
        let client_sk = IdentitySecret::generate();

        let (client_side, hub_side) = tokio::io::duplex(65_536);

        // Routing ids used in the test.
        let our_inbox: RoutingId = [0xC1; 16];
        let peer_target: RoutingId = [0xD2; 16];
        let inbound_body = b"sealed-envelope-bytes-incoming".to_vec();
        let outbound_body = b"sealed-envelope-bytes-outgoing".to_vec();

        // Hub-side task: respond to handshake, read SUBSCRIBE, push
        // an inbound DELIVER, then read the client's outbound DELIVER.
        let hub_inbound_body = inbound_body.clone();
        let hub_outbound_body = outbound_body.clone();
        let hub_task = tokio::spawn(async move {
            let mut stream = hub_side;
            let mut session = handshake_responder(&mut stream, &hub_sk)
                .await
                .expect("hub-side handshake");

            // Read SUBSCRIBE.
            let sub = read_frame(&mut stream, &mut session)
                .await
                .expect("read sub");
            assert_eq!(sub.frame_type, FRAME_SUBSCRIBE);
            assert_eq!(sub.payload, our_inbox.to_vec());

            // Push an inbound DELIVER to the client.
            let mut deliver_payload = Vec::new();
            deliver_payload.extend_from_slice(&our_inbox);
            deliver_payload.extend_from_slice(&hub_inbound_body);
            write_frame(
                &mut stream,
                &mut session,
                &InnerFrame {
                    frame_type: FRAME_DELIVER,
                    payload: deliver_payload,
                },
            )
            .await
            .expect("hub-side write deliver");

            // Read the client's outbound DELIVER.
            let out = read_frame(&mut stream, &mut session)
                .await
                .expect("read outbound");
            assert_eq!(out.frame_type, FRAME_DELIVER);
            assert_eq!(&out.payload[..16], peer_target.as_slice());
            assert_eq!(&out.payload[16..], hub_outbound_body.as_slice());
        });

        // Client-side: handshake, SUBSCRIBE, then run serve_session.
        let mut client_stream = client_side;
        let mut client_session =
            onyx_core::transport::handshake_initiator(&mut client_stream, &client_sk, &hub_pk)
                .await
                .expect("client handshake");
        write_subscribe(&mut client_stream, &mut client_session, &[our_inbox])
            .await
            .expect("client write subscribe");

        // Outbound channel pre-populated with one delivery; the
        // session loop will pick it up after handling the inbound one.
        let (out_tx, mut out_rx) = mpsc::channel::<HubOutbound>(8);
        out_tx
            .send(HubOutbound::deliver(peer_target, outbound_body.clone()))
            .await
            .expect("queue outbound");

        // Track what the on_deliver callback observes.
        let observed =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::<(RoutingId, Vec<u8>)>::new()));
        let observed_clone = observed.clone();

        // Run the session for a bounded time; close the outbound
        // channel from outside to force the loop to exit cleanly.
        let drop_signal = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            drop(out_tx);
        });

        let session_result = serve_session(
            &mut client_stream,
            &mut client_session,
            &mut out_rx,
            move |target, body| {
                let observed = observed_clone.clone();
                async move {
                    observed.lock().unwrap().push((target, body));
                }
            },
        )
        .await;
        drop_signal.await.unwrap();
        hub_task.await.unwrap();

        assert!(
            session_result.is_ok(),
            "serve_session returned: {session_result:?}"
        );
        let observed = observed.lock().unwrap();
        assert_eq!(observed.len(), 1, "expected exactly one inbound delivery");
        assert_eq!(observed[0].0, our_inbox);
        // Hub preserves the target prefix per wire spec — observed body
        // starts after the 16-byte prefix.
        assert_eq!(observed[0].1, inbound_body);
    }
}
