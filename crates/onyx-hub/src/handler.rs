//! Per-connection handler for the hub.
//!
//! Generic over the stream type — the tests use `tokio::io::duplex`
//! pairs to exercise the protocol without spinning Tor; the binary
//! passes in a `TorStream` from arti.

use std::sync::Arc;

use onyx_core::crypto::IdentitySecret;
use onyx_core::transport::{Session, handshake_responder, read_frame, write_frame};
use onyx_core::wire::{
    FRAME_DELIVER, FRAME_GOSSIP_DELIVER, FRAME_GOSSIP_PUBLISH, FRAME_KP_FETCH, FRAME_KP_PUBLISH,
    FRAME_KP_RESPONSE, FRAME_PAD, FRAME_SUBSCRIBE, GossipFrame, InnerFrame,
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
// `pub` for the lib consumers (the smoke harness uses this in
// `crates/onyx-hub/tests/rooms_smoke.rs`). The bin's own `mod
// handler` doesn't call it (main.rs uses the _with_cover variant
// to thread the operator's `--cover-traffic-mean-secs` through),
// so the bin compilation's dead-code lint fires. `#[allow]` it
// because the function IS used — just not from this specific
// module tree.
#[allow(dead_code)]
pub async fn hub_handle_connection<S>(
    stream: S,
    hub_x25519: &IdentitySecret,
    state: Arc<Mutex<HubState>>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    hub_handle_connection_with_cover(stream, hub_x25519, state, None).await
}

/// T-cover.hub: same as [`hub_handle_connection`] but with an
/// explicit cover-traffic mean. When `Some(secs)`, the hub injects
/// `FRAME_PAD` frames on this connection at exponentially-
/// distributed intervals (Poisson process, mean = `secs`). When
/// `None`, no cover traffic is emitted on this connection (the v0
/// default for hubs that don't opt in).
///
/// The existing [`hub_handle_connection`] wrapper passes `None` so
/// existing callers (e.g. tests) get byte-identical behaviour.
/// `onyx-hub/src/main.rs`'s production accept loop reads the
/// operator's `--cover-traffic-mean-secs` flag and threads it in.
pub async fn hub_handle_connection_with_cover<S>(
    mut stream: S,
    hub_x25519: &IdentitySecret,
    state: Arc<Mutex<HubState>>,
    cover_traffic_mean_secs: Option<u64>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut session = handshake_responder(&mut stream, hub_x25519)
        .await
        .map_err(|e| anyhow::anyhow!("hub: noise handshake failed: {e}"))?;

    // T8.3.b.4: role detection. After Noise XK, the authenticated
    // peer_static_key tells us whether this is a peer hub (in our
    // operator's `--peer-hub` allowlist) or a client. Peer-hub
    // sessions get a separate frame loop that only handles gossip
    // frames; client sessions get the existing handler. We do NOT
    // register peer-hub sessions in the client `senders` registry
    // (peer hubs don't subscribe to routing-ids; the connection-id
    // bookkeeping would just leak entries).
    let peer_pk = session.peer_static_key();
    let role_is_peer_hub = state.lock().await.is_peer_hub(&peer_pk);

    if role_is_peer_hub {
        info!(
            peer_pk_prefix = format!(
                "{:02x}{:02x}{:02x}{:02x}",
                peer_pk[0], peer_pk[1], peer_pk[2], peer_pk[3]
            ),
            "hub: noise XK complete; inbound peer-hub session"
        );
        let result = serve_peer_frames(&mut stream, &mut session, &state, &peer_pk).await;
        info!("hub: peer-hub session closed");
        return result;
    }

    info!("hub: noise XK complete; inbound client session");
    // Per-connection mailbox. The state pushes here when something
    // arrives for us; we drain in the select loop and write out.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(PER_CONN_MAILBOX);
    let conn_id = {
        let mut s = state.lock().await;
        s.register_conn(tx)
    };

    let result = serve_frames(
        &mut stream,
        &mut session,
        &state,
        conn_id,
        &peer_pk,
        &mut rx,
        cover_traffic_mean_secs,
    )
    .await;

    // Always clean up subscriptions on exit. The rate-limit bucket is
    // keyed on the identity (peer_pk), not the connection, and is only
    // dropped here if it has refilled to full — a throttled bucket
    // survives so a reconnect can't reset the budget (HIGH-3).
    {
        let mut s = state.lock().await;
        s.unregister_conn(conn_id);
        s.forget_rate_if_full(&peer_pk);
    }
    info!(conn = conn_id, "hub: connection closed");

    result
}

/// Frame loop for peer-hub inbound sessions (T8.3.b.4). Only
/// handles `FRAME_GOSSIP_PUBLISH` (and `FRAME_GOSSIP_DELIVER` once
/// T8.3.c lands). Any other frame type from a peer hub is a
/// protocol error from our perspective; we log a warning and drop
/// the frame, but keep the session open so the peer can recover
/// (a slightly-misconfigured peer is more useful alive than killed).
///
/// `source_pubkey` is the peer's authenticated Noise pubkey, used
/// to skip the re-fanout target so a forwarded frame never goes
/// straight back to its sender.
async fn serve_peer_frames<S>(
    stream: &mut S,
    session: &mut Session,
    state: &Arc<Mutex<HubState>>,
    source_pubkey: &[u8; 32],
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let read_result = read_frame(stream, session).await;
        let Ok(frame) = read_result else {
            // Peer disconnected (or wire error). Clean exit.
            return Ok(());
        };
        match frame.frame_type {
            FRAME_GOSSIP_PUBLISH => {
                handle_gossip_publish(&frame.payload, state, source_pubkey).await;
            }
            FRAME_GOSSIP_DELIVER => {
                handle_gossip_deliver(&frame.payload, state, source_pubkey).await;
            }
            other => {
                warn!(
                    frame_type = format!("{other:#x}"),
                    "hub: peer-hub session received unexpected frame type; dropping (keeping session open)"
                );
            }
        }
    }
}

/// Process one inbound `FRAME_GOSSIP_PUBLISH` from a peer hub
/// (T8.3.b.4). Drops on loop detection, drops on T7.3-sec
/// ownership-check failure, stores locally on success, and
/// re-fans-out to OTHER peer hubs with decremented TTL.
async fn handle_gossip_publish(
    payload: &[u8],
    state: &Arc<Mutex<HubState>>,
    source_pubkey: &[u8; 32],
) {
    // Decode the gossip header + body. Malformed → drop silently
    // (same posture as other malformed-frame handling).
    let Ok(frame) = GossipFrame::decode(payload) else {
        warn!("hub: peer-hub gossip frame did not decode; dropping");
        return;
    };

    // Loop check. If the sender claims a `seen_by` that equals our
    // own hub hash, this frame has already traversed us — dropping
    // is the correct behaviour (avoids amplification storms).
    {
        let s = state.lock().await;
        if frame.seen_by == s.self_hub_hash_for_test() {
            tracing::debug!("hub: gossip loop detected (seen_by == our hash); dropping");
            return;
        }
    }

    // Per T7.3-sec: the KP's embedded Ed25519 signing key MUST
    // derive the claimed routing id. Same ownership check we apply
    // to direct client KP_PUBLISH. A peer hub that gossips a KP it
    // shouldn't own gets silently rejected here.
    let signing_pk = match onyx_core::mls::signing_key_from_kp_bytes(&frame.body) {
        Ok(pk) => pk,
        Err(e) => {
            warn!(
                error = %e,
                "hub: gossip KP did not validate as a well-formed MLS KeyPackage; dropping"
            );
            return;
        }
    };
    let fingerprint = onyx_core::crypto::Fingerprint::from_bytes(signing_pk);
    let expected_routing = onyx_core::routing::introduction_inbox(&fingerprint);
    if expected_routing != frame.routing_id {
        warn!(
            "hub: gossip KP signing key does not derive the claimed routing id \
             (ownership check failed); dropping"
        );
        return;
    }

    // Store locally + log directory size.
    let dir_size = {
        let mut s = state.lock().await;
        s.publish_keypackage(frame.routing_id, frame.body.clone());
        s.keypackage_count()
    };
    info!(
        directory_size = dir_size,
        kp_bytes = frame.body.len(),
        "hub: gossiped KeyPackage accepted (ownership verified)"
    );

    // Forward to other peers (TTL decrement + seen_by rewrite via
    // GossipFrame::forward). Skip the source peer to avoid bouncing.
    if let Some(fwd) = frame.forward([0u8; 16]) {
        // We re-encode via fan_out_kp_to_peers_except so the
        // outgoing seen_by gets set to OUR hash (the dummy [0;16]
        // we passed to forward() above is overwritten — we only
        // used forward() for the TTL-decrement logic).
        let _ = fwd; // suppress unused: we only needed the TTL check
        let s = state.lock().await;
        let new_ttl = frame.ttl.saturating_sub(1);
        if new_ttl > 0 {
            s.fan_out_kp_to_peers_except(source_pubkey, new_ttl, frame.routing_id, &frame.body);
        }
    }
}

/// Process one inbound `FRAME_GOSSIP_DELIVER` from a peer hub
/// (T8.3.c). Decodes, drops on loop or expired TTL, delivers the
/// envelope locally (which may live-deliver to subscribers OR
/// enqueue, same semantics as a client-origin DELIVER), and
/// conditionally re-fans-out to OTHER peer hubs.
///
/// Re-fanout policy per [`GossipMode`]:
///   * `Eager`: always forward (when TTL allows).
///   * `Lazy`: forward only when we couldn't deliver locally
///     (i.e., no live subscriber for the routing id).
///
/// Unlike KP gossip, we cannot validate the envelope body — it's
/// AEAD-sealed under the recipient's hybrid KEM key and the hub
/// has no decryption capability. End-to-end integrity is enforced
/// by the recipient daemon via `open_bootstrap` (Ed25519 sig over
/// canonical bytes) and the replay guard (T7.3-sec.2). A peer hub
/// that gossips garbage envelope bytes just gets them silently
/// dropped at the recipient daemon, the same as a client gossiping
/// garbage. No new defense needed at this layer.
async fn handle_gossip_deliver(
    payload: &[u8],
    state: &Arc<Mutex<HubState>>,
    source_pubkey: &[u8; 32],
) {
    let Ok(frame) = GossipFrame::decode(payload) else {
        warn!("hub: peer-hub gossip envelope did not decode; dropping");
        return;
    };

    // Loop check: dropping a frame we already forwarded keeps the
    // mesh from amplifying. Same logic as the KP path.
    {
        let s = state.lock().await;
        if frame.seen_by == s.self_hub_hash_for_test() {
            tracing::debug!("hub: gossip envelope loop detected; dropping");
            return;
        }
    }

    // Deliver locally. The deliver() method tries live subscribers
    // first; falls back to queueing when none accept. We bypass
    // `deliver_from_client` here because that would gossip back
    // out (it doesn't know about source-skip); we manually handle
    // the re-fanout below with the source skip.
    let (delivered, mode) = {
        let mut s = state.lock().await;
        let d = s.deliver(frame.routing_id, frame.body.clone());
        (d, s.gossip_mode())
    };
    tracing::info!(
        live_subscribers = delivered,
        ttl = frame.ttl,
        ?mode,
        "hub: gossiped envelope delivered locally"
    );

    // Re-fanout to OTHER peers under the same policy as origin:
    // - Eager: always forward.
    // - Lazy: forward only when we couldn't deliver locally.
    let new_ttl = frame.ttl.saturating_sub(1);
    let should_forward = new_ttl > 0
        && match mode {
            crate::state::GossipMode::Eager => true,
            crate::state::GossipMode::Lazy => delivered == 0,
        };
    if should_forward {
        let s = state.lock().await;
        s.fan_out_envelope_to_peers_except(source_pubkey, new_ttl, frame.routing_id, &frame.body);
    }
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
    peer_pk: &[u8; 32],
    rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    cover_traffic_mean_secs: Option<u64>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // T-cover.hub: when cover traffic is enabled for this hub,
    // arm a sleep that fires at the first Poisson-distributed
    // interval. After each fire we re-arm with a fresh sample so
    // the inter-arrival times stay memoryless. Disabled → arm a
    // never-ready sleep so the select branch is a no-op.
    let cover_enabled = matches!(cover_traffic_mean_secs, Some(s) if s > 0);
    let initial_cover_dt = if cover_enabled {
        sample_exponential_interval(cover_traffic_mean_secs.expect("checked above"))
    } else {
        std::time::Duration::MAX
    };
    let cover_sleep = tokio::time::sleep(initial_cover_dt);
    tokio::pin!(cover_sleep);
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
                        // T8.x-ratelimit: per-connection token bucket.
                        // Drop silently on empty bucket (matches our
                        // "fail closed, log loudly" posture for other
                        // misbehaving-client signals).
                        if !state.lock().await.check_rate(peer_pk) {
                            warn!(
                                conn = conn_id,
                                "hub: DELIVER rate-limited (bucket empty); dropping frame"
                            );
                            continue;
                        }
                        // The hub reads the 16-byte target prefix to decide
                        // *where* to route, but forwards the entire payload
                        // (prefix included) to subscribers so they can tell
                        // *which* of their subscriptions matched. The
                        // recipient strips the prefix before decrypting.
                        let target = parse_target_prefix(&frame.payload)?;
                        // T8.3.c: use deliver_from_client so federation
                        // gossip happens per the configured GossipMode
                        // (lazy = forward only when no local subscriber;
                        // eager = always forward). No-op when no
                        // --peer-hub is configured.
                        let delivered = {
                            let mut s = state.lock().await;
                            s.deliver_from_client(target, frame.payload)
                        };
                        info!(
                            conn = conn_id,
                            live_subscribers = delivered,
                            "hub: deliver routed"
                        );
                    }
                    FRAME_KP_PUBLISH => {
                        // T8.x-ratelimit: KP_PUBLISH triggers MLS
                        // validation work (TLS deserialise + leaf-
                        // node signature check), so the bucket
                        // matters here too. Same shared bucket as
                        // DELIVER — one connection's DELIVER spam
                        // and KP_PUBLISH spam compete for the same
                        // budget.
                        if !state.lock().await.check_rate(peer_pk) {
                            warn!(
                                conn = conn_id,
                                "hub: KP_PUBLISH rate-limited (bucket empty); dropping frame"
                            );
                            continue;
                        }
                        // Latest-wins on accept. The publisher must
                        // prove ownership of the routing id by shipping
                        // a KP whose embedded Ed25519 signing key
                        // derives the claimed routing id via the same
                        // path the recipient uses (fingerprint =
                        // signing-key bytes, routing id =
                        // introduction_inbox(fingerprint)).
                        //
                        // Before T7.3-sec the hub stored blindly and
                        // relied on recipient-side verification
                        // (THREAT_MODEL §8.2 #15: a hostile publisher
                        // could overwrite anyone's directory entry,
                        // and recipients caught it on fetch). The
                        // hub-side check below makes the overwrite
                        // impossible in the first place — the malicious
                        // client's KP doesn't derive the target routing
                        // id, so the publish is rejected.
                        //
                        // Wire format unchanged: 16-byte routing id
                        // prefix, then the TLS-serialised KP. Same
                        // shape as DELIVER; same parse_target_prefix.
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

                        // Ownership check: extract the KP's signing
                        // key, hash to a fingerprint, derive the
                        // expected inbox id, compare to the claimed
                        // routing id. Any failure (un-parseable KP,
                        // failed MLS validation, mismatch) → reject.
                        match onyx_core::mls::signing_key_from_kp_bytes(&kp_bytes) {
                            Ok(signing_pk_bytes) => {
                                let fingerprint = onyx_core::crypto::Fingerprint::from_bytes(
                                    signing_pk_bytes,
                                );
                                let expected =
                                    onyx_core::routing::introduction_inbox(&fingerprint);
                                if expected != routing_id {
                                    warn!(
                                        conn = conn_id,
                                        kp_bytes = kp_len,
                                        "hub: KP_PUBLISH rejected — KP signing key does not \
                                         derive the claimed routing id (ownership check failed)"
                                    );
                                    continue;
                                }
                            }
                            Err(e) => {
                                warn!(
                                    conn = conn_id,
                                    kp_bytes = kp_len,
                                    error = %e,
                                    "hub: KP_PUBLISH rejected — KP did not validate as a \
                                     well-formed MLS KeyPackage"
                                );
                                continue;
                            }
                        }

                        let dir_size = {
                            let mut s = state.lock().await;
                            // T8.3.b.3: gossip the validated KP to
                            // every configured peer hub BEFORE the
                            // local publish consumes kp_bytes. No-op
                            // when no peer hubs configured. Best-
                            // effort (full peer-outbound channel →
                            // dropped for that peer; the recipient's
                            // replay guard would have dedup'd
                            // anyway if it arrived twice).
                            s.fan_out_kp_to_peers(routing_id, &kp_bytes);
                            s.publish_keypackage(routing_id, kp_bytes);
                            s.keypackage_count()
                        };
                        info!(
                            conn = conn_id,
                            kp_bytes = kp_len,
                            directory_size = dir_size,
                            "hub: KeyPackage published (ownership verified)"
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
                    FRAME_PAD => {
                        // T-cover.1: client-side cover traffic. Silently
                        // discard — no warn, no info, even no debug per-
                        // frame. The whole point is that the hub MUST
                        // NOT be able to distinguish cover from real
                        // traffic, including via its own logs (an
                        // operator scrolling stderr would otherwise see
                        // "alice's daemon is sending PAD frames" and
                        // know exactly when alice's actual sends
                        // happened by absence of PAD lines). Log at the
                        // coarsest "trace" level only.
                        tracing::trace!(conn = conn_id, "hub: dropped FRAME_PAD");
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
            // T-cover.hub: cover-traffic tick. Send a FRAME_PAD and
            // re-arm with a fresh exponentially-distributed interval.
            // The branch only fires when cover_enabled (the no-op
            // arm uses Duration::MAX which never elapses).
            () = &mut cover_sleep, if cover_enabled => {
                write_frame(stream, session, &InnerFrame {
                    frame_type: onyx_core::wire::FRAME_PAD,
                    payload: Vec::new(),
                }).await
                    .map_err(|e| anyhow::anyhow!("hub: write PAD: {e}"))?;
                tracing::trace!(conn = conn_id, "hub: outbound PAD sent");
                // Re-arm with a fresh Poisson sample. `set` reuses
                // the same Sleep allocation; cheaper than dropping
                // and recreating.
                if let Some(secs) = cover_traffic_mean_secs {
                    let dt = sample_exponential_interval(secs);
                    cover_sleep.as_mut().reset(tokio::time::Instant::now() + dt);
                }
            }
        }
    }
}

/// T-cover.hub: sample an exponentially-distributed inter-arrival
/// interval with mean `mean_secs`. Inverse-CDF method using OS
/// random bytes. Same algorithm as the daemon's
/// `next_exponential_interval`; kept private here to avoid a
/// cross-crate dependency. Clamped to `[1s, 10×mean]` for the same
/// reasons documented daemon-side (avoid CSPRNG-outlier circuit
/// saturation + long-tail "we never sent anything" gaps).
//
// Float precision/truncation casts intentional — feeding a sleep
// duration, not maintaining cryptographic precision. Clamp keeps
// the result sane regardless of float weirdness.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn sample_exponential_interval(mean_secs: u64) -> std::time::Duration {
    let mut buf = [0u8; 8];
    onyx_core::crypto::fill_random(&mut buf);
    let raw = u64::from_le_bytes(buf);
    let u = (raw as f64 + 1.0) / (u64::MAX as f64 + 1.0);
    let mean = mean_secs as f64;
    let secs = -mean * u.ln();
    let max_secs = mean * 10.0;
    let clamped = secs.clamp(1.0, max_secs);
    let millis = (clamped * 1000.0) as u64;
    std::time::Duration::from_millis(millis)
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

    /// T6.1 + T7.3-sec: publish + fetch round-trip over the wire,
    /// with real MLS KeyPackage bytes whose embedded signing key
    /// derives the claimed routing id (the hub's ownership check
    /// rejects anything else — see T7.3-sec).
    #[allow(clippy::similar_names)]
    #[tokio::test]
    async fn keypackage_publish_then_fetch_round_trip() {
        use onyx_core::identity::Identity;
        use onyx_core::mls::MlsParty;
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

        // Real KP from alice's MLS party, plus the routing id that
        // its embedded signing key derives — must match for the hub's
        // ownership check to accept the publish.
        let alice_identity = Identity::generate();
        let alice_party = MlsParty::from_identity(&alice_identity).unwrap();
        let alice_kp_bytes = alice_party.key_package_bytes().unwrap();
        let alice_fp = alice_identity.fingerprint();
        let alice_kp_id: RoutingId = onyx_core::routing::introduction_inbox(&alice_fp);

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

    /// T6.1 + T7.3-sec: latest-wins on republish, with two real KPs
    /// minted from the same alice identity (both pass the ownership
    /// check because they share alice's Ed25519 signing key → same
    /// derived routing id).
    #[allow(clippy::similar_names)]
    #[tokio::test]
    async fn keypackage_republish_overwrites() {
        use onyx_core::identity::Identity;
        use onyx_core::mls::MlsParty;
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

        let alice_identity = Identity::generate();
        let alice_party = MlsParty::from_identity(&alice_identity).unwrap();
        let alice_kp_v1 = alice_party.key_package_bytes().unwrap();
        let alice_kp_v2 = alice_party.key_package_bytes().unwrap();
        assert_ne!(
            alice_kp_v1, alice_kp_v2,
            "successive key_package_bytes() calls must mint distinct bundles \
             (their init keys differ); republish-overwrites is only meaningful then"
        );
        let id: RoutingId = onyx_core::routing::introduction_inbox(&alice_identity.fingerprint());

        // Alice publishes twice; the second publish must replace, not append.
        let hub_pk_for_alice = hub_pk;
        let alice_kp_v2_for_check = alice_kp_v2.clone();
        let alice_task = tokio::spawn(async move {
            let mut stream = alice_client;
            let mut session = handshake_initiator(&mut stream, &alice_sk, &hub_pk_for_alice)
                .await
                .expect("alice handshake");
            for (label, body) in [
                ("v1", alice_kp_v1.as_slice()),
                ("v2", alice_kp_v2.as_slice()),
            ] {
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
            assert_eq!(&resp.payload[1..], alice_kp_v2_for_check.as_slice());
        });
        bob_task.await.unwrap();
    }

    /// T7.3-sec: a hostile publisher cannot overwrite another peer's
    /// directory entry. The attacker's KP signing key derives the
    /// attacker's own routing id, not alice's — the hub rejects the
    /// publish at the ownership check, alice's entry stays put.
    ///
    /// This closes THREAT_MODEL.md §8.2 #15 at the hub layer (the
    /// recipient-side validation in `handle_fetch_peer_keypackage`
    /// continues to defend defence-in-depth).
    #[allow(clippy::similar_names)]
    #[tokio::test]
    async fn keypackage_publish_rejects_routing_id_mismatch() {
        use onyx_core::identity::Identity;
        use onyx_core::mls::MlsParty;
        use onyx_core::transport::handshake_initiator;

        let hub_sk = IdentitySecret::generate();
        let hub_pk = hub_sk.public();

        // Alice owns a routing id; attacker tries to overwrite it.
        let alice_identity = Identity::generate();
        let alice_party = MlsParty::from_identity(&alice_identity).unwrap();
        let alice_kp = alice_party.key_package_bytes().unwrap();
        let alice_routing_id: RoutingId =
            onyx_core::routing::introduction_inbox(&alice_identity.fingerprint());

        let attacker_identity = Identity::generate();
        let attacker_party = MlsParty::from_identity(&attacker_identity).unwrap();
        let attacker_kp = attacker_party.key_package_bytes().unwrap();

        let state = Arc::new(Mutex::new(HubState::new()));

        // 1. Alice legitimately publishes her KP under her own
        //    routing id.
        let (alice_client, alice_hub) = tokio::io::duplex(65_536);
        let _alice_hub_task = spawn_hub(alice_hub, hub_sk_clone(&hub_sk), state.clone());
        let alice_sk = IdentitySecret::generate();
        let alice_routing_for_publish = alice_routing_id;
        let alice_kp_for_publish = alice_kp.clone();
        let alice_task = tokio::spawn(async move {
            let mut stream = alice_client;
            let mut session = handshake_initiator(&mut stream, &alice_sk, &hub_pk)
                .await
                .expect("alice handshake");
            let mut payload = Vec::with_capacity(16 + alice_kp_for_publish.len());
            payload.extend_from_slice(&alice_routing_for_publish);
            payload.extend_from_slice(&alice_kp_for_publish);
            write_frame(
                &mut stream,
                &mut session,
                &InnerFrame {
                    frame_type: FRAME_KP_PUBLISH,
                    payload,
                },
            )
            .await
            .expect("alice publish");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });
        alice_task.await.unwrap();

        // 2. Attacker connects and tries to overwrite alice's entry
        //    by claiming alice's routing id with the attacker's KP.
        //    The hub MUST reject — KP signing key does not derive
        //    alice's routing id.
        let (attacker_client, attacker_hub) = tokio::io::duplex(65_536);
        let _attacker_hub_task = spawn_hub(attacker_hub, hub_sk_clone(&hub_sk), state.clone());
        let attacker_sk = IdentitySecret::generate();
        let attacker_kp_for_publish = attacker_kp.clone();
        let attacker_task = tokio::spawn(async move {
            let mut stream = attacker_client;
            let mut session = handshake_initiator(&mut stream, &attacker_sk, &hub_pk)
                .await
                .expect("attacker handshake");
            let mut payload = Vec::with_capacity(16 + attacker_kp_for_publish.len());
            payload.extend_from_slice(&alice_routing_id); // attacker claims alice's id
            payload.extend_from_slice(&attacker_kp_for_publish);
            write_frame(
                &mut stream,
                &mut session,
                &InnerFrame {
                    frame_type: FRAME_KP_PUBLISH,
                    payload,
                },
            )
            .await
            .expect("attacker publish (hub will reject silently)");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });
        attacker_task.await.unwrap();

        // 3. Direct state-check side-channel: the directory entry
        //    under alice_routing_id is still alice's KP, not the
        //    attacker's.
        let stored = state.lock().await.fetch_keypackage(&alice_routing_id);
        assert_eq!(
            stored.as_deref(),
            Some(alice_kp.as_slice()),
            "alice's entry must be intact; attacker's overwrite must have been rejected"
        );
    }

    // ── T8.3.d: gossip loop / forward semantics ──────────────────────

    /// Helper for T8.3.d tests: build a `HubState` with `peer_count`
    /// peer outbounds (all backed by `Receiver`s the caller can
    /// observe), our own hub hash set, and federation enabled.
    /// Returns the state plus a `Vec<(pubkey, rx)>` so tests can
    /// poke at each peer's channel.
    #[allow(clippy::type_complexity)] // test helper; tuple shape IS the contract
    fn fed_state(
        self_hash: [u8; 16],
        peer_count: usize,
    ) -> (
        HubState,
        Vec<(
            [u8; 32],
            tokio::sync::mpsc::Receiver<onyx_core::wire::InnerFrame>,
        )>,
    ) {
        let mut state = HubState::new();
        state.set_self_hub_hash(self_hash);
        let mut peers = std::collections::HashMap::new();
        let mut rxs = Vec::with_capacity(peer_count);
        for i in 0..peer_count {
            // Distinct pubkey per peer (low byte = index).
            let mut pk = [0u8; 32];
            pk[0] = u8::try_from(i + 1).expect("peer index fits in u8");
            let (tx, rx) = tokio::sync::mpsc::channel::<onyx_core::wire::InnerFrame>(16);
            peers.insert(pk, tx);
            rxs.push((pk, rx));
        }
        state.set_peer_outbounds(peers);
        (state, rxs)
    }

    /// Helper: build a valid MLS KeyPackage + its routing-id from a
    /// fresh Identity. Used wherever T7.3-sec ownership check needs
    /// to pass.
    fn fresh_kp_and_routing_id() -> (Vec<u8>, RoutingId) {
        use onyx_core::identity::Identity;
        use onyx_core::mls::MlsParty;
        let id = Identity::generate();
        let party = MlsParty::from_identity(&id).unwrap();
        let kp = party.key_package_bytes().unwrap();
        let rid = onyx_core::routing::introduction_inbox(&id.fingerprint());
        (kp, rid)
    }

    /// T8.3.d: a gossip frame whose `seen_by` equals our own hub
    /// hash is dropped silently — no local store, no re-fanout.
    /// Defends against an immediate-loop attack.
    #[tokio::test]
    async fn gossip_publish_self_seen_by_drops() {
        use onyx_core::wire::{GOSSIP_TTL_DEFAULT, GossipFrame};
        let our_hash = [0xAA; 16];
        let (state, mut peer_rxs) = fed_state(our_hash, 2);
        let state = Arc::new(Mutex::new(state));

        let (kp_bytes, rid) = fresh_kp_and_routing_id();
        // Forge a frame as if WE had already sent it (seen_by = us).
        let frame = GossipFrame {
            ttl: GOSSIP_TTL_DEFAULT,
            seen_by: our_hash,
            routing_id: rid,
            body: kp_bytes,
        };
        let payload = frame.encode();

        // Source pubkey can be anything; we won't reach the re-fanout.
        let source_pk = [0x99; 32];
        handle_gossip_publish(&payload, &state, &source_pk).await;

        // Nothing should have been stored locally.
        {
            let s = state.lock().await;
            assert_eq!(s.keypackage_count(), 0, "loop drop must skip local store");
        }
        // No peer channel received a re-fanout.
        for (_pk, rx) in &mut peer_rxs {
            assert!(
                rx.try_recv().is_err(),
                "loop drop must NOT trigger re-fanout"
            );
        }
    }

    /// T8.3.d: TTL=1 receives correctly store locally BUT do not
    /// re-fanout — `saturating_sub(1) == 0`, the TTL guard skips the
    /// forward. Bounds the propagation depth in any topology.
    #[tokio::test]
    async fn gossip_publish_ttl_one_stores_but_does_not_forward() {
        use onyx_core::wire::GossipFrame;
        let our_hash = [0xBB; 16];
        let (state, mut peer_rxs) = fed_state(our_hash, 2);
        let state = Arc::new(Mutex::new(state));

        let (kp_bytes, rid) = fresh_kp_and_routing_id();
        let frame = GossipFrame {
            ttl: 1,
            seen_by: [0xCC; 16], // from some other hub
            routing_id: rid,
            body: kp_bytes,
        };
        let payload = frame.encode();

        let source_pk = [0x77; 32];
        handle_gossip_publish(&payload, &state, &source_pk).await;

        // Local store HAPPENED (TTL only governs forwarding, not local accept).
        {
            let s = state.lock().await;
            assert_eq!(s.keypackage_count(), 1, "TTL=1 must still accept locally");
        }
        // No peer channel got the forward — TTL would have gone to 0.
        for (_pk, rx) in &mut peer_rxs {
            assert!(
                rx.try_recv().is_err(),
                "TTL=1 must NOT forward (saturating_sub would underflow)"
            );
        }
    }

    /// T8.3.d: source-pubkey skip on re-fanout. The peer who sent
    /// us the gossip never receives our forwarded copy — prevents
    /// trivial A→B→A ping-pong.
    #[tokio::test]
    async fn gossip_publish_source_pubkey_skipped_on_forward() {
        use onyx_core::wire::GossipFrame;
        let our_hash = [0xDD; 16];
        let (state, mut peer_rxs) = fed_state(our_hash, 3);
        // Pick peer #0 as the source.
        let source_pk = peer_rxs[0].0;
        let state = Arc::new(Mutex::new(state));

        let (kp_bytes, rid) = fresh_kp_and_routing_id();
        let frame = GossipFrame {
            ttl: 3,
            seen_by: [0xEE; 16],
            routing_id: rid,
            body: kp_bytes,
        };
        let payload = frame.encode();

        handle_gossip_publish(&payload, &state, &source_pk).await;

        // Source peer (#0) must have received NOTHING.
        assert!(
            peer_rxs[0].1.try_recv().is_err(),
            "source pubkey must be skipped on re-fanout"
        );
        // The other two peers each got the re-fanout.
        for (idx, (_pk, rx)) in peer_rxs.iter_mut().enumerate().skip(1) {
            let inner = rx
                .recv()
                .await
                .unwrap_or_else(|| panic!("peer #{idx} should have received re-fanout"));
            assert_eq!(inner.frame_type, onyx_core::wire::FRAME_GOSSIP_PUBLISH);
            let fwd = onyx_core::wire::GossipFrame::decode(&inner.payload).unwrap();
            assert_eq!(fwd.ttl, 2, "TTL decremented from 3 to 2");
            assert_eq!(fwd.seen_by, our_hash, "seen_by rewritten to OUR hash");
        }
    }

    /// T8.3.d: GOSSIP_DELIVER source-skip + TTL semantics — mirrors
    /// the GOSSIP_PUBLISH test above for the queue path.
    #[tokio::test]
    async fn gossip_deliver_source_pubkey_skipped_on_forward_eager() {
        use onyx_core::wire::GossipFrame;
        let our_hash = [0x11; 16];
        let (mut state, mut peer_rxs) = fed_state(our_hash, 3);
        state.set_gossip_mode(crate::state::GossipMode::Eager);
        let source_pk = peer_rxs[0].0;
        let state = Arc::new(Mutex::new(state));

        // Envelope body is opaque AEAD ciphertext from the hub's
        // perspective — we don't need a valid MLS object here.
        let frame = GossipFrame {
            ttl: 3,
            seen_by: [0x22; 16],
            routing_id: [0x33; 16],
            body: b"opaque sealed envelope bytes".to_vec(),
        };
        let payload = frame.encode();

        handle_gossip_deliver(&payload, &state, &source_pk).await;

        // Source peer skipped; other two peers received under eager.
        assert!(
            peer_rxs[0].1.try_recv().is_err(),
            "source pubkey must be skipped on re-fanout"
        );
        for (_pk, rx) in peer_rxs.iter_mut().skip(1) {
            let inner = rx.recv().await.expect("non-source peer received");
            assert_eq!(inner.frame_type, onyx_core::wire::FRAME_GOSSIP_DELIVER);
            let fwd = onyx_core::wire::GossipFrame::decode(&inner.payload).unwrap();
            assert_eq!(fwd.ttl, 2);
            assert_eq!(fwd.seen_by, our_hash);
        }
    }

    /// T8.3.d: lazy mode + gossip-receive with NO local subscriber
    /// → re-fanout happens (envelope would otherwise die at us).
    #[tokio::test]
    async fn gossip_deliver_lazy_forwards_when_no_local_sub() {
        use onyx_core::wire::GossipFrame;
        let our_hash = [0x44; 16];
        let (state, mut peer_rxs) = fed_state(our_hash, 2);
        // Default mode is Lazy.
        let source_pk = peer_rxs[0].0;
        let state = Arc::new(Mutex::new(state));

        let frame = GossipFrame {
            ttl: 3,
            seen_by: [0x55; 16],
            routing_id: [0x66; 16],
            body: b"opaque bytes".to_vec(),
        };
        let payload = frame.encode();

        handle_gossip_deliver(&payload, &state, &source_pk).await;

        // No local subscriber for routing_id 0x66 → lazy mode
        // forwards. Source skipped; peer #1 receives.
        assert!(peer_rxs[0].1.try_recv().is_err(), "source skipped");
        let inner = peer_rxs[1]
            .1
            .recv()
            .await
            .expect("non-source peer received under lazy when no local sub");
        assert_eq!(inner.frame_type, onyx_core::wire::FRAME_GOSSIP_DELIVER);
    }

    /// T8.3.d: lazy mode + gossip-receive WITH local subscriber
    /// → no re-fanout. The envelope reached its destination here,
    /// no need to keep gossiping.
    #[tokio::test]
    async fn gossip_deliver_lazy_does_not_forward_when_local_sub_accepted() {
        use onyx_core::wire::GossipFrame;
        let our_hash = [0x77; 16];
        let (mut state, mut peer_rxs) = fed_state(our_hash, 2);
        // Register a local subscriber for the routing id we'll
        // gossip to.
        let target_rid: RoutingId = [0x88; 16];
        let (sub_tx, _sub_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let conn = state.register_conn(sub_tx);
        state.subscribe(conn, &[target_rid]);
        let source_pk = peer_rxs[0].0;
        let state = Arc::new(Mutex::new(state));

        let frame = GossipFrame {
            ttl: 3,
            seen_by: [0x99; 16],
            routing_id: target_rid,
            body: b"will-be-delivered-locally".to_vec(),
        };
        let payload = frame.encode();

        handle_gossip_deliver(&payload, &state, &source_pk).await;

        // Neither peer channel sees the gossip — lazy mode swallowed
        // it because the local subscriber accepted.
        for (_pk, rx) in &mut peer_rxs {
            assert!(
                rx.try_recv().is_err(),
                "lazy mode must NOT forward when local subscriber accepted"
            );
        }
    }

    /// T8.3.d: gossip with garbage body (un-decodable as GossipFrame)
    /// is silently dropped — same posture as other malformed-frame
    /// handling. No panic.
    #[tokio::test]
    async fn gossip_publish_malformed_payload_drops_cleanly() {
        let our_hash = [0xAB; 16];
        let (state, mut peer_rxs) = fed_state(our_hash, 1);
        let state = Arc::new(Mutex::new(state));

        // Payload shorter than the gossip header.
        let too_short = vec![0u8; 5];
        handle_gossip_publish(&too_short, &state, &[0u8; 32]).await;
        handle_gossip_deliver(&too_short, &state, &[0u8; 32]).await;

        // No store, no fan-out.
        assert_eq!(state.lock().await.keypackage_count(), 0);
        for (_pk, rx) in &mut peer_rxs {
            assert!(rx.try_recv().is_err());
        }
    }

    /// T8.3.d: gossip KP whose signing key does NOT derive the
    /// claimed routing id is rejected (T7.3-sec ownership check
    /// propagated to gossip path). A hostile peer hub gossiping
    /// somebody else's routing id with their own KP gets silently
    /// dropped.
    #[tokio::test]
    async fn gossip_publish_ownership_check_propagates_to_gossip() {
        use onyx_core::wire::GossipFrame;
        let our_hash = [0xCD; 16];
        let (state, _rxs) = fed_state(our_hash, 1);
        let state = Arc::new(Mutex::new(state));

        // Real KP, but with a WRONG routing id (claimed by the
        // hostile gossiper).
        let (kp_bytes, _real_rid) = fresh_kp_and_routing_id();
        let wrong_rid: RoutingId = [0xFF; 16]; // not derivable from this KP
        let frame = GossipFrame {
            ttl: 3,
            seen_by: [0x55; 16],
            routing_id: wrong_rid,
            body: kp_bytes,
        };
        let payload = frame.encode();

        handle_gossip_publish(&payload, &state, &[0u8; 32]).await;

        // Rejected — nothing stored.
        assert_eq!(
            state.lock().await.keypackage_count(),
            0,
            "ownership-check failure must skip local store"
        );
    }
}
