//! Long-lived authenticated session from `onyxd` to an `onyx-hub`.
//!
//! v0 surface (T5.1): the daemon can dial a hub over Tor, complete a
//! Noise XK handshake against the hub's static identity, send one
//! `FRAME_SUBSCRIBE` with the daemon's own introduction-inbox routing
//! id, and then loop reading `FRAME_DELIVER` frames. **Frames are
//! handed off via callback** but not yet routed into the
//! conversation registry — that's T5.2 once the sealed-sender
//! envelope is wired on the daemon path.
//!
//! ## Why a single shared session
//!
//! Each hub-client connection is one Tor circuit. We don't want to
//! pay circuit-build cost per delivery, so we keep a long-lived
//! session open. On disconnect the calling task reconnects with
//! backoff — that loop lives in `main.rs`, not here.
//!
//! ## No bidirectional `select!` yet
//!
//! T5.1 is read-only from the hub's perspective: the daemon
//! subscribes and listens. T5.2 will add `tokio::select!` on an
//! outbound mpsc so we can send via the hub as well as receive.

use anyhow::Context;
use onyx_core::crypto::{IdentityPublic, IdentitySecret};
use onyx_core::routing::RoutingId;
use onyx_core::tor::TorRuntime;
use onyx_core::transport::{handshake_initiator, read_frame, write_frame};
use onyx_core::wire::{FRAME_DELIVER, FRAME_SUBSCRIBE, InnerFrame};
use tracing::{info, warn};

/// Run one hub session: dial → handshake → subscribe → receive loop.
///
/// Returns `Ok(())` on clean peer-closed disconnect, `Err(...)` on
/// any setup failure (dial, handshake, initial subscribe). The
/// reconnect loop in the caller treats both as a cue to backoff +
/// retry.
///
/// `on_deliver` is invoked for every `FRAME_DELIVER` received from
/// the hub. Bodies still carry the 16-byte target prefix (the hub
/// preserves it so a multi-subscribed client can demultiplex) — the
/// callback gets `(target, body_after_prefix)`.
pub async fn run_hub_session<F>(
    tor: &TorRuntime,
    host: &str,
    port: u16,
    hub_pubkey: &IdentityPublic,
    our_identity_sk: &IdentitySecret,
    subscribe_to: &[RoutingId],
    mut on_deliver: F,
) -> anyhow::Result<()>
where
    F: FnMut(RoutingId, Vec<u8>),
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

    // SUBSCRIBE payload = N × 16-byte routing ids concatenated, per
    // crates/onyx-core/src/wire.rs.
    let mut payload = Vec::with_capacity(subscribe_to.len() * 16);
    for id in subscribe_to {
        payload.extend_from_slice(id);
    }
    write_frame(
        &mut stream,
        &mut session,
        &InnerFrame {
            frame_type: FRAME_SUBSCRIBE,
            payload,
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("hub SUBSCRIBE write failed: {e}"))?;
    info!("hub: subscription registered, entering receive loop");

    // Receive loop.
    loop {
        let frame = match read_frame(&mut stream, &mut session).await {
            Ok(f) => f,
            Err(e) => {
                info!(error = %e, "hub: receive ended (peer closed?)");
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
                on_deliver(target, body);
            }
            other => {
                warn!(
                    frame_type = format!("{other:#06x}"),
                    "hub: unexpected frame type from hub"
                );
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
}
