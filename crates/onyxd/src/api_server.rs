//! Local API server inside `onyxd`.
//!
//! Binds a Unix-domain socket (default `./onyxd.sock`, override with
//! `--api-socket`) and serves NDJSON requests defined in
//! [`onyx_core::api`]. Each accepted connection runs in its own task
//! and lives until the client closes the socket.
//!
//! ## Two operating modes per connection
//!
//! 1. **Request/response** (the default). Each client request line
//!    produces exactly one response line, then the daemon waits for
//!    the next request on the same connection.
//! 2. **Streaming** (`ApiRequest::Tail` only). After the initial
//!    `TailStarted` ack the connection becomes a one-way push of
//!    `Event…` lines; the client must not send more requests on it.
//!    Open another connection if you want concurrent reads.
//!
//! ## Lifecycle
//!
//! The server task runs concurrently with the daemon's main mode
//! (accept or dial); main `select!`s on both, and whichever exits
//! first triggers a clean shutdown. On shutdown we attempt to
//! `unlink(2)` the socket file — best-effort; a leftover socket file
//! is benign because the next start will `remove_file` before bind.
//!
//! ## Security
//!
//! The socket is chmod'd to `0600` immediately after bind. We rely
//! on filesystem permissions, not on SO_PEERCRED or a token. If an
//! attacker can read the socket file they already have your UID's
//! filesystem access, which means they can also read the vault.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use onyx_core::api::{
    API_VERSION, ApiErrorCode, ApiRequest, ApiResponse, MessageDirection, TorState, decode_request,
    encode_response_line,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tracing::{Instrument, debug, info, info_span, warn};

use crate::DaemonState;

/// Run the API server until the listener errors or the surrounding
/// task is cancelled. Always tries to remove the socket file on exit.
pub async fn serve_api(
    socket_path: PathBuf,
    state: Arc<DaemonState>,
    tor_state: TorState,
) -> anyhow::Result<()> {
    let listener = bind_listener(&socket_path).await?;
    info!(
        path = %socket_path.display(),
        mode = "0600",
        "API socket bound — `onyx` CLI can connect"
    );

    let result = accept_loop(listener, state, tor_state).await;

    if let Err(e) = tokio::fs::remove_file(&socket_path).await {
        debug!(path = %socket_path.display(), error = %e, "could not remove API socket on exit (already gone?)");
    }
    result
}

async fn bind_listener(socket_path: &Path) -> anyhow::Result<UnixListener> {
    if let Some(parent) = socket_path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            anyhow::anyhow!("creating API socket parent dir {}: {e}", parent.display())
        })?;
    }

    if tokio::fs::try_exists(socket_path).await.unwrap_or(false) {
        warn!(
            path = %socket_path.display(),
            "API socket file exists from a prior run; removing before bind"
        );
        tokio::fs::remove_file(socket_path)
            .await
            .map_err(|e| anyhow::anyhow!("removing stale socket {}: {e}", socket_path.display()))?;
    }

    let listener = UnixListener::bind(socket_path)
        .map_err(|e| anyhow::anyhow!("binding API socket {}: {e}", socket_path.display()))?;

    let perms = std::fs::Permissions::from_mode(0o600);
    tokio::fs::set_permissions(socket_path, perms)
        .await
        .map_err(|e| anyhow::anyhow!("chmod API socket {}: {e}", socket_path.display()))?;

    Ok(listener)
}

async fn accept_loop(
    listener: UnixListener,
    state: Arc<DaemonState>,
    tor_state: TorState,
) -> anyhow::Result<()> {
    let mut next_client_id: u64 = 0;
    loop {
        let (stream, _addr) = listener
            .accept()
            .await
            .map_err(|e| anyhow::anyhow!("API socket accept: {e}"))?;
        let client_id = next_client_id;
        next_client_id += 1;
        let state = state.clone();
        let span = info_span!("api-client", id = client_id);
        tokio::spawn(
            async move {
                if let Err(e) = handle_client(stream, state, tor_state).await {
                    warn!(error = %e, "API client handler ended with error");
                }
            }
            .instrument(span),
        );
    }
}

async fn handle_client(
    stream: UnixStream,
    state: Arc<DaemonState>,
    tor_state: TorState,
) -> anyhow::Result<()> {
    debug!("API client connected");
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    while let Some(line) = lines
        .next_line()
        .await
        .map_err(|e| anyhow::anyhow!("reading from API socket: {e}"))?
    {
        if line.trim().is_empty() {
            continue;
        }
        let req = match decode_request(&line) {
            Ok(r) => r,
            Err(e) => {
                send_one(
                    &mut write_half,
                    &ApiResponse::Error {
                        code: ApiErrorCode::Malformed,
                        message: format!("could not decode request: {e}"),
                    },
                )
                .await?;
                continue;
            }
        };

        // `Tail` switches the connection into push mode and never returns.
        if matches!(req, ApiRequest::Tail) {
            return serve_tail(write_half, &state).await;
        }

        let response = dispatch_one_shot(&req, &state, tor_state).await;
        if send_one(&mut write_half, &response).await.is_err() {
            debug!("API client disconnected mid-write");
            return Ok(());
        }
    }
    debug!("API client disconnected cleanly");
    Ok(())
}

async fn send_one(
    write_half: &mut (impl AsyncWriteExt + Unpin),
    response: &ApiResponse,
) -> anyhow::Result<()> {
    let out = encode_response_line(response)
        .map_err(|e| anyhow::anyhow!("encoding API response: {e}"))?;
    write_half
        .write_all(out.as_bytes())
        .await
        .map_err(|e| anyhow::anyhow!("writing API response: {e}"))?;
    Ok(())
}

/// Handle every verb except `Tail`. Returns a single response.
async fn dispatch_one_shot(
    req: &ApiRequest,
    state: &DaemonState,
    tor_state: TorState,
) -> ApiResponse {
    match req {
        ApiRequest::Status => ApiResponse::StatusOk {
            api_version: API_VERSION,
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            identity_pub_b32: encode_b32(&state.identity.identity_key().public().to_bytes()),
            fingerprint: state.identity.fingerprint().to_string(),
            tor_state,
            identity_kem_pub_b32: encode_b32(&state.identity.kem_public().to_bytes()),
        },
        ApiRequest::Identity => ApiResponse::IdentityOk {
            identity_pub_b32: encode_b32(&state.identity.identity_key().public().to_bytes()),
            fingerprint: state.identity.fingerprint().to_string(),
            identity_kem_pub_b32: encode_b32(&state.identity.kem_public().to_bytes()),
        },
        ApiRequest::Peers => {
            let entries = state.conversations.lock().await.list();
            ApiResponse::PeersOk { entries }
        }
        ApiRequest::History { peer_short, limit } => {
            // Both sides are small constants; the only failure mode of
            // these conversions is "value > u32::MAX", which can't happen
            // for RING_CAPACITY. usize::try_from is infallible on the
            // platforms we care about but we let it bubble defensively.
            let ring_cap = u32::try_from(crate::conversations::RING_CAPACITY).unwrap_or(u32::MAX);
            let limit_clamped = usize::try_from((*limit).min(ring_cap)).unwrap_or(0);
            match state
                .conversations
                .lock()
                .await
                .history(peer_short, limit_clamped)
            {
                Some(messages) => ApiResponse::HistoryOk {
                    peer_short: peer_short.clone(),
                    messages,
                },
                None => ApiResponse::Error {
                    code: ApiErrorCode::NotReady,
                    message: format!("no peer with short_id {peer_short}"),
                },
            }
        }
        ApiRequest::Send { peer_short, text } => {
            // Look up the peer's outbound queue, push the text in, and
            // also echo it into the registry as our own outgoing
            // message so the TUI's scrollback updates immediately
            // (the peer session task does NOT push outgoing messages —
            // it only encrypts + sends them on the wire).
            let handle_opt = state
                .conversations
                .lock()
                .await
                .handle_for_short(peer_short);
            let Some(handle) = handle_opt else {
                return ApiResponse::Error {
                    code: ApiErrorCode::NotReady,
                    message: format!("no live conversation with peer {peer_short}"),
                };
            };
            match handle.outbound_tx.try_send(text.clone()) {
                Ok(()) => {
                    state.conversations.lock().await.push_message(
                        &handle.peer_pub,
                        MessageDirection::Outgoing,
                        text.clone(),
                    );
                    ApiResponse::SendOk
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => ApiResponse::Error {
                    code: ApiErrorCode::NotReady,
                    message: format!("outbound queue full for peer {peer_short}"),
                },
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => ApiResponse::Error {
                    code: ApiErrorCode::NotReady,
                    message: format!("peer {peer_short} disconnected before send"),
                },
            }
        }
        ApiRequest::SendBootstrap {
            peer_fingerprint,
            peer_kem_pub_b32,
            text,
        } => handle_send_bootstrap(
            peer_fingerprint,
            peer_kem_pub_b32,
            text,
            state.identity.signing(),
            state.identity.identity_key(),
            state.hub_outbound.as_ref(),
        ),
        ApiRequest::Tail => unreachable!("Tail handled by serve_tail"),
    }
}

/// Build + seal a [`BootstrapPayload::PlainMessage`] for the named
/// peer and push it into the hub's outbound queue. Fails closed on
/// every parsing or queueing failure — never sends a half-formed
/// envelope.
///
/// Takes only the daemon components it actually needs so the unhappy
/// paths can be unit-tested without standing up a full `DaemonState`.
fn handle_send_bootstrap(
    peer_fingerprint: &str,
    peer_kem_pub_b32: &str,
    text: &str,
    our_signing: &onyx_core::crypto::SigningKey,
    our_identity_sk: &onyx_core::crypto::IdentitySecret,
    hub_outbound: Option<&tokio::sync::mpsc::Sender<crate::hub_client::HubOutbound>>,
) -> ApiResponse {
    // Require the hub-client to be active. If `--hub-onion` wasn't
    // set at launch, `hub_outbound` is None and we can't relay
    // anything; surface that as NotReady (operator config issue, not
    // a malformed request).
    let Some(hub_outbound) = hub_outbound else {
        return ApiResponse::Error {
            code: ApiErrorCode::NotReady,
            message: "hub client is not enabled; relaunch with --hub-onion --hub-pubkey".into(),
        };
    };

    // Parse + validate the peer identifiers up front so a bad input
    // never reaches the crypto helpers.
    let Ok(fp) = onyx_core::crypto::Fingerprint::parse(peer_fingerprint) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "peer_fingerprint did not parse".into(),
        };
    };
    let Some(kem_pub_bytes) = base32::decode(
        base32::Alphabet::Rfc4648Lower { padding: false },
        peer_kem_pub_b32,
    ) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "peer_kem_pub_b32 is not valid base32".into(),
        };
    };
    let Ok(kem_pub) = onyx_core::crypto::HybridKemPublic::from_bytes(&kem_pub_bytes) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "peer_kem_pub_b32 did not decode as HybridKemPublic".into(),
        };
    };

    // Build the inner payload, encode CBOR, seal.
    let payload = onyx_core::routing::BootstrapPayload::PlainMessage {
        text: text.to_string(),
    };
    let Ok(payload_bytes) = payload.to_cbor() else {
        return ApiResponse::Error {
            code: ApiErrorCode::Internal,
            message: "encoding BootstrapPayload failed".into(),
        };
    };
    let Ok(sealed) = onyx_core::routing::seal_bootstrap(
        our_signing,
        our_identity_sk,
        &payload_bytes,
        &kem_pub,
    ) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Internal,
            message: "seal_bootstrap failed".into(),
        };
    };

    // Push to the hub-client's outbound queue. `try_send` so we
    // never block the API handler; full mailbox → NotReady.
    let target = onyx_core::routing::introduction_inbox(&fp);
    match hub_outbound.try_send(crate::hub_client::HubOutbound {
        target,
        body: sealed,
    }) {
        Ok(()) => ApiResponse::SendBootstrapOk,
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => ApiResponse::Error {
            code: ApiErrorCode::NotReady,
            message: "hub outbound queue is full; try again shortly".into(),
        },
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => ApiResponse::Error {
            code: ApiErrorCode::NotReady,
            message: "hub client task has ended; relaunch the daemon".into(),
        },
    }
}

/// Streaming-mode handler: ack with `TailStarted`, subscribe to the
/// global conversation events, forward each event as a response line
/// until the client closes the socket or the daemon shuts down.
async fn serve_tail(
    mut write_half: tokio::net::unix::OwnedWriteHalf,
    state: &DaemonState,
) -> anyhow::Result<()> {
    // Subscribe BEFORE sending the ack so we don't miss events fired
    // between the ack and the loop entry.
    let mut events = state.conversations.lock().await.subscribe_events();
    send_one(&mut write_half, &ApiResponse::TailStarted).await?;
    info!("API tail subscriber active");

    loop {
        match events.recv().await {
            Ok(event) => {
                if send_one(&mut write_half, &event).await.is_err() {
                    debug!("API tail client disconnected");
                    return Ok(());
                }
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(
                    skipped,
                    "API tail subscriber fell behind broadcast; some events dropped"
                );
                // Don't terminate — just keep going from the next live event.
            }
            Err(broadcast::error::RecvError::Closed) => {
                debug!("API tail event channel closed; ending");
                return Ok(());
            }
        }
    }
}

fn encode_b32(bytes: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use onyx_core::crypto::{HybridKemSecret, IdentitySecret, SigningKey};

    fn fresh_signing_and_id() -> (SigningKey, IdentitySecret) {
        (SigningKey::generate(), IdentitySecret::generate())
    }

    /// `--hub-onion` not set ⇒ `hub_outbound: None` ⇒ NotReady.
    /// Operator config error, not a malformed request.
    #[test]
    fn send_bootstrap_without_hub_is_not_ready() {
        let (sign, id) = fresh_signing_and_id();
        let bob_kem = HybridKemSecret::generate();
        let bob_kem_b32 = encode_b32(&bob_kem.public().to_bytes());
        let fp = SigningKey::generate()
            .verifying_key()
            .fingerprint()
            .to_string();

        let resp = handle_send_bootstrap(&fp, &bob_kem_b32, "hi bob", &sign, &id, None);
        match resp {
            ApiResponse::Error { code, .. } => assert_eq!(code, ApiErrorCode::NotReady),
            other => panic!("expected NotReady, got {other:?}"),
        }
    }

    /// Garbage fingerprint ⇒ Malformed.
    #[tokio::test]
    async fn send_bootstrap_bad_fingerprint_is_malformed() {
        let (sign, id) = fresh_signing_and_id();
        let bob_kem = HybridKemSecret::generate();
        let bob_kem_b32 = encode_b32(&bob_kem.public().to_bytes());
        let (tx, _rx) = tokio::sync::mpsc::channel(8);

        let resp = handle_send_bootstrap(
            "not-a-fingerprint",
            &bob_kem_b32,
            "x",
            &sign,
            &id,
            Some(&tx),
        );
        match resp {
            ApiResponse::Error { code, .. } => assert_eq!(code, ApiErrorCode::Malformed),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    /// Garbage KEM b32 ⇒ Malformed.
    #[tokio::test]
    async fn send_bootstrap_bad_kem_b32_is_malformed() {
        let (sign, id) = fresh_signing_and_id();
        let fp = SigningKey::generate()
            .verifying_key()
            .fingerprint()
            .to_string();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);

        let resp = handle_send_bootstrap(&fp, "not-base32!@#$", "x", &sign, &id, Some(&tx));
        match resp {
            ApiResponse::Error { code, .. } => assert_eq!(code, ApiErrorCode::Malformed),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    /// Wrong-length KEM b32 (valid base32 but wrong length) ⇒ Malformed.
    #[tokio::test]
    async fn send_bootstrap_wrong_length_kem_is_malformed() {
        let (sign, id) = fresh_signing_and_id();
        let fp = SigningKey::generate()
            .verifying_key()
            .fingerprint()
            .to_string();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);

        // Valid base32 of an obviously-wrong length (8 bytes, not 1216).
        let resp = handle_send_bootstrap(&fp, "aaaaaaaaaaaa", "x", &sign, &id, Some(&tx));
        match resp {
            ApiResponse::Error { code, .. } => assert_eq!(code, ApiErrorCode::Malformed),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    /// Well-formed inputs, hub queue has capacity ⇒ SendBootstrapOk
    /// and a single HubOutbound lands on the receiver carrying the
    /// recipient's introduction-inbox routing id.
    #[tokio::test]
    async fn send_bootstrap_happy_path_queues_outbound() {
        let (sign, id) = fresh_signing_and_id();

        // Recipient: fresh signing + KEM keypair.
        let bob_sign = SigningKey::generate();
        let bob_fp = bob_sign.verifying_key().fingerprint();
        let bob_fp_b32 = bob_fp.to_string();
        let bob_kem = HybridKemSecret::generate();
        let bob_kem_b32 = encode_b32(&bob_kem.public().to_bytes());

        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let resp = handle_send_bootstrap(
            &bob_fp_b32,
            &bob_kem_b32,
            "first hub-relayed hello",
            &sign,
            &id,
            Some(&tx),
        );
        assert!(matches!(resp, ApiResponse::SendBootstrapOk));

        let outbound = rx.recv().await.expect("HubOutbound delivered");
        // Target must be the introduction-inbox routing id derived
        // from bob's fingerprint — that's the security-relevant
        // invariant: the hub sees exactly which inbox we addressed,
        // nothing about the sender or content.
        let expected_target = onyx_core::routing::introduction_inbox(&bob_fp);
        assert_eq!(outbound.target, expected_target);
        assert!(
            !outbound.body.is_empty(),
            "sealed envelope must be non-empty"
        );

        // End-to-end check: bob can decapsulate + decode and recovers
        // exactly the plaintext we sent.
        let opened =
            onyx_core::routing::open_bootstrap(&outbound.body, &bob_kem).expect("bob opens");
        let payload =
            onyx_core::routing::BootstrapPayload::from_cbor(&opened.mls_welcome).expect("decode");
        match payload {
            onyx_core::routing::BootstrapPayload::PlainMessage { text } => {
                assert_eq!(text, "first hub-relayed hello");
            }
        }
        // The opened envelope also authenticates the sender — we
        // assert this matches our local signing key so an attacker
        // who substituted the body couldn't pose as us.
        assert_eq!(opened.sender_signing_pk, sign.verifying_key());
    }

    /// Full mailbox ⇒ NotReady.
    #[tokio::test]
    async fn send_bootstrap_full_mailbox_is_not_ready() {
        let (sign, id) = fresh_signing_and_id();
        let bob_sign = SigningKey::generate();
        let bob_fp = bob_sign.verifying_key().fingerprint().to_string();
        let bob_kem = HybridKemSecret::generate();
        let bob_kem_b32 = encode_b32(&bob_kem.public().to_bytes());

        // Capacity-1 channel; don't drain it, so the second send fills it.
        let (tx, _rx_held_open) = tokio::sync::mpsc::channel(1);
        let _ = handle_send_bootstrap(&bob_fp, &bob_kem_b32, "1", &sign, &id, Some(&tx));
        let resp = handle_send_bootstrap(&bob_fp, &bob_kem_b32, "2", &sign, &id, Some(&tx));
        match resp {
            ApiResponse::Error { code, .. } => assert_eq!(code, ApiErrorCode::NotReady),
            other => panic!("expected NotReady, got {other:?}"),
        }
    }
}
