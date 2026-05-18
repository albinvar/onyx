//! Local API protocol between the `onyx` CLI and the `onyxd` daemon.
//!
//! ## Why a local socket
//!
//! `onyxd` holds the only copy of the unlocked vault, the long-term
//! identity keys, the MLS group state, and the Tor circuit. The
//! `onyx` CLI is intentionally stateless — it dials a Unix domain
//! socket, asks the daemon to do something on its behalf, and exits.
//! This keeps secrets in exactly one process and lets the daemon run
//! detached (tmux, systemd, login-item, whatever) without the user
//! having to keep a TUI open.
//!
//! ## Wire format: newline-delimited JSON
//!
//! One JSON object per line. Chosen over CBOR because the primary
//! debugger of this layer for the next few months is going to be the
//! shell — `nc -U ./onyxd.sock | jq` should "just work". The wire
//! format between *daemons* is still CBOR over Noise; this is only
//! the local control channel.
//!
//! Tags use `serde(tag = "kind")` so every line is self-describing:
//!
//! ```json
//! {"kind":"Status"}
//! ```
//!
//! responds with
//!
//! ```json
//! {"kind":"StatusOk","api_version":1,"daemon_version":"0.0.1",
//!  "identity_pub_b32":"...","fingerprint":"...","tor_state":"ready"}
//! ```
//!
//! ## v0 scope
//!
//! Every request gets exactly one response. No multiplexing, no
//! request IDs, no streaming, no event push. Those come later when
//! we add `send` / `tail` / `subscribe`. The current minimal set
//! exists to prove the plumbing and let `onyx status` work.
//!
//! Authentication is **file-permission-based**: `onyxd` chmods the
//! socket to `0600` after binding, so only the daemon's UID can
//! connect. No tokens, no challenge — and no SO_PEERCRED check yet
//! (we trust the kernel's permission enforcement). This matches the
//! threat model: an attacker who can read your socket can already
//! read your vault.

use serde::{Deserialize, Serialize};

/// API protocol version. Bumped whenever a request/response shape
/// changes incompatibly. The client compares this to the version it
/// was built with and refuses to talk to a daemon that returns a
/// different number.
pub const API_VERSION: u16 = 1;

/// Default Unix-domain socket path. Both daemon and CLI use this if
/// neither `--api-socket` nor `ONYX_API_SOCKET` is set.
///
/// Lives in the current working directory rather than `$XDG_RUNTIME_DIR`
/// or `$TMPDIR` to keep paths short (macOS's `sun_path` is capped at
/// 104 bytes and `/var/folders/...` already eats half of that) and
/// to make it obvious to the operator where the socket is.
pub const DEFAULT_SOCKET_PATH: &str = "./onyxd.sock";

/// One request line on the wire (client → daemon).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum ApiRequest {
    /// Liveness + identity + Tor state in one round-trip.
    Status,
    /// Just the local identity (pub key + fingerprint).
    Identity,
    /// Snapshot of currently-known conversations (live + recently
    /// disconnected). Returns [`ApiResponse::PeersOk`].
    Peers,
    /// Send `text` into the conversation identified by `peer_short`
    /// (the 8-char id from [`PeerInfo::short_id`]). The daemon will
    /// MLS-encrypt and frame it on the peer's Noise session.
    Send { peer_short: String, text: String },
    /// Subscribe to all conversation events. The server responds with
    /// [`ApiResponse::TailStarted`] and then keeps pushing
    /// `Event…` response lines until the client closes the socket.
    /// After issuing `Tail`, the client **must not** send further
    /// requests on the same connection — open another one for that.
    Tail,
    /// Fetch up to `limit` most recent messages from the per-peer
    /// ring buffer. Used by clients to backfill scrollback after a
    /// restart or after a tail subscription reconnects. Returns
    /// [`ApiResponse::HistoryOk`].
    History { peer_short: String, limit: u32 },
}

/// One response line on the wire (daemon → client).
///
/// For every request kind other than [`ApiRequest::Tail`], the daemon
/// produces **exactly one** response line and then waits for the
/// next request. `Tail` is the lone streaming verb: after the
/// initial [`ApiResponse::TailStarted`] line, the daemon may emit
/// any number of `Event…` lines until the client closes the socket.
/// No request IDs / multiplexing — open more sockets if you want
/// concurrent reads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum ApiResponse {
    // ── one-shot responses ──────────────────────────────────────────
    /// Reply to [`ApiRequest::Status`].
    StatusOk {
        api_version: u16,
        daemon_version: String,
        identity_pub_b32: String,
        fingerprint: String,
        tor_state: TorState,
        /// Hybrid (X25519 ‖ ML-KEM-768) KEM public key, base32.
        ///
        /// **Length note**: the underlying bytes are
        /// `HYBRID_PUBLIC_LEN = 1216` bytes (32 + 1184); base32 with
        /// no padding encodes that to ~1948 characters. It looks
        /// alarming on stdout but it isn't a typo — that's the
        /// real on-the-wire size of an ML-KEM-768 encapsulation key.
        ///
        /// Used by senders to address sealed-sender envelopes to
        /// this identity. Safe to publish.
        identity_kem_pub_b32: String,
    },
    /// Reply to [`ApiRequest::Identity`].
    IdentityOk {
        identity_pub_b32: String,
        fingerprint: String,
        /// See [`Self::StatusOk::identity_kem_pub_b32`] for the
        /// length-and-encoding caveat.
        identity_kem_pub_b32: String,
    },
    /// Reply to [`ApiRequest::Peers`].
    PeersOk { entries: Vec<PeerInfo> },
    /// Reply to [`ApiRequest::Send`].
    SendOk,
    /// Reply to [`ApiRequest::History`]. Messages are ordered oldest
    /// → newest. May be shorter than `limit` if fewer messages exist
    /// (or empty if the peer has no exchanged messages yet).
    HistoryOk {
        peer_short: String,
        messages: Vec<HistoryEntry>,
    },

    // ── streaming-mode ack + events (Tail only) ─────────────────────
    /// Initial ack of [`ApiRequest::Tail`]. Tells the client the
    /// daemon will now push events on this connection.
    TailStarted,
    /// An application message decrypted from `peer_short`'s
    /// conversation. `direction` distinguishes incoming from
    /// echo-of-our-own-send. `ts_unix_ms` is the daemon's wall clock
    /// at the moment of processing — not the sender's clock.
    EventMessage {
        peer_short: String,
        direction: MessageDirection,
        text: String,
        ts_unix_ms: u64,
    },
    /// A new conversation was registered with the daemon (a peer
    /// dialled in, or `onyxd --dial-*` finished its handshake).
    EventPeerConnected { peer: PeerInfo },
    /// A conversation was torn down (peer closed the stream, dial
    /// session ended, etc.). The conversation handle is gone from
    /// the registry; the client should mark the row stale.
    EventPeerDisconnected { peer_short: String },

    // ── error ───────────────────────────────────────────────────────
    /// Catch-all error. The client matches on `code` for programmatic
    /// handling and shows `message` to the user.
    Error { code: ApiErrorCode, message: String },
}

/// One row in `PeersOk`. Mirrors what the daemon's conversation
/// registry holds for each live or recently-active peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerInfo {
    /// 8-char base32 prefix of the peer's X25519 identity public key.
    /// Used as a stable user-facing handle in `Send { peer_short }`
    /// and in event lines.
    pub short_id: String,
    /// Full base32 of the peer's X25519 identity public key.
    pub pubkey_b32: String,
    /// Peer's identity fingerprint (Ed25519 signing key, base32-grouped).
    pub fingerprint: String,
    /// Whether the peer's Noise session is still open. `false` means
    /// the conversation row is just history; new `Send`s will fail.
    pub connected: bool,
    /// `Some(text_preview)` for the most recent message, `None` if
    /// nothing has been exchanged yet.
    pub last_message_preview: Option<String>,
    /// Daemon wall clock (ms since UNIX epoch) of the last activity.
    pub last_active_unix_ms: u64,
}

/// One past message in a [`ApiResponse::HistoryOk`] reply.
///
/// Shape matches the daemon's internal `ChatLine` exactly so the
/// `HistoryOk` builder can map the ring buffer 1:1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryEntry {
    pub direction: MessageDirection,
    pub text: String,
    pub ts_unix_ms: u64,
}

/// Direction of an [`ApiResponse::EventMessage`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageDirection {
    /// Decrypted from the peer — show as "them".
    Incoming,
    /// Echo of a message the local user just sent — show as "me".
    Outgoing,
}

/// Coarse-grained Tor lifecycle states reported via [`ApiResponse::StatusOk`].
///
/// v0 only distinguishes "running with Tor" from "running without
/// Tor". Granular bootstrap progress, retry-after-failure, etc. will
/// add variants here without (we hope) breaking existing clients.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TorState {
    /// `--no-tor` was passed; the daemon is online but not anonymising.
    Disabled,
    /// Arti is bootstrapped and the hidden service has been requested.
    Ready,
}

/// Programmatic error classes returned in [`ApiResponse::Error`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApiErrorCode {
    /// The request `kind` is unknown to this daemon — usually a
    /// CLI built against a newer API version than the running daemon.
    UnknownRequest,
    /// The request was understood but couldn't be served right now
    /// (e.g. Tor not yet bootstrapped). Retryable.
    NotReady,
    /// An internal daemon error. The `message` has the details. The
    /// CLI should generally surface the message verbatim.
    Internal,
    /// The request line was malformed JSON or otherwise unparseable.
    /// Always non-retryable.
    Malformed,
}

/// Encode a request as a single NDJSON line, including the trailing newline.
pub fn encode_request_line(req: &ApiRequest) -> Result<String, serde_json::Error> {
    let mut s = serde_json::to_string(req)?;
    s.push('\n');
    Ok(s)
}

/// Encode a response as a single NDJSON line, including the trailing newline.
pub fn encode_response_line(resp: &ApiResponse) -> Result<String, serde_json::Error> {
    let mut s = serde_json::to_string(resp)?;
    s.push('\n');
    Ok(s)
}

/// Parse one NDJSON request line (without the trailing newline).
pub fn decode_request(line: &str) -> Result<ApiRequest, serde_json::Error> {
    serde_json::from_str(line)
}

/// Parse one NDJSON response line (without the trailing newline).
pub fn decode_response(line: &str) -> Result<ApiResponse, serde_json::Error> {
    serde_json::from_str(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every request variant must round-trip through NDJSON exactly.
    #[test]
    fn request_round_trip_status() {
        let r = ApiRequest::Status;
        let line = encode_request_line(&r).unwrap();
        assert!(line.ends_with('\n'));
        let parsed = decode_request(line.trim_end_matches('\n')).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn request_round_trip_identity() {
        let r = ApiRequest::Identity;
        let line = encode_request_line(&r).unwrap();
        let parsed = decode_request(line.trim_end_matches('\n')).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn response_round_trip_status_ok() {
        let r = ApiResponse::StatusOk {
            api_version: API_VERSION,
            daemon_version: "0.0.1".into(),
            identity_pub_b32: "abcdef".into(),
            fingerprint: "deadbeef".into(),
            tor_state: TorState::Ready,
            identity_kem_pub_b32: "long-b32-string-stand-in".into(),
        };
        let line = encode_response_line(&r).unwrap();
        let parsed = decode_response(line.trim_end_matches('\n')).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn response_round_trip_identity_ok() {
        let r = ApiResponse::IdentityOk {
            identity_pub_b32: "abc".into(),
            fingerprint: "def".into(),
            identity_kem_pub_b32: "long-b32-stand-in".into(),
        };
        let line = encode_response_line(&r).unwrap();
        let parsed = decode_response(line.trim_end_matches('\n')).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn response_round_trip_error_each_code() {
        for code in [
            ApiErrorCode::UnknownRequest,
            ApiErrorCode::NotReady,
            ApiErrorCode::Internal,
            ApiErrorCode::Malformed,
        ] {
            let r = ApiResponse::Error {
                code,
                message: "test".into(),
            };
            let line = encode_response_line(&r).unwrap();
            let parsed = decode_response(line.trim_end_matches('\n')).unwrap();
            assert_eq!(parsed, r);
        }
    }

    /// The wire format must be stable and human-readable; assert the
    /// literal JSON for one variant so accidental tag-renames break
    /// loudly.
    #[test]
    fn status_request_wire_shape() {
        let line = encode_request_line(&ApiRequest::Status).unwrap();
        assert_eq!(line, "{\"kind\":\"Status\"}\n");
    }

    #[test]
    fn tor_state_wire_shape() {
        // Lowercase via `serde(rename_all="snake_case")`.
        let s = serde_json::to_string(&TorState::Disabled).unwrap();
        assert_eq!(s, "\"disabled\"");
        let s = serde_json::to_string(&TorState::Ready).unwrap();
        assert_eq!(s, "\"ready\"");
    }

    #[test]
    fn request_round_trip_peers() {
        let r = ApiRequest::Peers;
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn request_round_trip_send() {
        let r = ApiRequest::Send {
            peer_short: "u5lhmxps".into(),
            text: "hello bob".into(),
        };
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn request_round_trip_tail() {
        let r = ApiRequest::Tail;
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn response_round_trip_peers_ok() {
        let r = ApiResponse::PeersOk {
            entries: vec![PeerInfo {
                short_id: "u5lhmxps".into(),
                pubkey_b32: "u5lhmxpsxxxx".into(),
                fingerprint: "fpr".into(),
                connected: true,
                last_message_preview: Some("hi".into()),
                last_active_unix_ms: 1_700_000_000_000,
            }],
        };
        let line = encode_response_line(&r).unwrap();
        assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn response_round_trip_send_ok_and_tail_started() {
        for r in [ApiResponse::SendOk, ApiResponse::TailStarted] {
            let line = encode_response_line(&r).unwrap();
            assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
        }
    }

    #[test]
    fn response_round_trip_event_message_both_directions() {
        for direction in [MessageDirection::Incoming, MessageDirection::Outgoing] {
            let r = ApiResponse::EventMessage {
                peer_short: "u5lhmxps".into(),
                direction,
                text: "x".into(),
                ts_unix_ms: 1_700_000_000_001,
            };
            let line = encode_response_line(&r).unwrap();
            assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
        }
    }

    #[test]
    fn response_round_trip_event_peer_connect_and_disconnect() {
        let connected = ApiResponse::EventPeerConnected {
            peer: PeerInfo {
                short_id: "u5lhmxps".into(),
                pubkey_b32: "u5lhmxpsxxxxxxxxxxxxxxxx".into(),
                fingerprint: "fpr".into(),
                connected: true,
                last_message_preview: None,
                last_active_unix_ms: 1,
            },
        };
        let disconnected = ApiResponse::EventPeerDisconnected {
            peer_short: "u5lhmxps".into(),
        };
        for r in [connected, disconnected] {
            let line = encode_response_line(&r).unwrap();
            assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
        }
    }

    #[test]
    fn request_round_trip_history() {
        let r = ApiRequest::History {
            peer_short: "u5lhmxps".into(),
            limit: 50,
        };
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn response_round_trip_history_ok() {
        let r = ApiResponse::HistoryOk {
            peer_short: "u5lhmxps".into(),
            messages: vec![
                HistoryEntry {
                    direction: MessageDirection::Incoming,
                    text: "hi".into(),
                    ts_unix_ms: 1_700_000_000_000,
                },
                HistoryEntry {
                    direction: MessageDirection::Outgoing,
                    text: "hey".into(),
                    ts_unix_ms: 1_700_000_000_001,
                },
            ],
        };
        let line = encode_response_line(&r).unwrap();
        assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn response_round_trip_history_ok_empty() {
        let r = ApiResponse::HistoryOk {
            peer_short: "fresh".into(),
            messages: vec![],
        };
        let line = encode_response_line(&r).unwrap();
        assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn unknown_request_kind_parses_as_serde_error() {
        let err = decode_request("{\"kind\":\"NonexistentVariant\"}").expect_err("must reject");
        // Just check it failed — exact error message is serde_json's.
        assert!(!err.to_string().is_empty());
    }
}
