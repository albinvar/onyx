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
}

/// One response line on the wire (daemon → client). Every request
/// produces exactly one of these — no streaming variants yet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum ApiResponse {
    /// Reply to [`ApiRequest::Status`].
    StatusOk {
        api_version: u16,
        daemon_version: String,
        identity_pub_b32: String,
        fingerprint: String,
        tor_state: TorState,
    },
    /// Reply to [`ApiRequest::Identity`].
    IdentityOk {
        identity_pub_b32: String,
        fingerprint: String,
    },
    /// Catch-all error. The client matches on `code` for programmatic
    /// handling and shows `message` to the user.
    Error { code: ApiErrorCode, message: String },
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
    fn unknown_request_kind_parses_as_serde_error() {
        let err = decode_request("{\"kind\":\"NonexistentVariant\"}").expect_err("must reject");
        // Just check it failed — exact error message is serde_json's.
        assert!(!err.to_string().is_empty());
    }
}
