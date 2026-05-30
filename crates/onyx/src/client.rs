//! Thin client over the local API socket.
//!
//! Opens a `UnixStream` to the daemon, ships one NDJSON line, parses
//! one NDJSON line back. Used by every CLI subcommand and by the
//! TUI's status refresh.

use std::path::Path;

use anyhow::Context;
use onyx_core::api::{ApiRequest, ApiResponse, decode_response, encode_request_line};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Open `socket_path`, send one `req`, read one response line, return
/// it. Closes the connection on drop.
///
/// Errors:
///   * connect failed (daemon not running, wrong path, permissions);
///   * the daemon disconnected before sending a full line;
///   * the response was not valid JSON for an [`ApiResponse`].
pub async fn one_shot(socket_path: &Path, req: &ApiRequest) -> anyhow::Result<ApiResponse> {
    let stream = UnixStream::connect(socket_path).await.with_context(|| {
        // Fresh-install UX: most users who hit this typed `onyx tui` or
        // `onyx room list` expecting the binary to do everything, not
        // realising those subcommands talk to a *running* daemon. Steer
        // them to the all-in-one (`onyx` with no subcommand) first; the
        // `onyxd` path is for headless / advanced setups.
        format!(
            "daemon not running at {} — run `onyx` (no subcommand) for the all-in-one \
             daemon+TUI, or start `onyxd` first for headless setups",
            socket_path.display()
        )
    })?;
    let (read_half, mut write_half) = stream.into_split();

    let line = encode_request_line(req).context("encode request")?;
    write_half
        .write_all(line.as_bytes())
        .await
        .context("write request")?;
    // No need to shutdown the write side — the daemon will reply
    // after seeing the newline.

    let mut lines = BufReader::new(read_half).lines();
    let resp_line = lines
        .next_line()
        .await
        .context("read response")?
        .context("daemon closed connection before responding")?;
    decode_response(&resp_line).with_context(|| format!("decode response (got: {resp_line:?})"))
}
