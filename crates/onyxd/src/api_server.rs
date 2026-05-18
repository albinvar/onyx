//! Local API server inside `onyxd`.
//!
//! Binds a Unix-domain socket (default `./onyxd.sock`, override with
//! `--api-socket`) and serves NDJSON requests defined in
//! [`onyx_core::api`]. Each accepted connection runs in its own task
//! and lives until the client closes the socket.
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
    API_VERSION, ApiErrorCode, ApiRequest, ApiResponse, TorState, decode_request,
    encode_response_line,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
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

    // Best-effort cleanup. A stale socket file is harmless on next start
    // (bind_listener removes it), but tidying up here keeps `ls` quiet.
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

    // If a stale socket file is left from a previous crash, remove it
    // — bind(2) would otherwise refuse with EADDRINUSE.
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

    // chmod 0600: owner-only RW. Do this *after* bind because the
    // socket file doesn't exist until then.
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
        let response = match decode_request(&line) {
            Ok(req) => dispatch(&req, &state, tor_state),
            Err(e) => ApiResponse::Error {
                code: ApiErrorCode::Malformed,
                message: format!("could not decode request: {e}"),
            },
        };
        let out = encode_response_line(&response)
            .map_err(|e| anyhow::anyhow!("encoding API response: {e}"))?;
        if let Err(e) = write_half.write_all(out.as_bytes()).await {
            debug!(error = %e, "API client disconnected mid-write");
            return Ok(());
        }
    }
    debug!("API client disconnected cleanly");
    Ok(())
}

/// Dispatch one decoded request to the right handler. Pure function
/// over `&DaemonState`; intentionally not async so it can't introduce
/// reordering surprises in the request/response stream.
fn dispatch(req: &ApiRequest, state: &DaemonState, tor_state: TorState) -> ApiResponse {
    match req {
        ApiRequest::Status => ApiResponse::StatusOk {
            api_version: API_VERSION,
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            identity_pub_b32: encode_b32(&state.identity.identity_key().public().to_bytes()),
            fingerprint: state.identity.fingerprint().to_string(),
            tor_state,
        },
        ApiRequest::Identity => ApiResponse::IdentityOk {
            identity_pub_b32: encode_b32(&state.identity.identity_key().public().to_bytes()),
            fingerprint: state.identity.fingerprint().to_string(),
        },
    }
}

fn encode_b32(bytes: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, bytes)
}
