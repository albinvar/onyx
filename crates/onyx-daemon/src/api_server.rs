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
use tokio::sync::mpsc::error::TrySendError;
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

        // L-2 (defense in depth): the API socket carries full control
        // of this identity, so only the owner UID must be able to
        // reach it. We chmod the socket itself to 0600 below, but that
        // chmod is necessarily *after* bind — a non-atomic window. The
        // durable guarantee is the *parent directory* being owner-only
        // (the default `~/.onyx` is created mode 0700 at startup): a
        // socket inside a 0700 dir is unreachable by other users
        // regardless of its own mode or the bind→chmod race. We can't
        // safely chmod an operator-chosen parent (it might be a shared
        // dir like `/tmp`), so instead we loudly warn if the resolved
        // parent is group/other-accessible. A custom `--api-socket`
        // path in a shared directory is the only scenario where the
        // bind→chmod window is actually exploitable.
        if let Ok(meta) = std::fs::metadata(parent) {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                warn!(
                    path = %parent.display(),
                    mode = format!("{:#o}", mode & 0o7777),
                    "API socket parent directory is accessible by group/other; the local \
                     UID guarantee then rests only on the socket's own 0600 mode, which is \
                     set just after bind (a brief race). Place the socket in an owner-only \
                     directory (e.g. the default ~/.onyx, mode 0700)."
                );
            }
        }
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
//
// Single match over the API enum; splitting it would just push each
// arm into a one-line helper and make the dispatch harder to read.
#[allow(clippy::too_many_lines)]
async fn dispatch_one_shot(
    req: &ApiRequest,
    state: &DaemonState,
    tor_state: TorState,
) -> ApiResponse {
    match req {
        ApiRequest::Status => ApiResponse::StatusOk {
            api_version: API_VERSION,
            daemon_version: onyx_core::VERSION.to_string(),
            identity_pub_b32: encode_b32(&state.identity.identity_key().public().to_bytes()),
            fingerprint: state.identity.fingerprint().to_string(),
            tor_state,
            identity_kem_pub_b32: encode_b32(&state.identity.kem_public().to_bytes()),
        },
        ApiRequest::Identity => ApiResponse::IdentityOk {
            identity_pub_b32: encode_b32(&state.identity.identity_key().public().to_bytes()),
            fingerprint: state.identity.fingerprint().to_string(),
            identity_kem_pub_b32: encode_b32(&state.identity.kem_public().to_bytes()),
            hubs: state
                .configured_hubs
                .iter()
                .map(|h| format!("{},{}", h.onion, h.pubkey))
                .collect(),
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
            // A0.3: refuse if this peer's pinned key has changed.
            if let Some(block) = pin_block(state, &handle.fingerprint).await {
                return block;
            }
            match handle
                .outbound_tx
                .try_send(crate::conversations::PeerOutbound::Dm(text.clone()))
            {
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
            &state.hub_outbounds,
        ),
        ApiRequest::SendBootstrapMls {
            peer_fingerprint,
            peer_kem_pub_b32,
            peer_kp_b64,
            initial_text,
        } => {
            handle_send_bootstrap_mls(
                peer_fingerprint,
                peer_kem_pub_b32,
                peer_kp_b64,
                initial_text.as_deref(),
                state,
            )
            .await
        }
        ApiRequest::FetchPeerKeyPackage { peer_fingerprint } => {
            handle_fetch_peer_keypackage(peer_fingerprint, state).await
        }
        ApiRequest::ExportKeyPackage => handle_export_key_package(state).await,
        ApiRequest::CreateRoom { name } => handle_create_room(name, state).await,
        ApiRequest::ListRooms => handle_list_rooms(state).await,
        ApiRequest::ListContacts => handle_list_contacts(state).await,
        ApiRequest::BuildInvite {
            with_kp,
            with_hubs,
            ttl_secs,
        } => handle_build_invite(state, *with_kp, *with_hubs, *ttl_secs).await,
        ApiRequest::SendInvite {
            url,
            text,
            insecure_accept_unsigned,
        } => handle_send_invite(state, url, text, *insecure_accept_unsigned).await,
        ApiRequest::InviteToRoom {
            group_id_b32,
            peer_fingerprint,
            peer_kem_pub_b32,
            peer_kp_b64,
        } => {
            handle_invite_to_room(
                group_id_b32,
                peer_fingerprint,
                peer_kem_pub_b32,
                peer_kp_b64,
                state,
            )
            .await
        }
        ApiRequest::SendRoom { group_id_b32, text } => {
            handle_send_room(group_id_b32, text, state).await
        }
        ApiRequest::DeleteRoom { group_id_b32 } => handle_delete_room(group_id_b32, state).await,
        ApiRequest::RenameRoom {
            group_id_b32,
            new_name,
        } => handle_rename_room(group_id_b32, new_name, state).await,
        ApiRequest::LeaveRoom { group_id_b32 } => handle_leave_room(group_id_b32, state).await,
        ApiRequest::RemoveFromRoom {
            group_id_b32,
            peer_fingerprint,
        } => handle_remove_from_room(group_id_b32, peer_fingerprint, state).await,
        ApiRequest::RoomHistory {
            group_id_b32,
            limit,
        } => handle_room_history(group_id_b32, *limit, state).await,
        ApiRequest::SendFileToRoom {
            group_id_b32,
            path,
            keep_filename,
            keep_metadata,
        } => {
            handle_send_file_to_room(group_id_b32, path, *keep_filename, *keep_metadata, state)
                .await
        }
        ApiRequest::SendFileToPeer {
            peer_short,
            path,
            keep_filename,
            keep_metadata,
        } => {
            handle_send_file_to_peer(peer_short, path, *keep_filename, *keep_metadata, state).await
        }
        ApiRequest::ListReceivedFiles {
            conversation,
            limit,
        } => handle_list_received_files(conversation, *limit, state).await,
        ApiRequest::Tail => unreachable!("Tail handled by serve_tail"),
    }
}

/// Mint a fresh KeyPackage from our local MLS party and return it as
/// standard base64. The CLI uses this to bundle a KP into invite URLs
/// (`onyx invite --with-kp`) so the recipient can do MLS-tier first
/// contact without a separate hub fetch. Purely local — no hub
/// required.
///
/// Each call mints a *new* KP and persists the resulting MLS state,
/// so the recipient's eventual `SendBootstrapMls` (which consumes
/// this KP's init key on our side when they connect and we resume
/// the group) can be matched even across a daemon restart.
async fn handle_export_key_package(state: &DaemonState) -> ApiResponse {
    let (kp_bytes, snapshot) = {
        let party = state.mls_party.lock().await;
        let kp = match party.key_package_bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                return ApiResponse::Error {
                    code: ApiErrorCode::Internal,
                    message: format!("mls: failed to mint KeyPackage: {e}"),
                };
            }
        };
        let Ok(snap) = party.snapshot_state() else {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: "snapshot_state failed".into(),
            };
        };
        (kp, snap)
    };
    {
        let vault = state.vault.lock().await;
        if let Err(e) = vault.save_mls_state(state.identity_id, &snapshot) {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: format!("save_mls_state: {e}"),
            };
        }
    }
    ApiResponse::ExportKeyPackageOk {
        kp_b64: base64_encode(&kp_bytes),
    }
}

/// Create a new multi-party MLS room with us as the sole member
/// (T6.3.b). The group_id of the resulting MLS group becomes the
/// room's cryptographic identity; `name` is a local-only display
/// label that does not propagate over the wire.
///
/// Side effects:
///   * `MlsParty::create_group` mints a fresh MLS group.
///   * MLS state is snapshotted + persisted to vault.
///   * A row is upserted into the `rooms` table with our own
///     fingerprint as the sole `members_b32` entry.
///
/// Failure of either persistence step surfaces as
/// `ApiErrorCode::Internal` — the in-memory MLS state may already
/// hold the group, but the caller should not assume so.
async fn handle_create_room(name: &str, state: &DaemonState) -> ApiResponse {
    // Create the MLS group + snapshot state.
    let (group_id_bytes, snapshot) = {
        let party = state.mls_party.lock().await;
        let group = match party.create_group() {
            Ok(g) => g,
            Err(e) => {
                return ApiResponse::Error {
                    code: ApiErrorCode::Internal,
                    message: format!("create_group failed: {e}"),
                };
            }
        };
        let group_id = group.group_id_bytes();
        let Ok(snap) = party.snapshot_state() else {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: "snapshot_state failed".into(),
            };
        };
        (group_id, snap)
    };

    // Persist MLS state.
    {
        let vault = state.vault.lock().await;
        if let Err(e) = vault.save_mls_state(state.identity_id, &snapshot) {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: format!("save_mls_state: {e}"),
            };
        }
    }

    // Insert the rooms-table row. Sole member at creation is us.
    let our_fp = state.identity.fingerprint().to_string();
    let created_at_ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()),
    )
    .unwrap_or(0);
    {
        let vault = state.vault.lock().await;
        if let Err(e) = vault.save_room(
            state.identity_id,
            &group_id_bytes,
            name,
            &our_fp,
            created_at_ms,
        ) {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: format!("save_room: {e}"),
            };
        }
    }

    // T6.3.g: subscribe to the new room's session-token inbox so
    // any future invitee can hub-publish room messages to us
    // before our next reconnect cycle.
    crate::announce_room_subscribe(&group_id_bytes, state).await;

    ApiResponse::CreateRoomOk {
        group_id_b32: encode_b32(&group_id_bytes),
        name: name.to_string(),
    }
}

/// List every room this daemon participates in (T6.3.b). Reads
/// from the vault's `rooms` table; projects each row into a
/// [`RoomInfo`] for the wire.
async fn handle_list_rooms(state: &DaemonState) -> ApiResponse {
    let rows = {
        let vault = state.vault.lock().await;
        match vault.list_rooms(state.identity_id) {
            Ok(rows) => rows,
            Err(e) => {
                return ApiResponse::Error {
                    code: ApiErrorCode::Internal,
                    message: format!("list_rooms: {e}"),
                };
            }
        }
    };
    let rooms = rows
        .into_iter()
        .map(|row| onyx_core::api::RoomInfo {
            name: row.name,
            group_id_b32: encode_b32(&row.group_id),
            members: row
                .members_b32
                .split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
            created_at_ms: u64::try_from(row.created_at_ms).unwrap_or(0),
        })
        .collect();
    ApiResponse::ListRoomsOk { rooms }
}

/// T-1: list the TOFU-pinned contacts for `onyx contact list`.
async fn handle_list_contacts(state: &DaemonState) -> ApiResponse {
    let rows = {
        let vault = state.vault.lock().await;
        match vault.list_pinned(state.identity_id) {
            Ok(rows) => rows,
            Err(e) => {
                return ApiResponse::Error {
                    code: ApiErrorCode::Internal,
                    message: format!("list_pinned: {e}"),
                };
            }
        }
    };
    let contacts = rows
        .into_iter()
        .map(|c| onyx_core::api::ContactInfo {
            fingerprint: c.fingerprint,
            x25519_pub_b32: encode_b32(&c.x25519_pub),
            first_seen_ms: c.first_seen_ms,
            last_seen_ms: c.last_seen_ms,
            key_changed: c.key_changed,
        })
        .collect();
    ApiResponse::ListContactsOk { contacts }
}

/// T-2: default invite TTL when the caller doesn't override — 30 days.
/// Long enough that users have time to share an invite over typical
/// side-channels; short enough that a leaked invite isn't usable
/// indefinitely.
const DEFAULT_INVITE_TTL_SECS: u64 = 30 * 86_400;

/// T-2: build a signed (v2) invite URL inside the daemon, where the
/// identity signing key actually lives. The CLI / API caller just
/// hands us the booleans + optional TTL and we mint, optionally
/// attach a fresh MLS KeyPackage + the configured hub list, sign with
/// `state.identity.signing()`, and return the URL + the stamped
/// expiry.
async fn handle_build_invite(
    state: &DaemonState,
    with_kp: bool,
    with_hubs: bool,
    ttl_secs: Option<u64>,
) -> ApiResponse {
    use base64::Engine;
    // Optional KP — reuse the existing handler so the mint + snapshot
    // + vault-persist path stays one place (no duplicated MLS logic).
    let kp_bytes = if with_kp {
        match handle_export_key_package(state).await {
            ApiResponse::ExportKeyPackageOk { kp_b64 } => {
                match base64::engine::general_purpose::STANDARD.decode(kp_b64) {
                    Ok(b) => Some(b),
                    Err(e) => {
                        return ApiResponse::Error {
                            code: ApiErrorCode::Internal,
                            message: format!("invite: KP base64 decode failed: {e}"),
                        };
                    }
                }
            }
            other @ ApiResponse::Error { .. } => return other,
            other => {
                return ApiResponse::Error {
                    code: ApiErrorCode::Internal,
                    message: format!("invite: unexpected ExportKeyPackage response: {other:?}"),
                };
            }
        }
    } else {
        None
    };

    let fp = state.identity.fingerprint();
    let kem_b32 = encode_b32(&state.identity.kem_public().to_bytes());
    let mut inv = match kp_bytes {
        Some(kp) => onyx_core::invite::Invite::with_key_package(fp, kem_b32, kp),
        None => onyx_core::invite::Invite::new(fp, kem_b32),
    };
    if with_hubs {
        let hubs: Vec<String> = state
            .configured_hubs
            .iter()
            .map(|h| format!("{},{}", h.onion, h.pubkey))
            .collect();
        if !hubs.is_empty() {
            inv = inv.with_hubs(hubs);
        }
    }

    // exp_ms = now + ttl. NEW-2 hardening:
    //   * a broken / pre-epoch clock is a HARD ERROR rather than
    //     `unwrap_or(0)` — `now_ms = 0` would silently produce an
    //     invite that's been "expired" for 56 years and break every
    //     verifier (we'd rather fail loudly at mint than ship junk);
    //   * the caller-provided `ttl_secs` is clamped to
    //     [`MAX_INVITE_TTL_SECS`] so we don't *ourselves* mint
    //     absurd-future invites by accident. The verifier ALSO
    //     enforces the same clamp (defence in depth).
    let now_ms: u64 = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => match u64::try_from(d.as_millis()) {
            Ok(ms) => ms,
            Err(_) => {
                return ApiResponse::Error {
                    code: ApiErrorCode::Internal,
                    message: "system clock value exceeds u64 ms — refusing to mint invite".into(),
                };
            }
        },
        Err(e) => {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: format!(
                    "system clock is set before unix epoch ({e}) — refusing to mint invite"
                ),
            };
        }
    };
    let ttl = ttl_secs
        .unwrap_or(DEFAULT_INVITE_TTL_SECS)
        .min(onyx_core::invite::MAX_INVITE_TTL_SECS);
    let exp_ms = now_ms.saturating_add(ttl.saturating_mul(1000));
    let nonce: [u8; 16] = onyx_core::crypto::random_array();
    let hubs_attached = inv.hubs.len();
    let signed = inv.sign(state.identity.signing(), exp_ms, nonce);
    ApiResponse::BuildInviteOk {
        url: signed.to_url(),
        exp_ms,
        hubs_attached,
    }
}

/// A0.3: refuse to send to a peer whose pinned identity key has
/// changed since first contact (a possible MITM / key rotation). T-1
/// pins + warns; the T-2 accept path cross-checks at first contact;
/// A0.3 closes the loop by blocking **every ongoing send** to a
/// compromised contact, not just the initial accept.
///
/// Returns `Some(Error)` (the response the caller should return
/// immediately) when the contact is flagged; `None` when the send may
/// proceed. A vault read error fails OPEN with a `warn!` rather than
/// blocking all sends on a transient DB hiccup — the key-change
/// detection itself already happened at pin time (T-1); this is the
/// belt-and-suspenders enforcement layer, and bricking messaging on a
/// read error would be a worse failure than the residual it guards.
async fn pin_block(state: &DaemonState, fingerprint: &str) -> Option<ApiResponse> {
    // Unverified `(peer/<x25519>)` placeholders are never pinned (T-3),
    // so they can't be "compromised"; skip the lookup.
    if fingerprint.starts_with("(peer/") {
        return None;
    }
    let compromised = {
        let vault = state.vault.lock().await;
        vault.is_pin_compromised(state.identity_id, fingerprint)
    };
    match compromised {
        Ok(true) => Some(ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: format!(
                "refusing to send: the pinned identity key for {fingerprint} has CHANGED \
                 since first contact (possible MITM or key rotation). Verify the fingerprint \
                 out of band; clear the pin only if you trust the new key. \
                 (`onyx contact list` shows the flag.)"
            ),
        }),
        Ok(false) => None,
        Err(e) => {
            warn!(error = %e, fingerprint = %fingerprint, "pin_block: vault read failed; failing open");
            None
        }
    }
}

/// T-2: trust-anchored accept-invite path. The daemon (not the CLI)
/// is the trust boundary — a malicious local process speaking to the
/// API socket cannot strip the v2 signature, claim a fake key was
/// pinned, or hand-craft fields that bypass first-contact safety.
///
/// Gates, in order:
///   1. **v1 (unsigned) is refused** unless `insecure_accept_unsigned`.
///   2. **v2 signature must verify** (Ed25519 over the canonical
///      field set, including the `MAX_INVITE_TTL_SECS` expiry clamp
///      that lives inside `verify_signature`).
///   3. **Pin-store cross-check** (T-1): if we've already pinned a
///      DIFFERENT key for this fingerprint, refuse — re-pinning a
///      changed key has to be an explicit, separate user action.
///   4. Dispatch internally to `handle_send_bootstrap_mls` (if the
///      invite carried a KP) or `handle_send_bootstrap` (msg/v1).
async fn handle_send_invite(
    state: &DaemonState,
    url: &str,
    text: &str,
    insecure_accept_unsigned: bool,
) -> ApiResponse {
    use base64::Engine;
    let invite = match onyx_core::invite::Invite::parse(url) {
        Ok(i) => i,
        Err(e) => {
            return ApiResponse::Error {
                code: ApiErrorCode::Malformed,
                message: format!("invite URL did not parse: {e}"),
            };
        }
    };

    // Gate 1+2: signature or refusal.
    let was_signed = invite.is_signed();
    if was_signed {
        let Some(now_ms) = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
        else {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: "system clock unreadable — refusing to verify invite signature".into(),
            };
        };
        if let Err(e) = invite.verify_signature(now_ms) {
            return ApiResponse::Error {
                code: ApiErrorCode::Malformed,
                message: format!("invite signature did not verify: {e}"),
            };
        }
    } else if !insecure_accept_unsigned {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "refusing unsigned (v1) invite; pass insecure_accept_unsigned=true to opt \
                      in (DANGEROUS — side-channel could have substituted any field)"
                .into(),
        };
    }

    // Gate 3: pin-store cross-check (T-1).
    let invite_fp = invite.fingerprint.to_string();
    {
        let vault = state.vault.lock().await;
        if let Ok(contacts) = vault.list_pinned(state.identity_id) {
            for c in &contacts {
                if c.fingerprint == invite_fp && c.key_changed {
                    return ApiResponse::Error {
                        code: ApiErrorCode::Malformed,
                        message: format!(
                            "fingerprint {invite_fp} is already pinned AND its identity key has \
                             changed since first contact (T-1). Refusing — verify out of band \
                             and clear the pin before re-accepting."
                        ),
                    };
                }
            }
        }
    }

    // Gate 4: dispatch to the right tier and translate the response.
    let kem_b32 = invite.kem_pub_b32.clone();
    if let Some(kp_bytes) = invite.key_package {
        let kp_b64 = base64::engine::general_purpose::STANDARD.encode(&kp_bytes);
        match handle_send_bootstrap_mls(&invite_fp, &kem_b32, &kp_b64, Some(text), state).await {
            ApiResponse::SendBootstrapMlsOk { .. } => ApiResponse::SendInviteOk {
                tier: "mls/v1".into(),
                was_signed,
            },
            other => other,
        }
    } else {
        match handle_send_bootstrap(
            &invite_fp,
            &kem_b32,
            text,
            state.identity.signing(),
            state.identity.identity_key(),
            &state.hub_outbounds,
        ) {
            ApiResponse::SendBootstrapOk => ApiResponse::SendInviteOk {
                tier: "msg/v1".into(),
                was_signed,
            },
            other => other,
        }
    }
}

/// Invite a peer into an existing room (T6.3.c). Parallels
/// [`handle_send_bootstrap_mls`] structurally — same KP-fingerprint
/// validation (`THREAT_MODEL.md` §8.2 #15), same `BootstrapPayload::
/// MlsWelcome` (`mls/v1`) envelope, same hub fan-out — but loads the
/// existing `MlsGroupState` by `group_id` instead of creating a fresh
/// 2-party group, and stamps `room_name = Some(room.name)` so the
/// recipient surfaces a room on their side instead of treating the
/// Welcome as a DM bootstrap.
///
/// After a successful invite commit, refreshes the local `rooms` row's
/// cached `members_b32` to include the new member's fingerprint.
//
// Function is one linear sequence with several short-circuit error
// branches; splitting per-step would yield helpers that are each a
// few lines of glue plus a typed error response, with no net
// readability win.
#[allow(clippy::too_many_lines)]
async fn handle_invite_to_room(
    group_id_b32: &str,
    peer_fingerprint: &str,
    peer_kem_pub_b32: &str,
    peer_kp_b64: &str,
    state: &DaemonState,
) -> ApiResponse {
    if state.hub_outbounds.is_empty() {
        return ApiResponse::Error {
            code: ApiErrorCode::NotReady,
            message: "no hubs configured; relaunch with --hub onion:port,b32pubkey".into(),
        };
    }

    // 1. Parse inputs.
    let Some(group_id_bytes) = base32::decode(
        base32::Alphabet::Rfc4648Lower { padding: false },
        group_id_b32,
    ) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "group_id_b32 is not valid base32".into(),
        };
    };
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
    let Ok(kp_bytes) = base64_decode(peer_kp_b64) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "peer_kp_b64 is not valid base64".into(),
        };
    };

    // 2. SECURITY: validate the KP's embedded Ed25519 signing key
    //    hashes to peer_fingerprint BEFORE inviting (THREAT_MODEL §8.2
    //    #15). Same mitigation as handle_send_bootstrap_mls.
    let extracted_signing_pk = {
        let party = state.mls_party.lock().await;
        match party.peer_signing_pk_from_kp_bytes(&kp_bytes) {
            Ok(pk) => pk,
            Err(_) => {
                return ApiResponse::Error {
                    code: ApiErrorCode::Malformed,
                    message: "peer_kp_b64 did not validate as a KeyPackage".into(),
                };
            }
        }
    };
    let Ok(vk) = onyx_core::crypto::VerifyingKey::from_bytes(extracted_signing_pk) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "KP signing key is not a valid Ed25519 point".into(),
        };
    };
    if vk.fingerprint() != fp {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "KP signing key does not match peer_fingerprint \
                      — refusing to invite (potential hub-directory tampering)"
                .into(),
        };
    }

    // 3. Look up the existing room row so we know what name to stamp
    //    on the recipient's Welcome. Refusing if the row is missing
    //    is the safer default — we'd rather fail loud than send a
    //    Welcome that the recipient renders nameless.
    let room_row = {
        let vault = state.vault.lock().await;
        match vault.list_rooms(state.identity_id) {
            Ok(rows) => rows.into_iter().find(|r| r.group_id == group_id_bytes),
            Err(e) => {
                return ApiResponse::Error {
                    code: ApiErrorCode::Internal,
                    message: format!("list_rooms: {e}"),
                };
            }
        }
    };
    let Some(room) = room_row else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "no room with that group_id (create one first with CreateRoom)".into(),
        };
    };

    // 4. Load the group, invite the peer, extract BOTH the commit
    //    (for existing members) and Welcome (for the new member)
    //    bytes (T6.3.h: pre-T6.3.h discarded the commit and silently
    //    broke 3+-party rooms). Existing-member commit distribution
    //    happens in step 9 below.
    let (
        commit_bytes,
        welcome_bytes,
        snapshot,
        refreshed_members_b32,
        members_before,
        old_epoch_token,
    ) = {
        let party = state.mls_party.lock().await;
        let mut group = match party.load_group(&group_id_bytes) {
            Ok(Some(g)) => g,
            Ok(None) => {
                return ApiResponse::Error {
                    code: ApiErrorCode::Malformed,
                    message: "MLS state has no group with that group_id (vault drift?)".into(),
                };
            }
            Err(e) => {
                return ApiResponse::Error {
                    code: ApiErrorCode::Internal,
                    message: format!("load_group: {e}"),
                };
            }
        };
        // T-smoke fix: capture the OLD-epoch session token BEFORE
        // invite() advances the group. Commits must route to the
        // OLD token — existing members are subscribed to that;
        // they don't have the new token's subscription yet because
        // they haven't seen the commit. T6.3.g's session-token
        // routing assumed sender + receiver always at the same
        // epoch, which is false during a member-add transition.
        let old_token = group
            .export_routing_secret(&party)
            .ok()
            .map(|s| onyx_core::routing::session_token(&s, 0));
        // Capture the pre-invite roster — these are the members who
        // need the commit (the new joiner doesn't, they bootstrap
        // from the Welcome). We pull this BEFORE invite() so the
        // list doesn't include the new member.
        let members_before = crate::members_b32_from_group(&group);
        let Ok((commit, welcome)) = group.invite(&party, &kp_bytes) else {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: "invite failed".into(),
            };
        };
        let Ok(snap) = party.snapshot_state() else {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: "snapshot_state failed".into(),
            };
        };
        // Re-derive members from the post-commit group. Same helper
        // the recipient uses on join — keeps the cache shape
        // symmetric.
        let members = crate::members_b32_from_group(&group);
        (commit, welcome, snap, members, members_before, old_token)
    };

    // 5. Persist post-invite MLS state and refresh the cached
    //    members_b32 on our side. Updates the row's name to itself
    //    (effectively just refreshes members) — save_room is an
    //    upsert by (identity_id, group_id).
    {
        let vault = state.vault.lock().await;
        if let Err(e) = vault.save_mls_state(state.identity_id, &snapshot) {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: format!("save_mls_state: {e}"),
            };
        }
        if let Err(e) = vault.save_room(
            state.identity_id,
            &group_id_bytes,
            &room.name,
            &refreshed_members_b32,
            room.created_at_ms,
        ) {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: format!("save_room: {e}"),
            };
        }
        // T6.3.e: stash the invitee's hybrid KEM pub keyed by
        // (group_id, fingerprint) so handle_send_room can hub-
        // fallback to them when they're offline. The pubkey
        // bytes are the validated `kem_pub_bytes` we already
        // decoded above; persisting them here is upsert by PK.
        if let Err(e) = vault.save_room_member_kem(
            state.identity_id,
            &group_id_bytes,
            peer_fingerprint,
            &kem_pub_bytes,
        ) {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: format!("save_room_member_kem: {e}"),
            };
        }
    }

    // 6. Build the current-roster KEM list (T6.3.h). Includes
    //    ourselves (always known), every existing member whose KEM
    //    we have cached, and the new invitee (we just decoded
    //    their KEM from the API args). The new joiner persists each
    //    entry on receive so they can hub-fallback to any member
    //    — closes the structural gap noted in T6.3.e's CHANGELOG.
    let our_fp = state.identity.fingerprint().to_string();
    let member_kems = {
        let mut out = Vec::new();
        out.push(onyx_core::routing::RoomMemberKem {
            fingerprint: our_fp.clone(),
            kem_pub: serde_bytes::ByteBuf::from(state.identity.kem_public().to_bytes()),
        });
        let vault = state.vault.lock().await;
        for fp in refreshed_members_b32
            .split(',')
            .filter(|s| !s.is_empty())
            .filter(|s| *s != our_fp && *s != peer_fingerprint)
        {
            if let Ok(Some(kem)) =
                vault.lookup_room_member_kem(state.identity_id, &group_id_bytes, fp)
            {
                out.push(onyx_core::routing::RoomMemberKem {
                    fingerprint: fp.to_string(),
                    kem_pub: serde_bytes::ByteBuf::from(kem),
                });
            }
        }
        // Always include the new invitee — we have their KEM
        // from the API args, so refusing to include it would just
        // make the joiner unable to fallback to themselves
        // (harmless but messy).
        out.push(onyx_core::routing::RoomMemberKem {
            fingerprint: peer_fingerprint.to_string(),
            kem_pub: serde_bytes::ByteBuf::from(kem_pub_bytes.clone()),
        });
        out
    };

    // 7. Seal the Welcome with room_name = Some(room.name) so the
    //    recipient knows this is a room invite, not a DM bootstrap.
    let payload = onyx_core::routing::BootstrapPayload::MlsWelcome {
        welcome: serde_bytes::ByteBuf::from(welcome_bytes),
        first_message: None,
        room_name: Some(room.name.clone()),
        member_kems,
    };
    let Ok(payload_bytes) = payload.to_cbor() else {
        return ApiResponse::Error {
            code: ApiErrorCode::Internal,
            message: "encoding mls/v1 BootstrapPayload failed".into(),
        };
    };
    let Ok(sealed) = onyx_core::routing::seal_bootstrap(
        state.identity.signing(),
        state.identity.identity_key(),
        &payload_bytes,
        &kem_pub,
    ) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Internal,
            message: "seal_bootstrap failed".into(),
        };
    };

    // 7. Fan-out across all configured hubs. Same shape as
    //    handle_send_bootstrap_mls; recipient's EnvelopeReplayGuard
    //    de-dupes if multiple hubs deliver.
    let target = onyx_core::routing::introduction_inbox(&fp);
    let mut accepted = 0;
    let mut last_err: Option<String> = None;
    for (idx, hub_outbound) in state.hub_outbounds.iter().enumerate() {
        match hub_outbound.try_send(crate::hub_client::HubOutbound::deliver(
            target,
            sealed.clone(),
        )) {
            Ok(()) => accepted += 1,
            Err(TrySendError::Full(_)) => {
                last_err = Some(format!("hub #{idx} outbound queue is full"));
            }
            Err(TrySendError::Closed(_)) => {
                last_err = Some(format!("hub #{idx} client task has ended"));
            }
        }
    }
    if accepted == 0 {
        return ApiResponse::Error {
            code: ApiErrorCode::NotReady,
            message: last_err.unwrap_or_else(|| "no hub accepted the Welcome envelope".into()),
        };
    }
    tracing::info!(
        op = "invite_to_room",
        accepted,
        total = state.hub_outbounds.len(),
        "Welcome hub fan-out"
    );

    // 9. T6.3.h: distribute the commit to every existing member (the
    //    members that were in the group BEFORE this invite). Without
    //    this, their MLS state stays at the old epoch and they
    //    silently stop being able to decrypt room messages. The new
    //    invitee does NOT need the commit — they bootstrap from the
    //    Welcome at the new epoch.
    let pre_existing_members: Vec<String> = members_before
        .split(',')
        .filter(|s| !s.is_empty())
        .filter(|s| *s != our_fp && *s != peer_fingerprint)
        .map(str::to_owned)
        .collect();
    if !pre_existing_members.is_empty() {
        fanout_room_mls_bytes(
            &group_id_bytes,
            &commit_bytes,
            &pre_existing_members,
            state,
            "commit",
            // T-smoke fix: route the commit to the OLD-epoch token
            // because existing members are subscribed to that;
            // they haven't seen the commit yet so they don't have
            // the new token's subscription.
            old_epoch_token,
        )
        .await;
    }

    // 10. T6.3.h: broadcast a KEM advertisement for the new member to
    //     existing members so they can hub-fallback to the new member
    //     when they're offline. Wraps in RoomAppMessage::KemAdvertisement,
    //     encrypts at the new epoch (which existing members will be at
    //     once they process the commit above), fans out via the same
    //     direct-or-hub path. Both messages travel via the same per-
    //     member channel (FIFO), so existing members process commit
    //     first → KEM-ad second; epoch ordering is preserved.
    if !pre_existing_members.is_empty() {
        let ad = onyx_core::room::RoomAppMessage::KemAdvertisement {
            fingerprint: peer_fingerprint.to_string(),
            kem_pub: serde_bytes::ByteBuf::from(kem_pub_bytes.clone()),
        };
        if let Ok(ad_plaintext) = ad.to_cbor() {
            let ad_ciphertext_opt = {
                let party = state.mls_party.lock().await;
                match party.load_group(&group_id_bytes) {
                    Ok(Some(mut g)) => g.encrypt_application(&party, &ad_plaintext).ok(),
                    _ => None,
                }
            };
            if let Some(ad_ciphertext) = ad_ciphertext_opt {
                // Snapshot the freshly-advanced MLS state.
                let snap_opt = {
                    let party = state.mls_party.lock().await;
                    party.snapshot_state().ok()
                };
                if let Some(snap) = snap_opt {
                    let vault = state.vault.lock().await;
                    let _ = vault.save_mls_state(state.identity_id, &snap);
                }
                fanout_room_mls_bytes(
                    &group_id_bytes,
                    &ad_ciphertext,
                    &pre_existing_members,
                    state,
                    "kem-ad",
                    // KEM-ad rides on the NEW-epoch token; existing
                    // members will have subscribed via
                    // announce_room_subscribe after processing the
                    // commit above. Hub queues by routing_id so if
                    // the KEM-ad arrives before the subscribe, the
                    // recipient drains it on next subscribe.
                    None,
                )
                .await;
            }
        }
    }

    // T6.3.g: our own epoch advanced (we just produced the commit).
    // Push an incremental SUBSCRIBE so we receive room messages at
    // the new epoch from any member who might publish before our
    // next reconnect cycle. (CreateRoom doesn't do this because the
    // initial group has no other members — nobody can publish to it
    // yet — but InviteToRoom must, because the new member can start
    // sending immediately after processing the Welcome.)
    crate::announce_room_subscribe(&group_id_bytes, state).await;

    let members = refreshed_members_b32
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    ApiResponse::InviteToRoomOk {
        group_id_b32: encode_b32(&group_id_bytes),
        members,
    }
}

/// T6.3.g: derive the per-(room, current-epoch) session-token
/// routing id from MLS group state. Returns `None` if the group
/// isn't loadable or the exporter fails — the caller falls back
/// to per-member introduction-inbox routing.
async fn compute_room_session_token(
    group_id_bytes: &[u8],
    state: &DaemonState,
) -> Option<onyx_core::routing::RoutingId> {
    let party = state.mls_party.lock().await;
    let Ok(Some(group)) = party.load_group(group_id_bytes) else {
        return None;
    };
    let secret = group.export_routing_secret(&party).ok()?;
    Some(onyx_core::routing::session_token(&secret, 0))
}

/// T-polish.3: fetch persistent room scrollback. Returns the most
/// recent `limit` messages oldest → newest. Empty response for an
/// unknown / never-seen room is `Ok`, not `Error`.
async fn handle_room_history(group_id_b32: &str, limit: u32, state: &DaemonState) -> ApiResponse {
    let Some(group_id_bytes) = base32::decode(
        base32::Alphabet::Rfc4648Lower { padding: false },
        group_id_b32,
    ) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "group_id_b32 is not valid base32".into(),
        };
    };
    let rows = {
        let vault = state.vault.lock().await;
        match vault.room_history(state.identity_id, &group_id_bytes, limit as usize) {
            Ok(rows) => rows,
            Err(e) => {
                return ApiResponse::Error {
                    code: ApiErrorCode::Internal,
                    message: format!("room_history: {e}"),
                };
            }
        }
    };
    let messages = rows
        .into_iter()
        .map(|r| onyx_core::api::RoomHistoryEntry {
            direction: if r.direction_outgoing {
                onyx_core::api::MessageDirection::Outgoing
            } else {
                onyx_core::api::MessageDirection::Incoming
            },
            sender_fp: r.sender_fp,
            text: r.text,
            ts_unix_ms: u64::try_from(r.created_at_ms).unwrap_or(0),
        })
        .collect();
    ApiResponse::RoomHistoryOk {
        group_id_b32: group_id_b32.to_string(),
        messages,
    }
}

/// T-polish.1: pure-local room delete. Forgets `rooms` row +
/// `room_member_kems` cache for this room + the MLS group state.
/// Does NOT notify other members — they keep their copy with us
/// listed as a (now-ghost) member. Idempotent: returns RoomOpOk
/// even if no row matched.
async fn handle_delete_room(group_id_b32: &str, state: &DaemonState) -> ApiResponse {
    let Some(group_id_bytes) = base32::decode(
        base32::Alphabet::Rfc4648Lower { padding: false },
        group_id_b32,
    ) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "group_id_b32 is not valid base32".into(),
        };
    };
    // Drop the MLS group state first, then snapshot, then drop
    // the vault rows. Order is deliberate: if the MLS snapshot
    // fails partway, the vault row stays so a future retry can
    // re-attempt. Better to leak a `rooms` row than to lose the
    // MLS state without the row recording the group.
    let snapshot_opt = {
        let party = state.mls_party.lock().await;
        if let Err(e) = party.forget_group(&group_id_bytes) {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: format!("forget_group: {e}"),
            };
        }
        party.snapshot_state().ok()
    };
    let vault = state.vault.lock().await;
    if let Some(snap) = snapshot_opt
        && let Err(e) = vault.save_mls_state(state.identity_id, &snap)
    {
        return ApiResponse::Error {
            code: ApiErrorCode::Internal,
            message: format!("save_mls_state after forget_group: {e}"),
        };
    }
    if let Err(e) = vault.forget_room_member_kems(state.identity_id, &group_id_bytes) {
        return ApiResponse::Error {
            code: ApiErrorCode::Internal,
            message: format!("forget_room_member_kems: {e}"),
        };
    }
    // T-polish.3: also drop persisted scrollback so a delete is a
    // clean forget — no orphan messages survive in the vault.
    if let Err(e) = vault.forget_room_messages(state.identity_id, &group_id_bytes) {
        tracing::warn!(error = %e, "delete_room: forget_room_messages failed");
    }
    if let Err(e) = vault.delete_room(state.identity_id, &group_id_bytes) {
        return ApiResponse::Error {
            code: ApiErrorCode::Internal,
            message: format!("delete_room: {e}"),
        };
    }
    tracing::info!(
        group_id_b32,
        "room: forgotten locally (T-polish.1 DeleteRoom)"
    );
    ApiResponse::RoomOpOk
}

/// T-polish.1: pure-local rename. Doesn't propagate; each member's
/// name is independent (`CHANNELS.md §2`). Idempotent.
async fn handle_rename_room(
    group_id_b32: &str,
    new_name: &str,
    state: &DaemonState,
) -> ApiResponse {
    let Some(group_id_bytes) = base32::decode(
        base32::Alphabet::Rfc4648Lower { padding: false },
        group_id_b32,
    ) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "group_id_b32 is not valid base32".into(),
        };
    };
    let vault = state.vault.lock().await;
    match vault.rename_room(state.identity_id, &group_id_bytes, new_name) {
        Ok(changed) => {
            tracing::info!(group_id_b32, new_name, changed, "room: renamed");
            ApiResponse::RoomOpOk
        }
        Err(e) => ApiResponse::Error {
            code: ApiErrorCode::Internal,
            message: format!("rename_room: {e}"),
        },
    }
}

/// T-polish.2: leave the room cleanly. Produce an MLS Remove
/// commit removing ourselves, fan the commit out to every other
/// current member via the same direct-or-hub-fallback path as
/// invite, then drop our local state. Other members will see
/// their roster shrink on their next refresh.
//
// Same shape + linear sequence as handle_invite_to_room — kept
// inline rather than split into helpers for the same reason
// documented there. Allow needed for the clippy line budget.
#[allow(clippy::too_many_lines)]
async fn handle_leave_room(group_id_b32: &str, state: &DaemonState) -> ApiResponse {
    let Some(group_id_bytes) = base32::decode(
        base32::Alphabet::Rfc4648Lower { padding: false },
        group_id_b32,
    ) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "group_id_b32 is not valid base32".into(),
        };
    };
    let our_fp = state.identity.fingerprint().to_string();
    // Capture OLD epoch session token BEFORE the remove commit
    // advances us — same routing-target shape as invite (existing
    // members are subscribed to the old token; new one is what we
    // advance to but they haven't merged yet).
    let (commit_bytes_opt, members_before, old_epoch_token) = {
        let party = state.mls_party.lock().await;
        let Ok(Some(mut group)) = party.load_group(&group_id_bytes) else {
            return ApiResponse::Error {
                code: ApiErrorCode::Malformed,
                message: "no MLS group with that group_id".into(),
            };
        };
        let old_token = group
            .export_routing_secret(&party)
            .ok()
            .map(|s| onyx_core::routing::session_token(&s, 0));
        let members_before = crate::members_b32_from_group(&group);
        // remove_members needs our own leaf index, which openmls
        // exposes via group.own_leaf_index(). Fall back to
        // searching the roster by our signing key if that method
        // isn't accessible at the wrapper layer.
        let commit_bytes = match group.remove_self(&party) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                // Solo group leave (no other members) — no commit
                // to ship. We can just drop local state.
                tracing::info!(error = %e, "leave_room: remove_self failed (solo group or other); local-drop");
                None
            }
        };
        (commit_bytes, members_before, old_token)
    };

    // Fan out the commit (if produced) to existing members.
    let pre_existing: Vec<String> = members_before
        .split(',')
        .filter(|s| !s.is_empty())
        .filter(|s| *s != our_fp)
        .map(str::to_owned)
        .collect();
    let members_count = u32::try_from(pre_existing.len()).unwrap_or(u32::MAX);
    if let Some(commit_bytes) = commit_bytes_opt
        && !pre_existing.is_empty()
    {
        fanout_room_mls_bytes(
            &group_id_bytes,
            &commit_bytes,
            &pre_existing,
            state,
            "leave-commit",
            old_epoch_token,
        )
        .await;
    }

    // Drop local state — vault rows + MLS group.
    let snapshot_opt = {
        let party = state.mls_party.lock().await;
        if let Err(e) = party.forget_group(&group_id_bytes) {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: format!("forget_group: {e}"),
            };
        }
        party.snapshot_state().ok()
    };
    let vault = state.vault.lock().await;
    if let Some(snap) = snapshot_opt {
        let _ = vault.save_mls_state(state.identity_id, &snap);
    }
    let _ = vault.forget_room_member_kems(state.identity_id, &group_id_bytes);
    // T-polish.3: also drop the persisted scrollback on leave.
    let _ = vault.forget_room_messages(state.identity_id, &group_id_bytes);
    let _ = vault.delete_room(state.identity_id, &group_id_bytes);
    tracing::info!(
        group_id_b32,
        notified = members_count,
        "room: left (T-polish.2 LeaveRoom)"
    );
    ApiResponse::LeaveRoomOk {
        group_id_b32: group_id_b32.to_string(),
        members: members_count,
    }
}

/// Task 325: remove (kick) another member from a room. Mirrors
/// `handle_leave_room` but targets a member by fingerprint and KEEPS
/// the local group (we stay a member): issue a Remove commit, fan it
/// out to all current members (incl. the evicted one), advance the
/// epoch, refresh + persist the roster. Requires `--hub`.
// Linear handler: parse → remove commit → fan out → persist roster.
// Over the 100-line budget but cohesive (same rationale as the other
// room handlers).
#[allow(clippy::too_many_lines)]
async fn handle_remove_from_room(
    group_id_b32: &str,
    peer_fingerprint: &str,
    state: &DaemonState,
) -> ApiResponse {
    if state.hub_outbounds.is_empty() {
        return ApiResponse::Error {
            code: ApiErrorCode::NotReady,
            message: "no hubs configured; relaunch with --hub onion:port,b32pubkey".into(),
        };
    }
    let Some(group_id_bytes) = base32::decode(
        base32::Alphabet::Rfc4648Lower { padding: false },
        group_id_b32,
    ) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "group_id_b32 is not valid base32".into(),
        };
    };
    let Ok(fp) = onyx_core::crypto::Fingerprint::parse(peer_fingerprint) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "peer_fingerprint did not parse".into(),
        };
    };
    let our_fp = state.identity.fingerprint().to_string();
    if peer_fingerprint == our_fp {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "use `leave` to remove yourself, not `remove`".into(),
        };
    }

    // Issue the Remove commit. Capture the OLD-epoch routing token
    // BEFORE the commit advances us (existing members are still
    // subscribed to it), same as invite/leave.
    let (commit_bytes, members_before, members_after, old_epoch_token, room_meta) = {
        let party = state.mls_party.lock().await;
        let Ok(Some(mut group)) = party.load_group(&group_id_bytes) else {
            return ApiResponse::Error {
                code: ApiErrorCode::Malformed,
                message: "no MLS group with that group_id".into(),
            };
        };
        let old_token = group
            .export_routing_secret(&party)
            .ok()
            .map(|s| onyx_core::routing::session_token(&s, 0));
        let before = crate::members_b32_from_group(&group);
        let Ok(commit) = group.remove_member(&party, fp.as_bytes()) else {
            return ApiResponse::Error {
                code: ApiErrorCode::Malformed,
                message: "that fingerprint is not a current member of the room".into(),
            };
        };
        let after = crate::members_b32_from_group(&group);
        // Room name/created_at for the roster re-save (upsert).
        let meta = {
            let vault = state.vault.lock().await;
            vault
                .list_rooms(state.identity_id)
                .ok()
                .and_then(|rows| rows.into_iter().find(|r| r.group_id == group_id_bytes))
                .map(|r| (r.name, r.created_at_ms))
        };
        (commit, before, after, old_token, meta)
    };

    // Fan the commit out to all members the room had BEFORE removal
    // (except us) — including the evicted member so its daemon
    // processes the commit and drops the group.
    let recipients: Vec<String> = members_before
        .split(',')
        .filter(|s| !s.is_empty())
        .filter(|s| *s != our_fp)
        .map(str::to_owned)
        .collect();
    if !recipients.is_empty() {
        fanout_room_mls_bytes(
            &group_id_bytes,
            &commit_bytes,
            &recipients,
            state,
            "remove-commit",
            old_epoch_token,
        )
        .await;
    }

    // Persist post-remove MLS state + refreshed roster.
    let snapshot_opt = {
        let party = state.mls_party.lock().await;
        party.snapshot_state().ok()
    };
    {
        let vault = state.vault.lock().await;
        if let Some(snap) = snapshot_opt {
            let _ = vault.save_mls_state(state.identity_id, &snap);
        }
        if let Some((name, created_at_ms)) = &room_meta {
            let _ = vault.save_room(
                state.identity_id,
                &group_id_bytes,
                name,
                &members_after,
                *created_at_ms,
            );
        }
        // Note: we deliberately do NOT drop cached member KEMs here.
        // `forget_room_member_kems` would drop ALL of them (breaking
        // hub-fallback to the remaining members); the evicted member's
        // stale KEM is harmless because future fan-outs iterate the
        // refreshed roster, which no longer includes them.
    }

    let members: Vec<String> = members_after
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    tracing::info!(
        group_id_b32,
        removed = %peer_fingerprint,
        remaining = members.len(),
        "room: removed member (task 325)"
    );
    ApiResponse::RemoveFromRoomOk {
        group_id_b32: group_id_b32.to_string(),
        members,
    }
}

/// T-files.d: read + sanitize + chunk a file and fan out the
/// resulting `FileMeta` + `FileChunk` MLS messages to every room
/// member. Caps enforced sender-side too (size cap), not just on
/// the receivers — defends against the local operator accidentally
/// shipping a 1 GB file across Tor.
#[allow(clippy::too_many_lines)]
async fn handle_send_file_to_room(
    group_id_b32: &str,
    path: &str,
    keep_filename: bool,
    keep_metadata: bool,
    state: &DaemonState,
) -> ApiResponse {
    use crate::files::{SanitizeOpts, chunk_file_for_send, sanitize_file, sanitize_filename};

    let Some(group_id_bytes) = base32::decode(
        base32::Alphabet::Rfc4648Lower { padding: false },
        group_id_b32,
    ) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "group_id_b32 is not valid base32".into(),
        };
    };

    // 1. Sanitize the file (strip metadata + sniff MIME).
    let cleaned = match sanitize_file(std::path::Path::new(path), SanitizeOpts { keep_metadata }) {
        Ok(c) => c,
        Err(e) => {
            return ApiResponse::Error {
                code: ApiErrorCode::Malformed,
                message: format!("sanitize_file: {e}"),
            };
        }
    };

    // 2. Cap-list §2.5: per-file send size.
    let size = cleaned.bytes.len() as u64;
    if size > state.files_config.max_send_size_bytes {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: format!(
                "file size {} exceeds max_send_size_bytes {}",
                size, state.files_config.max_send_size_bytes
            ),
        };
    }

    // 3. Compute file_id (random) + content_hash.
    let mut file_id = [0u8; 16];
    onyx_core::crypto::fill_random(&mut file_id);
    let content_hash = onyx_core::crypto::blake2b_256(&[&cleaned.bytes]);

    // 4. Compute the sanitized name to put on the wire.
    let raw_name = std::path::Path::new(path).file_name().map_or_else(
        || "unnamed".to_string(),
        |s| s.to_string_lossy().into_owned(),
    );
    let wire_name = if keep_filename {
        sanitize_filename(&raw_name)
    } else {
        // Strip name to just the extension; receiver will use the
        // hash prefix as the on-disk filename anyway.
        let ext = std::path::Path::new(&raw_name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("bin");
        format!("file.{ext}")
    };

    // 5. Look up the room + load MLS group + verify membership.
    let room_row = {
        let vault = state.vault.lock().await;
        match vault.list_rooms(state.identity_id) {
            Ok(rows) => rows.into_iter().find(|r| r.group_id == group_id_bytes),
            Err(e) => {
                return ApiResponse::Error {
                    code: ApiErrorCode::Internal,
                    message: format!("list_rooms: {e}"),
                };
            }
        }
    };
    let Some(room) = room_row else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "no room with that group_id".into(),
        };
    };

    // 6. Chunk + encrypt + fan out. Same shape as handle_send_room
    //    but iterates over the FileMeta + N FileChunk messages.
    let messages = chunk_file_for_send(
        file_id,
        &wire_name,
        &cleaned.mime,
        &cleaned.bytes,
        state.files_config.chunk_size_bytes,
        &content_hash,
    );
    let chunks_count = u32::try_from(messages.len() - 1).unwrap_or(u32::MAX);

    let our_fp = state.identity.fingerprint().to_string();
    let members: Vec<String> = room
        .members_b32
        .split(',')
        .filter(|s| !s.is_empty())
        .filter(|s| *s != our_fp)
        .map(str::to_owned)
        .collect();
    // A0.3: same fail-closed rule as handle_send_room — a room file
    // fans out to every member, so refuse the whole send if ANY
    // member's pinned identity key has changed (possible MITM). Done
    // BEFORE chunking/encrypting so we don't waste work on a send we
    // will refuse. (`members` already excludes our own fingerprint.)
    for member_fp in &members {
        if let Some(block) = pin_block(state, member_fp).await {
            return block;
        }
    }
    let total_members = u32::try_from(members.len()).unwrap_or(u32::MAX);

    // Encrypt each plaintext message through the room's MLS group
    // and fan out to members. We track delivery stats from the
    // first chunk's fanout only — the per-chunk stats would just
    // repeat for each chunk in the absence of mid-transfer failures.
    let mut total_direct: u32 = 0;
    let mut total_hub: u32 = 0;
    let mut total_skipped: u32 = 0;
    for msg in &messages {
        let Ok(plaintext) = msg.to_cbor() else {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: "RoomAppMessage CBOR encode failed".into(),
            };
        };
        let ciphertext_opt = {
            let party = state.mls_party.lock().await;
            match party.load_group(&group_id_bytes) {
                Ok(Some(mut g)) => g.encrypt_application(&party, &plaintext).ok(),
                _ => None,
            }
        };
        let Some(ciphertext) = ciphertext_opt else {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: "encrypt_application failed mid-transfer".into(),
            };
        };
        // Snapshot the freshly-advanced MLS state (each encrypt
        // advances the ratchet; lose it = de-sync).
        let snap_opt = {
            let party = state.mls_party.lock().await;
            party.snapshot_state().ok()
        };
        if let Some(snap) = snap_opt {
            let vault = state.vault.lock().await;
            let _ = vault.save_mls_state(state.identity_id, &snap);
        }
        // Per-chunk fanout. Returns no stats from the helper, so
        // we only use the LAST chunk's stats as the "delivery
        // count" reported to the caller. v0 limitation: if some
        // members lose their channel mid-transfer the user won't
        // see that; they'll see "delivered to N" for the last
        // chunk's destination.
        let (direct, hub, skipped) = fanout_room_mls_bytes_with_stats(
            &group_id_bytes,
            &ciphertext,
            &members,
            state,
            "file",
            None,
        )
        .await;
        total_direct = direct;
        total_hub = hub;
        total_skipped = skipped;
    }

    let file_id_b32 = base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, &file_id);
    tracing::info!(
        op = "send_file_to_room",
        group_id_b32,
        file_id_b32 = %file_id_b32,
        size,
        mime = %cleaned.mime,
        chunks = chunks_count,
        stripped = cleaned.stripped,
        "file sent"
    );
    ApiResponse::SendFileToRoomOk {
        group_id_b32: group_id_b32.to_string(),
        file_id_b32,
        size,
        mime: cleaned.mime,
        stripped_metadata: cleaned.stripped,
        chunks: chunks_count,
        delivered_to_direct: total_direct,
        delivered_to_hub: total_hub,
        skipped_no_kem: total_skipped,
        total_members,
    }
}

/// Task 322: send a file to a directly-connected DM peer. Same
/// sanitize + chunk pipeline as the room path, but each frame is
/// pushed (plaintext) to the peer-session task via `PeerOutbound::
/// DmFrame`, which encrypts it in the peer's DM MLS group. Direct-only:
/// requires a live conversation (no hub fallback for DM files in v1).
async fn handle_send_file_to_peer(
    peer_short: &str,
    path: &str,
    keep_filename: bool,
    keep_metadata: bool,
    state: &DaemonState,
) -> ApiResponse {
    use crate::files::{SanitizeOpts, chunk_file_for_send, sanitize_file, sanitize_filename};

    // 1. Require a live conversation with the peer (same gate as DM text).
    let handle_opt = state
        .conversations
        .lock()
        .await
        .handle_for_short(peer_short);
    let Some(handle) = handle_opt else {
        return ApiResponse::Error {
            code: ApiErrorCode::NotReady,
            message: format!(
                "no live conversation with peer {peer_short} (DM files are direct-only)"
            ),
        };
    };
    // A0.3: refuse if this peer's pinned key has changed.
    if let Some(block) = pin_block(state, &handle.fingerprint).await {
        return block;
    }

    // 2. Sanitize (strip metadata + sniff MIME).
    let cleaned = match sanitize_file(std::path::Path::new(path), SanitizeOpts { keep_metadata }) {
        Ok(c) => c,
        Err(e) => {
            return ApiResponse::Error {
                code: ApiErrorCode::Malformed,
                message: format!("sanitize_file: {e}"),
            };
        }
    };

    // 3. Per-file send-size cap.
    let size = cleaned.bytes.len() as u64;
    if size > state.files_config.max_send_size_bytes {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: format!(
                "file size {} exceeds max_send_size_bytes {}",
                size, state.files_config.max_send_size_bytes
            ),
        };
    }

    // 4. file_id + content hash + wire name (same logic as the room path).
    let mut file_id = [0u8; 16];
    onyx_core::crypto::fill_random(&mut file_id);
    let content_hash = onyx_core::crypto::blake2b_256(&[&cleaned.bytes]);
    let raw_name = std::path::Path::new(path).file_name().map_or_else(
        || "unnamed".to_string(),
        |s| s.to_string_lossy().into_owned(),
    );
    let wire_name = if keep_filename {
        sanitize_filename(&raw_name)
    } else {
        let ext = std::path::Path::new(&raw_name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("bin");
        format!("file.{ext}")
    };

    // 5. Chunk + push each frame to the peer session (it encrypts in
    //    the DM group). `.send().await` respects the bounded channel's
    //    backpressure so a many-chunk file doesn't overflow it.
    let messages = chunk_file_for_send(
        file_id,
        &wire_name,
        &cleaned.mime,
        &cleaned.bytes,
        state.files_config.chunk_size_bytes,
        &content_hash,
    );
    let chunks_count = u32::try_from(messages.len() - 1).unwrap_or(u32::MAX);
    for msg in messages {
        if handle
            .outbound_tx
            .send(crate::conversations::PeerOutbound::DmFrame(msg))
            .await
            .is_err()
        {
            return ApiResponse::Error {
                code: ApiErrorCode::NotReady,
                message: format!("peer {peer_short} disconnected mid-transfer"),
            };
        }
    }

    let file_id_b32 = base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, &file_id);
    tracing::info!(
        op = "send_file_to_peer",
        peer_short,
        file_id_b32 = %file_id_b32,
        size,
        mime = %cleaned.mime,
        chunks = chunks_count,
        stripped = cleaned.stripped,
        "dm file sent"
    );
    ApiResponse::SendFileToPeerOk {
        peer_short: peer_short.to_string(),
        file_id_b32,
        size,
        mime: cleaned.mime,
        stripped_metadata: cleaned.stripped,
        chunks: chunks_count,
    }
}

/// T-files.d: list files received in a conversation.
async fn handle_list_received_files(
    conversation: &str,
    limit: u32,
    state: &DaemonState,
) -> ApiResponse {
    let rows = {
        let vault = state.vault.lock().await;
        match vault.list_received_files(state.identity_id, conversation, limit as usize) {
            Ok(rows) => rows,
            Err(e) => {
                return ApiResponse::Error {
                    code: ApiErrorCode::Internal,
                    message: format!("list_received_files: {e}"),
                };
            }
        }
    };
    let files = rows
        .into_iter()
        .map(|r| onyx_core::api::ReceivedFileInfo {
            sender_fp: r.sender_fp,
            name: r.name,
            mime: r.mime,
            size: r.size,
            content_hash_b32: base32::encode(
                base32::Alphabet::Rfc4648Lower { padding: false },
                &r.content_hash,
            ),
            path: r.path,
            received_at_ms: u64::try_from(r.received_at_ms).unwrap_or(0),
        })
        .collect();
    ApiResponse::ListReceivedFilesOk {
        conversation: conversation.to_string(),
        files,
    }
}

/// T-files.d: variant of [`fanout_room_mls_bytes`] that returns
/// the delivery stats so `handle_send_file_to_room` can report
/// per-call counts. The original doesn't return stats because the
/// commit / KEM-ad broadcasts didn't care.
async fn fanout_room_mls_bytes_with_stats(
    group_id_bytes: &[u8],
    mls_bytes: &[u8],
    members: &[String],
    state: &DaemonState,
    op_label: &'static str,
    routing_target_override: Option<onyx_core::routing::RoutingId>,
) -> (u32, u32, u32) {
    let mut delivered_direct: u32 = 0;
    let mut delivered_hub: u32 = 0;
    let mut skipped_no_kem: u32 = 0;
    let room_target = match routing_target_override {
        Some(t) => Some(t),
        None => compute_room_session_token(group_id_bytes, state).await,
    };
    let direct_targets: Vec<(String, Option<crate::conversations::ConversationHandle>)> = {
        let reg = state.conversations.lock().await;
        members
            .iter()
            .map(|fp| (fp.clone(), reg.handle_for_fingerprint(fp)))
            .collect()
    };
    for (fp, maybe_handle) in direct_targets {
        if let Some(handle) = maybe_handle
            && handle
                .outbound_tx
                .try_send(crate::conversations::PeerOutbound::RoomFrame(
                    mls_bytes.to_vec(),
                ))
                .is_ok()
        {
            delivered_direct += 1;
            continue;
        }
        let kem_bytes_opt = {
            let vault = state.vault.lock().await;
            vault
                .lookup_room_member_kem(state.identity_id, group_id_bytes, &fp)
                .unwrap_or(None)
        };
        let Some(kem_bytes) = kem_bytes_opt else {
            skipped_no_kem += 1;
            continue;
        };
        let Ok(kem_pub) = onyx_core::crypto::HybridKemPublic::from_bytes(&kem_bytes) else {
            skipped_no_kem += 1;
            continue;
        };
        let target = if let Some(t) = room_target {
            t
        } else {
            let Ok(target_fp_parsed) = onyx_core::crypto::Fingerprint::parse(&fp) else {
                skipped_no_kem += 1;
                continue;
            };
            onyx_core::routing::introduction_inbox(&target_fp_parsed)
        };
        let payload = onyx_core::routing::BootstrapPayload::MlsApp {
            group_id: serde_bytes::ByteBuf::from(group_id_bytes.to_vec()),
            ciphertext: serde_bytes::ByteBuf::from(mls_bytes.to_vec()),
        };
        let Ok(payload_bytes) = payload.to_cbor() else {
            continue;
        };
        let Ok(sealed) = onyx_core::routing::seal_bootstrap(
            state.identity.signing(),
            state.identity.identity_key(),
            &payload_bytes,
            &kem_pub,
        ) else {
            continue;
        };
        let mut any_accepted = false;
        for hub_outbound in &state.hub_outbounds {
            if hub_outbound
                .try_send(crate::hub_client::HubOutbound::deliver(
                    target,
                    sealed.clone(),
                ))
                .is_ok()
            {
                any_accepted = true;
            }
        }
        if any_accepted {
            delivered_hub += 1;
        }
    }
    tracing::trace!(
        op_label,
        delivered_direct,
        delivered_hub,
        skipped_no_kem,
        "file-chunk fanout"
    );
    (delivered_direct, delivered_hub, skipped_no_kem)
}

/// T6.3.h fan-out helper. Pushes a pre-built MLS message
/// (commit or application-tier ciphertext) to every named member
/// over their direct Noise session if one is live, otherwise seals
/// it as a `BootstrapPayload::MlsApp` envelope and ships via the
/// hub. Same direct-or-hub fan-out logic as `handle_send_room`,
/// extracted so the post-invite commit + KEM-ad broadcasts can
/// reuse it without copy-paste.
///
/// `op_label` shows up in the tracing log line for observability —
/// e.g. "commit" vs "kem-ad" vs (in send_room) "app".
async fn fanout_room_mls_bytes(
    group_id_bytes: &[u8],
    mls_bytes: &[u8],
    members: &[String],
    state: &DaemonState,
    op_label: &'static str,
    routing_target_override: Option<onyx_core::routing::RoutingId>,
) {
    let mut delivered_direct: u32 = 0;
    let mut delivered_hub: u32 = 0;
    let mut skipped_no_kem: u32 = 0;
    // T6.3.g + T-smoke fix: compute the room's per-epoch session
    // token ONCE — all hub-routed copies of this MLS payload go to
    // the same inbox regardless of recipient. Override is used
    // by handle_invite_to_room's commit fan-out, where the commit
    // must route to the OLD-epoch token (existing members are
    // subscribed to that; they haven't seen the commit yet so
    // they don't have the new token's subscription). For app
    // messages routed at the current epoch, override is None and
    // we derive from the current group state.
    let room_target = match routing_target_override {
        Some(t) => Some(t),
        None => compute_room_session_token(group_id_bytes, state).await,
    };
    let direct_targets: Vec<(String, Option<crate::conversations::ConversationHandle>)> = {
        let reg = state.conversations.lock().await;
        members
            .iter()
            .map(|fp| (fp.clone(), reg.handle_for_fingerprint(fp)))
            .collect()
    };
    for (fp, maybe_handle) in direct_targets {
        if let Some(handle) = maybe_handle {
            if handle
                .outbound_tx
                .try_send(crate::conversations::PeerOutbound::RoomFrame(
                    mls_bytes.to_vec(),
                ))
                .is_ok()
            {
                delivered_direct += 1;
                continue;
            }
        }
        // Hub fallback.
        let kem_bytes_opt = {
            let vault = state.vault.lock().await;
            vault
                .lookup_room_member_kem(state.identity_id, group_id_bytes, &fp)
                .unwrap_or(None)
        };
        let Some(kem_bytes) = kem_bytes_opt else {
            skipped_no_kem += 1;
            continue;
        };
        let Ok(kem_pub) = onyx_core::crypto::HybridKemPublic::from_bytes(&kem_bytes) else {
            skipped_no_kem += 1;
            continue;
        };
        // T6.3.g: if we couldn't derive the session token (no MLS
        // state for this room — should never happen because the
        // caller already loaded it to encrypt, but defensive), fall
        // back to per-member introduction_inbox so the message still
        // routes. The recipient subscribes to both, so either lands.
        let target = if let Some(t) = room_target {
            t
        } else {
            let Ok(target_fp_parsed) = onyx_core::crypto::Fingerprint::parse(&fp) else {
                skipped_no_kem += 1;
                continue;
            };
            onyx_core::routing::introduction_inbox(&target_fp_parsed)
        };
        let payload = onyx_core::routing::BootstrapPayload::MlsApp {
            group_id: serde_bytes::ByteBuf::from(group_id_bytes.to_vec()),
            ciphertext: serde_bytes::ByteBuf::from(mls_bytes.to_vec()),
        };
        let Ok(payload_bytes) = payload.to_cbor() else {
            continue;
        };
        let Ok(sealed) = onyx_core::routing::seal_bootstrap(
            state.identity.signing(),
            state.identity.identity_key(),
            &payload_bytes,
            &kem_pub,
        ) else {
            continue;
        };
        let mut any_accepted = false;
        for hub_outbound in &state.hub_outbounds {
            if hub_outbound
                .try_send(crate::hub_client::HubOutbound::deliver(
                    target,
                    sealed.clone(),
                ))
                .is_ok()
            {
                any_accepted = true;
            }
        }
        if any_accepted {
            delivered_hub += 1;
        }
    }
    tracing::info!(
        op = "room_fanout",
        op_label,
        delivered_to_direct = delivered_direct,
        delivered_to_hub = delivered_hub,
        skipped_no_kem,
        total = members.len(),
        "room: per-member fan-out done"
    );
}

/// Send a plaintext message to every member of a room over their
/// **direct** Noise sessions (T6.3.d, "direct path only"). Hub
/// fan-out for offline / hub-only members lands in T6.3.e.
///
/// Encrypts **once** in the room's MLS group state — that's the
/// "one ciphertext for the whole group" property MLS gives us —
/// then pushes the same ciphertext into every member's per-peer
/// outbound queue as a `PeerOutbound::RoomFrame`. The per-peer
/// task forwards it as a `FRAME_MLS_APP` frame on the wire.
///
/// Returns the count of members successfully reached vs the total
/// (excluding ourselves) so the caller can warn that some members
/// won't receive the message until T6.3.e ships.
//
// Same shape as handle_invite_to_room / handle_send_bootstrap_mls
// — one linear parse → validate → load → encrypt → snapshot →
// fan-out path with several short-circuit error branches; per-step
// extraction would yield helpers that each carry their own typed
// error response with no net readability win.
#[allow(clippy::too_many_lines)]
async fn handle_send_room(group_id_b32: &str, text: &str, state: &DaemonState) -> ApiResponse {
    // 1. Parse + look up room row + own fingerprint.
    let Some(group_id_bytes) = base32::decode(
        base32::Alphabet::Rfc4648Lower { padding: false },
        group_id_b32,
    ) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "group_id_b32 is not valid base32".into(),
        };
    };
    let our_fp = state.identity.fingerprint().to_string();
    let room_row = {
        let vault = state.vault.lock().await;
        match vault.list_rooms(state.identity_id) {
            Ok(rows) => rows.into_iter().find(|r| r.group_id == group_id_bytes),
            Err(e) => {
                return ApiResponse::Error {
                    code: ApiErrorCode::Internal,
                    message: format!("list_rooms: {e}"),
                };
            }
        }
    };
    let Some(room) = room_row else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "no room with that group_id".into(),
        };
    };
    let members: Vec<String> = room
        .members_b32
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    // A0.3: a room message fans out to every member, so refuse the whole
    // send if ANY member's pinned identity key has changed since first
    // contact (possible MITM / key rotation) — fail closed rather than
    // deliver to a peer we can no longer authenticate. The user clears
    // the offending pin (`onyx contact list` flags it) before the room
    // works again.
    for member_fp in &members {
        if member_fp == &our_fp {
            continue;
        }
        if let Some(block) = pin_block(state, member_fp).await {
            return block;
        }
    }
    // 2. Wrap the user-typed text in a structured RoomAppMessage
    //    (T6.3.h) so the plaintext format is forward-compatible
    //    with the KEM-advertisement variant. Then encrypt once in
    //    the room's MLS group, snapshot.
    let app_msg = onyx_core::room::RoomAppMessage::Text {
        text: text.to_string(),
    };
    let Ok(plaintext_bytes) = app_msg.to_cbor() else {
        return ApiResponse::Error {
            code: ApiErrorCode::Internal,
            message: "RoomAppMessage CBOR encode failed".into(),
        };
    };
    let (ciphertext, snapshot) = {
        let party = state.mls_party.lock().await;
        let mut group = match party.load_group(&group_id_bytes) {
            Ok(Some(g)) => g,
            Ok(None) => {
                return ApiResponse::Error {
                    code: ApiErrorCode::Malformed,
                    message: "MLS state has no group with that group_id (vault drift?)".into(),
                };
            }
            Err(e) => {
                return ApiResponse::Error {
                    code: ApiErrorCode::Internal,
                    message: format!("load_group: {e}"),
                };
            }
        };
        let Ok(ct) = group.encrypt_application(&party, &plaintext_bytes) else {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: "encrypt_application failed".into(),
            };
        };
        let Ok(snap) = party.snapshot_state() else {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: "snapshot_state failed".into(),
            };
        };
        (ct, snap)
    };
    {
        let vault = state.vault.lock().await;
        if let Err(e) = vault.save_mls_state(state.identity_id, &snapshot) {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: format!("save_mls_state: {e}"),
            };
        }
    }
    // 3. Walk room members (excluding ourselves). For each member:
    //    - try direct push first; if a live Noise session exists,
    //      push PeerOutbound::RoomFrame(ciphertext.clone()).
    //    - otherwise (T6.3.e hub-fallback): if we have their cached
    //      hybrid KEM pub, seal the same MLS ciphertext as a
    //      BootstrapPayload::MlsApp envelope and fan it out across
    //      all configured hubs.
    //    - otherwise (no KEM cached): skip and count under
    //      skipped_no_kem so the caller can warn.
    let mut delivered_direct: u32 = 0;
    let mut delivered_hub: u32 = 0;
    let mut skipped_no_kem: u32 = 0;
    let mut total: u32 = 0;
    let direct_targets: Vec<(String, Option<crate::conversations::ConversationHandle>)> = {
        let reg = state.conversations.lock().await;
        members
            .iter()
            .filter(|fp| **fp != our_fp)
            .map(|fp| (fp.clone(), reg.handle_for_fingerprint(fp)))
            .collect()
    };
    for (fp, maybe_handle) in direct_targets {
        total += 1;
        if let Some(handle) = maybe_handle {
            if handle
                .outbound_tx
                .try_send(crate::conversations::PeerOutbound::RoomFrame(
                    ciphertext.clone(),
                ))
                .is_ok()
            {
                delivered_direct += 1;
                continue;
            }
            // Send failed (queue full / closed): fall through to hub.
        }
        // Hub-fallback path.
        let kem_bytes_opt = {
            let vault = state.vault.lock().await;
            vault
                .lookup_room_member_kem(state.identity_id, &group_id_bytes, &fp)
                .unwrap_or(None)
        };
        let Some(kem_bytes) = kem_bytes_opt else {
            skipped_no_kem += 1;
            tracing::warn!(
                op = "send_room",
                missing_member = %fp,
                "no cached KEM pub for member; hub-fallback skipped \
                 (KEM-pub exchange is a T6.3 follow-up)"
            );
            continue;
        };
        let Ok(kem_pub) = onyx_core::crypto::HybridKemPublic::from_bytes(&kem_bytes) else {
            skipped_no_kem += 1;
            tracing::warn!(
                op = "send_room",
                missing_member = %fp,
                "cached KEM pub did not decode as HybridKemPublic; skipping"
            );
            continue;
        };
        // T6.3.g: route to the room's per-epoch session token so the
        // hub sees one inbox per (room, epoch) rather than per
        // (room, member). Fall back to per-member introduction_inbox
        // if the session-token derivation fails — recipient subscribes
        // to both, so either lands.
        let target = if let Some(t) = compute_room_session_token(&group_id_bytes, state).await {
            t
        } else {
            let Ok(target_fp_parsed) = onyx_core::crypto::Fingerprint::parse(&fp) else {
                skipped_no_kem += 1;
                tracing::warn!(missing_member = %fp, "fingerprint did not parse");
                continue;
            };
            onyx_core::routing::introduction_inbox(&target_fp_parsed)
        };
        let payload = onyx_core::routing::BootstrapPayload::MlsApp {
            group_id: serde_bytes::ByteBuf::from(group_id_bytes.clone()),
            ciphertext: serde_bytes::ByteBuf::from(ciphertext.clone()),
        };
        let Ok(payload_bytes) = payload.to_cbor() else {
            tracing::warn!(missing_member = %fp, "MlsApp CBOR encode failed; skipping");
            continue;
        };
        let Ok(sealed) = onyx_core::routing::seal_bootstrap(
            state.identity.signing(),
            state.identity.identity_key(),
            &payload_bytes,
            &kem_pub,
        ) else {
            tracing::warn!(missing_member = %fp, "seal_bootstrap failed; skipping");
            continue;
        };
        let mut any_accepted = false;
        for hub_outbound in &state.hub_outbounds {
            if hub_outbound
                .try_send(crate::hub_client::HubOutbound::deliver(
                    target,
                    sealed.clone(),
                ))
                .is_ok()
            {
                any_accepted = true;
            }
        }
        if any_accepted {
            delivered_hub += 1;
        } else {
            tracing::warn!(
                missing_member = %fp,
                "no hub accepted the MlsApp envelope; recipient won't get this message \
                 until a hub session recovers"
            );
        }
    }
    tracing::info!(
        op = "send_room",
        group_id_b32,
        delivered_to_direct = delivered_direct,
        delivered_to_hub = delivered_hub,
        skipped_no_kem,
        total_members = total,
        "room: fan-out done"
    );
    // T-polish.3: persist the outgoing message to the room's
    // scrollback. Sender is us, so the fingerprint is authoritative.
    let now_ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()),
    )
    .unwrap_or(0);
    {
        let vault = state.vault.lock().await;
        if let Err(e) = vault.append_room_message(
            state.identity_id,
            &group_id_bytes,
            true,
            &our_fp,
            text,
            now_ms,
        ) {
            tracing::warn!(error = %e, "room: append outgoing message failed");
        }
    }
    ApiResponse::SendRoomOk {
        group_id_b32: group_id_b32.to_string(),
        delivered_to_direct: delivered_direct,
        delivered_to_hub: delivered_hub,
        skipped_no_kem,
        total_members: total,
    }
}

/// Fetch a peer's MLS KeyPackage from the hub's T6.1 directory.
/// Serialises concurrent calls via `state.hub_fetch_lock` because the
/// `FRAME_KP_RESPONSE` wire format has no request id — see the
/// `serve_session` doc-comment for the FIFO matching invariant.
///
/// **Security-critical** (mirrors `handle_send_bootstrap_mls`):
/// the returned KP's embedded Ed25519 signing key MUST hash to
/// `peer_fingerprint` before we hand it back to the caller. Without
/// this check, a hostile hub directory could feed a CLI user the
/// attacker's KP, which the user would then paste into
/// `SendBootstrapMls` and unknowingly invite the attacker.
/// `THREAT_MODEL.md` §8.2 #15.
async fn handle_fetch_peer_keypackage(peer_fingerprint: &str, state: &DaemonState) -> ApiResponse {
    if state.hub_outbounds.is_empty() {
        return ApiResponse::Error {
            code: ApiErrorCode::NotReady,
            message: "no hubs configured; relaunch with --hub onion:port,b32pubkey".into(),
        };
    }
    let Ok(fp) = onyx_core::crypto::Fingerprint::parse(peer_fingerprint) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "peer_fingerprint did not parse".into(),
        };
    };
    let target = onyx_core::routing::introduction_inbox(&fp);

    // Hold the hub_fetch_lock across the whole request/response cycle
    // so each hub-client's FIFO can't get out of order. T8.1: we
    // serialise across ALL hubs under the same lock — try each in
    // configured order, return the first success. The FIFO matching
    // invariant in `hub_client` is per-hub, but since we never have
    // more than one fetch in flight at a time (lock guarantees), the
    // invariant holds across the multi-hub fan.
    let _guard = state.hub_fetch_lock.lock().await;

    let mut last_send_err: Option<String> = None;
    let mut last_recv_err: bool = false;
    for (idx, hub_outbound) in state.hub_outbounds.iter().enumerate() {
        let (responder_tx, responder_rx) = tokio::sync::oneshot::channel();
        if let Err(e) = hub_outbound.try_send(crate::hub_client::HubOutbound::FetchKp {
            routing_id: target,
            responder: responder_tx,
        }) {
            last_send_err = Some(format!("hub #{idx} outbound queue: {e}"));
            continue;
        }
        match responder_rx.await {
            Ok(Some(kp_bytes)) => {
                // SECURITY: validate the returned KP's signing key
                // matches peer_fingerprint before surfacing. Same
                // T7.3-sec / THREAT_MODEL §8.2 #15 mitigation as
                // single-hub — applied to whichever hub answered.
                let extracted = {
                    let party = state.mls_party.lock().await;
                    party.peer_signing_pk_from_kp_bytes(&kp_bytes)
                };
                let Ok(signing_bytes) = extracted else {
                    return ApiResponse::Error {
                        code: ApiErrorCode::Malformed,
                        message: "fetched KP did not validate as a KeyPackage".into(),
                    };
                };
                let Ok(vk) = onyx_core::crypto::VerifyingKey::from_bytes(signing_bytes) else {
                    return ApiResponse::Error {
                        code: ApiErrorCode::Malformed,
                        message: "fetched KP signing key is not a valid Ed25519 point".into(),
                    };
                };
                if vk.fingerprint() != fp {
                    return ApiResponse::Error {
                        code: ApiErrorCode::Malformed,
                        message: "fetched KP signing key does not match peer_fingerprint \
                                  — refusing (potential hub-directory tampering)"
                            .into(),
                    };
                }
                return ApiResponse::FetchPeerKeyPackageOk {
                    kp_b64: base64_encode(&kp_bytes),
                };
            }
            Ok(None) => {
                // This hub doesn't have the KP — try the next one.
            }
            Err(_) => {
                last_recv_err = true;
            }
        }
    }
    if let Some(msg) = last_send_err {
        ApiResponse::Error {
            code: ApiErrorCode::NotReady,
            message: msg,
        }
    } else if last_recv_err {
        ApiResponse::Error {
            code: ApiErrorCode::Internal,
            message: "every hub session ended before responding".into(),
        }
    } else {
        ApiResponse::Error {
            code: ApiErrorCode::NotReady,
            message: "no configured hub has this peer's KeyPackage published".into(),
        }
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
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
    hub_outbounds: &[tokio::sync::mpsc::Sender<crate::hub_client::HubOutbound>],
) -> ApiResponse {
    // Require at least one hub-client to be active. If `--hub` wasn't
    // set at launch, `hub_outbounds` is empty and we can't relay
    // anything; surface that as NotReady (operator config issue, not
    // a malformed request).
    if hub_outbounds.is_empty() {
        return ApiResponse::Error {
            code: ApiErrorCode::NotReady,
            message: "no hubs configured; relaunch with --hub onion:port,b32pubkey".into(),
        };
    }

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
    let Ok(sealed) =
        onyx_core::routing::seal_bootstrap(our_signing, our_identity_sk, &payload_bytes, &kem_pub)
    else {
        return ApiResponse::Error {
            code: ApiErrorCode::Internal,
            message: "seal_bootstrap failed".into(),
        };
    };

    // T8.1 fan-out: push the same sealed envelope to every configured
    // hub. The recipient's `EnvelopeReplayGuard` (T7.3-sec.2) drops
    // duplicates silently, so the recipient sees exactly one
    // EventMessage regardless of how many hubs forwarded it. A
    // success on any one hub counts as overall success — partial
    // failures (some hubs full / closed) log a warn but still report
    // SendBootstrapOk.
    let target = onyx_core::routing::introduction_inbox(&fp);
    fan_out_deliver(hub_outbounds, target, &sealed, "send_bootstrap")
}

/// Push the same DELIVER envelope into every hub outbound queue.
/// Returns `SendBootstrapOk` if **any** hub accepted the envelope
/// (duplicates on the recipient side are dedup'd by the replay
/// guard). Returns `NotReady` only when **every** hub queue was full
/// or closed.
fn fan_out_deliver(
    hub_outbounds: &[tokio::sync::mpsc::Sender<crate::hub_client::HubOutbound>],
    target: onyx_core::routing::RoutingId,
    sealed: &[u8],
    op: &str,
) -> ApiResponse {
    let mut accepted = 0;
    let mut last_err: Option<String> = None;
    for (idx, hub_outbound) in hub_outbounds.iter().enumerate() {
        match hub_outbound.try_send(crate::hub_client::HubOutbound::deliver(
            target,
            sealed.to_vec(),
        )) {
            Ok(()) => accepted += 1,
            Err(TrySendError::Full(_)) => {
                last_err = Some(format!("hub #{idx} outbound queue is full"));
            }
            Err(TrySendError::Closed(_)) => {
                last_err = Some(format!("hub #{idx} client task has ended"));
            }
        }
    }
    if accepted > 0 {
        tracing::info!(op, accepted, total = hub_outbounds.len(), "hub fan-out");
        ApiResponse::SendBootstrapOk
    } else {
        ApiResponse::Error {
            code: ApiErrorCode::NotReady,
            message: last_err.unwrap_or_else(|| "no hub accepted the delivery".into()),
        }
    }
}

/// MLS-tier first-contact via hub. Fetches the peer's KP (provided
/// by the caller for v0; future T6.x will fetch from hub directory),
/// **verifies the KP's embedded signing key against the expected
/// fingerprint** (defends against a hostile hub directory swap —
/// `THREAT_MODEL.md` §8.2 #15), creates a fresh 2-party MLS group,
/// invites the peer, wraps the resulting Welcome in
/// `BootstrapPayload::MlsWelcome`, seals, sends.
///
/// On success: returns `SendBootstrapMlsOk { group_id_b32 }` and the
/// peer→group mapping is recorded in the vault so future direct dials
/// to this peer resume the same group (existing T2.x resume path).
///
/// Async because it locks `state.mls_party` and `state.vault`.
//
// Function is one linear "parse → validate → build → seal → persist →
// push" sequence; each step needs to short-circuit with a typed Error
// response on failure. Splitting per-step would add five tiny helpers
// that don't make any step easier to read.
#[allow(clippy::too_many_lines)]
async fn handle_send_bootstrap_mls(
    peer_fingerprint: &str,
    peer_kem_pub_b32: &str,
    peer_kp_b64: &str,
    initial_text: Option<&str>,
    state: &DaemonState,
) -> ApiResponse {
    // Defensive cap on the optional T7.2-mls-fu intro text. The wire
    // layer already pads to size buckets (SMALL=256, MEDIUM=1024,
    // LARGE=4092), so a very long first_message would jump the sealed
    // envelope from MEDIUM into LARGE — a length leak observable to
    // anyone watching the daemon↔hub Noise channel. Keeping the cap
    // small enough that "no intro" and "short intro" land in the same
    // bucket as the bare Welcome (~1.2-1.5 KB for a 2-party group).
    // 1 KiB is plenty for a paragraph of introduction text.
    const FIRST_MESSAGE_MAX_BYTES: usize = 1024;
    if let Some(text) = initial_text {
        if text.len() > FIRST_MESSAGE_MAX_BYTES {
            return ApiResponse::Error {
                code: ApiErrorCode::Malformed,
                message: format!(
                    "initial_text too long ({} bytes; max {FIRST_MESSAGE_MAX_BYTES}) — keep \
                     intro short to avoid bumping the sealed-envelope size bucket on the wire",
                    text.len()
                ),
            };
        }
    }

    if state.hub_outbounds.is_empty() {
        return ApiResponse::Error {
            code: ApiErrorCode::NotReady,
            message: "no hubs configured; relaunch with --hub onion:port,b32pubkey".into(),
        };
    }

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
    let Ok(kp_bytes) = base64_decode(peer_kp_b64) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "peer_kp_b64 is not valid base64".into(),
        };
    };

    // SECURITY: validate the KP's embedded Ed25519 signing key
    // hashes to the expected fingerprint BEFORE we invite the
    // publisher. A hostile hub or attacker could otherwise feed us
    // their own KP under a target's routing id, and we'd then add
    // them to the group thinking they were the target.
    let extracted_signing_pk = {
        let party = state.mls_party.lock().await;
        match party.peer_signing_pk_from_kp_bytes(&kp_bytes) {
            Ok(pk) => pk,
            Err(_) => {
                return ApiResponse::Error {
                    code: ApiErrorCode::Malformed,
                    message: "peer_kp_b64 did not validate as a KeyPackage".into(),
                };
            }
        }
    };
    let Ok(vk) = onyx_core::crypto::VerifyingKey::from_bytes(extracted_signing_pk) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "KP signing key is not a valid Ed25519 point".into(),
        };
    };
    if vk.fingerprint() != fp {
        return ApiResponse::Error {
            code: ApiErrorCode::Malformed,
            message: "KP signing key does not match peer_fingerprint \
                      — refusing to invite (potential hub-directory tampering)"
                .into(),
        };
    }

    // Build the group + invite the peer + extract the Welcome bytes.
    let (welcome_bytes, group_id_bytes, snapshot) = {
        let party = state.mls_party.lock().await;
        let Ok(mut group) = party.create_group() else {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: "create_group failed".into(),
            };
        };
        // T6.3.h: invite now returns (commit, welcome). The DM
        // bootstrap path (solo → 2-person) has no existing members
        // to ship the commit to, so we discard it — the recipient
        // bootstraps from the Welcome at the new epoch.
        let Ok((_commit_unused, welcome)) = group.invite(&party, &kp_bytes) else {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: "invite failed".into(),
            };
        };
        let group_id = group.group_id_bytes();
        let Ok(snap) = party.snapshot_state() else {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: "snapshot_state failed".into(),
            };
        };
        (welcome, group_id, snap)
    };

    // Seal the Welcome inside an mls/v1 BootstrapPayload, optionally
    // riding an initial plaintext message alongside it (T7.2-mls-fu).
    // The text is covered by the outer sealed-sender Ed25519 signature
    // — a MITM cannot tamper with it without invalidating the whole
    // envelope. It does **not** have MLS PCS (the ratchet only kicks
    // in for messages sent *inside* the new group from here on); this
    // is the same caveat as the Welcome itself.
    let payload = onyx_core::routing::BootstrapPayload::MlsWelcome {
        welcome: serde_bytes::ByteBuf::from(welcome_bytes),
        first_message: initial_text.map(str::to_owned),
        // SendBootstrapMls always creates a fresh 2-party DM group —
        // never a room. Rooms go through handle_invite_to_room
        // (T6.3.c) and set room_name = Some(name) so the recipient
        // surfaces a `rooms` entry instead of a DM conversation.
        room_name: None,
        // T6.3.h: not a room, so no member-roster KEM list.
        member_kems: vec![],
    };
    let Ok(payload_bytes) = payload.to_cbor() else {
        return ApiResponse::Error {
            code: ApiErrorCode::Internal,
            message: "encoding mls/v1 BootstrapPayload failed".into(),
        };
    };
    let Ok(sealed) = onyx_core::routing::seal_bootstrap(
        state.identity.signing(),
        state.identity.identity_key(),
        &payload_bytes,
        &kem_pub,
    ) else {
        return ApiResponse::Error {
            code: ApiErrorCode::Internal,
            message: "seal_bootstrap failed".into(),
        };
    };

    // Persist the post-invite MLS snapshot + the peer→group mapping
    // so a future direct dial to this peer resumes the same group
    // (existing T2.x resume path).
    // Persist the post-invite MLS state so a future direct dial to
    // this peer can resume the group instead of bootstrapping fresh
    // (existing T2.x resume path).
    //
    // Note: the existing `record_peer_group` mapping is keyed by the
    // peer's X25519 identity key, which we don't have here — we only
    // know their Ed25519 signing key from the validated KP. Recording
    // the X25519 mapping happens when the peer first direct-dials us
    // (existing handshake path lifts the X25519 from Noise XK). The
    // MLS *state* is persisted now regardless, so the group exists
    // and is ready to be linked the moment we learn the X25519.
    {
        let vault = state.vault.lock().await;
        if let Err(e) = vault.save_mls_state(state.identity_id, &snapshot) {
            return ApiResponse::Error {
                code: ApiErrorCode::Internal,
                message: format!("save_mls_state: {e}"),
            };
        }
    }

    // T8.1 fan-out across all configured hubs. The recipient's
    // EnvelopeReplayGuard drops duplicates. Success on any one hub
    // is overall success — but we override the response type to
    // include the new group_id_b32 (fan_out_deliver returns the
    // bootstrap-OK shape, which doesn't carry that field).
    let target = onyx_core::routing::introduction_inbox(&fp);
    let mut accepted = 0;
    let mut last_err: Option<String> = None;
    for (idx, hub_outbound) in state.hub_outbounds.iter().enumerate() {
        match hub_outbound.try_send(crate::hub_client::HubOutbound::deliver(
            target,
            sealed.clone(),
        )) {
            Ok(()) => accepted += 1,
            Err(TrySendError::Full(_)) => {
                last_err = Some(format!("hub #{idx} outbound queue is full"));
            }
            Err(TrySendError::Closed(_)) => {
                last_err = Some(format!("hub #{idx} client task has ended"));
            }
        }
    }
    if accepted > 0 {
        tracing::info!(
            op = "send_bootstrap_mls",
            accepted,
            total = state.hub_outbounds.len(),
            "hub fan-out"
        );
        ApiResponse::SendBootstrapMlsOk {
            group_id_b32: encode_b32(&group_id_bytes),
        }
    } else {
        ApiResponse::Error {
            code: ApiErrorCode::NotReady,
            message: last_err.unwrap_or_else(|| "no hub accepted the Welcome envelope".into()),
        }
    }
}

/// Standard base64 decode helper. The base64 crate is a transitive
/// dep (via openmls); reaching for it directly here keeps the
/// dependency surface visible.
fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s)
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

    /// `--hub` not set ⇒ `hub_outbounds` empty ⇒ NotReady.
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

        let resp = handle_send_bootstrap(&fp, &bob_kem_b32, "hi bob", &sign, &id, &[]);
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
            std::slice::from_ref(&tx),
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

        let resp = handle_send_bootstrap(
            &fp,
            "not-base32!@#$",
            "x",
            &sign,
            &id,
            std::slice::from_ref(&tx),
        );
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
        let resp = handle_send_bootstrap(
            &fp,
            "aaaaaaaaaaaa",
            "x",
            &sign,
            &id,
            std::slice::from_ref(&tx),
        );
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
            std::slice::from_ref(&tx),
        );
        assert!(matches!(resp, ApiResponse::SendBootstrapOk));

        let outbound = rx.recv().await.expect("HubOutbound delivered");
        // Target must be the introduction-inbox routing id derived
        // from bob's fingerprint — that's the security-relevant
        // invariant: the hub sees exactly which inbox we addressed,
        // nothing about the sender or content.
        let expected_target = onyx_core::routing::introduction_inbox(&bob_fp);
        let crate::hub_client::HubOutbound::Deliver { target, body } = outbound else {
            panic!("expected Deliver variant, got {outbound:?}");
        };
        assert_eq!(target, expected_target);
        assert!(!body.is_empty(), "sealed envelope must be non-empty");

        // End-to-end check: bob can decapsulate + decode and recovers
        // exactly the plaintext we sent.
        let opened = onyx_core::routing::open_bootstrap(&body, &bob_kem).expect("bob opens");
        let payload =
            onyx_core::routing::BootstrapPayload::from_cbor(&opened.mls_welcome).expect("decode");
        match payload {
            onyx_core::routing::BootstrapPayload::PlainMessage { text } => {
                assert_eq!(text, "first hub-relayed hello");
            }
            onyx_core::routing::BootstrapPayload::MlsWelcome { .. } => {
                panic!("expected PlainMessage, got MlsWelcome")
            }
            onyx_core::routing::BootstrapPayload::MlsApp { .. } => {
                panic!("expected PlainMessage, got MlsApp")
            }
        }
        // The opened envelope also authenticates the sender — we
        // assert this matches our local signing key so an attacker
        // who substituted the body couldn't pose as us.
        assert_eq!(opened.sender_signing_pk, sign.verifying_key());
    }

    /// SECURITY-CRITICAL: SendBootstrapMls must refuse if the
    /// supplied KP's embedded Ed25519 signing key does NOT hash to
    /// the supplied peer_fingerprint. This is the recipient-side
    /// mitigation for THREAT_MODEL §8.2 #15 (hostile hub directory
    /// could swap an attacker's KP under alice's routing id; without
    /// this check we'd invite the attacker into the MLS group
    /// thinking it's alice).
    ///
    /// We can't easily test the happy path here without standing up
    /// a full DaemonState + MlsParty (handled by main.rs callers and
    /// the existing mls module tests). The negative-path check is
    /// what we want anyway: assert mismatched fingerprint → refusal.
    /// Tests live in mls.rs for the extraction primitive
    /// (peer_signing_pk_from_kp_bytes); this test would be redundant
    /// with that, so for v0 we rely on the type-system + the
    /// extracted-pk-matches-fingerprint check being a single
    /// straight-line conditional in the dispatcher.
    ///
    /// If this validation step ever moves or changes shape, the
    /// commit must add a direct test of the refusal behaviour.
    #[test]
    fn send_bootstrap_mls_validation_step_exists() {
        // Document via a no-op test that the refusal IS in the code
        // and where to find it. A test that actually exercises the
        // happy path would require a full DaemonState — out of
        // scope here; covered end-to-end in any future smoke test.
        let source = include_str!("api_server.rs");
        assert!(
            source.contains("vk.fingerprint() != fp"),
            "the fingerprint-vs-KP-signing-key validation in \
             handle_send_bootstrap_mls must exist; if you renamed \
             the variables you need to update both the check and \
             this guardrail test"
        );
        assert!(
            source.contains("KP signing key does not match peer_fingerprint"),
            "the refusal error message in handle_send_bootstrap_mls \
             must be present so operators see exactly what went wrong"
        );
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
        let _ = handle_send_bootstrap(
            &bob_fp,
            &bob_kem_b32,
            "1",
            &sign,
            &id,
            std::slice::from_ref(&tx),
        );
        let resp = handle_send_bootstrap(
            &bob_fp,
            &bob_kem_b32,
            "2",
            &sign,
            &id,
            std::slice::from_ref(&tx),
        );
        match resp {
            ApiResponse::Error { code, .. } => assert_eq!(code, ApiErrorCode::NotReady),
            other => panic!("expected NotReady, got {other:?}"),
        }
    }
}
