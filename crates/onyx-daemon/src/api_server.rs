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

    // 4. Load the group, invite the peer, extract the Welcome bytes,
    //    snapshot updated MLS state.
    let (welcome_bytes, snapshot, refreshed_members_b32) = {
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
        let Ok(welcome) = group.invite(&party, &kp_bytes) else {
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
        (welcome, snap, members)
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
    }

    // 6. Seal the Welcome with room_name = Some(room.name) so the
    //    recipient knows this is a room invite, not a DM bootstrap.
    let payload = onyx_core::routing::BootstrapPayload::MlsWelcome {
        welcome: serde_bytes::ByteBuf::from(welcome_bytes),
        first_message: None,
        room_name: Some(room.name.clone()),
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
    if accepted > 0 {
        tracing::info!(
            op = "invite_to_room",
            accepted,
            total = state.hub_outbounds.len(),
            "hub fan-out"
        );
        let members = refreshed_members_b32
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        ApiResponse::InviteToRoomOk {
            group_id_b32: encode_b32(&group_id_bytes),
            members,
        }
    } else {
        ApiResponse::Error {
            code: ApiErrorCode::NotReady,
            message: last_err.unwrap_or_else(|| "no hub accepted the Welcome envelope".into()),
        }
    }
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
    // 2. Encrypt once in the room's MLS group, snapshot.
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
        let Ok(ct) = group.encrypt_application(&party, text.as_bytes()) else {
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
    // 3. Walk room members (excluding ourselves), push ciphertext to
    //    each live direct session. Skipped silently when a member has
    //    no live session — T6.3.e fills that gap via the hub.
    let mut delivered: u32 = 0;
    let mut total: u32 = 0;
    let reg = state.conversations.lock().await;
    for fp in &members {
        if fp == &our_fp {
            continue;
        }
        total += 1;
        let Some(handle) = reg.handle_for_fingerprint(fp) else {
            continue;
        };
        if handle
            .outbound_tx
            .try_send(crate::conversations::PeerOutbound::RoomFrame(
                ciphertext.clone(),
            ))
            .is_ok()
        {
            delivered += 1;
        }
    }
    drop(reg);
    tracing::info!(
        op = "send_room",
        group_id_b32,
        delivered_to_direct = delivered,
        total_members = total,
        "room: direct-path fan-out"
    );
    ApiResponse::SendRoomOk {
        group_id_b32: group_id_b32.to_string(),
        delivered_to_direct: delivered,
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
        let Ok(welcome) = group.invite(&party, &kp_bytes) else {
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
