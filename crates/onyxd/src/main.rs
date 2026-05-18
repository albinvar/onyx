//! `onyxd` — the Onyx daemon process.
//!
//! Responsibilities (DESIGN.md §3.2):
//!
//!   * Own the user's [`onyx_core::identity::Identity`] for the
//!     lifetime of the process (vault is unlocked at startup with a
//!     passphrase from the environment).
//!   * Own a single persistent [`onyx_core::mls::MlsParty`] bound to
//!     the long-term identity, with state saved to the vault after
//!     every meaningful change.
//!   * Run an embedded Tor client and publish the user's v3 hidden
//!     service so peers can dial in.
//!   * Maintain outbound connections to peers and hubs via Tor.
//!   * Expose a local API socket for the CLI (`onyx`) to drive.
//!
//! ## What this revision does
//!
//! Phase T2.3 — daemon-side MLS persistence:
//!
//!   * One shared `MlsParty` per daemon, wrapped as
//!     `Arc<tokio::sync::Mutex<MlsParty>>` so the accept-loop's spawned
//!     handler tasks can all use it consistently.
//!   * At startup, load MLS state from the vault if present; otherwise
//!     create fresh via `MlsParty::from_identity`.
//!   * After each handler exchange completes, snapshot the party's
//!     state and save it back to the vault.
//!   * Logs the loaded state size so persistence is visible.
//!
//! What's NOT here yet:
//!   * Reusing an existing MLS group across reconnections (every
//!     handler still bootstraps a fresh group). The persistence
//!     preserves *historical* group state but doesn't yet route new
//!     traffic to it.
//!   * Local API socket for the CLI.
//!   * Contact verification on dial path.
//!   * Sealed-sender bootstrap on the daemon path.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use futures::StreamExt;
use onyx_core::crypto::{Argon2Params, IdentityPublic};
use onyx_core::flows::{initiator_exchange, responder_exchange};
use onyx_core::identity::Identity;
use onyx_core::mls::{MlsGroupState, MlsParty};
use onyx_core::storage::Vault;
use onyx_core::tor::{TorRuntime, TorStream};
use onyx_core::transport::{
    Session, handshake_initiator, handshake_responder, read_frame, write_frame,
};
use onyx_core::wire::{FRAME_MLS_APP, InnerFrame};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tracing::{Instrument, error, info, info_span, warn};

const DEFAULT_IDENTITY_NICKNAME: &str = "default";
const HS_NICKNAME: &str = "onyx";

/// Virtual port on the hidden service.
const ONYX_HS_PORT: u16 = 1;

#[derive(Parser, Debug)]
#[command(name = "onyxd", version, about = "Onyx daemon")]
struct Args {
    /// Path to the encrypted vault file.
    #[arg(long, env = "ONYX_VAULT", default_value = "./onyx-state.db")]
    vault: PathBuf,

    /// Vault passphrase. Pass via environment variable rather than
    /// command line.
    #[arg(long, env = "ONYX_PASSPHRASE", hide_env_values = true)]
    passphrase: String,

    /// Skip the Tor bootstrap entirely.
    #[arg(long)]
    no_tor: bool,

    /// Override Arti's state directory. Use this to run multiple
    /// daemons on the same machine — each needs its own directory so
    /// they don't fight over Arti's state-file lock. If unset, Arti's
    /// platform default is used.
    #[arg(long, env = "ONYX_TOR_STATE_DIR")]
    tor_state_dir: Option<PathBuf>,

    /// **Dial mode**: connect to a peer's onion instead of publishing
    /// our own hidden service.
    #[arg(long, requires = "dial_pubkey")]
    dial_onion: Option<String>,

    /// X25519 identity public key of the peer to dial (base32).
    #[arg(long, requires = "dial_onion")]
    dial_pubkey: Option<String>,
}

/// Bundle of state every handler needs.
///
/// `vault` and `mls_party` both sit behind their own `Mutex`. Lock
/// order: **always take `mls_party` before `vault`** if you need
/// both. (A handler usually only takes them in sequence — operate
/// under the MLS lock, then briefly take the vault lock to persist
/// — but documenting the policy here makes future deadlocks easier
/// to catch.)
struct DaemonState {
    identity: Identity,
    identity_id: i64,
    mls_party: Arc<Mutex<MlsParty>>,
    vault: Arc<Mutex<Vault>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    // ── Vault + identity + MLS state ────────────────────────────────────
    let mut vault =
        open_or_create_vault(&args.vault, args.passphrase.as_bytes()).context("opening vault")?;

    let (identity_id, identity) =
        ensure_default_identity(&mut vault).context("ensuring default identity")?;

    let fingerprint = identity.fingerprint();
    let identity_pub_b32 = encode_b32(&identity.identity_key().public().to_bytes());
    info!(
        fingerprint = %fingerprint,
        identity_pub_b32 = %identity_pub_b32,
        "vault unlocked, identity loaded"
    );

    // Load or create the persistent MLS party.
    let mls_party = if let Some(state) = vault
        .load_mls_state(identity_id)
        .context("loading MLS state")?
    {
        info!(
            state_bytes = state.len(),
            "loaded persisted MLS state — resuming previous session's groups"
        );
        MlsParty::from_identity_and_state(&identity, &state)
            .map_err(|e| anyhow::anyhow!("MLS state restore failed: {e}"))?
    } else {
        info!("no persisted MLS state; starting fresh");
        MlsParty::from_identity(&identity)
            .map_err(|e| anyhow::anyhow!("MLS party create failed: {e}"))?
    };

    let state = DaemonState {
        identity,
        identity_id,
        mls_party: Arc::new(Mutex::new(mls_party)),
        vault: Arc::new(Mutex::new(vault)),
    };

    drop(args.passphrase);

    if args.no_tor {
        warn!("--no-tor set: skipping Tor; daemon will idle until Ctrl-C");
        wait_for_ctrl_c().await;
        return Ok(());
    }

    // ── Tor bootstrap ───────────────────────────────────────────────────
    let tor = if let Some(dir) = args.tor_state_dir.as_deref() {
        info!(state_dir = %dir.display(), "bootstrapping Tor with custom state directory…");
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating tor state dir {}", dir.display()))?;
        TorRuntime::bootstrap_with_state_dir(dir)
            .await
            .map_err(|e| anyhow::anyhow!("tor bootstrap failed: {e}"))?
    } else {
        info!(
            "bootstrapping Tor with default state directory (this may take 30-60s on a cold cache)…"
        );
        TorRuntime::bootstrap()
            .await
            .map_err(|e| anyhow::anyhow!("tor bootstrap failed: {e}"))?
    };
    info!("Tor bootstrap complete");

    let state = Arc::new(state);

    if let (Some(onion), Some(pubkey_b32)) = (&args.dial_onion, &args.dial_pubkey) {
        run_dial_mode(&tor, &state, onion, pubkey_b32).await?;
    } else {
        run_accept_mode(&tor, state.clone()).await?;
    }

    drop(tor);
    Ok(())
}

// ── Accept mode (default) ──────────────────────────────────────────────────

async fn run_accept_mode(tor: &TorRuntime, state: Arc<DaemonState>) -> anyhow::Result<()> {
    let mut hs = tor
        .publish_hidden_service(HS_NICKNAME)
        .map_err(|e| anyhow::anyhow!("hidden service publish failed: {e}"))?;

    if let Some(addr) = hs.onion_address() {
        info!(
            onion = %addr,
            port = ONYX_HS_PORT,
            "hidden service published — peer needs onion + port + identity_pub_b32"
        );
    } else {
        warn!("hidden service has no address yet — Arti will produce one shortly");
    }

    let mut accept = hs
        .take_accept_streams()
        .context("HS accept-stream already taken")?;

    info!("onyxd running in accept mode. Ctrl-C to stop.");

    let accept_loop = async {
        while let Some(stream) = accept.next().await {
            let state = state.clone();
            let our_fpr = state.identity.fingerprint();
            let span = info_span!("inbound", local_fpr = %our_fpr);
            tokio::spawn(
                async move {
                    if let Err(e) = handle_inbound(stream, state).await {
                        warn!(error = %e, "inbound handler failed");
                    }
                }
                .instrument(span),
            );
        }
        info!("accept stream ended");
    };

    tokio::select! {
        () = accept_loop => {},
        () = wait_for_ctrl_c() => info!("shutting down on Ctrl-C"),
    }

    drop(hs);
    Ok(())
}

async fn handle_inbound(mut stream: TorStream, state: Arc<DaemonState>) -> anyhow::Result<()> {
    info!("accepted inbound stream; starting Noise XK handshake (responder)");
    let mut session = handshake_responder(&mut stream, state.identity.identity_key())
        .await
        .map_err(|e| anyhow::anyhow!("handshake failed: {e}"))?;

    let peer_pub = session.peer_static_key();
    let peer_pub_b32 = encode_b32(&peer_pub);
    info!(
        peer_identity_pub_b32 = %peer_pub_b32,
        "Noise XK complete; awaiting MLS intent from initiator"
    );

    let reply_text = format!(
        "MLS reply from {} (responder)",
        state.identity.fingerprint()
    );

    // Take the MLS party lock for the duration of the exchange + the
    // snapshot. Drop it before taking the vault lock to keep our lock
    // order consistent (MLS first, vault second).
    let (snapshot, group_id, was_bootstrap, group) = {
        let party = state.mls_party.lock().await;
        let outcome = responder_exchange(&mut stream, &mut session, &party, reply_text.as_bytes())
            .await
            .map_err(|e| anyhow::anyhow!("MLS responder flow failed: {e}"))?;
        info!(
            peer_message = %String::from_utf8_lossy(&outcome.peer_message),
            mls_epoch = outcome.group.epoch(),
            was_bootstrap = outcome.was_bootstrap,
            "MLS round-trip complete (responder); entering chat receive loop"
        );
        let group_id = outcome.group.group_id_bytes();
        let snap = party
            .snapshot_state()
            .map_err(|e| anyhow::anyhow!("MLS snapshot failed: {e}"))?;
        (snap, group_id, outcome.was_bootstrap, outcome.group)
    };

    // Persist the post-bootstrap state immediately so a crash mid-chat
    // doesn't lose the group setup. Subsequent in-chat messages
    // re-snapshot on disconnect.
    persist_mls_snapshot(&state, &snapshot).await?;
    if was_bootstrap {
        record_peer_group(&state, &peer_pub, &group_id).await?;
    }

    // Enter the long-lived receive loop. Decrypts incoming MLS app
    // messages and prints them. Exits cleanly on peer disconnect.
    chat_loop_responder(stream, session, group, state, peer_pub_b32).await
}

// ── Dial mode ──────────────────────────────────────────────────────────────

// The dial flow is one logical sequence — parsing flags, dialling,
// handshaking, deciding bootstrap-vs-resume, running the exchange,
// persisting. Splitting it for line count would just trade one
// readable function for several context-stripped helpers.
#[allow(clippy::too_many_lines)]
async fn run_dial_mode(
    tor: &TorRuntime,
    state: &Arc<DaemonState>,
    onion_target: &str,
    peer_pubkey_b32: &str,
) -> anyhow::Result<()> {
    let (host, port) = match onion_target.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .with_context(|| format!("bad port in --dial-onion: {p}"))?,
        ),
        None => (onion_target.to_string(), ONYX_HS_PORT),
    };

    let peer_pub_bytes: [u8; 32] =
        decode_b32_32(peer_pubkey_b32).context("--dial-pubkey must decode to 32 bytes")?;
    let peer_pub = IdentityPublic::from_bytes(peer_pub_bytes);

    info!(host = %host, port = port, "dialing peer onion…");
    let mut stream = tor
        .dial(&host, port)
        .await
        .map_err(|e| anyhow::anyhow!("dial failed: {e}"))?;
    info!("Tor circuit established; starting Noise XK handshake (initiator)");

    let mut session = handshake_initiator(&mut stream, state.identity.identity_key(), &peer_pub)
        .await
        .map_err(|e| anyhow::anyhow!("handshake failed: {e}"))?;

    let peer_static = session.peer_static_key();
    let learned_peer = encode_b32(&peer_static);

    // Defence in depth: Noise XK *should* guarantee that the peer
    // holding the secret matches the pubkey we passed in, but assert
    // it explicitly so any future change to the handshake that
    // weakened the guarantee would fail loudly here instead of
    // silently. (`peer_pub_bytes` is what `--dial-pubkey` decoded to.)
    if peer_static != peer_pub_bytes {
        return Err(anyhow::anyhow!(
            "post-Noise peer static key mismatch — handshake should have caught this; \
             aborting before any application traffic"
        ));
    }
    info!(
        peer_identity_pub_b32 = %learned_peer,
        "peer X25519 matches --dial-pubkey ✓"
    );

    // Do we have a prior MLS group with this peer? If yes, try to
    // resume; if no, bootstrap.
    let existing_group_id = {
        let vault = state.vault.lock().await;
        vault
            .lookup_peer_group(state.identity_id, &peer_static)
            .map_err(|e| anyhow::anyhow!("peer-group lookup failed: {e}"))?
    };

    // Stale-mapping check: if the vault claims a group_id but our
    // MLS storage no longer has that group (e.g. snapshot got
    // corrupted or someone hand-edited the DB), fall back to
    // bootstrap rather than failing the handshake at the responder.
    let existing_group_id = if let Some(gid) = existing_group_id {
        let have_it = {
            let party = state.mls_party.lock().await;
            party
                .load_group(&gid)
                .map_err(|e| anyhow::anyhow!("local MLS group lookup failed: {e}"))?
                .is_some()
        };
        if have_it {
            Some(gid)
        } else {
            warn!(
                "vault has a peer→group mapping but the local MLS state is missing; \
                 dropping stale mapping and falling back to bootstrap"
            );
            let vault = state.vault.lock().await;
            vault
                .forget_peer_group(state.identity_id, &peer_static)
                .map_err(|e| anyhow::anyhow!("forget stale peer-group failed: {e}"))?;
            None
        }
    } else {
        None
    };

    if let Some(gid) = &existing_group_id {
        info!(
            peer_identity_pub_b32 = %learned_peer,
            existing_group_id_bytes = gid.len(),
            "resuming existing MLS group (initiator)"
        );
    } else {
        info!(
            peer_identity_pub_b32 = %learned_peer,
            "no prior group — bootstrapping (initiator)"
        );
    }

    let greeting = format!(
        "MLS hello from {} (initiator)",
        state.identity.fingerprint()
    );

    let (snapshot, group_id, was_bootstrap, group) = {
        let party = state.mls_party.lock().await;
        let outcome = initiator_exchange(
            &mut stream,
            &mut session,
            &party,
            existing_group_id.as_deref(),
            greeting.as_bytes(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("MLS initiator flow failed: {e}"))?;
        info!(
            peer_reply = %String::from_utf8_lossy(&outcome.peer_message),
            mls_epoch = outcome.group.epoch(),
            was_bootstrap = outcome.was_bootstrap,
            "MLS round-trip complete (initiator); entering interactive chat loop"
        );
        let group_id = outcome.group.group_id_bytes();
        let snap = party
            .snapshot_state()
            .map_err(|e| anyhow::anyhow!("MLS snapshot failed: {e}"))?;
        (snap, group_id, outcome.was_bootstrap, outcome.group)
    };

    persist_mls_snapshot(state, &snapshot).await?;
    if was_bootstrap {
        record_peer_group(state, &peer_static, &group_id).await?;
    }

    // Enter the interactive chat loop: stdin lines → encrypt → send;
    // peer frames → decrypt → print. Exits on stdin EOF or peer close.
    chat_loop_initiator(stream, session, group, state.clone()).await
}

// ── Persistence helper ────────────────────────────────────────────────────

async fn persist_mls_snapshot(state: &DaemonState, snapshot: &[u8]) -> anyhow::Result<()> {
    let vault = state.vault.lock().await;
    vault
        .save_mls_state(state.identity_id, snapshot)
        .map_err(|e| anyhow::anyhow!("MLS state save failed: {e}"))?;
    info!(state_bytes = snapshot.len(), "MLS state persisted to vault");
    Ok(())
}

async fn record_peer_group(
    state: &DaemonState,
    peer_x25519: &[u8; 32],
    group_id: &[u8],
) -> anyhow::Result<()> {
    let vault = state.vault.lock().await;
    vault
        .record_peer_group(state.identity_id, peer_x25519, group_id)
        .map_err(|e| anyhow::anyhow!("peer-group record failed: {e}"))?;
    info!(
        group_id_bytes = group_id.len(),
        "recorded peer→group mapping for future resume"
    );
    Ok(())
}

// ── Chat loops ────────────────────────────────────────────────────────────
//
// After bootstrap/resume completes (and the daemons have exchanged a
// greeting + reply as proof of liveness), both sides enter a chat
// loop that lets the MLS conversation continue across many messages.
//
// Dial mode = interactive chat: stdin → encrypt → send AND peer →
// decrypt → print, multiplexed via `tokio::select!`. Exits on stdin
// EOF (Ctrl-D) or peer disconnect.
//
// Accept mode = receive loop: peer → decrypt → print. We deliberately
// don't read stdin in accept mode because tokio::io::stdin() can't
// be cleanly multiplexed across many handler tasks; v0 keeps it
// asymmetric (dialer types, acceptor receives). Bidirectional chat
// belongs to the future CLI/local-API layer.
//
// Both loops snapshot+save MLS state on exit so the ratchet state
// survives the chat closing.

async fn chat_loop_initiator(
    mut stream: TorStream,
    mut session: Session,
    mut group: MlsGroupState,
    state: Arc<DaemonState>,
) -> anyhow::Result<()> {
    eprintln!();
    eprintln!("  ─── chat started — type to send, Ctrl-D (or EOF) to exit ───");
    eprintln!();

    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();

    loop {
        tokio::select! {
            // Peer sent us a frame.
            res = read_frame(&mut stream, &mut session) => {
                match res {
                    Ok(frame) => {
                        if frame.frame_type != FRAME_MLS_APP {
                            warn!(
                                frame_type = format!("{:#06x}", frame.frame_type),
                                "ignoring unexpected frame type from peer"
                            );
                            continue;
                        }
                        let plaintext = {
                            let party = state.mls_party.lock().await;
                            group
                                .decrypt_application(&party, &frame.payload)
                                .map_err(|e| anyhow::anyhow!("decrypt failed: {e}"))?
                        };
                        println!("  [peer] {}", String::from_utf8_lossy(&plaintext));
                    }
                    Err(e) => {
                        info!(error = %e, "peer side closed; ending chat");
                        break;
                    }
                }
            }
            // Stdin produced a line (or EOF).
            res = lines.next_line() => {
                match res {
                    Ok(Some(line)) if line.is_empty() => {
                        // Skip blank lines without sending an empty
                        // MLS application message.
                    }
                    Ok(Some(line)) => {
                        let ct = {
                            let party = state.mls_party.lock().await;
                            group
                                .encrypt_application(&party, line.as_bytes())
                                .map_err(|e| anyhow::anyhow!("encrypt failed: {e}"))?
                        };
                        write_frame(
                            &mut stream,
                            &mut session,
                            &InnerFrame {
                                frame_type: FRAME_MLS_APP,
                                payload: ct,
                            },
                        )
                        .await
                        .map_err(|e| anyhow::anyhow!("send failed: {e}"))?;
                        info!(text = %line, "chat message sent");
                    }
                    Ok(None) => {
                        info!("stdin EOF; ending chat");
                        break;
                    }
                    Err(e) => {
                        warn!(error = %e, "stdin read error; ending chat");
                        break;
                    }
                }
            }
        }
    }

    persist_final_state(&state).await?;
    // Give Arti a moment to actually flush any in-flight cells before
    // tearing down the stream. Without this, the END marker can reach
    // the peer before the final data cells; we observed this as the
    // peer's `read_frame` returning EOF on the next iteration even
    // though we'd just done `write_all` + `flush` successfully. A
    // proper protocol-level "BYE + ACK" handshake is the right fix
    // long-term; for now a small fixed delay does the job.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn chat_loop_responder(
    mut stream: TorStream,
    mut session: Session,
    mut group: MlsGroupState,
    state: Arc<DaemonState>,
    peer_pub_b32: String,
) -> anyhow::Result<()> {
    let peer_short: String = peer_pub_b32.chars().take(8).collect();
    info!(peer = %peer_short, "chat receive loop active; waiting for peer messages");

    loop {
        match read_frame(&mut stream, &mut session).await {
            Ok(frame) => {
                if frame.frame_type != FRAME_MLS_APP {
                    warn!(
                        frame_type = format!("{:#06x}", frame.frame_type),
                        "ignoring unexpected frame type from peer"
                    );
                    continue;
                }
                let plaintext = {
                    let party = state.mls_party.lock().await;
                    group
                        .decrypt_application(&party, &frame.payload)
                        .map_err(|e| anyhow::anyhow!("decrypt failed: {e}"))?
                };
                let text = String::from_utf8_lossy(&plaintext).into_owned();
                // Log structured + print to stdout so operators see it
                // both ways.
                info!(peer = %peer_short, message = %text, "chat message");
                println!("  [{peer_short}] {text}");
            }
            Err(e) => {
                info!(peer = %peer_short, error = %e, "peer side closed; ending receive loop");
                break;
            }
        }
    }

    persist_final_state(&state).await?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn persist_final_state(state: &Arc<DaemonState>) -> anyhow::Result<()> {
    let snapshot = {
        let party = state.mls_party.lock().await;
        party
            .snapshot_state()
            .map_err(|e| anyhow::anyhow!("final snapshot failed: {e}"))?
    };
    persist_mls_snapshot(state, &snapshot).await
}

// ── Vault helpers ──────────────────────────────────────────────────────────

fn open_or_create_vault(path: &std::path::Path, passphrase: &[u8]) -> anyhow::Result<Vault> {
    if path.exists() {
        info!(path = %path.display(), "opening existing vault");
        Vault::open(path, passphrase)
            .map_err(|e| anyhow::anyhow!("vault open failed (wrong passphrase?): {e}"))
    } else {
        info!(path = %path.display(), "creating new vault");
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating vault parent directory {}", parent.display()))?;
        }
        Vault::create(path, passphrase, &Argon2Params::FLOOR)
            .map_err(|e| anyhow::anyhow!("vault create failed: {e}"))
    }
}

fn ensure_default_identity(vault: &mut Vault) -> anyhow::Result<(i64, Identity)> {
    let existing = vault
        .list_identities()
        .map_err(|e| anyhow::anyhow!("list identities: {e}"))?;
    if let Some(first) = existing.into_iter().next() {
        let identity = vault
            .get_identity(first.id)
            .map_err(|e| anyhow::anyhow!("loading identity {}: {e}", first.id))?;
        return Ok((first.id, identity));
    }
    info!("no identity found; generating fresh \"{DEFAULT_IDENTITY_NICKNAME}\" identity");
    let (id, identity) = vault
        .create_identity(DEFAULT_IDENTITY_NICKNAME)
        .map_err(|e| anyhow::anyhow!("create identity: {e}"))?;
    Ok((id, identity))
}

// ── Base32 helpers for 32-byte X25519 pub keys ────────────────────────────

fn encode_b32(bytes: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, bytes)
}

fn decode_b32_32(s: &str) -> anyhow::Result<[u8; 32]> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    let bytes = base32::decode(base32::Alphabet::Rfc4648Lower { padding: false }, &cleaned)
        .ok_or_else(|| anyhow::anyhow!("not valid base32"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("expected 32 bytes, got {}", v.len()))?;
    Ok(arr)
}

async fn wait_for_ctrl_c() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => {}
        Err(e) => error!("failed to listen for Ctrl-C: {e}"),
    }
}
