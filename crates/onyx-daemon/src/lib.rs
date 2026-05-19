//! `onyx-daemon` — the Onyx daemon as a library.
//!
//! Used by two binaries:
//!   * `onyxd` — the standalone daemon. Thin clap-parsing wrapper.
//!   * `onyx`  — the all-in-one user binary. Runs this in a background
//!     task while the TUI renders in the foreground.
//!
//! The original `onyxd` daemon process.
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

pub mod api_server;
pub mod conversations;
pub mod hub_client;
pub mod replay_guard;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use futures::StreamExt;
use onyx_core::api::{MessageDirection, TorState};
use onyx_core::crypto::VerifyingKey;
use onyx_core::crypto::{Argon2Params, IdentityPublic};
use onyx_core::flows::{initiator_exchange, responder_exchange};
use onyx_core::identity::Identity;
use onyx_core::mls::{MlsGroupState, MlsParty};
use onyx_core::storage::Vault;
use onyx_core::tor::TorRuntime;
use onyx_core::transport::{
    Session, handshake_initiator, handshake_responder, read_frame, write_frame,
};
use onyx_core::wire::{FRAME_MLS_APP, InnerFrame};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, mpsc};
use tracing::{Instrument, debug, error, info, info_span, warn};
use zeroize::Zeroizing;

const DEFAULT_IDENTITY_NICKNAME: &str = "default";
const HS_NICKNAME: &str = "onyx";

/// Virtual port on the hidden service.
const ONYX_HS_PORT: u16 = 1;

/// Per-user data directory. Holds the vault, the API socket, and
/// Arti's state directory by default. `$HOME/.onyx` on Unix; falls
/// back to `./.onyx` if `HOME` is unset (so the CLI still works in
/// minimal CI containers).
#[must_use]
pub fn default_data_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
        .join(".onyx")
}

/// Default vault path: `~/.onyx/vault.db`.
#[must_use]
pub fn default_vault_path() -> PathBuf {
    default_data_dir().join("vault.db")
}

/// Default Unix-domain API socket path: `~/.onyx/onyx.sock`.
#[must_use]
pub fn default_api_socket_path() -> String {
    default_data_dir()
        .join("onyx.sock")
        .to_string_lossy()
        .into_owned()
}

/// Create `~/.onyx` (or the given dir) if missing, then chmod it to
/// 0700 on Unix so the vault + socket aren't world-readable. Idempotent
/// — safe to call every run.
///
/// We tighten permissions even if the directory already existed, in
/// case it was created earlier with a wider umask.
pub fn ensure_data_dir(dir: &std::path::Path) -> anyhow::Result<()> {
    use std::fs;
    fs::create_dir_all(dir).with_context(|| format!("creating data dir {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o700);
        fs::set_permissions(dir, perms)
            .with_context(|| format!("chmod 0700 on {}", dir.display()))?;
    }
    Ok(())
}

/// A single configured hub. The daemon spawns one hub-client task
/// per entry of [`Config::hubs`] (T8.1+).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubConfig {
    /// `onion:port` or just `onion` (port defaults to [`ONYX_HS_PORT`]).
    pub onion: String,
    /// X25519 identity public key of the hub, base32.
    pub pubkey: String,
}

/// Configuration for [`run`]. Mirrors the fields the original `onyxd`
/// `Args` clap struct used to carry, minus the clap conflicts/requires
/// constraints — those are enforced by whichever binary is parsing
/// CLI args (`onyxd` or `onyx daemon`). The library trusts its caller.
#[derive(Debug, Clone)]
pub struct Config {
    pub vault: PathBuf,
    /// Vault passphrase. Wrapped in [`Zeroizing`] so the bytes get
    /// scrubbed when the Config (or any clone of it) is dropped —
    /// not just deallocated. T-zeroize-audit.
    pub passphrase: Zeroizing<String>,
    pub no_tor: bool,
    pub tor_state_dir: Option<PathBuf>,
    pub dial_onion: Option<String>,
    pub dial_pubkey: Option<String>,
    pub api_socket: String,
    /// Zero or more hubs the daemon should connect to. Empty list ==
    /// no hub-relayed messaging (only direct peer-to-peer dials).
    /// Multiple entries == publish-to-all-subscribe-to-all multi-hub
    /// mode (T8.1+). The recipient's `EnvelopeReplayGuard` handles
    /// the resulting duplicates transparently.
    pub hubs: Vec<HubConfig>,
    pub listen_tcp: Option<String>,
    pub dial_tcp: Option<String>,
}

/// Bundle of state every handler needs.
///
/// `vault` and `mls_party` both sit behind their own `Mutex`. Lock
/// order: **always take `mls_party` before `vault`** if you need
/// both. (A handler usually only takes them in sequence — operate
/// under the MLS lock, then briefly take the vault lock to persist
/// — but documenting the policy here makes future deadlocks easier
/// to catch.)
#[derive(Debug)]
pub struct DaemonState {
    pub identity: Identity,
    pub identity_id: i64,
    pub mls_party: Arc<Mutex<MlsParty>>,
    pub vault: Arc<Mutex<Vault>>,
    pub conversations: conversations::SharedRegistry,
    /// One outbound channel per configured hub (T8.1+). Empty when
    /// no hubs are configured. Each sender drains into a dedicated
    /// `hub_client::run_hub_session` task. Senders are bounded;
    /// full-mailbox surfaces as `NotReady`.
    ///
    /// Hub deliveries (`HubOutbound::Deliver`) are **fanned out** —
    /// the sender pushes into every channel — so the recipient gets
    /// the envelope from whichever hub it picks up first. The
    /// recipient's `EnvelopeReplayGuard` drops duplicates silently.
    ///
    /// KP fetches (`HubOutbound::FetchKp`) are tried in
    /// configured order, holding [`Self::hub_fetch_lock`] for the
    /// duration so the per-hub FIFO matching invariant in
    /// `hub_client` stays sound. First hub that returns "found"
    /// wins; if all return "not found", the caller surfaces
    /// `NotReady`.
    pub hub_outbounds: Vec<mpsc::Sender<hub_client::HubOutbound>>,
    /// Serialises concurrent `FetchPeerKeyPackage` API calls. The
    /// `FRAME_KP_RESPONSE` wire format has no request id, so the
    /// hub-client's FIFO queue is correct only if we never have more
    /// than one fetch in flight at a time. Hold this mutex across
    /// the whole fetch (push → await response) — slow but correct.
    /// Future T6.x can add request-id multiplexing to remove the
    /// serialisation.
    pub hub_fetch_lock: Arc<Mutex<()>>,
    /// Bounded FIFO seen-set of envelope-body hashes (T7.3-sec.2).
    /// `handle_hub_delivery` consults this before any decryption work
    /// and drops a delivery silently if the hub is replaying an
    /// envelope we have already accepted. In-memory only; resets on
    /// daemon restart (documented restart window, see
    /// `replay_guard::EnvelopeReplayGuard` module rustdoc).
    pub seen_envelopes: Arc<Mutex<replay_guard::EnvelopeReplayGuard>>,
    /// Snapshot of the hubs the daemon was configured with at
    /// startup (T8.2+). Exposed via `IdentityOk.hubs` so the CLI can
    /// embed them in invite URLs (`onyx invite --with-hubs`). Order
    /// matches the order they were passed on the command line. Read
    /// only — the daemon does not currently support runtime hub
    /// reconfiguration.
    pub configured_hubs: Vec<HubConfig>,
}

/// Run the Onyx daemon to completion. Returns when the daemon exits
/// normally (Ctrl-C, peer disconnect in dial mode) or with an error
/// on startup/runtime failure.
///
/// Caller is responsible for setting up tracing-subscriber before
/// the first await. The binary entry points (`onyxd`, `onyx daemon`)
/// each do that exactly once.
//
// Body wires together vault → identity → MLS → Tor → API server →
// optional hub-client task → main mode (accept or dial) → shutdown.
// Splitting for line count would just trade one readable function
// for a fan of context-free helpers each doing 10 lines of setup.
#[allow(clippy::too_many_lines)]
pub async fn run(args: Config) -> anyhow::Result<()> {
    // ── Ensure parent directories exist (vault + socket) ────────────────
    // Default paths live under ~/.onyx/; create that with mode 0700 so
    // the on-disk vault + UDS aren't world-accessible. If the user
    // supplied custom paths under a different parent (e.g. /tmp), we
    // still mkdir -p but don't chmod — that's their territory.
    if let Some(parent) = args.vault.parent()
        && !parent.as_os_str().is_empty()
    {
        if parent == default_data_dir() {
            ensure_data_dir(parent).context("preparing default data dir for vault")?;
        } else {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating vault parent {}", parent.display()))?;
        }
    }
    if let Some(parent) = std::path::Path::new(&args.api_socket).parent()
        && !parent.as_os_str().is_empty()
    {
        if parent == default_data_dir() {
            ensure_data_dir(parent).context("preparing default data dir for socket")?;
        } else {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating socket parent {}", parent.display()))?;
        }
    }

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

    // Construct one outbound mpsc channel per configured hub up
    // front so the API server can hold the Senders alongside the
    // rest of DaemonState (T8.1+). The Receivers are parked here in
    // a Vec and consumed by the spawn-loop below; in --no-tor mode
    // (or when no hubs are configured) the Receivers are dropped
    // and `hub_outbounds` ends up empty — any Send-via-hub attempt
    // then fails cleanly with NotReady rather than queueing into a
    // void.
    let want_hubs = !args.hubs.is_empty() && !args.no_tor;
    let (hub_outbounds, hub_rx_holders) = if want_hubs {
        let mut txs = Vec::with_capacity(args.hubs.len());
        let mut rxs = Vec::with_capacity(args.hubs.len());
        for _ in &args.hubs {
            let (tx, rx) =
                mpsc::channel::<hub_client::HubOutbound>(hub_client::OUTBOUND_QUEUE_CAPACITY);
            txs.push(tx);
            rxs.push(rx);
        }
        (txs, rxs)
    } else {
        (Vec::new(), Vec::new())
    };
    let mut hub_rx_holders = hub_rx_holders;

    // Restore the envelope-replay seen-set from the vault if a
    // previous run persisted one (T7.3-sec.2-persist). Corrupt
    // snapshot → start with an empty guard rather than refuse to
    // launch (losing the seen-set re-opens the replay window for one
    // snapshot cycle, which is strictly better than the daemon
    // failing to boot).
    let initial_guard = if let Some(bytes) = vault
        .load_replay_state(identity_id)
        .context("loading replay state")?
    {
        if let Ok(g) = replay_guard::EnvelopeReplayGuard::restore(&bytes) {
            info!(
                entries = g.len(),
                capacity = g.capacity(),
                "loaded persisted envelope-replay seen-set"
            );
            g
        } else {
            warn!(
                snapshot_bytes = bytes.len(),
                "persisted replay snapshot did not parse; starting with \
                 empty guard (one snapshot cycle of replay vulnerability)"
            );
            replay_guard::EnvelopeReplayGuard::new()
        }
    } else {
        info!("no persisted replay seen-set; starting fresh");
        replay_guard::EnvelopeReplayGuard::new()
    };

    let state = Arc::new(DaemonState {
        identity,
        identity_id,
        mls_party: Arc::new(Mutex::new(mls_party)),
        vault: Arc::new(Mutex::new(vault)),
        conversations: conversations::new_shared(),
        hub_outbounds,
        hub_fetch_lock: Arc::new(Mutex::new(())),
        seen_envelopes: Arc::new(Mutex::new(initial_guard)),
        configured_hubs: args.hubs.clone(),
    });

    drop(args.passphrase);

    // T7.3-sec.2-persist: spawn the periodic snapshot task BEFORE
    // any mode-specific branch so it runs in every mode (TCP-test,
    // no-tor, Tor accept, Tor dial). Tick interval is 60s; the
    // snapshot is skipped when nothing changed since last save
    // (snapshot bytes are deterministic — see the
    // `snapshot_is_deterministic_when_state_unchanged` test).
    spawn_replay_snapshot_task(state.clone());

    let api_socket_path = PathBuf::from(&args.api_socket);

    // ── TEST-ONLY local-TCP modes (--listen-tcp / --dial-tcp) ───────────
    // Skip Tor entirely; useful for testing the chat path on localhost
    // without paying Tor's bootstrap cost. Loudly logged at startup so
    // an operator can't miss that anonymity is OFF.
    if let Some(addr) = args.listen_tcp.as_deref() {
        return run_tcp_listen_mode(addr, state, api_socket_path).await;
    }
    if let Some(addr) = args.dial_tcp.as_deref() {
        // clap `requires = "dial_pubkey"` guarantees this.
        let pubkey_b32 = args
            .dial_pubkey
            .as_deref()
            .expect("clap requires dial_pubkey when dial_tcp is set");
        return run_tcp_dial_mode(addr, pubkey_b32, state, api_socket_path).await;
    }

    if args.no_tor {
        warn!("--no-tor set: skipping Tor; daemon serves only the local API until Ctrl-C");
        let api_task = tokio::spawn(api_server::serve_api(
            api_socket_path,
            state.clone(),
            TorState::Disabled,
        ));
        tokio::select! {
            res = api_task => {
                if let Ok(Err(e)) = res {
                    warn!(error = %e, "API server stopped with error");
                }
            }
            () = wait_for_ctrl_c() => info!("shutting down on Ctrl-C"),
        }
        final_replay_snapshot(&state).await;
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
    let tor = Arc::new(tor);

    // Bring the API server up before the mode-specific logic so that a
    // long-running --dial-mode session is still observable via `onyx status`.
    let api_task = tokio::spawn(api_server::serve_api(
        api_socket_path,
        state.clone(),
        TorState::Ready,
    ));

    // Spawn one hub-client task per configured hub (T8.1+). Each
    // task: dial its hub, subscribe to our own inbox routing id,
    // self-publish a fresh KP per reconnect, drain its dedicated
    // outbound mpsc, decode any DELIVER frames via handle_hub_delivery.
    // Independent backoff per hub so a single flaky hub doesn't
    // perturb the others.
    //
    // All tasks share the same state.seen_envelopes guard so duplicate
    // deliveries (the recipient subscribed on N hubs, sender published
    // to N hubs → N copies of the same envelope) are silently dropped
    // by `EnvelopeReplayGuard` before they surface as events.
    let mut hub_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::with_capacity(args.hubs.len());
    if want_hubs {
        let our_inbox = onyx_core::routing::introduction_inbox(&state.identity.fingerprint());
        info!(
            our_inbox_b32 = %encode_b32(&our_inbox),
            hub_count = args.hubs.len(),
            "hub: our introduction-inbox routing id derived; spawning one client task per hub"
        );
        // IdentitySecret + HybridKemSecret deliberately don't impl
        // Clone. Round-trip via bytes once here; each spawned task
        // reconstructs them on the worker. Both buffers are wrapped
        // in Zeroizing so the raw key material is scrubbed when the
        // loop variable + per-task clones go out of scope —
        // T-zeroize-audit. Without this wrap, the 32-byte X25519
        // seed and ~2.4 KiB hybrid KEM seed would sit in process
        // memory until the allocator happened to overwrite them.
        let our_sk_bytes: Zeroizing<[u8; 32]> =
            Zeroizing::new(*state.identity.identity_key().to_bytes());
        let our_kem_bytes: Zeroizing<Vec<u8>> =
            Zeroizing::new(state.identity.kem_secret().to_bytes().to_vec());

        for (idx, hub_cfg) in args.hubs.iter().enumerate() {
            let (host, port) = hub_client::parse_host_port(&hub_cfg.onion, ONYX_HS_PORT)
                .with_context(|| format!("--hub onion #{idx}: {}", hub_cfg.onion))?;
            let hub_pubkey_bytes = decode_b32_32(&hub_cfg.pubkey)
                .with_context(|| format!("--hub pubkey #{idx}: {}", hub_cfg.pubkey))?;
            let hub_pubkey = IdentityPublic::from_bytes(hub_pubkey_bytes);

            let state_for_hub_task = state.clone();
            let tor_clone = tor.clone();
            // Per-iter Zeroizing clones — both buffers are no longer
            // Copy (the Zeroizing wrapper opts out), so each spawned
            // task gets its own scrub-on-drop copy of the seed bytes.
            let our_sk_bytes_task = our_sk_bytes.clone();
            let our_kem_bytes_task = our_kem_bytes.clone();
            let mut outbound_rx = hub_rx_holders.remove(0);
            let host = host.clone();
            let span = info_span!("hub", idx, host = %host, port);

            hub_tasks.push(tokio::spawn(async move {
                let our_sk = onyx_core::crypto::IdentitySecret::from_bytes(*our_sk_bytes_task);
                let our_kem = std::sync::Arc::new(
                    onyx_core::crypto::HybridKemSecret::from_bytes(&our_kem_bytes_task)
                        .expect("our own KEM secret must round-trip"),
                );
                let state_for_hub_cb = state_for_hub_task.clone();
                let our_kem_for_cb = our_kem.clone();
                let mut backoff = std::time::Duration::from_millis(500);
                loop {
                    let self_publish = {
                        let party = state_for_hub_task.mls_party.lock().await;
                        match party.key_package_bytes() {
                            Ok(kp_bytes) => Some(hub_client::SelfPublish {
                                routing_id: our_inbox,
                                kp_bytes,
                            }),
                            Err(e) => {
                                warn!(error = %e, "hub: KeyPackage generation failed; skipping publish this cycle");
                                None
                            }
                        }
                    };
                    let result = hub_client::run_hub_session(
                        &tor_clone,
                        &host,
                        port,
                        &hub_pubkey,
                        &our_sk,
                        &[our_inbox],
                        &mut outbound_rx,
                        |target, body| {
                            let state = state_for_hub_cb.clone();
                            let our_kem = our_kem_for_cb.clone();
                            async move {
                                handle_hub_delivery(target, body, &state, &our_kem).await;
                            }
                        },
                        self_publish.as_ref(),
                    )
                    .await;
                    match result {
                        Ok(()) => info!("hub: session ended cleanly"),
                        Err(e) => warn!(error = %e, "hub: session ended with error"),
                    }
                    info!(?backoff, "hub: backing off before reconnect");
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff * 2, std::time::Duration::from_secs(30));
                }
            }.instrument(span)));
        }
    }

    let mode_result = if let (Some(onion), Some(pubkey_b32)) = (&args.dial_onion, &args.dial_pubkey)
    {
        run_dial_mode(&tor, &state, onion, pubkey_b32).await
    } else {
        run_accept_mode(&tor, state.clone()).await
    };

    // Final replay-guard snapshot before we abort the API task — the
    // periodic snapshot task may have died mid-tick. T7.3-sec.2-persist.
    final_replay_snapshot(&state).await;

    // Stop the API server so its socket file gets unlinked promptly.
    api_task.abort();
    for h in hub_tasks {
        h.abort();
    }
    // Surface any mode error after API cleanup so it isn't lost.
    mode_result?;

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

    // No final_replay_snapshot here — the run() wrapper calls it
    // after mode_result returns. Keeps the snapshot exactly once.
    drop(hs);
    Ok(())
}

// Generic over the stream type so both real Tor circuits and (for
// `--listen-tcp` test mode) plain TCP sockets exercise exactly the
// same handshake + MLS + chat-loop code path.
async fn handle_inbound<S>(mut stream: S, state: Arc<DaemonState>) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
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

    // Enter the long-lived bidirectional session: peer frames →
    // registry events, registry outbound queue → peer frames. The TUI
    // (or any API tail subscriber) is the consumer.
    let _ = peer_pub_b32; // kept above only for the handshake log line
    peer_session(stream, session, group, peer_pub, state).await
}

// ── Dial mode ──────────────────────────────────────────────────────────────

// The dial flow is one logical sequence — parsing flags, dialling,
// handshaking, deciding bootstrap-vs-resume, running the exchange,
// persisting. Splitting it for line count would just trade one
// readable function for several context-stripped helpers.

// ── TEST-ONLY local-TCP modes ─────────────────────────────────────────────

async fn run_tcp_listen_mode(
    addr: &str,
    state: Arc<DaemonState>,
    api_socket_path: PathBuf,
) -> anyhow::Result<()> {
    warn!(
        addr = %addr,
        "LISTEN-TCP MODE — NO TOR, NO ANONYMITY. Test/dev only. \
         Anyone who can reach this address can speak Noise to this daemon."
    );
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding TCP listener at {addr}"))?;
    let local_addr = listener.local_addr().context("local_addr")?;
    info!(local_addr = %local_addr, "TCP listener bound; accepting connections");

    let identity_pub_b32 = encode_b32(&state.identity.identity_key().public().to_bytes());
    info!(
        identity_pub_b32 = %identity_pub_b32,
        "share `--dial-tcp {local_addr} --dial-pubkey {identity_pub_b32}` with a peer to chat"
    );

    let api_task = tokio::spawn(api_server::serve_api(
        api_socket_path,
        state.clone(),
        TorState::Disabled,
    ));

    let accept_state = state.clone();
    let accept_loop = async move {
        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, "TCP accept failed; continuing");
                    continue;
                }
            };
            info!(peer = %peer_addr, "accepted TCP connection");
            let st = accept_state.clone();
            let span = info_span!("inbound-tcp", peer = %peer_addr);
            tokio::spawn(
                async move {
                    if let Err(e) = handle_inbound(stream, st).await {
                        warn!(error = %e, "TCP inbound handler failed");
                    }
                }
                .instrument(span),
            );
        }
    };

    tokio::select! {
        () = accept_loop => {},
        () = wait_for_ctrl_c() => info!("shutting down on Ctrl-C"),
    }
    final_replay_snapshot(&state).await;
    api_task.abort();
    Ok(())
}

async fn run_tcp_dial_mode(
    addr: &str,
    peer_pubkey_b32: &str,
    state: Arc<DaemonState>,
    api_socket_path: PathBuf,
) -> anyhow::Result<()> {
    warn!(
        addr = %addr,
        "DIAL-TCP MODE — NO TOR, NO ANONYMITY. Test/dev only."
    );
    let peer_pub_bytes: [u8; 32] =
        decode_b32_32(peer_pubkey_b32).context("--dial-pubkey must decode to 32 bytes")?;

    let api_task = tokio::spawn(api_server::serve_api(
        api_socket_path,
        state.clone(),
        TorState::Disabled,
    ));

    info!(addr = %addr, "dialing peer over TCP…");
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .with_context(|| format!("TCP connect to {addr}"))?;
    info!("TCP connected; starting Noise XK handshake (initiator)");

    let mode_result = run_dial_session(stream, peer_pub_bytes, &state).await;

    api_task.abort();
    mode_result
}

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

    info!(host = %host, port = port, "dialing peer onion…");
    let stream = tor
        .dial(&host, port)
        .await
        .map_err(|e| anyhow::anyhow!("dial failed: {e}"))?;
    info!("Tor circuit established; starting Noise XK handshake (initiator)");

    run_dial_session(stream, peer_pub_bytes, state).await
}

/// Post-dial body of the initiator path: Noise XK handshake + MLS
/// bootstrap-or-resume + persistence + long-lived peer session.
/// Generic over the stream type so both Tor circuits and (for the
/// `--dial-tcp` test mode) plain TCP sockets reach exactly the same
/// chat-loop code.
#[allow(clippy::too_many_lines)]
async fn run_dial_session<S>(
    mut stream: S,
    peer_pub_bytes: [u8; 32],
    state: &Arc<DaemonState>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let peer_pub = IdentityPublic::from_bytes(peer_pub_bytes);

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

    // Same long-lived bidirectional session that the accept side runs.
    // No stdin reading here any more — the TUI drives sends via the
    // local API socket.
    peer_session(stream, session, group, peer_static, state.clone()).await
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

// ── Long-lived peer session ───────────────────────────────────────────────
//
// After bootstrap/resume completes both dial and accept sides run the
// same loop: read frames from the peer and feed them into the
// conversation registry as `Incoming` events; pull lines off the
// per-peer outbound mpsc (fed by the `Send` API verb) and encrypt
// them out on the wire.
//
// The TUI (or any API `Tail` subscriber) is the only consumer of the
// incoming events; the daemon process itself doesn't print messages
// to stdout any more (no more `println!("[peer] …")`).
//
// On exit, we deregister the conversation (which fires
// `EventPeerDisconnected` for any active tail), snapshot+save MLS
// state, then drain-and-shutdown the Tor stream.

async fn peer_session<S>(
    mut stream: S,
    mut session: Session,
    mut group: MlsGroupState,
    peer_pub: [u8; 32],
    state: Arc<DaemonState>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let peer_pub_b32 = encode_b32(&peer_pub);
    // Derive the peer's *real* fingerprint by walking the established
    // MLS group's member list and Blake2-hashing whichever member
    // signing key isn't ours. Falls back to the X25519 b32 if the
    // group isn't a tidy 2-party one (e.g. multi-party room) or the
    // bytes don't decode as a valid Ed25519 point.
    let fingerprint = derive_peer_fingerprint(&group, &state, &peer_pub_b32).await;

    let (handle, mut outbound_rx) = {
        let mut reg = state.conversations.lock().await;
        reg.register(peer_pub, &peer_pub_b32, fingerprint)
    };
    let short_id = handle.short_id.clone();
    info!(peer = %short_id, "conversation registered with registry");

    let session_result = drive_peer_session(
        &mut stream,
        &mut session,
        &mut group,
        &peer_pub,
        &state,
        &mut outbound_rx,
    )
    .await;

    {
        let mut reg = state.conversations.lock().await;
        reg.mark_disconnected(&peer_pub);
    }
    info!(peer = %short_id, "conversation marked disconnected");

    persist_final_state(&state).await?;

    // Drain-then-shutdown hack carried over from the old chat loop.
    // Without this, Arti's END marker can outrace in-flight data
    // cells and the peer sees EOF before the last frame. Proper fix
    // is a protocol-level BYE+ACK handshake.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let _ = stream.shutdown().await;
    session_result
}

/// Try to compute the peer's grouped Ed25519 fingerprint by reading
/// the just-established MLS group's member list. Returns the
/// `fallback` (typically `peer_pub_b32`) when anything along the way
/// doesn't decode cleanly — never panics.
async fn derive_peer_fingerprint(
    group: &MlsGroupState,
    state: &Arc<DaemonState>,
    fallback: &str,
) -> String {
    let our_signing_pub = {
        let party = state.mls_party.lock().await;
        party.signing_public_bytes()
    };
    let Some(peer_sig_bytes) = group.peer_signing_key_bytes(&our_signing_pub) else {
        return fallback.to_string();
    };
    let Ok(arr) = <[u8; 32]>::try_from(peer_sig_bytes.as_slice()) else {
        return fallback.to_string();
    };
    let Ok(vk) = VerifyingKey::from_bytes(arr) else {
        return fallback.to_string();
    };
    vk.fingerprint().to_base32_grouped()
}

async fn drive_peer_session<S>(
    stream: &mut S,
    session: &mut Session,
    group: &mut MlsGroupState,
    peer_pub: &[u8; 32],
    state: &Arc<DaemonState>,
    outbound_rx: &mut mpsc::Receiver<String>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    loop {
        tokio::select! {
            // Inbound: a frame arrived on the Tor stream.
            res = read_frame(stream, session) => {
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
                        let text = String::from_utf8_lossy(&plaintext).into_owned();
                        let mut reg = state.conversations.lock().await;
                        reg.push_message(peer_pub, MessageDirection::Incoming, text);
                    }
                    Err(e) => {
                        info!(error = %e, "peer side closed; ending session");
                        return Ok(());
                    }
                }
            }
            // Outbound: the API server pushed a Send into our mpsc.
            // (It also already pushed an `Outgoing` event into the
            // registry's ring buffer + broadcast, so don't double-push.)
            msg = outbound_rx.recv() => {
                let Some(text) = msg else {
                    debug!("outbound channel closed; ending session");
                    return Ok(());
                };
                let ct = {
                    let party = state.mls_party.lock().await;
                    group
                        .encrypt_application(&party, text.as_bytes())
                        .map_err(|e| anyhow::anyhow!("encrypt failed: {e}"))?
                };
                write_frame(
                    stream,
                    session,
                    &InnerFrame {
                        frame_type: FRAME_MLS_APP,
                        payload: ct,
                    },
                )
                .await
                .map_err(|e| anyhow::anyhow!("send failed: {e}"))?;
                info!(text = %text, "chat message sent");
            }
        }
    }
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

// ── Hub-delivery decode (T5.2.d) ──────────────────────────────────────────
//
// Called from the hub-client's on_deliver closure for every
// FRAME_DELIVER that arrives addressed to our routing id(s).
//
// Security-sensitive: anyone connected to the hub can spam bytes
// at our inbox. Decode failures are **silent** (debug-level only)
// so an attacker can't fill operator logs by churning out junk.

async fn handle_hub_delivery(
    target: onyx_core::routing::RoutingId,
    body: Vec<u8>,
    state: &Arc<DaemonState>,
    our_kem: &onyx_core::crypto::HybridKemSecret,
) {
    // 0. Replay defence (T7.3-sec.2): if we've already accepted an
    //    envelope with identical bytes, the hub is replaying it.
    //    Drop without spending CPU on the AEAD decapsulation. The
    //    seen-set is in-memory only — a daemon restart resets it,
    //    documented as a known window in `replay_guard` rustdoc.
    {
        let mut seen = state.seen_envelopes.lock().await;
        if !seen.check_and_record(&body) {
            debug!(
                target_b32 = %encode_b32(&target),
                body_bytes = body.len(),
                "hub: dropping replayed envelope (already accepted)"
            );
            return;
        }
    }

    // 1. Decapsulate + verify the envelope. Failures are expected
    //    (wrong recipient, tampering, garbage from an attacker
    //    probing our inbox) — drop silently at debug level so an
    //    attacker can't fill operator logs by spamming junk.
    let Ok(opened) = onyx_core::routing::open_bootstrap(&body, our_kem) else {
        debug!(
            target_b32 = %encode_b32(&target),
            body_bytes = body.len(),
            "hub: delivery did not open as sealed envelope; dropping"
        );
        return;
    };

    // 2. Demultiplex the inner payload by its versioned `v` tag.
    //    Unknown tags surface here as InvalidEncoding (see
    //    BootstrapPayload::from_cbor); we drop silently too.
    let Ok(payload) = onyx_core::routing::BootstrapPayload::from_cbor(&opened.mls_welcome) else {
        debug!("hub: envelope opened but inner payload did not decode; dropping");
        return;
    };

    let sender_x25519: [u8; 32] = opened.sender_identity_pk.to_bytes();
    let sender_pub_b32 = encode_b32(&sender_x25519);
    let sender_fingerprint = opened.sender_signing_pk.fingerprint().to_string();

    match payload {
        onyx_core::routing::BootstrapPayload::PlainMessage { text } => {
            // 3. Register the sender as a hub-only peer (idempotent),
            //    then push the message tagged as via-hub so the TUI
            //    can render the weaker security tier visibly.
            let mut reg = state.conversations.lock().await;
            let handle = reg.register_hub_only(sender_x25519, &sender_pub_b32, sender_fingerprint);
            reg.push_message_via_hub(&handle.peer_pub, MessageDirection::Incoming, text.clone());
            info!(
                from_short = %handle.short_id,
                text_bytes = text.len(),
                "hub: msg/v1 delivered into registry"
            );
        }
        onyx_core::routing::BootstrapPayload::MlsWelcome {
            welcome,
            first_message,
        } => {
            // 3'. mls/v1: the sender invited us into a fresh MLS group.
            //     Join the group (creates persistent MLS state on our
            //     side), snapshot to vault so a future direct-dial to
            //     this peer can resume the same group, then register
            //     the peer in the conversation registry as hub-only
            //     (we have no direct transport yet — but the *MLS
            //     group* is real and ready).
            //
            //     Silent failure on join (debug-level only): a hostile
            //     hub or attacker could send junk Welcome bytes; we
            //     don't want to spam operator logs.
            let join_result = {
                let party = state.mls_party.lock().await;
                party.join_from_welcome(welcome.as_ref())
            };
            let Ok(group) = join_result else {
                debug!(
                    welcome_bytes = welcome.len(),
                    "hub: mls/v1 Welcome did not join into a group; dropping"
                );
                return;
            };

            // Persist the post-join MLS state so the group survives
            // a daemon restart.
            let snapshot_result = {
                let party = state.mls_party.lock().await;
                party.snapshot_state()
            };
            if let Ok(snap) = snapshot_result {
                let vault = state.vault.lock().await;
                if let Err(e) = vault.save_mls_state(state.identity_id, &snap) {
                    warn!(error = %e, "hub: mls/v1 snapshot save failed");
                }
            }

            // Register the peer. They surface as a hub-only
            // conversation (no direct Tor transport yet), but the
            // MLS group is real — future direct-dial will lift them
            // to a live `Direct` conversation via the existing
            // resume path.
            {
                let mut reg = state.conversations.lock().await;
                let handle =
                    reg.register_hub_only(sender_x25519, &sender_pub_b32, sender_fingerprint);
                let group_id_b32 = encode_b32(&group.group_id_bytes());
                // T7.2-mls-fu: when the sender bundled an introduction
                // text alongside the Welcome (via `onyx accept <url>
                // --text "..."`), surface that as the first message of
                // the conversation. Otherwise fall back to the
                // synthetic "joined" placeholder so the TUI still
                // shows *something* happened on first contact.
                //
                // The text inherits the sealed-envelope's per-message
                // PFS and is authenticated by the outer Ed25519
                // signature — but predates the MLS ratchet, so it
                // shares the Welcome's lack of MLS PCS (the ratchet
                // covers everything sent *inside* the group from now
                // on). Same `via_hub` tag either way so the TUI
                // renders the weaker-tier badge consistently.
                let (text, has_first_message) = if let Some(intro) = first_message {
                    (intro, true)
                } else {
                    (
                        format!("(joined MLS group {group_id_b32} via hub Welcome)"),
                        false,
                    )
                };
                reg.push_message_via_hub(&handle.peer_pub, MessageDirection::Incoming, text);
                info!(
                    from_short = %handle.short_id,
                    mls_epoch = group.epoch(),
                    group_id_b32 = %group_id_b32,
                    has_first_message,
                    "hub: mls/v1 Welcome processed, MLS group joined"
                );
            }
        }
    }
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

/// Tick interval for the envelope-replay seen-set snapshot task
/// (T7.3-sec.2-persist). At 60 s the maximum replay-vulnerability
/// window after an unclean daemon exit is 60 s, which is a defensible
/// trade-off against the cost of an AEAD-sealed SQLite write per
/// tick when the guard hasn't changed.
const REPLAY_SNAPSHOT_INTERVAL_SECS: u64 = 60;

/// Spawn a background task that periodically snapshots the recipient-
/// side envelope-replay seen-set to the vault. T7.3-sec.2-persist.
///
/// The task runs forever (until the parent task aborts it on
/// shutdown). Each tick:
///   1. Lock the guard, take a deterministic snapshot.
///   2. Compare to the last-written bytes; skip the vault round-trip
///      if nothing changed (a quiet daemon costs zero disk I/O).
///   3. Otherwise, lock the vault and persist via
///      [`Vault::save_replay_state`].
///
/// Errors are logged at `warn!` level and the loop continues. A
/// failed snapshot doesn't break the in-memory replay defence —
/// only narrows the restart-window persistence guarantee.
///
/// We deliberately do *not* trigger snapshots on every guard insert
/// because the per-envelope vault write would dominate the cost of
/// receiving a message. The 60 s tick is a coarse but correct
/// amortisation: even a busy daemon snapshots a bounded number of
/// times per minute.
fn spawn_replay_snapshot_task(state: Arc<DaemonState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            REPLAY_SNAPSHOT_INTERVAL_SECS,
        ));
        // Skip the immediate first tick — the guard was just loaded
        // (or freshly created), there is nothing new to persist.
        interval.tick().await;
        let mut last_snapshot: Option<Vec<u8>> = None;
        loop {
            interval.tick().await;
            let snapshot = {
                let guard = state.seen_envelopes.lock().await;
                guard.snapshot()
            };
            if last_snapshot.as_ref() == Some(&snapshot) {
                continue; // unchanged since last write
            }
            let save_result = {
                let vault = state.vault.lock().await;
                vault.save_replay_state(state.identity_id, &snapshot)
            };
            match save_result {
                Ok(()) => {
                    debug!(
                        bytes = snapshot.len(),
                        "replay seen-set snapshot persisted to vault"
                    );
                    last_snapshot = Some(snapshot);
                }
                Err(e) => {
                    warn!(error = %e, "replay seen-set snapshot save failed; will retry next tick");
                }
            }
        }
    });
}

/// Synchronous version of the per-tick snapshot logic. Called once
/// from the Ctrl-C shutdown handler so we narrow the restart window
/// to "what happened since the last successful tick" rather than
/// "everything since the last periodic save".
async fn final_replay_snapshot(state: &DaemonState) {
    let snapshot = {
        let guard = state.seen_envelopes.lock().await;
        guard.snapshot()
    };
    let save_result = {
        let vault = state.vault.lock().await;
        vault.save_replay_state(state.identity_id, &snapshot)
    };
    match save_result {
        Ok(()) => info!(
            bytes = snapshot.len(),
            "final replay snapshot persisted on shutdown"
        ),
        Err(e) => warn!(error = %e, "final replay snapshot save failed on shutdown"),
    }
}
