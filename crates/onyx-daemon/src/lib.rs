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
pub mod files;
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
    /// **TEST-ONLY.** Same shape as `hubs` but the daemon dials the
    /// hub over plain TCP instead of Tor. Used by the smoke harness
    /// in `crates/onyx-daemon/tests/rooms_smoke.rs`. Each entry is
    /// the (addr_with_port, base32_pubkey) of a hub running with
    /// `--listen-tcp`. No Tor, no anonymity.
    pub hub_tcp_addrs: Vec<HubConfig>,
    pub listen_tcp: Option<String>,
    pub dial_tcp: Option<String>,
    /// T-cover.3: mean interval (in seconds) between client → hub
    /// FRAME_PAD cover-traffic frames, on each configured hub.
    /// `None` disables (the v0 default — opt-in until real-Tor
    /// smoke verifies the cadence doesn't itself leak).
    ///
    /// Honest framing: cover traffic raises a hub-watching
    /// adversary's cost to fingerprint "alice is actively chatting
    /// vs idling" by injecting indistinguishable PAD frames at
    /// exponentially-distributed (Poisson-process) intervals. It
    /// does NOT defeat a sophisticated traffic-analysis adversary
    /// — see `ANONYMITY.md` §3.1 for the full caveat. Mean values
    /// below 5s burn bandwidth without proportional gain; values
    /// above 60s mean the gap between cover frames is long enough
    /// that real-traffic bursts still stand out.
    pub cover_traffic_mean_secs: Option<u64>,
    /// T-cover.const ("high mode"): when `Some(ms)`, route **all**
    /// client → hub outbound through a constant-rate pacer that emits
    /// exactly one frame every `ms` milliseconds — a queued real frame
    /// if one is ready at the slot boundary, otherwise a `FRAME_PAD`.
    ///
    /// Unlike the Poisson [`cover_traffic_mean_secs`] emitter (which
    /// adds dummy frames *on top of* real traffic, so real bursts
    /// still ride above the noise floor), constant-rate makes the
    /// observable upstream cadence **invariant**: a hub-watching
    /// observer sees one frame per slot whether you are actively
    /// chatting or idle, so the inter-frame timing distribution no
    /// longer distinguishes the two.
    ///
    /// **Honest scope.** This covers the **client → hub (upstream)**
    /// direction only. The hub → client (downstream) direction still
    /// uses the hub's own (Poisson) cover, so the full bidirectional
    /// guarantee also needs a constant-rate hub. It is per-connection
    /// and does NOT defeat a global adversary correlating Tor entry/
    /// exit, nor TCP open/close ("alice connected") events. It costs
    /// up to one slot of added latency on every real frame plus a
    /// steady `bucket::SMALL`/slot of bandwidth. Mutually exclusive
    /// with [`cover_traffic_mean_secs`]. See `ANONYMITY.md` §3.1.
    pub constant_rate_ms: Option<u64>,
    /// D-1 (`--ephemeral-noise-static`): when `true`, the daemon's
    /// **Noise XK static key** to the hub is a freshly-generated
    /// X25519 keypair on every handshake — the hub no longer learns
    /// the long-term identity X25519 from the Noise layer. The
    /// long-term identity is still used by HIGH-2 sealed-sender
    /// envelopes (which run end-to-end *inside* Noise frames), so DMs
    /// and rooms keep working; only the transport identifier changes.
    ///
    /// **Necessary but not sufficient for §3.2.** The hub still
    /// learns your identity through (a) `SUBSCRIBE` to
    /// `introduction_inbox(fp)` and (b) `FRAME_KP_PUBLISH` — see
    /// `ANONYMITY.md` §3.2. To actually close §3.2 you need to
    /// compose ephemeral Noise with `--no-intro-inbox-subscribe`
    /// AND not publish a KP on this connection. Useful profile:
    /// "I'm in established rooms only, never accepting first contact
    /// via this hub" — the hub then cannot identify you on this
    /// connection at all.
    ///
    /// **Trade-off.** The per-static-key rate limiter (HIGH-3,
    /// `--max-frames-per-minute` on the hub) becomes effectively
    /// per-connection in this mode — a reconnect gets a fresh
    /// bucket. The user accepts this for the anonymity gain; per-
    /// connection frame caps still bound resource use.
    pub ephemeral_noise_static: bool,
    /// T-rotation.a: when `true` (the v0 default), the daemon
    /// subscribes to its own `introduction_inbox(fingerprint)` on
    /// every configured hub so it can receive first-contact
    /// envelopes (msg/v1, mls/v1 bootstraps).
    ///
    /// When `false`, the daemon skips that subscription — it can
    /// still **send** first-contact envelopes and still receives
    /// in-room messages (which route via T6.3.g per-(room, epoch)
    /// session tokens, NOT via intro_inbox), but anyone trying to
    /// reach this identity for the first time over the hub will
    /// have their envelope queued indefinitely.
    ///
    /// **Privacy trade.** The hub-watching adversary loses one
    /// observable: "alice is subscribed to introduction_inbox of
    /// fingerprint F." That subscription, by itself, was a strong
    /// "alice is online" signal (the routing id is fingerprint-
    /// derived; anyone with alice's fingerprint can probe it). See
    /// `ROTATION.md` for the full structural analysis of what this
    /// closes and what remains.
    ///
    /// This is an OPT-OUT for users who've established all their
    /// peer relationships and prefer maximum unlinkability over
    /// first-contact reachability.
    pub subscribe_intro_inbox: bool,
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
    /// T6.3.i (commit/KEM-ad ordering fix): per-group buffer for
    /// room frames that failed `process_incoming` — likely because
    /// they arrived at the wrong epoch (e.g. a KEM-advertisement
    /// encrypted at epoch N+1 reached us before the commit that
    /// advances us from N to N+1). After every successful Commit
    /// merge we drain the buffer and retry each pending frame; the
    /// ones that were waiting for that epoch now decrypt.
    ///
    /// Bounded per group ([`PENDING_ROOM_FRAMES_PER_GROUP_MAX`]) so a
    /// hostile or buggy peer can't fill memory by spamming
    /// undecryptable frames. Overflow drops the *oldest* buffered
    /// frame (FIFO) — losing a single undecryptable retry is the
    /// cheapest failure mode here.
    pub pending_room_frames: PendingRoomFrames,
    /// T-files.b: in-flight file-transfer reassembly state. Map
    /// from sender fingerprint to that peer's in-flight transfers
    /// (keyed by 16-byte file_id from `FileMeta`). Bounded per
    /// sender by `FILES_MAX_INFLIGHT_PER_PEER`; oldest transfer
    /// dropped on overflow. See `FILES.md §4` for the cap-list.
    pub inflight_files: InflightFiles,
    /// T-files.b: file-transfer config (size caps + storage dir +
    /// quota). Defaults from `Config::default_files()` honor the
    /// `FILES.md §4` defaults; operator overrides via CLI.
    pub files_config: FilesConfig,
}

/// T6.3.i: per-group out-of-order room-frame retry buffer. Map
/// from `group_id` (raw MLS bytes) to a FIFO of ciphertexts that
/// failed `process_incoming` and are waiting for an epoch-advancing
/// commit to make them decryptable.
pub type PendingRoomFrames =
    Arc<Mutex<std::collections::HashMap<Vec<u8>, std::collections::VecDeque<Vec<u8>>>>>;

/// T6.3.i: per-group bound on the out-of-order room-frame retry
/// buffer. 64 frames is comfortably above any realistic burst (the
/// typical "race" is at most 2-3 frames: a commit followed by 1-2
/// app messages that were already in flight). Anything beyond that
/// is almost certainly garbage / hostile probing.
pub const PENDING_ROOM_FRAMES_PER_GROUP_MAX: usize = 64;

/// T-files.b: per-peer in-flight file-transfer reassembly state.
/// Outer map keyed by sender fingerprint (so per-peer caps fire
/// correctly); inner map keyed by 16-byte `file_id` from
/// `FileMeta`. Each entry holds the manifest + a sparse chunk
/// buffer. Bounded entries per peer by
/// `FILES_MAX_INFLIGHT_PER_PEER`; bounded bytes per transfer by
/// `FilesConfig::max_recv_size_bytes`.
pub type InflightFiles = Arc<
    Mutex<std::collections::HashMap<String, std::collections::HashMap<[u8; 16], InflightFile>>>,
>;

/// T-files.b: state per in-flight transfer. See
/// [`crate::files::buffer_chunk`] for the reassembly path and
/// `FILES.md §2.7 + §2.11 + §2.12` for the caps this enforces.
#[derive(Debug)]
pub struct InflightFile {
    pub conversation: String,
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub chunks: u32,
    pub chunk_size: u32,
    pub content_hash: Vec<u8>,
    /// Sparse buffer: chunk_index → chunk bytes. Once all chunks
    /// are present, the receiver assembles + verifies + persists.
    pub received: std::collections::HashMap<u32, Vec<u8>>,
    pub started_at_ms: i64,
}

/// T-files.b cap-list §2.7: max simultaneously in-flight
/// transfers per peer. The 11th gets rejected.
pub const FILES_MAX_INFLIGHT_PER_PEER: usize = 10;

/// T-files.b: file-transfer configuration. Defaults per
/// `FILES.md §4`. Operator overrides via CLI / env vars at
/// daemon startup.
#[derive(Debug, Clone)]
pub struct FilesConfig {
    /// Per-file send size cap (§4 row 1).
    pub max_send_size_bytes: u64,
    /// Per-file receive size cap (§4 row 2). Sender's `FileMeta.size`
    /// over this = reject.
    pub max_recv_size_bytes: u64,
    /// Per-peer per-day receive quota (§4 row 3). Rolling 24h.
    pub max_recv_per_day_bytes: u64,
    /// Chunk size (§4 row 5). Bigger = fewer messages but bumps
    /// the wire frame to XLARGE more often. Defaults to 12 KB
    /// (fits inside XLARGE with margin for CBOR + MLS framing).
    pub chunk_size_bytes: u32,
    /// Where received files land on disk (§4 row 6). Default
    /// `<data_dir>/files/`.
    pub storage_dir: PathBuf,
    /// Audit MEDIUM: global cap on bytes reserved across ALL in-flight
    /// receive transfers (every peer, every file). The per-peer
    /// inflight count cap and per-file size cap together still allow
    /// `N_peers × 10 × 50 MB`, which is unbounded in the number of
    /// distinct sender identities. This ceiling bounds aggregate
    /// reassembly memory regardless of identity count: a new FileMeta
    /// whose declared size would push total reserved over this is
    /// rejected. Default 256 MiB.
    pub max_inflight_total_bytes: u64,
    /// Audit MEDIUM: a transfer that hasn't completed within this many
    /// milliseconds of its first `FileMeta` is reaped (its buffered
    /// chunks dropped, its budget freed). Closes the "send all-but-one
    /// chunk and stall forever" memory-pin. Default 10 minutes.
    pub inflight_deadline_ms: i64,
}

impl FilesConfig {
    /// T-files.b: defaults per `FILES.md §4`.
    #[must_use]
    pub fn defaults(data_dir: &std::path::Path) -> Self {
        Self {
            max_send_size_bytes: 50 * 1024 * 1024,
            max_recv_size_bytes: 50 * 1024 * 1024,
            max_recv_per_day_bytes: 500 * 1024 * 1024,
            chunk_size_bytes: 12 * 1024,
            storage_dir: data_dir.join("files"),
            max_inflight_total_bytes: 256 * 1024 * 1024,
            inflight_deadline_ms: 10 * 60 * 1000,
        }
    }
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
    // T-cover.const: constant-rate ("high mode") and Poisson cover are
    // two different disciplines for the same channel; running both at
    // once is incoherent (the pacer already emits a PAD on every idle
    // slot, so a second Poisson injector only adds non-constant noise
    // back on top of the constant cadence). Refuse the contradictory
    // config loudly rather than silently picking a winner.
    if args.constant_rate_ms.is_some() && args.cover_traffic_mean_secs.is_some() {
        anyhow::bail!(
            "--constant-rate-ms and --cover-traffic-mean-secs are mutually exclusive: \
             constant-rate already emits a PAD on every idle slot. Pick one."
        );
    }
    let constant_rate = args
        .constant_rate_ms
        .filter(|ms| *ms > 0)
        .map(std::time::Duration::from_millis);
    // Tor-hub channels first, then TCP-hub channels. Build two
    // separate rx Vecs so each spawn loop drains its own without
    // an implicit ordering dependency (T-smoke: the TCP spawn now
    // runs before the listen_tcp early-return, so it must not
    // steal Tor's rxs).
    let tor_hub_count = if want_hubs { args.hubs.len() } else { 0 };
    let tcp_hub_count = args.hub_tcp_addrs.len();
    let total_hubs = tor_hub_count + tcp_hub_count;
    let (hub_outbounds, mut hub_tor_rxs, mut hub_tcp_rxs) = if total_hubs > 0 {
        let mut txs = Vec::with_capacity(total_hubs);
        let mut tor_rxs = Vec::with_capacity(tor_hub_count);
        let mut tcp_rxs = Vec::with_capacity(tcp_hub_count);
        for _ in 0..tor_hub_count {
            let (tx, rx) = make_hub_outbound_channel(constant_rate);
            txs.push(tx);
            tor_rxs.push(rx);
        }
        for _ in 0..tcp_hub_count {
            let (tx, rx) = make_hub_outbound_channel(constant_rate);
            txs.push(tx);
            tcp_rxs.push(rx);
        }
        (txs, tor_rxs, tcp_rxs)
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };

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
        pending_room_frames: Arc::new(Mutex::new(std::collections::HashMap::new())),
        inflight_files: Arc::new(Mutex::new(std::collections::HashMap::new())),
        files_config: FilesConfig::defaults(
            args.vault
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
        ),
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

    // **TEST-ONLY** spawn the TCP-hub client tasks BEFORE the
    // listen_tcp early-return. Otherwise --listen-tcp would skip
    // hub connectivity entirely, which defeats the smoke-harness
    // shape (`crates/onyx-hub/tests/rooms_smoke.rs`) where the
    // daemon needs both: a TCP listener for direct DM peers AND
    // a TCP-dialled hub for room fan-out. Errors are non-fatal —
    // a misconfigured `--hub-tcp` shouldn't refuse to start the
    // whole daemon.
    if let Err(e) = spawn_tcp_hub_tasks(
        &state,
        &args.hub_tcp_addrs,
        tor_hub_count,
        args.cover_traffic_mean_secs,
        args.subscribe_intro_inbox,
        args.ephemeral_noise_static,
        &mut hub_tcp_rxs,
    ) {
        warn!(error = %e, "failed to spawn TCP-hub tasks; continuing without them");
    }

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
        // D-3: our intro-inbox id is a self-identifier; keep the full
        // value at debug so it doesn't persist in the default on-disk
        // log. The operational milestone stays at info without it.
        info!(
            hub_count = args.hubs.len(),
            "hub: spawning one client task per configured hub"
        );
        debug!(our_inbox_b32 = %encode_b32(&our_inbox), "hub: our introduction-inbox routing id");
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
        // HIGH-1: the Ed25519 signing seed, threaded into each hub task
        // so it can sign SUBSCRIBE proofs. Same Zeroizing round-trip.
        let our_signing_bytes: Zeroizing<[u8; 32]> =
            Zeroizing::new(*state.identity.signing().to_bytes());

        for (idx, hub_cfg) in args.hubs.iter().enumerate() {
            let (host, port) = hub_client::parse_host_port(&hub_cfg.onion, ONYX_HS_PORT)
                .with_context(|| format!("--hub onion #{idx}: {}", hub_cfg.onion))?;
            let hub_pubkey_bytes = decode_b32_32(&hub_cfg.pubkey)
                .with_context(|| format!("--hub pubkey #{idx}: {}", hub_cfg.pubkey))?;
            let hub_pubkey = IdentityPublic::from_bytes(hub_pubkey_bytes);

            let state_for_hub_task = state.clone();
            // D-2: each hub connection gets its own circuit-isolation
            // group, so a network/exit observer can't link this user's
            // separate hub sessions by seeing them share a Tor circuit.
            // The isolated client is held across this task's reconnect
            // loop, so the per-hub isolation is stable.
            let tor_clone = tor.isolated();
            // Per-iter Zeroizing clones — both buffers are no longer
            // Copy (the Zeroizing wrapper opts out), so each spawned
            // task gets its own scrub-on-drop copy of the seed bytes.
            let our_sk_bytes_task = our_sk_bytes.clone();
            let our_kem_bytes_task = our_kem_bytes.clone();
            let our_signing_bytes_task = our_signing_bytes.clone();
            let mut outbound_rx = hub_tor_rxs.remove(0);
            let host = host.clone();
            let subscribe_intro_inbox_task = args.subscribe_intro_inbox;
            let ephemeral_noise_static = args.ephemeral_noise_static;
            let span = info_span!("hub", idx, host = %host, port);

            hub_tasks.push(tokio::spawn(async move {
                let our_sk = onyx_core::crypto::IdentitySecret::from_bytes(*our_sk_bytes_task);
                let our_signing =
                    onyx_core::crypto::SigningKey::from_bytes(&our_signing_bytes_task);
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
                    // T6.3.g: subscribe to our intro_inbox AND every
                    // current room's per-epoch session token.
                    // Computed per (re)connect so vault state at
                    // connect time wins; mid-session room changes
                    // are picked up via incremental
                    // `HubOutbound::Subscribe` pushes from
                    // handle_invite_to_room / refresh_room_roster.
                    // T-rotation.a: subscribe_intro_inbox=false skips
                    // the fingerprint-derived intro_inbox; rooms
                    // still subscribe normally.
                    let mut subscriptions: Vec<onyx_core::routing::RoutingId> = Vec::new();
                    if subscribe_intro_inbox_task {
                        subscriptions.push(our_inbox);
                    }
                    subscriptions.extend(
                        current_room_session_tokens(&state_for_hub_task).await,
                    );
                    info!(
                        sub_count = subscriptions.len(),
                        intro_inbox = subscribe_intro_inbox_task,
                        "hub: connect subscriptions (intro + room session tokens)"
                    );
                    let result = hub_client::run_hub_session(
                        &tor_clone,
                        &host,
                        port,
                        &hub_pubkey,
                        &our_sk,
                        &our_signing,
                        &subscriptions,
                        &mut outbound_rx,
                        |target, body| {
                            let state = state_for_hub_cb.clone();
                            let our_kem = our_kem_for_cb.clone();
                            async move {
                                handle_hub_delivery(target, body, &state, &our_kem).await;
                            }
                        },
                        self_publish.as_ref(),
                        ephemeral_noise_static,
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

            // T-cover.2: per-hub cover-traffic emitter. Opt-in via
            // `--cover-traffic-mean-secs <N>`. The emitter clones the
            // hub's outbound Sender and pushes HubOutbound::Pad at
            // exponentially-distributed intervals (Poisson process
            // with mean N). Stops cleanly when the channel closes.
            if let Some(mean_secs) = args.cover_traffic_mean_secs
                && mean_secs > 0
            {
                let hub_tx = state.hub_outbounds[idx].clone();
                let cover_span = info_span!("cover", hub_idx = idx, mean_secs);
                hub_tasks.push(tokio::spawn(
                    async move {
                        run_cover_traffic_loop(hub_tx, mean_secs).await;
                    }
                    .instrument(cover_span),
                ));
            }
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
        // D-3: the node's own .onion is a self-identifier; keep the full
        // address at debug so it doesn't persist in the default on-disk
        // log. Operators who need it for direct-dial can run with debug
        // logging (a Status-API field is the cleaner follow-up). The
        // info line confirms publication without the address.
        info!(
            port = ONYX_HS_PORT,
            "hidden service published (run with debug logging to print the .onion address)"
        );
        debug!(onion = %addr, port = ONYX_HS_PORT, "hidden service onion address");
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
            // D-3: don't put our own fingerprint on the span — it would
            // propagate to every child log line in the default log.
            let span = info_span!("inbound");
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
    // D-3: peer identity pubkey is a social-graph identifier; keep it
    // at debug so it doesn't persist in the default ~/.onyx/onyx.log
    // (seized-device leak). The operational milestone stays loggable.
    debug!(
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

    // D-3: the peer's onion host is a social-graph identifier — debug,
    // not info, so it stays out of the default on-disk log.
    debug!(host = %host, port = port, "dialing peer onion…");
    // D-2: dial this peer through its own circuit-isolation group, so
    // this direct conversation never shares a Tor circuit with the hub
    // sessions or with another peer dial.
    let stream = tor
        .isolated()
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
    // D-3: peer identifier at debug (see above) — keep it out of the
    // default on-disk log.
    debug!(
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
        debug!(
            peer_identity_pub_b32 = %learned_peer,
            existing_group_id_bytes = gid.len(),
            "resuming existing MLS group (initiator)"
        );
    } else {
        debug!(
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

/// T-1: trust-on-first-use pin/verify of a peer's X25519 identity key
/// against their Ed25519 `fingerprint`, called as we register a
/// conversation. Placeholder fingerprints (the unverified
/// `(peer/<x25519>)` DM fallback, T-3) are skipped — there's no real
/// identity to pin. On a MISMATCH (the presented key differs from the
/// key pinned at first contact) we `warn!` loudly: it's a key rotation
/// or a man-in-the-middle, and the user should re-verify the
/// fingerprint out of band. The pinned key is kept, not auto-trusted;
/// `onyx contact list` flags the change.
async fn pin_check_peer(state: &DaemonState, fingerprint: &str, x25519: &[u8; 32]) {
    if fingerprint.starts_with("(peer/") {
        return; // unverified placeholder — no real identity to pin
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0);
    let outcome = {
        let vault = state.vault.lock().await;
        vault.pin_or_verify(state.identity_id, fingerprint, x25519, now_ms)
    };
    match outcome {
        Ok(onyx_core::storage::PinOutcome::New) => {
            debug!(fingerprint = %fingerprint, "contact: pinned peer identity key (first contact)");
        }
        Ok(onyx_core::storage::PinOutcome::Match) => {}
        Ok(onyx_core::storage::PinOutcome::Mismatch { .. }) => {
            warn!(
                fingerprint = %fingerprint,
                "contact: peer identity key CHANGED from the pinned first-contact key — \
                 possible key rotation OR man-in-the-middle. Re-verify the fingerprint out \
                 of band before trusting this conversation (`onyx contact list` flags it)."
            );
        }
        Err(e) => warn!(error = %e, "contact: pin/verify failed"),
    }
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

    // T-1: pin/verify this peer's identity key before registering.
    pin_check_peer(&state, &fingerprint, &peer_pub).await;

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
    // T-3: each fallback means we could NOT derive the peer's real
    // Ed25519 fingerprint from the MLS group and are attributing the
    // message under the unverified `(peer/<x25519>)` placeholder — i.e.
    // the sender *identity* is not cryptographically attributed. Warn
    // on each path (the peer's raw key is deliberately NOT logged, to
    // avoid the D-3 social-graph leak).
    let Some(peer_sig_bytes) = group.peer_signing_key_bytes(&our_signing_pub) else {
        warn!(
            "fingerprint: peer MLS signing key not found in group; attributing under an \
             unverified (peer/<x25519>) placeholder — sender identity is NOT verified"
        );
        return fallback.to_string();
    };
    let Ok(arr) = <[u8; 32]>::try_from(peer_sig_bytes.as_slice()) else {
        warn!(
            "fingerprint: peer MLS signing key is not 32 bytes; attributing under an \
             unverified (peer/<x25519>) placeholder — sender identity is NOT verified"
        );
        return fallback.to_string();
    };
    let Ok(vk) = VerifyingKey::from_bytes(arr) else {
        warn!(
            "fingerprint: peer MLS signing key is not a valid Ed25519 point; attributing \
             under an unverified (peer/<x25519>) placeholder — sender identity is NOT verified"
        );
        return fallback.to_string();
    };
    vk.fingerprint().to_base32_grouped()
}

// One linear select!-loop driving a peer's DM session (inbound
// decrypt+dispatch, outbound encrypt+send). Over the 100-line budget
// but cohesive — same rationale as the room/render handlers.
#[allow(clippy::too_many_lines)]
async fn drive_peer_session<S>(
    stream: &mut S,
    session: &mut Session,
    group: &mut MlsGroupState,
    peer_pub: &[u8; 32],
    state: &Arc<DaemonState>,
    outbound_rx: &mut mpsc::Receiver<conversations::PeerOutbound>,
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
                        // T6.3.d: an MLS app frame can belong to either
                        // this peer's DM group OR a multi-party room
                        // both sides are members of. Peek the group_id
                        // before decrypting so we route to the correct
                        // MlsGroupState — using the wrong group's
                        // ratchet would just fail to decrypt, but
                        // distinguishing here lets us surface the
                        // message under the right conversation.
                        let incoming_gid = match
                            onyx_core::mls::peek_group_id(&frame.payload) {
                            Ok(g) => g,
                            Err(e) => {
                                debug!(
                                    error = %e,
                                    "MLS frame: cannot peek group_id, dropping"
                                );
                                continue;
                            }
                        };
                        if incoming_gid == group.group_id_bytes() {
                            // DM-tier: decrypt against this peer's DM group.
                            let plaintext = {
                                let party = state.mls_party.lock().await;
                                group
                                    .decrypt_application(&party, &frame.payload)
                                    .map_err(|e| anyhow::anyhow!("decrypt failed: {e}"))?
                            };
                            // Task 322: the DM channel now carries the
                            // `RoomAppMessage` tagged envelope (Text /
                            // FileMeta / FileChunk), not raw UTF-8. Derive
                            // the peer's real fingerprint from the DM
                            // group roster (the member that isn't us) for
                            // file attribution.
                            let peer_fp = {
                                let party = state.mls_party.lock().await;
                                let ours = party.signing_public_bytes();
                                group
                                    .member_signing_keys()
                                    .into_iter()
                                    .find(|k| *k != ours)
                                    .and_then(|k| <[u8; 32]>::try_from(k.as_slice()).ok())
                                    .map(|a| {
                                        onyx_core::crypto::Fingerprint::from_bytes(a).to_string()
                                    })
                            };
                            handle_dm_app_frame(&plaintext, peer_pub, peer_fp, state).await;
                        } else {
                            // Room-tier (T6.3.d): load the matching room
                            // group, decrypt against it, emit a room-
                            // tagged event. Silent debug-level drop if
                            // the group_id doesn't match any group we
                            // know — could be a peer mis-routing a frame
                            // intended for someone else, or a room we
                            // haven't joined yet.
                            handle_room_app_frame(
                                &incoming_gid,
                                &frame.payload,
                                peer_pub,
                                state,
                            ).await;
                        }
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
                let Some(outbound) = msg else {
                    debug!("outbound channel closed; ending session");
                    return Ok(());
                };
                let (frame_payload, log_text) = match outbound {
                    conversations::PeerOutbound::Dm(text) => {
                        // Task 322: DM text now rides the RoomAppMessage
                        // tagged envelope (so files can share the channel).
                        let cbor = onyx_core::room::RoomAppMessage::Text { text: text.clone() }
                            .to_cbor()
                            .map_err(|e| anyhow::anyhow!("dm text encode failed: {e}"))?;
                        let ct = {
                            let party = state.mls_party.lock().await;
                            group
                                .encrypt_application(&party, &cbor)
                                .map_err(|e| anyhow::anyhow!("encrypt failed: {e}"))?
                        };
                        (ct, text)
                    }
                    conversations::PeerOutbound::DmFrame(msg) => {
                        // Task 322: a DM file frame (FileMeta / FileChunk).
                        let cbor = msg
                            .to_cbor()
                            .map_err(|e| anyhow::anyhow!("dm frame encode failed: {e}"))?;
                        let ct = {
                            let party = state.mls_party.lock().await;
                            group
                                .encrypt_application(&party, &cbor)
                                .map_err(|e| anyhow::anyhow!("encrypt failed: {e}"))?
                        };
                        (ct, "[dm file frame]".to_string())
                    }
                    conversations::PeerOutbound::RoomFrame(ct) => {
                        // Pre-encrypted in the room's MLS group state
                        // by handle_send_room (T6.3.d). Forward as-is;
                        // never decrypt-and-re-encrypt — that would
                        // burn an extra MLS ratchet step per
                        // recipient and break the "one ciphertext for
                        // the whole group" property MLS gives us.
                        let bytes = ct.len();
                        (ct, format!("[room ciphertext, {bytes} B]"))
                    }
                };
                write_frame(
                    stream,
                    session,
                    &InnerFrame {
                        frame_type: FRAME_MLS_APP,
                        payload: frame_payload,
                    },
                )
                .await
                .map_err(|e| anyhow::anyhow!("send failed: {e}"))?;
                info!(text = %log_text, "chat message sent");
            }
        }
    }
}

/// Task 322: handle a decrypted DM application frame. The DM channel
/// carries the `RoomAppMessage` tagged envelope (shared with rooms):
/// `Text` is surfaced as an incoming chat message; `FileMeta` /
/// `FileChunk` run the same receive pipeline as room files, scoped to
/// the `peer/<short>` conversation. `KemAdvertisement` is room-only
/// and ignored on the DM channel. `peer_fp` is the peer's real
/// fingerprint (from the DM group roster) for file attribution.
async fn handle_dm_app_frame(
    plaintext: &[u8],
    peer_pub: &[u8; 32],
    peer_fp: Option<String>,
    state: &Arc<DaemonState>,
) {
    let Ok(msg) = onyx_core::room::RoomAppMessage::from_cbor(plaintext) else {
        debug!(
            plaintext_bytes = plaintext.len(),
            "dm: decrypted but RoomAppMessage decode failed; dropping"
        );
        return;
    };
    let conversation = format!("peer/{}", short_id_of_peer_pub(peer_pub));
    // T-3 / §8.2 #5: when we have no authenticated Ed25519 fingerprint
    // for the DM peer, attribute under a `(peer/<x25519-short>)`
    // placeholder that is visually distinct from a real fingerprint
    // AND log a warn — the sender *identity* is not verified on this
    // path (the Noise handshake authenticates the X25519 static key,
    // which is a different key from the Ed25519 identity). Full
    // resolution needs identity-key pinning (T-1).
    let sender_fp = peer_fp.unwrap_or_else(|| {
        warn!(
            peer_short = %short_id_of_peer_pub(peer_pub),
            "dm: no authenticated Ed25519 fingerprint for this peer; attributing the \
             message under a non-identity (peer/<x25519>) placeholder — sender identity \
             is NOT verified"
        );
        format!("(peer/{})", short_id_of_peer_pub(peer_pub))
    });
    match msg {
        onyx_core::room::RoomAppMessage::Text { text } => {
            state.conversations.lock().await.push_message(
                peer_pub,
                MessageDirection::Incoming,
                text,
            );
        }
        onyx_core::room::RoomAppMessage::FileMeta {
            id,
            name,
            mime,
            size,
            chunks,
            chunk_size,
            content_hash,
        } => {
            let now_ms = now_unix_ms_i64();
            let decision = files::accept_file_meta(
                state,
                &sender_fp,
                &conversation,
                id.as_ref(),
                &name,
                &mime,
                size,
                chunks,
                chunk_size,
                content_hash.as_ref(),
                now_ms,
            )
            .await;
            match decision {
                files::AcceptDecision::Accepted => {
                    info!(sender_fp = %sender_fp, size, chunks, "dm file accepted; awaiting chunks");
                }
                other => warn!(?other, sender_fp = %sender_fp, "dm file rejected"),
            }
        }
        onyx_core::room::RoomAppMessage::FileChunk { id, index, bytes } => {
            let now_ms = now_unix_ms_i64();
            if let Some(path) = files::accept_file_chunk(
                state,
                &sender_fp,
                id.as_ref(),
                index,
                bytes.as_ref(),
                now_ms,
            )
            .await
            {
                info!(path = %path.display(), "dm file received + persisted");
            }
        }
        onyx_core::room::RoomAppMessage::KemAdvertisement { .. } => {
            debug!("dm: KemAdvertisement is room-only; ignoring on DM channel");
        }
    }
}

/// Decrypt an MLS app frame whose group_id is *not* this peer's DM
/// group — i.e. it belongs to a multi-party room (T6.3.d). Looks up
/// the matching `MlsGroupState` via `MlsParty::load_group`, decrypts,
/// and emits the message as a room-tagged event. Failures are debug-
/// level only (a peer could route a frame to us that we don't have
/// the group for — likely lag, not an attack).
//
// Body is a single linear sequence (peek → decrypt → snapshot →
// dispatch by RoomAppMessage variant → emit). Each stage needs to
// short-circuit on its own failure mode; per-step extraction would
// yield small helpers each carrying its own typed error response
// for no net readability win.
#[allow(clippy::too_many_lines)]
async fn handle_room_app_frame(
    group_id: &[u8],
    payload: &[u8],
    sender_peer_pub: &[u8; 32],
    state: &Arc<DaemonState>,
) {
    // T6.3.h: an incoming MLS frame for a room can be either an
    // application message (chat text or KEM advertisement) OR a
    // commit (an existing member added/removed someone — we must
    // merge it so our group state advances to the new epoch).
    // `process_incoming` discriminates internally.
    let processed_result = {
        let party = state.mls_party.lock().await;
        match party.load_group(group_id) {
            Ok(Some(mut room_group)) => room_group
                .process_incoming_with_sender(&party, payload)
                .map(|(im, sender)| (im, sender, room_group.epoch())),
            Ok(None) => {
                debug!(
                    group_id_b32 = %encode_b32(group_id),
                    "MLS room frame: no matching group; dropping"
                );
                return;
            }
            Err(e) => {
                debug!(error = %e, "MLS room frame: load_group failed; dropping");
                return;
            }
        }
    };
    let Ok((incoming, sender_identity, epoch)) = processed_result else {
        // T6.3.i: process_incoming failed — most likely the message
        // arrived ahead of a commit that would have advanced us to
        // the right epoch (e.g. a KEM-ad encrypted at N+1 reached
        // us before the commit from N→N+1). Stash for retry; we'll
        // re-feed every pending frame for this group right after
        // the next Commit merge lands.
        buffer_pending_room_frame(group_id, payload, state).await;
        return;
    };
    // Persist updated MLS state regardless of message kind — both
    // app messages and commits mutate the ratchet.
    let snap_result = {
        let party = state.mls_party.lock().await;
        party.snapshot_state()
    };
    if let Ok(snap) = snap_result {
        let vault = state.vault.lock().await;
        if let Err(e) = vault.save_mls_state(state.identity_id, &snap) {
            warn!(error = %e, "room frame: snapshot save failed");
        }
    }
    let plaintext = match incoming {
        onyx_core::mls::IncomingRoomMessage::Application(pt) => pt,
        onyx_core::mls::IncomingRoomMessage::Commit => {
            refresh_room_roster_after_commit(group_id, sender_peer_pub, epoch, state).await;
            // T6.3.i: a commit just advanced our epoch — drain the
            // per-group pending-frame buffer and retry each frame.
            // The ones that were waiting for this epoch now succeed.
            drain_pending_room_frames(group_id, sender_peer_pub, state).await;
            return;
        }
    };
    // T6.3.h: every room app message is a CBOR-tagged RoomAppMessage.
    // Drop at debug (no warn) on decode failure — could be a pre-
    // T6.3.h sender (no such installed base today) or future variant.
    let Ok(msg) = onyx_core::room::RoomAppMessage::from_cbor(&plaintext) else {
        debug!(
            group_id_b32 = %encode_b32(group_id),
            plaintext_bytes = plaintext.len(),
            "room: decrypted but RoomAppMessage CBOR decode failed; dropping"
        );
        return;
    };
    // Task 321: attribute the message to the sender's REAL fingerprint
    // (from the MLS credential), not the transport-key placeholder. The
    // BasicCredential identity is the Ed25519 fingerprint bytes; if for
    // any reason it isn't 32 bytes, fall back to the old placeholder so
    // attribution degrades gracefully rather than dropping the message.
    let sender_fp = sender_identity
        .as_deref()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .map_or_else(
            || format!("(peer/{})", short_id_of_peer_pub(sender_peer_pub)),
            |arr| onyx_core::crypto::Fingerprint::from_bytes(arr).to_string(),
        );
    match msg {
        onyx_core::room::RoomAppMessage::Text { text } => {
            info!(
                group_id_b32 = %encode_b32(group_id),
                from_peer_short = %short_id_of_peer_pub(sender_peer_pub),
                mls_epoch = epoch,
                text_bytes = text.len(),
                "room: incoming text message"
            );
            // T-polish.3: persist to room_messages so the TUI can
            // backfill scrollback after restart. Task 321: sender_fp is
            // now the real MLS-credential fingerprint.
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
                    group_id,
                    false,
                    &sender_fp,
                    &text,
                    now_ms,
                ) {
                    warn!(error = %e, "room: append_room_message failed");
                }
            }
            let _ = state.conversations.lock().await.push_room_message(
                group_id,
                *sender_peer_pub,
                text,
            );
        }
        onyx_core::room::RoomAppMessage::KemAdvertisement {
            fingerprint,
            kem_pub,
        } => {
            // T6.3.h: in-room KEM-pub advertisement from another
            // member, persisted into room_member_kems so we can
            // hub-fallback to that member later.
            //
            // G-1: key the entry on `sender_fp` — the fingerprint
            // pulled from the MLS *credential* of whoever sent this
            // frame — NOT the `fingerprint` carried in the message
            // body. A member can only advertise their OWN KEM; using
            // the body value would let a malicious member persist a
            // KEM under another member's fingerprint, poisoning that
            // member's directory entry (delivery DoS, or worse if the
            // poisoned KEM is the attacker's). If the body claims a
            // different fingerprint, drop it as a poisoning attempt.
            if fingerprint == sender_fp {
                let vault = state.vault.lock().await;
                match vault.save_room_member_kem(
                    state.identity_id,
                    group_id,
                    &sender_fp,
                    kem_pub.as_ref(),
                ) {
                    Ok(()) => info!(
                        group_id_b32 = %encode_b32(group_id),
                        member_fp = %sender_fp,
                        kem_bytes = kem_pub.len(),
                        "room: KEM advertisement persisted"
                    ),
                    Err(e) => warn!(
                        error = %e,
                        member_fp = %sender_fp,
                        "room: KEM advertisement save failed"
                    ),
                }
            } else {
                warn!(
                    claimed_fp = %fingerprint,
                    authenticated_fp = %sender_fp,
                    "room: KEM advertisement body fingerprint != MLS-credential sender; \
                     dropping as a poisoning attempt"
                );
            }
        }
        onyx_core::room::RoomAppMessage::FileMeta {
            id,
            name,
            mime,
            size,
            chunks,
            chunk_size,
            content_hash,
        } => {
            // T-files.b: handshake-side of a file transfer. Run
            // the receive caps + allocate the in-flight buffer.
            // Task 321: sender_fp is the real MLS fingerprint (computed
            // above). Conversation = "room/<gid_short>".
            let conversation =
                format!("room/{}", crate::conversations::short_id_of_group(group_id));
            let now_ms = now_unix_ms_i64();
            let decision = files::accept_file_meta(
                state,
                &sender_fp,
                &conversation,
                id.as_ref(),
                &name,
                &mime,
                size,
                chunks,
                chunk_size,
                content_hash.as_ref(),
                now_ms,
            )
            .await;
            match decision {
                files::AcceptDecision::Accepted => info!(
                    sender_fp = %sender_fp,
                    size, chunks, mime = %mime,
                    "file transfer accepted; waiting for chunks"
                ),
                other => warn!(?other, sender_fp = %sender_fp, "file transfer rejected"),
            }
        }
        onyx_core::room::RoomAppMessage::FileChunk { id, index, bytes } => {
            // T-files.b: chunk-side. accept_file_chunk dedups,
            // appends, and triggers finalize when complete. Task 321:
            // uses the real sender_fp computed above.
            let now_ms = now_unix_ms_i64();
            if let Some(path) = files::accept_file_chunk(
                state,
                &sender_fp,
                id.as_ref(),
                index,
                bytes.as_ref(),
                now_ms,
            )
            .await
            {
                info!(path = %path.display(), "file received + persisted");
            }
        }
    }
}

/// T-files.b: i64 wall-clock helper. Used by the file handler.
fn now_unix_ms_i64() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()),
    )
    .unwrap_or(0)
}

/// **TEST-ONLY** spawn the TCP-hub client tasks (and their
/// per-hub cover-traffic emitters when enabled). Mirrors the
/// Tor-hub spawn loop in `run` but uses
/// [`hub_client::run_hub_session_tcp`] instead of the Tor dial.
/// Tasks are spawned-and-forgotten — they live for the daemon's
/// lifetime and die with the runtime.
fn spawn_tcp_hub_tasks(
    state: &Arc<DaemonState>,
    hub_tcp_addrs: &[HubConfig],
    tor_hub_count: usize,
    cover_traffic_mean_secs: Option<u64>,
    subscribe_intro_inbox: bool,
    ephemeral_noise_static: bool,
    hub_tcp_rxs: &mut Vec<mpsc::Receiver<hub_client::HubOutbound>>,
) -> anyhow::Result<()> {
    if hub_tcp_addrs.is_empty() {
        return Ok(());
    }
    warn!(
        count = hub_tcp_addrs.len(),
        "HUB-TCP MODE — no Tor on hub side; test/dev only"
    );
    let our_sk_bytes: Zeroizing<[u8; 32]> =
        Zeroizing::new(*state.identity.identity_key().to_bytes());
    let our_signing_bytes: Zeroizing<[u8; 32]> =
        Zeroizing::new(*state.identity.signing().to_bytes());
    let our_inbox = onyx_core::routing::introduction_inbox(&state.identity.fingerprint());
    for (rel_idx, hub_cfg) in hub_tcp_addrs.iter().enumerate() {
        let hub_pubkey_bytes = decode_b32_32(&hub_cfg.pubkey)
            .with_context(|| format!("--hub-tcp pubkey: {}", hub_cfg.pubkey))?;
        let hub_pubkey = IdentityPublic::from_bytes(hub_pubkey_bytes);
        let addr = hub_cfg.onion.clone();
        let state_for_hub_task = state.clone();
        let our_sk_bytes_task = our_sk_bytes.clone();
        let our_signing_bytes_task = our_signing_bytes.clone();
        let mut outbound_rx = hub_tcp_rxs.remove(0);
        let absolute_idx = tor_hub_count + rel_idx;
        let span = info_span!("hub-tcp", idx = absolute_idx, addr = %addr);
        tokio::spawn(
            async move {
                let our_sk = onyx_core::crypto::IdentitySecret::from_bytes(*our_sk_bytes_task);
                let our_signing =
                    onyx_core::crypto::SigningKey::from_bytes(&our_signing_bytes_task);
                let state_for_hub_cb = state_for_hub_task.clone();
                let mut backoff = std::time::Duration::from_millis(500);
                loop {
                    let self_publish = {
                        let party = state_for_hub_task.mls_party.lock().await;
                        party
                            .key_package_bytes()
                            .ok()
                            .map(|kp_bytes| hub_client::SelfPublish {
                                routing_id: our_inbox,
                                kp_bytes,
                            })
                    };
                    let mut subscriptions: Vec<onyx_core::routing::RoutingId> = Vec::new();
                    if subscribe_intro_inbox {
                        subscriptions.push(our_inbox);
                    }
                    subscriptions.extend(current_room_session_tokens(&state_for_hub_task).await);
                    let kem_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
                        state_for_hub_task.identity.kem_secret().to_bytes().to_vec(),
                    );
                    let our_kem = std::sync::Arc::new(
                        onyx_core::crypto::HybridKemSecret::from_bytes(&kem_bytes)
                            .expect("own KEM round-trip"),
                    );
                    let our_kem_for_cb = our_kem.clone();
                    let result = hub_client::run_hub_session_tcp(
                        &addr,
                        &hub_pubkey,
                        &our_sk,
                        &our_signing,
                        &subscriptions,
                        &mut outbound_rx,
                        |target, body| {
                            let state = state_for_hub_cb.clone();
                            let our_kem = our_kem_for_cb.clone();
                            async move {
                                handle_hub_delivery(target, body, &state, &our_kem).await;
                            }
                        },
                        self_publish.as_ref(),
                        ephemeral_noise_static,
                    )
                    .await;
                    match result {
                        Ok(()) => info!("hub-tcp: session ended cleanly"),
                        Err(e) => warn!(error = %e, "hub-tcp: session ended with error"),
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff * 2, std::time::Duration::from_secs(30));
                }
            }
            .instrument(span),
        );

        if let Some(mean_secs) = cover_traffic_mean_secs
            && mean_secs > 0
        {
            let hub_tx = state.hub_outbounds[absolute_idx].clone();
            let cover_span = info_span!("cover-tcp", hub_idx = absolute_idx, mean_secs);
            tokio::spawn(
                async move {
                    run_cover_traffic_loop(hub_tx, mean_secs).await;
                }
                .instrument(cover_span),
            );
        }
    }
    Ok(())
}

/// T-cover.2: emit `HubOutbound::Pad` at exponentially-distributed
/// intervals (Poisson process with mean `mean_secs`). Sender clone
/// is consumed when the channel closes (daemon shutdown) — that's
/// the clean termination signal.
///
/// **Why Poisson, not fixed-interval.** A fixed-clock cover-traffic
/// emitter is itself a fingerprint: an adversary correlating frame
/// arrival times across the whole hub population can pick out the
/// "tick" cadence and silently subtract it from each user's stream.
/// A Poisson process — where inter-arrival times are exponentially
/// distributed — produces gaps that are memoryless: the time until
/// the next frame doesn't depend on how long it's been since the
/// last one, so there's no rhythm to subtract.
///
/// Two clamps:
///   * minimum 1s between frames so a CSPRNG outlier doesn't
///     accidentally produce a microsecond gap that would saturate
///     the Tor circuit.
///   * Hard maximum at 10 × mean to avoid the long-tail of the
///     exponential producing a "we never sent anything" gap that
///     itself signals something.
async fn run_cover_traffic_loop(tx: mpsc::Sender<hub_client::HubOutbound>, mean_secs: u64) {
    info!(mean_secs, "cover-traffic emitter: started");
    loop {
        let dt = next_exponential_interval(mean_secs);
        tokio::time::sleep(dt).await;
        if tx.send(hub_client::HubOutbound::Pad).await.is_err() {
            info!("cover-traffic emitter: outbound channel closed; ending");
            return;
        }
        tracing::trace!(interval_ms = dt.as_millis(), "cover: PAD queued");
    }
}

/// Build one hub's outbound channel pair: `(Sender held by the API,
/// Receiver drained by the hub session)`.
///
/// With `constant_rate` set (T-cover.const "high mode") this
/// interposes a [`run_constant_rate_pacer`] task between the two: the
/// API pushes into the pacer's input, and the pacer forwards exactly
/// one frame per slot — a queued real frame or a `Pad` — into the
/// session's input. The session loop ([`hub_client::serve_session`])
/// is unchanged; it simply writes whatever the pacer hands it, so the
/// constant cadence is produced entirely in this isolated, testable
/// stage. Without `constant_rate` it returns a plain channel and the
/// API talks to the session directly (the default, zero-overhead
/// path).
fn make_hub_outbound_channel(
    constant_rate: Option<std::time::Duration>,
) -> (
    mpsc::Sender<hub_client::HubOutbound>,
    mpsc::Receiver<hub_client::HubOutbound>,
) {
    let (api_tx, api_rx) =
        mpsc::channel::<hub_client::HubOutbound>(hub_client::OUTBOUND_QUEUE_CAPACITY);
    match constant_rate {
        None => (api_tx, api_rx),
        Some(slot) => {
            let (session_tx, session_rx) =
                mpsc::channel::<hub_client::HubOutbound>(hub_client::OUTBOUND_QUEUE_CAPACITY);
            let slot_ms = u64::try_from(slot.as_millis()).unwrap_or(u64::MAX);
            tokio::spawn(
                run_constant_rate_pacer(api_rx, session_tx, slot)
                    .instrument(info_span!("cover-const", slot_ms)),
            );
            (api_tx, session_rx)
        }
    }
}

/// T-cover.const: drain `real_rx` at a fixed cadence and forward into
/// `paced_tx`, emitting one queued real frame per slot or a
/// `HubOutbound::Pad` when the slot finds nothing waiting. The result
/// is an **invariant** client→hub frame cadence: a hub-watching
/// observer sees one frame every `slot` whether the user is chatting
/// or idle, so the inter-frame timing distribution no longer
/// distinguishes the two states.
///
/// Contrast with [`run_cover_traffic_loop`] (Poisson): that injects
/// dummy frames *alongside* real ones, so a real burst still rises
/// above the noise floor and an adversary autocorrelating the rate
/// can eventually pull it back out. Constant-rate removes the rate
/// signal entirely (at the cost of up to one slot of latency on every
/// real frame, plus a steady PAD/slot of bandwidth even when idle).
///
/// `MissedTickBehavior::Delay` is load-bearing for the security
/// property: if a slot's forward stalls (the session's input is full
/// because the hub link is slow or reconnecting), the next tick is
/// scheduled one full `slot` after the stall clears — never a burst
/// of catch-up frames that would reintroduce a detectable rate spike.
///
/// Terminates when either side closes: `real_rx` disconnecting (the
/// API's Sender — held in `DaemonState` for the process lifetime — so
/// this only happens on shutdown) or `paced_tx` failing to send (the
/// session Receiver dropped). Both are the clean shutdown signal.
async fn run_constant_rate_pacer(
    mut real_rx: mpsc::Receiver<hub_client::HubOutbound>,
    paced_tx: mpsc::Sender<hub_client::HubOutbound>,
    slot: std::time::Duration,
) {
    info!(slot_ms = slot.as_millis(), "constant-rate pacer: started");
    let mut ticker = tokio::time::interval(slot);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let frame = match real_rx.try_recv() {
            Ok(action) => action,
            Err(mpsc::error::TryRecvError::Empty) => hub_client::HubOutbound::Pad,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                info!("constant-rate pacer: input channel closed; ending");
                return;
            }
        };
        if paced_tx.send(frame).await.is_err() {
            info!("constant-rate pacer: session channel closed; ending");
            return;
        }
    }
}

/// Sample an exponentially-distributed inter-arrival interval with
/// mean `mean_secs`. Uses the inverse-CDF method: `-mean * ln(u)`
/// where `u` is uniform on `(0, 1]`. Both clamps documented on
/// [`run_cover_traffic_loop`].
//
// Precision-loss + truncation casts are intentional here: the f64
// computations only need to drive a sleep duration, not maintain
// cryptographic precision. The clamp keeps the result in a sane
// range regardless of float weirdness.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn next_exponential_interval(mean_secs: u64) -> std::time::Duration {
    let mut buf = [0u8; 8];
    onyx_core::crypto::fill_random(&mut buf);
    // Map 0..2^64 → (0, 1]. We add 1 before dividing to avoid the
    // exact-zero case (which would make ln(0) = -∞).
    let raw = u64::from_le_bytes(buf);
    let u = (raw as f64 + 1.0) / (u64::MAX as f64 + 1.0);
    let mean = mean_secs as f64;
    let secs = -mean * u.ln();
    let max_secs = mean * 10.0;
    let clamped = secs.clamp(1.0, max_secs);
    let millis = (clamped * 1000.0) as u64;
    std::time::Duration::from_millis(millis)
}

/// T6.3.i: stash a room frame that just failed `process_incoming`,
/// keyed by `group_id`. Bounded per group at
/// [`PENDING_ROOM_FRAMES_PER_GROUP_MAX`]; overflow drops the oldest
/// buffered frame (FIFO). The next successful Commit merge on this
/// group calls [`drain_pending_room_frames`] which retries every
/// frame currently in the buffer.
async fn buffer_pending_room_frame(group_id: &[u8], payload: &[u8], state: &Arc<DaemonState>) {
    let mut pending = state.pending_room_frames.lock().await;
    let q = pending.entry(group_id.to_vec()).or_default();
    if q.len() >= PENDING_ROOM_FRAMES_PER_GROUP_MAX {
        q.pop_front();
        debug!(
            group_id_b32 = %encode_b32(group_id),
            "T6.3.i: pending-frame buffer full; dropped oldest"
        );
    }
    q.push_back(payload.to_vec());
    debug!(
        group_id_b32 = %encode_b32(group_id),
        pending = q.len(),
        "T6.3.i: room frame buffered for retry"
    );
}

/// T6.3.i: drain the per-group pending-frame buffer and retry each
/// frame via `process_incoming` now that our epoch has advanced. A
/// frame that's still out of order (very rare; would require N+2
/// already in flight) gets re-buffered for the next commit. A frame
/// that's genuinely garbage gets dropped silently.
///
/// Sender_peer_pub is propagated so retried Application frames
/// surface under the right log line; for Commit retries it's just a
/// log field.
async fn drain_pending_room_frames(
    group_id: &[u8],
    sender_peer_pub: &[u8; 32],
    state: &Arc<DaemonState>,
) {
    let drained: Vec<Vec<u8>> = {
        let mut pending = state.pending_room_frames.lock().await;
        pending
            .get_mut(group_id)
            .map(|q| q.drain(..).collect())
            .unwrap_or_default()
    };
    if drained.is_empty() {
        return;
    }
    debug!(
        group_id_b32 = %encode_b32(group_id),
        count = drained.len(),
        "T6.3.i: retrying buffered room frames after commit merge"
    );
    // Use Box::pin to call the async function recursively without
    // overflowing the future's size — handle_room_app_frame may
    // itself buffer-and-retry, so the future-of-future-of-future
    // would be unbounded otherwise.
    for payload in drained {
        Box::pin(handle_room_app_frame(
            group_id,
            &payload,
            sender_peer_pub,
            state,
        ))
        .await;
    }
}

/// T6.3.g: push an incremental `HubOutbound::Subscribe` for a room's
/// current-epoch session token across every configured hub. Used
/// when an epoch advances mid-session (either we just produced a
/// commit in `handle_invite_to_room`, or we just merged one in
/// `refresh_room_roster_after_commit`). The subscribe is additive
/// at the hub layer, so the next hub-routed room message at the new
/// epoch lands in our connection.
///
/// Best-effort: a full hub-outbound queue or closed channel is
/// logged and skipped — the next hub-session reconnect will pick
/// up the new token via [`current_room_session_tokens`].
pub(crate) async fn announce_room_subscribe(group_id: &[u8], state: &DaemonState) {
    let Some(token) = ({
        let party = state.mls_party.lock().await;
        match party.load_group(group_id) {
            Ok(Some(g)) => g
                .export_routing_secret(&party)
                .ok()
                .map(|s| onyx_core::routing::session_token(&s, 0)),
            _ => None,
        }
    }) else {
        warn!(
            group_id_b32 = %encode_b32(group_id),
            "session-tokens: cannot derive token for incremental SUBSCRIBE; deferring to next reconnect"
        );
        return;
    };
    for (idx, hub_outbound) in state.hub_outbounds.iter().enumerate() {
        if let Err(e) = hub_outbound.try_send(hub_client::HubOutbound::Subscribe(vec![token])) {
            warn!(hub_idx = idx, error = %e, "session-tokens: incremental SUBSCRIBE push failed");
        }
    }
}

/// Derive the per-(room, current-epoch) session-token routing id
/// for every room this daemon participates in (T6.3.g). The same
/// derivation runs on every member at the same epoch, so the
/// inviter publishing to `session_token(secret, 0)` lands in the
/// same inbox each subscribing member fetches from. The hub sees
/// one inbox per (room, epoch) rather than one per room-member,
/// which is the unlinkability gain — passive hubs can no longer
/// fingerprint room membership by correlating intro-inbox fetches
/// across rooms.
///
/// Index `0` only; finer-grained intra-epoch rotation
/// (`session_token(secret, n>0)`) is reserved for a future slice.
/// Failures load_group/export_routing_secret on a single room are
/// logged and skipped — that room just won't have a session token
/// this connect cycle (recipient falls back to discovering the
/// message only after the daemon retries the hub session).
async fn current_room_session_tokens(
    state: &Arc<DaemonState>,
) -> Vec<onyx_core::routing::RoutingId> {
    let rows = {
        let vault = state.vault.lock().await;
        match vault.list_rooms(state.identity_id) {
            Ok(rows) => rows,
            Err(e) => {
                warn!(error = %e, "session-tokens: list_rooms failed; subscribing intro_inbox only");
                return Vec::new();
            }
        }
    };
    let mut tokens = Vec::with_capacity(rows.len());
    let party = state.mls_party.lock().await;
    for row in &rows {
        let Ok(Some(group)) = party.load_group(&row.group_id) else {
            warn!(
                group_id_b32 = %encode_b32(&row.group_id),
                "session-tokens: load_group failed; skipping"
            );
            continue;
        };
        let Ok(secret) = group.export_routing_secret(&party) else {
            warn!(
                group_id_b32 = %encode_b32(&row.group_id),
                "session-tokens: export_routing_secret failed; skipping"
            );
            continue;
        };
        tokens.push(onyx_core::routing::session_token(&secret, 0));
    }
    tokens
}

/// Post-commit roster refresh (T6.3.h). Called when
/// [`handle_room_app_frame`] processes an MLS commit on a room —
/// rebuilds `rooms.members_b32` from the post-merge group so
/// subsequent local `list_rooms` / `send_room` queries see the
/// new roster. Pure side-effect helper; failures warn but never
/// propagate.
async fn refresh_room_roster_after_commit(
    group_id: &[u8],
    sender_peer_pub: &[u8; 32],
    epoch: u64,
    state: &Arc<DaemonState>,
) {
    let new_members_b32 = {
        let party = state.mls_party.lock().await;
        match party.load_group(group_id) {
            Ok(Some(g)) => members_b32_from_group(&g),
            _ => String::new(),
        }
    };
    if !new_members_b32.is_empty() {
        let vault = state.vault.lock().await;
        if let Ok(rows) = vault.list_rooms(state.identity_id)
            && let Some(row) = rows.into_iter().find(|r| r.group_id == group_id)
            && let Err(e) = vault.save_room(
                state.identity_id,
                group_id,
                &row.name,
                &new_members_b32,
                row.created_at_ms,
            )
        {
            warn!(error = %e, "room frame: roster refresh failed");
        }
    }
    info!(
        group_id_b32 = %encode_b32(group_id),
        from_peer_short = %short_id_of_peer_pub(sender_peer_pub),
        mls_epoch = epoch,
        "room: commit merged; group epoch advanced"
    );
    // T6.3.g: the per-epoch session token just changed. Push an
    // incremental SUBSCRIBE so the next hub-routed room message at
    // the new epoch lands in our connection without a reconnect.
    announce_room_subscribe(group_id, state).await;
}

/// 8-char base32 prefix of a peer's X25519 pubkey — matches what the
/// conversation registry uses as `short_id`. Helper kept tiny on
/// purpose so the room-frame log line above doesn't pull in the
/// whole registry just for a debug field.
fn short_id_of_peer_pub(peer_pub: &[u8; 32]) -> String {
    encode_b32(peer_pub).chars().take(8).collect()
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
        if !seen.check_and_record(&target, &body) {
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
            // T-1: pin/verify the sender's identity key first.
            pin_check_peer(state, &sender_fingerprint, &sender_x25519).await;
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
            room_name,
            member_kems,
        } => {
            process_hub_mls_welcome(
                welcome.as_ref(),
                first_message,
                room_name,
                member_kems,
                sender_x25519,
                &sender_pub_b32,
                sender_fingerprint,
                state,
            )
            .await;
        }
        onyx_core::routing::BootstrapPayload::MlsApp {
            group_id,
            ciphertext,
        } => {
            process_hub_mls_app(
                group_id.as_ref(),
                ciphertext.as_ref(),
                &sender_x25519,
                &sender_fingerprint,
                state,
            )
            .await;
        }
    }
}

/// Handle a T6.3.e `BootstrapPayload::MlsApp` hub-delivery. Extracted
/// so `handle_hub_delivery`'s match block stays under the clippy
/// `too_many_lines` budget. Both sides must already share the MLS
/// group; if we don't know it, drop silently at debug level — could
/// be a hostile sender probing whether we're in a given room, or the
/// recipient hasn't joined yet. Either way, the sender learns
/// nothing.
async fn process_hub_mls_app(
    group_id: &[u8],
    ciphertext: &[u8],
    sender_x25519: &[u8; 32],
    sender_fingerprint: &str,
    state: &Arc<DaemonState>,
) {
    handle_room_app_frame(group_id, ciphertext, sender_x25519, state).await;
    info!(
        from_fingerprint = %sender_fingerprint,
        group_id_b32 = %encode_b32(group_id),
        ciphertext_bytes = ciphertext.len(),
        "hub: mlsapp/v1 room frame processed"
    );
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
        // M-1: production vaults use the full 256 MiB DEFAULT KDF
        // cost, not the 64 MiB FLOOR (the FLOOR is the minimum the
        // daemon will *accept* on open, intended for already-created
        // low-memory-device vaults — not the bar for fresh ones). The
        // params are persisted per-vault in `vault_meta`, so existing
        // FLOOR vaults keep unlocking with their stored cost; only
        // newly-created vaults get the stronger offline-crack cost.
        Vault::create(path, passphrase, &Argon2Params::DEFAULT)
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

/// Receive-side processing of an `mls/v1` `BootstrapPayload::MlsWelcome`.
/// Extracted from [`handle_hub_delivery`] so its match block stays
/// under the clippy `too_many_lines` budget. Joins the MLS group,
/// snapshots state, then dispatches to either room-row persistence
/// (when `room_name = Some`) or the existing DM register-hub-only
/// path (when `room_name = None`).
#[allow(clippy::too_many_arguments)]
async fn process_hub_mls_welcome(
    welcome_bytes: &[u8],
    first_message: Option<String>,
    room_name: Option<String>,
    member_kems: Vec<onyx_core::routing::RoomMemberKem>,
    sender_x25519: [u8; 32],
    sender_pub_b32: &str,
    sender_fingerprint: String,
    state: &Arc<DaemonState>,
) {
    // Silent failure on join (debug-level only): a hostile hub or
    // attacker could send junk Welcome bytes; we don't want to spam
    // operator logs.
    let join_result = {
        let party = state.mls_party.lock().await;
        party.join_from_welcome(welcome_bytes)
    };
    let Ok(group) = join_result else {
        debug!(
            welcome_bytes = welcome_bytes.len(),
            "hub: mls/v1 Welcome did not join into a group; dropping"
        );
        return;
    };

    // MEDIUM (audit): inviter authorization. The sealed-sender
    // envelope is authenticated to `sender_fingerprint` (HIGH-2 binds
    // it to us as recipient and the inner Ed25519 signature proves the
    // sender). Require that this authenticated sender is ACTUALLY a
    // member of the group it just added us to. Without this, anyone
    // who learns our intro inbox + KEM key could seal us a Welcome to
    // a group we have no relationship with (unsolicited group-add);
    // we'd persist state + emit per-epoch tokens for it. Cross-
    // checking the signer against the freshly-joined roster closes
    // that: a Welcome whose signer isn't in the group is dropped
    // before any state is persisted.
    let signer_in_roster = group.member_signing_keys().iter().any(|pk_bytes| {
        <[u8; 32]>::try_from(pk_bytes.as_slice()).is_ok_and(|arr| {
            onyx_core::crypto::Fingerprint::from_bytes(arr).to_string() == sender_fingerprint
        })
    });
    if !signer_in_roster {
        warn!(
            sender_fp = %sender_fingerprint,
            "hub: mls/v1 Welcome signer is not a member of the group it invited us to; \
             dropping (possible unsolicited group-add)"
        );
        // Drop the just-joined group state so it doesn't linger in the
        // MLS provider's in-memory store (it was never persisted).
        let party = state.mls_party.lock().await;
        let _ = party.forget_group(&group.group_id_bytes());
        return;
    }

    // T-1: pin/verify the (now-authenticated) inviter's identity key.
    // Placed here — after the signer-in-roster check, before the
    // room-vs-DM branch — so it fires for BOTH room invites and 2-party
    // DM bootstraps (the per-branch registration paths diverge below).
    pin_check_peer(state, &sender_fingerprint, &sender_x25519).await;

    // Persist the post-join MLS state so the group survives a daemon
    // restart.
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

    // T6.3.c: if the Welcome carried a `room_name`, this is a multi-
    // party room invite rather than a 2-party DM bootstrap.
    if let Some(name) = room_name.clone() {
        // T6.3.h: persist every (fingerprint, kem_pub) pair the
        // inviter bundled so this new joiner can hub-fallback to
        // any current member (not just the inviter). Save BEFORE
        // process_room_welcome so even if a member-row save fails
        // partway through, the room row's own save still happens.
        if !member_kems.is_empty() {
            let group_id_bytes = group.group_id_bytes();
            let vault = state.vault.lock().await;
            for entry in &member_kems {
                if let Err(e) = vault.save_room_member_kem(
                    state.identity_id,
                    &group_id_bytes,
                    &entry.fingerprint,
                    entry.kem_pub.as_ref(),
                ) {
                    warn!(
                        error = %e,
                        member = %entry.fingerprint,
                        "hub: mls/v1 Welcome: save_room_member_kem failed"
                    );
                }
            }
            info!(
                count = member_kems.len(),
                "hub: mls/v1 Welcome carried roster KEMs; persisted"
            );
        }
        process_room_welcome(&group, &name, &sender_fingerprint, state).await;
        // T6.3.g: subscribe to the new room's session-token inbox so
        // we receive subsequent hub-routed room messages without
        // waiting for the next hub reconnect.
        announce_room_subscribe(&group.group_id_bytes(), state).await;
        return;
    }

    // Register the peer as hub-only. Future direct-dial lifts them
    // to a live Direct conversation via the existing resume path.
    let mut reg = state.conversations.lock().await;
    let handle = reg.register_hub_only(sender_x25519, sender_pub_b32, sender_fingerprint);
    let group_id_b32 = encode_b32(&group.group_id_bytes());
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

/// Persist a freshly-joined room on the recipient side (T6.3.c).
/// Extracted from [`handle_hub_delivery`] so its room-arm stays
/// short. Logs success at info, failures at warn.
async fn process_room_welcome(
    group: &onyx_core::mls::MlsGroupState,
    name: &str,
    sender_fingerprint: &str,
    state: &Arc<DaemonState>,
) {
    let members_b32 = members_b32_from_group(group);
    let group_id_bytes = group.group_id_bytes();
    let now_ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()),
    )
    .unwrap_or(0);
    let vault = state.vault.lock().await;
    match vault.save_room(
        state.identity_id,
        &group_id_bytes,
        name,
        &members_b32,
        now_ms,
    ) {
        Ok(()) => {
            info!(
                room_name = %name,
                group_id_b32 = %encode_b32(&group_id_bytes),
                mls_epoch = group.epoch(),
                from_fingerprint = %sender_fingerprint,
                "hub: mls/v1 Welcome processed, joined room"
            );
        }
        Err(e) => {
            warn!(error = %e, "hub: mls/v1 room save failed");
        }
    }
}

/// Derive the comma-separated fingerprint list cached in
/// `rooms.members_b32` from a joined MLS group (T6.3.c). One entry
/// per current member (leaf-index order from MLS), formatted via
/// `Fingerprint::to_string` — the same form printed by `onyx
/// identity` and accepted everywhere else in the wire/UI surface.
/// Members whose embedded signing key is not a valid Ed25519 point
/// are skipped silently (defensive: should never happen for groups
/// we've actually joined, since openmls would have rejected the
/// Welcome).
pub(crate) fn members_b32_from_group(group: &onyx_core::mls::MlsGroupState) -> String {
    let mut out = Vec::new();
    for raw in group.member_signing_keys() {
        let Ok(arr) = <[u8; 32]>::try_from(raw.as_slice()) else {
            continue;
        };
        if let Ok(vk) = onyx_core::crypto::VerifyingKey::from_bytes(arr) {
            out.push(vk.fingerprint().to_string());
        }
    }
    out.join(",")
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

#[cfg(test)]
mod cover_traffic_tests {
    use super::*;

    /// T-cover.2: every sampled interval is bounded by the
    /// documented clamp [1s, 10×mean]. Important: a buggy sampler
    /// returning Duration::ZERO would saturate the Tor circuit;
    /// returning enormous Durations would create gaps that
    /// themselves signal something. Pin both clamps over a large
    /// sample.
    #[test]
    fn next_exponential_interval_is_clamped() {
        let mean_secs: u64 = 5;
        let lo = std::time::Duration::from_secs(1);
        let hi = std::time::Duration::from_secs(mean_secs * 10);
        for _ in 0..10_000 {
            let dt = next_exponential_interval(mean_secs);
            assert!(dt >= lo, "interval {dt:?} below lower clamp {lo:?}");
            assert!(dt <= hi, "interval {dt:?} above upper clamp {hi:?}");
        }
    }

    /// Statistical sanity: across many samples the average should
    /// be in the right ballpark relative to the mean. Because of
    /// the [1s, 10×mean] clamp, the true mean is slightly lower
    /// than `mean_secs` (the long tail is cut off) and slightly
    /// higher than `mean_secs - 1` (the bottom is cut off). A
    /// generous ±50% band around `mean_secs` catches a bug where
    /// the sampler is constant or wildly skewed without flaking on
    /// CSPRNG randomness.
    const COVER_SAMPLES_FOR_AVG: u32 = 10_000;

    #[test]
    fn next_exponential_interval_average_is_reasonable() {
        let mean_secs: u64 = 10;
        let mut sum_ms: u128 = 0;
        for _ in 0..COVER_SAMPLES_FOR_AVG {
            sum_ms += next_exponential_interval(mean_secs).as_millis();
        }
        let avg_ms = sum_ms / u128::from(COVER_SAMPLES_FOR_AVG);
        let target_ms = u128::from(mean_secs) * 1000;
        assert!(
            avg_ms >= target_ms / 2 && avg_ms <= target_ms * 3 / 2,
            "avg {avg_ms}ms should be within ±50% of target {target_ms}ms"
        );
    }

    // --- T-cover.const: constant-rate pacer -----------------------

    /// Helper: a small Deliver action tagged by the first target byte
    /// so tests can assert ordering/identity without caring about the
    /// body. (`HubOutbound` isn't `PartialEq` — the `FetchKp` variant
    /// carries a oneshot — so tests match on `target[0]` instead.)
    fn deliver_tagged(tag: u8) -> hub_client::HubOutbound {
        hub_client::HubOutbound::Deliver {
            target: [tag; 16],
            body: vec![tag],
        }
    }

    /// The security-relevant invariant: every slot emits exactly one
    /// frame, real frames are forwarded first **in FIFO order**, and
    /// once the real queue drains the pacer keeps emitting `Pad` —
    /// i.e. the wire cadence is identical whether or not real traffic
    /// is flowing. Timing-independent by construction: we enqueue the
    /// reals *before* spawning the pacer, then read the first four
    /// emitted frames and assert the sequence `[real, real, pad, pad]`.
    #[tokio::test]
    async fn constant_rate_pacer_forwards_reals_in_order_then_pads() {
        let (api_tx, api_rx) = mpsc::channel(16);
        let (sess_tx, mut sess_rx) = mpsc::channel(16);
        // Enqueue two real frames before the pacer starts so the first
        // two slots are guaranteed to find them (no scheduler race).
        api_tx.send(deliver_tagged(7)).await.unwrap();
        api_tx.send(deliver_tagged(8)).await.unwrap();
        tokio::spawn(run_constant_rate_pacer(
            api_rx,
            sess_tx,
            std::time::Duration::from_millis(10),
        ));

        let mut got = Vec::new();
        for _ in 0..4 {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(2), sess_rx.recv())
                .await
                .expect("pacer should emit within the timeout")
                .expect("pacer channel should stay open");
            got.push(frame);
        }

        match &got[0] {
            hub_client::HubOutbound::Deliver { target, .. } => assert_eq!(target[0], 7),
            other => panic!("slot 0 should be the first real frame, got {other:?}"),
        }
        match &got[1] {
            hub_client::HubOutbound::Deliver { target, .. } => assert_eq!(target[0], 8),
            other => panic!("slot 1 should be the second real frame, got {other:?}"),
        }
        assert!(
            matches!(got[2], hub_client::HubOutbound::Pad),
            "slot 2 should be a Pad once the real queue drained, got {:?}",
            got[2]
        );
        assert!(
            matches!(got[3], hub_client::HubOutbound::Pad),
            "slot 3 should keep emitting Pad while idle, got {:?}",
            got[3]
        );
    }

    /// An idle pacer (no real traffic ever) still emits a steady
    /// stream of `Pad` — this is the whole point of "high mode": an
    /// idle circuit looks identical to an active one on the wire.
    #[tokio::test]
    async fn constant_rate_pacer_emits_pads_while_fully_idle() {
        let (_api_tx, api_rx) = mpsc::channel(16);
        let (sess_tx, mut sess_rx) = mpsc::channel(16);
        tokio::spawn(run_constant_rate_pacer(
            api_rx,
            sess_tx,
            std::time::Duration::from_millis(10),
        ));
        for _ in 0..3 {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(2), sess_rx.recv())
                .await
                .expect("idle pacer should still emit within the timeout")
                .expect("pacer channel should stay open");
            assert!(
                matches!(frame, hub_client::HubOutbound::Pad),
                "idle slot must be a Pad, got {frame:?}"
            );
        }
    }

    /// The pacer terminates cleanly when the session side goes away
    /// (the hub session's Receiver dropped on shutdown). Without this
    /// the task would leak on every reconnect-free shutdown.
    #[tokio::test]
    async fn constant_rate_pacer_exits_when_session_closed() {
        let (_api_tx, api_rx) = mpsc::channel(16);
        let (sess_tx, sess_rx) = mpsc::channel::<hub_client::HubOutbound>(16);
        let handle = tokio::spawn(run_constant_rate_pacer(
            api_rx,
            sess_tx,
            std::time::Duration::from_millis(10),
        ));
        // Drop the consumer; the next slot's send fails → pacer returns.
        drop(sess_rx);
        tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("pacer should exit promptly after the session closes")
            .expect("pacer task should not panic");
    }
}
