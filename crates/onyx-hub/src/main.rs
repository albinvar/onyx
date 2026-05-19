//! `onyx-hub` — optional relay server.
//!
//! Holds an authenticated v3 hidden service and maintains in-memory
//! routing-id subscriptions + offline queues. Clients open one
//! authenticated Noise XK session per connection and exchange two
//! frame types only:
//!
//!   * [`onyx_core::wire::FRAME_SUBSCRIBE`] — tell the hub which
//!     routing IDs we want live deliveries for. Payload = N × 16 bytes.
//!   * [`onyx_core::wire::FRAME_DELIVER`] — ask the hub to deliver an
//!     opaque payload to a routing ID. Payload = 16-byte target ‖ body.
//!
//! The hub sees no plaintext: every frame on the wire is already
//! encrypted under the recipient's MLS group. The hub only learns
//! routing IDs (BLAKE2b-128(signing_pk ‖ "onyx/v1/inbox") per DESIGN
//! §5.5) and connection liveness.
//!
//! ## v0 scope (this binary)
//!
//!   * Single-instance, in-memory state (no SQLite persistence yet).
//!   * Open-registration: anyone who knows the hub's static key can
//!     connect. Invite-only auth comes later.
//!   * No rate-limiting / quota.
//!   * No metrics endpoint.
//!
//! All of those are tracked in CHANGELOG.md as carry-forward items.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use futures::StreamExt;
use onyx_core::crypto::Argon2Params;
use onyx_core::identity::Identity;
use onyx_core::storage::Vault;
use onyx_core::tor::TorRuntime;
use tokio::sync::Mutex;
use tracing::{Instrument, error, info, info_span, warn};

use onyx_core::crypto::{IdentityPublic, IdentitySecret};

use crate::handler::hub_handle_connection;
use crate::state::{GossipMode, HubState, PeerHubConfig};

mod handler;
mod peer_link;
mod rate_limit;
mod state;
mod store;

const DEFAULT_IDENTITY_NICKNAME: &str = "hub";
const HS_NICKNAME: &str = "onyx-hub";

/// Virtual port on the hidden service.
const HUB_HS_PORT: u16 = 1;

#[derive(Parser, Debug)]
#[command(
    name = "onyx-hub",
    version,
    about = "Onyx hub — encrypted store-and-forward relay"
)]
struct Args {
    /// Path to the encrypted vault file holding the hub's long-term
    /// X25519 identity key.
    #[arg(long, env = "ONYX_HUB_VAULT", default_value = "./onyx-hub.db")]
    vault: PathBuf,

    /// Vault passphrase. Pass via environment variable rather than
    /// command line so it does not show up in `ps`.
    #[arg(long, env = "ONYX_HUB_PASSPHRASE", hide_env_values = true)]
    passphrase: String,

    /// Skip the Tor bootstrap. The hub will idle until Ctrl-C — only
    /// useful for smoke-testing vault open without network setup.
    #[arg(long)]
    no_tor: bool,

    /// Override Arti's state directory. Required when running more
    /// than one Tor-backed process on the same machine; each needs
    /// its own directory to avoid fighting the state-file lock.
    #[arg(long, env = "ONYX_HUB_TOR_STATE_DIR")]
    tor_state_dir: Option<PathBuf>,

    /// Path to the SQLite database that durably stores queued
    /// envelopes + published KeyPackages (T8.0). Defaults to
    /// `./onyx-hub-state.db` next to the vault file. Pass
    /// `--state-db ""` (empty string) to opt out and run the hub
    /// ephemeral — restart loses every queue + KP, same posture as
    /// pre-T8.0.
    #[arg(long, env = "ONYX_HUB_STATE_DB", default_value = "./onyx-hub-state.db")]
    state_db: String,

    /// Maximum age (in days) for queued envelopes (T8.0.gc).
    /// Periodic GC drops queue rows older than this threshold so
    /// the hub's `queue_entry` table doesn't grow without bound
    /// when a recipient never returns to drain their inbox. KPs
    /// are NOT pruned (they're designed to be republished per
    /// reconnect; silent pruning would break first-contact for a
    /// peer that hasn't reconnected in a while).
    ///
    /// Set to 0 to disable GC entirely (keeps every queued
    /// envelope forever — only do this if you have unbounded
    /// disk or are running ephemeral via `--state-db ""`).
    #[arg(long, env = "ONYX_HUB_MAX_QUEUE_AGE_DAYS", default_value_t = 30)]
    max_queue_age_days: u32,

    /// Per-connection rate limit for DELIVER + KP_PUBLISH frames
    /// (T8.x-ratelimit). Each connection gets a token bucket capped
    /// at this many frames; sustained refill rate is the same value
    /// per minute. A normal client never approaches this limit
    /// (typical chat = single-digit frames/min); the cap exists to
    /// prevent a single hostile or misbehaving client from
    /// monopolising the hub's CPU/disk by spamming DELIVERs or
    /// KP_PUBLISHes (the latter triggers MLS validation work per
    /// frame).
    ///
    /// SUBSCRIBE frames are NOT limited (cheap). Set to 0 to
    /// disable the limiter entirely (NOT recommended for any
    /// production hub).
    #[arg(long, env = "ONYX_HUB_MAX_FRAMES_PER_MINUTE", default_value_t = 600)]
    max_frames_per_minute: u32,

    /// Repeatable: each `--peer-hub onion:port,b32pubkey` adds one
    /// peer hub this hub will gossip KPs to (T8.3.b.2+). Each peer
    /// gets its own outbound Noise XK session; on success, every
    /// validated client `FRAME_KP_PUBLISH` is fanned out to peer
    /// hubs as `FRAME_GOSSIP_PUBLISH` (TTL=3, our hub's hash as
    /// `seen_by`).
    ///
    /// The peer hub's pubkey doubles as a role allowlist entry:
    /// inbound Noise XK sessions whose authenticated peer_static_key
    /// matches one of these are treated as peer hubs, NOT clients
    /// (T8.3.b.4 — currently the inbound side is not yet wired, so
    /// peer-hub gossip we receive will be dropped as "unknown
    /// frame type" until that slice lands).
    ///
    /// Empty default → no federation, byte-identical pre-T8.3
    /// behaviour. Per-hub operator-opt-in.
    #[arg(long = "peer-hub", action = clap::ArgAction::Append)]
    peer_hubs: Vec<String>,

    /// Queue-gossip policy when federation is enabled (T8.3.c).
    /// `lazy` (default) only forwards envelopes that we couldn't
    /// deliver to a local subscriber — bandwidth-efficient for
    /// star topologies. `eager` always forwards, giving stronger
    /// eventual consistency across the mesh at ~3× bandwidth.
    /// The recipient daemon's replay guard dedups any duplicates
    /// at zero added complexity. FEDERATION.md §3.2 has the full
    /// tradeoff.
    ///
    /// Ignored when no `--peer-hub` is configured.
    #[arg(long, value_parser = ["lazy", "eager"], default_value = "lazy")]
    gossip_mode: String,

    /// **TEST-ONLY** local-TCP listen mode. When set, the hub binds
    /// a plain TCP listener at `addr` instead of standing up a
    /// hidden service. Mirrors the daemon's `--listen-tcp`. No Tor,
    /// no anonymity — strictly for the end-to-end smoke harness
    /// (`crates/onyx-daemon/tests/rooms_smoke.rs`) and local dev.
    /// Loudly warned at startup so an operator can't accidentally
    /// run the hub in this mode publicly.
    ///
    /// Conflicts with `--peer-hub` (federation requires Tor).
    /// Conflicts with `--no-tor` (which already bypasses bind).
    #[arg(long, env = "ONYX_HUB_LISTEN_TCP",
          conflicts_with_all = ["no_tor", "peer_hubs"])]
    listen_tcp: Option<String>,
}

// Linear startup: tracing → vault → identity → Tor → HS → state →
// accept-loop. Splitting per-section helpers would only relocate
// the same body into call sites without making startup easier to
// follow.
#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let mut vault = open_or_create_vault(&args.vault, args.passphrase.as_bytes())
        .context("opening hub vault")?;
    let (_identity_id, identity) =
        ensure_default_identity(&mut vault).context("ensuring hub identity")?;

    let fingerprint = identity.fingerprint();
    let identity_pub_b32 = encode_b32(&identity.identity_key().public().to_bytes());
    info!(
        fingerprint = %fingerprint,
        hub_pub_b32 = %identity_pub_b32,
        "hub vault unlocked, identity loaded — clients dial with --hub-onion + --hub-pubkey"
    );

    drop(args.passphrase);
    // v0 hub keeps no per-connection persisted state; release the
    // vault file as soon as we have the identity.
    drop(vault);

    if args.no_tor {
        warn!("--no-tor set: skipping Tor; hub will idle until Ctrl-C");
        wait_for_ctrl_c().await;
        return Ok(());
    }

    // TEST-ONLY: --listen-tcp bypasses Tor entirely and accepts
    // plain TCP. Used by the smoke harness in
    // `crates/onyx-daemon/tests/rooms_smoke.rs`. Loudly warned.
    if let Some(addr) = args.listen_tcp.as_deref() {
        return run_listen_tcp_mode(
            addr,
            identity,
            args.state_db.clone(),
            args.max_queue_age_days,
            args.max_frames_per_minute,
        )
        .await;
    }

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
    // Arc-wrap so peer-link tasks can share the runtime (T8.3.b.2+).
    let tor = Arc::new(tor);
    info!("Tor bootstrap complete");

    let mut hs = tor
        .publish_hidden_service(HS_NICKNAME)
        .map_err(|e| anyhow::anyhow!("hidden service publish failed: {e}"))?;

    if let Some(addr) = hs.onion_address() {
        info!(
            onion = %addr,
            port = HUB_HS_PORT,
            "hub hidden service published — share onion + hub_pub_b32 with clients"
        );
    } else {
        warn!("hub HS has no address yet — Arti will produce one shortly");
    }

    let mut accept = hs
        .take_accept_streams()
        .context("HS accept-stream already taken")?;

    // T8.0: open the SQLite-backed store unless the operator
    // explicitly opted out via `--state-db ""`. The HubState warms
    // its in-memory caches from the store on construct so the hot
    // path stays in-memory.
    let state = if args.state_db.is_empty() {
        warn!(
            "--state-db is empty: running ephemeral. Queued envelopes \
             and published KPs will NOT survive a hub restart."
        );
        HubState::new()
    } else {
        let db_path = std::path::PathBuf::from(&args.state_db);
        if let Some(parent) = db_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "creating hub state-db parent directory {}",
                    parent.display()
                )
            })?;
        }
        info!(state_db = %db_path.display(), "opening hub durable state-db");
        let store = crate::store::Store::open(&db_path).context("opening hub state-db")?;
        HubState::with_store(store).context("warming HubState from store")?
    };
    // T8.x-ratelimit: install the per-connection rate limiter.
    // Operator can opt out with `--max-frames-per-minute 0` (loudly
    // discouraged for production hubs).
    let mut state = if args.max_frames_per_minute == 0 {
        warn!(
            "--max-frames-per-minute 0: rate limiting is DISABLED. \
             Any single connection can spam DELIVER / KP_PUBLISH \
             frames as fast as the wire allows."
        );
        state
    } else {
        info!(
            max_frames_per_minute = args.max_frames_per_minute,
            "per-connection rate limit installed (DELIVER + KP_PUBLISH; SUBSCRIBE unlimited)"
        );
        state.with_rate_limit(args.max_frames_per_minute)
    };

    // T8.3.b.2: parse --peer-hub flags, spawn one outbound Noise XK
    // task per peer, install the resulting mpsc senders + our own
    // hub-pubkey hash into HubState so client KP_PUBLISH receives
    // can fan out via state.fan_out_kp_to_peers(...).
    let mut peer_outbound_txs: std::collections::HashMap<
        [u8; 32],
        tokio::sync::mpsc::Sender<onyx_core::wire::InnerFrame>,
    > = std::collections::HashMap::new();
    if !args.peer_hubs.is_empty() {
        let our_hub_pubkey_bytes = identity.identity_key().public().to_bytes();
        let self_hub_hash = HubState::hub_pubkey_to_hash(&our_hub_pubkey_bytes);
        state.set_self_hub_hash(self_hub_hash);

        // IdentitySecret doesn't impl Clone — round-trip via bytes
        // once and Arc-wrap so peer-link tasks share without
        // duplicating the secret material.
        let our_sk_bytes: [u8; 32] = *identity.identity_key().to_bytes();
        let our_sk = Arc::new(IdentitySecret::from_bytes(our_sk_bytes));
        let tor_arc = tor.clone();

        for (idx, raw) in args.peer_hubs.iter().enumerate() {
            let (onion, pubkey) = raw.split_once(',').ok_or_else(|| {
                anyhow::anyhow!(
                    "--peer-hub value must be `onion:port,b32pubkey` (missing comma): {raw}"
                )
            })?;
            if onion.is_empty() || pubkey.is_empty() {
                anyhow::bail!("--peer-hub value has empty field: {raw}");
            }
            let cfg = PeerHubConfig {
                onion: onion.to_string(),
                pubkey: pubkey.to_string(),
            };
            let (host, port) =
                parse_host_port(&cfg.onion, HUB_HS_PORT).context("--peer-hub onion")?;
            let pubkey_bytes = decode_b32_32(&cfg.pubkey).context("--peer-hub pubkey")?;
            let peer_pubkey = IdentityPublic::from_bytes(pubkey_bytes);

            let (tx, rx) = tokio::sync::mpsc::channel::<onyx_core::wire::InnerFrame>(
                crate::peer_link::PEER_OUTBOUND_CAPACITY,
            );
            peer_outbound_txs.insert(pubkey_bytes, tx);
            let tor_for_task = tor_arc.clone();
            let our_sk_for_task = our_sk.clone();
            let span = info_span!("peer-hub", idx, host = %host, port);
            tokio::spawn(
                async move {
                    if let Err(e) = crate::peer_link::run_peer_session(
                        tor_for_task,
                        host,
                        port,
                        peer_pubkey,
                        our_sk_for_task,
                        rx,
                    )
                    .await
                    {
                        warn!(error = %e, "peer-hub session task exited with error");
                    }
                }
                .instrument(span),
            );
        }
        state.set_peer_outbounds(peer_outbound_txs);
        let mode = match args.gossip_mode.as_str() {
            "eager" => GossipMode::Eager,
            _ => GossipMode::Lazy,
        };
        state.set_gossip_mode(mode);
        info!(
            peer_count = args.peer_hubs.len(),
            ?mode,
            "T8.3 federation enabled; KPs gossiped on client publish; envelopes gossiped per --gossip-mode"
        );
    }

    let state = Arc::new(Mutex::new(state));

    // T8.0.gc: spawn the periodic queue-GC task. Runs hourly,
    // deletes queue rows older than --max-queue-age-days. Disabled
    // via `--max-queue-age-days 0`.
    if args.max_queue_age_days > 0 {
        let gc_state = state.clone();
        let age_days = args.max_queue_age_days;
        info!(
            max_queue_age_days = age_days,
            "spawning periodic queue-GC task (hourly tick)"
        );
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            // First tick fires immediately; skip it so we don't GC at
            // startup before the warm-from-disk even completes.
            interval.tick().await;
            loop {
                interval.tick().await;
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .and_then(|d| i64::try_from(d.as_millis()).ok())
                    .unwrap_or(0);
                let cutoff = now_ms - i64::from(age_days) * 24 * 60 * 60 * 1000;
                let result = {
                    let s = gc_state.lock().await;
                    s.gc_queue_entries_older_than(cutoff)
                };
                match result {
                    Ok(0) => {} // nothing to GC; stay quiet
                    Ok(n) => info!(deleted = n, "hub queue GC: dropped stale rows"),
                    Err(e) => warn!(error = %e, "hub queue GC failed; will retry next tick"),
                }
            }
        });
    } else {
        warn!(
            "--max-queue-age-days 0: queue GC is DISABLED. Queued envelopes \
             will accumulate forever for routing-ids whose owner never returns."
        );
    }

    let hub_secret = Arc::new(IdentityHandle::new(identity));

    info!("onyx-hub running. Ctrl-C to stop.");

    let accept_loop = async {
        while let Some(stream) = accept.next().await {
            let state = state.clone();
            let hub_secret = hub_secret.clone();
            let span = info_span!("hub-inbound");
            tokio::spawn(
                async move {
                    if let Err(e) =
                        hub_handle_connection(stream, hub_secret.identity_key(), state).await
                    {
                        warn!(error = %e, "hub connection handler failed");
                    }
                }
                .instrument(span),
            );
        }
        info!("hub accept stream ended");
    };

    tokio::select! {
        () = accept_loop => {},
        () = wait_for_ctrl_c() => info!("hub shutting down on Ctrl-C"),
    }

    drop(hs);
    drop(tor);
    Ok(())
}

/// **TEST-ONLY** run-mode: bind a plain TCP listener instead of
/// publishing a hidden service. Used by the smoke harness in
/// `crates/onyx-daemon/tests/rooms_smoke.rs` to exercise the whole
/// hub + daemon stack on localhost without paying Tor bootstrap.
///
/// Sets up the same `HubState` (durable store + rate limit) as the
/// Tor path, just plumbed onto a `TcpListener::accept` loop. No
/// federation (`--peer-hub` is forbidden in this mode by clap's
/// `conflicts_with_all`).
async fn run_listen_tcp_mode(
    addr: &str,
    identity: Identity,
    state_db: String,
    max_queue_age_days: u32,
    max_frames_per_minute: u32,
) -> anyhow::Result<()> {
    warn!(
        addr = %addr,
        "HUB LISTEN-TCP MODE — NO TOR, NO ANONYMITY. Test/dev only. \
         Anyone who can reach this address can speak Noise to this hub."
    );

    // Mirror the Tor path's HubState construction: durable store
    // (unless --state-db ""), per-connection rate limit.
    let state = if state_db.is_empty() {
        warn!("--state-db is empty: running ephemeral.");
        HubState::new()
    } else {
        let db_path = std::path::PathBuf::from(&state_db);
        if let Some(parent) = db_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "creating hub state-db parent directory {}",
                    parent.display()
                )
            })?;
        }
        let store = crate::store::Store::open(&db_path).context("opening hub state-db")?;
        HubState::with_store(store).context("warming HubState from store")?
    };
    let state = if max_frames_per_minute == 0 {
        state
    } else {
        state.with_rate_limit(max_frames_per_minute)
    };
    let state = Arc::new(Mutex::new(state));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding hub TCP listener at {addr}"))?;
    let local_addr = listener.local_addr().context("local_addr")?;
    info!(
        local_addr = %local_addr,
        hub_pub_b32 = %encode_b32(&identity.identity_key().public().to_bytes()),
        "hub TCP listener bound; share `--hub-tcp <addr>,<pubkey>` with daemons"
    );

    // Periodic queue GC (mirrors the Tor path).
    if max_queue_age_days > 0 {
        let gc_state = state.clone();
        let age_days = max_queue_age_days;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            interval.tick().await;
            loop {
                interval.tick().await;
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .and_then(|d| i64::try_from(d.as_millis()).ok())
                    .unwrap_or(0);
                let cutoff = now_ms - i64::from(age_days) * 24 * 60 * 60 * 1000;
                let result = {
                    let s = gc_state.lock().await;
                    s.gc_queue_entries_older_than(cutoff)
                };
                if let Ok(n) = result
                    && n > 0
                {
                    info!(deleted = n, "hub queue GC: dropped stale rows");
                }
            }
        });
    }

    let hub_secret = Arc::new(IdentityHandle::new(identity));
    let accept_loop = async {
        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, "hub TCP accept failed; continuing");
                    continue;
                }
            };
            let state = state.clone();
            let hub_secret = hub_secret.clone();
            let span = info_span!("hub-inbound-tcp", peer = %peer_addr);
            tokio::spawn(
                async move {
                    if let Err(e) =
                        hub_handle_connection(stream, hub_secret.identity_key(), state).await
                    {
                        warn!(error = %e, "hub TCP connection handler failed");
                    }
                }
                .instrument(span),
            );
        }
    };
    tokio::select! {
        () = accept_loop => {},
        () = wait_for_ctrl_c() => info!("hub shutting down on Ctrl-C"),
    }
    Ok(())
}

/// Wrapper to keep the hub's [`Identity`] (and therefore its
/// `IdentitySecret`) alive across spawn boundaries. [`Identity`]
/// itself isn't `Clone` by design (duplicating long-term secrets
/// should be deliberate), so we share it behind an `Arc`.
struct IdentityHandle {
    identity: Identity,
}

impl IdentityHandle {
    fn new(identity: Identity) -> Self {
        Self { identity }
    }
    fn identity_key(&self) -> &onyx_core::crypto::IdentitySecret {
        self.identity.identity_key()
    }
}

// ── Vault helpers (mirror onyxd's; v0 keeps them duplicated rather
//    than promoting to a shared crate just yet) ───────────────────────────

fn open_or_create_vault(path: &std::path::Path, passphrase: &[u8]) -> anyhow::Result<Vault> {
    if path.exists() {
        info!(path = %path.display(), "opening existing hub vault");
        Vault::open(path, passphrase)
            .map_err(|e| anyhow::anyhow!("vault open failed (wrong passphrase?): {e}"))
    } else {
        info!(path = %path.display(), "creating new hub vault");
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
    info!("no identity found; generating fresh \"{DEFAULT_IDENTITY_NICKNAME}\" hub identity");
    let (id, identity) = vault
        .create_identity(DEFAULT_IDENTITY_NICKNAME)
        .map_err(|e| anyhow::anyhow!("create identity: {e}"))?;
    Ok((id, identity))
}

fn encode_b32(bytes: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, bytes)
}

/// Parse `host:port` (or `host`, using `default_port`). Mirrors
/// `onyx_daemon::hub_client::parse_host_port` — we don't want to
/// depend on the daemon crate from the hub binary, so the helper
/// is re-implemented here.
fn parse_host_port(s: &str, default_port: u16) -> anyhow::Result<(String, u16)> {
    match s.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().with_context(|| format!("bad port in {s:?}"))?;
            Ok((h.to_string(), port))
        }
        None => Ok((s.to_string(), default_port)),
    }
}

/// Decode an RFC4648-lower base32 string of expected-32-byte
/// content into `[u8; 32]`. Used by `--peer-hub` parsing.
fn decode_b32_32(s: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = base32::decode(base32::Alphabet::Rfc4648Lower { padding: false }, s)
        .ok_or_else(|| anyhow::anyhow!("not valid base32"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("base32 must decode to exactly 32 bytes"))?;
    Ok(arr)
}

async fn wait_for_ctrl_c() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => {}
        Err(e) => error!("failed to listen for Ctrl-C: {e}"),
    }
}
