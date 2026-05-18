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

use crate::handler::hub_handle_connection;
use crate::state::HubState;

mod handler;
mod state;

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

    let state = Arc::new(Mutex::new(HubState::new()));
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

async fn wait_for_ctrl_c() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => {}
        Err(e) => error!("failed to listen for Ctrl-C: {e}"),
    }
}
