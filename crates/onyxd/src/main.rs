//! `onyxd` — the Onyx daemon process.
//!
//! Responsibilities (DESIGN.md §3.2):
//!
//!   * Own the user's [`onyx_core::identity::Identity`] for the
//!     lifetime of the process (vault is unlocked at startup with a
//!     passphrase from the environment or an interactive prompt).
//!   * Run an embedded Tor client and publish the user's v3 hidden
//!     service so peers can dial in.
//!   * Maintain outbound connections to peers and hubs via Tor.
//!   * Expose a local API socket for the CLI (`onyx`) to drive.
//!
//! ## What this revision does
//!
//! Phase T1.1 + T1.2 from the project roadmap:
//!
//!   * Vault open / create (asks for passphrase via `ONYX_PASSPHRASE`
//!     env var; interactive prompting is a follow-up).
//!   * On first run, generates a fresh [`onyx_core::identity::Identity`]
//!     called "default" and stores it.
//!   * Bootstraps [`onyx_core::tor::TorRuntime`] (downloads consensus,
//!     builds initial circuits).
//!   * Publishes a v3 hidden service under the nickname `"onyx"` and
//!     logs the resulting `.onion` address.
//!   * Drains the inbound rendezvous-request stream in a background
//!     task so the service doesn't back-pressure.
//!   * Idles until Ctrl-C, then shuts down gracefully.
//!
//! What's **not** here yet: per-connection Noise XK handshake, frame
//! handling, local API socket, anything that uses
//! [`onyx_core::transport::Session`] on a real socket. Those land in
//! the next phase (the "two-daemon smoke test" milestone).

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use futures::StreamExt;
use onyx_core::crypto::Argon2Params;
use onyx_core::storage::Vault;
use onyx_core::tor::TorRuntime;
use tracing::{error, info, warn};

/// Default vault nickname for the auto-generated first identity.
const DEFAULT_IDENTITY_NICKNAME: &str = "default";

/// Hidden service nickname under which Arti's keymgr files the HS key.
/// Bumping this string makes Arti generate a fresh `.onion` (different
/// keystore slot) — the user's identity is then disconnected from
/// their previous onion. Don't change it casually.
const HS_NICKNAME: &str = "onyx";

#[derive(Parser, Debug)]
#[command(name = "onyxd", version, about = "Onyx daemon")]
struct Args {
    /// Path to the encrypted vault file. Created on first run, opened
    /// thereafter. Defaults to `./onyx-state.db`; for real use, point
    /// it at `~/.local/share/onyx/state.db` (or your platform's
    /// equivalent).
    #[arg(long, env = "ONYX_VAULT", default_value = "./onyx-state.db")]
    vault: PathBuf,

    /// Vault passphrase. **Strongly recommended** to pass via
    /// environment variable rather than command line (command lines
    /// are visible in `ps` and shell histories).
    #[arg(long, env = "ONYX_PASSPHRASE", hide_env_values = true)]
    passphrase: String,

    /// Skip the Tor bootstrap entirely. Useful for smoke-testing the
    /// CLI parsing / vault flow without a 30-second wait or outbound
    /// network.
    #[arg(long)]
    no_tor: bool,
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

    // ── Vault ─────────────────────────────────────────────────────────────
    let mut vault =
        open_or_create_vault(&args.vault, args.passphrase.as_bytes()).context("opening vault")?;

    let identity = ensure_default_identity(&mut vault).context("ensuring default identity")?;
    info!(
        fingerprint = %identity.fingerprint(),
        "vault unlocked, identity loaded"
    );

    // Zeroize the passphrase string we received from clap. (clap doesn't
    // give us a `Zeroizing<String>` directly; we drop our copy here.
    // The OS-level memory it lived in before main() — env var, kernel
    // arg-list, shell history — is outside our control.)
    drop(args.passphrase);

    if args.no_tor {
        warn!("--no-tor set: skipping Tor bootstrap; daemon will idle until Ctrl-C");
        wait_for_ctrl_c().await;
        return Ok(());
    }

    // ── Tor + Hidden Service ─────────────────────────────────────────────
    info!("bootstrapping Tor (this may take 30-60s on a cold cache)…");
    let tor = TorRuntime::bootstrap()
        .await
        .map_err(|e| anyhow::anyhow!("tor bootstrap failed: {e}"))?;
    info!("Tor bootstrap complete");

    let mut hs = tor
        .publish_hidden_service(HS_NICKNAME)
        .map_err(|e| anyhow::anyhow!("hidden service publish failed: {e}"))?;

    if let Some(addr) = hs.onion_address() {
        info!(onion = %addr, "hidden service published — share this address out of band");
    } else {
        warn!("hidden service has no address yet — Arti will produce one shortly");
    }

    // Spawn a task that drains the rendezvous-request stream. For now
    // we just drop each request — actual frame handling (Noise XK
    // handshake as responder + transport::Session) lands next phase.
    if let Some(mut requests) = hs.take_rend_requests() {
        tokio::spawn(async move {
            while let Some(req) = requests.next().await {
                warn!(
                    "received inbound rendezvous request — dropping (frame handling \
                     not yet implemented). request: {req:?}"
                );
                drop(req);
            }
        });
    }

    info!("onyxd running. Ctrl-C to stop.");
    wait_for_ctrl_c().await;
    info!("shutting down");
    // Dropping `hs` (and `tor`) stops the HS from publishing and tears
    // down circuits. `Vault` zeroizes its AEAD key on drop.
    drop(hs);
    drop(tor);
    drop(vault);
    Ok(())
}

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

fn ensure_default_identity(vault: &mut Vault) -> anyhow::Result<onyx_core::identity::Identity> {
    let existing = vault
        .list_identities()
        .map_err(|e| anyhow::anyhow!("list identities: {e}"))?;

    if let Some(first) = existing.into_iter().next() {
        return vault
            .get_identity(first.id)
            .map_err(|e| anyhow::anyhow!("loading identity {}: {e}", first.id));
    }

    info!("no identity found; generating fresh \"{DEFAULT_IDENTITY_NICKNAME}\" identity");
    let (_id, identity) = vault
        .create_identity(DEFAULT_IDENTITY_NICKNAME)
        .map_err(|e| anyhow::anyhow!("create identity: {e}"))?;
    Ok(identity)
}

async fn wait_for_ctrl_c() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => {}
        Err(e) => error!("failed to listen for Ctrl-C: {e}"),
    }
}
