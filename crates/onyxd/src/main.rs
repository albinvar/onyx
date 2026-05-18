//! `onyxd` — the standalone Onyx daemon binary.
//!
//! This is a thin clap-parsing wrapper around [`onyx_daemon::run`].
//! All daemon logic lives in the `onyx-daemon` library crate so the
//! all-in-one `onyx` binary can use the same implementation.
//!
//! If you're a normal user, you almost certainly want the `onyx`
//! binary instead — it bundles the daemon and the TUI in one
//! process. `onyxd` is for running a headless daemon (server,
//! background process under systemd, etc.) without a UI attached.

use std::path::PathBuf;

use clap::Parser;
use onyx_daemon::Config;

#[derive(Parser, Debug)]
#[command(name = "onyxd", version, about = "Onyx daemon (headless)")]
struct Args {
    /// Path to the encrypted vault file. Defaults to `~/.onyx/vault.db`
    /// (the parent directory is auto-created with mode 0700 if missing).
    #[arg(long, env = "ONYX_VAULT")]
    vault: Option<PathBuf>,

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

    /// Path for the local API socket (Unix domain socket) that the
    /// `onyx` CLI / TUI connects to. Defaults to `~/.onyx/onyx.sock`.
    /// The daemon `chmod`s it to `0600` after bind.
    #[arg(long, env = "ONYX_API_SOCKET")]
    api_socket: Option<String>,

    /// **Hub-client mode**: long-lived authenticated session to an
    /// `onyx-hub` for offline-message subscribe + relay. Pair with
    /// `--hub-pubkey`.
    #[arg(long, env = "ONYX_HUB_ONION", requires = "hub_pubkey")]
    hub_onion: Option<String>,

    /// Hub's X25519 identity public key (base32), printed by `onyx-hub`
    /// at startup. Required with `--hub-onion`.
    #[arg(long, env = "ONYX_HUB_PUBKEY", requires = "hub_onion")]
    hub_pubkey: Option<String>,

    /// **TEST-ONLY** local-TCP listen mode. No Tor, no anonymity.
    /// See `SECURITY.md` §6.2.
    #[arg(long, env = "ONYX_LISTEN_TCP", conflicts_with_all = ["dial_onion", "dial_tcp"])]
    listen_tcp: Option<String>,

    /// **TEST-ONLY** local-TCP dial mode. No Tor, no anonymity.
    /// Requires `--dial-pubkey`.
    #[arg(long, env = "ONYX_DIAL_TCP", requires = "dial_pubkey",
          conflicts_with_all = ["dial_onion", "listen_tcp"])]
    dial_tcp: Option<String>,
}

impl From<Args> for Config {
    fn from(a: Args) -> Self {
        Self {
            vault: a.vault.unwrap_or_else(onyx_daemon::default_vault_path),
            passphrase: a.passphrase,
            no_tor: a.no_tor,
            tor_state_dir: a.tor_state_dir,
            dial_onion: a.dial_onion,
            dial_pubkey: a.dial_pubkey,
            api_socket: a
                .api_socket
                .unwrap_or_else(onyx_daemon::default_api_socket_path),
            hub_onion: a.hub_onion,
            hub_pubkey: a.hub_pubkey,
            listen_tcp: a.listen_tcp,
            dial_tcp: a.dial_tcp,
        }
    }
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
    onyx_daemon::run(args.into()).await
}
