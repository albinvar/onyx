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
#[command(name = "onyxd", version = onyx_core::VERSION, about = "Onyx daemon (headless)")]
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
    /// `onyx-hub` for offline-message subscribe + relay (legacy
    /// single-hub form — kept for backward compat). Pair with
    /// `--hub-pubkey`. Prefer `--hub onion:port,pubkey` for new
    /// deployments; that form is repeatable for multi-hub
    /// redundancy (T8.1+).
    #[arg(long, env = "ONYX_HUB_ONION", requires = "hub_pubkey")]
    hub_onion: Option<String>,

    /// Hub's X25519 identity public key (base32), printed by
    /// `onyx-hub` at startup. Required with `--hub-onion`. Legacy
    /// single-hub form.
    #[arg(long, env = "ONYX_HUB_PUBKEY", requires = "hub_onion")]
    hub_pubkey: Option<String>,

    /// Repeatable: each `--hub onion:port,b32pubkey` adds one hub to
    /// the daemon's hub list. Multi-hub mode (T8.1+) publishes
    /// envelopes to *all* configured hubs in parallel and subscribes
    /// on *all* of them, so a single hub going down does not lose
    /// deliveries. The recipient's replay guard (T7.3-sec.2) silently
    /// dedups duplicate envelopes that arrive from multiple hubs.
    ///
    /// Conflicts with `--hub-onion` / `--hub-pubkey` (the legacy
    /// single-hub form). Pick one form or the other; do not mix.
    #[arg(long = "hub", action = clap::ArgAction::Append,
          conflicts_with_all = ["hub_onion", "hub_pubkey"])]
    hubs: Vec<String>,

    /// **TEST-ONLY** local-TCP listen mode. No Tor, no anonymity.
    /// See `SECURITY.md` §6.2.
    #[arg(long, env = "ONYX_LISTEN_TCP", conflicts_with_all = ["dial_onion", "dial_tcp"])]
    listen_tcp: Option<String>,

    /// **TEST-ONLY** local-TCP dial mode. No Tor, no anonymity.
    /// Requires `--dial-pubkey`.
    #[arg(long, env = "ONYX_DIAL_TCP", requires = "dial_pubkey",
          conflicts_with_all = ["dial_onion", "listen_tcp"])]
    dial_tcp: Option<String>,

    /// **Opt-in.** Mean interval (in seconds) between cover-traffic
    /// PAD frames on each configured hub. See `ANONYMITY.md` §3.1.
    /// Off by default (the v0 default; not yet verified in real-Tor
    /// smoke). Setting 0 also disables.
    #[arg(long, env = "ONYX_COVER_TRAFFIC_MEAN_SECS")]
    cover_traffic_mean_secs: Option<u64>,

    /// **Opt-in, "high mode".** Slot interval (in milliseconds) for
    /// constant-rate client→hub cover traffic: one frame per slot to
    /// each hub (a queued real frame or a FRAME_PAD), making the
    /// upstream cadence invariant. Stronger than the Poisson
    /// `--cover-traffic-mean-secs` but costs up to one slot of latency
    /// per real frame. Mutually exclusive with that flag.
    /// See `ANONYMITY.md` §3.1.
    #[arg(long, env = "ONYX_CONSTANT_RATE_MS")]
    constant_rate_ms: Option<u64>,

    /// **D-1 — opt IN to first-contact reachability via the hub
    /// (default OFF = private).** Single master switch. Off (default):
    /// fresh per-connection ephemeral Noise static + ephemeral
    /// SUBSCRIBE-signing key, no `introduction_inbox(fp)` subscription,
    /// no KeyPackage publish — the hub cannot link the connection to
    /// your long-term identity (existing rooms + direct onion dials
    /// still work; you are just not reachable for first contact via
    /// this hub). On: long-term keys + intro-inbox + KP publish, so
    /// anyone with your fingerprint can reach you, at the cost of the
    /// hub linking all your activity on it to you. See `ANONYMITY.md`
    /// §3.2.
    #[arg(long, env = "ONYX_FIRST_CONTACT_REACHABLE")]
    first_contact_reachable: bool,

    /// **A1.2 — acknowledge clearnet (NO TOR, NO ANONYMITY).** Required
    /// to use any plain-TCP transport (`--no-tor`, `--listen-tcp`,
    /// `--dial-tcp`, `--hub-tcp`). Without it the daemon refuses to start
    /// those modes, so a mistyped flag can't silently expose your IP.
    /// Test/dev only.
    #[arg(long, env = "ONYX_ALLOW_CLEARNET")]
    allow_clearnet: bool,
}

impl TryFrom<Args> for Config {
    type Error = anyhow::Error;
    fn try_from(a: Args) -> Result<Self, Self::Error> {
        // Merge the legacy single-hub form (--hub-onion + --hub-pubkey)
        // and the new repeatable form (--hub onion:port,b32pubkey)
        // into a single Vec<HubConfig>. clap already forbids both at
        // once via conflicts_with_all, so at most one of these
        // branches contributes entries.
        let mut hubs: Vec<onyx_daemon::HubConfig> = Vec::new();
        if let (Some(onion), Some(pubkey)) = (a.hub_onion, a.hub_pubkey) {
            hubs.push(onyx_daemon::HubConfig { onion, pubkey });
        }
        for raw in a.hubs {
            let (onion, pubkey) = raw.split_once(',').ok_or_else(|| {
                anyhow::anyhow!("--hub value must be `onion:port,b32pubkey` (missing comma): {raw}")
            })?;
            if onion.is_empty() || pubkey.is_empty() {
                anyhow::bail!("--hub value has empty field: {raw}");
            }
            hubs.push(onyx_daemon::HubConfig {
                onion: onion.to_string(),
                pubkey: pubkey.to_string(),
            });
        }

        Ok(Self {
            vault: a.vault.unwrap_or_else(onyx_daemon::default_vault_path),
            passphrase: zeroize::Zeroizing::new(a.passphrase),
            no_tor: a.no_tor,
            tor_state_dir: a.tor_state_dir,
            dial_onion: a.dial_onion,
            dial_pubkey: a.dial_pubkey,
            api_socket: a
                .api_socket
                .unwrap_or_else(onyx_daemon::default_api_socket_path),
            hubs,
            hub_tcp_addrs: Vec::new(),
            listen_tcp: a.listen_tcp,
            dial_tcp: a.dial_tcp,
            cover_traffic_mean_secs: a.cover_traffic_mean_secs,
            constant_rate_ms: a.constant_rate_ms,
            first_contact_reachable: a.first_contact_reachable,
            allow_clearnet: a.allow_clearnet,
        })
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
    let config: Config = args.try_into()?;
    onyx_daemon::run(config).await
}
