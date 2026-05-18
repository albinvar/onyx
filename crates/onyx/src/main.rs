//! `onyx` — Onyx CLI/TUI client.
//!
//! Stateless client. Connects to a running `onyxd` over the local
//! API socket and asks it to do things on the user's behalf. All
//! long-term secrets — vault, identity, MLS state, Tor circuit —
//! live in `onyxd`, never here.
//!
//! ## v0 subcommands
//!
//! * `onyx` — **(no subcommand)** launches the daemon AND the TUI in
//!   one process. The recommended way to use Onyx interactively. T7.1+
//! * `onyx daemon` — run the daemon work without the TUI (foreground).
//!   Useful for headless use, debug, or running under process supervisors.
//! * `onyx status` — daemon liveness + identity + Tor state.
//! * `onyx identity` — just the identity (public key + fingerprint).
//! * `onyx send-bootstrap` — first-contact send via hub (msg/v1, PFS only).
//! * `onyx send-bootstrap-mls` — first-contact send via hub (mls/v1, full MLS PCS).
//! * `onyx fetch-keypackage` — pull a peer's published KP from the hub directory.
//! * `onyx invite [--with-kp]` — print a shareable `onyx://invite/v1?…`
//!   URL bundling this identity's fingerprint + KEM pubkey. With
//!   `--with-kp`, also bundles a fresh MLS KeyPackage so the accepting
//!   peer gets full PCS on first contact (T7.2 + T7.2-mls).
//! * `onyx accept <url> --text "…"` — parse such a URL and send the
//!   bundled identity a first-contact via the hub. Tier auto-picked
//!   from the URL: MLS if `kp` present, else msg/v1 (T7.2+).
//! * `onyx tui` — open the multi-pane Ratatui interface against an
//!   already-running daemon (won't start one for you — use the
//!   no-subcommand form for that).
//!
//! ## Planned subcommands (see DESIGN.md §4 + §5)
//!
//!   * `onyx dial <onion> <pubkey>` — start a direct conversation.
//!   * `onyx send <peer> <msg>`     — send into an existing direct conversation.
//!   * `onyx tail <peer>`           — stream messages as they arrive.
//!   * `onyx contact [add|verify|list]`
//!   * `onyx wipe` — zeroize and exit (DESIGN.md §4.2)
//!
//! ## Exit codes
//!
//!   * `0` — request succeeded.
//!   * `1` — usage error or daemon returned [`ApiResponse::Error`].
//!   * `2` — could not connect to the daemon.

mod client;
mod tui;

use std::path::PathBuf;
use std::process::ExitCode;

use base64::Engine;
use clap::{Parser, Subcommand};
use onyx_core::api::{ApiRequest, ApiResponse};

#[derive(Parser, Debug)]
#[command(
    name = "onyx",
    version,
    about = "Onyx — anonymous E2E-encrypted chat over Tor. Run with no \
             subcommand to launch the daemon + TUI in one process."
)]
struct Args {
    /// Path of the local API socket. Defaults to `~/.onyx/onyx.sock`
    /// (same default as `onyxd --api-socket`). Override here or via
    /// `ONYX_API_SOCKET`.
    #[arg(long, env = "ONYX_API_SOCKET", global = true)]
    socket: Option<PathBuf>,

    /// Path to the encrypted vault file. Only used when this `onyx`
    /// invocation *starts* a daemon (no-subcommand form, or
    /// `onyx daemon`). One-shot CLI commands that talk to an
    /// already-running daemon ignore this flag. Defaults to
    /// `~/.onyx/vault.db` (auto-created with mode 0700).
    #[arg(long, env = "ONYX_VAULT", global = true)]
    vault: Option<PathBuf>,

    /// Vault passphrase. Required when starting a daemon
    /// (no-subcommand form, or `onyx daemon`). Pass via env var
    /// rather than CLI flag so it doesn't show up in `ps`.
    #[arg(long, env = "ONYX_PASSPHRASE", hide_env_values = true, global = true)]
    passphrase: Option<String>,

    /// **TEST-ONLY** local-TCP listen mode for the embedded daemon.
    /// See `onyxd --help` for the full caveat.
    #[arg(long, env = "ONYX_LISTEN_TCP", global = true)]
    listen_tcp: Option<String>,

    /// **TEST-ONLY** local-TCP dial mode for the embedded daemon.
    /// Requires `--dial-pubkey`.
    #[arg(long, env = "ONYX_DIAL_TCP", global = true)]
    dial_tcp: Option<String>,

    /// X25519 identity public key of the peer to dial (base32).
    /// Required by `--dial-tcp` / `--dial-onion`.
    #[arg(long, global = true)]
    dial_pubkey: Option<String>,

    #[command(subcommand)]
    cmd: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print daemon liveness + identity + Tor state as JSON.
    Status,
    /// Print the daemon's identity public key + fingerprint as JSON.
    Identity,
    /// Open the interactive multi-pane TUI against an already-running
    /// daemon (does NOT start one). For the all-in-one experience
    /// (daemon + TUI), run `onyx` with no subcommand.
    Tui,
    /// Run the daemon without a TUI (foreground). Useful for headless
    /// deployments or running under a process supervisor. Same as the
    /// standalone `onyxd` binary.
    Daemon,
    /// First-contact send via the hub (msg/v1 sealed-sender envelope).
    ///
    /// Requires the daemon to have been launched with
    /// `--hub-onion` + `--hub-pubkey`. The recipient does **not**
    /// need to be online — when they come online and subscribe to
    /// their introduction inbox, their daemon will receive and
    /// decode the envelope.
    ///
    /// Security tier note: `msg/v1` envelopes have per-message PFS
    /// only — no MLS PCS. See `SECURITY.md` §6.1 for the full
    /// tradeoff. The recipient TUI will render the message with a
    /// yellow `[hub]` badge so they can tell which tier it is.
    SendBootstrap {
        /// Recipient's base32-grouped fingerprint (the value printed
        /// by `onyx identity` under `fingerprint`).
        #[arg(long)]
        peer_fingerprint: String,
        /// Recipient's hybrid KEM public key, base32 (the value
        /// printed by `onyx identity` under `identity_kem_pub_b32`).
        /// ~1948 chars long — expect it to wrap on your terminal.
        #[arg(long)]
        peer_kem_pub_b32: String,
        /// Plaintext message to send.
        #[arg(long)]
        text: String,
    },
    /// **MLS-tier** first-contact via the hub. Establishes a real
    /// 2-party MLS group with the named peer; every application
    /// message exchanged in that group has full MLS post-compromise
    /// security.
    ///
    /// You need three things about the peer:
    ///   * `--peer-fingerprint` and `--peer-kem-pub-b32` — out of
    ///     band, like for `send-bootstrap`.
    ///   * `--peer-kp-b64` — pull this with
    ///     `onyx fetch-keypackage --peer-fingerprint X` (which talks
    ///     to your daemon's hub session to query the directory).
    ///
    /// After this call, both you and the peer hold a persistent MLS
    /// group; subsequent direct dials between you will resume the
    /// group via the existing T2.x path. Ongoing MLS-over-hub
    /// (async chat without a direct circuit) is T6.x.
    SendBootstrapMls {
        #[arg(long)]
        peer_fingerprint: String,
        #[arg(long)]
        peer_kem_pub_b32: String,
        /// Recipient's MLS KeyPackage in base64. Get via
        /// `onyx fetch-keypackage`.
        #[arg(long)]
        peer_kp_b64: String,
    },
    /// Look up a peer's published KeyPackage in the hub directory.
    /// Prints the KP bytes as base64 on stdout — suitable for
    /// piping into `--peer-kp-b64` of `send-bootstrap-mls`.
    ///
    /// The daemon validates the returned KP against `peer_fingerprint`
    /// before surfacing it; a mismatched KP (potential hub-directory
    /// tampering) surfaces as an `Error { code: malformed }` response.
    FetchKeypackage {
        #[arg(long)]
        peer_fingerprint: String,
    },
    /// Print a shareable `onyx://invite/v1?…` URL bundling our
    /// fingerprint and KEM public key. Hand it to a peer (over Signal,
    /// in person, whatever channel you trust to authenticate them) and
    /// they run `onyx accept <url> --text "hi"` to introduce themselves
    /// via the hub. The URL carries no secrets — it's the same data
    /// `onyx identity` already prints, just bundled.
    ///
    /// With `--with-kp`, the URL *also* embeds a fresh MLS KeyPackage
    /// so the accepting peer's `onyx accept` automatically uses
    /// MLS-tier bootstrap (full PCS on every subsequent message).
    /// KPs are single-use in MLS — mint a fresh URL per recipient if
    /// you want both to succeed.
    Invite {
        /// Embed a fresh MLS KeyPackage in the URL so the accepting
        /// peer uses `SendBootstrapMls` (full MLS PCS on first
        /// contact) instead of msg/v1 (PFS only).
        #[arg(long)]
        with_kp: bool,
    },
    /// Accept an `onyx://invite/v1?…` URL by sending the named
    /// fingerprint a first-contact message via the hub. Equivalent to
    /// `onyx send-bootstrap --peer-fingerprint … --peer-kem-pub-b32 …
    /// --text …` but you don't have to copy two long base32 strings.
    ///
    /// Tier: msg/v1 (PFS only). MLS-tier bootstrap via invite URL is
    /// queued for a follow-up phase; for now use `fetch-keypackage` +
    /// `send-bootstrap-mls` if you need MLS PCS on first contact.
    Accept {
        /// The `onyx://invite/v1?…` URL.
        url: String,
        /// Plaintext message to deliver alongside the introduction.
        /// Required — a sealed-sender envelope always carries a
        /// payload, so an empty "just say hi" introduction doesn't
        /// exist at the protocol level.
        #[arg(long)]
        text: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    // Initialise tracing for any mode that runs the daemon or the TUI;
    // pure one-shot CLI commands keep stdout clean so they pipe into `jq`.
    let needs_logging = matches!(args.cmd, Some(Command::Tui | Command::Daemon) | None);
    if needs_logging {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_writer(std::io::stderr)
            .init();
    }

    match dispatch(args).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("onyx: {e:#}");
            ExitCode::from(2)
        }
    }
}

/// Build a daemon `Config` from the global `Args`. Used by both the
/// no-subcommand path (`onyx`) and the explicit `onyx daemon` form.
fn build_daemon_config(
    args: &Args,
    socket: &std::path::Path,
) -> anyhow::Result<onyx_daemon::Config> {
    let Some(passphrase) = args.passphrase.clone() else {
        anyhow::bail!(
            "starting the embedded daemon requires --passphrase (or the \
             ONYX_PASSPHRASE env var). Pass it via env so it doesn't \
             show up in `ps`."
        );
    };
    Ok(onyx_daemon::Config {
        vault: args
            .vault
            .clone()
            .unwrap_or_else(onyx_daemon::default_vault_path),
        passphrase,
        no_tor: args.listen_tcp.is_some() || args.dial_tcp.is_some(),
        tor_state_dir: None,
        dial_onion: None,
        dial_pubkey: args.dial_pubkey.clone(),
        api_socket: socket.to_string_lossy().into_owned(),
        hub_onion: None,
        hub_pubkey: None,
        listen_tcp: args.listen_tcp.clone(),
        dial_tcp: args.dial_tcp.clone(),
    })
}

async fn dispatch(args: Args) -> anyhow::Result<ExitCode> {
    // Resolve the optional --socket once so every arm sees the same
    // path. Defaulting to `~/.onyx/onyx.sock` matches the daemon's
    // default api_socket; the parent dir is auto-created by
    // `onyx_daemon::run` with mode 0700.
    let socket: PathBuf = args
        .socket
        .clone()
        .unwrap_or_else(|| PathBuf::from(onyx_daemon::default_api_socket_path()));
    match args.cmd {
        // ── No subcommand: launch daemon + TUI in one process ───────────
        None => {
            let config = build_daemon_config(&args, &socket)?;
            // Spawn the daemon work in a background task.
            let daemon_handle = tokio::spawn(async move {
                if let Err(e) = onyx_daemon::run(config).await {
                    eprintln!("onyx: daemon exited with error: {e:#}");
                }
            });
            // Give the daemon a moment to bind the API socket so the
            // TUI's first connect doesn't race. We don't poll because
            // the TUI's own 2-second tick will keep retrying on its own.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let tui_result = tui::run(socket).await;
            daemon_handle.abort();
            tui_result?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Daemon) => {
            let config = build_daemon_config(&args, &socket)?;
            onyx_daemon::run(config).await?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Status) => one_shot_print(&socket, ApiRequest::Status).await,
        Some(Command::Identity) => one_shot_print(&socket, ApiRequest::Identity).await,
        Some(Command::Tui) => {
            tui::run(socket).await?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::SendBootstrap {
            peer_fingerprint,
            peer_kem_pub_b32,
            text,
        }) => {
            one_shot_print(
                &socket,
                ApiRequest::SendBootstrap {
                    peer_fingerprint,
                    peer_kem_pub_b32,
                    text,
                },
            )
            .await
        }
        Some(Command::SendBootstrapMls {
            peer_fingerprint,
            peer_kem_pub_b32,
            peer_kp_b64,
        }) => {
            one_shot_print(
                &socket,
                ApiRequest::SendBootstrapMls {
                    peer_fingerprint,
                    peer_kem_pub_b32,
                    peer_kp_b64,
                },
            )
            .await
        }
        Some(Command::FetchKeypackage { peer_fingerprint }) => {
            one_shot_print(
                &socket,
                ApiRequest::FetchPeerKeyPackage { peer_fingerprint },
            )
            .await
        }
        Some(Command::Invite { with_kp }) => run_invite(&socket, with_kp).await,
        Some(Command::Accept { url, text }) => run_accept(&socket, &url, text).await,
    }
}

/// Build an `onyx://invite/v1?…` URL from the daemon's identity and
/// print it on stdout. Plain string output (not JSON) — this is meant
/// to be piped directly into a clipboard / chat client. With
/// `with_kp`, also calls `ExportKeyPackage` and bundles a fresh KP
/// in the URL so `onyx accept` on the other side will use MLS-tier
/// bootstrap (full PCS) instead of msg/v1 (PFS only).
async fn run_invite(socket: &std::path::Path, with_kp: bool) -> anyhow::Result<ExitCode> {
    let id_resp = client::one_shot(socket, &ApiRequest::Identity).await?;
    let (fingerprint, kem) = match id_resp {
        ApiResponse::IdentityOk {
            fingerprint,
            identity_kem_pub_b32,
            ..
        } => (fingerprint, identity_kem_pub_b32),
        ApiResponse::Error { .. } => {
            println!("{}", serde_json::to_string_pretty(&id_resp)?);
            return Ok(ExitCode::from(1));
        }
        other => anyhow::bail!("unexpected daemon response to Identity: {other:?}"),
    };
    let fp = onyx_core::crypto::Fingerprint::parse(&fingerprint)?;

    let invite = if with_kp {
        let kp_resp = client::one_shot(socket, &ApiRequest::ExportKeyPackage).await?;
        let kp_b64_std = match kp_resp {
            ApiResponse::ExportKeyPackageOk { kp_b64 } => kp_b64,
            ApiResponse::Error { .. } => {
                println!("{}", serde_json::to_string_pretty(&kp_resp)?);
                return Ok(ExitCode::from(1));
            }
            other => anyhow::bail!("unexpected daemon response to ExportKeyPackage: {other:?}"),
        };
        // API returns standard base64; Invite stores raw bytes and
        // re-emits as base64url in the URL. Convert once so the Invite
        // type stays decoupled from the API encoding.
        let kp_bytes = base64::engine::general_purpose::STANDARD
            .decode(kp_b64_std)
            .map_err(|e| anyhow::anyhow!("daemon returned invalid base64 KP: {e}"))?;
        onyx_core::invite::Invite::with_key_package(fp, kem, kp_bytes)
    } else {
        onyx_core::invite::Invite::new(fp, kem)
    };
    println!("{}", invite.to_url());
    Ok(ExitCode::SUCCESS)
}

/// Parse an invite URL, then ship a sealed-sender bootstrap to the
/// recipient with `text` as the payload. Picks the tier from the URL:
/// MLS-tier (`SendBootstrapMls`, full PCS) when the URL carries a
/// `kp`, otherwise msg/v1 (`SendBootstrap`, PFS only).
///
/// Note: the existing `SendBootstrapMls` API only ships the MLS
/// Welcome — it doesn't carry an application message — so the
/// `--text` payload is *not* delivered on the MLS-tier path. The
/// introduction completes silently on the recipient's side and chat
/// starts from their first reply. Extending `SendBootstrapMls` to
/// carry an inline first message is a separate slice.
async fn run_accept(socket: &std::path::Path, url: &str, text: String) -> anyhow::Result<ExitCode> {
    let invite = onyx_core::invite::Invite::parse(url)
        .map_err(|e| anyhow::anyhow!("invalid invite URL: {e}"))?;
    let peer_fingerprint = invite.fingerprint.to_string();
    let req = if let Some(peer_kp_b64) = invite.kp_standard_b64() {
        ApiRequest::SendBootstrapMls {
            peer_fingerprint,
            peer_kem_pub_b32: invite.kem_pub_b32,
            peer_kp_b64,
        }
    } else {
        ApiRequest::SendBootstrap {
            peer_fingerprint,
            peer_kem_pub_b32: invite.kem_pub_b32,
            text,
        }
    };
    one_shot_print(socket, req).await
}

/// Send `req`, pretty-print the response as JSON on stdout, return
/// `1` if the daemon returned an `Error`, `0` otherwise.
async fn one_shot_print(socket: &std::path::Path, req: ApiRequest) -> anyhow::Result<ExitCode> {
    let resp = client::one_shot(socket, &req).await?;
    let json = serde_json::to_string_pretty(&resp)?;
    println!("{json}");
    Ok(match resp {
        ApiResponse::Error { .. } => ExitCode::from(1),
        _ => ExitCode::SUCCESS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Lock in the CLI shape so a future arg rename doesn't silently
    /// break shell scripts users have written against this command.
    #[test]
    fn send_bootstrap_parses_with_three_flags() {
        let args = Args::try_parse_from([
            "onyx",
            "send-bootstrap",
            "--peer-fingerprint",
            "abcd efgh",
            "--peer-kem-pub-b32",
            "longb32stringgoeshere",
            "--text",
            "hello via hub",
        ])
        .expect("parses");
        match args.cmd {
            Some(Command::SendBootstrap {
                peer_fingerprint,
                peer_kem_pub_b32,
                text,
            }) => {
                assert_eq!(peer_fingerprint, "abcd efgh");
                assert_eq!(peer_kem_pub_b32, "longb32stringgoeshere");
                assert_eq!(text, "hello via hub");
            }
            other => panic!("expected SendBootstrap, got {other:?}"),
        }
    }

    #[test]
    fn send_bootstrap_requires_all_three_flags() {
        // Omitting --text must surface as a clap parse error rather
        // than defaulting to empty (sending an empty message silently
        // would be a real footgun).
        assert!(
            Args::try_parse_from([
                "onyx",
                "send-bootstrap",
                "--peer-fingerprint",
                "x",
                "--peer-kem-pub-b32",
                "y",
            ])
            .is_err()
        );
    }

    #[test]
    fn send_bootstrap_mls_parses_with_three_flags() {
        let args = Args::try_parse_from([
            "onyx",
            "send-bootstrap-mls",
            "--peer-fingerprint",
            "abcd",
            "--peer-kem-pub-b32",
            "kem",
            "--peer-kp-b64",
            "kpbase64",
        ])
        .expect("parses");
        match args.cmd {
            Some(Command::SendBootstrapMls {
                peer_fingerprint,
                peer_kem_pub_b32,
                peer_kp_b64,
            }) => {
                assert_eq!(peer_fingerprint, "abcd");
                assert_eq!(peer_kem_pub_b32, "kem");
                assert_eq!(peer_kp_b64, "kpbase64");
            }
            other => panic!("expected SendBootstrapMls, got {other:?}"),
        }
    }

    #[test]
    fn fetch_keypackage_parses() {
        let args = Args::try_parse_from(["onyx", "fetch-keypackage", "--peer-fingerprint", "abcd"])
            .expect("parses");
        match args.cmd {
            Some(Command::FetchKeypackage { peer_fingerprint }) => {
                assert_eq!(peer_fingerprint, "abcd");
            }
            other => panic!("expected FetchKeypackage, got {other:?}"),
        }
    }

    #[test]
    fn send_bootstrap_mls_requires_all_three_flags() {
        // Same anti-footgun discipline as send-bootstrap: omitting
        // --peer-kp-b64 must be a clap parse error, not a silent default.
        assert!(
            Args::try_parse_from([
                "onyx",
                "send-bootstrap-mls",
                "--peer-fingerprint",
                "x",
                "--peer-kem-pub-b32",
                "y",
            ])
            .is_err()
        );
    }

    #[test]
    fn invite_subcommand_parses_with_no_args() {
        let args = Args::try_parse_from(["onyx", "invite"]).expect("parses");
        assert!(matches!(args.cmd, Some(Command::Invite { with_kp: false })));
    }

    #[test]
    fn invite_subcommand_parses_with_kp_flag() {
        let args = Args::try_parse_from(["onyx", "invite", "--with-kp"]).expect("parses");
        assert!(matches!(args.cmd, Some(Command::Invite { with_kp: true })));
    }

    #[test]
    fn accept_subcommand_parses_url_and_text() {
        let args = Args::try_parse_from([
            "onyx",
            "accept",
            "onyx://invite/v1?fp=abcd&kem=efgh",
            "--text",
            "hi from accept",
        ])
        .expect("parses");
        match args.cmd {
            Some(Command::Accept { url, text }) => {
                assert_eq!(url, "onyx://invite/v1?fp=abcd&kem=efgh");
                assert_eq!(text, "hi from accept");
            }
            other => panic!("expected Accept, got {other:?}"),
        }
    }

    #[test]
    fn accept_requires_text_flag() {
        // Empty introduction would silently ship an empty plaintext —
        // surface it as a clap parse error instead, same discipline
        // as send-bootstrap.
        assert!(Args::try_parse_from(["onyx", "accept", "onyx://invite/v1?fp=x&kem=y"]).is_err());
    }
}
