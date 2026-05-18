//! `onyx` — Onyx CLI/TUI client.
//!
//! Stateless client. Connects to a running `onyxd` over the local
//! API socket and asks it to do things on the user's behalf. All
//! long-term secrets — vault, identity, MLS state, Tor circuit —
//! live in `onyxd`, never here.
//!
//! ## v0 subcommands
//!
//!   * `onyx status`             — daemon liveness + identity + Tor state.
//!   * `onyx identity`           — just the identity (public key + fingerprint).
//!   * `onyx send-bootstrap`     — first-contact send via hub (msg/v1, PFS only).
//!   * `onyx send-bootstrap-mls` — first-contact send via hub (mls/v1, full MLS PCS).
//!   * `onyx fetch-keypackage`   — pull a peer's published KP from the hub directory.
//!   * `onyx tui`                — open the multi-pane Ratatui interface.
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

use clap::{Parser, Subcommand};
use onyx_core::api::{ApiRequest, ApiResponse, DEFAULT_SOCKET_PATH};

#[derive(Parser, Debug)]
#[command(
    name = "onyx",
    version,
    about = "Onyx CLI/TUI — talks to onyxd over a local Unix socket"
)]
struct Args {
    /// Path of the local API socket. Defaults to `./onyxd.sock`
    /// (same default as `onyxd --api-socket`). Override here or via
    /// `ONYX_API_SOCKET`.
    #[arg(long, env = "ONYX_API_SOCKET", default_value = DEFAULT_SOCKET_PATH, global = true)]
    socket: PathBuf,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print daemon liveness + identity + Tor state as JSON.
    Status,
    /// Print the daemon's identity public key + fingerprint as JSON.
    Identity,
    /// Open the interactive multi-pane TUI.
    Tui,
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
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    // Initialise tracing only for the TUI; CLI subcommands keep
    // stdout clean so they can be piped into `jq`.
    if matches!(args.cmd, Command::Tui) {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
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

async fn dispatch(args: Args) -> anyhow::Result<ExitCode> {
    match args.cmd {
        Command::Status => one_shot_print(&args.socket, ApiRequest::Status).await,
        Command::Identity => one_shot_print(&args.socket, ApiRequest::Identity).await,
        Command::Tui => {
            tui::run(args.socket).await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::SendBootstrap {
            peer_fingerprint,
            peer_kem_pub_b32,
            text,
        } => {
            one_shot_print(
                &args.socket,
                ApiRequest::SendBootstrap {
                    peer_fingerprint,
                    peer_kem_pub_b32,
                    text,
                },
            )
            .await
        }
        Command::SendBootstrapMls {
            peer_fingerprint,
            peer_kem_pub_b32,
            peer_kp_b64,
        } => {
            one_shot_print(
                &args.socket,
                ApiRequest::SendBootstrapMls {
                    peer_fingerprint,
                    peer_kem_pub_b32,
                    peer_kp_b64,
                },
            )
            .await
        }
        Command::FetchKeypackage { peer_fingerprint } => {
            one_shot_print(
                &args.socket,
                ApiRequest::FetchPeerKeyPackage { peer_fingerprint },
            )
            .await
        }
    }
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
            Command::SendBootstrap {
                peer_fingerprint,
                peer_kem_pub_b32,
                text,
            } => {
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
            Command::SendBootstrapMls {
                peer_fingerprint,
                peer_kem_pub_b32,
                peer_kp_b64,
            } => {
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
            Command::FetchKeypackage { peer_fingerprint } => {
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
}
