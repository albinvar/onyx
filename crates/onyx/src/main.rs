//! `onyx` — Onyx CLI/TUI client.
//!
//! Stateless client. Connects to a running `onyxd` over the local
//! API socket and asks it to do things on the user's behalf. All
//! long-term secrets — vault, identity, MLS state, Tor circuit —
//! live in `onyxd`, never here.
//!
//! ## v0 subcommands
//!
//!   * `onyx status`   — daemon liveness + identity + Tor state.
//!   * `onyx identity` — just the identity (public key + fingerprint).
//!   * `onyx tui`      — open the multi-pane Ratatui interface.
//!
//! ## Planned subcommands (see DESIGN.md §4 + §5)
//!
//!   * `onyx dial <onion> <pubkey>` — start a new conversation.
//!   * `onyx send <peer> <msg>`     — send into an existing conversation.
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
