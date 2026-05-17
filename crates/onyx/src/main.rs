//! `onyx` — Onyx CLI/TUI client.
//!
//! Connects to a running `onyxd` over the local API socket. All security
//! guarantees in DESIGN.md are validated against this client; the local-web
//! and onion-web frontends are derivatives.
//!
//! Planned subcommands (see DESIGN.md §4 + §5):
//!   * `onyx init`                  — generate identity, derive onion
//!   * `onyx identity [list|new|export|import]`
//!   * `onyx contact [add|verify|list]`
//!   * `onyx room [create|join|leave|list]`
//!   * `onyx send <target> <message>`
//!   * `onyx wipe`                  — zeroize and exit (DESIGN.md §4.2)

fn main() -> std::process::ExitCode {
    eprintln!(
        "onyx v{} — scaffold only. See DESIGN.md v0.2-draft for the specification.",
        env!("CARGO_PKG_VERSION"),
    );
    std::process::ExitCode::from(1)
}
