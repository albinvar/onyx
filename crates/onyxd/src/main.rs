//! `onyxd` — the Onyx daemon process.
//!
//! Wraps [`onyx_core`] and exposes:
//!   * a local Unix socket / authenticated TCP API for the TUI and local-web
//!     frontends (DESIGN.md §3.2);
//!   * a v3 hidden service endpoint for inbound peer connections and inbound
//!     hub deliveries (DESIGN.md §5.6, §3.2);
//!   * optional onion-web tier, gated by client-auth onion (DESIGN.md §8).

fn main() -> std::process::ExitCode {
    eprintln!(
        "onyxd v{} — scaffold only. See DESIGN.md v0.2-draft for the specification.",
        env!("CARGO_PKG_VERSION"),
    );
    std::process::ExitCode::from(1)
}
