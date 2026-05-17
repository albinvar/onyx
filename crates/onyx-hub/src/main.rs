//! `onyx-hub` — optional relay server.
//!
//! Holds an authenticated hidden service, maintains encrypted offline message
//! queues keyed by routing identifier (DESIGN.md §5.5), hosts MLS-encrypted
//! group rooms (storing only ciphertext + ratchet tree state), and routes
//! between connected clients. Never sees plaintext.
//!
//! Hub authentication is invite-only by default (DESIGN.md §9.1) with an
//! optional open-registration mode.

fn main() -> std::process::ExitCode {
    eprintln!(
        "onyx-hub v{} — scaffold only. See DESIGN.md v0.2-draft for the specification.",
        env!("CARGO_PKG_VERSION"),
    );
    std::process::ExitCode::from(1)
}
