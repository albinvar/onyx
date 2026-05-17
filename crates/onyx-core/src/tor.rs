//! Embedded Tor client (Arti) — hidden service publication and outbound circuits.
//!
//! See DESIGN.md §3.2. The daemon publishes its own v3 hidden service whose
//! key is derived from the long-term signing key (§4.1) and dials other
//! `.onion` addresses through Arti. The onion-web tier (§8) requires
//! client-auth (stealth) onion publication; peer onions can use either
//! mode at the user's discretion.
