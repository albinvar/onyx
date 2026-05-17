//! Routing identifiers — introduction inbox + rotating session tokens.
//!
//! See DESIGN.md §5.5 (revised) for the full scheme. Summary:
//!
//!   * **Tier 1 — introduction inbox** (long-term, per recipient):
//!     `inbox_id = BLAKE2b-128(recipient_signing_pk || "onyx/v1/inbox")`
//!     Used for bootstrap envelopes via sealed-sender (HPKE under the
//!     recipient's X25519 identity key). The outer envelope's `from` and
//!     `sig` fields are null so the hub sees nothing about the sender.
//!
//!   * **Tier 2 — rotating session tokens** (per MLS epoch):
//!     `token_e_i = BLAKE2b-128(MLS-Exporter("onyx/v1/routing", 32) || u64_be(i))`
//!     Pre-registered in batches with the hub via SUBSCRIBE. Rotated on
//!     every MLS commit; explicit Update every 24h of activity.
//!
//! Residual linkability is documented in DESIGN.md §5.5 — the inbox is
//! observable to anyone holding the fingerprint, and token batches share
//! a SUBSCRIBE connection unless clients deliberately fan out over
//! distinct Tor circuits.
