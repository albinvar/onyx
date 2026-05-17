//! Identity, keys, and the on-disk vault.
//!
//! See DESIGN.md §4 in full. Key points:
//!   * An identity owns an Ed25519 signing key, an X25519 identity key,
//!     and an Ed25519 v3 onion service key derived from the signing key
//!     (so the user's fingerprint and onion address are equivalent).
//!   * Long-term key material is held in a `Zeroizing<>` buffer in memory
//!     and AEAD-encrypted at rest under an Argon2id-derived vault key.
//!   * Verification of contacts is fingerprint-based, established out of
//!     band — the chat layer cannot bootstrap trust.
//!
//! No types stubbed yet; the public surface will land alongside the storage
//! schema work so the in-memory and on-disk representations evolve together.
