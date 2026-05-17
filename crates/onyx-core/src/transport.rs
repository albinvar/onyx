//! Wire transport — Noise XK handshake + framed AEAD channel.
//!
//! See DESIGN.md §5.1–§5.3. The handshake is `Noise_XK_25519_ChaChaPoly_BLAKE2s`
//! followed by an explicit key-confirmation exchange (each side sends an
//! AEAD-encrypted constant under the new transport key before any
//! application traffic).
//!
//! Frame layout (§5.3, revised in v0.2):
//!
//! ```text
//! 0       2                                          N
//! ┌───────┬──────────────────────────────────────────┐
//! │ len   │  ChaCha20-Poly1305(type ‖ payload)       │
//! │ u16   │                                          │
//! └───────┴──────────────────────────────────────────┘
//! ```
//!
//! Critical invariant: the 2-byte `type` discriminator lives **inside** the
//! AEAD envelope. Without that, the hub could distinguish PAD from DELIVER
//! and the cover-traffic guarantee of §5.7 would not hold. Any change here
//! is a security regression unless the threat model is updated to match.
//!
//! Frames are padded to one of three buckets (§5.8: 256 / 1024 / 4096 B)
//! before encryption, so size on the wire reveals only the bucket.
