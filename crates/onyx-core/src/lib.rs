//! Onyx core — security-critical primitives for the Onyx anonymous chat system.
//!
//! All code in this crate is on the security boundary. See `DESIGN.md` at the
//! project root for the full specification (v0.2-draft).
//!
//! Module map (cross-references DESIGN.md sections):
//!
//! | module      | DESIGN.md sections                          |
//! |-------------|---------------------------------------------|
//! | [`crypto`]  | §4.1 keys, §5 transport primitives          |
//! | [`error`]   | (cross-cutting)                             |
//! | [`identity`]| §4 identity, lifecycle, verification        |
//! | [`mls`]     | §6 end-to-end encryption                    |
//! | [`routing`] | §5.5 introduction inbox + session tokens    |
//! | [`storage`] | §7 local database, at-rest encryption       |
//! | [`tor`]     | §3.2 Arti integration, hidden services      |
//! | [`transport`]| §5.2 Noise XK, §5.3 framing, §5.7 cover    |
//! | [`wire`]    | §5.4 envelope, §5.8 size buckets, CBOR codec|

#![doc(html_no_source)]

pub mod api;
pub mod crypto;
pub mod error;
pub mod flows;
pub mod identity;
pub mod mls;
pub mod routing;
pub mod storage;
pub mod tor;
pub mod transport;
pub mod wire;

/// Onyx protocol version transmitted in the HELLO frame (DESIGN.md §5.3).
pub const PROTOCOL_VERSION: u16 = 1;

/// Label namespace for all HKDF/BLAKE2 derivations. Bumping this string
/// invalidates every cross-protocol derivation, so it changes only with a
/// protocol-incompatible revision.
pub const KDF_NAMESPACE: &str = "onyx/v1";
