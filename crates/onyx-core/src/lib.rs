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
pub mod invite;
pub mod mls;
pub mod room;
pub mod routing;
pub mod storage;
pub mod tor;
pub mod transport;
pub mod wire;

/// Onyx protocol version transmitted in the HELLO frame (DESIGN.md §5.3).
pub const PROTOCOL_VERSION: u16 = 1;

/// Release version string, the single source of truth for every
/// binary's `--version` and the daemon's reported `daemon_version`.
///
/// The workspace `Cargo.toml` version is deliberately pinned at
/// `0.0.1` (internal crate versioning); user-facing releases are
/// tagged independently (`vX.Y.Z`). At release-build time the CI
/// workflow exports `ONYX_RELEASE_VERSION` from the git tag, so a
/// published binary reports the version that matches its filename and
/// GitHub release. Local/dev builds (no env set) fall back to the
/// crate version. `option_env!` is const-evaluable, so this stays a
/// `const` with zero runtime cost.
pub const VERSION: &str = match option_env!("ONYX_RELEASE_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

/// Label namespace for all HKDF/BLAKE2 derivations. Bumping this string
/// invalidates every cross-protocol derivation, so it changes only with a
/// protocol-incompatible revision.
pub const KDF_NAMESPACE: &str = "onyx/v1";
