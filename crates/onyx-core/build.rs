//! Build script for `onyx-core`.
//!
//! Its sole job is to make `onyx_core::VERSION` (which reads the
//! `ONYX_RELEASE_VERSION` env via `option_env!`) cache-correct. Cargo
//! does NOT track env vars consumed by `env!`/`option_env!` in its
//! fingerprint unless a build script declares them. Without this, a
//! cached `onyx-core` artifact built for an earlier release tag could
//! be reused for a later one, baking in a stale version string (the
//! CI release job uses a build cache, so this is a real hazard, not a
//! theoretical one). Declaring the dependency forces a recompile
//! whenever the release version changes, appears, or disappears.

fn main() {
    println!("cargo:rerun-if-env-changed=ONYX_RELEASE_VERSION");
}
