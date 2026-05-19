//! `onyx-hub` library surface — exposes the modules so the
//! workspace's integration tests can spin up a hub in-process
//! without paying the binary-spawn round-trip.
//!
//! The primary entry point is still the binary (`src/main.rs`); the
//! library exists so an integration test can construct + drive a
//! [`state::HubState`] and run inbound connections through
//! [`handler::hub_handle_connection`] directly. The smoke harness
//! in `crates/onyx-hub/tests/` is the only consumer today.

pub mod handler;
pub mod peer_link;
pub mod rate_limit;
pub mod state;
pub mod store;
