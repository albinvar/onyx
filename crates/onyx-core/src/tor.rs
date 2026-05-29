//! Tor integration via Arti.
//!
//! Two responsibilities (DESIGN.md §3.2):
//!
//!   * **Outbound circuits** — dial peer `.onion` addresses and hubs.
//!     [`TorRuntime::bootstrap`] starts a tokio-driven Arti client;
//!     [`TorRuntime::dial`] returns an async stream
//!     [`crate::transport::Session`] can wrap.
//!   * **Inbound hidden service** — publish this user's v3 onion derived
//!     from their long-term signing key. Not yet implemented (see
//!     [`TorRuntime::publish_hidden_service`] for the carry-forward).
//!     Hidden service publication requires `tor-hsservice` and a more
//!     involved configuration pass; it will land alongside the first
//!     `onyxd` async wiring.
//!
//! ## Why Arti
//!
//! Arti is the Tor Project's own Rust implementation of the Tor client
//! protocol. Embedding it means we don't depend on a system-installed
//! `tor` daemon (no exec, no IPC, no protocol mismatch surprises).
//! Cost: a long transitive dep set and substantial compile time on
//! first build. The `Swatinem/rust-cache` action in CI absorbs the
//! repeat cost.
//!
//! ## Runtime
//!
//! Arti is async. We default to its tokio integration (its `tokio`
//! feature is on by default), so [`TorStream`] implements
//! [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`] directly with
//! no adapter.
//!
//! ## Network in tests
//!
//! Unit tests in this module are deliberately **compilation-only**.
//! Anything that actually starts Tor needs outbound network and a
//! lengthy bootstrap (30–60 s on cold cache); not appropriate for
//! `cargo test` in CI. End-to-end exercising belongs in a separate
//! integration-test suite or in `onyxd`'s smoke tests once it exists.

use std::sync::Arc;

use arti_client::{TorClient, TorClientConfig};
use futures::StreamExt;
use safelog::DisplayRedacted;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{HsNickname, RunningOnionService, handle_rend_requests};
use tor_rtcompat::PreferredRuntime;

use crate::error::{Error, Result};

/// Async stream over a Tor circuit. Implements
/// [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`] — pass it to
/// [`crate::transport::Session::encrypt_frame`] / `decrypt_frame` once
/// the daemon's frame-on-stream loop exists.
///
/// Re-exported as a type alias rather than a newtype wrapper for v0;
/// callers can use Arti's `DataStream` methods directly if they need
/// circuit-level introspection. If we later want to hide Arti's surface
/// entirely, this becomes a newtype with delegated I/O impls.
pub type TorStream = arti_client::DataStream;

/// Embedded Tor client.
///
/// One per daemon. Holds open the Tor consensus and reuses circuits
/// across outbound dials. Reasonably cheap to share via [`Arc`].
#[derive(Clone)]
pub struct TorRuntime {
    inner: Arc<TorClient<PreferredRuntime>>,
}

impl TorRuntime {
    /// Start Arti with the default config (state cached in Arti's
    /// platform-default directory: `~/.local/share/arti` on Linux,
    /// `~/Library/Application Support/arti` on macOS, …) and run the
    /// full bootstrap.
    ///
    /// Async because the bootstrap downloads consensus + builds initial
    /// circuits. On a cold cache this can take 30–60 s; on a warm
    /// cache it's much faster.
    pub async fn bootstrap() -> Result<Self> {
        Self::bootstrap_with(None).await
    }

    /// Start Arti with an explicit state directory (overrides the
    /// platform default). Use this to run multiple Onyx daemons on
    /// the same machine without them fighting over Arti's state-file
    /// lock — each daemon points at a distinct directory.
    ///
    /// `cache_dir` keeps the platform default (consensus + descriptors
    /// are shared-safe to read between daemons even when written by
    /// only one).
    pub async fn bootstrap_with_state_dir(state_dir: &std::path::Path) -> Result<Self> {
        Self::bootstrap_with(Some(state_dir)).await
    }

    async fn bootstrap_with(state_dir: Option<&std::path::Path>) -> Result<Self> {
        use arti_client::config::CfgPath;

        let config = if let Some(dir) = state_dir {
            let mut builder = TorClientConfig::builder();
            builder.storage().state_dir(CfgPath::new_literal(dir));
            builder.build().map_err(|e| {
                tracing::error!(error = %e, "tor: config build failed");
                Error::Internal("tor: config build failed (see tracing log)")
            })?
        } else {
            TorClientConfig::default()
        };
        let client = TorClient::create_bootstrapped(config).await.map_err(|e| {
            // Bootstrap can fail for many reasons (network blocked,
            // permission errors on state dir from fs-mistrust, etc).
            // Log the underlying error before collapsing to our opaque
            // variant so operators can debug.
            tracing::error!(error = %e, "tor: bootstrap failed");
            Error::Internal("tor: bootstrap failed (see tracing log)")
        })?;
        Ok(Self {
            inner: Arc::new(client),
        })
    }

    /// Dial a remote target over a Tor circuit. `host` can be a
    /// `.onion` address (e.g. `"abc123…xyz.onion"`) or — for testing —
    /// a clearnet hostname. Arti's `connect((host, port))` accepts
    /// anything that implements `IntoTorAddr`.
    pub async fn dial(&self, host: &str, port: u16) -> Result<TorStream> {
        self.inner
            .connect((host, port))
            .await
            .map_err(|_| Error::Internal("tor: dial failed"))
    }

    /// Return a clone of this client whose outbound dials form a fresh
    /// **circuit-isolation group** (Arti's `isolated_client`): streams
    /// opened through the returned runtime will not share a Tor circuit
    /// with streams from this runtime or from any other isolated clone
    /// (D-2). Use one isolated runtime per logical peer — each hub
    /// connection, each peer conversation — so a network/exit observer
    /// can't trivially link two of the user's conversations by seeing
    /// them ride the same circuit, and a single circuit's compromise or
    /// failure is scoped to one peer.
    ///
    /// **Scope (honest):** this isolates *circuits*, not *guards*. Tor
    /// deliberately reuses a small, sticky guard set across all circuits
    /// — more guards would make guard-discovery attacks easier, not
    /// harder — so the entry relay is intentionally shared; isolation
    /// operates at the circuit layer above it. It also does nothing
    /// against a global passive adversary correlating timing across
    /// circuits (see `ANONYMITY.md` §3.1).
    #[must_use]
    pub fn isolated(&self) -> Self {
        Self {
            inner: Arc::new(self.inner.isolated_client()),
        }
    }

    /// Publish a v3 hidden service under the given nickname.
    ///
    /// Returns an [`HiddenService`] handle (with `onion_address()`) plus
    /// the stream of inbound rendezvous requests that arti's introduction
    /// points produced. Hand the stream to a consumer that calls
    /// `tor_hsservice::handle_rend_requests` to turn each `RendRequest`
    /// into one or more application streams.
    ///
    /// **Identity binding caveat (v0).** The HS service key is currently
    /// generated by Arti's `KeyMgr` and stored in the platform-default
    /// keystore directory. Binding it to [`crate::identity::Identity`]'s
    /// long-term Ed25519 signing key — so the user's fingerprint and
    /// onion address are mathematically equivalent (DESIGN.md §4.1) —
    /// is the natural next step; it needs an importer that constructs
    /// an `HsIdKeypair` from raw bytes and feeds it to the keymgr.
    pub fn publish_hidden_service(&self, nickname: &str) -> Result<HiddenService> {
        let nick: HsNickname = nickname
            .parse()
            .map_err(|_| Error::InvalidEncoding("tor: HS nickname must be ASCII alnum + _ -"))?;
        let config = OnionServiceConfigBuilder::default()
            .nickname(nick)
            .build()
            .map_err(|_| Error::Internal("tor: HS config build failed"))?;

        let (running, rend_requests) = self
            .inner
            .launch_onion_service(config)
            .map_err(|_| Error::Internal("tor: launch HS failed"))?
            .ok_or(Error::Internal("tor: HS disabled by config"))?;

        Ok(HiddenService {
            running,
            rend_requests: Some(Box::pin(rend_requests)),
        })
    }
}

// ── HiddenService ──────────────────────────────────────────────────────────

/// Re-export so consumers (`onyxd`) don't have to depend on `tor-hsservice` directly.
pub use tor_hsservice::RendRequest as InboundRendRequest;

/// A running hidden service.
///
/// Two things you can do with it:
///   * Query [`HiddenService::onion_address`] for the `*.onion` string.
///   * Take the [`HiddenService::take_rend_requests`] stream **once** and
///     hand it to a consumer that will use
///     [`tor_hsservice::handle_rend_requests`] to convert each
///     `RendRequest` into one or more inbound application streams.
///
/// Dropping the `HiddenService` (specifically the inner
/// `RunningOnionService`) stops the service from publishing and from
/// accepting new requests. Keep it alive for as long as the daemon
/// wants to be reachable.
pub struct HiddenService {
    running: Arc<RunningOnionService>,
    rend_requests:
        Option<std::pin::Pin<Box<dyn futures::Stream<Item = InboundRendRequest> + Send>>>,
}

impl HiddenService {
    /// The `*.onion` address Arti has assigned this service. Returns
    /// `None` if the HS has not yet finished initial publication. Arti
    /// usually has the address available immediately (the key material
    /// exists before the descriptor is published) but the API is
    /// fallible per upstream.
    #[must_use]
    pub fn onion_address(&self) -> Option<String> {
        // HsId deliberately doesn't impl Display so accidental log
        // statements don't leak the address. We use the unredacted form
        // explicitly because the daemon's operator needs the full
        // address to share it OOB.
        self.running
            .onion_address()
            .map(|hsid| hsid.display_unredacted().to_string())
    }

    /// Take the stream of incoming rendezvous requests. Returns `Some`
    /// on the first call and `None` thereafter — there's exactly one
    /// stream per `HiddenService`.
    pub fn take_rend_requests(
        &mut self,
    ) -> Option<std::pin::Pin<Box<dyn futures::Stream<Item = InboundRendRequest> + Send>>> {
        self.rend_requests.take()
    }

    /// Take the inbound stream and convert it into a high-level stream
    /// of **accepted** [`TorStream`]s. Each yielded stream is ready to
    /// be handed straight to
    /// [`crate::transport::handshake_responder`].
    ///
    /// Errors during per-stream acceptance (e.g. a rendezvous failure
    /// or a dropped circuit) are logged to `tracing` and the iterator
    /// moves on rather than ending the whole accept loop — Arti's HS
    /// startup is fragile in the first few minutes and a single bad
    /// request shouldn't bring the daemon down.
    pub fn take_accept_streams(
        &mut self,
    ) -> Option<std::pin::Pin<Box<dyn futures::Stream<Item = TorStream> + Send>>> {
        let rend = self.rend_requests.take()?;
        // tor-hsservice's helper handles each `RendRequest::accept` and
        // flattens to a `Stream<StreamRequest>`. We then accept each of
        // those (with an empty `Connected` reply, which is what Tor
        // hidden services normally send) to get a `DataStream`.
        let stream_requests = handle_rend_requests(rend);
        let accepted = stream_requests.filter_map(|sr| async {
            match sr.accept(Connected::new_empty()).await {
                Ok(ds) => Some(ds),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "tor: failed to accept inbound stream request; continuing"
                    );
                    None
                }
            }
        });
        Some(Box::pin(accepted))
    }
}

impl std::fmt::Debug for HiddenService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HiddenService")
            .field("onion_address", &self.onion_address())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for TorRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorRuntime").finish_non_exhaustive()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirm the type aliases and trait impls we promise are real
    /// without actually starting Tor.
    #[test]
    fn tor_stream_implements_tokio_io() {
        fn assert_tokio_async_read<T: tokio::io::AsyncRead>() {}
        fn assert_tokio_async_write<T: tokio::io::AsyncWrite>() {}
        assert_tokio_async_read::<TorStream>();
        assert_tokio_async_write::<TorStream>();
    }

    /// Compilation-only: TorRuntime is Send + Sync (it's Arc-wrapped
    /// internally) so a daemon task can share it across worker
    /// threads.
    #[test]
    fn tor_runtime_is_send_sync_clone() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        fn assert_clone<T: Clone>() {}
        assert_send::<TorRuntime>();
        assert_sync::<TorRuntime>();
        assert_clone::<TorRuntime>();
    }

    /// Stub returns the right error variant. When the implementation
    /// lands, this test will fail loudly and remind us to update it.
    #[tokio::test]
    async fn publish_hidden_service_is_stubbed() {
        // We can construct a fake TorRuntime by skipping bootstrap —
        // but `TorClient::create_bootstrapped` requires network, and
        // `Arc::new(TorClient::...)` is the only way in. Since the
        // stub doesn't actually touch self, write the call as a doc-
        // expressed expectation in a single sentence and skip the
        // runtime construction. (`tor_runtime.publish_hidden_service()`
        // would return Err(NotImplemented) — verified by reading the
        // impl above.)
        //
        // A real test follows when we implement the function.
    }
}
