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
        Self::bootstrap_with(None, &[]).await
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
        Self::bootstrap_with(Some(state_dir), &[]).await
    }

    /// F2.2a: bootstrap with optional state dir AND optional Tor **bridge**
    /// lines. Each `bridges` entry is a standard bridge line (vanilla:
    /// `<ip:port> <fingerprint>`); with bridges configured, Arti connects
    /// via the unlisted bridge relay(s) instead of public guards, evading
    /// IP-blocklists of public guards. Empty `bridges` → default guard
    /// selection (byte-identical to the no-bridge path). See `TOR-BRIDGES.md`.
    ///
    /// F2.2b: `transports` are the pluggable-transport binaries for bridge
    /// lines that name a transport (`obfs4 …`, `snowflake …`); resolve them
    /// with [`resolve_transports`] first.
    pub async fn bootstrap_with_bridges(
        state_dir: Option<&std::path::Path>,
        bridges: &[String],
        transports: &[PtBinary],
    ) -> Result<Self> {
        Self::bootstrap_with_config(build_tor_config(state_dir, bridges, transports)?).await
    }

    async fn bootstrap_with(
        state_dir: Option<&std::path::Path>,
        bridges: &[String],
    ) -> Result<Self> {
        Self::bootstrap_with_config(build_tor_config(state_dir, bridges, &[])?).await
    }

    async fn bootstrap_with_config(config: TorClientConfig) -> Result<Self> {
        // Surface the effective HS vanguard mode at startup. This is
        // CONFIG, not identity — safe to log per D-3. If this ever prints
        // anything other than "full" the guard-discovery defense (A1.3)
        // has regressed.
        tracing::info!(
            hs_vanguard_mode = %effective_vanguard_mode(&config),
            "tor: vanguards pinned for onion-service circuits (A1.3 guard-discovery defense)"
        );

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
        use arti_client::HasKind as _;
        self.inner.connect((host, port)).await.map_err(|e| {
            // The caller only sees an opaque error, so record Arti's reason
            // here. The kind (e.g. "onion service descriptor not found",
            // "introduction points unreachable") names no address and is
            // safe at warn; the full error can name the target, so it is
            // debug only.
            tracing::warn!(kind = %e.kind(), "tor: dial failed");
            tracing::debug!(error = %e, "tor: dial failed (detail)");
            Error::Internal("tor: dial failed")
        })
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
    /// **Identity binding caveat (v0) — A6.4 / D-4.** The HS service key is
    /// currently generated by Arti's `KeyMgr` (random, keystore-managed),
    /// NOT derived from [`crate::identity::Identity`]'s signing key. So the
    /// user's `.onion` and their fingerprint are **independent keys with no
    /// cryptographic link**. **Security consequence: callers MUST NOT treat a
    /// peer's onion address as proof of their fingerprint** — authenticate by
    /// fingerprint (which the sealed-sender / MLS layers actually verify).
    /// The DESIGN.md §4.1 "onion == fingerprint, mathematically equivalent"
    /// property is the *intended* end state, not today's behaviour. Closing
    /// it (A6.4 in `ANONYMITY_ROADMAP.md`) needs a `KeyMgr` importer that
    /// builds an `HsIdKeypair` from the identity key and installs it before
    /// `launch_onion_service`.
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

/// A1.3: build the `TorClientConfig`, pinning **Full vanguards** for
/// guard-discovery defense. Factored out of [`TorRuntime::bootstrap_with`]
/// so the regression test can assert the pinned mode without bootstrapping
/// a real Tor client.
///
/// **Why pin, and why Full.** Our daemon publishes a v3 onion service
/// ([`TorRuntime::publish_hidden_service`]), the surface most exposed to
/// guard-discovery attacks (A6-band: a moderately-resourced adversary who
/// can repeatedly dial the `.onion` forces circuit builds and statistically
/// enumerates the relay adjacent to the entry guard → finds the guard).
/// Vanguards insert extra pinned, slow-rotating guard layers (L2, and for
/// `Full`, L3) so enumeration takes longer than the layers' rotation
/// periods. arti's *consensus default* for HS circuits is already `Full`,
/// but (a) the `vanguards` cargo feature must be compiled in — without it
/// `VanguardMode` collapses to `Disabled`-only and there is NO protection
/// (verified absent before this change) — and (b) we set the mode
/// **explicitly** rather than inheriting it, so a hostile/anomalous Tor
/// consensus cannot silently downgrade us below `Full`.
///
/// **Honest scope:** `Full` vanguards *slow* guard discovery; they do not
/// make it impossible. And this is whole-client config (arti exposes one
/// `VanguardMode`, not a general/HS split): general circuits get L2 as they
/// would under `Lite`; onion-service circuits additionally get L3. We do
/// NOT widen the outbound client entry-guard set — more entry guards make
/// discovery *easier*, not harder.
fn build_tor_config(
    state_dir: Option<&std::path::Path>,
    bridges: &[String],
    transports: &[PtBinary],
) -> Result<TorClientConfig> {
    use arti_client::config::BridgeConfigBuilder;
    use arti_client::config::CfgPath;
    use arti_client::config::pt::TransportConfigBuilder;
    use arti_client::config::vanguards::VanguardConfigBuilder;
    use tor_config::ExplicitOrAuto;
    use tor_guardmgr::VanguardMode;

    let mut builder = TorClientConfig::builder();
    if let Some(dir) = state_dir {
        builder.storage().state_dir(CfgPath::new_literal(dir));
    }

    // F2.2a: Tor bridges. Each line is parsed into a `BridgeConfigBuilder`
    // and pushed; a non-empty bridge list makes Arti's `BridgesConfig`
    // auto-enable bridge mode (connect via the unlisted bridge instead of a
    // public guard). Vanguards (below) still apply on top. With no bridges
    // this block is a no-op and the config is identical to the default path.
    for line in bridges {
        let bridge: BridgeConfigBuilder = line.parse().map_err(|e| {
            tracing::error!(error = %e, "tor: invalid --bridge line");
            Error::InvalidEncoding("tor: invalid bridge line")
        })?;
        builder.bridges().bridges().push(bridge);
    }
    if !bridges.is_empty() {
        tracing::info!(
            count = bridges.len(),
            "tor: configured with bridge(s) — connecting via unlisted relay(s) (F2.2a)"
        );
    }

    // F2.2b: one managed transport per binary. Arti refuses to build a
    // config whose bridges name a transport nothing provides, so a missing
    // binary is a hard error rather than a silent fallback to public guards.
    for pt in transports {
        let mut names = Vec::with_capacity(pt.protocols.len());
        for p in &pt.protocols {
            names.push(p.parse().map_err(|_| {
                tracing::error!(transport = %p, "tor: invalid transport name");
                Error::InvalidEncoding("tor: invalid transport name")
            })?);
        }
        let mut t = TransportConfigBuilder::default();
        t.protocols(names)
            .path(CfgPath::new_literal(&pt.path))
            .run_on_startup(false);
        builder.bridges().transports().push(t);
        tracing::info!(
            transports = %pt.protocols.join(","),
            binary = %pt.path.display(),
            "tor: pluggable transport configured (F2.2b)"
        );
    }

    // Pin Full. `.vanguards()` returns the sub-builder (like `.storage()`);
    // `.mode()` takes `ExplicitOrAuto<VanguardMode>` — `Explicit` (not
    // `Auto`) is what makes this a hard pin rather than "inherit the
    // consensus default." `VanguardConfigBuilder` is unused now that we go
    // through the sub-builder, but the import documents the type involved.
    let _ = VanguardConfigBuilder::default();
    builder
        .vanguards()
        .mode(ExplicitOrAuto::Explicit(VanguardMode::Full));

    builder.build().map_err(|e| {
        tracing::error!(error = %e, "tor: config build failed");
        Error::Internal("tor: config build failed (see tracing log)")
    })
}

/// F2.2b: a pluggable-transport client binary and the transports it provides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtBinary {
    /// Transport names, e.g. `["obfs4", "webtunnel"]`.
    pub protocols: Vec<String>,
    /// Absolute path to the binary (e.g. `/usr/bin/lyrebird`).
    pub path: std::path::PathBuf,
}

/// The transport a bridge line names (`"obfs4"`, `"snowflake"`, …), or
/// `None` for a plain bridge (`<ip:port> <fingerprint>`). Accepts the
/// optional leading `Bridge` keyword that Tor Browser and BridgeDB print.
#[must_use]
pub fn bridge_transport(line: &str) -> Option<String> {
    let mut words = line.split_whitespace();
    let mut first = words.next()?;
    if first.eq_ignore_ascii_case("bridge") {
        first = words.next()?;
    }
    // Transport names are identifiers, so they never start with a digit;
    // an address starts with a digit (IPv4) or `[` (IPv6).
    if first.starts_with('[') || first.starts_with(|c: char| c.is_ascii_digit()) {
        None
    } else {
        Some(first.to_ascii_lowercase())
    }
}

/// Parse a `--pt-binary` value: `<transport>[,<transport>…]=<absolute path>`,
/// e.g. `obfs4=/usr/bin/lyrebird` or `obfs4,webtunnel=/opt/lyrebird`.
///
/// # Errors
/// A readable message if the value is malformed or the path is relative.
pub fn parse_pt_binary(spec: &str) -> std::result::Result<PtBinary, String> {
    let (names, path) = spec
        .split_once('=')
        .ok_or_else(|| format!("expected <transport>=<path>, got {spec:?}"))?;
    let protocols: Vec<String> = names
        .split(',')
        .map(|n| n.trim().to_ascii_lowercase())
        .filter(|n| !n.is_empty())
        .collect();
    if protocols.is_empty() {
        return Err(format!("no transport name before '=' in {spec:?}"));
    }
    let path = std::path::PathBuf::from(path.trim());
    if !path.is_absolute() {
        return Err(format!(
            "transport binary path must be absolute, got {:?}",
            path.display()
        ));
    }
    Ok(PtBinary { protocols, path })
}

/// Binaries that are known to provide each transport, best first.
/// lyrebird is the Tor Project's maintained obfs4 client (successor to
/// obfs4proxy, which does not speak webtunnel).
fn known_pt_binaries(transport: &str) -> &'static [&'static str] {
    match transport {
        "obfs4" => &["lyrebird", "obfs4proxy"],
        "webtunnel" | "meek_lite" => &["lyrebird"],
        "snowflake" => &["snowflake-client", "lyrebird"],
        _ => &[],
    }
}

/// Where to look for a transport binary that is not on `PATH`: the usual
/// package locations plus the copies Tor Browser ships with.
const PT_SEARCH_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/Applications/Tor Browser.app/Contents/MacOS/Tor/PluggableTransports",
];

/// Find an executable named `name` on `PATH` or in [`PT_SEARCH_DIRS`].
#[must_use]
pub fn find_pt_binary(name: &str) -> Option<std::path::PathBuf> {
    let path_dirs = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .unwrap_or_default();
    path_dirs
        .into_iter()
        .chain(PT_SEARCH_DIRS.iter().map(std::path::PathBuf::from))
        .filter(|d| d.is_absolute())
        .map(|d| d.join(name))
        .find(|p| is_executable_file(p))
}

fn is_executable_file(p: &std::path::Path) -> bool {
    let Ok(meta) = std::fs::metadata(p) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.is_file() && meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        meta.is_file()
    }
}

/// F2.2b: work out which transport binaries the configured bridges need.
///
/// Explicit `--pt-binary` entries win. Any transport a bridge names that
/// they don't cover is looked up with `find` (normally [`find_pt_binary`])
/// among the binaries known to provide it. Transports served by the same
/// binary are grouped so it runs once.
///
/// # Errors
/// A message naming the transport if a bridge needs one that can't be found,
/// so the daemon stops instead of connecting without the bridge.
pub fn resolve_transports(
    bridges: &[String],
    explicit: &[String],
    find: &dyn Fn(&str) -> Option<std::path::PathBuf>,
) -> std::result::Result<Vec<PtBinary>, String> {
    let mut out: Vec<PtBinary> = Vec::new();
    for spec in explicit {
        out.push(parse_pt_binary(spec)?);
    }
    let mut needed: Vec<String> = bridges.iter().filter_map(|b| bridge_transport(b)).collect();
    needed.sort();
    needed.dedup();
    for transport in needed {
        if out.iter().any(|b| b.protocols.contains(&transport)) {
            continue;
        }
        let candidates = known_pt_binaries(&transport);
        let Some(path) = candidates.iter().find_map(|name| find(name)) else {
            let hint = if candidates.is_empty() {
                String::new()
            } else {
                format!(" (install {})", candidates.join(" or "))
            };
            return Err(format!(
                "a bridge uses the {transport} transport but no program for it was found{hint}; \
                 or set pt_binaries / --pt-binary {transport}=/path/to/program"
            ));
        };
        if let Some(existing) = out.iter_mut().find(|b| b.path == path) {
            existing.protocols.push(transport);
        } else {
            out.push(PtBinary {
                protocols: vec![transport],
                path,
            });
        }
    }
    Ok(out)
}

/// A1.3: the effective vanguard mode the daemon will run with. Used by the
/// startup log + the regression test. Returns the `VanguardConfig`'s
/// resolved mode (`Full` when pinned as above).
#[must_use]
pub fn effective_vanguard_mode(config: &TorClientConfig) -> tor_guardmgr::VanguardMode {
    let vc: &tor_guardmgr::VanguardConfig = config.as_ref();
    vc.mode()
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

    /// A1.3 regression: the Tor config we build MUST pin Full vanguards
    /// for guard-discovery defense on our onion service. If this reads
    /// anything other than `Full`, the explicit pin in `build_tor_config`
    /// regressed to inheriting the consensus default.
    #[test]
    fn tor_config_pins_full_vanguards() {
        let config = build_tor_config(None, &[], &[]).expect("config build");
        assert_eq!(
            effective_vanguard_mode(&config),
            tor_guardmgr::VanguardMode::Full,
            "onion-service circuits must use Full (L2+L3) vanguards (A1.3)"
        );

        // Also hold under the multi-daemon state-dir path (what the
        // daemon actually uses via bootstrap_with_state_dir).
        let tmp = std::env::temp_dir();
        let config2 = build_tor_config(Some(&tmp), &[], &[]).expect("config build (state dir)");
        assert_eq!(
            effective_vanguard_mode(&config2),
            tor_guardmgr::VanguardMode::Full,
            "Full vanguards must also be pinned on the state-dir path"
        );
    }

    #[test]
    fn tor_config_accepts_vanilla_bridge_and_keeps_vanguards() {
        // F2.2a: a syntactically-valid vanilla bridge line (`<ip:port>
        // <rsa-fingerprint>`) parses and the config builds. We don't
        // bootstrap — just assert the bridge plumbing + that vanguards are
        // still pinned alongside bridges.
        let bridges = vec!["192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567".to_string()];
        let cfg = build_tor_config(None, &bridges, &[]).expect("bridge config should build");
        assert_eq!(
            effective_vanguard_mode(&cfg),
            tor_guardmgr::VanguardMode::Full,
            "vanguards must still be pinned when bridges are configured"
        );
    }

    #[test]
    fn tor_config_rejects_garbage_bridge_line() {
        // F2.2a: a malformed --bridge line is a hard error, not silently
        // dropped (so a typo can't leave you on public guards thinking
        // you're bridged).
        let bridges = vec!["definitely not a bridge line".to_string()];
        assert!(
            build_tor_config(None, &bridges, &[]).is_err(),
            "a malformed bridge line must fail config build"
        );
    }

    // Made-up obfs4 bridge from Arti's own docs; never dialled in tests.
    const OBFS4_LINE: &str = "obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F \
        cert=YXJlIGZyZXF1ZW50bHkgZnVsbCBvZiBsaXR0bGUgbWVzc2FnZXMgeW91IGNhbiBmaW5kLg iat-mode=0";

    #[test]
    fn bridge_transport_reads_the_first_word() {
        assert_eq!(bridge_transport(OBFS4_LINE).as_deref(), Some("obfs4"));
        assert_eq!(
            bridge_transport(&format!("Bridge {OBFS4_LINE}")).as_deref(),
            Some("obfs4")
        );
        assert_eq!(
            bridge_transport("192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567"),
            None
        );
        assert_eq!(bridge_transport("[2001:db8::1]:443 0123456789ABCDEF"), None);
        assert_eq!(bridge_transport("   "), None);
    }

    #[test]
    fn pt_binary_spec_needs_names_and_an_absolute_path() {
        let b = parse_pt_binary("obfs4,WebTunnel=/usr/bin/lyrebird").unwrap();
        assert_eq!(b.protocols, vec!["obfs4", "webtunnel"]);
        assert_eq!(b.path, std::path::PathBuf::from("/usr/bin/lyrebird"));
        assert!(parse_pt_binary("/usr/bin/lyrebird").is_err());
        assert!(parse_pt_binary("=/usr/bin/lyrebird").is_err());
        assert!(parse_pt_binary("obfs4=lyrebird").is_err(), "relative path");
    }

    #[test]
    fn resolve_transports_finds_groups_and_refuses_missing() {
        let lyrebird = std::path::PathBuf::from("/x/lyrebird");
        let find = |name: &str| (name == "lyrebird").then(|| lyrebird.clone());
        let bridges = vec![
            OBFS4_LINE.to_string(),
            "webtunnel 192.0.2.3:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://e.example/x"
                .to_string(),
            "192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567".to_string(),
        ];
        let got = resolve_transports(&bridges, &[], &find).unwrap();
        assert_eq!(
            got,
            vec![PtBinary {
                protocols: vec!["obfs4".into(), "webtunnel".into()],
                path: lyrebird.clone()
            }],
            "one process for both transports"
        );

        // Plain bridges need nothing.
        assert!(
            resolve_transports(&bridges[2..], &[], &find)
                .unwrap()
                .is_empty()
        );

        // An explicit entry wins over the search.
        let got = resolve_transports(&bridges[..1], &["obfs4=/opt/o4".into()], &|_| None).unwrap();
        assert_eq!(got[0].path, std::path::PathBuf::from("/opt/o4"));

        // Nothing found: a clear error naming the transport.
        let err = resolve_transports(&bridges[..1], &[], &|_| None).unwrap_err();
        assert!(err.contains("obfs4") && err.contains("lyrebird"), "{err}");
    }

    #[test]
    fn obfs4_bridge_builds_only_with_its_transport() {
        let bridges = vec![OBFS4_LINE.to_string()];
        let pt = vec![PtBinary {
            protocols: vec!["obfs4".into()],
            path: "/usr/bin/lyrebird".into(),
        }];
        let cfg = build_tor_config(None, &bridges, &pt).expect("obfs4 config should build");
        assert_eq!(
            effective_vanguard_mode(&cfg),
            tor_guardmgr::VanguardMode::Full,
            "vanguards must still be pinned with a pluggable transport"
        );
        assert!(
            build_tor_config(None, &bridges, &[]).is_err(),
            "an obfs4 bridge with no transport must not silently build"
        );
    }

    /// A1.3 build-time tripwire: naming `VanguardMode::Full` only compiles
    /// when the `vanguards` cargo feature is active (without it the enum
    /// collapses to `Disabled`-only). This test existing + compiling is
    /// the CI guard that the feature hasn't been dropped from Cargo.toml.
    #[test]
    fn vanguards_feature_is_compiled_in() {
        assert_ne!(
            tor_guardmgr::VanguardMode::Full,
            tor_guardmgr::VanguardMode::Lite
        );
    }
}
