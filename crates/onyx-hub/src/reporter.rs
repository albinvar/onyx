//! Opt-in hub liveness reporter (metrics P2).
//!
//! When the operator passes `--metrics-report <onion[:port]>`, the hub
//! periodically sends a signed [`SignedHeartbeat`] to a central collector
//! onion service. The design is deliberately conservative:
//!
//!   * **Tor-only.** The collector is an `.onion`; we reach it via the
//!     shared [`TorRuntime`] on a *fresh isolated circuit* each time, so the
//!     hub's IP is never exposed and heartbeats aren't linkable to the hub's
//!     other circuits. There is no clearnet code path here at all.
//!   * **Liveness only.** The payload is a [`HubHeartbeat`], whose field set
//!     is the privacy contract (see `onyx_core::metrics`): no counter that
//!     tracks user activity ever leaves the hub.
//!   * **Fixed cadence.** A constant tick (not jittered) carries no signal
//!     beyond up/down, because it fires regardless of what users do.
//!   * **Fail-open.** Any send error is logged at `warn!` and dropped; the
//!     hub is never blocked or back-pressured by a slow/absent collector,
//!     and nothing is queued for retry (a missed beat just reads as a brief
//!     gap on the dashboard).
//!   * **Signed.** Each report is signed by the hub's Ed25519 key so the
//!     collector can authenticate it; the collector authorises by allowlist.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use onyx_core::crypto::SigningKey;
use onyx_core::metrics::{HubHeartbeat, SignedHeartbeat};
use onyx_core::tor::TorRuntime;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

/// Default virtual port for the metrics collector onion service.
pub const METRICS_HS_PORT: u16 = 1;

/// Hard cap on a single heartbeat frame. Heartbeats are tiny (~200 bytes);
/// this only bounds a misbehaving build so it can't blast the collector.
const MAX_FRAME_BYTES: usize = 4096;

/// Static configuration for the reporter loop.
#[derive(Clone, Debug)]
pub struct ReporterConfig {
    /// Collector onion host (without port).
    pub collector_host: String,
    /// Collector onion virtual port.
    pub collector_port: u16,
    /// Interval between heartbeats.
    pub interval: Duration,
}

/// Run the heartbeat reporter forever. Intended to be `tokio::spawn`ed.
///
/// `signing_seed` is the hub's Ed25519 secret seed (the task owns its own
/// reconstructed [`SigningKey`] so it doesn't borrow the hub identity).
/// `tor_reachable` reflects whether the hub's hidden service had an address
/// at startup — an honest "we published an HS" signal, not a live probe.
pub async fn run_heartbeat_reporter(
    tor: Arc<TorRuntime>,
    cfg: ReporterConfig,
    signing_seed: [u8; 32],
    hub_id_b32: String,
    software_version: String,
    tor_reachable: bool,
    started: Instant,
) {
    let signing = SigningKey::from_bytes(&signing_seed);
    info!(
        host = %cfg.collector_host,
        port = cfg.collector_port,
        interval_secs = cfg.interval.as_secs(),
        "metrics: heartbeat reporter started (opt-in, Tor-only, liveness-only)"
    );
    let mut ticker = tokio::time::interval(cfg.interval);
    loop {
        ticker.tick().await;
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let uptime_secs = started.elapsed().as_secs();
        let hb = HubHeartbeat::new(
            &hub_id_b32,
            &software_version,
            tor_reachable,
            uptime_secs,
            now_secs,
        );
        match SignedHeartbeat::sign(hb, &signing) {
            Ok(signed) => match send_once(&tor, &cfg, &signed).await {
                Ok(()) => info!("metrics: heartbeat sent"),
                Err(e) => warn!(error = %e, "metrics: heartbeat send failed (fail-open; dropped)"),
            },
            Err(e) => warn!(error = ?e, "metrics: heartbeat sign failed (skipping this tick)"),
        }
    }
}

/// Dial the collector on a fresh isolated circuit and push one
/// length-prefixed CBOR heartbeat. The stream is closed immediately after.
async fn send_once(
    tor: &TorRuntime,
    cfg: &ReporterConfig,
    signed: &SignedHeartbeat,
) -> anyhow::Result<()> {
    let bytes = signed.to_cbor()?;
    anyhow::ensure!(
        bytes.len() <= MAX_FRAME_BYTES,
        "heartbeat frame too large ({} bytes)",
        bytes.len()
    );
    // Fresh isolated circuit per heartbeat — unlinkable from the hub's
    // other Tor activity.
    let mut stream = tor
        .isolated()
        .dial(&cfg.collector_host, cfg.collector_port)
        .await
        .map_err(|e| anyhow::anyhow!("dial collector: {e}"))?;
    let len = u32::try_from(bytes.len()).expect("bounded by MAX_FRAME_BYTES");
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    // Best-effort close; the collector reads exactly `len` bytes anyway.
    let _ = stream.shutdown().await;
    Ok(())
}

/// Parse a `--metrics-report` value (`onion` or `onion:port`) into a
/// [`ReporterConfig`]. Mirrors the hub's `parse_host_port` convention.
pub fn parse_reporter_target(raw: &str, interval: Duration) -> anyhow::Result<ReporterConfig> {
    anyhow::ensure!(!raw.trim().is_empty(), "--metrics-report value is empty");
    let (host, port) = match raw.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .map_err(|_| anyhow::anyhow!("bad port in --metrics-report {raw:?}"))?;
            (h.to_string(), port)
        }
        None => (raw.to_string(), METRICS_HS_PORT),
    };
    anyhow::ensure!(!host.is_empty(), "--metrics-report has empty host");
    Ok(ReporterConfig {
        collector_host: host,
        collector_port: port,
        interval,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_onion_without_port() {
        let cfg = parse_reporter_target("abc.onion", Duration::from_secs(300)).unwrap();
        assert_eq!(cfg.collector_host, "abc.onion");
        assert_eq!(cfg.collector_port, METRICS_HS_PORT);
        assert_eq!(cfg.interval, Duration::from_secs(300));
    }

    #[test]
    fn parses_onion_with_port() {
        let cfg = parse_reporter_target("abc.onion:7", Duration::from_secs(60)).unwrap();
        assert_eq!(cfg.collector_host, "abc.onion");
        assert_eq!(cfg.collector_port, 7);
    }

    #[test]
    fn rejects_empty_and_bad_port() {
        assert!(parse_reporter_target("", Duration::from_secs(300)).is_err());
        assert!(parse_reporter_target("  ", Duration::from_secs(300)).is_err());
        assert!(parse_reporter_target("abc.onion:notaport", Duration::from_secs(300)).is_err());
    }
}
