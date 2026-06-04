//! `onyx-metrics` — the central liveness collector.
//!
//! Receives signed, **liveness-only** [`SignedHeartbeat`]s from enrolled
//! Onyx hubs over a Tor hidden service, and serves a plain status page on
//! localhost. It deliberately keeps no time series and no user data — only
//! the latest state per hub (see [`store`]). What a hub may report is
//! constrained by `onyx_core::metrics`; this collector only authenticates,
//! authorises, and displays it.
//!
//! ## Trust model
//!
//!   * **Inbound over Tor only.** Heartbeats arrive on the collector's
//!     `.onion`; hubs dial it, so hub IPs are never exposed to the collector.
//!   * **Authenticated.** Every report carries an Ed25519 signature; an
//!     invalid signature is dropped ([`SignedHeartbeat::verify`]).
//!   * **Authorised by allowlist.** Only reports whose signing key appears in
//!     the operator's `--allowlist` file are stored; unknown keys are logged
//!     (so the operator can enrol them) and dropped. This stops anyone who
//!     learns the collector onion from polluting it with fake hubs.
//!   * **Dashboard is localhost-only by default.** The status page binds to
//!     `127.0.0.1`; view it directly or over an SSH tunnel. Binding it
//!     publicly is the operator's explicit choice (and loudly warned).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use futures::StreamExt;
use onyx_core::metrics::SignedHeartbeat;
use onyx_core::tor::TorRuntime;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

mod store;
use store::{HubRecord, Store};

/// Virtual port the collector hidden service listens on. Hubs dial
/// `--metrics-report <collector-onion>` which defaults to this port.
const HS_PORT: u16 = 1;
/// HS nickname for the Arti keystore.
const HS_NICKNAME: &str = "onyx-metrics";
/// Hard cap on an inbound heartbeat frame (matches the reporter side).
const MAX_FRAME_BYTES: u32 = 4096;
/// Reject heartbeats whose self-reported timestamp is older than this — a
/// dead hub's captured beat must not keep it looking alive (replay guard).
const MAX_REPORT_AGE_SECS: u64 = 3600;
/// Tolerated clock skew for a heartbeat timestamp in the future.
const MAX_SKEW_SECS: u64 = 600;

#[derive(Parser, Debug)]
#[command(
    name = "onyx-metrics",
    version = onyx_core::VERSION,
    about = "Onyx metrics collector — signed liveness-only hub heartbeats over Tor"
)]
struct Args {
    /// Path to the collector's SQLite database (latest state per hub).
    #[arg(long, env = "ONYX_METRICS_DB", default_value = "./onyx-metrics.db")]
    db: String,

    /// Path to the enrollment allowlist (JSON: `{ "hubs": [ { "name": …,
    /// "sig_pub_b32": … } ] }`). Only hubs whose Ed25519 reporting key is
    /// listed here are accepted.
    #[arg(long, env = "ONYX_METRICS_ALLOWLIST")]
    allowlist: String,

    /// Address for the localhost status page. Keep it on 127.0.0.1 and reach
    /// it over an SSH tunnel; a non-loopback bind is loudly warned.
    #[arg(long, env = "ONYX_METRICS_HTTP", default_value = "127.0.0.1:9876")]
    http_listen: String,

    /// A hub with no heartbeat newer than this many seconds is shown as
    /// "stale" on the status page. Default 900 s (3× the 5-min cadence).
    #[arg(long, env = "ONYX_METRICS_STALE_AFTER_SECS", default_value_t = 900)]
    stale_after_secs: u64,

    /// Custom Tor state directory (Arti keystore + cache).
    #[arg(long, env = "ONYX_METRICS_TOR_STATE_DIR")]
    tor_state_dir: Option<std::path::PathBuf>,

    /// Public status-site output directory. When set, the collector
    /// periodically writes a static `status.json` + `index.html` here
    /// (atomically). Point any web server or an onion service at this
    /// directory to publish a Tor-Metrics-style fleet status page. The
    /// published data is LIVENESS-ONLY — the same safe fields as the local
    /// status page — so it is fine to expose publicly.
    #[arg(long, env = "ONYX_METRICS_PUBLISH_DIR")]
    publish_dir: Option<std::path::PathBuf>,

    /// How often (seconds) to regenerate the published status files.
    #[arg(long, env = "ONYX_METRICS_PUBLISH_INTERVAL_SECS", default_value_t = 60)]
    publish_interval_secs: u64,
}

/// Allowlist file shape.
#[derive(Debug, Deserialize)]
struct Allowlist {
    hubs: Vec<AllowedHub>,
}

#[derive(Debug, Deserialize)]
struct AllowedHub {
    name: String,
    sig_pub_b32: String,
}

/// Load the allowlist into a `sig_pub_b32 -> friendly name` map.
fn load_allowlist(path: &std::path::Path) -> Result<HashMap<String, String>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading allowlist {}", path.display()))?;
    let parsed: Allowlist = serde_json::from_str(&raw)
        .with_context(|| format!("parsing allowlist {}", path.display()))?;
    Ok(parsed
        .hubs
        .into_iter()
        .map(|h| (h.sig_pub_b32, h.name))
        .collect())
}

/// The outcome of classifying an inbound heartbeat.
#[derive(Debug, PartialEq, Eq)]
enum Ingest {
    /// Valid signature + enrolled key + fresh timestamp.
    Accept,
    /// Signature did not verify.
    BadSignature,
    /// Signing key is not in the allowlist.
    NotEnrolled,
    /// Self-reported timestamp is too old or implausibly future.
    Stale,
}

/// Decide what to do with a parsed heartbeat. Pure, so it is unit-tested.
fn classify(signed: &SignedHeartbeat, allow: &HashMap<String, String>, now: u64) -> Ingest {
    if signed.verify().is_err() {
        return Ingest::BadSignature;
    }
    if !allow.contains_key(&signed.hub_sig_pub_b32) {
        return Ingest::NotEnrolled;
    }
    let ts = signed.heartbeat.coarse_ts;
    if ts + MAX_REPORT_AGE_SECS < now || ts > now.saturating_add(MAX_SKEW_SECS) {
        return Ingest::Stale;
    }
    Ingest::Accept
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let allow = load_allowlist(std::path::Path::new(&args.allowlist))?;
    info!(
        enrolled = allow.len(),
        "metrics collector: allowlist loaded"
    );

    let store = Arc::new(Mutex::new(
        Store::open(std::path::Path::new(&args.db)).context("opening collector store")?,
    ));

    // Localhost status page.
    if !args.http_listen.starts_with("127.0.0.1:") && !args.http_listen.starts_with("[::1]:") {
        warn!(
            addr = %args.http_listen,
            "status page is NOT bound to loopback — anyone who can reach this \
             address can read your fleet status. Prefer 127.0.0.1 + an SSH tunnel."
        );
    }
    let http = TcpListener::bind(&args.http_listen)
        .await
        .with_context(|| format!("binding status page on {}", args.http_listen))?;
    info!(addr = %args.http_listen, "status page listening");
    {
        let store = store.clone();
        let stale_after = args.stale_after_secs;
        tokio::spawn(async move { run_http(http, store, stale_after).await });
    }

    // P5: optional static public status-site publisher. Writes liveness-only
    // status.json + index.html atomically into --publish-dir so any web
    // server / onion can serve a public fleet status page.
    if let Some(dir) = args.publish_dir.clone() {
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating publish dir {}", dir.display()))?;
        let store = store.clone();
        let stale_after = args.stale_after_secs;
        let interval = std::time::Duration::from_secs(args.publish_interval_secs.max(5));
        info!(dir = %dir.display(), interval_secs = interval.as_secs(), "public status-site publisher enabled (liveness-only)");
        tokio::spawn(async move { run_publisher(&dir, &store, stale_after, interval).await });
    }

    // Tor hidden service for inbound heartbeats.
    let tor = if let Some(dir) = args.tor_state_dir.as_deref() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating tor state dir {}", dir.display()))?;
        info!(state_dir = %dir.display(), "bootstrapping Tor…");
        TorRuntime::bootstrap_with_state_dir(dir)
            .await
            .map_err(|e| anyhow::anyhow!("tor bootstrap failed: {e}"))?
    } else {
        info!("bootstrapping Tor (default state dir; cold cache may take 30-60s)…");
        TorRuntime::bootstrap()
            .await
            .map_err(|e| anyhow::anyhow!("tor bootstrap failed: {e}"))?
    };
    info!("Tor bootstrap complete");

    let mut hs = tor
        .publish_hidden_service(HS_NICKNAME)
        .map_err(|e| anyhow::anyhow!("hidden service publish failed: {e}"))?;
    if let Some(addr) = hs.onion_address() {
        info!(
            onion = %addr,
            port = HS_PORT,
            "collector hidden service published — point hubs at this with --metrics-report"
        );
    } else {
        warn!("collector HS has no address yet — Arti will produce one shortly");
    }
    let mut accept = hs
        .take_accept_streams()
        .context("HS accept-stream already taken")?;

    let allow = Arc::new(allow);
    info!("onyx-metrics running. Ctrl-C to stop.");
    let accept_loop = async {
        while let Some(stream) = accept.next().await {
            let store = store.clone();
            let allow = allow.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_ingest(stream, &store, &allow).await {
                    warn!(error = %e, "metrics ingest connection failed");
                }
            });
        }
        info!("collector accept stream ended");
    };

    tokio::select! {
        () = accept_loop => {},
        r = tokio::signal::ctrl_c() => {
            if let Err(e) = r { error!(error = %e, "ctrl-c wait failed"); }
            info!("shutdown requested");
        }
    }
    Ok(())
}

/// Read one length-prefixed CBOR heartbeat from `stream`, classify it, and
/// (if accepted) upsert it. One heartbeat per connection.
async fn handle_ingest<S>(
    mut stream: S,
    store: &Arc<Mutex<Store>>,
    allow: &HashMap<String, String>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    // Bound the whole exchange so a stuck peer can't pin a task forever.
    let signed = tokio::time::timeout(std::time::Duration::from_secs(30), read_frame(&mut stream))
        .await
        .context("ingest read timed out")??;

    let now = now_secs();
    match classify(&signed, allow, now) {
        Ingest::Accept => {
            let name = allow
                .get(&signed.hub_sig_pub_b32)
                .cloned()
                .unwrap_or_default();
            {
                let store = store.lock().expect("store mutex poisoned");
                store.upsert(&signed.hub_sig_pub_b32, &signed.heartbeat, now)?;
            }
            info!(
                hub = %name,
                version = %signed.heartbeat.software_version,
                reachable = signed.heartbeat.tor_reachable,
                uptime = signed.heartbeat.uptime.as_str(),
                "metrics: accepted heartbeat"
            );
        }
        Ingest::BadSignature => warn!("metrics: dropped heartbeat with bad signature"),
        Ingest::NotEnrolled => warn!(
            key = %signed.hub_sig_pub_b32,
            "metrics: dropped heartbeat from un-enrolled key (add it to --allowlist to accept)"
        ),
        Ingest::Stale => warn!(
            ts = signed.heartbeat.coarse_ts,
            "metrics: dropped stale/future heartbeat"
        ),
    }
    Ok(())
}

/// Read a `u32` length prefix (≤ [`MAX_FRAME_BYTES`]) then that many CBOR
/// bytes, and decode a [`SignedHeartbeat`].
async fn read_frame<S>(stream: &mut S) -> Result<SignedHeartbeat>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    anyhow::ensure!(
        len <= MAX_FRAME_BYTES,
        "heartbeat frame too large ({len} bytes)"
    );
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    SignedHeartbeat::from_cbor(&buf).map_err(|e| anyhow::anyhow!("decode heartbeat: {e:?}"))
}

// ── status page ──────────────────────────────────────────────────────────

async fn run_http(listener: TcpListener, store: Arc<Mutex<Store>>, stale_after: u64) {
    loop {
        match listener.accept().await {
            Ok((sock, _)) => {
                let store = store.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_http(sock, &store, stale_after).await {
                        warn!(error = %e, "status-page request failed");
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "status-page accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
    }
}

async fn handle_http(
    mut sock: tokio::net::TcpStream,
    store: &Arc<Mutex<Store>>,
    stale_after: u64,
) -> Result<()> {
    let mut buf = [0u8; 1024];
    let n = sock.read(&mut buf).await?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req.split_whitespace().nth(1).unwrap_or("/");

    let records = {
        let store = store.lock().expect("store mutex poisoned");
        store.all().unwrap_or_default()
    };
    let now = now_secs();

    let (status, ctype, body) = match path {
        "/json" => (
            "200 OK",
            "application/json",
            render_json(&records, now, stale_after),
        ),
        "/" => (
            "200 OK",
            "text/html; charset=utf-8",
            render_html(&records, now, stale_after),
        ),
        _ => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found".to_string(),
        ),
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(resp.as_bytes()).await?;
    sock.flush().await?;
    Ok(())
}

// ── public static status-site publisher (P5) ───────────────────────────────

/// Periodically render the liveness-only status page + JSON and write them
/// atomically into `dir`, so a plain web server or an onion can serve a
/// public fleet-status site without ever touching the live store or ingest.
async fn run_publisher(
    dir: &std::path::Path,
    store: &Arc<Mutex<Store>>,
    stale_after: u64,
    interval: std::time::Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        let records = {
            let store = store.lock().expect("store mutex poisoned");
            store.all().unwrap_or_default()
        };
        let now = now_secs();
        let html = render_html(&records, now, stale_after);
        let json = render_json(&records, now, stale_after);
        if let Err(e) = publish_files(dir, &html, &json) {
            warn!(error = %e, "status-site publish failed (will retry next tick)");
        }
    }
}

/// Write `index.html` + `status.json` into `dir`, each atomically.
fn publish_files(dir: &std::path::Path, html: &str, json: &str) -> std::io::Result<()> {
    atomic_write(&dir.join("index.html"), html.as_bytes())?;
    atomic_write(&dir.join("status.json"), json.as_bytes())?;
    Ok(())
}

/// Atomically replace `path`: write a sibling temp file then rename over it
/// (rename is atomic within a filesystem), so a web server never serves a
/// half-written page.
fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// True if the hub's last heartbeat is within the freshness window.
fn is_fresh(rec: &HubRecord, now: u64, stale_after: u64) -> bool {
    now.saturating_sub(rec.received_at) <= stale_after
}

fn render_json(records: &[HubRecord], now: u64, stale_after: u64) -> String {
    let items: Vec<serde_json::Value> = records
        .iter()
        .map(|r| {
            serde_json::json!({
                "name_key": r.sig_pub_b32,
                "hub_id_b32": r.hub_id_b32,
                "version": r.software_version,
                "up": r.up,
                "tor_reachable": r.tor_reachable,
                "uptime": r.uptime,
                "fresh": is_fresh(r, now, stale_after),
                "last_seen_secs_ago": now.saturating_sub(r.received_at),
            })
        })
        .collect();
    serde_json::json!({ "now": now, "stale_after_secs": stale_after, "hubs": items }).to_string()
}

fn render_html(records: &[HubRecord], now: u64, stale_after: u64) -> String {
    use std::fmt::Write as _;
    let mut rows = String::new();
    if records.is_empty() {
        rows.push_str("<tr><td colspan=\"6\">no heartbeats received yet</td></tr>");
    }
    for r in records {
        let fresh = is_fresh(r, now, stale_after);
        let state = if fresh { "● up" } else { "○ stale" };
        let color = if fresh { "#3fb950" } else { "#f85149" };
        let reach = if r.tor_reachable { "yes" } else { "no" };
        let ago = now.saturating_sub(r.received_at);
        let hub_id = html_escape(&r.hub_id_b32);
        let version = html_escape(&r.software_version);
        let uptime = html_escape(&r.uptime);
        // write! to a String is infallible; ignore the Result.
        let _ = write!(
            rows,
            "<tr><td style=\"color:{color}\">{state}</td><td>{hub_id}</td><td>{version}</td><td>{uptime}</td><td>{reach}</td><td>{ago}s ago</td></tr>",
        );
    }
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta http-equiv=\"refresh\" content=\"30\">\
         <title>Onyx hub status</title>\
         <style>body{{background:#0d1117;color:#c9d1d9;font-family:ui-monospace,monospace;padding:2rem}}\
         h1{{font-size:1.1rem}}table{{border-collapse:collapse;width:100%}}\
         th,td{{text-align:left;padding:.4rem .8rem;border-bottom:1px solid #21262d;font-size:.9rem}}\
         th{{color:#8b949e}}small{{color:#8b949e}}</style></head><body>\
         <h1>◆ Onyx hub fleet — liveness</h1>\
         <table><tr><th>state</th><th>hub id</th><th>version</th><th>uptime</th><th>tor</th><th>last seen</th></tr>\
         {rows}</table>\
         <p><small>{} hub(s) · refreshes every 30s · stale after {stale_after}s · liveness only, no user data · <a style=\"color:#58a6ff\" href=\"/json\">/json</a></small></p>\
         </body></html>",
        records.len(),
    )
}

/// Minimal HTML escaping for the few string fields we render.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use onyx_core::crypto::SigningKey;
    use onyx_core::metrics::HubHeartbeat;

    fn signed_now(now: u64) -> (SigningKey, SignedHeartbeat) {
        let sk = SigningKey::generate();
        let hb = HubHeartbeat::new("hubid", "0.1.25", true, 90_000, now);
        let signed = SignedHeartbeat::sign(hb, &sk).unwrap();
        (sk, signed)
    }

    fn allow_of(signed: &SignedHeartbeat) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert(signed.hub_sig_pub_b32.clone(), "piko".to_string());
        m
    }

    #[test]
    fn classify_accepts_enrolled_valid_fresh() {
        let now = 1_700_000_100;
        let (_sk, signed) = signed_now(now);
        assert_eq!(classify(&signed, &allow_of(&signed), now), Ingest::Accept);
    }

    #[test]
    fn classify_rejects_unenrolled() {
        let now = 1_700_000_100;
        let (_sk, signed) = signed_now(now);
        let empty = HashMap::new();
        assert_eq!(classify(&signed, &empty, now), Ingest::NotEnrolled);
    }

    #[test]
    fn classify_rejects_bad_signature() {
        let now = 1_700_000_100;
        let (_sk, mut signed) = signed_now(now);
        signed.heartbeat.tor_reachable = false; // invalidate signature
        assert_eq!(
            classify(&signed, &allow_of(&signed), now),
            Ingest::BadSignature
        );
    }

    #[test]
    fn classify_rejects_stale_and_future() {
        let (_sk, signed) = signed_now(1_700_000_100);
        let allow = allow_of(&signed);
        // far future "now" → heartbeat is too old.
        assert_eq!(
            classify(&signed, &allow, 1_700_000_100 + 99_999),
            Ingest::Stale
        );
        // far past "now" → heartbeat is implausibly in the future.
        assert_eq!(
            classify(&signed, &allow, 1_700_000_100 - 99_999),
            Ingest::Stale
        );
    }

    #[test]
    fn allowlist_parses() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("allow.json");
        std::fs::write(
            &p,
            r#"{ "hubs": [ { "name": "piko", "sig_pub_b32": "abc" },
                          { "name": "pi", "sig_pub_b32": "def" } ] }"#,
        )
        .unwrap();
        let m = load_allowlist(&p).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m.get("abc").map(String::as_str), Some("piko"));
    }

    #[test]
    fn html_and_json_render_records() {
        let rec = HubRecord {
            sig_pub_b32: "sig".into(),
            hub_id_b32: "7xseki3".into(),
            software_version: "0.1.25".into(),
            up: true,
            tor_reachable: true,
            uptime: "<1w".into(),
            coarse_ts: 1_700_000_100,
            received_at: 1_700_000_100,
        };
        let html = render_html(std::slice::from_ref(&rec), 1_700_000_110, 900);
        assert!(html.contains("7xseki3"));
        assert!(html.contains("0.1.25"));
        assert!(html.contains("up"));
        let json = render_json(&[rec], 1_700_000_110, 900);
        assert!(json.contains("\"version\":\"0.1.25\""));
        assert!(json.contains("\"fresh\":true"));
    }

    #[test]
    fn freshness_window() {
        let rec = HubRecord {
            sig_pub_b32: "s".into(),
            hub_id_b32: "h".into(),
            software_version: "v".into(),
            up: true,
            tor_reachable: true,
            uptime: "<1h".into(),
            coarse_ts: 0,
            received_at: 1_000,
        };
        assert!(is_fresh(&rec, 1_500, 900));
        assert!(!is_fresh(&rec, 2_500, 900));
    }

    #[test]
    fn html_escapes_fields() {
        assert_eq!(html_escape("a<b>&\"c"), "a&lt;b&gt;&amp;&quot;c");
    }

    #[test]
    fn publish_writes_both_files_atomically() {
        let dir = tempfile::tempdir().unwrap();
        publish_files(dir.path(), "<html>hi</html>", "{\"ok\":true}").unwrap();
        let html = std::fs::read_to_string(dir.path().join("index.html")).unwrap();
        let json = std::fs::read_to_string(dir.path().join("status.json")).unwrap();
        assert_eq!(html, "<html>hi</html>");
        assert_eq!(json, "{\"ok\":true}");
        // No temp files left behind.
        assert!(!dir.path().join("index.tmp").exists());
        assert!(!dir.path().join("status.tmp").exists());
        // A second publish overwrites cleanly.
        publish_files(dir.path(), "<html>2</html>", "{}").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("index.html")).unwrap(),
            "<html>2</html>"
        );
    }
}
