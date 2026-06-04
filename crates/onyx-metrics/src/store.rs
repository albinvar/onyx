//! Durable last-seen store for the metrics collector.
//!
//! One row per enrolled hub, keyed by its Ed25519 reporting key. Each
//! heartbeat upserts the row, so the table is always "latest known state per
//! hub" — never a time series (we deliberately keep no history, so the
//! collector itself can't be turned into a correlation oracle).

use anyhow::{Context, Result};
use onyx_core::metrics::HubHeartbeat;
use rusqlite::{Connection, params};

/// A hub's latest reported state, as shown on the status page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubRecord {
    /// Ed25519 reporting key (base32) — the enrolled identity.
    pub sig_pub_b32: String,
    /// Public X25519 hub id (base32) — matches `hubs.json`.
    pub hub_id_b32: String,
    /// Software version the hub last reported.
    pub software_version: String,
    /// Hub self-reported up (always true in practice).
    pub up: bool,
    /// Whether the hub's onion was reachable when it last reported.
    pub tor_reachable: bool,
    /// Coarse uptime label (`<1h`/`<1d`/`<1w`/`>1w`).
    pub uptime: String,
    /// Hub's self-reported coarse timestamp (unix secs, 5-min snapped).
    pub coarse_ts: u64,
    /// When the collector received this heartbeat (unix secs).
    pub received_at: u64,
}

/// SQLite-backed collector store.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (creating if needed) the collector database at `path`.
    pub fn open(path: &std::path::Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("open metrics db {}", path.display()))?;
        Self::init(conn)
    }

    /// In-memory store (tests).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS hub_status (
                sig_pub_b32      TEXT PRIMARY KEY,
                hub_id_b32       TEXT NOT NULL,
                software_version TEXT NOT NULL,
                up               INTEGER NOT NULL,
                tor_reachable    INTEGER NOT NULL,
                uptime           TEXT NOT NULL,
                coarse_ts        INTEGER NOT NULL,
                received_at      INTEGER NOT NULL
            );",
        )
        .context("create hub_status table")?;
        Ok(Self { conn })
    }

    /// Upsert the latest state for one hub.
    pub fn upsert(&self, sig_pub_b32: &str, hb: &HubHeartbeat, received_at: u64) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO hub_status
                    (sig_pub_b32, hub_id_b32, software_version, up,
                     tor_reachable, uptime, coarse_ts, received_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(sig_pub_b32) DO UPDATE SET
                    hub_id_b32       = excluded.hub_id_b32,
                    software_version = excluded.software_version,
                    up               = excluded.up,
                    tor_reachable    = excluded.tor_reachable,
                    uptime           = excluded.uptime,
                    coarse_ts        = excluded.coarse_ts,
                    received_at      = excluded.received_at",
                params![
                    sig_pub_b32,
                    hb.hub_id_b32,
                    hb.software_version,
                    i64::from(hb.up),
                    i64::from(hb.tor_reachable),
                    hb.uptime.as_str(),
                    i64::try_from(hb.coarse_ts).unwrap_or(i64::MAX),
                    i64::try_from(received_at).unwrap_or(i64::MAX),
                ],
            )
            .context("upsert hub_status")?;
        Ok(())
    }

    /// All known hubs, most-recently-seen first.
    pub fn all(&self) -> Result<Vec<HubRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT sig_pub_b32, hub_id_b32, software_version, up,
                    tor_reachable, uptime, coarse_ts, received_at
             FROM hub_status ORDER BY received_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(HubRecord {
                sig_pub_b32: r.get(0)?,
                hub_id_b32: r.get(1)?,
                software_version: r.get(2)?,
                up: r.get::<_, i64>(3)? != 0,
                tor_reachable: r.get::<_, i64>(4)? != 0,
                uptime: r.get(5)?,
                coarse_ts: u64::try_from(r.get::<_, i64>(6)?).unwrap_or(0),
                received_at: u64::try_from(r.get::<_, i64>(7)?).unwrap_or(0),
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use onyx_core::metrics::HubHeartbeat;

    #[test]
    fn upsert_then_read_roundtrips_and_overwrites() {
        let store = Store::open_in_memory().unwrap();
        let hb1 = HubHeartbeat::new("hubid", "0.1.25", true, 90_000, 1_700_000_100);
        store.upsert("sigkey", &hb1, 1_700_000_120).unwrap();

        let all = store.all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].sig_pub_b32, "sigkey");
        assert_eq!(all[0].software_version, "0.1.25");
        assert_eq!(all[0].uptime, "<1w");
        assert_eq!(all[0].received_at, 1_700_000_120);

        // A second heartbeat for the same key overwrites (no history kept).
        let hb2 = HubHeartbeat::new("hubid", "0.1.26", false, 100, 1_700_000_400);
        store.upsert("sigkey", &hb2, 1_700_000_420).unwrap();
        let all = store.all().unwrap();
        assert_eq!(all.len(), 1, "same key must not create a new row");
        assert_eq!(all[0].software_version, "0.1.26");
        assert_eq!(all[0].uptime, "<1h");
        assert!(!all[0].tor_reachable);
    }

    #[test]
    fn multiple_hubs_sorted_by_recency() {
        let store = Store::open_in_memory().unwrap();
        let hb = HubHeartbeat::new("h", "0.1.25", true, 90_000, 1_700_000_100);
        store.upsert("older", &hb, 1_000).unwrap();
        store.upsert("newer", &hb, 2_000).unwrap();
        let all = store.all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].sig_pub_b32, "newer");
        assert_eq!(all[1].sig_pub_b32, "older");
    }
}
