//! Hub-side SQLite persistence for the two non-ephemeral state pieces:
//! the offline-envelope queues and the MLS KeyPackage directory.
//!
//! The other two pieces of [`HubState`](crate::state::HubState) —
//! `senders` (live mpsc channels) and `subscribers` (live conn-id
//! membership) — are **connection state**: they exist only as long
//! as the underlying Noise XK session exists, so they reset to
//! empty on every hub restart by construction.  Queues and KPs, by
//! contrast, *should* survive a hub restart — and before T8.0 they
//! didn't.
//!
//! ## What this defends against
//!
//! A hub restart (deploy, OOM-kill, machine reboot, SIGTERM) used to
//! be indistinguishable from a permanent hub death: every queued
//! envelope was lost, every published KeyPackage was lost. Senders
//! got no signal; recipients silently lost first-contact attempts.
//! T8.0 makes the hub durable across its own restart so the only
//! thing a restart costs is "you reconnect with backoff."
//!
//! ## What this does NOT defend against
//!
//!   * **Hub permanent death.** If the disk underneath this SQLite
//!     file is destroyed, the queue and the KP directory are gone.
//!     Multi-hub publish/subscribe (T8.1) is the answer there.
//!   * **Hub operator misbehavior.** An operator with shell access
//!     can read every encrypted-blob row and learn nothing about
//!     content (sealed envelopes are AEAD ciphertext under the
//!     recipient's hybrid KEM key) but can learn timing, counts,
//!     and routing-id traffic patterns. Same posture as before T8.0
//!     — persistence does not change the trust model, only the
//!     durability.
//!   * **Tampering with on-disk rows.** Hub-side rows are NOT
//!     AEAD-sealed (unlike the daemon's vault). The hub never had
//!     the right to read content in the first place, so there's no
//!     key it could seal under that the recipient could later
//!     unseal. End-to-end integrity is via the sealed envelope's
//!     Ed25519 signature, verified by the recipient — a hub that
//!     edits queued bytes just gets its rewrites silently dropped
//!     by `open_bootstrap`.
//!
//! ## Schema
//!
//! Two tables.  Pinned at v1; no schema_version cell (a hub state
//! DB has no other rows worth coordinating with). Additive bumps
//! later via `CREATE TABLE IF NOT EXISTS` if needed.
//!
//! ```sql
//! CREATE TABLE queue_entry (
//!     id           INTEGER PRIMARY KEY AUTOINCREMENT,
//!     routing_id   BLOB NOT NULL,   -- 16 bytes (BLAKE2b-128 of fingerprint)
//!     payload      BLOB NOT NULL,   -- full DELIVER body, ready to forward
//!     enqueued_at  INTEGER NOT NULL -- ms since epoch
//! );
//! CREATE INDEX queue_entry_routing_idx ON queue_entry(routing_id);
//!
//! CREATE TABLE keypackage (
//!     routing_id    BLOB PRIMARY KEY, -- 16 bytes
//!     kp_bytes      BLOB NOT NULL,    -- TLS-serialised MLS KeyPackage
//!     published_at  INTEGER NOT NULL  -- ms since epoch
//! );
//! ```
//!
//! Auto-incrementing `queue_entry.id` is the FIFO order. On
//! [`Store::drain_queue`] we `SELECT … ORDER BY id ASC` then
//! `DELETE` the matching rows in the same transaction.

use std::path::Path;

use anyhow::Context;
use rusqlite::{Connection, OpenFlags, params};

use crate::state::RoutingId;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS queue_entry (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  routing_id   BLOB NOT NULL,
  payload      BLOB NOT NULL,
  enqueued_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS queue_entry_routing_idx ON queue_entry(routing_id);

CREATE TABLE IF NOT EXISTS keypackage (
  routing_id    BLOB PRIMARY KEY,
  kp_bytes      BLOB NOT NULL,
  published_at  INTEGER NOT NULL
);
";

/// SQLite-backed durable store for queue + KP-directory state.
///
/// Not `Clone` and not `Sync` (the inner `Connection` isn't). The
/// hub already wraps `HubState` in an `Arc<Mutex<…>>`; the store
/// lives inside `HubState`, so the same `Mutex` serialises store
/// access too.
#[derive(Debug)]
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (or create) the store at `path`. Parent directory must
    /// already exist; the hub's `main.rs` `ensure_data_dir`s before
    /// calling this.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )
        .with_context(|| format!("opening hub store at {}", path.display()))?;
        conn.execute_batch(SCHEMA).context("applying hub schema")?;
        Ok(Self { conn })
    }

    /// In-memory store. Used by tests + by hub instances explicitly
    /// configured for ephemeral operation.
    #[allow(dead_code)] // currently only test-callers; will become
    // operator-facing when the hub gains a `--state-db memory` mode
    pub fn open_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory().context("opening hub store in memory")?;
        conn.execute_batch(SCHEMA).context("applying hub schema")?;
        Ok(Self { conn })
    }

    /// Append a payload to the queue for `routing_id`. Returns the
    /// auto-assigned row id (FIFO sequence number).
    pub fn enqueue(&self, routing_id: &RoutingId, payload: &[u8]) -> anyhow::Result<i64> {
        let now = epoch_ms();
        self.conn
            .execute(
                "INSERT INTO queue_entry (routing_id, payload, enqueued_at) VALUES (?, ?, ?)",
                params![routing_id.as_slice(), payload, now],
            )
            .context("enqueue")?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Drain (return + delete) all queued payloads for `routing_id`
    /// in FIFO order. Atomic: the SELECT and DELETE run in a single
    /// transaction so a concurrent enqueue can never be partially
    /// taken.
    pub fn drain_queue(&mut self, routing_id: &RoutingId) -> anyhow::Result<Vec<Vec<u8>>> {
        let tx = self.conn.transaction().context("begin tx for drain")?;
        let entries: Vec<Vec<u8>> = {
            let mut stmt = tx
                .prepare("SELECT payload FROM queue_entry WHERE routing_id = ? ORDER BY id ASC")
                .context("prepare drain select")?;
            let rows = stmt
                .query_map(params![routing_id.as_slice()], |r| r.get::<_, Vec<u8>>(0))
                .context("query drain rows")?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .context("collect drain rows")?
        };
        tx.execute(
            "DELETE FROM queue_entry WHERE routing_id = ?",
            params![routing_id.as_slice()],
        )
        .context("delete drained rows")?;
        tx.commit().context("commit drain tx")?;
        Ok(entries)
    }

    /// Load every queued payload (per routing id) from disk. Used
    /// once at hub startup to warm the in-memory queue cache so
    /// reads during normal operation don't touch SQLite.
    pub fn load_all_queues(&self) -> anyhow::Result<Vec<(RoutingId, Vec<Vec<u8>>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT routing_id, payload FROM queue_entry ORDER BY id ASC")
            .context("prepare load_all_queues")?;
        let rows = stmt
            .query_map([], |r| {
                let rid: Vec<u8> = r.get(0)?;
                let payload: Vec<u8> = r.get(1)?;
                Ok((rid, payload))
            })
            .context("query load_all_queues rows")?;

        // Group by routing_id while preserving FIFO order within each.
        let mut groups: Vec<(RoutingId, Vec<Vec<u8>>)> = Vec::new();
        for row in rows {
            let (rid_bytes, payload) = row.context("read load_all_queues row")?;
            let rid: RoutingId = rid_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("queue_entry.routing_id not 16 bytes"))?;
            if let Some(last) = groups.last_mut()
                && last.0 == rid
            {
                last.1.push(payload);
            } else if let Some(existing) = groups.iter_mut().find(|(r, _)| *r == rid) {
                existing.1.push(payload);
            } else {
                groups.push((rid, vec![payload]));
            }
        }
        Ok(groups)
    }

    /// UPSERT the KeyPackage for `routing_id`. The handler already
    /// validates publisher-ownership of the routing id (T7.3-sec)
    /// before calling this; the store layer trusts its caller.
    pub fn set_keypackage(&self, routing_id: &RoutingId, kp_bytes: &[u8]) -> anyhow::Result<()> {
        let now = epoch_ms();
        self.conn
            .execute(
                "INSERT INTO keypackage (routing_id, kp_bytes, published_at) \
                 VALUES (?, ?, ?) \
                 ON CONFLICT(routing_id) DO UPDATE SET \
                   kp_bytes = excluded.kp_bytes, \
                   published_at = excluded.published_at",
                params![routing_id.as_slice(), kp_bytes, now],
            )
            .context("set_keypackage")?;
        Ok(())
    }

    /// Delete every queue row older than `cutoff_unix_ms` (i.e.,
    /// rows where `enqueued_at < cutoff_unix_ms`). Returns the
    /// number of rows deleted. Idempotent — safe to call repeatedly.
    ///
    /// **Why only queue rows, not KPs.** KeyPackages are designed to
    /// be republished on every reconnect (`hub_client::SelfPublish`
    /// does it per session start). Pruning a stale KP silently would
    /// break first-contact for a peer that hasn't reconnected in a
    /// while — the recipient's `fetch_keypackage` would return
    /// not-found, and the sender would fail. Queue entries, by
    /// contrast, are one-shot offline mailbox deliveries — if a
    /// recipient hasn't been online in 30 days, the sender's first-
    /// contact attempt has already failed in every meaningful sense.
    /// Pruning the row is the right call.
    ///
    /// **What this defends against (T8.0.gc).** Unbounded queue
    /// growth. Before today, an envelope addressed to a
    /// routing-id whose owner never comes back online lived in the
    /// hub's `queue_entry` table forever. A hub running for months
    /// would eventually fill its disk. GC bounds that.
    pub fn gc_queue_entries_older_than(&self, cutoff_unix_ms: i64) -> anyhow::Result<usize> {
        let deleted = self
            .conn
            .execute(
                "DELETE FROM queue_entry WHERE enqueued_at < ?",
                params![cutoff_unix_ms],
            )
            .context("gc_queue_entries_older_than")?;
        Ok(deleted)
    }

    /// Load all stored KeyPackages. Used at hub startup to populate
    /// the in-memory KP cache; the hot fetch path then reads from
    /// memory.
    pub fn load_all_keypackages(&self) -> anyhow::Result<Vec<(RoutingId, Vec<u8>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT routing_id, kp_bytes FROM keypackage")
            .context("prepare load_all_keypackages")?;
        let rows = stmt
            .query_map([], |r| {
                let rid: Vec<u8> = r.get(0)?;
                let kp: Vec<u8> = r.get(1)?;
                Ok((rid, kp))
            })
            .context("query load_all_keypackages rows")?;
        let mut out = Vec::new();
        for row in rows {
            let (rid_bytes, kp) = row.context("read load_all_keypackages row")?;
            let rid: RoutingId = rid_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("keypackage.routing_id not 16 bytes"))?;
            out.push((rid, kp));
        }
        Ok(out)
    }
}

fn epoch_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Store {
        Store::open_memory().expect("open in-memory store")
    }

    #[test]
    fn enqueue_then_drain_round_trip() {
        let mut s = fresh();
        let rid: RoutingId = [0xAA; 16];
        s.enqueue(&rid, b"first").unwrap();
        s.enqueue(&rid, b"second").unwrap();
        s.enqueue(&rid, b"third").unwrap();

        let drained = s.drain_queue(&rid).unwrap();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0], b"first");
        assert_eq!(drained[1], b"second");
        assert_eq!(drained[2], b"third");

        // Second drain on the same id returns empty.
        let again = s.drain_queue(&rid).unwrap();
        assert!(again.is_empty());
    }

    #[test]
    fn drain_only_affects_targeted_routing_id() {
        let mut s = fresh();
        let rid_a: RoutingId = [0x01; 16];
        let rid_b: RoutingId = [0x02; 16];
        s.enqueue(&rid_a, b"for-a-1").unwrap();
        s.enqueue(&rid_b, b"for-b-1").unwrap();
        s.enqueue(&rid_a, b"for-a-2").unwrap();
        s.enqueue(&rid_b, b"for-b-2").unwrap();

        let drained_a = s.drain_queue(&rid_a).unwrap();
        assert_eq!(drained_a, vec![b"for-a-1".to_vec(), b"for-a-2".to_vec()]);

        // b's entries untouched.
        let drained_b = s.drain_queue(&rid_b).unwrap();
        assert_eq!(drained_b, vec![b"for-b-1".to_vec(), b"for-b-2".to_vec()]);
    }

    #[test]
    fn keypackage_upsert_latest_wins() {
        let s = fresh();
        let rid: RoutingId = [0xBB; 16];
        s.set_keypackage(&rid, b"v1").unwrap();
        s.set_keypackage(&rid, b"v2").unwrap();
        let all = s.load_all_keypackages().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].0, rid);
        assert_eq!(all[0].1, b"v2");
    }

    #[test]
    fn load_all_queues_groups_by_routing_id_in_fifo_order() {
        let s = fresh();
        let rid_a: RoutingId = [0x10; 16];
        let rid_b: RoutingId = [0x20; 16];
        s.enqueue(&rid_a, b"a1").unwrap();
        s.enqueue(&rid_b, b"b1").unwrap();
        s.enqueue(&rid_a, b"a2").unwrap();
        s.enqueue(&rid_b, b"b2").unwrap();
        s.enqueue(&rid_a, b"a3").unwrap();

        let groups = s.load_all_queues().unwrap();
        let mut a_payloads = Vec::new();
        let mut b_payloads = Vec::new();
        for (rid, payloads) in groups {
            if rid == rid_a {
                a_payloads = payloads;
            } else if rid == rid_b {
                b_payloads = payloads;
            }
        }
        assert_eq!(
            a_payloads,
            vec![b"a1".to_vec(), b"a2".to_vec(), b"a3".to_vec()]
        );
        assert_eq!(b_payloads, vec![b"b1".to_vec(), b"b2".to_vec()]);
    }

    #[test]
    fn schema_is_idempotent_on_existing_store() {
        // Opening twice with the same on-disk file must not error
        // (CREATE TABLE IF NOT EXISTS is the contract). Use a temp
        // file because in-memory doesn't survive `Store::open` calls.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        // Note: NamedTempFile creates the file empty; we want the
        // store to use this exact path. Drop the file handle but
        // keep the path alive via the TempDir-style pattern…
        drop(tmp);

        let s1 = Store::open(&path).unwrap();
        let rid: RoutingId = [0x33; 16];
        s1.set_keypackage(&rid, b"hello").unwrap();
        drop(s1);

        // Reopen — schema apply must be a no-op, and the data must
        // still be present.
        let s2 = Store::open(&path).unwrap();
        let all = s2.load_all_keypackages().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].1, b"hello");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn survives_close_and_reopen() {
        // The real headline durability test: write, close, reopen,
        // read back the same bytes. Models hub restart.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp);

        {
            let s = Store::open(&path).unwrap();
            s.enqueue(&[0xCA; 16], b"queued before restart").unwrap();
            s.set_keypackage(&[0xCB; 16], b"kp before restart").unwrap();
        }

        let mut s = Store::open(&path).unwrap();
        let kps = s.load_all_keypackages().unwrap();
        assert_eq!(kps, vec![([0xCB; 16], b"kp before restart".to_vec())]);
        let drained = s.drain_queue(&[0xCA; 16]).unwrap();
        assert_eq!(drained, vec![b"queued before restart".to_vec()]);

        std::fs::remove_file(&path).ok();
    }

    // ── T8.0.gc: queue garbage collection ─────────────────────────────

    #[test]
    fn gc_deletes_old_rows_only() {
        // Three queue entries; we'll hand-set their enqueued_at via
        // direct SQL so the test doesn't depend on wall-clock timing.
        let s = fresh();
        let rid: RoutingId = [0xA0; 16];
        s.enqueue(&rid, b"old-1").unwrap();
        s.enqueue(&rid, b"old-2").unwrap();
        s.enqueue(&rid, b"recent").unwrap();

        // Backdate the first two rows to 100 days ago.
        let now = epoch_ms();
        let old_ts = now - 100 * 24 * 60 * 60 * 1000;
        s.conn
            .execute(
                "UPDATE queue_entry SET enqueued_at = ? \
                 WHERE payload IN (?, ?)",
                params![old_ts, b"old-1", b"old-2"],
            )
            .unwrap();

        // GC anything older than 30 days.
        let cutoff = now - 30 * 24 * 60 * 60 * 1000;
        let deleted = s.gc_queue_entries_older_than(cutoff).unwrap();
        assert_eq!(deleted, 2, "two backdated rows were GC'd");

        // The "recent" entry survives.
        let mut s_mut = s;
        let remaining = s_mut.drain_queue(&rid).unwrap();
        assert_eq!(remaining, vec![b"recent".to_vec()]);
    }

    #[test]
    fn gc_with_far_future_cutoff_deletes_everything() {
        // Sanity: cutoff in the year 9999 → every row in the future
        // (which is none of them — they're all in the past) → wait,
        // that's the opposite. Cutoff in the FUTURE means "anything
        // older than the future" which is everything. Test that.
        let s = fresh();
        let rid: RoutingId = [0xB0; 16];
        s.enqueue(&rid, b"a").unwrap();
        s.enqueue(&rid, b"b").unwrap();

        let far_future = epoch_ms() + 1_000_000_000;
        let deleted = s.gc_queue_entries_older_than(far_future).unwrap();
        assert_eq!(deleted, 2);
    }

    #[test]
    fn gc_with_far_past_cutoff_deletes_nothing() {
        let s = fresh();
        let rid: RoutingId = [0xC0; 16];
        s.enqueue(&rid, b"x").unwrap();

        let far_past = 0i64;
        let deleted = s.gc_queue_entries_older_than(far_past).unwrap();
        assert_eq!(deleted, 0, "nothing older than the epoch");
    }

    #[test]
    fn gc_does_not_touch_keypackages() {
        // GC is queue-only by design (see rustdoc). Verify the KP
        // table is untouched even when we GC with a future cutoff.
        let s = fresh();
        let rid: RoutingId = [0xD0; 16];
        s.set_keypackage(&rid, b"kp-bytes").unwrap();
        s.enqueue(&rid, b"some-queued-payload").unwrap();

        let far_future = epoch_ms() + 1_000_000_000;
        let deleted = s.gc_queue_entries_older_than(far_future).unwrap();
        assert_eq!(deleted, 1, "the queue row was GC'd");

        // KP still there.
        let kps = s.load_all_keypackages().unwrap();
        assert_eq!(kps.len(), 1);
        assert_eq!(kps[0].1, b"kp-bytes");
    }
}
