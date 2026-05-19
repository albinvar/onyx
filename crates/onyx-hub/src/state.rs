//! In-memory hub state: subscribers + offline queues.
//!
//! Wrapped in `Arc<tokio::sync::Mutex<HubState>>` by the binary so the
//! per-connection handlers can mutate it consistently. Lock granularity
//! is currently "the whole hub" — fine for v0 with single-digit
//! concurrent connections; future work would shard by routing-id
//! prefix or use a concurrent map.
//!
//! ## What lives here
//!
//!   * `senders` — for each open client connection, an mpsc sender
//!     that the connection's handler reads from and writes out to the
//!     wire. The handler **registers** itself at start and
//!     **unregisters** on disconnect.
//!   * `subscribers` — routing-id → set of connection-ids that want
//!     live delivery of frames addressed to that id.
//!   * `queues` — routing-id → list of payloads pending delivery
//!     (queued when nobody was subscribed). Drained when a new
//!     subscriber registers for that routing id.

use std::collections::{HashMap, HashSet};

use tokio::sync::mpsc;
use tracing::warn;

use crate::store::Store;

/// Routing identifier — 16 bytes from `BLAKE2b-128` per DESIGN §5.5.
pub type RoutingId = [u8; 16];

/// Unique-per-process connection identifier. The hub assigns these
/// monotonically as connections register; they're meaningless outside
/// the running process.
pub type ConnId = u64;

/// Per-connection mailbox size. Bounded so a slow client can't make
/// the hub buffer unbounded data on their behalf.
pub const PER_CONN_MAILBOX: usize = 64;

/// All the mutable state the hub keeps.
///
/// **Persistence (T8.0):** `queues` and `keypackages` are write-through-
/// cached against the optional [`Store`] (`durable_store`).  On
/// construction via [`Self::with_store`], the in-memory caches are
/// warmed from the store so reads stay fast.  Mutations (`deliver`'s
/// queue path, `subscribe`'s drain path, `publish_keypackage`) write
/// through to the store immediately; a failed write logs at `warn!`
/// and continues — the in-memory state remains consistent, only
/// durability is lost for that one operation. `senders` and
/// `subscribers` are NOT persisted (they're per-connection state
/// that reset by definition on restart).
///
/// In-memory-only `Self::new()` is preserved for tests and for
/// operators who explicitly want ephemeral hub semantics.
#[derive(Debug, Default)]
pub struct HubState {
    next_conn_id: ConnId,
    senders: HashMap<ConnId, mpsc::Sender<Vec<u8>>>,
    subscribers: HashMap<RoutingId, HashSet<ConnId>>,
    queues: HashMap<RoutingId, Vec<Vec<u8>>>,
    /// MLS KeyPackage directory. Maps a routing id (typically the
    /// publisher's introduction-inbox id) to the latest KeyPackage
    /// bytes they've published. Latest-wins: each `publish_keypackage`
    /// overwrites the previous entry for that routing id.
    ///
    /// **Security note**: as of T7.3-sec, the hub *does* validate
    /// publisher ownership in `handler.rs::FRAME_KP_PUBLISH` before
    /// calling [`Self::publish_keypackage`] — see THREAT_MODEL §8.2 #15.
    keypackages: HashMap<RoutingId, Vec<u8>>,
    /// Optional SQLite-backed durable store (T8.0). `None` means the
    /// hub is running ephemeral — fine for tests and short-lived
    /// dev runs. Production uses `Self::with_store`.
    durable_store: Option<Store>,
}

impl HubState {
    /// In-memory-only state. Hub data does not survive a restart of
    /// the hub process. Preserved for tests and dev runs; production
    /// hubs should use [`Self::with_store`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// State backed by the given SQLite store. On construct, loads
    /// every queued envelope and every published KeyPackage from the
    /// store into the in-memory caches so the hot path stays
    /// in-memory. Subsequent mutations write through to the store.
    pub fn with_store(store: Store) -> anyhow::Result<Self> {
        let mut me = Self::default();
        // Warm the KP cache.
        for (rid, kp) in store.load_all_keypackages()? {
            me.keypackages.insert(rid, kp);
        }
        // Warm the queue cache.
        for (rid, payloads) in store.load_all_queues()? {
            me.queues.insert(rid, payloads);
        }
        me.durable_store = Some(store);
        Ok(me)
    }

    /// Register a fresh connection. Returns the [`ConnId`] the
    /// caller must use for [`Self::subscribe`] and
    /// [`Self::unregister_conn`].
    pub fn register_conn(&mut self, sender: mpsc::Sender<Vec<u8>>) -> ConnId {
        let id = self.next_conn_id;
        self.next_conn_id += 1;
        self.senders.insert(id, sender);
        id
    }

    /// Subscribe `conn` to the given routing ids and return any
    /// previously-queued payloads for those ids (so the caller can
    /// immediately flush them to the wire).
    ///
    /// When backed by a durable store (T8.0), the drained rows are
    /// also deleted from disk in the same logical step so a hub
    /// crash between "subscriber takes ownership" and "subscriber
    /// processes the bytes" never results in a duplicate delivery.
    /// (The recipient's `EnvelopeReplayGuard` would dedup such a
    /// duplicate anyway, so this is belt-and-braces.)
    pub fn subscribe(&mut self, conn: ConnId, ids: &[RoutingId]) -> Vec<Vec<u8>> {
        let mut drained = Vec::new();
        for id in ids {
            self.subscribers.entry(*id).or_default().insert(conn);
            if let Some(q) = self.queues.remove(id) {
                drained.extend(q);
                if let Some(store) = &mut self.durable_store {
                    // Best-effort: if the disk write fails, the
                    // in-memory drain still happened and the
                    // subscriber will still receive the bytes; we
                    // just leave the on-disk rows present and they
                    // re-warm into the cache on next hub restart
                    // (causing a one-time duplicate the recipient's
                    // replay guard then drops).
                    if let Err(e) = store.drain_queue(id) {
                        warn!(error = %e, "hub store: drain_queue failed");
                    }
                }
            }
        }
        drained
    }

    /// Deliver `payload` to the given routing id. If any connections
    /// are subscribed, push to each of their channels. If none — or
    /// if every subscribed sender is full/closed — drop the payload
    /// into the offline queue.
    ///
    /// Returns the number of subscribers it was live-delivered to.
    pub fn deliver(&mut self, target: RoutingId, payload: Vec<u8>) -> usize {
        let subs = match self.subscribers.get(&target) {
            Some(s) if !s.is_empty() => s.clone(),
            _ => {
                self.enqueue_durable(target, &payload);
                self.queues.entry(target).or_default().push(payload);
                return 0;
            }
        };

        // Try to send to each subscriber. If a sender is closed/full
        // we silently drop for this attempt — the connection's
        // unregister_conn will clean up properly when it tears down.
        let mut delivered = 0;
        for conn in &subs {
            if let Some(tx) = self.senders.get(conn) {
                if tx.try_send(payload.clone()).is_ok() {
                    delivered += 1;
                }
            }
        }

        // If nobody could actually accept the delivery (everyone was
        // full or closed), queue it instead. This keeps the
        // promise that a slow client doesn't lose messages.
        if delivered == 0 {
            self.enqueue_durable(target, &payload);
            self.queues.entry(target).or_default().push(payload);
        }
        delivered
    }

    /// Best-effort write-through enqueue to the durable store, if
    /// one is attached.  Failure logs `warn!` and continues — the
    /// in-memory queue still holds the payload, only durability is
    /// lost for this one entry.
    fn enqueue_durable(&mut self, target: RoutingId, payload: &[u8]) {
        if let Some(store) = &self.durable_store {
            if let Err(e) = store.enqueue(&target, payload) {
                warn!(error = %e, "hub store: enqueue failed (in-memory queue still consistent)");
            }
        }
    }

    /// Remove a connection and all its subscriptions.
    pub fn unregister_conn(&mut self, conn: ConnId) {
        self.senders.remove(&conn);
        for subs in self.subscribers.values_mut() {
            subs.remove(&conn);
        }
        // Reclaim empty-set entries so subscribers doesn't grow without bound.
        self.subscribers.retain(|_, subs| !subs.is_empty());
    }

    // ── KeyPackage directory (T6.1) ────────────────────────────────────────

    /// Store (or replace) the KeyPackage published at `routing_id`.
    /// Latest-wins. Publisher-ownership is verified in `handler.rs`
    /// (T7.3-sec) BEFORE this call — `state.rs` trusts its caller.
    ///
    /// Write-through to the durable store (T8.0) if attached. A
    /// failed disk write logs `warn!` and continues; the in-memory
    /// cache stays consistent.
    pub fn publish_keypackage(&mut self, routing_id: RoutingId, bytes: Vec<u8>) {
        if let Some(store) = &self.durable_store {
            if let Err(e) = store.set_keypackage(&routing_id, &bytes) {
                warn!(error = %e, "hub store: set_keypackage failed (in-memory cache still consistent)");
            }
        }
        self.keypackages.insert(routing_id, bytes);
    }

    /// Return the most recent KeyPackage stored at `routing_id`, or
    /// `None` if nothing has ever been published there.
    #[must_use]
    pub fn fetch_keypackage(&self, routing_id: &RoutingId) -> Option<Vec<u8>> {
        self.keypackages.get(routing_id).cloned()
    }

    /// Diagnostic: number of routing ids that currently hold a
    /// published KeyPackage. Used by tests + future status reporting.
    #[allow(dead_code)]
    pub fn keypackage_count(&self) -> usize {
        self.keypackages.len()
    }

    // ── Diagnostics (used by tests today; the binary's status
    //    logging will pick them up once we add a periodic report) ──

    #[allow(dead_code)]
    pub fn subscriber_count(&self, id: &RoutingId) -> usize {
        self.subscribers.get(id).map_or(0, HashSet::len)
    }

    #[allow(dead_code)]
    pub fn queue_len(&self, id: &RoutingId) -> usize {
        self.queues.get(id).map_or(0, Vec::len)
    }

    #[allow(dead_code)]
    pub fn connection_count(&self) -> usize {
        self.senders.len()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn subscribe_then_deliver_routes_live() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut state = HubState::new();
        let conn = state.register_conn(tx);
        let id: RoutingId = [42u8; 16];

        let drained = state.subscribe(conn, &[id]);
        assert!(drained.is_empty(), "no queued messages yet");

        let payload = b"hello".to_vec();
        let delivered = state.deliver(id, payload.clone());
        assert_eq!(delivered, 1);

        let received = rx.recv().await.expect("channel closed");
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn deliver_then_subscribe_drains_queue() {
        let mut state = HubState::new();
        let id: RoutingId = [1u8; 16];

        // Three deliveries with nobody subscribed — all queued.
        for body in [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()] {
            let delivered = state.deliver(id, body);
            assert_eq!(delivered, 0, "no subs → queued");
        }
        assert_eq!(state.queue_len(&id), 3);

        // Subscriber arrives and gets all three at once.
        let (tx, mut rx) = mpsc::channel(8);
        let conn = state.register_conn(tx);
        let drained = state.subscribe(conn, &[id]);
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0], b"a");
        assert_eq!(drained[1], b"b");
        assert_eq!(drained[2], b"c");

        // Queue is now empty.
        assert_eq!(state.queue_len(&id), 0);
        // Channel saw nothing yet — `subscribe` only returns the
        // drained items; the handler is responsible for flushing them
        // to the wire. (No live delivery while we subscribed.)
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn multiple_subscribers_all_get_delivery() {
        let mut state = HubState::new();
        let id: RoutingId = [9u8; 16];
        let (tx1, mut rx1) = mpsc::channel(8);
        let (tx2, mut rx2) = mpsc::channel(8);
        let c1 = state.register_conn(tx1);
        let c2 = state.register_conn(tx2);
        state.subscribe(c1, &[id]);
        state.subscribe(c2, &[id]);
        assert_eq!(state.subscriber_count(&id), 2);

        let delivered = state.deliver(id, b"x".to_vec());
        assert_eq!(delivered, 2);
        assert_eq!(rx1.recv().await.unwrap(), b"x");
        assert_eq!(rx2.recv().await.unwrap(), b"x");
    }

    #[tokio::test]
    async fn unregister_cleans_up_subscriptions() {
        let mut state = HubState::new();
        let id: RoutingId = [7u8; 16];
        let (tx, _rx) = mpsc::channel(8);
        let conn = state.register_conn(tx);
        state.subscribe(conn, &[id]);
        assert_eq!(state.subscriber_count(&id), 1);
        assert_eq!(state.connection_count(), 1);

        state.unregister_conn(conn);
        assert_eq!(state.subscriber_count(&id), 0);
        assert_eq!(state.connection_count(), 0);
        // The whole routing-id entry should have been pruned, not
        // left empty in the map.
        assert!(!state.subscribers.contains_key(&id));
    }

    // ── KeyPackage directory (T6.1) ────────────────────────────────────

    #[tokio::test]
    async fn fetch_keypackage_missing_returns_none() {
        let state = HubState::new();
        let id: RoutingId = [0xAA; 16];
        assert!(state.fetch_keypackage(&id).is_none());
        assert_eq!(state.keypackage_count(), 0);
    }

    #[tokio::test]
    async fn publish_then_fetch_returns_bytes() {
        let mut state = HubState::new();
        let id: RoutingId = [0xBB; 16];
        state.publish_keypackage(id, b"kp-bytes-v1".to_vec());
        assert_eq!(
            state.fetch_keypackage(&id).as_deref(),
            Some(b"kp-bytes-v1".as_slice())
        );
        assert_eq!(state.keypackage_count(), 1);
    }

    #[tokio::test]
    async fn publish_overwrites_latest() {
        let mut state = HubState::new();
        let id: RoutingId = [0xCC; 16];
        state.publish_keypackage(id, b"kp-v1".to_vec());
        state.publish_keypackage(id, b"kp-v2".to_vec());
        // Latest-wins, not concatenation or rejection.
        assert_eq!(
            state.fetch_keypackage(&id).as_deref(),
            Some(b"kp-v2".as_slice())
        );
        // And the directory size stays at 1 — we replaced, not appended.
        assert_eq!(state.keypackage_count(), 1);
    }

    // ── T8.0 durability ───────────────────────────────────────────────

    /// Restart-survival: write some KPs + queue some envelopes,
    /// "restart" the hub (drop + recreate HubState pointing at the
    /// same on-disk store), assert everything is still there.
    #[tokio::test]
    async fn with_store_survives_restart() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp);

        let rid_a: RoutingId = [0xA1; 16];
        let rid_b: RoutingId = [0xB2; 16];

        // First lifetime: queue two envelopes for rid_a (no
        // subscriber) and publish a KP for rid_b.
        {
            let store = Store::open(&path).unwrap();
            let mut state = HubState::with_store(store).unwrap();
            state.deliver(rid_a, b"queued-1".to_vec());
            state.deliver(rid_a, b"queued-2".to_vec());
            state.publish_keypackage(rid_b, b"kp-bytes".to_vec());
            assert_eq!(state.queue_len(&rid_a), 2);
            assert_eq!(state.keypackage_count(), 1);
        }

        // Second lifetime: reopen, expect both pieces of state.
        {
            let store = Store::open(&path).unwrap();
            let mut state = HubState::with_store(store).unwrap();
            assert_eq!(
                state.queue_len(&rid_a),
                2,
                "queued envelopes must survive restart"
            );
            assert_eq!(
                state.fetch_keypackage(&rid_b).as_deref(),
                Some(b"kp-bytes".as_slice()),
                "published KP must survive restart"
            );

            // Now a subscriber arrives and drains; both the in-memory
            // cache and the on-disk rows should clear.
            let (tx, _rx) = mpsc::channel(8);
            let conn = state.register_conn(tx);
            let drained = state.subscribe(conn, &[rid_a]);
            assert_eq!(drained.len(), 2);
            assert_eq!(state.queue_len(&rid_a), 0);
        }

        // Third lifetime: reopen one more time. The drained envelopes
        // must NOT come back — that would be a duplicate-delivery
        // bug (and would prove the drain-on-disk step failed).
        {
            let store = Store::open(&path).unwrap();
            let state = HubState::with_store(store).unwrap();
            assert_eq!(
                state.queue_len(&rid_a),
                0,
                "drained envelopes must not reappear after restart"
            );
            // KP still there (drain doesn't touch KPs).
            assert_eq!(
                state.fetch_keypackage(&rid_b).as_deref(),
                Some(b"kp-bytes".as_slice())
            );
        }

        std::fs::remove_file(&path).ok();
    }

    /// In-memory mode (`Self::new`) must continue to work without a
    /// store attached — preserves the existing test path + dev
    /// runs that don't care about durability.
    #[tokio::test]
    async fn new_is_ephemeral_no_store_no_panic() {
        let mut state = HubState::new();
        let id: RoutingId = [0xEE; 16];
        state.deliver(id, b"x".to_vec()); // no subscriber → queue
        state.publish_keypackage(id, b"kp".to_vec());
        assert_eq!(state.queue_len(&id), 1);
        assert_eq!(state.keypackage_count(), 1);
        // No durable_store, no errors, no panics. Ephemeral semantics
        // preserved.
    }
}
