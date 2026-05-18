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
#[derive(Debug, Default)]
pub struct HubState {
    next_conn_id: ConnId,
    senders: HashMap<ConnId, mpsc::Sender<Vec<u8>>>,
    subscribers: HashMap<RoutingId, HashSet<ConnId>>,
    queues: HashMap<RoutingId, Vec<Vec<u8>>>,
}

impl HubState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
    pub fn subscribe(&mut self, conn: ConnId, ids: &[RoutingId]) -> Vec<Vec<u8>> {
        let mut drained = Vec::new();
        for id in ids {
            self.subscribers.entry(*id).or_default().insert(conn);
            if let Some(q) = self.queues.remove(id) {
                drained.extend(q);
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
            self.queues.entry(target).or_default().push(payload);
        }
        delivered
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
}
