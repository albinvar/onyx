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

use onyx_core::crypto::blake2b_128;
use onyx_core::wire::{
    FRAME_GOSSIP_DELIVER, FRAME_GOSSIP_PUBLISH, GOSSIP_SEEN_BY_LEN, GossipFrame, InnerFrame,
};
use tokio::sync::mpsc;
use tracing::warn;

use crate::rate_limit::RateLimiter;
use crate::store::Store;

/// Queue-gossip policy (T8.3.c). Controls when this hub forwards
/// an envelope it has just received (from a client or from a peer
/// hub) to its other peer hubs.
///
///   * `Lazy` (default): forward only when the envelope could NOT
///     be delivered to a local subscriber. Minimal bandwidth;
///     works well when most users subscribe to the same hub
///     (typical small deployment). May fail in mesh topologies
///     where subscribers are spread across peer hubs — a hub that
///     happens to have ANY local subscriber for the routing-id
///     swallows the gossip and never tells the peer hubs the
///     other subscribers are on.
///   * `Eager`: forward to every peer hub regardless of local
///     delivery. Stronger eventual consistency at ~3× bandwidth.
///     The recipient daemon's `EnvelopeReplayGuard` (T7.3-sec.2)
///     dedups any duplicate arrivals at zero added complexity.
///
/// FEDERATION.md §3.2 has the full tradeoff analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GossipMode {
    /// Forward only when not delivered locally. Default.
    #[default]
    Lazy,
    /// Forward to all peers regardless of local delivery.
    Eager,
}

/// Configuration for one peer hub the operator wants this hub to
/// federate with (T8.3). Each entry produces one outbound Noise XK
/// session managed by [`crate::peer_link`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHubConfig {
    /// `onion:port` (or just `onion`; port defaults to the hub HS port).
    pub onion: String,
    /// X25519 identity public key of the peer hub, base32. Doubles
    /// as the **role allowlist entry** — an incoming Noise XK
    /// session whose authenticated peer_static_key matches this hub
    /// is treated as a peer hub (T8.3.b.4), not a client.
    pub pubkey: String,
}

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
    /// Per-connection rate limiter (T8.x-ratelimit). Optional so
    /// existing tests + ephemeral hubs don't pay the cost; `None`
    /// means "no limit, accept everything." Bound on first frame
    /// per connection (lazy); cleared on unregister_conn.
    rate_limiter: Option<RateLimiter>,
    /// One outbound channel per peer hub (T8.3.b.2+), keyed by the
    /// peer's hub identity X25519 pubkey. The key serves two
    /// purposes: (1) on inbound peer-hub recognition (T8.3.b.4) we
    /// check `peer_outbounds.contains_key(&peer_static_key)` to
    /// decide role; (2) on gossip re-fanout we skip the source
    /// peer's channel via `fan_out_kp_to_peers_except(source_pk)`
    /// to avoid bouncing the frame back where it came from.
    ///
    /// Empty HashMap when no `--peer-hub` is configured.
    peer_outbounds: HashMap<[u8; 32], mpsc::Sender<InnerFrame>>,
    /// Low 16 bytes of BLAKE2b-128 of our own hub identity pubkey
    /// (T8.3.b.2+). Used as the `seen_by` value when we originate
    /// or forward a gossip frame so peer hubs can detect loops
    /// involving us. Set once at startup via
    /// [`Self::set_self_hub_hash`]; zero-initialised by default so
    /// existing tests that don't enable federation don't have to
    /// supply a value.
    self_hub_hash: [u8; GOSSIP_SEEN_BY_LEN],
    /// Queue-gossip policy (T8.3.c). Default `Lazy`. See
    /// [`GossipMode`] for the tradeoff.
    gossip_mode: GossipMode,
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

    /// Install a per-connection rate limiter (T8.x-ratelimit). Each
    /// connection lazily gets a token bucket capped at
    /// `frames_per_minute` for DELIVER + KP_PUBLISH; sustained rate
    /// is `frames_per_minute / 60` per second, burst tolerance is
    /// the full bucket capacity. SUBSCRIBE frames are not limited
    /// (cheap; no heavy work).
    pub fn with_rate_limit(mut self, frames_per_minute: u32) -> Self {
        self.rate_limiter = Some(RateLimiter::with_frames_per_minute(frames_per_minute));
        self
    }

    /// Check + consume one token for `conn`. Returns `true` if the
    /// caller should process the frame, `false` if the connection
    /// has exceeded its rate quota and the frame should be silently
    /// dropped. When no rate limiter is installed, always returns
    /// `true` (limiter is opt-in).
    pub fn check_rate(&mut self, conn: ConnId) -> bool {
        match &mut self.rate_limiter {
            Some(rl) => rl.check(conn),
            None => true,
        }
    }

    /// Install the per-peer-hub outbound channels (T8.3.b.2+),
    /// keyed by the peer hub's X25519 identity pubkey. Empty
    /// HashMap (the default) disables federation entirely.
    pub fn set_peer_outbounds(
        &mut self,
        peer_outbounds: HashMap<[u8; 32], mpsc::Sender<InnerFrame>>,
    ) {
        self.peer_outbounds = peer_outbounds;
    }

    /// T8.3.b.4: does this authenticated peer pubkey belong to a
    /// configured peer hub? Used by `hub_handle_connection` after
    /// the Noise XK handshake to decide role (peer hub vs client).
    #[must_use]
    pub fn is_peer_hub(&self, peer_pubkey: &[u8; 32]) -> bool {
        self.peer_outbounds.contains_key(peer_pubkey)
    }

    /// Expose our own hub hash for the gossip loop-detection check
    /// in `handler::handle_gossip_publish`. Named `_for_test` to
    /// keep the public surface clearly internal; not actually
    /// test-only — it's called from the handler too.
    #[must_use]
    pub fn self_hub_hash_for_test(&self) -> [u8; GOSSIP_SEEN_BY_LEN] {
        self.self_hub_hash
    }

    /// Set our own hub-pubkey hash for gossip `seen_by` purposes
    /// (T8.3.b.2+). Compute once at startup from
    /// `blake2b_128(our_hub_pubkey.to_bytes())`, low 16 bytes.
    pub fn set_self_hub_hash(&mut self, hash: [u8; GOSSIP_SEEN_BY_LEN]) {
        self.self_hub_hash = hash;
    }

    /// Set the queue-gossip policy (T8.3.c). Default at construct
    /// is `Lazy`.
    pub fn set_gossip_mode(&mut self, mode: GossipMode) {
        self.gossip_mode = mode;
    }

    /// Current queue-gossip policy. Read by `deliver_from_client`
    /// and the inbound `handle_gossip_deliver` path to decide
    /// whether to re-fanout.
    #[must_use]
    pub fn gossip_mode(&self) -> GossipMode {
        self.gossip_mode
    }

    /// Build a [`blake2b_128`] hash of the given hub pubkey and
    /// return its low 16 bytes — the canonical `seen_by` value for
    /// gossip frames originating from / forwarded by that hub.
    /// Stateless convenience.
    #[must_use]
    pub fn hub_pubkey_to_hash(pubkey_bytes: &[u8; 32]) -> [u8; GOSSIP_SEEN_BY_LEN] {
        blake2b_128(&[pubkey_bytes.as_slice()])
    }

    /// Fan out a freshly-validated KeyPackage to every configured
    /// peer hub (T8.3.b.3). Wraps the KP in a fresh `GossipFrame`
    /// at TTL=`GOSSIP_TTL_DEFAULT` with `seen_by` = our hash,
    /// encodes, and `try_send`s a `FRAME_GOSSIP_PUBLISH` InnerFrame
    /// to each peer-hub outbound channel.
    pub fn fan_out_kp_to_peers(&self, routing_id: RoutingId, kp_bytes: &[u8]) {
        if self.peer_outbounds.is_empty() {
            return;
        }
        let gossip = GossipFrame::new(self.self_hub_hash, routing_id, kp_bytes.to_vec());
        let frame = InnerFrame {
            frame_type: FRAME_GOSSIP_PUBLISH,
            payload: gossip.encode(),
        };
        self.broadcast_to_peers(&frame, None, "gossip KP (origin)");
    }

    /// Fan out a gossip-forwarded KeyPackage to every configured
    /// peer hub **except** the source (T8.3.b.4). `source_pubkey`
    /// is the authenticated Noise pubkey of the peer hub we just
    /// received the gossip from — skipping it on re-fanout avoids
    /// bouncing the frame straight back across the same link.
    ///
    /// `ttl_already_decremented` is the TTL the caller wants on the
    /// outgoing frame (already-decremented by `GossipFrame::forward`).
    /// Returns the encoded outgoing frame for testability; in
    /// production callers ignore the return value.
    pub fn fan_out_kp_to_peers_except(
        &self,
        source_pubkey: &[u8; 32],
        ttl_already_decremented: u8,
        routing_id: RoutingId,
        kp_bytes: &[u8],
    ) {
        if self.peer_outbounds.is_empty() {
            return;
        }
        let gossip = GossipFrame {
            ttl: ttl_already_decremented,
            seen_by: self.self_hub_hash,
            routing_id,
            body: kp_bytes.to_vec(),
        };
        let frame = InnerFrame {
            frame_type: FRAME_GOSSIP_PUBLISH,
            payload: gossip.encode(),
        };
        self.broadcast_to_peers(&frame, Some(source_pubkey), "gossip KP (forward)");
    }

    /// Internal: send the pre-encoded gossip payload to every peer
    /// outbound channel, optionally skipping one source pubkey.
    fn broadcast_to_peers(&self, frame: &InnerFrame, skip: Option<&[u8; 32]>, op: &'static str) {
        let mut accepted = 0usize;
        let total = self.peer_outbounds.len();
        for (pk, tx) in &self.peer_outbounds {
            if Some(pk) == skip {
                continue;
            }
            match tx.try_send(frame.clone()) {
                Ok(()) => accepted += 1,
                Err(e) => warn!(
                    peer_pk_prefix = format!("{:02x}{:02x}{:02x}{:02x}", pk[0], pk[1], pk[2], pk[3]),
                    error = %e,
                    op,
                    "hub: peer-hub outbound queue full or closed; dropping gossip for this peer"
                ),
            }
        }
        tracing::debug!(accepted, total, op, "hub: gossip fan-out");
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

    /// T8.3.c: deliver an envelope received from a local client,
    /// then conditionally gossip it to peer hubs per the configured
    /// `GossipMode`.
    ///
    ///   * `Eager`: always gossip after delivery (regardless of
    ///     local subscribe count). Higher bandwidth, stronger
    ///     eventual consistency across the mesh.
    ///   * `Lazy` (default): only gossip when the envelope wasn't
    ///     delivered to any local subscriber (`delivered == 0`).
    ///     Bandwidth-efficient for star topologies where most
    ///     users subscribe to the same hub.
    ///
    /// Returns the same `delivered` count as [`Self::deliver`] so
    /// the caller can log the live-subscriber result.
    pub fn deliver_from_client(&mut self, target: RoutingId, payload: Vec<u8>) -> usize {
        let payload_for_gossip = payload.clone();
        let delivered = self.deliver(target, payload);
        let should_gossip = match self.gossip_mode {
            GossipMode::Eager => true,
            GossipMode::Lazy => delivered == 0,
        };
        if should_gossip {
            self.fan_out_envelope_to_peers(target, &payload_for_gossip);
        }
        delivered
    }

    /// Fan out a freshly-received envelope to every configured
    /// peer hub (T8.3.c origin path). Wraps the envelope in a
    /// fresh `GossipFrame` at TTL=`GOSSIP_TTL_DEFAULT` with
    /// `seen_by` = our hash, encodes as a `FRAME_GOSSIP_DELIVER`
    /// payload, `try_send`s to each peer-hub outbound channel.
    ///
    /// Same best-effort semantics as KP fan-out: a full channel
    /// drops the gossip for that peer; the local store + other
    /// peers still succeed.
    ///
    /// No-op when `peer_outbounds` is empty (no federation).
    pub fn fan_out_envelope_to_peers(&self, routing_id: RoutingId, envelope_bytes: &[u8]) {
        if self.peer_outbounds.is_empty() {
            return;
        }
        let gossip = GossipFrame::new(self.self_hub_hash, routing_id, envelope_bytes.to_vec());
        let frame = InnerFrame {
            frame_type: FRAME_GOSSIP_DELIVER,
            payload: gossip.encode(),
        };
        self.broadcast_to_peers(&frame, None, "gossip envelope (origin)");
    }

    /// Fan out a gossip-forwarded envelope to every configured peer
    /// hub EXCEPT the source (T8.3.c forward path). Mirror of
    /// [`Self::fan_out_kp_to_peers_except`]. `ttl_already_decremented`
    /// is the TTL the caller wants on the outgoing frame (already
    /// reduced by `GossipFrame::forward`).
    pub fn fan_out_envelope_to_peers_except(
        &self,
        source_pubkey: &[u8; 32],
        ttl_already_decremented: u8,
        routing_id: RoutingId,
        envelope_bytes: &[u8],
    ) {
        if self.peer_outbounds.is_empty() {
            return;
        }
        let gossip = GossipFrame {
            ttl: ttl_already_decremented,
            seen_by: self.self_hub_hash,
            routing_id,
            body: envelope_bytes.to_vec(),
        };
        let frame = InnerFrame {
            frame_type: FRAME_GOSSIP_DELIVER,
            payload: gossip.encode(),
        };
        self.broadcast_to_peers(&frame, Some(source_pubkey), "gossip envelope (forward)");
    }

    /// Remove a connection and all its subscriptions.
    pub fn unregister_conn(&mut self, conn: ConnId) {
        self.senders.remove(&conn);
        for subs in self.subscribers.values_mut() {
            subs.remove(&conn);
        }
        // Reclaim empty-set entries so subscribers doesn't grow without bound.
        self.subscribers.retain(|_, subs| !subs.is_empty());
        // T8.x-ratelimit: drop the rate bucket too — otherwise the
        // map slowly leaks one entry per disconnected conn id.
        if let Some(rl) = &mut self.rate_limiter {
            rl.forget(conn);
        }
    }

    // ── KeyPackage directory (T6.1) ────────────────────────────────────────

    /// Garbage-collect queued envelopes older than `cutoff_unix_ms`
    /// (T8.0.gc). No-op when running ephemeral (no durable store).
    /// Removes rows from the persisted `queue_entry` table; does NOT
    /// touch the in-memory `queues` HashMap because the in-memory
    /// queue is what's CURRENTLY live (an entry in the in-memory
    /// queue is by definition recent — the entry was either just
    /// enqueued, or it survived the last warm-from-disk on startup,
    /// in which case the next subscriber will drain it momentarily).
    ///
    /// Returns the number of on-disk rows deleted. Callers should
    /// log this for visibility into hub operability.
    pub fn gc_queue_entries_older_than(&self, cutoff_unix_ms: i64) -> anyhow::Result<usize> {
        match &self.durable_store {
            Some(store) => store.gc_queue_entries_older_than(cutoff_unix_ms),
            None => Ok(0),
        }
    }

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

    // ── T8.3.b.2+.3: peer-hub fan-out ─────────────────────────────────

    /// `fan_out_kp_to_peers` is a no-op when no peer hubs are
    /// configured. Real KP path keeps working unchanged.
    #[tokio::test]
    async fn fan_out_kp_to_peers_noop_when_no_peers() {
        let state = HubState::new();
        // No peer_outbounds, no senders to push to. Just shouldn't
        // panic and shouldn't block.
        state.fan_out_kp_to_peers([0x42; 16], b"opaque kp bytes");
    }

    /// With peer_outbounds installed, a fan-out pushes a properly-
    /// encoded GossipFrame payload to every peer channel.
    #[tokio::test]
    async fn fan_out_kp_to_peers_pushes_to_all_peers() {
        let (tx_a, mut rx_a) = mpsc::channel::<InnerFrame>(8);
        let (tx_b, mut rx_b) = mpsc::channel::<InnerFrame>(8);
        let mut state = HubState::new();
        state.set_self_hub_hash([0xAA; 16]);
        let mut peers = HashMap::new();
        peers.insert([0x01; 32], tx_a);
        peers.insert([0x02; 32], tx_b);
        state.set_peer_outbounds(peers);

        let rid: RoutingId = [0x11; 16];
        let kp = b"opaque kp bytes".to_vec();
        state.fan_out_kp_to_peers(rid, &kp);

        // Each peer received one InnerFrame.
        let inner_a = rx_a.recv().await.expect("peer A received");
        let inner_b = rx_b.recv().await.expect("peer B received");

        // Same wrapper to both — fan-out, not per-peer customisation.
        assert_eq!(inner_a, inner_b);
        assert_eq!(inner_a.frame_type, FRAME_GOSSIP_PUBLISH);

        // Decode the inner GossipFrame and inspect.
        let frame =
            GossipFrame::decode(&inner_a.payload).expect("payload is a well-formed gossip frame");
        assert_eq!(
            frame.ttl,
            onyx_core::wire::GOSSIP_TTL_DEFAULT,
            "fresh frames use default TTL"
        );
        assert_eq!(frame.seen_by, [0xAA; 16], "seen_by = our hub hash");
        assert_eq!(frame.routing_id, rid);
        assert_eq!(frame.body, kp);
    }

    /// A full peer-outbound channel drops gossip for THAT peer
    /// only; other peers still receive. Local store (not exercised
    /// here directly) is unaffected by the fan-out's behaviour.
    #[tokio::test]
    async fn fan_out_kp_to_peers_full_channel_only_drops_that_peer() {
        let (tx_full, _rx_full_never_read) = mpsc::channel::<InnerFrame>(1);
        let (tx_open, mut rx_open) = mpsc::channel::<InnerFrame>(8);

        // Pre-fill the "full" channel so the next try_send fails.
        tx_full
            .try_send(InnerFrame {
                frame_type: 0x99,
                payload: b"pre-fill".to_vec(),
            })
            .expect("seed full channel");

        let mut state = HubState::new();
        state.set_self_hub_hash([0xCC; 16]);
        let mut peers = HashMap::new();
        peers.insert([0x03; 32], tx_full);
        peers.insert([0x04; 32], tx_open);
        state.set_peer_outbounds(peers);

        // Should not panic; should successfully push to tx_open.
        state.fan_out_kp_to_peers([0x22; 16], b"kp");

        // The open channel got the gossip.
        let inner = rx_open.recv().await.expect("open peer received");
        assert_eq!(inner.frame_type, FRAME_GOSSIP_PUBLISH);
        let frame = GossipFrame::decode(&inner.payload).unwrap();
        assert_eq!(frame.routing_id, [0x22; 16]);
    }

    /// T8.3.b.4 is_peer_hub: contains_key shorthand. Configured
    /// peer pubkeys return true; anything else returns false.
    #[tokio::test]
    async fn is_peer_hub_recognises_configured_pubkeys() {
        let (tx, _rx) = mpsc::channel::<InnerFrame>(8);
        let mut state = HubState::new();
        let mut peers = HashMap::new();
        peers.insert([0x77; 32], tx);
        state.set_peer_outbounds(peers);

        assert!(state.is_peer_hub(&[0x77; 32]));
        assert!(!state.is_peer_hub(&[0x88; 32]));
        // No peers installed → nothing is a peer.
        let empty_state = HubState::new();
        assert!(!empty_state.is_peer_hub(&[0x77; 32]));
    }

    /// T8.3.b.4 forward path: re-fanout to peers OTHER THAN the
    /// source. Source pubkey's channel is silent; every other
    /// peer's channel receives the forwarded frame.
    #[tokio::test]
    async fn fan_out_except_skips_source() {
        let (tx_src, mut rx_src) = mpsc::channel::<InnerFrame>(8);
        let (tx_a, mut rx_a) = mpsc::channel::<InnerFrame>(8);
        let (tx_b, mut rx_b) = mpsc::channel::<InnerFrame>(8);

        let mut state = HubState::new();
        state.set_self_hub_hash([0xEE; 16]);
        let mut peers = HashMap::new();
        let src_pk = [0xAA; 32];
        peers.insert(src_pk, tx_src);
        peers.insert([0xBB; 32], tx_a);
        peers.insert([0xCC; 32], tx_b);
        state.set_peer_outbounds(peers);

        state.fan_out_kp_to_peers_except(&src_pk, 2, [0x33; 16], b"forwarded kp");

        // Source should have received NOTHING.
        assert!(
            rx_src.try_recv().is_err(),
            "source must not receive its own forward"
        );

        // Other two peers got the gossip.
        let inner_a = rx_a.recv().await.expect("peer A received");
        let inner_b = rx_b.recv().await.expect("peer B received");
        assert_eq!(inner_a, inner_b);
        assert_eq!(inner_a.frame_type, FRAME_GOSSIP_PUBLISH);

        let frame = GossipFrame::decode(&inner_a.payload).unwrap();
        assert_eq!(frame.ttl, 2, "forwarded TTL preserved verbatim");
        assert_eq!(frame.seen_by, [0xEE; 16], "seen_by = OUR hash (rewritten)");
        assert_eq!(frame.routing_id, [0x33; 16]);
        assert_eq!(frame.body, b"forwarded kp");
    }

    /// T8.3.c lazy mode: deliver_from_client gossips ONLY when the
    /// envelope wasn't delivered to a local subscriber.
    #[tokio::test]
    async fn deliver_from_client_lazy_only_gossips_when_no_local_sub() {
        let (tx_peer, mut rx_peer) = mpsc::channel::<InnerFrame>(8);
        let mut state = HubState::new();
        state.set_self_hub_hash([0x99; 16]);
        let mut peers = HashMap::new();
        peers.insert([0xDE; 32], tx_peer);
        state.set_peer_outbounds(peers);
        // Default mode is Lazy; no explicit set_gossip_mode call needed.
        assert_eq!(state.gossip_mode(), GossipMode::Lazy);

        // Path 1: no local subscriber → envelope queued AND gossiped.
        state.deliver_from_client([0xA0; 16], b"queued envelope".to_vec());
        let inner = rx_peer.recv().await.expect("lazy mode gossiped");
        assert_eq!(inner.frame_type, FRAME_GOSSIP_DELIVER);
        let frame = GossipFrame::decode(&inner.payload).unwrap();
        assert_eq!(frame.routing_id, [0xA0; 16]);
        assert_eq!(frame.body, b"queued envelope");

        // Path 2: live subscriber present → envelope delivered locally
        // and NOT gossiped (lazy).
        let (sub_tx, _sub_rx) = mpsc::channel::<Vec<u8>>(8);
        let conn = state.register_conn(sub_tx);
        state.subscribe(conn, &[[0xB0; 16]]);
        state.deliver_from_client([0xB0; 16], b"live-delivered".to_vec());
        assert!(
            rx_peer.try_recv().is_err(),
            "lazy mode must NOT gossip when local subscriber accepted"
        );
    }

    /// T8.3.c eager mode: deliver_from_client always gossips, even
    /// when a local subscriber accepted.
    #[tokio::test]
    async fn deliver_from_client_eager_always_gossips() {
        let (tx_peer, mut rx_peer) = mpsc::channel::<InnerFrame>(8);
        let mut state = HubState::new();
        state.set_self_hub_hash([0x88; 16]);
        let mut peers = HashMap::new();
        peers.insert([0xAD; 32], tx_peer);
        state.set_peer_outbounds(peers);
        state.set_gossip_mode(GossipMode::Eager);
        assert_eq!(state.gossip_mode(), GossipMode::Eager);

        // Add a local subscriber so the envelope IS delivered locally;
        // eager mode should still gossip.
        let (sub_tx, mut sub_rx) = mpsc::channel::<Vec<u8>>(8);
        let conn = state.register_conn(sub_tx);
        state.subscribe(conn, &[[0xC0; 16]]);
        state.deliver_from_client([0xC0; 16], b"eager-tier".to_vec());

        // Local subscriber got it.
        let local = sub_rx.recv().await.expect("local subscriber received");
        assert_eq!(local, b"eager-tier");
        // Peer ALSO got the gossip (eager).
        let inner = rx_peer.recv().await.expect("eager mode gossiped");
        assert_eq!(inner.frame_type, FRAME_GOSSIP_DELIVER);
    }

    /// `hub_pubkey_to_hash` is a stable function of its input;
    /// matters because every hub computes its own hash this way
    /// and they need to compare equal across implementations.
    #[test]
    fn hub_pubkey_to_hash_is_deterministic() {
        let pk = [0x55; 32];
        let h1 = HubState::hub_pubkey_to_hash(&pk);
        let h2 = HubState::hub_pubkey_to_hash(&pk);
        assert_eq!(h1, h2);
        // Different pubkey → different hash (sanity, not a strong
        // collision-resistance check — BLAKE2b is presumed safe).
        let h3 = HubState::hub_pubkey_to_hash(&[0x56; 32]);
        assert_ne!(h1, h3);
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
