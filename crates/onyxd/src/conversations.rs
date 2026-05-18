//! In-process conversation registry.
//!
//! `onyxd` keeps one `ConversationHandle` per live (or recently-live)
//! peer session. The handle is the bridge between two halves of the
//! daemon:
//!
//!   * The **peer session task** (Noise + MLS over a Tor stream)
//!     reads from a per-conversation `mpsc::Receiver<String>` when it
//!     wants something to send, and pushes decrypted incoming
//!     messages into the registry's global event broadcast.
//!   * The **API server** (`api_server.rs`) looks up a handle by its
//!     8-char `short_id` when serving `ApiRequest::Send`, and
//!     subscribes to the broadcast when serving `ApiRequest::Tail`.
//!
//! The registry itself sits behind a single `tokio::sync::Mutex`.
//! Lock granularity is intentionally coarse — at v0 scale (single
//! user, a handful of peers) the lock is held only long enough to
//! mutate a HashMap.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use onyx_core::api::{ApiResponse, HistoryEntry, MessageDirection, PeerInfo};
use tokio::sync::{Mutex, broadcast, mpsc};

/// Per-peer outbound queue depth. The API's `Send` handler `try_send`s
/// into this; if full it returns an [`ApiErrorCode::NotReady`]-style
/// error rather than blocking.
pub const OUTBOUND_MAILBOX: usize = 32;

/// How many of the most recent messages we keep in memory per peer
/// for preview / scrollback rendering.
pub const RING_CAPACITY: usize = 200;

/// Broadcast queue depth for live `Tail` subscribers. Each `Tail`
/// client gets its own consumer; if a consumer falls behind by more
/// than this many events, they get dropped (a `Lagged` error from
/// `broadcast::Receiver`).
pub const EVENT_BROADCAST_CAPACITY: usize = 1024;

/// What we keep per peer.
///
/// Cloning a `ConversationHandle` is cheap (mpsc senders + an arc-ish
/// broadcast sender) and intentional: handlers spawn-and-forget tasks
/// that need their own clones.
#[derive(Debug, Clone)]
pub struct ConversationHandle {
    pub peer_pub: [u8; 32],
    pub short_id: String,
    pub pubkey_b32: String,
    pub fingerprint: String,
    /// Push to this to have the peer session task encrypt + send.
    pub outbound_tx: mpsc::Sender<String>,
}

/// Mutable per-peer state. Held inside the registry behind its own
/// lock so we can read/update a single conversation's ring buffer
/// without contending with other peers.
#[derive(Debug)]
struct ConversationState {
    handle: ConversationHandle,
    connected: bool,
    ring: VecDeque<ChatLine>,
    last_active_unix_ms: u64,
}

/// One line in a conversation's ring buffer. Mirrors the
/// [`HistoryEntry`] wire shape.
#[derive(Debug, Clone)]
pub struct ChatLine {
    pub direction: MessageDirection,
    pub text: String,
    pub ts_unix_ms: u64,
}

/// Top-level registry, wrap in `Arc<Mutex<…>>` and clone the `Arc`
/// into each handler task.
#[derive(Debug)]
pub struct ConversationRegistry {
    by_peer: HashMap<[u8; 32], ConversationState>,
    by_short: HashMap<String, [u8; 32]>,
    /// Fan-out of conversation events to API `Tail` subscribers.
    events_tx: broadcast::Sender<ApiResponse>,
}

impl ConversationRegistry {
    #[must_use]
    pub fn new() -> Self {
        let (events_tx, _rx) = broadcast::channel(EVENT_BROADCAST_CAPACITY);
        Self {
            by_peer: HashMap::new(),
            by_short: HashMap::new(),
            events_tx,
        }
    }

    /// Subscribe to the global event stream. New subscribers see
    /// events emitted **after** the subscribe call; backfill is the
    /// caller's job (typically a `Peers` request to learn current state).
    pub fn subscribe_events(&self) -> broadcast::Receiver<ApiResponse> {
        self.events_tx.subscribe()
    }

    /// Register a new live conversation. Caller must supply the
    /// receiver end of the outbound channel and consume it in the
    /// peer session task.
    ///
    /// Pushes [`ApiResponse::EventPeerConnected`] to all current
    /// `Tail` subscribers.
    pub fn register(
        &mut self,
        peer_pub: [u8; 32],
        pubkey_b32: &str,
        fingerprint: String,
    ) -> (ConversationHandle, mpsc::Receiver<String>) {
        let short_id = short_id_of(pubkey_b32);
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_MAILBOX);
        let handle = ConversationHandle {
            peer_pub,
            short_id: short_id.clone(),
            pubkey_b32: pubkey_b32.to_string(),
            fingerprint,
            outbound_tx,
        };
        self.by_short.insert(short_id, peer_pub);
        let state = ConversationState {
            handle: handle.clone(),
            connected: true,
            ring: VecDeque::with_capacity(RING_CAPACITY),
            last_active_unix_ms: now_unix_ms(),
        };
        self.by_peer.insert(peer_pub, state);

        let info = self
            .peer_info_for(&peer_pub)
            .expect("just inserted")
            .clone();
        // Drop the event silently if there are no subscribers — that's
        // not an error, just nobody listening yet.
        let _ = self
            .events_tx
            .send(ApiResponse::EventPeerConnected { peer: info });

        (handle, outbound_rx)
    }

    /// Mark a conversation as disconnected (peer closed the stream
    /// or our session task ended) and emit
    /// [`ApiResponse::EventPeerDisconnected`]. We keep the row in
    /// `by_peer` so the TUI can still render history; a future call
    /// to [`Self::deregister`] would remove it for real.
    pub fn mark_disconnected(&mut self, peer_pub: &[u8; 32]) {
        if let Some(state) = self.by_peer.get_mut(peer_pub) {
            state.connected = false;
            state.last_active_unix_ms = now_unix_ms();
            let short = state.handle.short_id.clone();
            let _ = self
                .events_tx
                .send(ApiResponse::EventPeerDisconnected { peer_short: short });
        }
    }

    /// Append a message to the ring buffer and broadcast it as an
    /// [`ApiResponse::EventMessage`]. Returns `false` if the peer is
    /// unknown (caller probably has a stale handle).
    pub fn push_message(
        &mut self,
        peer_pub: &[u8; 32],
        direction: MessageDirection,
        text: String,
    ) -> bool {
        let ts_unix_ms = now_unix_ms();
        let short = match self.by_peer.get_mut(peer_pub) {
            Some(state) => {
                if state.ring.len() == RING_CAPACITY {
                    state.ring.pop_front();
                }
                state.ring.push_back(ChatLine {
                    direction,
                    text: text.clone(),
                    ts_unix_ms,
                });
                state.last_active_unix_ms = ts_unix_ms;
                state.handle.short_id.clone()
            }
            None => return false,
        };
        let _ = self.events_tx.send(ApiResponse::EventMessage {
            peer_short: short,
            direction,
            text,
            ts_unix_ms,
        });
        true
    }

    /// Look up a handle by the user-facing short_id (e.g. typed into
    /// `onyx send <short> <text>`). Returns `None` if no live peer
    /// matches or the peer's session has ended.
    pub fn handle_for_short(&self, short_id: &str) -> Option<ConversationHandle> {
        let peer_pub = self.by_short.get(short_id)?;
        let state = self.by_peer.get(peer_pub)?;
        if state.connected {
            Some(state.handle.clone())
        } else {
            None
        }
    }

    /// Snapshot of every peer the registry knows about, live or not.
    #[must_use]
    pub fn list(&self) -> Vec<PeerInfo> {
        self.by_peer.values().map(info_of).collect()
    }

    /// Most recent `limit` messages for the peer, oldest → newest.
    /// Returns `None` if no peer with that `short_id` is known —
    /// distinct from `Some(vec![])`, which means "known peer, no
    /// messages exchanged yet". Disconnected peers still have
    /// retrievable history.
    #[must_use]
    pub fn history(&self, short_id: &str, limit: usize) -> Option<Vec<HistoryEntry>> {
        let peer_pub = self.by_short.get(short_id)?;
        let state = self.by_peer.get(peer_pub)?;
        let total = state.ring.len();
        let take_from = total.saturating_sub(limit);
        Some(
            state
                .ring
                .iter()
                .skip(take_from)
                .map(|line| HistoryEntry {
                    direction: line.direction,
                    text: line.text.clone(),
                    ts_unix_ms: line.ts_unix_ms,
                })
                .collect(),
        )
    }

    fn peer_info_for(&self, peer_pub: &[u8; 32]) -> Option<PeerInfo> {
        self.by_peer.get(peer_pub).map(info_of)
    }
}

impl Default for ConversationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn info_of(state: &ConversationState) -> PeerInfo {
    let last_message_preview = state.ring.back().map(|line| {
        let mut s = line.text.clone();
        if s.len() > 64 {
            s.truncate(64);
            s.push('…');
        }
        s
    });
    PeerInfo {
        short_id: state.handle.short_id.clone(),
        pubkey_b32: state.handle.pubkey_b32.clone(),
        fingerprint: state.handle.fingerprint.clone(),
        connected: state.connected,
        last_message_preview,
        last_active_unix_ms: state.last_active_unix_ms,
    }
}

/// User-facing 8-char prefix derived from the peer's full base32
/// pubkey. Matches `short_id` rendering everywhere else in the codebase.
#[must_use]
pub fn short_id_of(pubkey_b32: &str) -> String {
    pubkey_b32.chars().take(8).collect()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Convenience alias used at module callsites.
pub type SharedRegistry = Arc<Mutex<ConversationRegistry>>;

#[must_use]
pub fn new_shared() -> SharedRegistry {
    Arc::new(Mutex::new(ConversationRegistry::new()))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn b32() -> String {
        "u5lhmxpsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_string()
    }

    #[tokio::test]
    async fn register_then_lookup_by_short() {
        let mut reg = ConversationRegistry::new();
        let (handle, _rx) = reg.register([7u8; 32], &b32(), "fpr".into());
        assert_eq!(handle.short_id.len(), 8);
        let h = reg.handle_for_short(&handle.short_id).expect("present");
        assert_eq!(h.peer_pub, handle.peer_pub);
    }

    #[tokio::test]
    async fn push_message_appears_in_list_preview() {
        let mut reg = ConversationRegistry::new();
        let (handle, _rx) = reg.register([1u8; 32], &b32(), "fpr".into());
        assert!(reg.push_message(
            &handle.peer_pub,
            MessageDirection::Incoming,
            "hello there".into(),
        ));
        let list = reg.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].last_message_preview.as_deref(), Some("hello there"));
        assert!(list[0].connected);
    }

    #[tokio::test]
    async fn mark_disconnected_keeps_row_but_blocks_send_lookup() {
        let mut reg = ConversationRegistry::new();
        let (handle, _rx) = reg.register([2u8; 32], &b32(), "fpr".into());
        let short = handle.short_id.clone();
        reg.mark_disconnected(&handle.peer_pub);
        // Still in `list` for the TUI's history view.
        let list = reg.list();
        assert_eq!(list.len(), 1);
        assert!(!list[0].connected);
        // But `handle_for_short` refuses — `Send` would fail.
        assert!(reg.handle_for_short(&short).is_none());
    }

    #[tokio::test]
    async fn ring_buffer_caps_at_capacity() {
        let mut reg = ConversationRegistry::new();
        let (handle, _rx) = reg.register([3u8; 32], &b32(), "fpr".into());
        for i in 0..(RING_CAPACITY + 10) {
            reg.push_message(
                &handle.peer_pub,
                MessageDirection::Incoming,
                format!("msg-{i}"),
            );
        }
        // Look inside; only `RING_CAPACITY` retained.
        let state = reg.by_peer.get(&handle.peer_pub).unwrap();
        assert_eq!(state.ring.len(), RING_CAPACITY);
        // Oldest dropped, newest kept.
        assert_eq!(state.ring.front().unwrap().text, format!("msg-{}", 10));
        assert_eq!(
            state.ring.back().unwrap().text,
            format!("msg-{}", RING_CAPACITY + 9)
        );
    }

    #[tokio::test]
    async fn subscribe_then_register_emits_connected_event() {
        let mut reg = ConversationRegistry::new();
        let mut rx = reg.subscribe_events();
        let (_handle, _o_rx) = reg.register([4u8; 32], &b32(), "fpr".into());
        let event = rx.recv().await.expect("recv");
        match event {
            ApiResponse::EventPeerConnected { peer } => {
                assert_eq!(peer.short_id.len(), 8);
                assert!(peer.connected);
            }
            other => panic!("expected EventPeerConnected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn push_message_emits_event_message() {
        let mut reg = ConversationRegistry::new();
        let (handle, _rx) = reg.register([5u8; 32], &b32(), "fpr".into());
        let mut events = reg.subscribe_events();
        reg.push_message(&handle.peer_pub, MessageDirection::Incoming, "yo".into());
        let event = events.recv().await.expect("recv");
        match event {
            ApiResponse::EventMessage {
                peer_short,
                direction,
                text,
                ..
            } => {
                assert_eq!(peer_short, handle.short_id);
                assert_eq!(direction, MessageDirection::Incoming);
                assert_eq!(text, "yo");
            }
            other => panic!("expected EventMessage, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn outbound_send_round_trip_via_mpsc() {
        let mut reg = ConversationRegistry::new();
        let (handle, mut rx) = reg.register([6u8; 32], &b32(), "fpr".into());
        handle.outbound_tx.send("hi peer".into()).await.unwrap();
        assert_eq!(rx.recv().await.unwrap(), "hi peer");
    }

    #[tokio::test]
    async fn history_returns_messages_oldest_to_newest() {
        let mut reg = ConversationRegistry::new();
        let (handle, _rx) = reg.register([10u8; 32], &b32(), "fpr".into());
        for i in 0..5 {
            reg.push_message(
                &handle.peer_pub,
                MessageDirection::Incoming,
                format!("m{i}"),
            );
        }
        let hist = reg.history(&handle.short_id, 10).expect("known peer");
        assert_eq!(hist.len(), 5);
        let texts: Vec<&str> = hist.iter().map(|h| h.text.as_str()).collect();
        assert_eq!(texts, ["m0", "m1", "m2", "m3", "m4"]);
    }

    #[tokio::test]
    async fn history_limit_returns_only_the_most_recent() {
        let mut reg = ConversationRegistry::new();
        let (handle, _rx) = reg.register([11u8; 32], &b32(), "fpr".into());
        for i in 0..10 {
            reg.push_message(
                &handle.peer_pub,
                MessageDirection::Outgoing,
                format!("m{i}"),
            );
        }
        let hist = reg.history(&handle.short_id, 3).unwrap();
        assert_eq!(
            hist.iter().map(|h| h.text.as_str()).collect::<Vec<_>>(),
            ["m7", "m8", "m9"]
        );
    }

    #[tokio::test]
    async fn history_unknown_peer_is_none() {
        let reg = ConversationRegistry::new();
        assert!(reg.history("nopeer", 10).is_none());
    }

    #[tokio::test]
    async fn history_for_disconnected_peer_still_works() {
        let mut reg = ConversationRegistry::new();
        let (handle, _rx) = reg.register([12u8; 32], &b32(), "fpr".into());
        reg.push_message(&handle.peer_pub, MessageDirection::Incoming, "saved".into());
        reg.mark_disconnected(&handle.peer_pub);
        let hist = reg.history(&handle.short_id, 10).expect("known peer");
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].text, "saved");
        // But Send-lookup is blocked.
        assert!(reg.handle_for_short(&handle.short_id).is_none());
    }
}
