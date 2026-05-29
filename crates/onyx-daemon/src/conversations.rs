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
use tracing::warn;

/// Per-peer outbound queue depth. The API's `Send` handler `try_send`s
/// into this; if full it returns an [`ApiErrorCode::NotReady`]-style
/// error rather than blocking.
pub const OUTBOUND_MAILBOX: usize = 32;

/// What gets pushed into a peer's outbound channel. Two variants —
///
///   * `Dm(text)` — plaintext for the DM with this peer. The per-
///     peer session task MLS-encrypts this against the DM group
///     state it owns, then sends as `FRAME_MLS_APP`. The original
///     T2.x / T6.x shape.
///   * `RoomFrame(ciphertext)` — *already-encrypted* MLS ciphertext
///     belonging to a multi-party room (T6.3.d). The room sender
///     encrypts **once** in the room's group state, then pushes the
///     same ciphertext into every member's direct-session outbound
///     queue. The per-peer task forwards it as a `FRAME_MLS_APP`
///     frame without touching it.
///
/// Receiver-side disambiguation lives in the per-peer session task:
/// it peeks the `group_id` from every incoming `FRAME_MLS_APP` and
/// routes to either the DM group state (existing) or a room group
/// state (T6.3.d) before decrypting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerOutbound {
    /// DM plaintext text — the peer-session task wraps it in
    /// `RoomAppMessage::Text` and encrypts in this peer's DM group
    /// before sending.
    Dm(String),
    /// A DM application frame (task 322: file transfer). The
    /// peer-session task CBOR-encodes it and encrypts in this peer's
    /// DM group, exactly like `Dm`. The DM channel reuses the
    /// `RoomAppMessage` tagged envelope so the whole chunk/accept/
    /// finalize pipeline in `files.rs` is shared with rooms.
    DmFrame(onyx_core::room::RoomAppMessage),
    /// Already-MLS-encrypted room ciphertext — the peer-session
    /// task sends as-is; the room sender already encrypted in the
    /// room's group state.
    RoomFrame(Vec<u8>),
}

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
    /// Push to this to have the peer session task either encrypt-
    /// and-send (DM) or just-send (room ciphertext) — see
    /// [`PeerOutbound`].
    pub outbound_tx: mpsc::Sender<PeerOutbound>,
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
/// [`HistoryEntry`] wire shape including `via_hub`, so a fresh
/// `Tail` subscriber's `History` backfill carries the tier
/// indicator forward across restarts (otherwise hub-relayed
/// messages would silently downgrade to "direct-MLS-looking" on
/// the second daemon launch, which is a security UX bug).
#[derive(Debug, Clone)]
pub struct ChatLine {
    pub direction: MessageDirection,
    pub text: String,
    pub ts_unix_ms: u64,
    pub via_hub: bool,
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
    #[must_use]
    pub fn subscribe_events(&self) -> broadcast::Receiver<ApiResponse> {
        self.events_tx.subscribe()
    }

    /// Register a new live conversation. Caller must supply the
    /// receiver end of the outbound channel and consume it in the
    /// peer session task.
    ///
    /// Pushes [`ApiResponse::EventPeerConnected`] to all current
    /// `Tail` subscribers.
    /// P-2: insert a `short_id → peer_pub` mapping, refusing to
    /// overwrite an existing mapping to a **different** peer. The
    /// 8-char (40-bit) short id is grindable, so a silent overwrite
    /// would let an attacker who generates a key colliding on a
    /// victim's short id hijack it and have the user's short-id sends
    /// misdirected. On collision we keep the original owner and warn;
    /// the colliding peer is still reachable by its full pubkey.
    /// Re-registering the same peer (same short id → same key) is a
    /// no-op overwrite and allowed.
    fn insert_short_id(&mut self, short_id: String, peer_pub: [u8; 32]) {
        match self.by_short.get(&short_id) {
            Some(existing) if *existing != peer_pub => {
                warn!(
                    short_id = %short_id,
                    "conversations: short-id collision with a different peer; keeping the \
                     original owner (possible grinding attack — the new peer is still \
                     addressable by full key)"
                );
            }
            _ => {
                self.by_short.insert(short_id, peer_pub);
            }
        }
    }

    pub fn register(
        &mut self,
        peer_pub: [u8; 32],
        pubkey_b32: &str,
        fingerprint: String,
    ) -> (ConversationHandle, mpsc::Receiver<PeerOutbound>) {
        let short_id = short_id_of(pubkey_b32);
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_MAILBOX);
        let handle = ConversationHandle {
            peer_pub,
            short_id: short_id.clone(),
            pubkey_b32: pubkey_b32.to_string(),
            fingerprint,
            outbound_tx,
        };
        self.insert_short_id(short_id, peer_pub);
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

    /// Register (or no-op if already present) a peer we've only
    /// observed via the hub — no direct Noise session, no
    /// `peer_session` task, no transport to reply on. The returned
    /// handle's `outbound_tx` is wired to a `Receiver` we drop
    /// immediately, so any `try_send` into it eventually surfaces as
    /// `TrySendError::Closed` — exactly how a peer with a torn-down
    /// direct session would behave. The API server's `Send` handler
    /// returns its existing `NotReady` for that case.
    ///
    /// Idempotent: if a registration already exists for `peer_pub`
    /// (direct or hub-only), we return a clone of the existing handle
    /// without firing a duplicate `EventPeerConnected`.
    pub fn register_hub_only(
        &mut self,
        peer_pub: [u8; 32],
        pubkey_b32: &str,
        fingerprint: String,
    ) -> ConversationHandle {
        if let Some(existing) = self.by_peer.get(&peer_pub) {
            return existing.handle.clone();
        }
        let short_id = short_id_of(pubkey_b32);
        // Drop the Receiver immediately; the Sender's try_send will
        // return Closed once anyone tries to use it.
        let (outbound_tx, _drop_rx) = mpsc::channel(1);
        let handle = ConversationHandle {
            peer_pub,
            short_id: short_id.clone(),
            pubkey_b32: pubkey_b32.to_string(),
            fingerprint,
            outbound_tx,
        };
        self.insert_short_id(short_id, peer_pub);
        let state = ConversationState {
            handle: handle.clone(),
            // `connected: false` because there's no live direct
            // session; `handle_for_short` therefore refuses sends
            // for these peers, which is exactly what we want.
            connected: false,
            ring: VecDeque::with_capacity(RING_CAPACITY),
            last_active_unix_ms: now_unix_ms(),
        };
        self.by_peer.insert(peer_pub, state);

        let info = self
            .peer_info_for(&peer_pub)
            .expect("just inserted")
            .clone();
        let _ = self
            .events_tx
            .send(ApiResponse::EventPeerConnected { peer: info });

        handle
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
        self.push_message_inner(peer_pub, direction, text, false)
    }

    /// Variant of [`Self::push_message`] for messages that arrived
    /// via the hub (sealed-sender envelope, not a direct Noise
    /// session). Same behaviour, but stores + emits with
    /// `via_hub: true` so both the live `EventMessage` and the
    /// `History` backfill carry the weaker-security-tier indicator.
    /// See `SECURITY.md` §6.1 for the PFS/PCS table.
    pub fn push_message_via_hub(
        &mut self,
        peer_pub: &[u8; 32],
        direction: MessageDirection,
        text: String,
    ) -> bool {
        self.push_message_inner(peer_pub, direction, text, true)
    }

    /// Shared body for both push_message variants. Storing `via_hub`
    /// in the ring means a fresh `Tail` subscriber that backfills
    /// via `History` correctly reconstructs the security tier of
    /// each historical message.
    fn push_message_inner(
        &mut self,
        peer_pub: &[u8; 32],
        direction: MessageDirection,
        text: String,
        via_hub: bool,
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
                    via_hub,
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
            via_hub,
        });
        true
    }

    /// T6.3.d: surface a freshly-decoded room application message
    /// as an `EventMessage` whose `peer_short` is the room's
    /// `group_id` short prefix. The TUI room pane (T6.3.f) will
    /// distinguish room events from DM events by inspecting whether
    /// `peer_short` matches a known room. For now this is logging-
    /// adjacent — the live broadcast surfaces the message to any
    /// `Tail` subscriber, and a future T6.3.f will route to the
    /// right pane.
    ///
    /// Room messages are **not** added to any per-peer ring buffer
    /// — `History` is DM-scoped today. Persistent room scrollback
    /// is its own follow-up (CHANNELS.md §8 deferred bullet).
    pub fn push_room_message(
        &mut self,
        group_id: &[u8],
        _sender_peer_pub: [u8; 32],
        text: String,
    ) -> bool {
        let ts_unix_ms = now_unix_ms();
        let peer_short = format!("room/{}", short_id_of_group(group_id));
        let _ = self.events_tx.send(ApiResponse::EventMessage {
            peer_short,
            direction: MessageDirection::Incoming,
            text,
            ts_unix_ms,
            via_hub: false,
        });
        true
    }

    /// Look up a live-session handle by the peer's fingerprint
    /// (T6.3.d: used by `handle_send_room` to find every room
    /// member's direct channel). Returns `None` if no live peer
    /// matches or the peer's session has ended — same semantics as
    /// [`Self::handle_for_short`]. Linear over `by_peer`, which is
    /// fine at v0 scale (single user, a handful of peers).
    #[must_use]
    pub fn handle_for_fingerprint(&self, fingerprint: &str) -> Option<ConversationHandle> {
        for state in self.by_peer.values() {
            if state.connected && state.handle.fingerprint == fingerprint {
                return Some(state.handle.clone());
            }
        }
        None
    }

    /// Look up a handle by the user-facing short_id (e.g. typed into
    /// `onyx send <short> <text>`). Returns `None` if no live peer
    /// matches or the peer's session has ended.
    #[must_use]
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
                    via_hub: line.via_hub,
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

/// User-facing 8-char prefix of an MLS `group_id`, used to label
/// room-tagged events (T6.3.d). `peer_short = "room/<8-char-b32>"`
/// keeps the wire shape backwards-compatible with `EventMessage`'s
/// existing `peer_short` field; clients that don't know about
/// rooms (pre-T6.3.d TUI) render the short id as an unknown peer
/// rather than misrendering it as a DM.
#[must_use]
pub fn short_id_of_group(group_id: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, group_id)
        .chars()
        .take(8)
        .collect()
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
    async fn short_id_collision_does_not_hijack_existing_peer() {
        // P-2: the 8-char short id is grindable; a second peer that
        // collides on it must NOT overwrite the first peer's mapping
        // (which would misdirect the user's short-id sends to the
        // attacker). Both b32 strings share the first 8 chars.
        let mut reg = ConversationRegistry::new();
        let victim_b32 = "aaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let attacker_b32 = "aaaaaaaaccccccccccccccccccccccccccccccccccccc";
        let (victim, _rxv) = reg.register([1u8; 32], victim_b32, "victim-fpr".into());
        let (attacker, _rxa) = reg.register([2u8; 32], attacker_b32, "attacker-fpr".into());

        assert_eq!(
            victim.short_id, attacker.short_id,
            "test setup: the two short ids must collide"
        );
        // Both peers are independently registered (by full key)...
        assert_eq!(reg.list().len(), 2, "both peers should be registered");
        // ...but the short-id lookup still resolves to the FIRST owner,
        // so the user's short-id sends are not hijacked.
        let resolved = reg
            .handle_for_short(&victim.short_id)
            .expect("short id present");
        assert_eq!(
            resolved.peer_pub, victim.peer_pub,
            "a colliding short id must not hijack the original owner"
        );
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
        handle
            .outbound_tx
            .send(PeerOutbound::Dm("hi peer".into()))
            .await
            .unwrap();
        assert_eq!(rx.recv().await.unwrap(), PeerOutbound::Dm("hi peer".into()));
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
    async fn register_hub_only_appears_in_list_as_disconnected() {
        let mut reg = ConversationRegistry::new();
        let h = reg.register_hub_only([0x20; 32], &b32(), "fpr".into());
        assert_eq!(h.short_id.len(), 8);
        let list = reg.list();
        assert_eq!(list.len(), 1);
        // Hub-only peers are "known but not directly connected"; the
        // TUI must show this distinction so users know `Send` won't
        // reach them.
        assert!(!list[0].connected);
        // `handle_for_short` filters out !connected — `Send` errors.
        assert!(reg.handle_for_short(&h.short_id).is_none());
    }

    #[tokio::test]
    async fn register_hub_only_is_idempotent() {
        let mut reg = ConversationRegistry::new();
        let peer_pub = [0x21; 32];
        let h1 = reg.register_hub_only(peer_pub, &b32(), "fpr".into());
        let h2 = reg.register_hub_only(peer_pub, &b32(), "fpr".into());
        // Same logical peer ⇒ same short_id (and registry size stays at 1).
        assert_eq!(h1.short_id, h2.short_id);
        assert_eq!(reg.list().len(), 1);
    }

    #[tokio::test]
    async fn register_hub_only_emits_event_peer_connected_once() {
        let mut reg = ConversationRegistry::new();
        let mut events = reg.subscribe_events();
        let _h = reg.register_hub_only([0x22; 32], &b32(), "fpr".into());
        match events.recv().await.expect("one event") {
            ApiResponse::EventPeerConnected { peer } => {
                assert!(!peer.connected, "hub-only peer surfaces as !connected");
            }
            other => panic!("expected EventPeerConnected, got {other:?}"),
        }
        // Re-registering must NOT emit a second event (idempotent).
        let _h2 = reg.register_hub_only([0x22; 32], &b32(), "fpr".into());
        // tokio::sync::broadcast::Receiver::try_recv returns Empty when nothing else arrived.
        assert!(matches!(
            events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn push_message_via_hub_tags_event() {
        let mut reg = ConversationRegistry::new();
        let h = reg.register_hub_only([0x23; 32], &b32(), "fpr".into());
        let mut events = reg.subscribe_events();
        reg.push_message_via_hub(
            &h.peer_pub,
            MessageDirection::Incoming,
            "hello from afar".into(),
        );
        match events.recv().await.expect("EventMessage") {
            ApiResponse::EventMessage {
                peer_short,
                via_hub,
                text,
                ..
            } => {
                assert_eq!(peer_short, h.short_id);
                assert!(via_hub, "must tag the message as via_hub");
                assert_eq!(text, "hello from afar");
            }
            other => panic!("expected EventMessage, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn hub_only_handle_send_returns_closed_immediately() {
        let mut reg = ConversationRegistry::new();
        let h = reg.register_hub_only([0x24; 32], &b32(), "fpr".into());
        // The Receiver was dropped inside register_hub_only; any
        // try_send should hit Closed almost immediately. (It might
        // succeed once before the channel notices.)
        let first = h.outbound_tx.try_send(PeerOutbound::Dm("msg".into()));
        let second = h.outbound_tx.try_send(PeerOutbound::Dm("msg".into()));
        // At least one of the two attempts must be Closed — a future
        // refactor that silently absorbs all messages into a dropped
        // channel would defeat the whole point of `register_hub_only`.
        assert!(
            matches!(
                first,
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_))
            ) || matches!(
                second,
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_))
            ),
            "outbound_tx on a hub-only handle must error Closed; \
             got first={first:?}, second={second:?}"
        );
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
