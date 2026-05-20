//! Ratatui-based multi-pane TUI.
//!
//! ## Layout
//!
//! ```text
//! ┌─ onyx ──────────────────────────────────────────┐
//! │ Peers & Rooms  │ #<selected>                    │
//! │ ────────────── │ ───────────────────────────── │
//! │ ● peer-a       │ <message scrollback>           │
//! │ ○ peer-b       │                                │
//! │ ◆ #general (3m)│                                │
//! │ ◆ #audit   (2m)│ ┌────────────────────────────┐ │
//! │                │ │ > <composer>               │ │
//! │                │ └────────────────────────────┘ │
//! ├────────────────┴────────────────────────────────┤
//! │ <status bar: tor · onion · peers · unread>      │
//! └──────────────────────────────────────────────────┘
//! ```
//!
//! T6.3.f.2: the left pane shows DM peers (● live / ○ disconnected)
//! AND multi-party rooms (◆ name + member count). Selection cycles
//! through peers first, then rooms; sending dispatches to either
//! [`ApiRequest::Send`] or [`ApiRequest::SendRoom`] based on the
//! selected entry's kind.
//!
//! ## Wiring
//!
//! Three concurrent async sources feed the render loop, multiplexed
//! with `tokio::select!`:
//!
//!   * **status tick** — every 2 s, fire `ApiRequest::Status` and
//!     `ApiRequest::Peers` on a one-shot connection. Updates the
//!     status bar + peer list.
//!   * **tail subscription** — a dedicated long-lived connection
//!     that sends `ApiRequest::Tail` once and then receives
//!     `EventMessage` / `EventPeerConnected` / `EventPeerDisconnected`
//!     until the daemon dies. On disconnect we retry with backoff.
//!   * **keyboard** — a `spawn_blocking` task forwards crossterm
//!     `KeyEvent`s into an mpsc.
//!
//! ## Keys
//!
//!   * `Esc` or `Ctrl-C` — quit (or close active modal).
//!   * `↑` / `↓`            — move peer/room selection.
//!   * `PgUp` / `PgDn`      — scroll the messages pane up / down by 10 lines (T-polish.4).
//!   * `Home`               — jump to oldest scrollback (T-polish.4).
//!   * `End`                — snap back to live (T-polish.4).
//!   * `F1`                 — keyboard help overlay (every binding).
//!   * `Ctrl-K`             — command palette: fuzzy-run any action.
//!   * `Ctrl-N`             — open the Create Room modal (T-polish.6).
//!   * `Ctrl-I`             — open the Invite Peer modal (requires a room selected; T-polish.6).
//!   * `Ctrl-F`             — open the Send File modal (requires a room selected; T-files.e).
//!   * `Ctrl-E`             — build + copy (OSC52) this identity's invite link.
//!   * `Tab` (in modal)     — cycle between input fields.
//!   * `Space` (in modal)   — toggle the focused checkbox (Send File only).
//!   * `Enter`              — send composer text / submit active modal.
//!   * `Backspace`          — delete one char (in composer or modal).
//!   * any other char       — append to composer (snaps back to live) or modal field.
//!
//! ## History backfill
//!
//! On each refresh tick the TUI fetches `History` for any peer whose
//! short_id isn't yet in the `backfilled` set. Replies are merged
//! into the existing scrollback (deduplicated by `(ts_unix_ms, text)`
//! against live entries that arrived during the round-trip). Once a
//! peer is in `backfilled` we don't ask again — live events take
//! over.
//!
//! Room scrollback persists via `ApiRequest::RoomHistory` (T-polish.3);
//! same backfill semantics.
//!
//! ## Unread + sort (T-polish.5)
//!
//! Per-conversation unread counter increments on every incoming
//! `EventMessage` that isn't for the currently-selected entry. Resets
//! on selection. Rendered as a yellow `(N)` badge after the name in
//! the peers/rooms list. Both peers and rooms are sorted by most-
//! recent-activity descending (TUI-tracked `last_activity_ms`,
//! falling back to `created_at_ms` for rooms with no activity yet).

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use onyx_core::api::{
    ApiRequest, ApiResponse, HistoryEntry, MessageDirection, PeerInfo, RoomInfo, TorState,
    decode_response, encode_request_line,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use zeroize::Zeroize;

use base64::Engine as _;

use crate::client;

const STATUS_REFRESH_INTERVAL: Duration = Duration::from_secs(2);

// ── State ────────────────────────────────────────────────────────────────

/// Live data the TUI renders from.
#[derive(Debug, Clone)]
struct AppState {
    socket_path: PathBuf,
    /// Last status response, or an error message if the daemon
    /// was unreachable on the last poll.
    last_status: Option<Result<StatusSnapshot, String>>,
    peers: Vec<PeerInfo>,
    /// Multi-party rooms this daemon participates in (T6.3.f.2).
    /// Fetched via `ApiRequest::ListRooms` alongside peers on every
    /// status tick. Rendered in the same selection list as peers,
    /// below them; selection-indexing logic lives in
    /// [`Self::selected_entry`].
    rooms: Vec<RoomInfo>,
    /// Index into the combined `peers ++ rooms` list (peers first).
    /// Out of range means "no selection". See
    /// [`Self::selected_entry`] for the kind discriminator.
    selected: usize,
    /// Per-conversation scrollback keyed by selector identity:
    ///   * DM peer entries are keyed by `short_id` (8-char base32
    ///     of peer's X25519 pubkey) — same as today.
    ///   * Room entries are keyed by `room/<8-char-b32-of-group_id>`
    ///     — the same key the daemon ships in `EventMessage::peer_short`
    ///     for room messages (T6.3.d), so the apply_event match
    ///     stores them under the room's selector without prefix
    ///     stripping.
    scrollback: HashMap<String, Vec<ChatLine>>,
    /// Bytes the user has typed but not yet sent.
    composer: String,
    /// The most recent `Send` outcome, surfaced as a transient
    /// banner in the composer pane until the next keystroke.
    last_send_result: Option<Result<(), String>>,
    /// Visual indicator of whether the tail connection is alive.
    tail_active: bool,
    /// Set of `short_id`s we've already fetched History for. Prevents
    /// re-firing the backfill request every refresh tick.
    backfilled: HashSet<String>,
    /// T-polish.4: per-conversation scroll offset into the
    /// scrollback. 0 = pinned to the bottom (most recent visible);
    /// positive values scroll up by that many lines. Reset to 0
    /// whenever the user selects a different entry OR types a new
    /// character (the typing-while-scrolled-up case is "I want to
    /// reply to what's on screen — bring me back to live").
    messages_scroll: HashMap<String, u16>,
    /// T-polish.5: per-conversation unread counter, keyed the
    /// same way as `scrollback`. Increments on every incoming
    /// `EventMessage` that isn't for the currently-selected
    /// conversation. Resets to 0 on selection.
    unread: HashMap<String, u32>,
    /// T-polish.5: per-conversation last-activity timestamp
    /// (daemon ms-since-epoch from the most recent EventMessage,
    /// or 0 if we've never seen one). Drives the "most-recent
    /// first" sort in `render_peers`. Outgoing messages also
    /// bump this so the conversation you just talked in stays at
    /// the top.
    last_activity_ms: HashMap<String, u64>,
    /// T-polish.6: active modal overlay. `None` = normal UI;
    /// otherwise key events route to the modal handler and the
    /// main UI is dimmed behind it.
    modal: Option<ModalState>,
    /// T-files.e: file-ids (b32) we've already rendered as inline
    /// `📎 received …` lines in some scrollback. Used to dedupe
    /// the periodic `ListReceivedFiles` poll: a file appears
    /// exactly once in a room's history, no matter how many
    /// refresh ticks fire after it arrives. Globally unique
    /// (BLAKE2b-256 content hash truncated to 32 bytes / 52 b32
    /// chars), so no per-conversation namespacing needed.
    seen_files: HashSet<String>,
    /// UX overhaul: set by the command palette's "Quit" action so the
    /// modal handler can request app exit without rewiring every
    /// modal-key return into a quit signal. Checked by `handle_key`
    /// right after the modal handler runs.
    quit_requested: bool,
}

/// T-polish.6: TUI modals for room operations that can't easily
/// be driven from the composer line. Currently two:
///
///   * **CreateRoom** — single-line input for the room name.
///     Opens on `Ctrl-N`. Submits via `ApiRequest::CreateRoom`.
///   * **InvitePeer** — three multi-line paste fields
///     (fingerprint, KEM pub b32, KP b64). Opens on `Ctrl-I`
///     ONLY when the selected entry is a room (we need its
///     group_id_b32). Submits via `ApiRequest::InviteToRoom`.
///
/// `Tab` cycles between fields in InvitePeer; `Esc` closes
/// without submitting; `Enter` submits.
#[derive(Debug, Clone)]
enum ModalState {
    CreateRoom {
        name: String,
    },
    InvitePeer {
        group_id_b32: String,
        fingerprint: String,
        kem_pub_b32: String,
        kp_b64: String,
        /// Which of the three input fields has focus (0..3).
        focus: usize,
    },
    /// T-files.e: file-picker modal. Opened with Ctrl-F when a
    /// room is selected. Path is a single line; two toggles
    /// (Tab to cycle, Space to flip). Submit dispatches
    /// `ApiRequest::SendFileToRoom`. Strip defaults (keep_metadata
    /// = false, keep_filename = false) match the daemon defaults
    /// from FILES.md §3 — privacy-by-default, with opt-out flags
    /// for the operator who knows what they're doing.
    SendFile {
        group_id_b32: String,
        path: String,
        keep_filename: bool,
        keep_metadata: bool,
        /// 0 = path field, 1 = keep_filename toggle,
        /// 2 = keep_metadata toggle.
        focus: usize,
    },
    /// UX overhaul: full keybinding cheat-sheet overlay. Opens on
    /// `F1`. Any key closes it.
    Help,
    /// UX overhaul: fuzzy command palette. Opens on `Ctrl-K`. Type to
    /// filter the action list; `↑/↓` move the selection; `Enter` runs
    /// the highlighted action; `Esc` closes.
    CommandPalette {
        query: String,
        selected: usize,
    },
    /// UX overhaul: shows this identity's invite URL (built from
    /// Identity + KeyPackage + configured hubs) and whether it was
    /// copied to the clipboard via OSC52. Opens on `Ctrl-E`. The URL
    /// is fetched async when the modal opens.
    Invite {
        url: String,
        copied: bool,
    },
}

/// UX overhaul: actions runnable from the command palette (`Ctrl-K`).
/// Kept as a small enum so the palette list, the fuzzy filter, and the
/// dispatch all stay in sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PaletteAction {
    CreateRoom,
    InvitePeer,
    SendFile,
    CopyInvite,
    Help,
    Quit,
}

impl PaletteAction {
    /// All actions, in palette display order.
    const ALL: [PaletteAction; 6] = [
        PaletteAction::CreateRoom,
        PaletteAction::InvitePeer,
        PaletteAction::SendFile,
        PaletteAction::CopyInvite,
        PaletteAction::Help,
        PaletteAction::Quit,
    ];

    /// Human label shown in the palette.
    fn label(self) -> &'static str {
        match self {
            PaletteAction::CreateRoom => "Create room",
            PaletteAction::InvitePeer => "Invite peer to room",
            PaletteAction::SendFile => "Send file to room",
            PaletteAction::CopyInvite => "Copy my invite link",
            PaletteAction::Help => "Show keyboard help",
            PaletteAction::Quit => "Quit Onyx",
        }
    }

    /// The keybinding hint shown on the right of the palette row.
    fn key_hint(self) -> &'static str {
        match self {
            PaletteAction::CreateRoom => "^N",
            PaletteAction::InvitePeer => "^I",
            PaletteAction::SendFile => "^F",
            PaletteAction::CopyInvite => "^E",
            PaletteAction::Help => "F1",
            PaletteAction::Quit => "^C",
        }
    }
}

/// What the current selection refers to (T6.3.f.2). `Peer` drives
/// DM `Send`s; `Room` drives multi-party `SendRoom`s. The composer
/// pane title and the send dispatcher both branch on this.
#[derive(Debug, Clone)]
enum SelectedEntry<'a> {
    Peer(&'a PeerInfo),
    Room(&'a RoomInfo),
}

impl SelectedEntry<'_> {
    /// User-facing short identifier — the key used in `scrollback`
    /// and rendered in titles. Same shape on both wire and TUI.
    fn scrollback_key(&self) -> String {
        match self {
            Self::Peer(p) => p.short_id.clone(),
            Self::Room(r) => format!("room/{}", short_id(&r.group_id_b32)),
        }
    }
}

#[derive(Debug, Clone)]
struct StatusSnapshot {
    daemon_version: String,
    #[allow(dead_code)] // surfaced via the API; not currently shown in the bar
    identity_pub_b32: String,
    fingerprint: String,
    tor_state: TorState,
}

#[derive(Debug, Clone)]
struct ChatLine {
    direction: MessageDirection,
    text: String,
    /// Daemon wall clock at the moment the line was created. Used for
    /// deduplication when history backfill races with live events.
    ts_unix_ms: u64,
    /// `true` when this message arrived via the hub (sealed-sender
    /// envelope, weaker forward-secrecy properties than direct MLS).
    /// Rendered as a yellow `[hub]` badge in the conversation pane
    /// so users can read the security tier at a glance.
    via_hub: bool,
}

impl AppState {
    fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            last_status: None,
            peers: Vec::new(),
            rooms: Vec::new(),
            selected: 0,
            scrollback: HashMap::new(),
            composer: String::new(),
            last_send_result: None,
            tail_active: false,
            backfilled: HashSet::new(),
            messages_scroll: HashMap::new(),
            unread: HashMap::new(),
            last_activity_ms: HashMap::new(),
            modal: None,
            seen_files: HashSet::new(),
            quit_requested: false,
        }
    }

    /// Total count of selectable entries (peers + rooms).
    fn total_entries(&self) -> usize {
        self.peers.len() + self.rooms.len()
    }

    /// What's currently selected, if anything. Selection layout is
    /// peers first, then rooms — so index `n < peers.len()` is a
    /// peer, and `n - peers.len()` is the room slot.
    fn selected_entry(&self) -> Option<SelectedEntry<'_>> {
        if self.selected < self.peers.len() {
            self.peers.get(self.selected).map(SelectedEntry::Peer)
        } else {
            let room_idx = self.selected - self.peers.len();
            self.rooms.get(room_idx).map(SelectedEntry::Room)
        }
    }

    /// T-polish.4: scroll the message pane by `lines` (positive =
    /// up, negative = down). Clamped at 0 (back to live); upper
    /// bound is enforced by the render call (it caps to the actual
    /// scrollback height).
    fn scroll_messages(&mut self, lines: i16) {
        let Some(key) = self.selected_entry().map(|e| e.scrollback_key()) else {
            return;
        };
        let cur = self.messages_scroll.get(&key).copied().unwrap_or(0);
        let next = if lines >= 0 {
            cur.saturating_add(lines.unsigned_abs())
        } else {
            cur.saturating_sub(lines.unsigned_abs())
        };
        self.messages_scroll.insert(key, next);
    }

    /// T-polish.4: snap the messages pane back to live (offset 0)
    /// for the current selection. Called on send/typing.
    fn snap_messages_to_live(&mut self) {
        if let Some(key) = self.selected_entry().map(|e| e.scrollback_key()) {
            self.messages_scroll.insert(key, 0);
        }
    }

    /// T-polish.4: read the current scroll offset for the selected
    /// entry. Default 0 (live).
    fn current_messages_scroll(&self) -> u16 {
        self.selected_entry()
            .map(|e| e.scrollback_key())
            .and_then(|k| self.messages_scroll.get(&k).copied())
            .unwrap_or(0)
    }

    fn move_selection(&mut self, delta: isize) {
        let n = self.total_entries();
        if n == 0 {
            self.selected = 0;
            return;
        }
        let cur = self.selected.min(n - 1);
        // Stepwise so we never need signed arithmetic: handle the two
        // unit-step cases the UI actually emits (±1) directly. Other
        // deltas wrap correctly modulo n by chained applications.
        let next = if delta >= 0 {
            (cur + delta.unsigned_abs() % n) % n
        } else {
            let step = delta.unsigned_abs() % n;
            (cur + n - step) % n
        };
        let changed = self.selected != next;
        self.selected = next;
        if changed {
            // T-polish.4: switching conversations resets the new
            // entry's scroll to live (offset 0). Doesn't touch
            // other entries' scrolls — they're preserved per-key.
            self.snap_messages_to_live();
            // T-polish.5: selecting an entry clears its unread
            // count. The user is now looking at it.
            if let Some(key) = self.selected_entry().map(|e| e.scrollback_key()) {
                self.unread.remove(&key);
            }
        }
    }

    /// Apply one event coming from the tail subscription. Returns
    /// `true` if the screen needs a re-render.
    fn apply_event(&mut self, ev: ApiResponse) -> bool {
        match ev {
            ApiResponse::EventMessage {
                peer_short,
                direction,
                text,
                ts_unix_ms,
                via_hub,
            } => {
                // T-polish.5: bump activity timestamp + unread
                // counter (only for incoming; outgoing doesn't
                // imply "needs attention"). Don't bump unread if
                // the event is for the currently-selected
                // entry — the user is already looking at it.
                self.last_activity_ms.insert(peer_short.clone(), ts_unix_ms);
                let is_selected =
                    self.selected_entry().map(|e| e.scrollback_key()) == Some(peer_short.clone());
                if matches!(direction, MessageDirection::Incoming) && !is_selected {
                    *self.unread.entry(peer_short.clone()).or_insert(0) += 1;
                }
                self.scrollback
                    .entry(peer_short)
                    .or_default()
                    .push(ChatLine {
                        direction,
                        text,
                        ts_unix_ms,
                        via_hub,
                    });
                true
            }
            ApiResponse::EventPeerConnected { peer } => {
                self.upsert_peer(peer);
                true
            }
            ApiResponse::EventPeerDisconnected { peer_short } => {
                if let Some(p) = self.peers.iter_mut().find(|p| p.short_id == peer_short) {
                    p.connected = false;
                }
                true
            }
            ApiResponse::TailStarted => {
                self.tail_active = true;
                true
            }
            // Status/Peers/Identity responses don't arrive on the tail
            // socket; ignore anything unexpected without crashing.
            _ => false,
        }
    }

    /// Replace existing peers entry with same short_id, or append.
    fn upsert_peer(&mut self, peer: PeerInfo) {
        if let Some(slot) = self.peers.iter_mut().find(|p| p.short_id == peer.short_id) {
            *slot = peer;
        } else {
            self.peers.push(peer);
        }
    }

    fn apply_peers_snapshot(&mut self, mut new_peers: Vec<PeerInfo>) {
        // Most-recently-active first (descending). sort_by_key with
        // `Reverse` keeps clippy happy and avoids the manual closure.
        new_peers.sort_by_key(|p| std::cmp::Reverse(p.last_active_unix_ms));
        let prev_key = self.selected_entry().map(|e| e.scrollback_key());
        self.peers = new_peers;
        if let Some(key) = prev_key {
            self.restore_selection_by_key(&key);
        }
    }

    /// T6.3.f.2: refresh the room list from a `ListRoomsOk`. Same
    /// "preserve selection by key" pattern as `apply_peers_snapshot`.
    /// T-polish.5: sort by last-activity desc (TUI-tracked
    /// `last_activity_ms`, falling back to `created_at_ms` for
    /// rooms that haven't seen activity yet).
    fn apply_rooms_snapshot(&mut self, mut new_rooms: Vec<RoomInfo>) {
        let activity_map = self.last_activity_ms.clone();
        new_rooms.sort_by_key(|r| {
            let key = format!("room/{}", short_id(&r.group_id_b32));
            std::cmp::Reverse(activity_map.get(&key).copied().unwrap_or(r.created_at_ms))
        });
        let prev_key = self.selected_entry().map(|e| e.scrollback_key());
        self.rooms = new_rooms;
        if let Some(key) = prev_key {
            self.restore_selection_by_key(&key);
        }
    }

    /// Reposition `selected` to the entry whose `scrollback_key`
    /// matches `key`, if it still exists in the combined list. No-op
    /// otherwise.
    fn restore_selection_by_key(&mut self, key: &str) {
        if let Some(idx) = self.peers.iter().position(|p| p.short_id == *key) {
            self.selected = idx;
            return;
        }
        if let Some(idx) = self
            .rooms
            .iter()
            .position(|r| format!("room/{}", short_id(&r.group_id_b32)) == key)
        {
            self.selected = self.peers.len() + idx;
        }
    }
}

// ── Entry point ──────────────────────────────────────────────────────────

pub async fn run(socket_path: PathBuf) -> anyhow::Result<()> {
    let mut terminal = setup_terminal()?;
    let panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = teardown_terminal_global();
        panic_hook(info);
    }));

    let mut app = AppState::new(socket_path.clone());

    // Background: tail subscription (reconnects automatically).
    let (tail_tx, tail_rx) = mpsc::channel::<ApiResponse>(256);
    let tail_socket = socket_path.clone();
    tokio::spawn(async move {
        run_tail_subscriber(tail_socket, tail_tx).await;
    });

    // Background: keyboard. spawn_blocking → blocking_send.
    let (key_tx, key_rx) = mpsc::channel::<KeyEvent>(64);
    tokio::task::spawn_blocking(move || {
        run_keyboard_pump(&key_tx);
    });

    // Initial refresh so the bar isn't blank on first paint.
    refresh_status_and_peers(&socket_path, &mut app).await;

    let result = event_loop(&mut terminal, &mut app, key_rx, tail_rx).await;

    teardown_terminal(&mut terminal)?;
    result
}

// ── Event loop ───────────────────────────────────────────────────────────

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut AppState,
    mut key_rx: mpsc::Receiver<KeyEvent>,
    mut tail_rx: mpsc::Receiver<ApiResponse>,
) -> anyhow::Result<()> {
    let mut tick = tokio::time::interval(STATUS_REFRESH_INTERVAL);
    // First `tick` fires immediately; we already refreshed, skip it.
    tick.tick().await;

    loop {
        terminal.draw(|frame| render(frame, app))?;

        tokio::select! {
            Some(key) = key_rx.recv() => {
                if handle_key(app, key).await {
                    break;
                }
            }
            Some(event) = tail_rx.recv() => {
                app.apply_event(event);
            }
            _ = tick.tick() => {
                refresh_status_and_peers(&app.socket_path.clone(), app).await;
            }
        }
    }

    Ok(())
}

/// Returns `true` if the loop should exit.
async fn handle_key(app: &mut AppState, key: KeyEvent) -> bool {
    if key.kind != KeyEventKind::Press {
        return false;
    }
    // Clear the transient banner on any keystroke.
    app.last_send_result = None;

    // T-polish.6: route keys to the modal handler when one is
    // open. The modal handler returns Ok(true) on close (back to
    // main UI) or Err(_) if the key wasn't consumed and should
    // fall through to the main handler — currently nothing falls
    // through (Esc closes modal; everything else is consumed by
    // the active field).
    if app.modal.is_some() {
        handle_modal_key(app, key).await;
        // The command palette's Quit action sets this; everything
        // else leaves it false.
        return app.quit_requested;
    }

    match (key.code, key.modifiers) {
        // T-polish.6: Ctrl-N opens the create-room modal.
        (KeyCode::Char('n'), m) if m.contains(KeyModifiers::CONTROL) => {
            app.modal = Some(ModalState::CreateRoom {
                name: String::new(),
            });
            return false;
        }
        // T-polish.6: Ctrl-I opens the invite-peer modal — but
        // only when the selected entry is a room (we need its
        // group_id_b32 to invite into).
        (KeyCode::Char('i'), m) if m.contains(KeyModifiers::CONTROL) => {
            if let Some(SelectedEntry::Room(r)) = app.selected_entry() {
                app.modal = Some(ModalState::InvitePeer {
                    group_id_b32: r.group_id_b32.clone(),
                    fingerprint: String::new(),
                    kem_pub_b32: String::new(),
                    kp_b64: String::new(),
                    focus: 0,
                });
            } else {
                app.last_send_result = Some(Err("invite-peer needs a room selected".to_string()));
            }
            return false;
        }
        // T-files.e: Ctrl-F opens the send-file modal. Same
        // selection gate as Ctrl-I — files only flow into rooms
        // today (DM file sending is documented out of scope in
        // FILES.md §7). Defaults match daemon defaults: strip
        // metadata + replace filename. The operator can flip
        // both toggles in the modal.
        (KeyCode::Char('f'), m) if m.contains(KeyModifiers::CONTROL) => {
            if let Some(SelectedEntry::Room(r)) = app.selected_entry() {
                app.modal = Some(ModalState::SendFile {
                    group_id_b32: r.group_id_b32.clone(),
                    path: String::new(),
                    keep_filename: false,
                    keep_metadata: false,
                    focus: 0,
                });
            } else {
                app.last_send_result = Some(Err("send-file needs a room selected".to_string()));
            }
            return false;
        }
        // UX overhaul: F1 opens the keybinding help overlay.
        (KeyCode::F(1), _) => {
            app.modal = Some(ModalState::Help);
            return false;
        }
        // UX overhaul: Ctrl-K opens the fuzzy command palette.
        (KeyCode::Char('k'), m) if m.contains(KeyModifiers::CONTROL) => {
            app.modal = Some(ModalState::CommandPalette {
                query: String::new(),
                selected: 0,
            });
            return false;
        }
        // UX overhaul: Ctrl-E builds + shows + copies the invite link.
        (KeyCode::Char('e'), m) if m.contains(KeyModifiers::CONTROL) => {
            open_invite_modal(app).await;
            return false;
        }
        (KeyCode::Esc, _) => return true,
        (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => return true,
        (KeyCode::Up, _) => app.move_selection(-1),
        (KeyCode::Down, _) => app.move_selection(1),
        // T-polish.4: scroll the messages pane. PgUp/PgDn scroll
        // by 10 lines (one "page" for typical terminal heights).
        // Home jumps to oldest (huge offset, render clamps it to
        // the actual scrollback length). End / Ctrl-End snaps
        // back to live.
        (KeyCode::PageUp, _) => app.scroll_messages(10),
        (KeyCode::PageDown, _) => app.scroll_messages(-10),
        (KeyCode::Home, _) => app.scroll_messages(i16::MAX),
        (KeyCode::End, _) => app.snap_messages_to_live(),
        (KeyCode::Backspace, _) => {
            app.composer.pop();
        }
        (KeyCode::Enter, _) => {
            send_composer(app).await;
            // T-polish.4: snap back to live on send so the user
            // sees their own message land.
            app.snap_messages_to_live();
        }
        (KeyCode::Char(c), _) => {
            app.composer.push(c);
            // T-polish.4: typing while scrolled up is a strong
            // "I want to reply to what's on screen" — snap back
            // to live so the next render shows the message they
            // were composing for.
            app.snap_messages_to_live();
        }
        _ => {}
    }
    false
}

/// T-polish.6: route a key to the active modal. Esc closes
/// without submitting; Enter submits; Tab cycles focus in the
/// multi-field InvitePeer modal; everything else appends to the
/// focused field (Backspace pops).
// Modal handler is a single linear keystroke dispatcher with many
// match arms; clippy lints fire on individual arms but the whole
// shape is the most readable form (each arm handles one
// (modal-variant, key) pair with explicit modal-put-back).
#[allow(
    clippy::too_many_lines,
    clippy::collapsible_if,
    clippy::collapsible_match,
    clippy::if_not_else
)]
async fn handle_modal_key(app: &mut AppState, key: KeyEvent) {
    // Take + put back so we can mutate without fighting the borrow
    // checker over `app` being borrowed by `app.modal`.
    let Some(mut modal) = app.modal.take() else {
        return;
    };
    let submit_intent: Option<ModalState>;
    match (&mut modal, key.code) {
        // Esc closes any modal without submitting. Help + Invite are
        // read-only overlays, so ANY key dismisses them too.
        (_, KeyCode::Esc) | (ModalState::Help | ModalState::Invite { .. }, _) => {
            return;
        }
        // UX overhaul: command palette navigation + filtering.
        (ModalState::CommandPalette { selected, .. }, KeyCode::Up) => {
            *selected = selected.saturating_sub(1);
            app.modal = Some(modal);
            return;
        }
        (ModalState::CommandPalette { query, selected }, KeyCode::Down) => {
            let n = palette_filter(query).len();
            if n > 0 {
                *selected = (*selected + 1).min(n - 1);
            }
            app.modal = Some(modal);
            return;
        }
        (ModalState::CommandPalette { query, selected }, KeyCode::Backspace) => {
            query.pop();
            *selected = 0;
            app.modal = Some(modal);
            return;
        }
        (ModalState::CommandPalette { query, selected }, KeyCode::Enter) => {
            let action = palette_filter(query).get(*selected).copied();
            // Modal consumed (not put back). Running the action either
            // opens the relevant modal, performs the action, or (Quit)
            // sets app.quit_requested.
            if let Some(a) = action {
                run_palette_action(app, a).await;
            }
            return;
        }
        (ModalState::CommandPalette { query, selected }, KeyCode::Char(c)) => {
            query.push(c);
            *selected = 0;
            app.modal = Some(modal);
            return;
        }
        (ModalState::CreateRoom { name }, KeyCode::Enter) => {
            if name.trim().is_empty() {
                app.modal = Some(modal);
                return;
            }
            submit_intent = Some(modal.clone());
        }
        (ModalState::CreateRoom { name }, KeyCode::Backspace) => {
            name.pop();
            app.modal = Some(modal);
            return;
        }
        (ModalState::CreateRoom { name }, KeyCode::Char(c)) => {
            name.push(c);
            app.modal = Some(modal);
            return;
        }
        (
            ModalState::InvitePeer {
                fingerprint,
                kem_pub_b32,
                kp_b64,
                focus,
                ..
            },
            KeyCode::Tab,
        ) => {
            *focus = (*focus + 1) % 3;
            let _ = (fingerprint, kem_pub_b32, kp_b64);
            app.modal = Some(modal);
            return;
        }
        (
            ModalState::InvitePeer {
                fingerprint,
                kem_pub_b32,
                kp_b64,
                focus,
                ..
            },
            KeyCode::Backspace,
        ) => {
            match *focus {
                0 => {
                    fingerprint.pop();
                }
                1 => {
                    kem_pub_b32.pop();
                }
                _ => {
                    kp_b64.pop();
                }
            }
            app.modal = Some(modal);
            return;
        }
        (
            ModalState::InvitePeer {
                fingerprint,
                kem_pub_b32,
                kp_b64,
                focus,
                ..
            },
            KeyCode::Char(c),
        ) => {
            match *focus {
                0 => fingerprint.push(c),
                1 => kem_pub_b32.push(c),
                _ => kp_b64.push(c),
            }
            app.modal = Some(modal);
            return;
        }
        (ModalState::InvitePeer { .. }, KeyCode::Enter) => {
            submit_intent = Some(modal.clone());
        }
        // T-files.e SendFile arms: Tab cycles (path → keep_filename
        // → keep_metadata → path), Space toggles the focused
        // checkbox, Char appends to path, Backspace pops from
        // path, Enter submits.
        (ModalState::SendFile { focus, .. }, KeyCode::Tab) => {
            *focus = (*focus + 1) % 3;
            app.modal = Some(modal);
            return;
        }
        (
            ModalState::SendFile {
                keep_filename,
                keep_metadata,
                focus,
                ..
            },
            KeyCode::Char(' '),
        ) if *focus != 0 => {
            if *focus == 1 {
                *keep_filename = !*keep_filename;
            } else {
                *keep_metadata = !*keep_metadata;
            }
            app.modal = Some(modal);
            return;
        }
        (ModalState::SendFile { path, focus, .. }, KeyCode::Backspace) if *focus == 0 => {
            path.pop();
            app.modal = Some(modal);
            return;
        }
        (ModalState::SendFile { path, focus, .. }, KeyCode::Char(c)) if *focus == 0 => {
            path.push(c);
            app.modal = Some(modal);
            return;
        }
        (ModalState::SendFile { path, .. }, KeyCode::Enter) => {
            if path.trim().is_empty() {
                app.modal = Some(modal);
                return;
            }
            submit_intent = Some(modal.clone());
        }
        _ => {
            app.modal = Some(modal);
            return;
        }
    }
    // Submit path (modal was consumed; don't put back).
    if let Some(submit) = submit_intent {
        let req = match submit {
            ModalState::CreateRoom { name } => Some(ApiRequest::CreateRoom { name }),
            ModalState::InvitePeer {
                group_id_b32,
                fingerprint,
                kem_pub_b32,
                kp_b64,
                ..
            } => Some(ApiRequest::InviteToRoom {
                group_id_b32,
                peer_fingerprint: fingerprint,
                peer_kem_pub_b32: kem_pub_b32,
                peer_kp_b64: kp_b64,
            }),
            // T-files.e: SendFile dispatches to the same daemon
            // handler the CLI calls (`onyx room send-file`). The
            // modal trims the path so trailing whitespace from
            // paste-into-terminal doesn't blow up open().
            ModalState::SendFile {
                group_id_b32,
                path,
                keep_filename,
                keep_metadata,
                ..
            } => Some(ApiRequest::SendFileToRoom {
                group_id_b32,
                path: path.trim().to_string(),
                keep_filename,
                keep_metadata,
            }),
            // Help / CommandPalette / Invite never set submit_intent
            // (they're handled inline above), so they can't reach here.
            ModalState::Help | ModalState::CommandPalette { .. } | ModalState::Invite { .. } => {
                None
            }
        };
        if let Some(req) = req {
            match client::one_shot(&app.socket_path, &req).await {
                Ok(ApiResponse::CreateRoomOk { name, .. }) => {
                    app.last_send_result = Some(Ok(()));
                    tracing::info!(room = %name, "room created via TUI modal");
                }
                Ok(ApiResponse::InviteToRoomOk { members, .. }) => {
                    app.last_send_result = Some(Ok(()));
                    tracing::info!(roster = members.len(), "invited via TUI modal");
                }
                Ok(ApiResponse::SendFileToRoomOk {
                    group_id_b32,
                    file_id_b32,
                    size,
                    mime,
                    stripped_metadata,
                    chunks,
                    delivered_to_direct,
                    delivered_to_hub,
                    skipped_no_kem,
                    total_members,
                }) => {
                    // T-files.e: surface delivery counts the same
                    // way SendRoomOk does. Also append a local
                    // "you sent <file>" line so the operator sees
                    // their own upload in the scrollback (the
                    // daemon does NOT echo outgoing files back as
                    // events — same rationale as SendRoomOk).
                    let key = format!("room/{}", short_id(&group_id_b32));
                    let now = now_unix_ms();
                    let label = format!(
                        "📎 sent {} ({} bytes, {}, {} chunks{})",
                        short_id(&file_id_b32),
                        size,
                        mime,
                        chunks,
                        if stripped_metadata { ", stripped" } else { "" }
                    );
                    app.scrollback
                        .entry(key.clone())
                        .or_default()
                        .push(ChatLine {
                            direction: MessageDirection::Outgoing,
                            text: label,
                            ts_unix_ms: now,
                            via_hub: false,
                        });
                    app.last_activity_ms.insert(key, now);
                    app.last_send_result = Some(Ok(()));
                    tracing::info!(
                        delivered_to_direct,
                        delivered_to_hub,
                        skipped_no_kem,
                        total_members,
                        "file send delivery counts"
                    );
                }
                Ok(ApiResponse::Error { message, .. }) => {
                    app.last_send_result = Some(Err(message));
                }
                Ok(other) => {
                    app.last_send_result = Some(Err(format!("unexpected response: {other:?}")));
                }
                Err(e) => {
                    app.last_send_result = Some(Err(format!("{e:#}")));
                }
            }
        }
    }
}

/// UX overhaul: filter the palette actions by a case-insensitive
/// substring of the action label. Empty query → all actions.
fn palette_filter(query: &str) -> Vec<PaletteAction> {
    let q = query.trim().to_lowercase();
    PaletteAction::ALL
        .into_iter()
        .filter(|a| q.is_empty() || a.label().to_lowercase().contains(&q))
        .collect()
}

/// UX overhaul: run a command-palette action. Opens the relevant
/// modal, performs the action, or (Quit) sets `app.quit_requested`.
async fn run_palette_action(app: &mut AppState, action: PaletteAction) {
    match action {
        PaletteAction::CreateRoom => {
            app.modal = Some(ModalState::CreateRoom {
                name: String::new(),
            });
        }
        PaletteAction::InvitePeer => {
            if let Some(SelectedEntry::Room(r)) = app.selected_entry() {
                app.modal = Some(ModalState::InvitePeer {
                    group_id_b32: r.group_id_b32.clone(),
                    fingerprint: String::new(),
                    kem_pub_b32: String::new(),
                    kp_b64: String::new(),
                    focus: 0,
                });
            } else {
                app.last_send_result = Some(Err("invite-peer needs a room selected".to_string()));
            }
        }
        PaletteAction::SendFile => {
            if let Some(SelectedEntry::Room(r)) = app.selected_entry() {
                app.modal = Some(ModalState::SendFile {
                    group_id_b32: r.group_id_b32.clone(),
                    path: String::new(),
                    keep_filename: false,
                    keep_metadata: false,
                    focus: 0,
                });
            } else {
                app.last_send_result = Some(Err("send-file needs a room selected".to_string()));
            }
        }
        PaletteAction::CopyInvite => open_invite_modal(app).await,
        PaletteAction::Help => app.modal = Some(ModalState::Help),
        PaletteAction::Quit => app.quit_requested = true,
    }
}

/// UX overhaul: build this identity's invite URL, copy it to the
/// system clipboard (OSC52), and open the Invite modal showing the
/// URL + whether the copy succeeded.
async fn open_invite_modal(app: &mut AppState) {
    match build_invite_url(&app.socket_path).await {
        Ok(url) => {
            let copied = osc52_copy(&url).is_ok();
            app.modal = Some(ModalState::Invite { url, copied });
        }
        Err(e) => {
            app.last_send_result = Some(Err(format!("invite: {e:#}")));
        }
    }
}

/// UX overhaul: assemble an `onyx://invite/v1?…` URL from the daemon's
/// Identity + a fresh KeyPackage + the configured hub list — the same
/// bundle `onyx invite --with-kp --with-hubs` produces on the CLI.
async fn build_invite_url(socket: &Path) -> anyhow::Result<String> {
    let id = client::one_shot(socket, &ApiRequest::Identity).await?;
    let (fingerprint, kem, hubs) = match id {
        ApiResponse::IdentityOk {
            fingerprint,
            identity_kem_pub_b32,
            hubs,
            ..
        } => (fingerprint, identity_kem_pub_b32, hubs),
        other => anyhow::bail!("unexpected Identity response: {other:?}"),
    };
    let fp = onyx_core::crypto::Fingerprint::parse(&fingerprint)?;
    let kp = client::one_shot(socket, &ApiRequest::ExportKeyPackage).await?;
    let mut invite = match kp {
        ApiResponse::ExportKeyPackageOk { kp_b64 } => {
            let kp_bytes = base64::engine::general_purpose::STANDARD.decode(kp_b64)?;
            onyx_core::invite::Invite::with_key_package(fp, kem, kp_bytes)
        }
        // No KP available → fall back to a PFS-only (msg/v1) invite.
        _ => onyx_core::invite::Invite::new(fp, kem),
    };
    if !hubs.is_empty() {
        invite = invite.with_hubs(hubs);
    }
    Ok(invite.to_url())
}

/// UX overhaul: copy `text` to the terminal's clipboard via the OSC52
/// escape sequence. Works over SSH and inside the alternate screen on
/// terminals that support it (iTerm2, kitty, wezterm, modern xterm,
/// tmux with `set -g set-clipboard on`). On terminals that don't, the
/// sequence is silently ignored — the Invite modal still shows the URL
/// for manual selection, so this is best-effort.
fn osc52_copy(text: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
    let seq = format!("\x1b]52;c;{b64}\x07");
    let mut out = std::io::stdout();
    out.write_all(seq.as_bytes())?;
    out.flush()
}

async fn send_composer(app: &mut AppState) {
    if app.composer.is_empty() {
        return;
    }
    // T6.3.f.2: clone the bits we need out of the borrow before we
    // mutate `app.composer` — the selection borrow holds `app`
    // immutably otherwise.
    let dispatch = match app.selected_entry() {
        Some(SelectedEntry::Peer(p)) => SendDispatch::Dm(p.short_id.clone()),
        Some(SelectedEntry::Room(r)) => SendDispatch::Room(r.group_id_b32.clone()),
        None => {
            app.last_send_result = Some(Err("no conversation selected".to_string()));
            return;
        }
    };
    let mut text = std::mem::take(&mut app.composer);
    let req = match &dispatch {
        SendDispatch::Dm(short) => ApiRequest::Send {
            peer_short: short.clone(),
            text: text.clone(),
        },
        SendDispatch::Room(gid_b32) => ApiRequest::SendRoom {
            group_id_b32: gid_b32.clone(),
            text: text.clone(),
        },
    };
    match client::one_shot(&app.socket_path, &req).await {
        Ok(ApiResponse::SendOk) => {
            app.last_send_result = Some(Ok(()));
            // T-zeroize-audit: scrub the local text buffer after a
            // successful send. The cloned copy that rode in the
            // ApiRequest::Send is gone by now (consumed during the
            // socket write). Don't push into scrollback here — the
            // daemon broadcasts an `EventMessage { direction:
            // Outgoing }` for the send, which the tail loop will
            // deliver and apply_event will record. Pushing here
            // would double up.
            text.zeroize();
        }
        Ok(ApiResponse::SendRoomOk {
            delivered_to_direct,
            delivered_to_hub,
            skipped_no_kem,
            total_members,
            ..
        }) => {
            // T6.3.f.2: surface room-send delivery counts so the user
            // sees which members got the message and which didn't.
            // The daemon does NOT echo room sends back as Outgoing
            // EventMessages (the conversation registry is DM-only,
            // T6.3.d note); push our own local line so the scrollback
            // shows what we said.
            let key = format!("room/{}", short_id(&dispatch.b32_key()));
            let now = now_unix_ms();
            app.scrollback
                .entry(key.clone())
                .or_default()
                .push(ChatLine {
                    direction: MessageDirection::Outgoing,
                    text: text.clone(),
                    ts_unix_ms: now,
                    via_hub: false,
                });
            // T-polish.5: bump activity so this room stays at the
            // top of the activity-sorted list.
            app.last_activity_ms.insert(key, now);
            app.last_send_result = Some(Ok(()));
            tracing::info!(
                delivered_to_direct,
                delivered_to_hub,
                skipped_no_kem,
                total_members,
                "room send delivery counts"
            );
            text.zeroize();
        }
        Ok(ApiResponse::Error { message, .. }) => {
            app.composer = text; // restore so user can edit & retry
            app.last_send_result = Some(Err(message));
        }
        Ok(other) => {
            app.composer = text;
            app.last_send_result = Some(Err(format!("unexpected response: {other:?}")));
        }
        Err(e) => {
            app.composer = text;
            app.last_send_result = Some(Err(format!("{e:#}")));
        }
    }
}

/// What a composer-send should target. Built from the selection
/// before any borrow of `app` is mutated so the call site doesn't
/// fight the borrow checker.
#[derive(Debug, Clone)]
enum SendDispatch {
    Dm(String),
    Room(String),
}

impl SendDispatch {
    fn b32_key(&self) -> String {
        match self {
            Self::Dm(short) => short.clone(),
            Self::Room(gid_b32) => gid_b32.clone(),
        }
    }
}

fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

async fn refresh_status_and_peers(socket: &Path, app: &mut AppState) {
    // Status
    match client::one_shot(socket, &ApiRequest::Status).await {
        Ok(ApiResponse::StatusOk {
            daemon_version,
            identity_pub_b32,
            fingerprint,
            tor_state,
            ..
        }) => {
            app.last_status = Some(Ok(StatusSnapshot {
                daemon_version,
                identity_pub_b32,
                fingerprint,
                tor_state,
            }));
        }
        Ok(ApiResponse::Error { code, message }) => {
            app.last_status = Some(Err(format!("daemon error: {code:?}: {message}")));
        }
        Ok(other) => {
            app.last_status = Some(Err(format!("unexpected response: {other:?}")));
        }
        Err(e) => {
            app.last_status = Some(Err(format!("{e:#}")));
        }
    }

    // Peers — best-effort; don't overwrite the previous snapshot on
    // transient failure (the status field above will show the error).
    if let Ok(ApiResponse::PeersOk { entries }) = client::one_shot(socket, &ApiRequest::Peers).await
    {
        app.apply_peers_snapshot(entries);
    }

    // T6.3.f.2: rooms — same best-effort policy. Refreshed every
    // status tick so newly created/joined rooms surface in the pane
    // without restart.
    if let Ok(ApiResponse::ListRoomsOk { rooms }) =
        client::one_shot(socket, &ApiRequest::ListRooms).await
    {
        app.apply_rooms_snapshot(rooms);
    }

    // History backfill for any peer we haven't fetched yet. Cheap to
    // run every tick because the `backfilled` set short-circuits the
    // common case.
    let to_backfill: Vec<String> = app
        .peers
        .iter()
        .filter(|p| !app.backfilled.contains(&p.short_id))
        .map(|p| p.short_id.clone())
        .collect();
    for short in to_backfill {
        let req = ApiRequest::History {
            peer_short: short.clone(),
            limit: 200,
        };
        if let Ok(ApiResponse::HistoryOk {
            peer_short,
            messages,
        }) = client::one_shot(socket, &req).await
        {
            merge_history(app, &peer_short, messages);
            app.backfilled.insert(peer_short);
        }
        // Any non-Ok or non-HistoryOk: leave unbackfilled, retry next tick.
    }

    // T-files.e: poll for received files on every room we know
    // about. Cheap (one round-trip per room) and bounded by room
    // count, which is small. `seen_files` dedupes across ticks
    // so an already-rendered attachment doesn't get re-added on
    // every refresh.
    //
    // Why per-room and not a single global list: scrollback is
    // per-conversation; we need to know which key to push the
    // line into. The daemon's `ListReceivedFiles` is already
    // scoped that way (`conversation` is the request key).
    let room_keys: Vec<(String, String)> = app
        .rooms
        .iter()
        .map(|r| {
            (
                r.group_id_b32.clone(),
                format!("room/{}", short_id(&r.group_id_b32)),
            )
        })
        .collect();
    for (_gid_b32, conv_key) in room_keys {
        let req = ApiRequest::ListReceivedFiles {
            conversation: conv_key.clone(),
            limit: 200,
        };
        if let Ok(ApiResponse::ListReceivedFilesOk { files, .. }) =
            client::one_shot(socket, &req).await
        {
            apply_received_files(app, &conv_key, files);
        }
    }
}

/// T-files.e: merge the daemon's per-room file list into the
/// scrollback as `📎 received NAME (size, mime) → PATH` lines.
/// Dedupes against `app.seen_files` (the file-id b32, BLAKE2b-256
/// content hash) so the periodic poll only adds each file once.
/// Lines are inserted in ts order; existing live lines retain
/// their position — `received_at_ms` from the manifest is the
/// timestamp.
fn apply_received_files(
    app: &mut AppState,
    conv_key: &str,
    files: Vec<onyx_core::api::ReceivedFileInfo>,
) {
    if files.is_empty() {
        return;
    }
    let mut additions: Vec<ChatLine> = Vec::new();
    for f in files {
        if !app.seen_files.insert(f.content_hash_b32.clone()) {
            continue;
        }
        let label = format!(
            "📎 received {} ({} bytes, {}) → {}",
            f.name, f.size, f.mime, f.path
        );
        additions.push(ChatLine {
            direction: MessageDirection::Incoming,
            text: label,
            ts_unix_ms: f.received_at_ms,
            via_hub: false,
        });
        // T-polish.5: count new files toward unread when they're
        // not in the active selection.
        let active_key = app
            .selected_entry()
            .map(|e| e.scrollback_key())
            .unwrap_or_default();
        if active_key != conv_key {
            *app.unread.entry(conv_key.to_string()).or_insert(0) += 1;
        }
        let prev = app.last_activity_ms.get(conv_key).copied().unwrap_or(0);
        if f.received_at_ms > prev {
            app.last_activity_ms
                .insert(conv_key.to_string(), f.received_at_ms);
        }
    }
    if additions.is_empty() {
        return;
    }
    let entry = app.scrollback.entry(conv_key.to_string()).or_default();
    entry.extend(additions);
    entry.sort_by_key(|l| l.ts_unix_ms);
}

/// Merge `messages` (oldest → newest) into the front of the scrollback
/// for `peer_short`, deduplicating against any already-stored live
/// entries by `(ts_unix_ms, text)`. Live entries that happened during
/// the History fetch keep their position at the end of the buffer.
fn merge_history(app: &mut AppState, peer_short: &str, messages: Vec<HistoryEntry>) {
    let entry = app.scrollback.entry(peer_short.to_string()).or_default();
    if messages.is_empty() {
        return;
    }
    let live_keys: HashSet<(u64, String)> = entry
        .iter()
        .map(|l| (l.ts_unix_ms, l.text.clone()))
        .collect();
    let mut prepend: Vec<ChatLine> = messages
        .into_iter()
        .filter(|m| !live_keys.contains(&(m.ts_unix_ms, m.text.clone())))
        .map(|m| ChatLine {
            direction: m.direction,
            text: m.text,
            ts_unix_ms: m.ts_unix_ms,
            via_hub: m.via_hub,
        })
        .collect();
    let existing = std::mem::take(entry);
    prepend.extend(existing);
    *entry = prepend;
}

// ── Background tasks ─────────────────────────────────────────────────────

/// Long-lived tail subscriber. Connects, sends Tail, forwards every
/// event into the mpsc until the connection drops, then reconnects
/// with a small backoff.
async fn run_tail_subscriber(socket_path: PathBuf, tx: mpsc::Sender<ApiResponse>) {
    let mut delay = Duration::from_millis(250);
    loop {
        match try_tail_once(&socket_path, &tx).await {
            Ok(()) | Err(_) => {
                // Reset backoff on successful establishment (the inner
                // loop returned Ok only when the channel closed — the
                // app is shutting down, time to exit).
                tokio::time::sleep(delay).await;
                delay = std::cmp::min(delay * 2, Duration::from_secs(5));
            }
        }
        if tx.is_closed() {
            return;
        }
    }
}

async fn try_tail_once(socket_path: &Path, tx: &mpsc::Sender<ApiResponse>) -> anyhow::Result<()> {
    let stream = UnixStream::connect(socket_path)
        .await
        .context("tail: connect")?;
    let (read_half, mut write_half) = stream.into_split();
    let line = encode_request_line(&ApiRequest::Tail).context("encode tail")?;
    write_half
        .write_all(line.as_bytes())
        .await
        .context("write tail request")?;

    let mut lines = BufReader::new(read_half).lines();
    while let Some(line) = lines.next_line().await? {
        let resp =
            decode_response(&line).with_context(|| format!("decode tail response: {line:?}"))?;
        if tx.send(resp).await.is_err() {
            // Receiver gone — app is shutting down.
            return Ok(());
        }
    }
    Ok(())
}

fn run_keyboard_pump(tx: &mpsc::Sender<KeyEvent>) {
    loop {
        match crossterm::event::read() {
            Ok(Event::Key(k)) => {
                if tx.blocking_send(k).is_err() {
                    return;
                }
            }
            Ok(_) => {} // mouse, resize, etc.
            Err(_) => return,
        }
    }
}

// ── Rendering ────────────────────────────────────────────────────────────

fn render(frame: &mut ratatui::Frame<'_>, app: &AppState) {
    let area = frame.area();

    let outer = Block::default().borders(Borders::ALL).title(Span::styled(
        " onyx ",
        Style::default().add_modifier(Modifier::BOLD),
    ));
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(inner);
    let main_area = chunks[0];
    let status_area = chunks[1];

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(22), Constraint::Min(0)])
        .split(main_area);
    let peers_area = cols[0];
    let chat_col = cols[1];

    let chat_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(chat_col);
    let messages_area = chat_rows[0];
    let composer_area = chat_rows[1];

    render_peers(frame, peers_area, app);
    render_messages(frame, messages_area, app);
    render_composer(frame, composer_area, app);
    render_status(frame, status_area, app);

    // T-polish.6: modal overlay rendered LAST so it draws on top
    // of the main UI. Centered, fixed width.
    if let Some(modal) = &app.modal {
        render_modal(frame, area, modal);
    }
}

/// T-polish.6: render the active modal as a centered overlay.
// Three variants × ~40 lines each puts the total over the 100-line
// clippy default. Each variant block is self-contained (different
// fields, different layouts) so splitting into helpers would just
// chase the line count around without improving readability.
#[allow(clippy::too_many_lines)]
fn render_modal(frame: &mut ratatui::Frame<'_>, area: Rect, modal: &ModalState) {
    // Compute a centered region. Width = min(76, area.width - 4).
    let width = area.width.saturating_sub(4).min(76);
    let height = match modal {
        ModalState::CreateRoom { .. } => 7,
        ModalState::InvitePeer { .. } => 17,
        ModalState::SendFile { .. } => 13,
        ModalState::Help => 18,
        ModalState::CommandPalette { .. } => {
            u16::try_from(PaletteAction::ALL.len() + 6).unwrap_or(12)
        }
        ModalState::Invite { .. } => 11,
    };
    let x = (area.width.saturating_sub(width)) / 2;
    let y = (area.height.saturating_sub(height)) / 2;
    let rect = Rect::new(x, y, width, height);
    // Clear behind the modal so the underlying UI doesn't bleed through.
    frame.render_widget(ratatui::widgets::Clear, rect);
    match modal {
        ModalState::CreateRoom { name } => {
            let block = Block::default().borders(Borders::ALL).title(Span::styled(
                " Create Room  (Esc=cancel, Enter=submit) ",
                Style::default().add_modifier(Modifier::BOLD),
            ));
            let body = Paragraph::new(vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled(" Name: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        name.clone(),
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    " The name is local-only — each member can call ",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    " the same MLS group whatever they like. ",
                    Style::default().fg(Color::DarkGray),
                )),
            ])
            .block(block);
            frame.render_widget(body, rect);
        }
        ModalState::InvitePeer {
            group_id_b32,
            fingerprint,
            kem_pub_b32,
            kp_b64,
            focus,
        } => {
            let block = Block::default().borders(Borders::ALL).title(Span::styled(
                " Invite Peer  (Tab=cycle, Esc=cancel, Enter=submit) ",
                Style::default().add_modifier(Modifier::BOLD),
            ));
            let inviting = format!(" → room/{} ", short_id(group_id_b32));
            let mk_field = |label: &str, val: &str, idx: usize| -> Line<'_> {
                let focus_marker = if *focus == idx { "▶ " } else { "  " };
                Line::from(vec![
                    Span::styled(
                        format!("{focus_marker}{label}: "),
                        Style::default().fg(if *focus == idx {
                            Color::Yellow
                        } else {
                            Color::Gray
                        }),
                    ),
                    Span::styled(
                        truncate_for_display(val, 60),
                        Style::default().fg(Color::White),
                    ),
                ])
            };
            let body = Paragraph::new(vec![
                Line::from(Span::styled(inviting, Style::default().fg(Color::Magenta))),
                Line::from(""),
                mk_field("Fingerprint", fingerprint, 0),
                Line::from(""),
                mk_field("KEM pub (b32)", kem_pub_b32, 1),
                Line::from(""),
                mk_field("KP (b64)", kp_b64, 2),
                Line::from(""),
                Line::from(Span::styled(
                    " Paste each long field then press Tab.",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    " Get KP via `onyx fetch-keypackage --peer-fingerprint X`.",
                    Style::default().fg(Color::DarkGray),
                )),
            ])
            .block(block);
            frame.render_widget(body, rect);
        }
        ModalState::SendFile {
            group_id_b32,
            path,
            keep_filename,
            keep_metadata,
            focus,
        } => {
            // T-files.e: send-file modal. Three rows. Path is a
            // free-form line; the two toggles are rendered as
            // [x]/[ ] checkboxes. Hint at the bottom reminds the
            // operator what defaults-off means (FILES.md §3).
            let block = Block::default().borders(Borders::ALL).title(Span::styled(
                " Send File  (Tab=cycle, Space=toggle, Esc=cancel, Enter=send) ",
                Style::default().add_modifier(Modifier::BOLD),
            ));
            let sending_to = format!(" → room/{} ", short_id(group_id_b32));
            let path_focused = *focus == 0;
            let path_line = Line::from(vec![
                Span::styled(
                    if path_focused {
                        "▶ Path: "
                    } else {
                        "  Path: "
                    },
                    Style::default().fg(if path_focused {
                        Color::Yellow
                    } else {
                        Color::Gray
                    }),
                ),
                Span::styled(
                    truncate_for_display(path, 60),
                    Style::default().fg(Color::White),
                ),
                if path_focused {
                    Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK))
                } else {
                    Span::raw("")
                },
            ]);
            let mk_toggle = |label: &str, val: bool, idx: usize| -> Line<'_> {
                let focused = *focus == idx;
                let box_glyph = if val { "[x]" } else { "[ ]" };
                Line::from(vec![
                    Span::styled(
                        if focused { "▶ " } else { "  " },
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::styled(
                        format!("{box_glyph} {label}"),
                        Style::default().fg(if focused { Color::Yellow } else { Color::White }),
                    ),
                ])
            };
            let body = Paragraph::new(vec![
                Line::from(Span::styled(
                    sending_to,
                    Style::default().fg(Color::Magenta),
                )),
                Line::from(""),
                path_line,
                Line::from(""),
                mk_toggle(
                    "Keep original filename (otherwise random)",
                    *keep_filename,
                    1,
                ),
                mk_toggle("Keep metadata (no EXIF/etc. strip)", *keep_metadata, 2),
                Line::from(""),
                Line::from(Span::styled(
                    " Default: strip metadata + random filename (privacy first).",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    " Sender-side size cap applies — see FILES.md §4.",
                    Style::default().fg(Color::DarkGray),
                )),
            ])
            .block(block);
            frame.render_widget(body, rect);
        }
        ModalState::Help => render_help_modal(frame, rect),
        ModalState::CommandPalette { query, selected } => {
            render_palette_modal(frame, rect, query, *selected);
        }
        ModalState::Invite { url, copied } => render_invite_modal(frame, rect, url, *copied),
    }
}

/// UX overhaul: keybinding cheat-sheet overlay (F1). Two columns of
/// `key — action` rows, grouped.
fn render_help_modal(frame: &mut ratatui::Frame<'_>, rect: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Span::styled(
            " Keyboard Help  (any key to close) ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
    let key = |k: &str, d: &str| -> Line<'static> {
        Line::from(vec![
            Span::styled(
                format!("  {k:<10}"),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(d.to_string(), Style::default().fg(Color::White)),
        ])
    };
    let head = |t: &str| -> Line<'static> {
        Line::from(Span::styled(
            format!(" {t}"),
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ))
    };
    let body = Paragraph::new(vec![
        head("Navigation"),
        key("↑ / ↓", "move between conversations"),
        key("PgUp/PgDn", "scroll messages · Home/End jump"),
        key("Enter", "send the composed message"),
        Line::from(""),
        head("Actions"),
        key("Ctrl-K", "command palette (run anything)"),
        key("Ctrl-N", "create a room / channel"),
        key("Ctrl-I", "invite a peer to the selected room"),
        key("Ctrl-F", "send a file to the selected room"),
        key("Ctrl-E", "copy my invite link to clipboard"),
        Line::from(""),
        head("General"),
        key("F1", "this help · Esc/any key closes overlays"),
        key("Ctrl-C / Esc", "quit Onyx"),
    ])
    .block(block);
    frame.render_widget(body, rect);
}

/// UX overhaul: fuzzy command palette (Ctrl-K).
fn render_palette_modal(frame: &mut ratatui::Frame<'_>, rect: Rect, query: &str, selected: usize) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow))
        .title(Span::styled(
            " Command Palette  (type to filter · ↑↓ · Enter · Esc) ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
    let matches = palette_filter(query);
    let mut lines: Vec<Line> = Vec::with_capacity(matches.len() + 2);
    lines.push(Line::from(vec![
        Span::styled(" ▸ ", Style::default().fg(Color::Yellow)),
        Span::styled(
            query.to_string(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
    ]));
    lines.push(Line::from(""));
    if matches.is_empty() {
        lines.push(Line::from(Span::styled(
            "   (no matching command)",
            Style::default().fg(Color::DarkGray),
        )));
    }
    for (i, action) in matches.iter().enumerate() {
        let sel = i == selected;
        let marker = if sel { "▶ " } else { "  " };
        let row_style = if sel {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {marker}{:<28}", action.label()), row_style),
            Span::styled(
                action.key_hint().to_string(),
                Style::default().fg(if sel { Color::Black } else { Color::DarkGray }),
            ),
        ]));
    }
    frame.render_widget(Paragraph::new(lines).block(block), rect);
}

/// UX overhaul: invite-link overlay (Ctrl-E). Shows the URL and
/// whether it was copied to the clipboard.
fn render_invite_modal(frame: &mut ratatui::Frame<'_>, rect: Rect, url: &str, copied: bool) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green))
        .title(Span::styled(
            " Your Invite Link  (any key to close) ",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ));
    let status = if copied {
        Line::from(Span::styled(
            " ✓ copied to clipboard (OSC52)",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ))
    } else {
        Line::from(Span::styled(
            " ⚠ clipboard copy unavailable — select the text below to copy",
            Style::default().fg(Color::Yellow),
        ))
    };
    let body = Paragraph::new(vec![
        Line::from(""),
        status,
        Line::from(""),
        Line::from(Span::styled(
            url.to_string(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            " Share this with a friend; they run `onyx accept <url>`.",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .block(block)
    .wrap(Wrap { trim: false });
    frame.render_widget(body, rect);
}

/// Truncate `s` for display in the modal — long base32/base64 fields
/// would otherwise wrap and break the layout. Shows the first N
/// chars + "…(LEN)" so the user knows it's not empty even when
/// hidden.
fn truncate_for_display(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max.saturating_sub(8)).collect();
        format!("{head}…({})", s.len())
    }
}

fn render_peers(frame: &mut ratatui::Frame<'_>, area: Rect, app: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Peers & Rooms ");
    if app.peers.is_empty() && app.rooms.is_empty() {
        let body = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                " (nothing yet)",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            Line::from(Span::styled(
                " start onyxd with",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                " --dial-onion / --dial-pubkey",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                " for a DM, or",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                " `onyx room create --name X`",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                " for a multi-party room.",
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .block(block);
        frame.render_widget(body, area);
        return;
    }

    let mut items: Vec<ListItem<'_>> = Vec::with_capacity(app.peers.len() + app.rooms.len());
    for p in &app.peers {
        let dot = if p.connected {
            Span::styled("● ", Style::default().fg(Color::Green))
        } else {
            Span::styled("○ ", Style::default().fg(Color::DarkGray))
        };
        let name = Span::styled(
            p.short_id.clone(),
            Style::default()
                .fg(if p.connected {
                    Color::White
                } else {
                    Color::DarkGray
                })
                .add_modifier(if p.connected {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                }),
        );
        let mut spans = vec![dot, name];
        // T-polish.5: unread badge on the right.
        if let Some(&n) = app.unread.get(&p.short_id)
            && n > 0
        {
            spans.push(Span::styled(
                format!(" ({n})"),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        items.push(ListItem::new(Line::from(spans)));
    }
    for r in &app.rooms {
        let label = format!("#{} ({}m)", r.name, r.members.len());
        let mut spans = vec![
            Span::styled("◆ ", Style::default().fg(Color::Magenta)),
            Span::styled(label, Style::default().fg(Color::White)),
        ];
        let room_key = format!("room/{}", short_id(&r.group_id_b32));
        if let Some(&n) = app.unread.get(&room_key)
            && n > 0
        {
            spans.push(Span::styled(
                format!(" ({n})"),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        items.push(ListItem::new(Line::from(spans)));
    }
    let list = List::new(items)
        .block(block)
        .highlight_style(Style::default().bg(Color::DarkGray).fg(Color::White))
        .highlight_symbol("▶ ");
    let total = app.total_entries();
    let mut state = ListState::default();
    state.select(Some(app.selected.min(total.saturating_sub(1))));
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_messages(frame: &mut ratatui::Frame<'_>, area: Rect, app: &AppState) {
    let (title, scrollback_key, who_label) = match app.selected_entry() {
        Some(SelectedEntry::Peer(p)) => (
            format!(" #{} ", p.short_id),
            p.short_id.clone(),
            p.short_id.clone(),
        ),
        Some(SelectedEntry::Room(r)) => (
            format!(" #{} (room, {} members) ", r.name, r.members.len()),
            format!("room/{}", short_id(&r.group_id_b32)),
            format!("#{}", r.name),
        ),
        None => (" Conversation ".to_string(), String::new(), String::new()),
    };
    let block = Block::default().borders(Borders::ALL).title(title);
    if app.selected_entry().is_none() {
        let body = Paragraph::new(vec![
            Line::from(Span::styled(
                "No conversation selected.",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Use ↑/↓ to pick a peer or room once one shows up.",
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .block(block)
        .wrap(Wrap { trim: false });
        frame.render_widget(body, area);
        return;
    }
    let lines: Vec<Line<'_>> = match app.scrollback.get(&scrollback_key) {
        Some(scroll) if !scroll.is_empty() => scroll
            .iter()
            .map(|line| {
                let (who, color) = match line.direction {
                    MessageDirection::Incoming => (who_label.as_str(), Color::Cyan),
                    MessageDirection::Outgoing => ("me", Color::Green),
                };
                let mut spans: Vec<Span<'_>> = Vec::with_capacity(3);
                spans.push(Span::styled(
                    format!("{who:>10}: "),
                    Style::default().fg(color),
                ));
                if line.via_hub {
                    spans.push(Span::styled(
                        "[hub] ",
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ));
                }
                spans.push(Span::raw(line.text.clone()));
                Line::from(spans)
            })
            .collect(),
        _ => vec![Line::from(Span::styled(
            "(no messages yet — send one below)",
            Style::default().fg(Color::DarkGray),
        ))],
    };
    // T-polish.4: bottom-anchored scroll. Live (offset 0) shows
    // the most recent messages; PgUp scrolls back. We count
    // LOGICAL lines (one per ChatLine), not visually-wrapped
    // lines — close enough for a usable scroll without needing
    // ratatui's internal wrapping math. PgUp(10) moves 10
    // logical messages even if they each wrap to 3 visual lines.
    let total_lines = u16::try_from(lines.len()).unwrap_or(u16::MAX);
    let viewport = area.height.saturating_sub(2); // borders
    let user_scroll = app.current_messages_scroll();
    let bottom_anchor = total_lines.saturating_sub(viewport);
    // Clamp user_scroll so we don't scroll past the oldest line.
    let clamped_user_scroll = user_scroll.min(bottom_anchor);
    let scroll = bottom_anchor.saturating_sub(clamped_user_scroll);
    let body = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    frame.render_widget(body, area);
}

fn render_composer(frame: &mut ratatui::Frame<'_>, area: Rect, app: &AppState) {
    let block = Block::default().borders(Borders::ALL).title(" Compose ");

    let line = if let Some(Err(msg)) = &app.last_send_result {
        Line::from(vec![
            Span::styled(" send failed: ", Style::default().fg(Color::Red)),
            Span::raw(msg.clone()),
        ])
    } else if let Some(Ok(())) = &app.last_send_result {
        Line::from(vec![
            Span::styled(" sent ✓ ", Style::default().fg(Color::Green)),
            Span::raw("— "),
            Span::raw(app.composer.clone()),
        ])
    } else if app.selected_entry().is_none() {
        Line::from(Span::styled(
            " > (no peer or room to send to)",
            Style::default().fg(Color::DarkGray),
        ))
    } else {
        Line::from(vec![
            Span::raw(" > "),
            Span::styled(
                app.composer.clone(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
        ])
    };
    frame.render_widget(Paragraph::new(line).block(block), area);
}

fn render_status(frame: &mut ratatui::Frame<'_>, area: Rect, app: &AppState) {
    let line = match &app.last_status {
        None => Line::from(Span::styled(
            " connecting to daemon… ",
            Style::default().fg(Color::Yellow),
        )),
        Some(Err(e)) => Line::from(vec![
            Span::styled(
                " daemon unreachable: ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(e.clone()),
            Span::styled("  · Esc to quit", Style::default().fg(Color::DarkGray)),
        ]),
        Some(Ok(s)) => {
            let tor = match s.tor_state {
                TorState::Ready => Span::styled("tor ready", Style::default().fg(Color::Green)),
                TorState::Disabled => {
                    Span::styled("tor disabled", Style::default().fg(Color::Yellow))
                }
            };
            let live = if app.tail_active {
                Span::styled("● live", Style::default().fg(Color::Green))
            } else {
                Span::styled("○ no tail", Style::default().fg(Color::Red))
            };
            let live_count = app.peers.iter().filter(|p| p.connected).count();
            Line::from(vec![
                Span::raw(" "),
                tor,
                Span::raw("  ·  "),
                live,
                Span::raw("  ·  "),
                Span::styled("you ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    short_id(&s.fingerprint),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  ·  "),
                Span::styled(
                    format!(
                        "{live_count} peer{}",
                        if live_count == 1 { "" } else { "s" }
                    ),
                    Style::default().fg(Color::Gray),
                ),
                Span::raw("  ·  "),
                Span::styled(
                    format!("v{}", s.daemon_version),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw("   "),
                // UX overhaul: colored, always-visible keybind hints.
                kb("F1"),
                Span::styled("help ", Style::default().fg(Color::Gray)),
                kb("^K"),
                Span::styled("palette ", Style::default().fg(Color::Gray)),
                kb("^N"),
                Span::styled("room ", Style::default().fg(Color::Gray)),
                kb("^F"),
                Span::styled("file ", Style::default().fg(Color::Gray)),
                kb("^E"),
                Span::styled("invite", Style::default().fg(Color::Gray)),
            ])
        }
    };
    frame.render_widget(Paragraph::new(line), area);
}

/// UX overhaul: render a keybinding chip for the footer (bold yellow
/// key + trailing space).
fn kb(key: &str) -> Span<'static> {
    Span::styled(
        format!("{key} "),
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )
}

fn short_id(s: &str) -> String {
    s.chars().take(8).collect()
}

// ── Terminal lifecycle ───────────────────────────────────────────────────

fn setup_terminal() -> anyhow::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;
    Ok(terminal)
}

fn teardown_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> anyhow::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn teardown_terminal_global() -> anyhow::Result<()> {
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}

// ── Snapshot tests (render-only) ─────────────────────────────────────────

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn mock_app_with_status(tor_state: TorState) -> AppState {
        let mut app = AppState::new(PathBuf::from("./onyxd.sock"));
        app.last_status = Some(Ok(StatusSnapshot {
            daemon_version: "0.0.1".to_string(),
            identity_pub_b32: "fudqeber2e4dutmkw3yahejh6gpemta3k6vx6no55h65pmpmimkq".to_string(),
            fingerprint: "6dzx yrut hgez rucw js3g fpdu xggt jn7r 53on aowq iop5 nvmx fk7q"
                .to_string(),
            tor_state,
        }));
        app
    }

    fn mock_app_with_peers_and_scrollback() -> AppState {
        let mut app = mock_app_with_status(TorState::Ready);
        app.tail_active = true;
        app.peers = vec![
            PeerInfo {
                short_id: "u5lhmxps".into(),
                pubkey_b32: "u5lhmxpsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".into(),
                fingerprint: "fpr".into(),
                connected: true,
                last_message_preview: Some("how's the audit?".into()),
                last_active_unix_ms: 1_700_000_000_000,
            },
            PeerInfo {
                short_id: "k9rfthxz".into(),
                pubkey_b32: "k9rfthxzxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".into(),
                fingerprint: "fpr2".into(),
                connected: false,
                last_message_preview: Some("see you at 3?".into()),
                last_active_unix_ms: 1_699_900_000_000,
            },
        ];
        app.scrollback.insert(
            "u5lhmxps".into(),
            vec![
                ChatLine {
                    direction: MessageDirection::Incoming,
                    text: "hi (first contact via hub)".into(),
                    ts_unix_ms: 1_700_000_000_000,
                    via_hub: true,
                },
                ChatLine {
                    direction: MessageDirection::Incoming,
                    text: "hi".into(),
                    ts_unix_ms: 1_700_000_000_005,
                    via_hub: false,
                },
                ChatLine {
                    direction: MessageDirection::Outgoing,
                    text: "hey".into(),
                    ts_unix_ms: 1_700_000_000_010,
                    via_hub: false,
                },
                ChatLine {
                    direction: MessageDirection::Incoming,
                    text: "how's the audit?".into(),
                    ts_unix_ms: 1_700_000_000_020,
                    via_hub: false,
                },
            ],
        );
        app.composer = "looking good — found a bug in §5".to_string();
        app
    }

    fn render_to_string(app: &AppState, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal.draw(|frame| render(frame, app)).expect("draw");
        let buffer = terminal.backend().buffer();
        let mut out = String::with_capacity(usize::from(width + 1) * usize::from(height));
        for y in 0..height {
            for x in 0..width {
                let cell = &buffer.content[usize::from(y) * usize::from(width) + usize::from(x)];
                out.push_str(cell.symbol());
            }
            out.push('\n');
        }
        out
    }

    fn snapshot_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("target")
    }

    #[test]
    fn dump_snapshot_empty() {
        let app = mock_app_with_status(TorState::Ready);
        let snap = render_to_string(&app, 90, 24);
        let dir = snapshot_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("tui-snapshot.txt"), &snap).unwrap();
        assert!(snap.contains("onyx"));
        // T6.3.f.2: pane title is now "Peers & Rooms"; empty-state
        // copy changed from "(no peers yet)" to "(nothing yet)".
        assert!(snap.contains("Peers"));
        assert!(snap.contains("(nothing yet)"));
    }

    #[test]
    fn dump_snapshot_with_rooms() {
        // T6.3.f.2: a populated room list must render below peers
        // with the [diamond] glyph + name + member count.
        let mut app = mock_app_with_peers_and_scrollback();
        app.rooms = vec![
            RoomInfo {
                name: "general".into(),
                group_id_b32: "abcdefghijkl".into(),
                members: vec!["fp_alice".into(), "fp_bob".into()],
                created_at_ms: 1_700_000_000_000,
            },
            RoomInfo {
                name: "audit".into(),
                group_id_b32: "mnopqrstuvwx".into(),
                members: vec!["fp_alice".into(), "fp_bob".into(), "fp_carol".into()],
                created_at_ms: 1_700_000_010_000,
            },
        ];
        let snap = render_to_string(&app, 90, 24);
        assert!(
            snap.contains("#general"),
            "room name must render with `#` prefix; got:\n{snap}"
        );
        assert!(
            snap.contains("(2m)"),
            "room member count must render; got:\n{snap}"
        );
        assert!(
            snap.contains("#audit"),
            "second room must render; got:\n{snap}"
        );
        assert!(
            snap.contains("(3m)"),
            "second room's member count must render; got:\n{snap}"
        );
    }

    #[test]
    fn selected_entry_indexes_rooms_after_peers() {
        let mut app = mock_app_with_peers_and_scrollback();
        app.rooms = vec![RoomInfo {
            name: "r1".into(),
            group_id_b32: "g1".into(),
            members: vec![],
            created_at_ms: 0,
        }];
        // 2 peers (indices 0..1) + 1 room (index 2)
        app.selected = 0;
        assert!(matches!(app.selected_entry(), Some(SelectedEntry::Peer(_))));
        app.selected = 1;
        assert!(matches!(app.selected_entry(), Some(SelectedEntry::Peer(_))));
        app.selected = 2;
        assert!(matches!(app.selected_entry(), Some(SelectedEntry::Room(_))));
        app.selected = 3;
        assert!(app.selected_entry().is_none());
    }

    #[test]
    fn dump_snapshot_with_chat() {
        let app = mock_app_with_peers_and_scrollback();
        let snap = render_to_string(&app, 90, 24);
        let dir = snapshot_dir();
        std::fs::write(dir.join("tui-snapshot-chat.txt"), &snap).unwrap();
        assert!(snap.contains("u5lhmxps"));
        assert!(snap.contains("how's the audit?"));
        assert!(snap.contains("looking good"));
        assert!(snap.contains("● live"));
        // T5.2.f: hub-relayed messages must visibly carry the
        // weaker-security-tier indicator. If this assertion ever
        // regresses, users would silently lose the ability to read
        // which messages have MLS PCS and which don't.
        assert!(
            snap.contains("[hub]"),
            "via_hub messages must render the [hub] badge; snapshot:\n{snap}"
        );
    }

    #[test]
    fn merge_history_dedupes_against_live_entries() {
        let mut app = mock_app_with_status(TorState::Ready);
        // Pretend the live tail already delivered one message.
        app.scrollback.insert(
            "u5lhmxps".into(),
            vec![ChatLine {
                direction: MessageDirection::Incoming,
                text: "live-3".into(),
                ts_unix_ms: 3_000,
                via_hub: false,
            }],
        );
        // History returns three messages including one that matches
        // the live entry exactly — the dup must drop, not stack.
        // One history entry is via-hub to verify the tier indicator
        // round-trips through merge_history.
        let history = vec![
            HistoryEntry {
                direction: MessageDirection::Incoming,
                text: "old-1".into(),
                ts_unix_ms: 1_000,
                via_hub: true,
            },
            HistoryEntry {
                direction: MessageDirection::Outgoing,
                text: "old-2".into(),
                ts_unix_ms: 2_000,
                via_hub: false,
            },
            HistoryEntry {
                direction: MessageDirection::Incoming,
                text: "live-3".into(),
                ts_unix_ms: 3_000,
                via_hub: false,
            },
        ];
        merge_history(&mut app, "u5lhmxps", history);
        let entries = app.scrollback.get("u5lhmxps").unwrap();
        let texts: Vec<&str> = entries.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts, ["old-1", "old-2", "live-3"]);
        // Tier preserved through merge: old-1 stays via_hub.
        assert!(entries[0].via_hub, "history's via_hub must propagate");
        assert!(!entries[1].via_hub);
        assert!(!entries[2].via_hub);
    }

    #[test]
    fn merge_history_empty_inserts_marker() {
        let mut app = mock_app_with_status(TorState::Ready);
        merge_history(&mut app, "fresh", vec![]);
        // Entry exists (so we won't keep retrying) but is empty.
        let s = app.scrollback.get("fresh").unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn apply_received_files_dedupes_across_polls_and_orders_by_ts() {
        // T-files.e: the periodic ListReceivedFiles poll must add
        // each file exactly once even when it appears in every
        // tick's response. Also: additions sort into the existing
        // scrollback by ts_unix_ms so a later-discovered older
        // file doesn't jump to the bottom.
        let mut app = mock_app_with_status(TorState::Ready);
        // Pretend there's already a live text message in the room
        // at ts=2000.
        let conv = "room/abcdefgh";
        app.scrollback.insert(
            conv.into(),
            vec![ChatLine {
                direction: MessageDirection::Outgoing,
                text: "hi".into(),
                ts_unix_ms: 2_000,
                via_hub: false,
            }],
        );
        let f1 = onyx_core::api::ReceivedFileInfo {
            sender_fp: "(peer)".into(),
            name: "early.txt".into(),
            mime: "text/plain".into(),
            size: 4,
            content_hash_b32: "HASH-A".into(),
            path: "/tmp/a".into(),
            received_at_ms: 1_000,
        };
        let f2 = onyx_core::api::ReceivedFileInfo {
            sender_fp: "(peer)".into(),
            name: "late.txt".into(),
            mime: "text/plain".into(),
            size: 4,
            content_hash_b32: "HASH-B".into(),
            path: "/tmp/b".into(),
            received_at_ms: 3_000,
        };
        apply_received_files(&mut app, conv, vec![f1.clone(), f2.clone()]);
        let entries = app.scrollback.get(conv).unwrap();
        // Order: early.txt (1000), hi (2000), late.txt (3000).
        let texts: Vec<&str> = entries.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts.len(), 3);
        assert!(texts[0].starts_with("📎 received early.txt"));
        assert_eq!(texts[1], "hi");
        assert!(texts[2].starts_with("📎 received late.txt"));
        // Second tick with same files: must not double-add.
        apply_received_files(&mut app, conv, vec![f1, f2]);
        assert_eq!(app.scrollback.get(conv).unwrap().len(), 3);
    }

    #[test]
    fn select_wraps_around() {
        let mut app = mock_app_with_peers_and_scrollback();
        assert_eq!(app.selected, 0);
        app.move_selection(1);
        assert_eq!(app.selected, 1);
        app.move_selection(1);
        assert_eq!(app.selected, 0);
        app.move_selection(-1);
        assert_eq!(app.selected, 1);
    }
}
