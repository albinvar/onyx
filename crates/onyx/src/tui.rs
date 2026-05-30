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
//! Rooms get the same treatment via `ApiRequest::RoomHistory`,
//! tracked by the separate `backfilled_rooms` set (task 320) — room
//! scrollback reloads on restart with the same dedup semantics as DMs.
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
use crate::theme;

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
    /// Rooms (by `room/<short>` key) whose persisted history we've
    /// already fetched via `RoomHistory`. Mirrors `backfilled` for
    /// DMs so room scrollback reloads on restart instead of vanishing.
    backfilled_rooms: HashSet<String>,
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
        /// Where the file goes — a room (`SendFileToRoom`) or a
        /// directly-connected DM peer (`SendFileToPeer`, task 322).
        target: FileTarget,
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
    /// Task 324: read-only settings / identity panel — your
    /// fingerprint, KEM pubkey, Tor state, daemon version, and
    /// configured hubs. Fetched async on open (via the command
    /// palette). Any key closes. Runtime config (cover traffic,
    /// intro-inbox) is set at daemon launch and not shown here.
    Settings {
        info: Vec<(String, String)>,
    },
    /// UX overhaul phase 4: scrollable daemon-log overlay. Opens on
    /// `Ctrl-L`. `lines` is a snapshot of the tail of ~/.onyx/onyx.log
    /// captured when the modal opens; `scroll` is lines-from-bottom
    /// (0 = newest pinned to the bottom). PgUp/PgDn/Home/End scroll;
    /// Esc or any other key closes. Color-coded by log level.
    Logs {
        lines: Vec<String>,
        scroll: u16,
    },
    /// v0.1.12: paste a peer's `onyx://invite/v…` URL and accept it
    /// in-app — the TUI equivalent of `onyx accept <url>`. Opens on
    /// `Ctrl-A` or via the command palette. `input` is the single
    /// text field; `Enter` dispatches `ApiRequest::SendInvite` (the
    /// daemon re-parses + re-verifies the URL, cross-checks the pin
    /// store, and picks the tier). `Esc` closes without sending.
    AcceptInvite {
        input: String,
    },
    /// v0.1.12: TUI-managed hub / dial / reachability editor. Reads
    /// `~/.onyx/config.json` on open and writes it back on save (Ctrl-S).
    /// Changes apply on the next `onyx` launch (the embedded daemon
    /// reads config at boot — live apply is a later follow-up). `focus`
    /// selects the active control: 0 = add-hub input, 1 = dial onion,
    /// 2 = dial pubkey, 3 = reachability toggle, 4.. = an existing hub
    /// row (Enter/Del removes it). Tab / ↑↓ move focus.
    ManageHubs {
        hubs: Vec<String>,
        add_input: String,
        dial_onion: String,
        dial_pubkey: String,
        reachable: bool,
        focus: usize,
        /// Set after a successful save so the render can show a hint.
        saved: bool,
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
    AcceptInvite,
    ManageHubs,
    Settings,
    Help,
    Quit,
}

impl PaletteAction {
    /// All actions, in palette display order.
    const ALL: [PaletteAction; 9] = [
        PaletteAction::CreateRoom,
        PaletteAction::InvitePeer,
        PaletteAction::SendFile,
        PaletteAction::CopyInvite,
        PaletteAction::AcceptInvite,
        PaletteAction::ManageHubs,
        PaletteAction::Settings,
        PaletteAction::Help,
        PaletteAction::Quit,
    ];

    /// Human label shown in the palette.
    fn label(self) -> &'static str {
        match self {
            PaletteAction::CreateRoom => "Create room",
            PaletteAction::InvitePeer => "Invite peer to room",
            PaletteAction::SendFile => "Send file (room or DM peer)",
            PaletteAction::CopyInvite => "Copy my invite link",
            PaletteAction::AcceptInvite => "Accept invite link (paste)",
            PaletteAction::ManageHubs => "Manage hubs / dial / reachability",
            PaletteAction::Settings => "Settings / identity",
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
            PaletteAction::AcceptInvite => "^A",
            PaletteAction::ManageHubs => "^G",
            PaletteAction::Settings => "",
            PaletteAction::Help => "F1",
            PaletteAction::Quit => "^C",
        }
    }
}

/// Task 322: the destination for a file send in the `SendFile` modal —
/// either a multi-party room or a directly-connected DM peer.
#[derive(Debug, Clone)]
enum FileTarget {
    Room { group_id_b32: String },
    Peer { peer_short: String },
}

/// Map the current selection to a [`FileTarget`] for the send-file modal.
fn file_target_for(entry: SelectedEntry<'_>) -> FileTarget {
    match entry {
        SelectedEntry::Room(r) => FileTarget::Room {
            group_id_b32: r.group_id_b32.clone(),
        },
        SelectedEntry::Peer(p) => FileTarget::Peer {
            peer_short: p.short_id.clone(),
        },
    }
}

/// What the current selection refers to (T6.3.f.2). `Peer` drives
/// DM `Send`s; `Room` drives multi-party `SendRoom`s. The composer
/// pane title and the send dispatcher both branch on this.
#[derive(Debug, Clone, Copy)]
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
            backfilled_rooms: HashSet::new(),
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
        // T-files.e / task 322: Ctrl-F opens the send-file modal for
        // the selected conversation — a room (SendFileToRoom) or a DM
        // peer (SendFileToPeer). Defaults match the daemon: strip
        // metadata + random filename; toggles flip both in the modal.
        (KeyCode::Char('f'), m) if m.contains(KeyModifiers::CONTROL) => {
            if let Some(target) = app.selected_entry().map(file_target_for) {
                app.modal = Some(ModalState::SendFile {
                    target,
                    path: String::new(),
                    keep_filename: false,
                    keep_metadata: false,
                    focus: 0,
                });
            } else {
                app.last_send_result =
                    Some(Err("send-file needs a peer or room selected".to_string()));
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
        // UX phase 4: Ctrl-L opens the daemon-log overlay (tail of
        // ~/.onyx/onyx.log), color-coded by level + scrollable.
        (KeyCode::Char('l'), m) if m.contains(KeyModifiers::CONTROL) => {
            app.modal = Some(ModalState::Logs {
                lines: read_log_tail(500),
                scroll: 0,
            });
            return false;
        }
        // UX overhaul: Ctrl-E builds + shows + copies the invite link.
        (KeyCode::Char('e'), m) if m.contains(KeyModifiers::CONTROL) => {
            open_invite_modal(app).await;
            return false;
        }
        // v0.1.12: Ctrl-A opens the accept-invite modal — paste a peer's
        // onyx:// URL to start a conversation in-app (no CLI needed).
        (KeyCode::Char('a'), m) if m.contains(KeyModifiers::CONTROL) => {
            app.modal = Some(ModalState::AcceptInvite {
                input: String::new(),
            });
            return false;
        }
        // v0.1.12: Ctrl-G opens the hub / dial / reachability manager,
        // reading ~/.onyx/config.json so the user can configure transport
        // from inside the TUI instead of CLI flags.
        (KeyCode::Char('g'), m) if m.contains(KeyModifiers::CONTROL) => {
            app.modal = Some(open_manage_hubs_modal());
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
        // UX phase 4: log-overlay scrolling. MUST precede the read-only
        // close arm below, or those keys would dismiss the overlay
        // instead of scrolling. `scroll` is lines-from-bottom; the
        // render clamps an over-large value to the top.
        (ModalState::Logs { scroll, .. }, KeyCode::PageUp) => {
            *scroll = scroll.saturating_add(10);
            app.modal = Some(modal);
            return;
        }
        (ModalState::Logs { scroll, .. }, KeyCode::PageDown) => {
            *scroll = scroll.saturating_sub(10);
            app.modal = Some(modal);
            return;
        }
        (ModalState::Logs { scroll, lines }, KeyCode::Home) => {
            *scroll = u16::try_from(lines.len()).unwrap_or(u16::MAX);
            app.modal = Some(modal);
            return;
        }
        (ModalState::Logs { scroll, .. }, KeyCode::End) => {
            *scroll = 0;
            app.modal = Some(modal);
            return;
        }
        // Esc closes any modal without submitting. Help + Invite +
        // Settings + Logs are read-only overlays, so ANY (non-scroll)
        // key dismisses them too.
        (_, KeyCode::Esc)
        | (
            ModalState::Help
            | ModalState::Invite { .. }
            | ModalState::Settings { .. }
            | ModalState::Logs { .. },
            _,
        ) => {
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
        (ModalState::AcceptInvite { input }, KeyCode::Backspace) => {
            input.pop();
            app.modal = Some(modal);
            return;
        }
        (ModalState::AcceptInvite { input }, KeyCode::Char(c)) => {
            input.push(c);
            app.modal = Some(modal);
            return;
        }
        (ModalState::AcceptInvite { input }, KeyCode::Enter) => {
            // Reject empty / obviously-wrong input before bothering the
            // daemon. The daemon does the real parse + signature verify.
            if !input.trim().starts_with("onyx://invite/") {
                app.last_send_result = Some(Err(
                    "paste a full onyx://invite/v… link to accept".to_string()
                ));
                app.modal = Some(modal);
                return;
            }
            submit_intent = Some(modal.clone());
        }
        // ── v0.1.12: hub / dial / reachability manager ──────────────
        // Ctrl-S persists to ~/.onyx/config.json. Guard must precede the
        // generic Char arm so typing 's' into a field isn't a save.
        (ModalState::ManageHubs { .. }, KeyCode::Char('s'))
            if key.modifiers.contains(KeyModifiers::CONTROL) =>
        {
            if let ModalState::ManageHubs {
                hubs,
                dial_onion,
                dial_pubkey,
                reachable,
                saved,
                ..
            } = &mut modal
            {
                match save_manage_hubs(hubs, dial_onion, dial_pubkey, *reachable) {
                    Ok(()) => {
                        *saved = true;
                        app.last_send_result = Some(Ok(()));
                    }
                    Err(e) => {
                        app.last_send_result = Some(Err(format!("save config: {e}")));
                    }
                }
            }
            app.modal = Some(modal);
            return;
        }
        (ModalState::ManageHubs { hubs, focus, .. }, KeyCode::Tab | KeyCode::Down) => {
            // Controls: 0=add-hub, 1=dial onion, 2=dial pubkey,
            // 3=reachable toggle, 4..=existing hub rows.
            let n = 4 + hubs.len();
            *focus = (*focus + 1) % n;
            app.modal = Some(modal);
            return;
        }
        (ModalState::ManageHubs { hubs, focus, .. }, KeyCode::Up) => {
            let n = 4 + hubs.len();
            *focus = (*focus + n - 1) % n;
            app.modal = Some(modal);
            return;
        }
        (
            ModalState::ManageHubs {
                hubs,
                add_input,
                reachable,
                focus,
                saved,
                ..
            },
            KeyCode::Enter,
        ) => {
            *saved = false;
            match *focus {
                // Add-hub: must look like `onion:port,b32pubkey`.
                0 => {
                    let v = add_input.trim();
                    if v.contains(',') && !v.starts_with(',') && !v.ends_with(',') {
                        hubs.push(v.to_string());
                        add_input.clear();
                    } else {
                        app.last_send_result =
                            Some(Err("hub must be onion:port,b32pubkey".to_string()));
                    }
                }
                3 => *reachable = !*reachable,
                // A focused hub row: Enter removes it.
                i if i >= 4 && (i - 4) < hubs.len() => {
                    hubs.remove(i - 4);
                    if *focus >= 4 + hubs.len() {
                        *focus = (4 + hubs.len()).saturating_sub(1);
                    }
                }
                _ => {}
            }
            app.modal = Some(modal);
            return;
        }
        (ModalState::ManageHubs { hubs, focus, .. }, KeyCode::Delete) => {
            if *focus >= 4 && (*focus - 4) < hubs.len() {
                hubs.remove(*focus - 4);
                if *focus >= 4 + hubs.len() {
                    *focus = (4 + hubs.len()).saturating_sub(1);
                }
            }
            app.modal = Some(modal);
            return;
        }
        (
            ModalState::ManageHubs {
                add_input,
                dial_onion,
                dial_pubkey,
                reachable,
                focus,
                saved,
                ..
            },
            KeyCode::Char(c),
        ) => {
            *saved = false;
            match *focus {
                0 => add_input.push(c),
                1 => dial_onion.push(c),
                2 => dial_pubkey.push(c),
                // Space toggles reachability when that row is focused.
                3 if c == ' ' => *reachable = !*reachable,
                _ => {}
            }
            app.modal = Some(modal);
            return;
        }
        (
            ModalState::ManageHubs {
                add_input,
                dial_onion,
                dial_pubkey,
                focus,
                saved,
                ..
            },
            KeyCode::Backspace,
        ) => {
            *saved = false;
            match *focus {
                0 => {
                    add_input.pop();
                }
                1 => {
                    dial_onion.pop();
                }
                2 => {
                    dial_pubkey.pop();
                }
                _ => {}
            }
            app.modal = Some(modal);
            return;
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
            // T-files.e / task 322: SendFile dispatches to the room
            // (`SendFileToRoom`) or peer (`SendFileToPeer`) handler
            // depending on the target. Path trimmed so a trailing
            // paste-whitespace doesn't blow up open().
            ModalState::SendFile {
                target,
                path,
                keep_filename,
                keep_metadata,
                ..
            } => Some(match target {
                FileTarget::Room { group_id_b32 } => ApiRequest::SendFileToRoom {
                    group_id_b32,
                    path: path.trim().to_string(),
                    keep_filename,
                    keep_metadata,
                },
                FileTarget::Peer { peer_short } => ApiRequest::SendFileToPeer {
                    peer_short,
                    path: path.trim().to_string(),
                    keep_filename,
                    keep_metadata,
                },
            }),
            // v0.1.12: accept a pasted invite link — the TUI twin of
            // `onyx accept <url>`. The daemon re-parses + re-verifies the
            // URL, cross-checks the pin store, and picks the tier. We
            // refuse unsigned (v1) by default here too (no in-TUI danger
            // override — re-issue a signed link instead).
            ModalState::AcceptInvite { input } => Some(ApiRequest::SendInvite {
                url: input.trim().to_string(),
                text: String::new(),
                insecure_accept_unsigned: false,
            }),
            // Help / CommandPalette / Invite / Settings never set
            // submit_intent (handled inline above), so they can't
            // reach here.
            ModalState::Help
            | ModalState::CommandPalette { .. }
            | ModalState::Invite { .. }
            | ModalState::Settings { .. }
            | ModalState::Logs { .. }
            // ManageHubs is handled inline (saves a file, no API call), so
            // it never sets submit_intent — but the match must cover it.
            | ModalState::ManageHubs { .. } => None,
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
                Ok(ApiResponse::SendFileToPeerOk {
                    peer_short,
                    file_id_b32,
                    size,
                    mime,
                    stripped_metadata,
                    chunks,
                }) => {
                    // Task 322: local "you sent <file>" line in the DM
                    // scrollback (keyed by the peer's short_id).
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
                        .entry(peer_short.clone())
                        .or_default()
                        .push(ChatLine {
                            direction: MessageDirection::Outgoing,
                            text: label,
                            ts_unix_ms: now,
                            via_hub: false,
                        });
                    app.last_activity_ms.insert(peer_short, now);
                    app.last_send_result = Some(Ok(()));
                }
                // v0.1.12: in-TUI accept-invite result. The daemon shipped
                // the first-contact bootstrap; the peer surfaces as a real
                // conversation on its next status tick.
                Ok(ApiResponse::SendInviteOk { tier, was_signed }) => {
                    app.last_send_result = Some(Ok(()));
                    tracing::info!(%tier, was_signed, "invite accepted via TUI modal");
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
            if let Some(target) = app.selected_entry().map(file_target_for) {
                app.modal = Some(ModalState::SendFile {
                    target,
                    path: String::new(),
                    keep_filename: false,
                    keep_metadata: false,
                    focus: 0,
                });
            } else {
                app.last_send_result =
                    Some(Err("send-file needs a peer or room selected".to_string()));
            }
        }
        PaletteAction::CopyInvite => open_invite_modal(app).await,
        PaletteAction::AcceptInvite => {
            app.modal = Some(ModalState::AcceptInvite {
                input: String::new(),
            });
        }
        PaletteAction::ManageHubs => {
            app.modal = Some(open_manage_hubs_modal());
        }
        PaletteAction::Settings => open_settings_modal(app).await,
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

/// Task 324: open the read-only settings / identity panel. Pulls
/// identity + hubs from `Identity` and tor/version from the cached
/// `Status` snapshot.
async fn open_settings_modal(app: &mut AppState) {
    let mut info: Vec<(String, String)> = Vec::new();
    if let Some(Ok(s)) = &app.last_status {
        info.push(("Fingerprint".into(), s.fingerprint.clone()));
        info.push((
            "Tor".into(),
            match s.tor_state {
                TorState::Ready => "ready".into(),
                TorState::Bootstrapping { percent } => format!("bootstrapping {percent}%"),
                TorState::Disabled => "disabled (test mode)".into(),
            },
        ));
        info.push(("Daemon".into(), format!("v{}", s.daemon_version)));
    }
    match client::one_shot(&app.socket_path, &ApiRequest::Identity).await {
        Ok(ApiResponse::IdentityOk {
            identity_pub_b32,
            identity_kem_pub_b32,
            hubs,
            ..
        }) => {
            info.push(("Identity pub".into(), identity_pub_b32));
            info.push((
                "KEM pub".into(),
                format!(
                    "{}… ({} chars)",
                    short_id(&identity_kem_pub_b32),
                    identity_kem_pub_b32.len()
                ),
            ));
            info.push((
                "Hubs".into(),
                if hubs.is_empty() {
                    "none configured (rooms/DM-offline need one)".into()
                } else {
                    format!("{} configured", hubs.len())
                },
            ));
        }
        Ok(other) => info.push(("identity".into(), format!("unexpected: {other:?}"))),
        Err(e) => info.push(("identity".into(), format!("error: {e:#}"))),
    }
    info.push((
        "Config".into(),
        "cover-traffic / intro-inbox set at daemon launch".into(),
    ));
    app.modal = Some(ModalState::Settings { info });
}

/// v0.1.12: build the hub-manager modal seeded from the persisted
/// `~/.onyx/config.json`. A missing/malformed file just yields an empty
/// editor (we don't block the UI on a bad file — the daemon's own load
/// surfaces parse errors at launch).
fn open_manage_hubs_modal() -> ModalState {
    let cfg = crate::load_file_config().ok().flatten().unwrap_or_default();
    ModalState::ManageHubs {
        hubs: cfg.hubs,
        add_input: String::new(),
        dial_onion: cfg.dial_onion.unwrap_or_default(),
        dial_pubkey: cfg.dial_pubkey.unwrap_or_default(),
        reachable: cfg.first_contact_reachable,
        focus: 0,
        saved: false,
    }
}

/// v0.1.12: persist the hub-manager modal's fields to
/// `~/.onyx/config.json`. Returns a user-facing message.
fn save_manage_hubs(
    hubs: &[String],
    dial_onion: &str,
    dial_pubkey: &str,
    reachable: bool,
) -> Result<(), String> {
    let trim_opt = |s: &str| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    };
    // Preserve fields the modal doesn't edit (e.g. cover traffic).
    let mut cfg = crate::load_file_config().ok().flatten().unwrap_or_default();
    cfg.hubs = hubs.to_vec();
    cfg.dial_onion = trim_opt(dial_onion);
    cfg.dial_pubkey = trim_opt(dial_pubkey);
    cfg.first_contact_reachable = reachable;
    crate::save_file_config(&cfg).map_err(|e| format!("{e:#}"))
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
    for (gid_b32, conv_key) in room_keys {
        // Task 320: reload persisted room scrollback once per room
        // (mirrors the DM History backfill above). Without this, room
        // messages vanish from the TUI on restart even though the
        // daemon persisted them. `backfilled_rooms` short-circuits
        // after the first successful fetch.
        if !app.backfilled_rooms.contains(&conv_key) {
            let req = ApiRequest::RoomHistory {
                group_id_b32: gid_b32.clone(),
                limit: 200,
            };
            if let Ok(ApiResponse::RoomHistoryOk { messages, .. }) =
                client::one_shot(socket, &req).await
            {
                merge_room_history(app, &conv_key, messages);
                app.backfilled_rooms.insert(conv_key.clone());
            }
        }

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

/// Task 320: merge persisted `RoomHistory` rows into a room's
/// scrollback. Room messages carry no hub/direct tier, so `via_hub`
/// is false. Dedup + prepend is shared with DMs via
/// [`prepend_history_lines`].
fn merge_room_history(
    app: &mut AppState,
    conv_key: &str,
    messages: Vec<onyx_core::api::RoomHistoryEntry>,
) {
    let lines = messages.into_iter().map(|m| ChatLine {
        direction: m.direction,
        text: m.text,
        ts_unix_ms: m.ts_unix_ms,
        via_hub: false,
    });
    prepend_history_lines(
        app.scrollback.entry(conv_key.to_string()).or_default(),
        lines,
    );
}

/// Prepend backfilled history `lines` (oldest → newest) to the front of
/// a conversation's `scrollback`, dropping any that duplicate an
/// already-stored live entry by `(ts_unix_ms, text)`. Live entries that
/// arrived during the History round-trip keep their position at the
/// end. Shared by DM ([`merge_history`]) and room ([`merge_room_history`])
/// backfill so the dedup rule lives in exactly one place.
fn prepend_history_lines(scrollback: &mut Vec<ChatLine>, lines: impl Iterator<Item = ChatLine>) {
    let live_keys: HashSet<(u64, String)> = scrollback
        .iter()
        .map(|l| (l.ts_unix_ms, l.text.clone()))
        .collect();
    let mut prepend: Vec<ChatLine> = lines
        .filter(|l| !live_keys.contains(&(l.ts_unix_ms, l.text.clone())))
        .collect();
    if prepend.is_empty() {
        return;
    }
    prepend.append(scrollback);
    *scrollback = prepend;
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
    let lines = messages.into_iter().map(|m| ChatLine {
        direction: m.direction,
        text: m.text,
        ts_unix_ms: m.ts_unix_ms,
        via_hub: m.via_hub,
    });
    prepend_history_lines(
        app.scrollback.entry(peer_short.to_string()).or_default(),
        lines,
    );
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

// The top-level frame compositor: builds the rail/chat/details layout
// and dispatches to every sub-renderer. Long by nature (it's the layout
// map of the whole UI); same #[allow] the other render_* fns carry.
#[allow(clippy::too_many_lines)]
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

    // UX overhaul: 3-pane layout (Conversations │ Chat │ Details)
    // when the terminal is wide enough; gracefully falls back to the
    // 2-pane layout on narrow terminals so nothing gets crushed.
    let wide = main_area.width >= 92;
    let cols = if wide {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(26),
                Constraint::Min(0),
                Constraint::Length(32),
            ])
            .split(main_area)
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(24), Constraint::Min(0)])
            .split(main_area)
    };
    let left_rail = cols[0];
    let chat_col = cols[1];
    let details_area = if wide { Some(cols[2]) } else { None };

    // UX overhaul phase 2: the left rail is a stack —
    //   logo (brand)  ·  peers & rooms (flexible)  ·  daemon status.
    // The logo box is fixed; the status box is fixed; peers takes the
    // rest. On a very short terminal the logo is the first to yield
    // (its Length collapses gracefully and the art clips to the box).
    let art_lines = u16::try_from(theme::ONION_ART.len()).unwrap_or(5);
    let logo_h: u16 = (art_lines + 4).min(left_rail.height / 2);
    let rail = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(logo_h),
            Constraint::Min(3),
            Constraint::Length(4),
        ])
        .split(left_rail);
    let logo_area = rail[0];
    let peers_area = rail[1];
    let daemon_area = rail[2];

    let chat_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(chat_col);
    let messages_area = chat_rows[0];
    let composer_area = chat_rows[1];

    render_logo(frame, logo_area);
    render_peers(frame, peers_area, app);
    render_daemon_status(frame, daemon_area, app);
    render_messages(frame, messages_area, app);
    render_composer(frame, composer_area, app);
    if let Some(d) = details_area {
        render_details(frame, d, app);
    }
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
        ModalState::Settings { info } => u16::try_from(info.len() + 4).unwrap_or(14),
        // UX phase 4: the log overlay takes most of the height — reading
        // logs benefits from vertical room (capped at 30).
        ModalState::Logs { .. } => area.height.saturating_sub(2).min(30),
        // v0.1.12: paste-an-invite text input.
        ModalState::AcceptInvite { .. } => 9,
        // v0.1.12: hub manager grows with the hub list (+ fixed controls).
        ModalState::ManageHubs { hubs, .. } => u16::try_from(hubs.len() + 12)
            .unwrap_or(20)
            .min(area.height.saturating_sub(2)),
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
            target,
            path,
            keep_filename,
            keep_metadata,
            focus,
        } => {
            // T-files.e / task 322: send-file modal. Three rows. Path
            // is a free-form line; the two toggles are rendered as
            // [x]/[ ] checkboxes. Hint at the bottom reminds the
            // operator what defaults-off means (FILES.md §3).
            let block = Block::default().borders(Borders::ALL).title(Span::styled(
                " Send File  (Tab=cycle, Space=toggle, Esc=cancel, Enter=send) ",
                Style::default().add_modifier(Modifier::BOLD),
            ));
            let sending_to = match target {
                FileTarget::Room { group_id_b32 } => format!(" → room/{} ", short_id(group_id_b32)),
                FileTarget::Peer { peer_short } => format!(" → {peer_short} (DM) "),
            };
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
        ModalState::Settings { info } => render_settings_modal(frame, rect, info),
        ModalState::Logs { lines, scroll } => render_logs_modal(frame, rect, lines, *scroll),
        // v0.1.12: paste a peer's onyx:// invite link and accept it
        // in-app — the TUI twin of `onyx accept <url>`.
        ModalState::AcceptInvite { input } => {
            let block = Block::default().borders(Borders::ALL).title(Span::styled(
                " Accept Invite  (Esc=cancel, Enter=accept) ",
                Style::default().add_modifier(Modifier::BOLD),
            ));
            // Show a bounded tail so a ~1500-char invite URL doesn't
            // overflow the box; the daemon receives the full string.
            let shown: String = {
                let n = input.chars().count();
                if n > 50 {
                    let tail: String = input.chars().skip(n - 47).collect();
                    format!("…{tail}")
                } else {
                    input.clone()
                }
            };
            let body = Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled(
                    " Paste a peer's onyx://invite/v2 link: ",
                    Style::default().fg(Color::Gray),
                )),
                Line::from(vec![
                    Span::styled(" › ", Style::default().fg(Color::Yellow)),
                    Span::styled(
                        shown,
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    " Unsigned (v1) links are refused — ask for a fresh `onyx invite`. ",
                    Style::default().fg(Color::DarkGray),
                )),
            ])
            .block(block);
            frame.render_widget(body, rect);
        }
        // v0.1.12: hub / dial / reachability manager.
        ModalState::ManageHubs {
            hubs,
            add_input,
            dial_onion,
            dial_pubkey,
            reachable,
            focus,
            saved,
        } => {
            let block = Block::default().borders(Borders::ALL).title(Span::styled(
                " Manage Transport  (Tab=move, ^S=save, Esc=close) ",
                Style::default().add_modifier(Modifier::BOLD),
            ));
            let cur = *focus;
            let foc = move |idx: usize| -> Style {
                if cur == idx {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                }
            };
            let mark = move |idx: usize| -> &'static str { if cur == idx { "▶ " } else { "  " } };
            let mut lines: Vec<Line> = Vec::new();
            lines.push(Line::from(Span::styled(
                " Hubs (store-and-forward relays):",
                Style::default().fg(Color::DarkGray),
            )));
            if hubs.is_empty() {
                lines.push(Line::from(Span::styled(
                    "   (none — add one below; needed for rooms + offline DM)",
                    Style::default().fg(Color::DarkGray),
                )));
            }
            for (i, h) in hubs.iter().enumerate() {
                let idx = 4 + i;
                lines.push(Line::from(vec![
                    Span::styled(
                        format!(" {}{}", mark(idx), truncate_for_display(h, 56)),
                        foc(idx),
                    ),
                    Span::styled(
                        if *focus == idx {
                            "  [Del/Enter removes]"
                        } else {
                            ""
                        },
                        Style::default().fg(Color::DarkGray),
                    ),
                ]));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled(format!(" {}add hub: ", mark(0)), foc(0)),
                Span::styled(add_input.clone(), Style::default().fg(Color::White)),
                if *focus == 0 {
                    Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK))
                } else {
                    Span::raw("")
                },
            ]));
            lines.push(Line::from(Span::styled(
                "   format: onion:port,b32pubkey  (Enter adds)",
                Style::default().fg(Color::DarkGray),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled(format!(" {}dial onion: ", mark(1)), foc(1)),
                Span::styled(
                    truncate_for_display(dial_onion, 48),
                    Style::default().fg(Color::White),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled(format!(" {}dial pubkey: ", mark(2)), foc(2)),
                Span::styled(
                    truncate_for_display(dial_pubkey, 48),
                    Style::default().fg(Color::White),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled(format!(" {}first-contact reachable: ", mark(3)), foc(3)),
                Span::styled(
                    if *reachable { "[x] on" } else { "[ ] off" },
                    Style::default().fg(if *reachable {
                        Color::Green
                    } else {
                        Color::Gray
                    }),
                ),
                Span::styled("  (Space toggles)", Style::default().fg(Color::DarkGray)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                if *saved {
                    " ✓ saved to ~/.onyx/config.json — restart onyx to apply"
                } else {
                    " ^S saves to ~/.onyx/config.json (applies on next launch)"
                },
                Style::default().fg(if *saved {
                    Color::Green
                } else {
                    Color::DarkGray
                }),
            )));
            frame.render_widget(Paragraph::new(lines).block(block), rect);
        }
    }
}

/// UX overhaul phase 4: read the tail of the daemon log file
/// (~/.onyx/onyx.log) for the `Ctrl-L` overlay. Returns up to `max`
/// most-recent lines (oldest first). Best-effort: a missing/unreadable
/// log yields an explanatory line rather than an error, since the
/// overlay is a convenience, not a critical path.
fn read_log_tail(max: usize) -> Vec<String> {
    let path = onyx_daemon::default_data_dir().join("onyx.log");
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let all: Vec<&str> = content.lines().collect();
            let start = all.len().saturating_sub(max);
            let tail: Vec<String> = all[start..].iter().map(|s| (*s).to_string()).collect();
            if tail.is_empty() {
                vec![format!("(log is empty: {})", path.display())]
            } else {
                tail
            }
        }
        Err(e) => vec![
            format!("(could not read {}: {e})", path.display()),
            "the daemon writes logs here only in TUI / combined mode.".to_string(),
        ],
    }
}

/// UX overhaul phase 4: render the scrollable, level-colored daemon-log
/// overlay. `scroll` is lines-from-bottom (0 = newest pinned to the
/// bottom edge). Lines are colored by the level token tracing emits.
fn render_logs_modal(frame: &mut ratatui::Frame<'_>, rect: Rect, lines: &[String], scroll: u16) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border_active())
        .title(Span::styled(
            " daemon logs  (PgUp/PgDn scroll · Esc close) ",
            theme::header(),
        ));
    let inner_h = rect.height.saturating_sub(2) as usize;

    let styled: Vec<Line<'static>> = lines
        .iter()
        .map(|l| {
            let style = if l.contains("ERROR") {
                theme::error()
            } else if l.contains("WARN") {
                theme::warn()
            } else if l.contains("DEBUG") || l.contains("TRACE") {
                theme::muted()
            } else if l.contains("INFO") {
                theme::ok()
            } else {
                theme::text()
            };
            Line::from(Span::styled(l.clone(), style))
        })
        .collect();

    // Bottom-anchored: show the last `inner_h` lines, offset up by
    // `scroll`. Clamp so scrolling past the top just pins to the top.
    let total = styled.len();
    let max_scroll = total.saturating_sub(inner_h);
    let scroll = (scroll as usize).min(max_scroll);
    let end = total.saturating_sub(scroll);
    let start = end.saturating_sub(inner_h);
    let view: Vec<Line<'static>> = styled[start..end].to_vec();

    frame.render_widget(Paragraph::new(view).block(block), rect);
}

/// Task 324: read-only settings / identity panel.
fn render_settings_modal(frame: &mut ratatui::Frame<'_>, rect: Rect, info: &[(String, String)]) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Span::styled(
            " Settings / Identity  (any key to close) ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
    let lines: Vec<Line> = info
        .iter()
        .map(|(k, v)| {
            Line::from(vec![
                Span::styled(
                    format!(" {k:<14}"),
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(v.clone(), Style::default().fg(Color::White)),
            ])
        })
        .collect();
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        rect,
    );
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
        key("Ctrl-A", "accept an invite link (paste)"),
        key("Ctrl-G", "manage hubs / dial / reachability"),
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
            " Share it; they paste it via ^A (Accept invite) — or:  onyx accept '<url>'",
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

/// UX overhaul: render one titled, colored, bordered sub-panel filled
/// with `lines`. The building block of the split Details column.
fn boxed(
    frame: &mut ratatui::Frame<'_>,
    rect: Rect,
    title: &str,
    color: Color,
    lines: Vec<Line<'_>>,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        rect,
    );
}

/// UX overhaul: the right-hand Details column — split into individually
/// titled, colored sub-panels (a small dashboard) rather than one box.
/// Room → Channel / Members / Actions; DM peer → Peer / Note;
/// nothing selected → Getting Started.
#[allow(clippy::too_many_lines)]
fn render_details(frame: &mut ratatui::Frame<'_>, area: Rect, app: &AppState) {
    let kv = |k: &str, v: String| -> Line<'static> {
        Line::from(vec![
            Span::styled(format!(" {k}: "), Style::default().fg(Color::Gray)),
            Span::styled(v, Style::default().fg(Color::White)),
        ])
    };
    let my_fp = app
        .last_status
        .as_ref()
        .and_then(|r| r.as_ref().ok())
        .map(|s| s.fingerprint.clone())
        .unwrap_or_default();

    match app.selected_entry() {
        Some(SelectedEntry::Room(r)) => {
            // Channel (cyan) │ Members (magenta, fills) │ Actions (green).
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(5),
                    Constraint::Min(3),
                    Constraint::Length(4),
                ])
                .split(area);
            boxed(
                frame,
                rows[0],
                "Channel",
                Color::Cyan,
                vec![
                    kv("name", format!("#{}", r.name)),
                    kv("members", r.members.len().to_string()),
                    kv("id", short_id(&r.group_id_b32)),
                ],
            );
            let mut roster: Vec<Line> = Vec::with_capacity(r.members.len());
            for m in &r.members {
                let is_me = !my_fp.is_empty() && m == &my_fp;
                roster.push(Line::from(vec![
                    Span::styled(" • ", Style::default().fg(Color::Magenta)),
                    Span::styled(
                        short_id(&m.replace(' ', "")),
                        Style::default().fg(if is_me { Color::Cyan } else { Color::White }),
                    ),
                    if is_me {
                        Span::styled(" (you)", Style::default().fg(Color::Cyan))
                    } else {
                        Span::raw("")
                    },
                ]));
            }
            boxed(frame, rows[1], "Members", Color::Magenta, roster);
            boxed(
                frame,
                rows[2],
                "Actions",
                Color::Green,
                vec![
                    Line::from(vec![
                        Span::styled(" ^I ", Style::default().fg(Color::Yellow)),
                        Span::styled("invite peer", Style::default().fg(Color::White)),
                    ]),
                    Line::from(vec![
                        Span::styled(" ^F ", Style::default().fg(Color::Yellow)),
                        Span::styled("send file", Style::default().fg(Color::White)),
                    ]),
                ],
            );
        }
        Some(SelectedEntry::Peer(p)) => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(5), Constraint::Min(3)])
                .split(area);
            let state = if p.connected {
                Span::styled(
                    "● connected",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled("○ offline", Style::default().fg(Color::DarkGray))
            };
            boxed(
                frame,
                rows[0],
                "Peer",
                Color::Cyan,
                vec![
                    kv("peer", p.short_id.clone()),
                    Line::from(vec![
                        Span::styled(" state: ", Style::default().fg(Color::Gray)),
                        state,
                    ]),
                ],
            );
            boxed(
                frame,
                rows[1],
                "Actions",
                Color::Green,
                vec![Line::from(vec![
                    Span::styled(" ^F ", Style::default().fg(Color::Yellow)),
                    Span::styled("send file (direct)", Style::default().fg(Color::White)),
                ])],
            );
        }
        None => {
            boxed(
                frame,
                area,
                "Getting Started",
                Color::DarkGray,
                vec![
                    Line::from(Span::styled(
                        " Pick a conversation (↑/↓).",
                        Style::default().fg(Color::Gray),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        " Ctrl-K  command palette",
                        Style::default().fg(Color::DarkGray),
                    )),
                    Line::from(Span::styled(
                        " F1      all shortcuts",
                        Style::default().fg(Color::DarkGray),
                    )),
                    Line::from(Span::styled(
                        " Ctrl-E  copy invite",
                        Style::default().fg(Color::DarkGray),
                    )),
                ],
            );
        }
    }
}

// Linear render fn: empty-state branch + grouped DM/Channels item
// build + visual-row mapping. Over the 100-line budget but cohesive
// (same rationale as the other render_* helpers).
/// UX overhaul phase 2: the brand box at the top of the left rail —
/// the layered Tor onion in brand purple, the ONYX wordmark (also
/// purple), and a muted tagline. Centered; clips gracefully in a short
/// box.
fn render_logo(frame: &mut ratatui::Frame<'_>, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border())
        .title(Span::styled(" onyx ", theme::header()));
    let inner_w = area.width.saturating_sub(2) as usize;
    let center = |s: &str| -> Line<'static> {
        let len = s.chars().count();
        let pad = inner_w.saturating_sub(len) / 2;
        Line::from(Span::styled(
            format!("{}{}", " ".repeat(pad), s),
            theme::logo(),
        ))
    };
    let mut lines: Vec<Line<'static>> = theme::ONION_ART.iter().map(|l| center(l)).collect();
    lines.push(center(theme::WORDMARK));
    lines.push(Line::from(Span::styled(
        {
            let len = theme::TAGLINE.chars().count();
            let pad = inner_w.saturating_sub(len) / 2;
            format!("{}{}", " ".repeat(pad), theme::TAGLINE)
        },
        theme::muted(),
    )));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// UX overhaul phase 2: the daemon-status box at the bottom of the left
/// rail — a compact dashboard line for Tor + tail health + version, so
/// the user can see the embedded daemon is alive at a glance (it starts
/// automatically, so this is the only place that visibly confirms it).
fn render_daemon_status(frame: &mut ratatui::Frame<'_>, area: Rect, app: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border())
        .title(Span::styled(" daemon ", theme::header()));

    let lines: Vec<Line<'static>> = match &app.last_status {
        None => vec![Line::from(Span::styled("◌ starting…", theme::warn()))],
        Some(Err(_)) => vec![
            Line::from(Span::styled("✗ unreachable", theme::error())),
            Line::from(Span::styled("reconnecting…", theme::muted())),
        ],
        Some(Ok(s)) => {
            // UX phase 5: while bootstrapping, the daemon box shows a
            // real progress bar built from arti's reported percentage
            // instead of the binary ready/off glyph.
            if let TorState::Bootstrapping { percent } = s.tor_state {
                let filled = (usize::from(percent) * 10 / 100).min(10);
                let bar: String = "█".repeat(filled) + &"░".repeat(10 - filled);
                return frame.render_widget(
                    Paragraph::new(vec![
                        Line::from(vec![
                            Span::styled("◌ ", theme::warn()),
                            Span::styled("bootstrapping tor", theme::warn()),
                        ]),
                        Line::from(vec![
                            Span::styled(bar, theme::warn()),
                            Span::styled(format!(" {percent}%"), theme::muted()),
                        ]),
                    ])
                    .block(block),
                    area,
                );
            }
            let (glyph, label, style) = match s.tor_state {
                TorState::Ready => ("◉", "tor ready", theme::ok()),
                TorState::Bootstrapping { .. } => ("◌", "bootstrapping", theme::warn()),
                TorState::Disabled => ("○", "tor off (clearnet)", theme::warn()),
            };
            let tail = if app.tail_active {
                Span::styled("● live", theme::ok())
            } else {
                Span::styled("○ reconnecting", theme::warn())
            };
            vec![
                Line::from(vec![
                    Span::styled(format!("{glyph} "), style),
                    Span::styled(label.to_string(), style),
                ]),
                Line::from(vec![
                    Span::styled("link ", theme::muted()),
                    tail,
                    Span::styled(format!("   v{}", s.daemon_version), theme::muted()),
                ]),
            ]
        }
    };
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

#[allow(clippy::too_many_lines)]
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

    // Task 324: group into "Direct messages" / "Channels" sections
    // with headers. Headers are non-selectable list rows, so we map
    // the entry index (`app.selected`, into peers++rooms) to the
    // VISUAL row index the ListState should highlight.
    let header = |t: &str| -> ListItem<'_> {
        ListItem::new(Line::from(Span::styled(
            t.to_string(),
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )))
    };
    let mut items: Vec<ListItem<'_>> = Vec::with_capacity(app.peers.len() + app.rooms.len() + 2);
    if !app.peers.is_empty() {
        items.push(header("DIRECT MESSAGES"));
    }
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
    if !app.rooms.is_empty() {
        items.push(header("CHANNELS"));
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
    // Map the selected entry index to its visual row. DM section, when
    // present, is [header, peers…] = 1 + peers.len() rows; the channels
    // header adds 1 before the rooms.
    let sel = app.selected.min(app.total_entries().saturating_sub(1));
    let visual = if sel < app.peers.len() {
        1 + sel // skip the DM header
    } else {
        let dm_rows = if app.peers.is_empty() {
            0
        } else {
            1 + app.peers.len()
        };
        let room_idx = sel - app.peers.len();
        dm_rows + 1 + room_idx // + channels header
    };
    let mut state = ListState::default();
    state.select(Some(visual));
    frame.render_stateful_widget(list, area, &mut state);
}

// Linear render fn: title selection + empty-state branches + message
// styling loop. Over the 100-line budget but cohesive (same rationale
// as render_modal / render_details).
#[allow(clippy::too_many_lines)]
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
        // UX overhaul: brand-new user (no peers, no rooms) gets a real
        // welcome + concrete first steps, instead of a bare "nothing
        // selected". Once they have conversations, it's just the
        // "pick one" hint.
        let brand_new = app.peers.is_empty() && app.rooms.is_empty();
        let body = if brand_new {
            let step = |k: &str, d: &str| -> Line<'static> {
                Line::from(vec![
                    Span::styled(
                        format!("   {k:<8}"),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(d.to_string(), Style::default().fg(Color::White)),
                ])
            };
            Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  Welcome to Onyx 🖤",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  You're not connected to anyone yet. To start:",
                    Style::default().fg(Color::Gray),
                )),
                Line::from(""),
                step("Ctrl-E", "copy your invite link — send it to a friend"),
                step("", "(they run: onyx accept '<link>')"),
                Line::from(""),
                step("Ctrl-N", "create a room / channel"),
                step("Ctrl-K", "command palette — run anything by name"),
                step("F1", "see every keyboard shortcut"),
                Line::from(""),
                Line::from(Span::styled(
                    "  Note: rooms & file-sharing need a hub configured",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    "  (--hub …). See README for setup.",
                    Style::default().fg(Color::DarkGray),
                )),
            ])
        } else {
            Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  Pick a conversation on the left with ↑/↓.",
                    Style::default().fg(Color::Gray),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  Ctrl-K palette · F1 help · Ctrl-E invite",
                    Style::default().fg(Color::DarkGray),
                )),
            ])
        };
        frame.render_widget(body.block(block).wrap(Wrap { trim: false }), area);
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
    // UX overhaul: colored border + a title that names the current
    // target ("Compose → #general" / "→ alice"), so it's always clear
    // where a message will go.
    let (title, border) = match app.selected_entry() {
        Some(SelectedEntry::Room(r)) => (format!(" Compose → #{} ", r.name), Color::Green),
        Some(SelectedEntry::Peer(p)) => (format!(" Compose → {} ", p.short_id), Color::Green),
        None => (" Compose ".to_string(), Color::DarkGray),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border))
        .title(Span::styled(
            title,
            Style::default().fg(border).add_modifier(Modifier::BOLD),
        ));

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
        None => Line::from(Span::styled(" connecting to daemon… ", theme::warn())),
        Some(Err(e)) => Line::from(vec![
            Span::styled(" daemon unreachable: ", theme::error()),
            Span::styled(e.clone(), theme::text()),
            Span::styled("  · Esc to quit", theme::muted()),
        ]),
        Some(Ok(s)) => {
            let tor = match s.tor_state {
                TorState::Ready => Span::styled("tor ready", theme::ok()),
                TorState::Bootstrapping { percent } => {
                    Span::styled(format!("tor bootstrapping {percent}%"), theme::warn())
                }
                TorState::Disabled => Span::styled("tor disabled", theme::warn()),
            };
            let live = if app.tail_active {
                Span::styled("● live", theme::ok())
            } else {
                Span::styled("○ no tail", theme::error())
            };
            let live_count = app.peers.iter().filter(|p| p.connected).count();
            Line::from(vec![
                Span::raw(" "),
                tor,
                Span::raw("  ·  "),
                live,
                Span::raw("  ·  "),
                Span::styled("you ", theme::muted()),
                Span::styled(short_id(&s.fingerprint), theme::you()),
                Span::raw("  ·  "),
                Span::styled(
                    format!(
                        "{live_count} peer{}",
                        if live_count == 1 { "" } else { "s" }
                    ),
                    theme::muted(),
                ),
                Span::raw("  ·  "),
                Span::styled(format!("v{}", s.daemon_version), theme::muted()),
                Span::raw("   "),
                // UX overhaul: colored, always-visible keybind hints.
                kb("F1"),
                Span::styled("help ", theme::keylabel()),
                kb("^K"),
                Span::styled("palette ", theme::keylabel()),
                kb("^N"),
                Span::styled("room ", theme::keylabel()),
                kb("^F"),
                Span::styled("file ", theme::keylabel()),
                kb("^E"),
                Span::styled("invite", theme::keylabel()),
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
        // UX overhaul phase 2: the stacked left rail must render the
        // brand box (wordmark + tagline) and the daemon-status box.
        assert!(snap.contains("O N Y X"), "logo wordmark missing:\n{snap}");
        assert!(snap.contains("anonymous"), "tagline missing:\n{snap}");
        assert!(
            snap.contains("daemon"),
            "daemon status box missing:\n{snap}"
        );
        assert!(
            snap.contains("tor ready"),
            "daemon box should show tor state:\n{snap}"
        );
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
