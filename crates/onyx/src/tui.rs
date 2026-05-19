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
//!   * `Esc` or `Ctrl-C` — quit.
//!   * `↑` / `↓`            — move peer selection.
//!   * `Enter`              — send composer text into the selected peer.
//!   * `Backspace`          — delete one char.
//!   * any other char       — append to composer.
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
//! ## Things deliberately not here yet
//!
//!   * Visual indicator of unread per-peer counts beyond the bold
//!     marker.
//!   * Wrapping / scrolling for very long messages.

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
        self.selected = next;
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
    fn apply_rooms_snapshot(&mut self, new_rooms: Vec<RoomInfo>) {
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

    match (key.code, key.modifiers) {
        (KeyCode::Esc, _) => return true,
        (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => return true,
        (KeyCode::Up, _) => app.move_selection(-1),
        (KeyCode::Down, _) => app.move_selection(1),
        (KeyCode::Backspace, _) => {
            app.composer.pop();
        }
        (KeyCode::Enter, _) => {
            send_composer(app).await;
        }
        (KeyCode::Char(c), _) => {
            app.composer.push(c);
        }
        _ => {}
    }
    false
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
            app.scrollback.entry(key).or_default().push(ChatLine {
                direction: MessageDirection::Outgoing,
                text: text.clone(),
                ts_unix_ms: now_unix_ms(),
                via_hub: false,
            });
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
        items.push(ListItem::new(Line::from(vec![dot, name])));
    }
    for r in &app.rooms {
        let label = format!("#{} ({}m)", r.name, r.members.len());
        items.push(ListItem::new(Line::from(vec![
            Span::styled("◆ ", Style::default().fg(Color::Magenta)),
            Span::styled(label, Style::default().fg(Color::White)),
        ])));
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
    let body = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
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
                Span::styled(
                    "  ·  ↑↓ peer · Enter send · Esc quit",
                    Style::default().fg(Color::DarkGray),
                ),
            ])
        }
    };
    frame.render_widget(Paragraph::new(line), area);
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
