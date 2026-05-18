//! Ratatui-based multi-pane TUI.
//!
//! ## Layout
//!
//! ```text
//! ┌─ onyx ──────────────────────────────────────────┐
//! │ Peers          │ #<peer-short>                  │
//! │ ────────────── │ ───────────────────────────── │
//! │ <peer list>    │ <message scrollback>           │
//! │                │                                │
//! │                │ ┌────────────────────────────┐ │
//! │                │ │ > <composer>               │ │
//! │                │ └────────────────────────────┘ │
//! ├────────────────┴────────────────────────────────┤
//! │ <status bar: tor · onion · peers · unread>      │
//! └──────────────────────────────────────────────────┘
//! ```
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
//! ## Things deliberately not here yet
//!
//!   * Backfill of message history on tail-resume (the registry has
//!     a ring buffer, but the API has no `History` verb yet — so
//!     new tail subscribers only see messages from the moment they
//!     subscribed).
//!   * Visual indicator of unread per-peer counts beyond the bold
//!     marker.
//!   * Wrapping / scrolling for very long messages.

use std::collections::HashMap;
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
    ApiRequest, ApiResponse, MessageDirection, PeerInfo, TorState, decode_response,
    encode_request_line,
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
    /// Index into `peers`; out of range means "no selection".
    selected: usize,
    /// Per-peer scrollback (keyed by `short_id`). Populated from
    /// live `EventMessage`s; not backfilled from server history yet.
    scrollback: HashMap<String, Vec<ChatLine>>,
    /// Bytes the user has typed but not yet sent.
    composer: String,
    /// The most recent `Send` outcome, surfaced as a transient
    /// banner in the composer pane until the next keystroke.
    last_send_result: Option<Result<(), String>>,
    /// Visual indicator of whether the tail connection is alive.
    tail_active: bool,
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
}

impl AppState {
    fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            last_status: None,
            peers: Vec::new(),
            selected: 0,
            scrollback: HashMap::new(),
            composer: String::new(),
            last_send_result: None,
            tail_active: false,
        }
    }

    fn selected_peer(&self) -> Option<&PeerInfo> {
        self.peers.get(self.selected)
    }

    fn move_selection(&mut self, delta: isize) {
        if self.peers.is_empty() {
            self.selected = 0;
            return;
        }
        let n = self.peers.len();
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
                ..
            } => {
                self.scrollback
                    .entry(peer_short)
                    .or_default()
                    .push(ChatLine { direction, text });
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
        let prev_short = self.selected_peer().map(|p| p.short_id.clone());
        self.peers = new_peers;
        if let Some(short) = prev_short {
            if let Some(idx) = self.peers.iter().position(|p| p.short_id == short) {
                self.selected = idx;
            }
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
    let Some(peer) = app.selected_peer().cloned() else {
        app.last_send_result = Some(Err("no peer selected".to_string()));
        return;
    };
    let text = std::mem::take(&mut app.composer);
    let req = ApiRequest::Send {
        peer_short: peer.short_id.clone(),
        text: text.clone(),
    };
    match client::one_shot(&app.socket_path, &req).await {
        Ok(ApiResponse::SendOk) => {
            app.last_send_result = Some(Ok(()));
            // Don't push into scrollback here — the daemon broadcasts
            // an `EventMessage { direction: Outgoing }` for the send,
            // which the tail loop will deliver and apply_event will
            // record. Pushing here would double up.
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
    let block = Block::default().borders(Borders::ALL).title(" Peers ");
    if app.peers.is_empty() {
        let body = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                " (no peers yet)",
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
                " to bring one up.",
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .block(block);
        frame.render_widget(body, area);
        return;
    }

    let items: Vec<ListItem<'_>> = app
        .peers
        .iter()
        .map(|p| {
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
            ListItem::new(Line::from(vec![dot, name]))
        })
        .collect();
    let list = List::new(items)
        .block(block)
        .highlight_style(Style::default().bg(Color::DarkGray).fg(Color::White))
        .highlight_symbol("▶ ");
    let mut state = ListState::default();
    state.select(Some(app.selected.min(app.peers.len().saturating_sub(1))));
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_messages(frame: &mut ratatui::Frame<'_>, area: Rect, app: &AppState) {
    let title = app.selected_peer().map_or_else(
        || " Conversation ".to_string(),
        |p| format!(" #{} ", p.short_id),
    );
    let block = Block::default().borders(Borders::ALL).title(title);

    let Some(peer) = app.selected_peer() else {
        let body = Paragraph::new(vec![
            Line::from(Span::styled(
                "No conversation selected.",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Use ↑/↓ to pick a peer once one shows up.",
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .block(block)
        .wrap(Wrap { trim: false });
        frame.render_widget(body, area);
        return;
    };

    let lines: Vec<Line<'_>> = match app.scrollback.get(&peer.short_id) {
        Some(scroll) if !scroll.is_empty() => scroll
            .iter()
            .map(|line| {
                let (who, color) = match line.direction {
                    MessageDirection::Incoming => (peer.short_id.as_str(), Color::Cyan),
                    MessageDirection::Outgoing => ("me", Color::Green),
                };
                Line::from(vec![
                    Span::styled(format!("{who:>10}: "), Style::default().fg(color)),
                    Span::raw(line.text.clone()),
                ])
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
    } else if app.selected_peer().is_none() {
        Line::from(Span::styled(
            " > (no peer to send to)",
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
                    text: "hi".into(),
                },
                ChatLine {
                    direction: MessageDirection::Outgoing,
                    text: "hey".into(),
                },
                ChatLine {
                    direction: MessageDirection::Incoming,
                    text: "how's the audit?".into(),
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
        assert!(snap.contains("Peers"));
        assert!(snap.contains("(no peers yet)"));
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
