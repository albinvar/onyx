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
//! ## v0 scope
//!
//! The chrome and layout are complete; the status bar pulls real
//! data from the daemon over the API socket. The peers/messages/
//! composer panes show informative placeholders because dialling +
//! sending isn't wired yet — that lands in the next phase together
//! with the conversation-state refactor in `onyxd`.
//!
//! Keys: `q` or `Ctrl-C` quit. `r` forces an immediate status
//! refresh (otherwise the bar refreshes every two seconds).

use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use onyx_core::api::{ApiRequest, ApiResponse, TorState};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

use crate::client;

const STATUS_REFRESH_INTERVAL: Duration = Duration::from_secs(2);
const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(150);

/// Live data the TUI renders from. Refreshed from the daemon every
/// [`STATUS_REFRESH_INTERVAL`].
#[derive(Debug, Clone)]
struct AppState {
    socket_path: PathBuf,
    /// `None` until the first successful refresh; `Some(Err(...))` if
    /// the daemon is unreachable / errored. The status bar shows
    /// either the live data or the error.
    last_status: Option<Result<StatusSnapshot, String>>,
    last_refresh_at: Option<Instant>,
}

#[derive(Debug, Clone)]
struct StatusSnapshot {
    daemon_version: String,
    identity_pub_b32: String,
    fingerprint: String,
    tor_state: TorState,
}

impl AppState {
    fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            last_status: None,
            last_refresh_at: None,
        }
    }

    async fn refresh(&mut self) {
        let result = match client::one_shot(&self.socket_path, &ApiRequest::Status).await {
            Ok(ApiResponse::StatusOk {
                daemon_version,
                identity_pub_b32,
                fingerprint,
                tor_state,
                ..
            }) => Ok(StatusSnapshot {
                daemon_version,
                identity_pub_b32,
                fingerprint,
                tor_state,
            }),
            Ok(ApiResponse::Error { code, message }) => {
                Err(format!("daemon error: {code:?}: {message}"))
            }
            Ok(other) => Err(format!("unexpected response shape: {other:?}")),
            Err(e) => Err(format!("{e:#}")),
        };
        self.last_status = Some(result);
        self.last_refresh_at = Some(Instant::now());
    }
}

/// Entry point: set up the terminal, render until the user quits,
/// restore the terminal even if rendering panics.
pub async fn run(socket_path: PathBuf) -> anyhow::Result<()> {
    let mut terminal = setup_terminal()?;

    // Make sure the terminal is restored even on panic.
    let panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = teardown_terminal_global();
        panic_hook(info);
    }));

    let mut app = AppState::new(socket_path);
    app.refresh().await;

    let result = event_loop(&mut terminal, &mut app).await;

    teardown_terminal(&mut terminal)?;
    result
}

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut AppState,
) -> anyhow::Result<()> {
    loop {
        terminal.draw(|frame| render(frame, app))?;

        // Auto-refresh the status bar in the background between key
        // presses without blocking the UI.
        if app
            .last_refresh_at
            .is_none_or(|t| t.elapsed() >= STATUS_REFRESH_INTERVAL)
        {
            app.refresh().await;
        }

        // Short-poll for keyboard input so we can also tick the
        // background refresh. The poll itself is blocking inside
        // crossterm; the short timeout keeps that cost negligible.
        if crossterm::event::poll(EVENT_POLL_INTERVAL)? {
            if let Event::Key(key) = crossterm::event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match (key.code, key.modifiers) {
                    (KeyCode::Char('q'), _) => break,
                    (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => break,
                    (KeyCode::Char('r'), _) => app.refresh().await,
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

fn render(frame: &mut ratatui::Frame<'_>, app: &AppState) {
    let area = frame.area();

    // Outer chrome: title + borders around everything.
    let outer = Block::default().borders(Borders::ALL).title(Span::styled(
        " onyx ",
        Style::default().add_modifier(Modifier::BOLD),
    ));
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    // Vertical: main area on top, single-line status bar at the bottom.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(inner);
    let main_area = chunks[0];
    let status_area = chunks[1];

    // Horizontal: peer list on the left, chat area on the right.
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(20), Constraint::Min(0)])
        .split(main_area);
    let peers_area = cols[0];
    let chat_col = cols[1];

    // Chat column: message scrollback on top, composer on the bottom.
    let chat_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(chat_col);
    let messages_area = chat_rows[0];
    let composer_area = chat_rows[1];

    render_peers(frame, peers_area);
    render_messages(frame, messages_area);
    render_composer(frame, composer_area);
    render_status(frame, status_area, app);
}

fn render_peers(frame: &mut ratatui::Frame<'_>, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" Peers ");
    // No real conversations yet — show a placeholder line so the
    // pane reads as "intentionally empty" rather than broken.
    let items = vec![ListItem::new(Line::from(Span::styled(
        "(none — next phase)",
        Style::default().fg(Color::DarkGray),
    )))];
    let list = List::new(items).block(block);
    frame.render_widget(list, area);
}

fn render_messages(frame: &mut ratatui::Frame<'_>, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Conversation ");
    let body = Paragraph::new(vec![
        Line::from(Span::styled(
            "No conversation selected.",
            Style::default().fg(Color::Gray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Dialling, sending, and live message tail will land in the",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "next phase together with the daemon's conversation refactor.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Today: the chrome is real, the status bar is live.",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .block(block)
    .wrap(Wrap { trim: false });
    frame.render_widget(body, area);
}

fn render_composer(frame: &mut ratatui::Frame<'_>, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" Compose ");
    let body = Paragraph::new(Line::from(Span::styled(
        " > (send disabled — no active conversation)",
        Style::default().fg(Color::DarkGray),
    )))
    .block(block);
    frame.render_widget(body, area);
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
            Span::styled(
                "  · press `r` to retry, `q` to quit",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Some(Ok(s)) => {
            let tor = match s.tor_state {
                TorState::Ready => Span::styled("tor ready", Style::default().fg(Color::Green)),
                TorState::Disabled => {
                    Span::styled("tor disabled", Style::default().fg(Color::Yellow))
                }
            };
            let short_fpr = short_id(&s.fingerprint);
            let short_id = short_id(&s.identity_pub_b32);
            Line::from(vec![
                Span::raw(" "),
                tor,
                Span::raw("  ·  "),
                Span::styled("you ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    short_fpr,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" ({short_id})"),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw("  ·  "),
                Span::styled(
                    format!("onyxd v{}", s.daemon_version),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    "  ·  q quit · r refresh",
                    Style::default().fg(Color::DarkGray),
                ),
            ])
        }
    };
    let bar = Paragraph::new(line);
    frame.render_widget(bar, area);
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

/// Used from the panic hook where we don't have access to the
/// `Terminal` instance any more. Best-effort.
fn teardown_terminal_global() -> anyhow::Result<()> {
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}
