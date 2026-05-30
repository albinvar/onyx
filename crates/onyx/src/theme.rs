//! Centralised TUI theme — the "hacker green" palette.
//!
//! Before this module the TUI hard-coded `Color::*` at ~117 render
//! sites. Funnelling every colour through one place makes the look
//! consistent and tweakable (and a future `--theme` switch a small
//! change). The palette is a phosphor-terminal aesthetic:
//!
//!   * **green** — the primary: you, online peers, ready states, chrome
//!   * **dim green** — borders / inactive chrome (recedes)
//!   * **cyan** — structure: section headers, rooms, incoming text
//!   * **amber (yellow)** — attention: unread badges, keybind chips,
//!     "bootstrapping" / transitional states, hub-relayed badge
//!   * **magenta** — security-relevant alerts (key-changed, MITM)
//!   * **red** — hard errors / unreachable / failed
//!
//! Everything here is `const fn` or returns `Style`, so it's zero-cost
//! and usable in `const` contexts where helpful.

// Phase 1 of a multi-phase UX overhaul: this module defines the full
// palette + semantic helpers up front, but the later phases (left-rail
// restructure, onboarding, log panel) wire most of them in. Allow
// not-yet-used items here so each phase stays a clean, green commit
// rather than forcing the whole overhaul into one. Every item is
// exercised by the time the overhaul lands; the unit tests below already
// touch the core ones.
#![allow(dead_code)]

use ratatui::style::{Color, Modifier, Style};

// ── Raw palette ─────────────────────────────────────────────────────────
//
// Named once. If you want to retune the whole UI, change these eight.

/// Primary phosphor green — you, online, ready, default foreground accents.
pub const GREEN: Color = Color::Rgb(0x33, 0xff, 0x66);
/// Dim green — borders and inactive chrome that should recede.
pub const GREEN_DIM: Color = Color::Rgb(0x1f, 0x8a, 0x44);
/// Structure / rooms / incoming — cyan.
pub const CYAN: Color = Color::Rgb(0x46, 0xe6, 0xe6);
/// Attention — amber/yellow for badges, hints, transitional states.
pub const AMBER: Color = Color::Rgb(0xff, 0xc1, 0x33);
/// Security alert — magenta (key changed, MITM, "verify out of band").
pub const MAGENTA: Color = Color::Rgb(0xff, 0x5f, 0xd7);
/// Hard error / unreachable / failed.
pub const RED: Color = Color::Rgb(0xff, 0x5f, 0x5f);
/// Neutral body text.
pub const TEXT: Color = Color::Rgb(0xc8, 0xd0, 0xc8);
/// Muted meta text (timestamps, version, secondary labels).
pub const MUTED: Color = Color::Rgb(0x6b, 0x7a, 0x6b);

// ── Semantic styles ─────────────────────────────────────────────────────
//
// Render code should prefer these over the raw colours so intent stays
// legible and a retune touches one site.

/// You / the local identity — bright green, bold.
#[must_use]
pub fn you() -> Style {
    Style::default().fg(GREEN).add_modifier(Modifier::BOLD)
}

/// An online / connected peer's name.
#[must_use]
pub fn online() -> Style {
    Style::default().fg(GREEN).add_modifier(Modifier::BOLD)
}

/// An offline peer — recedes.
#[must_use]
pub fn offline() -> Style {
    Style::default().fg(MUTED)
}

/// A room / channel accent (the ◆ glyph, room names).
#[must_use]
pub fn room() -> Style {
    Style::default().fg(CYAN)
}

/// Section header ("DIRECT MESSAGES", "CHANNELS", box titles).
#[must_use]
pub fn header() -> Style {
    Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
}

/// Panel border / chrome — dim green so content stands out.
#[must_use]
pub fn border() -> Style {
    Style::default().fg(GREEN_DIM)
}

/// Border of the *focused* / active panel — full green.
#[must_use]
pub fn border_active() -> Style {
    Style::default().fg(GREEN)
}

/// Incoming message text.
#[must_use]
pub fn incoming() -> Style {
    Style::default().fg(CYAN)
}

/// Outgoing message text.
#[must_use]
pub fn outgoing() -> Style {
    Style::default().fg(GREEN)
}

/// Unread-count badge / attention.
#[must_use]
pub fn badge() -> Style {
    Style::default().fg(AMBER).add_modifier(Modifier::BOLD)
}

/// A keybinding chip key (the "^K" part).
#[must_use]
pub fn keychip() -> Style {
    Style::default().fg(AMBER).add_modifier(Modifier::BOLD)
}

/// The label after a keychip (the "palette" part).
#[must_use]
pub fn keylabel() -> Style {
    Style::default().fg(MUTED)
}

/// A good / ready state ("tor ready", "● live").
#[must_use]
pub fn ok() -> Style {
    Style::default().fg(GREEN)
}

/// A transitional / warning state ("bootstrapping", "tor disabled").
#[must_use]
pub fn warn() -> Style {
    Style::default().fg(AMBER)
}

/// A hard error / failed / unreachable state.
#[must_use]
pub fn error() -> Style {
    Style::default().fg(RED).add_modifier(Modifier::BOLD)
}

/// A security alert — key changed, possible MITM. The loudest non-error.
#[must_use]
pub fn alert() -> Style {
    Style::default().fg(MAGENTA).add_modifier(Modifier::BOLD)
}

/// Neutral body text.
#[must_use]
pub fn text() -> Style {
    Style::default().fg(TEXT)
}

/// Muted meta text (timestamps, version, secondary labels).
#[must_use]
pub fn muted() -> Style {
    Style::default().fg(MUTED)
}

/// Selection highlight (the highlighted row in a list).
#[must_use]
pub fn selection() -> Style {
    Style::default()
        .bg(GREEN_DIM)
        .fg(Color::Black)
        .add_modifier(Modifier::BOLD)
}

// ── Brand / ASCII art ───────────────────────────────────────────────────

/// The ONYX onion logo for the left-rail top box. Rendered as the Tor
/// "onion" motif with the centre highlighted. Six lines, designed to fit
/// inside a box ~22 cols wide (the left rail). Caller styles it green.
///
/// Kept deliberately small so it survives a short terminal; the wordmark
/// line below the art carries the brand if the art is clipped.
pub const ONION_ART: &[&str] = &[
    r#"   .-"""""-.   "#,
    "  / _     _ \\  ",
    " |  o)   (o  | ",
    "  \\   ._.   /  ",
    "   '-.....-'   ",
];

/// The wordmark shown under the onion art.
pub const WORDMARK: &str = "O N Y X";

/// One-line tagline under the wordmark (anonymous, E2E, over Tor).
pub const TAGLINE: &str = "anonymous · e2e · tor";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_styles_resolve_to_palette() {
        // Cheap guard: the semantic helpers wire to the intended hues,
        // so a future palette retune doesn't silently cross wires.
        assert_eq!(you().fg, Some(GREEN));
        assert_eq!(alert().fg, Some(MAGENTA));
        assert_eq!(error().fg, Some(RED));
        assert_eq!(room().fg, Some(CYAN));
        assert_eq!(badge().fg, Some(AMBER));
    }

    #[test]
    fn onion_art_fits_left_rail() {
        // The left rail is 22-24 cols; every art line must fit inside a
        // bordered box (width - 2 for the borders, - 2 padding).
        for line in ONION_ART {
            assert!(
                line.chars().count() <= 20,
                "onion art line too wide for the left rail: {line:?} ({} chars)",
                line.chars().count()
            );
        }
    }
}
