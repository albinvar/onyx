//! Human-readable rendering of daemon responses for the CLI.
//!
//! Every one-shot command used to print the raw JSON response. That is the
//! right thing for a script and the wrong thing for a person, so the CLI
//! now picks per invocation:
//!
//!   * **a terminal** → the plain-language rendering in this module;
//!   * **a pipe / redirect, or `--json`** → the JSON response, unchanged,
//!     so existing scripts keep working without a flag.
//!
//! Anything this module has no rendering for falls back to JSON.
//!
//! Text that came from another party (message bodies, nicknames, room
//! names) is passed through [`clean`] first: it is about to be written to
//! the user's terminal, and control characters there can move the cursor,
//! rewrite earlier lines or change the window title.

use std::fmt::Write as _;

use onyx_core::api::{
    ApiResponse, ContactInfo, HistoryEntry, MessageDirection, PeerInfo, RoomHistoryEntry, RoomInfo,
    TorState,
};

const GREEN: &str = "32";
const AMBER: &str = "33";
const RED: &str = "31";
const MAGENTA: &str = "35";
const CYAN: &str = "36";
const DIM: &str = "2";
const BOLD: &str = "1";

/// Styling for the human rendering. Colour is used only when asked for
/// (the caller passes whether stdout is a terminal); every line still
/// reads correctly without it.
#[derive(Debug, Clone, Copy)]
pub struct Style {
    pub color: bool,
}

impl Style {
    fn paint(self, text: &str, sgr: &str) -> String {
        if self.color {
            format!("\x1b[{sgr}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
}

/// Make remote-controlled text safe to print: every control character
/// (including ESC, and newlines inside a single field) becomes `·`.
#[must_use]
pub fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '·' } else { c })
        .collect()
}

/// First eight characters of a fingerprint, ungrouped.
fn short_fp(fingerprint: &str) -> String {
    fingerprint
        .chars()
        .filter(|c| !c.is_whitespace())
        .take(8)
        .collect()
}

fn peer_name(peer: &PeerInfo) -> String {
    peer.nickname
        .as_deref()
        .filter(|n| !n.is_empty())
        .map_or_else(|| peer.short_id.clone(), clean)
}

/// Render `resp` for a person. `None` means "no human rendering — print
/// the JSON".
// One arm per response variant; each is a few lines of formatting.
// Splitting it would only scatter a flat lookup table.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn render(resp: &ApiResponse, style: Style) -> Option<String> {
    let mut out = String::new();
    match resp {
        ApiResponse::Error { message, .. } => {
            let _ = writeln!(out, "{} {}", style.paint("error:", RED), clean(message));
        }
        ApiResponse::StatusOk {
            daemon_version,
            fingerprint,
            tor_state,
            onion,
            hub_count,
            hubs_connected,
            ..
        } => {
            let tor = match tor_state {
                TorState::Ready => style.paint("ready", GREEN),
                TorState::Bootstrapping { percent } => {
                    style.paint(&format!("starting ({percent}%)"), AMBER)
                }
                TorState::Disabled => style.paint("OFF — no anonymity", RED),
            };
            let reachable = match onion {
                Some(_) => style.paint("yes — share `onyx code` with a contact", GREEN),
                None => style.paint("not yet (onion service still publishing)", AMBER),
            };
            let hubs = if *hub_count == 0 {
                style.paint("none configured (direct connections only)", DIM)
            } else if *hubs_connected == *hub_count {
                style.paint(&format!("{hubs_connected}/{hub_count} connected"), GREEN)
            } else if *hubs_connected == 0 {
                style.paint(&format!("0/{hub_count} connected"), RED)
            } else {
                style.paint(&format!("{hubs_connected}/{hub_count} connected"), AMBER)
            };
            let _ = writeln!(out, "{}  v{daemon_version}", style.paint("onyx", BOLD));
            let _ = writeln!(out, "  tor          {tor}");
            let _ = writeln!(out, "  reachable    {reachable}");
            let _ = writeln!(out, "  hubs         {hubs}");
            let _ = writeln!(out, "  fingerprint  {fingerprint}");
        }
        ApiResponse::IdentityOk {
            identity_pub_b32,
            fingerprint,
            hubs,
            ..
        } => {
            let _ = writeln!(out, "{}", style.paint("your identity", BOLD));
            let _ = writeln!(out, "  fingerprint  {fingerprint}");
            let _ = writeln!(out, "  key          {identity_pub_b32}");
            let _ = writeln!(out, "  hubs         {}", hubs.len());
            let _ = writeln!(
                out,
                "{}",
                style.paint(
                    "  Compare the fingerprint with your contact over a channel you trust.",
                    DIM
                )
            );
        }
        ApiResponse::PeersOk { entries } => render_peers(&mut out, entries, style),
        ApiResponse::SendOk => {
            let _ = writeln!(out, "{}", style.paint("sent", GREEN));
        }
        ApiResponse::DialPeerOk => {
            let _ = writeln!(
                out,
                "{} — building a Tor circuit takes 10–60s; check `onyx peers`.",
                style.paint("connecting", GREEN)
            );
        }
        ApiResponse::HistoryOk { messages, .. } => render_history(&mut out, messages, style),
        ApiResponse::ListRoomsOk { rooms } => render_rooms(&mut out, rooms, style),
        ApiResponse::CreateRoomOk { group_id_b32, name } => {
            let _ = writeln!(
                out,
                "{} {}  {}",
                style.paint("created room", GREEN),
                clean(name),
                style.paint(group_id_b32, DIM)
            );
        }
        ApiResponse::SendRoomOk {
            delivered_to_direct,
            delivered_to_hub,
            skipped_no_kem,
            total_members,
            ..
        } => {
            let reached = delivered_to_direct + delivered_to_hub;
            let _ = writeln!(
                out,
                "{} to {reached} of {total_members} member(s) ({delivered_to_direct} direct, {delivered_to_hub} via hub)",
                style.paint("sent", GREEN)
            );
            if *skipped_no_kem > 0 {
                let _ = writeln!(
                    out,
                    "{} {skipped_no_kem} member(s) could not be reached (no route to them yet)",
                    style.paint("warning:", AMBER)
                );
            }
        }
        ApiResponse::RoomHistoryOk { messages, .. } => {
            render_room_history(&mut out, messages, style);
        }
        ApiResponse::InviteToRoomOk { members, .. } => {
            let _ = writeln!(
                out,
                "{} — the room now has {} member(s)",
                style.paint("invited", GREEN),
                members.len()
            );
        }
        ApiResponse::RemoveFromRoomOk { members, .. } => {
            let _ = writeln!(
                out,
                "{} — the room now has {} member(s)",
                style.paint("removed", GREEN),
                members.len()
            );
        }
        ApiResponse::LeaveRoomOk { .. } => {
            let _ = writeln!(out, "{}", style.paint("left the room", GREEN));
        }
        ApiResponse::RoomOpOk => {
            let _ = writeln!(out, "{}", style.paint("done", GREEN));
        }
        ApiResponse::PendingInvitesOk { invites } => {
            if invites.is_empty() {
                let _ = writeln!(out, "No pending invitations.");
            }
            for invite in invites {
                let _ = writeln!(
                    out,
                    "{}  room \"{}\"  from {}  ({} listed member(s))",
                    style.paint(&format!("#{}", invite.id), BOLD),
                    clean(&invite.room_name),
                    short_fp(&invite.from_fingerprint),
                    invite.members
                );
            }
            if !invites.is_empty() {
                let _ = writeln!(
                    out,
                    "{}",
                    style.paint(
                        "  Join with `onyx room accept <id>`, or discard with `onyx room decline <id>`.",
                        DIM
                    )
                );
            }
        }
        ApiResponse::ListContactsOk { contacts } => render_contacts(&mut out, contacts, style),
        ApiResponse::SetContactVerifiedOk { updated } | ApiResponse::SetNicknameOk { updated } => {
            if *updated {
                let _ = writeln!(out, "{}", style.paint("updated", GREEN));
            } else {
                let _ = writeln!(
                    out,
                    "{} no contact with that fingerprint",
                    style.paint("not found:", AMBER)
                );
            }
        }
        ApiResponse::SendInviteOk { tier, was_signed } => {
            let _ = writeln!(
                out,
                "{} ({tier}, invite was {})",
                style.paint("first message sent via hub", GREEN),
                if *was_signed { "signed" } else { "UNSIGNED" }
            );
            let _ = writeln!(
                out,
                "{}",
                style.paint(
                    "  Verify their fingerprint out of band before trusting the conversation.",
                    DIM
                )
            );
        }
        ApiResponse::NetworkStatusOk {
            hubs,
            dm_hub_fallback,
            delivery_receipts,
            contacts,
            contacts_connected,
            rooms,
            queued_messages,
            pending_invites,
        } => {
            if hubs.is_empty() {
                let _ = writeln!(out, "hubs        none (direct contact only)");
            }
            for h in hubs {
                let state = if h.connected {
                    style.paint("connected", GREEN)
                } else if h.failures_in_a_row > 0 {
                    style.paint(
                        &format!("not connected ({} failed attempts)", h.failures_in_a_row),
                        RED,
                    )
                } else {
                    style.paint("connecting", AMBER)
                };
                let _ = writeln!(out, "hub         {}  {state}", clean(&h.label));
                if !h.connected
                    && let Some(e) = &h.last_error
                {
                    let _ = writeln!(out, "            {}", style.paint(&clean(e), DIM));
                }
            }
            let on_off = |b: bool| if b { "on" } else { "off" };
            let _ = writeln!(out, "hub relay   {}", on_off(*dm_hub_fallback));
            let _ = writeln!(out, "receipts    {}", on_off(*delivery_receipts));
            let _ = writeln!(
                out,
                "contacts    {contacts} ({contacts_connected} connected)   rooms {rooms}   \
                 waiting {queued_messages}   invitations {pending_invites}"
            );
        }
        _ => return None,
    }
    Some(out)
}

fn render_peers(out: &mut String, entries: &[PeerInfo], style: Style) {
    if entries.is_empty() {
        let _ = writeln!(
            out,
            "No contacts yet. Share `onyx code`, or run `onyx connect <their code>`."
        );
        return;
    }
    for peer in entries {
        let dot = if peer.connected {
            style.paint("●", GREEN)
        } else {
            style.paint("○", DIM)
        };
        let trust = if peer.key_changed {
            style.paint("KEY CHANGED — verify before trusting", MAGENTA)
        } else if peer.verified {
            style.paint("verified", GREEN)
        } else {
            style.paint("unverified", AMBER)
        };
        let seen = crate::tui::fmt_relative(peer.last_active_unix_ms);
        let _ = writeln!(
            out,
            "{dot} {:<10}  {}  {trust}  {}",
            peer_name(peer),
            style.paint(&peer.short_id, DIM),
            style.paint(&seen, DIM)
        );
        if let Some(preview) = peer
            .last_message_preview
            .as_deref()
            .filter(|p| !p.is_empty())
        {
            let _ = writeln!(out, "    {}", style.paint(&clean(preview), DIM));
        }
    }
}

fn render_history(out: &mut String, messages: &[HistoryEntry], style: Style) {
    if messages.is_empty() {
        let _ = writeln!(out, "No messages yet.");
        return;
    }
    for message in messages {
        let (who, sgr) = match message.direction {
            MessageDirection::Outgoing => ("me  ", GREEN),
            MessageDirection::Incoming => ("them", CYAN),
        };
        let tier = if message.via_hub {
            format!("{} ", style.paint("[hub]", AMBER))
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            "{}  {}  {tier}{}",
            style.paint(&crate::tui::fmt_hhmm(message.ts_unix_ms), DIM),
            style.paint(who, sgr),
            clean(&message.text)
        );
    }
}

fn render_room_history(out: &mut String, messages: &[RoomHistoryEntry], style: Style) {
    if messages.is_empty() {
        let _ = writeln!(out, "No messages yet.");
        return;
    }
    for message in messages {
        let (who, sgr) = match message.direction {
            MessageDirection::Outgoing => ("me".to_string(), GREEN),
            MessageDirection::Incoming => (short_fp(&message.sender_fp), CYAN),
        };
        let _ = writeln!(
            out,
            "{}  {}  {}",
            style.paint(&crate::tui::fmt_hhmm(message.ts_unix_ms), DIM),
            style.paint(&format!("{who:<8}"), sgr),
            clean(&message.text)
        );
    }
}

fn render_rooms(out: &mut String, rooms: &[RoomInfo], style: Style) {
    if rooms.is_empty() {
        let _ = writeln!(
            out,
            "No rooms yet. Create one with `onyx room create <name>`."
        );
        return;
    }
    for room in rooms {
        let _ = writeln!(
            out,
            "{} {:<20}  {} member(s)  {}",
            style.paint("◆", CYAN),
            clean(&room.name),
            room.members.len(),
            style.paint(&room.group_id_b32, DIM)
        );
    }
}

fn render_contacts(out: &mut String, contacts: &[ContactInfo], style: Style) {
    if contacts.is_empty() {
        let _ = writeln!(out, "No contacts pinned yet.");
        return;
    }
    for contact in contacts {
        let flag = if contact.key_changed {
            style.paint("KEY CHANGED — re-verify out of band", MAGENTA)
        } else {
            style.paint("key unchanged since first contact", DIM)
        };
        let _ = writeln!(out, "{}  {flag}", contact.fingerprint);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN: Style = Style { color: false };

    #[test]
    fn remote_text_cannot_inject_terminal_escapes() {
        let resp = ApiResponse::HistoryOk {
            peer_short: "abcdefgh".into(),
            messages: vec![HistoryEntry {
                direction: MessageDirection::Incoming,
                text: "hi\x1b]0;owned\x07\nme  fake line".into(),
                ts_unix_ms: 1_700_000_000_000,
                via_hub: true,
            }],
        };
        let text = render(&resp, PLAIN).expect("rendered");
        assert!(!text.contains('\x1b'));
        assert!(!text.contains('\x07'));
        assert_eq!(text.lines().count(), 1, "a message is always one line");
        assert!(text.contains("[hub]"));
    }

    #[test]
    fn plain_style_has_no_escape_codes() {
        let resp = ApiResponse::PeersOk {
            entries: vec![PeerInfo {
                short_id: "abcdefgh".into(),
                pubkey_b32: "k".into(),
                fingerprint: "fp".into(),
                connected: true,
                last_message_preview: Some("hello".into()),
                last_active_unix_ms: 0,
                pinned: true,
                key_changed: true,
                verified: false,
                nickname: Some("bob".into()),
            }],
        };
        let text = render(&resp, PLAIN).expect("rendered");
        assert!(!text.contains('\x1b'));
        assert!(text.contains("bob"));
        assert!(text.contains("KEY CHANGED"));
        let coloured = render(&resp, Style { color: true }).expect("rendered");
        assert!(coloured.contains('\x1b'));
    }

    #[test]
    fn errors_and_empty_states_read_as_sentences() {
        let err = ApiResponse::Error {
            code: onyx_core::api::ApiErrorCode::NotReady,
            message: "no hubs configured".into(),
        };
        assert_eq!(render(&err, PLAIN).unwrap(), "error: no hubs configured\n");
        let none = ApiResponse::PeersOk { entries: vec![] };
        assert!(
            render(&none, PLAIN)
                .unwrap()
                .starts_with("No contacts yet.")
        );
        // A response with no human form falls back to JSON.
        assert!(render(&ApiResponse::TailStarted, PLAIN).is_none());
    }
}
