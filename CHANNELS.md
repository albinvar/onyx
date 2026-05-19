# Channels / Multi-party Rooms (T6.3) — Design Doc

> **Status: design phase.** No code yet. This document is the prerequisite to T6.3.b through T6.3.f. Open questions in §5 are flagged; resolve them (or note disagreement) before T6.3.b begins. Mirrors the `FEDERATION.md` pattern that worked for T8.3. Last updated: 2026-05-19.

---

## 0. The honest framing

The cryptographic substrate for multi-party chat is **already there**. `MlsParty` in `crates/onyx-core/src/mls.rs` is implemented against RFC 9420's full group semantics — the same `MlsGroup` we use for today's 2-party direct conversations handles N members with no protocol change. Per-message PCS, transcript-binding signatures, ratchet evolution: all of it works at 5 or 50 members the same way it works at 2.

**What's missing is the surface around it.** There is no "Room" concept in `onyx-daemon`. There are no API verbs to create, list, invite into, leave, or send to a room. The TUI has no pane to render one. The vault doesn't persist room ↔ group_id mappings beyond what `mls_state` already does (the MLS state itself survives, but there's no convenient "list my rooms" lookup).

T6.3 is the "wire up the surface" project. The cryptography is solved; the application layer needs to learn it.

**Goals:**

  * `onyx create-room <name>` creates a fresh MLS group with just our identity in it; subsequent invites add members.
  * `onyx invite-to-room <name> <peer-fingerprint>` adds a peer via MLS Welcome through the existing T7.2-mls hub path.
  * `onyx send-to-room <name> <text>` encrypts under the room's MLS group and routes to every member (direct dial if connected; hub sealed-sender envelope otherwise).
  * Receiving an app message tagged for a room surfaces in the TUI as the room (not as a per-peer DM).
  * Leaving a room rotates the group (MLS Remove); other members keep PCS guarantees.

**Non-goals (deferred or explicit):**

  * Room *discovery* — no "list public rooms" service. Same posture as the rest of Onyx: rooms exist via invite, not catalog. (Future work would compose with T8.4-style governance, which we already decided to defer in `DISCOVERY.md`.)
  * Room *moderation* — no admin role, no kick/ban beyond "any member can Remove any other member" which is what MLS allows. Real role-based admin needs a separate design.
  * Room *history backfill for new joiners* — MLS does not give you forward access to messages sent before you joined; that's a property of the ratchet. Onyx will not invent a backdoor around it.
  * **Persistence of room messages on the hub** beyond the standard offline-queue behavior (which already handles 1-1 messages via T8.3.c gossip and per-routing-id queues).

---

## 1. Adversary model — anything new?

T6.3 does NOT introduce new adversary classes. It exercises the existing ones in a wider configuration:

  * **A2 (hub operator)**: a hub forwarding messages to N members instead of 1 sees N routing-ids per message. Same as N parallel 1-1 sends. *No new disclosure*, just N× the existing per-message signal.
  * **A3 (compromised peer)**: an attacker who joins a room sees all subsequent messages in that room. This is the same property as joining any MLS group — it's by-design, not a bug. Mitigation: don't invite people you don't trust into rooms. (Same as IRC, Matrix, Signal groups, every multi-party tool.)
  * **A4 (active network attacker)**: same MLS PCS + sealed envelope as today's 1-1. No degradation.

The honest extra surface T6.3 adds:

  * **Member visibility within the room**: every member sees every other member's fingerprint via the MLS group state. This is a property of MLS; we don't try to hide membership from members. Documented in §7.
  * **"Group ghost" / quiet observer**: an MLS member who joins and then never sends anything is invisible-to-observers-of-traffic-patterns but visible-in-group-state to other members. Same as Matrix/Signal.

---

## 2. Data model

### 2.1 `Room` in the daemon

```rust
pub struct Room {
    /// User-supplied display name. Local-only; not part of the
    /// MLS-group identity. Two members can call the same group
    /// different names.
    pub name: String,

    /// Stable MLS GroupId — the bytes from
    /// `MlsGroupState::group_id_bytes()`. This IS the room's
    /// cryptographic identity; the name is just a label.
    pub group_id: Vec<u8>,

    /// Convenience cache of current members' fingerprints,
    /// derived from the MLS group state at the last write. Used
    /// to route an outgoing message without re-walking the MLS
    /// tree per send. Refreshed on every Commit (invite/remove)
    /// and on every successful Welcome decode at a recipient.
    pub members: Vec<Fingerprint>,

    /// Wall-clock ms when the room was created locally (for
    /// sorting in the TUI). Not authoritative; each member has
    /// their own created_at.
    pub created_at_ms: i64,
}
```

### 2.2 Vault persistence

New table `rooms`:

```sql
CREATE TABLE rooms (
    identity_id     INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    group_id        BLOB NOT NULL,
    name            TEXT NOT NULL,
    members_b32     TEXT NOT NULL,    -- comma-separated fingerprints, base32
    created_at_ms   INTEGER NOT NULL,
    PRIMARY KEY (identity_id, group_id)
);
```

Additive (same `CREATE TABLE IF NOT EXISTS` pattern as `replay_state` from T7.3-sec.2-persist; no schema version bump). Pre-T6.3 vaults pick up the table on next open.

### 2.3 Conversation registry

Today's `conversations::Registry` is per-peer (keyed by X25519 pubkey). T6.3 adds a parallel index keyed by `group_id`:

```rust
pub enum ConversationKey {
    Peer(IdentityPublic),
    Room(Vec<u8>),  // group_id bytes
}
```

Same `ChatLine` ring buffer per `ConversationKey`. TUI renders the same way regardless of which key.

---

## 3. Lifecycle

### 3.1 Create

`onyx create-room <name>`:
1. Daemon calls `MlsParty::create_group()` → fresh `MlsGroupState` with only us as member.
2. Snapshot MLS state → `vault.save_mls_state(identity_id, snap)`.
3. Insert into `rooms` table: `(name, group_id, members=[us], created_at_ms)`.
4. Return `RoomCreated { group_id_b32 }` on the API.

Room is local-only until first invite.

### 3.2 Invite

`onyx invite-to-room <name> <peer-fingerprint>`:
1. Look up room by name → `group_id`.
2. Load the `MlsGroup` via existing `MlsParty::load_group(group_id)`.
3. Fetch the peer's KP via existing `FetchPeerKeyPackage` API (or accept a `--peer-kp-b64` if the user already has it).
4. Call `group.invite(&party, &kp_bytes)` → produces a `Welcome` for the new member.
5. Snapshot + persist MLS state (the group is now N+1 members on our side).
6. Update the `rooms` row's `members_b32` to include the new peer's fingerprint.
7. Wrap the Welcome in a sealed-sender envelope (same `BootstrapPayload::MlsWelcome` we use for 1-1 MLS-tier bootstrap, **plus an `initial_text` that says "you've been invited to room <name>"**).
8. Ship via hub. Recipient daemon decodes the Welcome, joins the group, sees the routing-id alongside an existing 1-1 conversation entry. The "this is a room not a DM" hint is the new field we add to `BootstrapPayload::MlsWelcome` — see §4.1.

### 3.3 Send

`onyx send-to-room <name> <text>`:
1. Look up room → `group_id`, `members`.
2. Load MLS group, encrypt `text` via `MlsGroup::encrypt_app(&party, text.as_bytes())` → `MlsMessageOut` bytes.
3. **Route to each member**: for each member fingerprint:
   * If there's a live direct conversation registered → send via existing FRAME_MLS_APP path.
   * Else → wrap in a `BootstrapPayload` variant — see open question §5.Q3 about whether we add a new `MlsApp` variant or reuse `MlsWelcome`.
4. Snapshot + persist MLS state (the send advanced our ratchet).

### 3.4 Receive

When a daemon receives an MLS app message (any path — direct or via hub):
1. Find the `MlsGroup` it decrypts under by trying current groups.
2. The group's `group_id` is the room identity.
3. Look up the room in the local `rooms` table → name.
4. Push `EventMessage { conversation_key: Room(group_id), ... }` to subscribers.

If a Welcome arrives and the daemon doesn't yet have a row in `rooms` for that group_id, create one — name pulled from the inviter's `initial_text` (we agree on a small format like `room: <name>`).

### 3.5 Leave

`onyx leave-room <name>`:
1. `group.remove(&party, our_leaf_index)` → `Remove` proposal + `Commit`.
2. Ship the Commit to every other member (same routing as send).
3. Delete the local `rooms` row.
4. Persist MLS state.

Other members receive the Commit, process it, rotate the ratchet. We're out of the group; we cannot decrypt subsequent messages — that's MLS PCS for the leaver.

---

## 4. Wire considerations

### 4.1 `BootstrapPayload::MlsWelcome` — new field for room name

Today's variant:

```rust
MlsWelcome {
    welcome: ByteBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    first_message: Option<String>,
}
```

We add:

```rust
MlsWelcome {
    welcome: ByteBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    first_message: Option<String>,
    /// T6.3: when the welcome is into a room (not a 2-party
    /// conversation), this carries the inviter's display name
    /// for the room. Pre-T6.3 recipients ignore the field;
    /// post-T6.3 recipients use it to label the new entry in
    /// their `rooms` table on the first Welcome decode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    room_name: Option<String>,
}
```

Wire back-compat: `#[serde(default)]` keeps pre-T6.3 daemons happy (they treat the Welcome as a 2-party MLS bootstrap, which is what it looked like to them anyway). The room ↔ DM distinction is a local labeling concern, not a protocol-level role.

### 4.2 Message routing — direct vs hub

For each member of a send:
  * **Direct** (already have a live `peer_session` to that fingerprint's X25519): write a `FRAME_MLS_APP` over that session. Existing path, no change.
  * **Hub** (no live session): wrap in a `BootstrapPayload` and ship via hub-deliver to the member's introduction-inbox routing-id. **Open question (§5.Q3)**: do we add a new `BootstrapPayload::RoomMessage { group_id, app_bytes }` variant, or shoehorn into an existing variant?

### 4.3 Per-epoch session tokens (existing — `routing::session_token`)

`routing.rs` already has `session_token(group_secret, index)` for per-epoch in-group routing. Today's 2-party MLS doesn't use it because we always route via the peer's stable inbox-id; for rooms, **the existing `session_token` is the right primitive** — every group epoch derives a per-epoch routing id that all members subscribe to. The hub sees only the routing-id (per-epoch, unlinkable across epochs).

**Open question (§5.Q4)**: do we route room messages via `session_token` for the per-epoch unlinkability win, or via per-member introduction-inboxes for simpler routing logic?

---

## 5. Open questions

  * **Q1**: rooms are local-only-named (each member can call the same group whatever they like). Or do we propagate the inviter's name via the new `room_name` field as the "canonical" name unless the user explicitly renames? *Recommendation: store the inviter's name as the local default; the user can rename freely; the name never goes over MLS app messages.* The MLS group has no concept of a name.

  * **Q2**: should `onyx invite-to-room` accept a `--peer-kp-b64` (operator pasted the KP) OR auto-fetch from the hub directory (same path as T6.2 `fetch-keypackage`)? *Recommendation: support both. The CLI takes the explicit form for scripting/no-hub setups; the no-flag form auto-fetches.*

  * **Q3**: new `BootstrapPayload::RoomMessage` variant for hub-routed in-group messages, or reuse `MlsWelcome` (which already carries arbitrary MLS message bytes)? *Recommendation: new variant `BootstrapPayload::MlsApp { group_id_b32, mls_app_bytes }`. Reusing MlsWelcome would conflate roles and confuse the recipient's "is this a join or a regular message" dispatch.*

  * **Q4**: route hub-relayed in-group messages via per-epoch session tokens (`routing::session_token(group_secret, epoch)`) for unlinkability — OR per-member introduction-inboxes for simplicity? *Recommendation: per-member introduction-inboxes for T6.3.b/c first cut; per-epoch session tokens as a follow-up T6.3.g once the rest is shaken out. Trade-off: simpler routing now, weaker hub unlinkability now, both improvable later without breaking compatibility.*

  * **Q5**: `onyx leave-room` semantics — should we wait for confirmation that other members processed our Commit before removing our local state? *Recommendation: no. Fire-and-forget the Commit; remove local state immediately. PCS works either way; "I am gone" is unilateral. Other members might miss the Commit if they're offline, but the next time they connect to a hub the queue has it (or, if we set `--gossip-mode eager`, multiple hubs do).*

These are recommendations, not decisions. Review before T6.3.b begins.

---

## 6. Slice plan

If this design holds up, implement T6.3 in six slices:

### T6.3.b — data model + create-room (no invite yet) (~1.5 h)
  * `Room` struct in `onyxd::conversations` (or a new `rooms` module).
  * Vault `rooms` table + `save_room` / `list_rooms` / `delete_room`.
  * `ApiRequest::CreateRoom { name }` → calls `MlsParty::create_group`, persists, returns `RoomCreated { group_id_b32, name }`.
  * `ApiRequest::ListRooms` → returns the local rooms vector.
  * Tests: round-trip via vault, list returns inserted rooms.

### T6.3.c — invite-to-room via existing T7.2-mls path (~1.5 h)
  * `BootstrapPayload::MlsWelcome` gains `room_name: Option<String>`.
  * `ApiRequest::InviteToRoom { name, peer_fingerprint, peer_kp_b64 }` (or no `peer_kp_b64` → auto-fetch).
  * Reuse existing `handle_send_bootstrap_mls` infrastructure; pass `room_name` through.
  * Recipient daemon: on `BootstrapPayload::MlsWelcome` decode with `room_name: Some(...)`, create a `Room` row instead of (or alongside) the existing 1-1 conversation registration.
  * Tests: alice creates a room, invites bob, bob's daemon ends up with a `Room` row holding the same `group_id`.

### T6.3.d — send-to-room: direct path only (~1 h)
  * `ApiRequest::SendToRoom { name, text }`.
  * For each member: if a live `peer_session` exists, route via `FRAME_MLS_APP`; if not, emit a `NotReady`-shaped error listing which members weren't online.
  * Per-member persistence of MLS state after the encrypt step.
  * Test: alice + bob both online with direct connections; alice sends to room; bob receives `EventMessage` tagged with `ConversationKey::Room(group_id)`.

### T6.3.e — send-to-room: hub fallback path (~2 h)
  * New `BootstrapPayload::MlsApp { group_id_b32, mls_app_bytes }` variant.
  * Sender: for each offline member, wrap the MLS app message in `BootstrapPayload::MlsApp`, ship via hub to member's introduction-inbox.
  * Recipient: on `BootstrapPayload::MlsApp` decode, find the MLS group by `group_id`, decrypt, emit `EventMessage`.
  * **Note**: this uses per-member inboxes (Q4 recommendation); per-epoch session tokens are a follow-up.
  * Test: alice sends to a room where bob is offline; bob comes online, sees the message via hub queue.

### T6.3.f — TUI room pane + room list (~1.5 h)
  * TUI gains a `[Rooms]` section in the peer list, above the per-peer DM section.
  * `Tab` cycles room/DM panes.
  * `Ctrl-N` opens a "create room" prompt; new commands `/invite <peer>` and `/leave` inside a room pane.
  * Snapshot test for the new layout.

### T6.3.g (follow-up, not blocking) — per-epoch session tokens (~2 h)
  * Switch hub-routed room messages to use `routing::session_token(exported_secret, epoch)` instead of per-member inboxes.
  * Each member subscribes to the per-epoch token on group entry; the hub sees rotating routing-ids per epoch (unlinkable across epochs to the hub).
  * Trade-off: more complex routing (need to track per-epoch subscriptions), but stronger anonymity property.

Total T6.3.b–T6.3.f: ~7.5 hours of focused work, spread across 5 commits. **Not a one-shot.** T6.3.g is genuine follow-up that can happen later.

---

## 7. Threat-model deltas

T6.3 does NOT introduce new adversary classes (as §1 noted). It DOES introduce two design properties worth noting in `THREAT_MODEL.md`:

  * **Member-list visibility within a room**: every member sees every other member's MLS credential (fingerprint). This is a property of MLS, not a leak — but worth being explicit. If you don't want bob to know carol is in a room, don't put them in the same room. *Mitigation: none in protocol; it's a design property.* Will add as `§4 trust assumption` line or `§3 N#` non-defended class.

  * **Room ↔ DM disambiguation depends on a (forward-compatible) wire-format field**: the new `BootstrapPayload::MlsWelcome.room_name: Option<String>` is the discriminator. A pre-T6.3 daemon that receives a room invite treats it as a 2-party MLS bootstrap (no harm; they just see a "DM" with the inviter). This is acceptable but worth flagging — recipients can't tell the difference until they upgrade. *Mitigation: none needed; the property is benign.*

No new `THREAT_MODEL.md` §8.2 carry-forwards. T6.3 is additive feature work that composes safely with existing defenses.

---

## 8. What this design intentionally defers

  * **Role-based moderation**: no admin, no kick, no ban beyond MLS's flat-member Remove. A real role system needs application-layer authorization separate from MLS membership.
  * **Cryptographic history backfill for new joiners**: MLS forbids it by construction. Onyx will not invent a back door.
  * **Public room discovery / listing**: same posture as `DISCOVERY.md` for hubs — rooms exist via invite, not catalog.
  * **Room federation across hub boundaries beyond what T8.3 already does**: today's gossip handles per-routing-id traffic; a room is just N parallel routing-ids. Nothing extra needed.
  * **Persistent message history on the hub**: per the existing offline-queue model (T8.0 + T8.3.c gossip). No "scrollback for new joiner" feature.

---

## 9. Related documents

  * `FEDERATION.md` — hub-to-hub gossip (T8.3). Rooms with members across federated hubs compose for free (each member's introduction-inbox is reachable via gossip).
  * `DISCOVERY.md` — why we don't have public hub discovery. Same posture applies to rooms: no public room list, ever.
  * `ANONYMITY.md` §3 — the residual gap list. T6.3 doesn't expand §3 entries.
  * `THREAT_MODEL.md` §1 (assets) + §3 (non-defended) — T6.3.b will add a one-line member-visibility note.
  * `DESIGN.md` §6 (end-to-end encryption) — already covers MLS group semantics; T6.3 just builds the application surface on top.
  * `ROADMAP.md` §3 — T6.3 listed as the next queued feature.

---

## 10. Decision log

  * **2026-05-19** — Drafted. Awaiting review of §5 open questions (Q1–Q5) before T6.3.b begins.
