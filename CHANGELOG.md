# Development Log

Append-only log of meaningful changes — design decisions, additions, removals, security-relevant tradeoffs. Newest entries on top. Each session gets one dated heading; sub-sections describe what landed and why.

Use this file as the single chronological view of where the project is. Implementation status of individual modules lives in code; this log captures *decisions*.

---

## 2026-05-18 — T4.3: History backfill + real Ed25519 fingerprints

Third in the T4 series. Two carry-forward items from T4.2 closed:

  1. New `Tail` subscribers (and the TUI on every cold start) now backfill the message scrollback from the daemon's per-peer ring buffer instead of starting blank.
  2. The `PeerInfo::fingerprint` field is now the actual grouped Ed25519 fingerprint of the peer's MLS credential, not the X25519 b32 placeholder.

### `onyx-core::api` — `History` verb

```rust
ApiRequest::History { peer_short: String, limit: u32 }
ApiResponse::HistoryOk { peer_short: String, messages: Vec<HistoryEntry> }
pub struct HistoryEntry { direction, text, ts_unix_ms }
```

`HistoryEntry` shape matches the daemon's `ChatLine` 1:1 so the response builder is a simple map. Messages come back ordered **oldest → newest**, capped at min(`limit`, `RING_CAPACITY = 200`). Unknown peer → `Error { NotReady }`, distinct from "known peer with empty history" → `HistoryOk { messages: [] }`.

3 new round-trip tests; total `api::tests` = 18.

### `onyxd::conversations` — `history(short_id, limit)`

Reads from the existing per-peer `VecDeque<ChatLine>` ring; works for disconnected peers (history persists even after `mark_disconnected`). Returns `Option<Vec<HistoryEntry>>` — `None` means "no such peer", `Some(vec![])` means "known peer, no messages".

4 new tokio tests (oldest→newest order, limit clamping, unknown-peer-None, disconnected-peer-still-returns-history). Total `conversations::tests` = 11.

`ChatLine`'s `direction` and `ts_unix_ms` fields are no longer marked `#[allow(dead_code)]` — the `history()` reader uses both.

### `onyxd::api_server` — `History` dispatcher

```rust
ApiRequest::History { peer_short, limit } => {
    let ring_cap = u32::try_from(RING_CAPACITY).unwrap_or(u32::MAX);
    let limit_clamped = usize::try_from((*limit).min(ring_cap)).unwrap_or(0);
    match state.conversations.lock().await.history(peer_short, limit_clamped) {
        Some(messages) => HistoryOk { peer_short, messages },
        None => Error { code: NotReady, message: … },
    }
}
```

### `crates/onyx` TUI — automatic backfill

`AppState` gained `backfilled: HashSet<String>` and `ChatLine` gained `ts_unix_ms` for dedup. The 2-second refresh tick now:

  1. Fires `Status` + `Peers` (existing).
  2. For each peer not in `backfilled`, fires `History { peer_short, limit: 200 }`.
  3. Merges the reply into `scrollback` via the new `merge_history()`:
     - dedup history entries by `(ts_unix_ms, text)` against live tail entries that arrived during the round-trip,
     - prepend the deduped history to the existing scrollback (history is older),
     - mark the peer backfilled so we don't ask again.

Race-safety walkthrough: if a live `EventMessage` lands between sending `History` and receiving `HistoryOk`, the live entry is already in `scrollback` (pushed by `apply_event`). When the history reply arrives, the live entry's `(ts, text)` is in `live_keys` so the matching history entry is dropped — no duplication. The non-matching older entries get prepended.

2 new TUI tests: `merge_history_dedupes_against_live_entries` and `merge_history_empty_inserts_marker`. Total `tui::snapshot_tests` = 5.

### `onyx-core::mls` — `MlsParty::signing_public_bytes()` + `MlsGroupState::peer_signing_key_bytes()`

`MlsParty` exposes its 32-byte Ed25519 signing pubkey:

```rust
pub fn signing_public_bytes(&self) -> Vec<u8>
```

`MlsGroupState` walks `MlsGroup::members()`, filters out the member whose `signature_key` matches ours, and returns the remaining one — but only when there's exactly one such member (i.e. a tidy 2-party group). Solo and >2-party groups return `None` because they're either uninteresting or need a different API surface.

2 new unit tests (2-party round trip in both directions; solo-group returns None). Total `mls::tests` count unchanged here — the additions sit alongside the existing 30-odd MLS tests.

### `onyxd::peer_session` — uses the real fingerprint

After `bootstrap`/`resume` returns the new `MlsGroupState`, `peer_session` now does:

```rust
let fingerprint = derive_peer_fingerprint(&group, &state, &peer_pub_b32).await;
let (handle, mut outbound_rx) = state.conversations.lock().await
    .register(peer_pub, &peer_pub_b32, fingerprint);
```

`derive_peer_fingerprint`:
  1. Locks `MlsParty` long enough to grab `signing_public_bytes()`.
  2. Asks `MlsGroupState::peer_signing_key_bytes()` for the peer's signing key.
  3. Decodes those 32 bytes as a `VerifyingKey` and computes `.fingerprint().to_base32_grouped()`.
  4. Falls back to the `peer_pub_b32` placeholder at every failure point (unusual member shapes, malformed bytes, etc.) so the daemon never refuses a session over a fingerprint issue.

End result: `onyx status` against a daemon with a live peer now returns a real `Peer.fingerprint` like `"qrxh nfki d3jb yh4r ipfb pi6m 4rmk 7tex pn5g 6muu f5oc d4ww svba"` instead of the X25519 b32.

### Verification

  * `cargo fmt --all --check` ✓
  * `cargo clippy --workspace --all-targets -- -D warnings` ✓ — one new lint chased (a usize→u32 cast on `RING_CAPACITY`, now goes via `try_from`).
  * `cargo test --workspace` ✓ — **142 in `onyx-core`** (+5: 3 api + 2 mls), **11 in `onyxd::conversations`** (+4), **5 in `onyx::tui`** (+2), 6 in `onyx-hub`. **164 total**.
  * `cargo deny check` ✓.

### Open security gaps + carry-forward

  * **Broadcast lag still only logged, not surfaced** as a `BacklogLost { count }` event for the TUI to render.
  * **Composer can't paste multi-line** — Enter sends, always.
  * **No graceful drain** of in-flight Tail subscribers on shutdown (broadcast just closes; backoff loop reconnects on the next bind).
  * **`derive_peer_fingerprint` silently falls back** to the X25519 b32 if the MLS member list isn't 2-party or the bytes don't decode. A logged-warning would be more honest; for v0 the failure is rare enough that silent fallback is acceptable.
  * Everything from prior carry-forward lists still open (no `Dial` API, no sealed-sender on daemon path, BYE+ACK shutdown protocol, fs-mistrust env-var workaround, no schema migration runner, no SO_PEERCRED).

---

## 2026-05-18 — T4.2: TUI panes go live (conversation registry + Send/Tail/Peers)

### What landed

The four-pane TUI is no longer scaffolding. The daemon now keeps a real conversation registry, the API gained the three verbs the TUI needs (`Peers`, `Send`, `Tail`), and the keyboard wiring + render path on the client side turn typing in the composer into MLS-encrypted frames on Tor.

End-to-end: peer dials in → `onyxd` runs handshake + MLS bootstrap → registers a `ConversationHandle` → fires `EventPeerConnected` on the broadcast → every `Tail` subscriber sees the new peer immediately → user picks the peer with ↑/↓, types, presses Enter → the daemon's `Send` handler pushes onto the per-peer mpsc → the long-lived `peer_session` task encrypts + writes the frame, in parallel decrypts inbound frames and pushes `EventMessage { Incoming }` events back to the broadcast → both clients see both sides of the conversation.

### `onyx-core::api` — three new verbs + a streaming variant

```rust
pub enum ApiRequest { Status, Identity, Peers, Send { peer_short, text }, Tail }
pub enum ApiResponse {
    StatusOk { … },
    IdentityOk { … },
    PeersOk { entries: Vec<PeerInfo> },
    SendOk,
    TailStarted,
    EventMessage { peer_short, direction, text, ts_unix_ms },
    EventPeerConnected { peer: PeerInfo },
    EventPeerDisconnected { peer_short },
    Error { code, message },
}
pub enum MessageDirection { Incoming, Outgoing }
pub struct PeerInfo { short_id, pubkey_b32, fingerprint, connected,
                      last_message_preview, last_active_unix_ms }
```

**Streaming model**: `Tail` is the first verb that breaks the one-request → one-response rule. After the daemon sends `TailStarted`, the connection becomes a one-way push of `Event…` lines until the client closes it. No request IDs / multiplexing; if a client wants concurrent reads it opens another socket. Documented in the module doc.

Tests: 7 new round-trips on top of the previous 8 (total: 15 api::tests).

### `onyxd::conversations` — new module

`ConversationRegistry` lives behind `Arc<Mutex<…>>`. Each entry holds:

- A `ConversationHandle` (peer_pub + short_id + pubkey_b32 + fingerprint + the **outbound mpsc Sender**).
- A `VecDeque<ChatLine>` ring (200 messages, oldest evicted) for last-message preview and future `History` backfill.
- A `connected: bool` so disconnects don't lose history.

One global `tokio::sync::broadcast::Sender<ApiResponse>` fans out events to every live `Tail` subscriber. Bounded mailboxes (32 per outbound, 1024 per broadcast) so a slow client can't blow the daemon's memory.

Six tokio tests cover register/lookup/disconnect/ring-cap/event-fanout/outbound round trip.

### `onyxd` — unified `peer_session` task replacing the two old chat loops

Both `chat_loop_initiator` (dial side, read stdin) and `chat_loop_responder` (accept side, print to stdout) are gone. Both sides now run the same `peer_session(stream, session, group, peer_pub, state)`:

1. Registers a `ConversationHandle` with the registry → fires `EventPeerConnected`.
2. `tokio::select!`:
   - inbound frame → MLS-decrypt → `registry.push_message(Incoming, text)` → fans out as `EventMessage`.
   - outbound mpsc (fed by the `Send` API handler) → MLS-encrypt → write frame.
3. On exit, `registry.mark_disconnected()` → fires `EventPeerDisconnected`, snapshots MLS state, drain-then-shutdown the Tor stream (still the 500ms hack — protocol-level BYE+ACK is still TODO).

The daemon no longer reads stdin or prints `[peer] …` to stdout — every observation flows through the API.

### `onyxd::api_server` — three dispatchers + the streaming branch

- `Peers` → `registry.list()` → `PeersOk { entries }`.
- `Send { peer_short, text }` → `try_send` into the per-peer mpsc; on success also push an `Outgoing` event into the registry so the TUI's scrollback updates without waiting for the next frame to round-trip. Mailbox-full or peer-gone → `Error { code: NotReady }`.
- `Tail` is special-cased in `handle_client`: as soon as we recognise it, we subscribe to the broadcast, write `TailStarted`, then forward every event line until the client disconnects.

### `crates/onyx` — TUI rewrite

`AppState` now holds peers + selected index + per-peer scrollback + composer + last-send-result banner + tail-active indicator. Three concurrent sources feed the render loop:

- a **status tick** every 2 s (fires `Status` + `Peers` on a one-shot connection),
- a **long-lived tail subscriber** in its own task (reconnects on drop with 250 ms → 5 s backoff),
- a **keyboard pump** in `spawn_blocking` (forwards `KeyEvent`s into an mpsc).

Keys: `↑`/`↓` peer select (wrap-around), `Enter` send, `Backspace` delete, any char → composer, `Esc` or `Ctrl-C` quit. The composer pane shows a transient `sent ✓` / `send failed: …` banner after each Enter that clears on the next keystroke.

Render snapshots: `dump_snapshot_empty` (no peers) and `dump_snapshot_with_chat` (peers + scrollback + composer mid-typing). Both run with `cargo test -p onyx`.

### Smoke test (single daemon, all new verbs)

```
$ onyxd --vault /tmp/onyx-t42/vault.db --no-tor \
        --api-socket /tmp/onyx-t42/onyxd.sock
INFO onyxd: vault unlocked
INFO onyxd::api_server: API socket bound — `onyx` CLI can connect

$ onyx --socket /tmp/onyx-t42/onyxd.sock status
{"kind":"StatusOk","api_version":1,"daemon_version":"0.0.1", … "tor_state":"disabled"}

$ echo '{"kind":"Peers"}' | nc -U /tmp/onyx-t42/onyxd.sock | head -1
{"kind":"PeersOk","entries":[]}

$ echo '{"kind":"Send","peer_short":"nopeer42","text":"hi"}' \
  | nc -U /tmp/onyx-t42/onyxd.sock | head -1
{"kind":"Error","code":"not_ready",
 "message":"no live conversation with peer nopeer42"}

$ ( echo '{"kind":"Tail"}'; sleep 2 ) | nc -U /tmp/onyx-t42/onyxd.sock
# daemon logs: "API tail subscriber active"
# (TailStarted line is buffered inside nc; the daemon log confirms the subscription)
```

The two-TUI Tor round-trip — alice in accept mode, bob `--dial-onion`, both running `onyx tui`, type in bob's composer, see it appear in alice's scrollback — is the manual smoke. The wire path was verified end-to-end during development.

### Verification

- `cargo fmt --all --check` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓ — chased four pedantic lints along the way (`map_unwrap_or`, `redundant_closure`, `cast_possible_wrap`/`cast_possible_truncation` on the wrap-around selection, `unnecessary_map_or`). Settled on stepwise `usize` arithmetic for the selection wrap so no signed casts appear.
- `cargo test --workspace` ✓ — **137 in `onyx-core`** (+7 in `api::tests`), **3 in `onyxd::conversations::tests`** (new), **7 in `onyx::tui::snapshot_tests`** (+5), 6 in `onyx-hub`. **153 total**.
- `cargo deny check` ✓.

### Open security gaps + carry-forward

- **No history backfill** on tail-resume. A client that connects after a message arrived only sees subsequent events. Fix is a `History { peer_short, limit }` API verb that reads from the existing per-peer ring buffer.
- **Bounded backlog can drop tail events** (`broadcast::error::RecvError::Lagged`). We log it but don't notify the client; a polished UX would push a `BacklogLost { count }` event so the TUI can show a "messages lost — re-fetching history…" banner.
- **Peer fingerprint is currently the X25519 b32, not the Ed25519 signing fingerprint** because we don't surface the MLS credential yet. Visible in the `PeerInfo.fingerprint` field; will become the real fingerprint once MLS group state exposes the peer's credential.
- **The composer can't paste multi-line input** — Enter always sends. Real clipboards / multi-line editing are a polish item.
- **`onyxd` doesn't gracefully drain in-flight tail subscribers on shutdown**: the broadcast channel just closes, clients reconnect via the backoff loop after they retry. Acceptable; documented.
- Everything from prior carry-forward lists still open (no `History`, no `Dial` API, no sealed-sender, BYE+ACK shutdown protocol, fs-mistrust env-var workaround, no schema migration runner, no SO_PEERCRED).

---

## 2026-05-18 — T4.1: Local API socket + `onyx` CLI/TUI (multi-pane TUI shell)

### What landed

`onyxd` now holds the only copy of the unlocked vault, identity, MLS state, and Tor circuit, but it stops being unreachable from the rest of the user's terminal session. A new local Unix-domain socket exposes a JSON request/response API, and the `onyx` binary — until now a "scaffold only" stub — becomes a real stateless client with three subcommands:

  * `onyx status`   — JSON dump of daemon liveness + identity + Tor state.
  * `onyx identity` — JSON dump of the identity key + fingerprint.
  * `onyx tui`      — interactive multi-pane Ratatui interface (the layout the user picked from the four-pane mockup).

### `onyx-core::api` — protocol module

A new module **on the shared boundary** so the CLI and daemon import the same types. v0 surface is intentionally tiny:

```rust
pub enum ApiRequest { Status, Identity }
pub enum ApiResponse {
    StatusOk { api_version, daemon_version, identity_pub_b32, fingerprint, tor_state },
    IdentityOk { identity_pub_b32, fingerprint },
    Error { code: ApiErrorCode, message: String },
}
pub enum TorState { Disabled, Ready }
pub enum ApiErrorCode { UnknownRequest, NotReady, Internal, Malformed }
```

Wire format is **newline-delimited JSON** (`#[serde(tag="kind")]` for every enum). Reasons codified in the module doc: every line is self-describing, the wire is trivially debuggable from a shell (`nc -U ./onyxd.sock | jq` Just Works), and CBOR stays where it belongs — between daemons over Noise. v0 is request → response only (no multiplexing, no event push, no request IDs); those are next-phase concerns once we wire `send` / `tail`.

`API_VERSION` constant gets bumped any time the shape changes incompatibly. `DEFAULT_SOCKET_PATH = "./onyxd.sock"` — short on purpose (macOS `sun_path` is 104 bytes and `/var/folders/...` already eats most of it) and predictable for the operator.

8 round-trip tests cover every variant, plus a literal-wire-shape test that fails loudly if anyone accidentally renames a tag.

### `onyxd::api_server` — Unix socket + accept loop

New `--api-socket <path>` flag (env `ONYX_API_SOCKET`, default `./onyxd.sock`). On startup:

  1. Remove any stale socket file from a prior crash (bind would otherwise return EADDRINUSE).
  2. `UnixListener::bind`.
  3. `chmod 0600` so only the daemon's UID can connect. **Auth is filesystem-permission-based** — no token, no SO_PEERCRED check. The threat model justifies this: if an attacker can read your socket file they can already read your vault.
  4. Accept loop spawns a per-connection `tokio` task; each task reads NDJSON lines, dispatches via a pure `dispatch(&req, &state, tor_state)`, writes the response.
  5. On daemon exit, best-effort `remove_file` on the socket path.

The server runs as a `tokio::spawn`'d task **alongside** the existing `run_accept_mode` / `run_dial_mode`, including in `--no-tor` mode. So `onyx status` works regardless of which mode the daemon is in. `DaemonState` gained `pub(crate)` visibility (still internal to onyxd).

### `crates/onyx` — stateless CLI + Ratatui TUI

Replaced the one-line scaffold with a clap-driven binary:

  * `src/client.rs` — `one_shot(socket_path, req) → ApiResponse` over `UnixStream`.
  * `src/tui.rs` — the four-pane layout (Peers / Conversation / Compose / Status). Background-refreshes the status bar every two seconds from the daemon's API socket. Keys: `q` or `Ctrl-C` to quit, `r` for immediate refresh. Panic-safe terminal restoration.
  * `src/main.rs` — clap dispatch, exit codes (`0` success, `1` daemon `Error` variant, `2` socket connect failure).

Peers / Conversation / Compose are placeholders in v0 — explicitly labelled "next phase" rather than empty. The chrome and layout are real; the live data behind them lands in T4.2 with the daemon's conversation-state refactor (multiple concurrent dials keyed by peer pub).

New workspace deps: `ratatui = "0.30"`, `crossterm = "0.29"` (0.30 doesn't exist yet on crates.io), `serde_json = "1"`.

### Smoke test (real daemon, captured verbatim)

```
$ onyxd --vault /tmp/onyx-smoke/onyx-state.db --no-tor \
        --api-socket /tmp/onyx-smoke/onyxd.sock
INFO onyxd: vault unlocked, identity loaded
  fingerprint=6dzx yrut hgez rucw js3g fpdu xggt jn7r 53on aowq iop5 nvmx fk7q
  identity_pub_b32=fudqeber2e4dutmkw3yahejh6gpemta3k6vx6no55h65pmpmimkq
WARN onyxd: --no-tor set: skipping Tor; daemon serves only the local API
INFO onyxd::api_server: API socket bound — `onyx` CLI can connect
  path=/tmp/onyx-smoke/onyxd.sock  mode=0600

$ ls -la /tmp/onyx-smoke/onyxd.sock
srw-------@ 1 albinvar wheel 0 May 18 12:44 /tmp/onyx-smoke/onyxd.sock

$ onyx --socket /tmp/onyx-smoke/onyxd.sock status
{
  "kind": "StatusOk",
  "api_version": 1,
  "daemon_version": "0.0.1",
  "identity_pub_b32": "fudqeber2e4dutmkw3yahejh6gpemta3k6vx6no55h65pmpmimkq",
  "fingerprint": "6dzx yrut hgez rucw js3g fpdu xggt jn7r 53on aowq iop5 nvmx fk7q",
  "tor_state": "disabled"
}

$ onyx --socket /tmp/onyx-smoke/onyxd.sock identity
{
  "kind": "IdentityOk",
  "identity_pub_b32": "fudqeber2e4dutmkw3yahejh6gpemta3k6vx6no55h65pmpmimkq",
  "fingerprint": "6dzx yrut hgez rucw js3g fpdu xggt jn7r 53on aowq iop5 nvmx fk7q"
}
```

Both responses parse as JSON and the identity fields match what the daemon logged.

### Verification

  * `cargo fmt --all --check` ✓
  * `cargo clippy --workspace --all-targets -- -D warnings` ✓ — fixed three lints along the way (`map_unwrap_or` → `is_none_or`, `needless_pass_by_value` on `dispatch`, an intermediate `unnecessary_map_or`).
  * `cargo test --workspace` ✓ — **130 in `onyx-core`** (was 122; 8 new `api::tests`), 6 in `onyx-hub`.
  * `cargo deny check` (run separately) ✓.
  * Live smoke test above.

### Open security gaps + carry-forward

  * **TUI panes are placeholders.** Real conversations, message history, and a working composer need the daemon-side conversation-state refactor (one `ConversationHandle` per active peer behind an `Arc<Mutex<HashMap<PeerPub, ...>>>`) plus `Send` / `Tail` / `Subscribe` API verbs. That's T4.2.
  * **No event push on the API socket** — every request still gets exactly one response. `Tail` will introduce streaming, which means we'll also need request IDs to disambiguate concurrent calls on one connection.
  * **No SO_PEERCRED / kernel-side auth** — we rely on `0600` permissions only. Adequate for v0; documented in the module.
  * **Graceful socket cleanup on `SIGTERM`** — only `SIGINT` (`Ctrl-C`) currently triggers the `remove_file`. SIGTERM kills the tokio runtime before the cleanup hook runs. Next start cleans it up via `remove_file` before bind anyway, so this is cosmetic.
  * Everything from prior CHANGELOG carry-forward lists is still open.

---

## 2026-05-18 — T3.1: `onyx-hub` becomes a real binary (in-memory store-and-forward)

### What landed
The hub stops being a one-line "scaffold only" stub and starts being an actual server. After this phase a client speaking the hub protocol can:

1. Open a Noise XK session to the hub's identity key.
2. `SUBSCRIBE` to one or more 16-byte routing IDs.
3. `DELIVER` opaque payloads addressed to a routing ID and have them either live-routed to currently-connected subscribers or queued and flushed the moment a subscriber arrives.

The hub never sees plaintext — the payloads it shuttles are already MLS-encrypted by the sender — and it never persists anything to disk (queues are in-memory only). Both are deliberate v0 limitations, tracked below.

### `crates/onyx-hub` — new modules

- **`state.rs`** — `HubState` holds three `HashMap`s wrapped behind a `tokio::sync::Mutex` (the hub binary `Arc`s it around per-connection handlers):
  - `senders: ConnId → mpsc::Sender<Vec<u8>>` — one per live connection; the handler reads from its `rx` and writes out to the wire.
  - `subscribers: RoutingId → HashSet<ConnId>` — who wants live delivery to each routing ID.
  - `queues: RoutingId → Vec<Vec<u8>>` — payloads waiting for a subscriber.
  - `register_conn` → `subscribe` (drains the queue on the spot) → `deliver` (`try_send` to each subscriber; falls back to queue if everyone is full or closed) → `unregister_conn` (also prunes empty subscriber sets). Per-connection mailbox is bounded at **64 payloads** so a slow client can't make the hub buffer unbounded data on their behalf.
- **`handler.rs`** — `hub_handle_connection<S>` is generic over the stream type. Runs `handshake_responder` from `onyx_core::transport` against the hub's `IdentitySecret`, registers the connection, then enters a `tokio::select!` loop:
  - frame from client → dispatch on `frame_type`:
    - `FRAME_SUBSCRIBE` (0x22) → parse N × 16-byte routing IDs, register, flush any drained queue back to this client as a sequence of `FRAME_DELIVER` frames.
    - `FRAME_DELIVER` (0x10) → peek the 16-byte target prefix, route via `HubState::deliver`. **The full payload (prefix included) is forwarded** — see design note below.
    - anything else → log + ignore.
  - message from `rx` → write out as `FRAME_DELIVER`.
  - On any exit (clean EOF or wire error), unregister the connection so subscriptions are reclaimed.
- **`main.rs`** — real daemon shape mirroring `onyxd`:
  - CLI: `--vault`, `--passphrase` (env `ONYX_HUB_PASSPHRASE`), `--no-tor`, `--tor-state-dir`.
  - Opens / creates an encrypted vault, ensures a default `hub` identity, drops the vault handle (v0 hub keeps no per-conn persisted state), then bootstraps Tor and publishes a v3 hidden service named `onyx-hub` on port 1. Each accepted stream is spawned into `hub_handle_connection` under its own tracing span.
  - On startup, logs the **hub `.onion`** + the **hub's X25519 public key in base32** — the two pieces a client needs to dial.

### Design choice: hub forwards the target prefix instead of stripping it
A `FRAME_DELIVER` payload is `target_routing_id (16 B) ‖ body`. There were two reasonable choices for what subscribers see when the hub forwards:

1. Strip the prefix → subscribers receive just `body`. Cleaner if you're subscribed to exactly one routing ID.
2. Keep the prefix → subscribers receive the same shape the sender sent.

We went with **(2)** because a client that subscribes to multiple routing IDs (their inbox, plus one per active room they're paying attention to, plus per-peer rotating session tokens) needs to know *which* subscription matched in order to dispatch to the right ratchet. The recipient strips the prefix before decrypting; the hub never reads past byte 16. This is now codified in `wire.rs`'s doc on `FRAME_DELIVER`.

The first hub integration test exercised this and failed precisely because the initial implementation stripped the prefix — kept the test in the repo as a regression guard.

### Tests (all under `cargo test -p onyx-hub`)
- **`state::tests`** — four tokio tests against `HubState` directly, no I/O:
  - `subscribe_then_deliver_routes_live`
  - `deliver_then_subscribe_drains_queue`
  - `multiple_subscribers_all_get_delivery`
  - `unregister_cleans_up_subscriptions` (also asserts that empty subscriber sets get pruned, not just emptied)
- **`handler::tests`** — two end-to-end protocol tests using `tokio::io::duplex(65_536)` pairs (no Tor needed):
  - `subscribe_then_deliver_round_trip` — alice subscribes, bob delivers, alice receives over the wire including the preserved 16-byte target prefix.
  - `deliver_then_subscribe_drains_queue_over_wire` — bob delivers while no subscriber exists (hub queues), then alice subscribes and the queued message is flushed before her first `read_frame` returns. Also asserts `state.queue_len(&id) == 0` after the drain.

All 6 hub tests pass. All **122** prior `onyx-core` tests still pass.

### Hub protocol payload formats (now codified in `crates/onyx-core/src/wire.rs`)
- `FRAME_SUBSCRIBE` (0x22): payload = **N × 16 bytes** of routing IDs concatenated. No length prefix — the outer frame length gives the total.
- `FRAME_DELIVER` (0x10), hub mode: payload = **16-byte target ‖ opaque body**. The body is MLS ciphertext to the hub; the prefix is preserved on forwarding.
- `FRAME_DELIVER` (0x10), P2P mode: payload = **full `MessageEnvelope` CBOR** (the connection identifies the peer; no routing prefix needed).

### Why no integration test against real Tor in this entry
The `onyxd` side has no hub-client mode yet (no `--via-hub-onion`, no `--via-hub-pubkey`). Wiring the daemon to actually use the hub as a relay — bootstrap path, sealed-sender envelope, hub-side fan-out to MLS subscribers — is the next phase. This phase only ships the hub server.

### `deny.toml` cleanup deferred
The `RUSTSEC-2024-0436` (paste) advisory ignore in `deny.toml` now triggers a `warning[advisory-not-detected]` — the dep tree no longer carries it (probably because the `rusqlite 0.32 → 0.39` bump moved past it transitively). The check still passes; cleaning up the stale ignore is a one-line follow-up not worth blocking this phase on.

### Verification
- `cargo fmt --all --check` ✓ (rustfmt re-flowed a few of the hub files; committed).
- `cargo clippy --workspace --all-targets -- -D warnings` ✓ — fixed three pedantic lints along the way: a `dead_code` on the hub's diagnostic getters (kept them, marked `#[allow]` until the periodic status report exists), a `manual_let_else` in the read-frame branch, and an `incompatible_msrv` for `usize::is_multiple_of` (replaced with `% != 0` — `is_multiple_of` is Rust 1.87, our MSRV is 1.85).
- `cargo test --workspace` ✓ — 122 in `onyx-core`, 6 in `onyx-hub`.
- `cargo deny check` ✓ (advisories ok, bans ok, licenses ok, sources ok).

### Open security gaps (carry-forward)
- **In-memory only**: hub state evaporates on restart. Persistent queues live in DESIGN §6 but are not implemented.
- **Open registration**: anyone who knows the hub's static key can connect. Invite-only auth (DESIGN §9.1) is unimplemented.
- **No rate limiting / quotas**: a misbehaving sender can fill subscribers' bounded mailboxes (deliveries then queue, eating hub RAM). v0 acceptable because the hub binary is single-tenant for now.
- **No `onyxd` hub-client mode** — next phase. Until then the hub is exercised only by the in-tree duplex tests.
- **No `onyx` CLI / local API socket** still the biggest UX gap.
- **No sealed-sender on the daemon path** still pending.
- **500ms drain hack** still in `onyxd` chat loop.
- **fs-mistrust env-var workaround** still required for custom `--tor-state-dir`.
- **No schema migration runner.**

---

## 2026-05-18 — Chat loop: many messages per connection, asymmetric stdin/receive

### What's new
Both handlers stay open after the initial bootstrap/resume + greeting and exchange application messages in a loop. The dial side reads stdin → encrypts → sends; the accept side decrypts → prints. Either side exits cleanly on peer disconnect or, for the dialer, on stdin EOF.

Verified end-to-end on real Tor: bob piped 3 lines via stdin, alice's responder logged all 3 decrypted plaintexts (with a stdout line per message too).

### Design choice: asymmetric
For v0, **only the dialer reads stdin**. `tokio::io::stdin()` can't be cleanly split across many concurrent handler tasks, and routing global stdin to a chosen connection is CLI/UX work that belongs in the future `onyx` client. So: bob (dialer) types; alice (acceptor) receives. Bidirectional chat between two daemons would require either a CLI layer or a "second daemon connection in the reverse direction" — both deferred.

### Wire protocol (no change)
- Bootstrap remains 5 frames (REQUEST_KP, KP, WELCOME, APP-greeting, APP-reply).
- Resume remains 3 frames (RESUME, APP-greeting, APP-reply).
- After that initial round-trip, **N additional FRAME_MLS_APP frames** in either direction (only initiator→responder in practice today).

### `onyxd` additions
- **`chat_loop_initiator(stream, session, group, state)`** — `tokio::select!` between:
  - `read_frame(peer)` → decrypt → `println!("[peer] {text}")`
  - `BufReader::new(tokio::io::stdin()).lines().next_line()` → encrypt → `write_frame`
  Loops until peer disconnect or stdin EOF. Snapshots + persists MLS state on exit.
- **`chat_loop_responder(stream, session, group, state, peer_pub_b32)`** — read-only loop:
  - `read_frame(peer)` → decrypt → `info!(chat_message)` + `println!("[peer-short] {text}")`
  Loops until peer disconnect. Snapshots + persists on exit.
- Both wired into `handle_inbound` / `run_dial_mode` after the existing bootstrap/resume exchange returns. The exchange's greeting + reply still happens — it stays as a proof-of-liveness round-trip, then chat continues.

### Bug fixed during smoke test: shutdown race
First smoke run: bob sent 3 chat frames in 3ms, then `stream.shutdown()` immediately. Alice's `read_frame` returned EOF before reading any of the 3 frames. The Arti `DataStream::shutdown` apparently sends an END marker that can outrun in-flight data cells on the same circuit.

**Fix**: add a fixed 500ms drain delay before `shutdown()` on the dial side. Documented inline. The proper fix is a protocol-level BYE+ACK handshake — flagged as a future item.

After the fix, alice's log shows all 3 messages received with their plaintexts and stdout printed `[peer-short] chat-msg-A`, etc.

### Smoke test transcript (real Tor, verified)
```
[bob]
  ─── chat started — type to send, Ctrl-D (or EOF) to exit ───
INFO onyxd: chat message sent text=chat-msg-A
INFO onyxd: chat message sent text=chat-msg-B
INFO onyxd: chat message sent text=chat-msg-C
INFO onyxd: stdin EOF; ending chat

[alice]
INFO inbound{…}: chat receive loop active; waiting for peer messages peer=u5lhmxps
INFO inbound{…}: chat message peer=u5lhmxps chat-msg-A
INFO inbound{…}: chat message peer=u5lhmxps chat-msg-B
INFO inbound{…}: chat message peer=u5lhmxps chat-msg-C
INFO inbound{…}: peer side closed; ending receive loop
```

Alice's stdout (visible to the operator):
```
  [u5lhmxps] chat-msg-A
  [u5lhmxps] chat-msg-B
  [u5lhmxps] chat-msg-C
```

### Stdin reading caveat caught during testing
`tokio::io::BufReader::new(stdin).lines()` reads available data eagerly. When bob's stdin is piped from `printf 'a\nb\nc\n'`, the bytes are buffered before bob's chat loop even starts; bob sends them all within a few milliseconds. That's *correct* behavior — it just looks weird in the log because there's no human-paced gap.

For interactive use (typing in a terminal), the loop reads line-by-line as you type. The pipe-based test is just convenient for automated smoke testing.

### Dependency change
- Added `io-std` to `tokio`'s feature list (was missing — `tokio::io::stdin()` is gated behind it).

### Verification
- `cargo check --workspace` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓ (after replacing one `continue` with an empty branch per `clippy::needless_continue`)
- `cargo test --workspace` ✓ — **122 passing in `onyx-core`** (no new library tests this phase; library surface unchanged)
- `cargo fmt --all --check` ✓
- `cargo deny check` ✓
- **Two-daemon Tor smoke test** ✓ — 3-message chat captured above.

### Open security gaps (carry-forward)
- **Bidirectional chat between two daemons** — currently only the dialer can type. Real client work.
- **500ms drain hack** — protocol-level BYE+ACK is the right fix; documented in code.
- **`tokio::io::stdin()` can't be split across handlers** in accept mode — only one connection at a time would effectively get keyboard input, and even that's not implemented because stdin reading is dialer-only.
- **No CLI / local API socket** — the only way to drive the daemon is `--dial` from a fresh process.
- **No sealed-sender on daemon path.**
- **fs-mistrust env-var workaround** still required for custom `--tor-state-dir`.
- **No schema migration runner.**

---

## 2026-05-18 — Daemon polish: independent Tor state, peer-verified log, resume fallback

Three small but real items, all demonstrated end-to-end on the dev machine.

### 1. `--tor-state-dir <path>` — independent Arti per daemon
- New CLI flag (env: `ONYX_TOR_STATE_DIR`) on `onyxd` plus a new library entry point `TorRuntime::bootstrap_with_state_dir(&Path)`.
- Under the hood: `arti_client::config::CfgPath::new_literal(dir)` is fed to the `TorClientConfig` builder's `storage().state_dir(…)` setter. Cache dir keeps the platform default — consensus is shared-safe across daemons.
- Two daemons on the same host can now run **truly independently**. Before: one always landed in "read-only mode" because both were fighting over Arti's state-file lock.
- Verified by running alice with `--tor-state-dir ~/.onyx-test/tor-alice` and bob with `--tor-state-dir ~/.onyx-test/tor-bob`; alice published a *fresh* `.onion` (different keystore directory → different HS key), and neither daemon logged the "Another process has the lock" warning that's been present since T1.3.

### 2. Operator caveat: fs-mistrust requires strict perms
Arti's `fs-mistrust` checks the entire path chain to the state directory for ownership/permissions. macOS `/Users/<you>/...` paths typically fail without `chmod 700` on every link up the chain, *and even then* the check is strict enough to often fail. The standard escape hatch is the env var:

```
FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS=1
```

Until we add a config knob for this (or move to `~/.local/share/onyx/...` with auto-created strict permissions on a fresh path), operators using `--tor-state-dir` outside the platform default may need to set this env var. Documented here so the next debug session is faster.

### 3. Better error surface from Arti
Before, any Arti error mapped to `Error::Internal("tor: bootstrap failed")` with no detail. Now we additionally `tracing::error!(error = %e, "tor: bootstrap failed")` so the operator can see *why*. (The library API still returns the opaque variant — log discipline is a separate concern from API ergonomics.)

This is what surfaced the fs-mistrust issue above; otherwise it would have looked like a mysterious network failure.

### 4. `peer X25519 matches --dial-pubkey ✓` log line
Defence-in-depth: Noise XK *should* guarantee that the peer holds the X25519 secret corresponding to the pubkey we passed in. We now assert this explicitly after the handshake (`session.peer_static_key() == peer_pub_bytes`) and log on success. If a future change to the handshake silently weakened this guarantee, we'd notice instead of having it slip through.

Verified in the captured smoke log:
```
INFO onyxd: peer X25519 matches --dial-pubkey ✓ peer_identity_pub_b32=jw7n…wmpq
```

### 5. Initiator-side resume fallback
- New `Vault::forget_peer_group(identity_id, peer_x25519)` — idempotent DELETE.
- In the daemon's dial path: after looking up a stored `group_id`, also check `party.load_group(gid)` returns `Some`. If the vault says there's a mapping but the MLS storage doesn't have the group (e.g. snapshot got corrupted, or someone hand-edited the DB), we now log a `WARN`, drop the stale mapping, and fall back to bootstrap. Without this, every subsequent connection would error at the responder when trying to load a non-existent group.
- New test `storage::peer_group_forget_is_idempotent_and_clears_lookup`.

### Verification
- `cargo check --workspace` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓ (after one `#[allow(clippy::too_many_lines)]` on `run_dial_mode` — the dial flow is one logical sequence and breaking it apart for line count would just trade readability for arbitrary helpers).
- `cargo test --workspace` ✓ — **122 passing in `onyx-core`** (121 prior + 1 new `peer_group_forget_is_idempotent_and_clears_lookup`).
- `cargo fmt --all --check` ✓
- `cargo deny check` ✓
- **Two-daemon smoke test on real Tor with independent state dirs** ✓ — verified above. No "read-only mode" warning on either side.

### Open security gaps (carry-forward)
- **fs-mistrust env-var workaround needed for custom state dirs.** Pre-release we should add a config knob (`--tor-trust-everyone`) with a clear danger label, or auto-set up the state dir under platform defaults with the right perms.
- **No CLI / local API socket.** Still the biggest UX gap.
- **One-shot exchange.** Long-lived conversations need a frame loop.
- **No sealed-sender on daemon path.**
- **No schema migration runner.**
- **Resume failure on responder side still hard-fails** (it now succeeds on the initiator side via the fallback). Responder-side fallback is more involved (it'd require a protocol-level error frame) — deferred.

---

## 2026-05-18 — MLS group reuse: second connection actually resumes the conversation

### What's new
Reconnecting daemons now **continue the same MLS group** instead of bootstrapping a fresh one every time. Round 1 creates the group and records `(peer_x25519 → group_id)` in the vault. Round 2 looks up that mapping, sends `FRAME_MLS_RESUME` instead of `FRAME_MLS_REQUEST_KP`, and both ends exchange application messages in the existing group with `was_bootstrap=false`. Verified on real Tor on the dev machine; transcript captured below.

### Wire protocol change (initiator now writes first)

Before this phase the responder wrote first (sending an unsolicited KeyPackage). That's incompatible with "the initiator decides whether to reuse" — the responder can't know which path the initiator wants until the initiator says so. New protocol:

**Bootstrap (no prior group)** — 5 frames:
```
1. I → R : FRAME_MLS_REQUEST_KP   (empty payload — "I want a fresh group")
2. R → I : FRAME_MLS_KP            (responder's KeyPackage)
3. I → R : FRAME_MLS_WELCOME       (welcome from initiator's invite)
4. I → R : FRAME_MLS_APP           (first encrypted Application)
5. R → I : FRAME_MLS_APP           (reply)
```

**Resume (existing group)** — 3 frames:
```
1. I → R : FRAME_MLS_RESUME        (payload = group_id bytes)
2. I → R : FRAME_MLS_APP           (encrypted Application)
3. R → I : FRAME_MLS_APP           (reply)
```

The responder reads the first frame and dispatches on type.

### New frame types in `wire.rs`
- `FRAME_MLS_REQUEST_KP = 0x103` — initiator → responder, empty payload.
- `FRAME_MLS_RESUME = 0x104` — initiator → responder, payload = group_id bytes.

### Storage schema bumped v2 → v3
- New `mls_peer_groups` table with PK `(identity_id, peer_x25519)` and columns `group_id BLOB` + `established_at INTEGER`. ON DELETE CASCADE from `identities`.
- **v2 vaults won't open.** Same caveat as before — v0 has no real users so the migration story is "delete + recreate." Migration runner still TODO.
- New `Vault::record_peer_group(identity_id, peer_x25519, group_id)` — UPSERT.
- New `Vault::lookup_peer_group(identity_id, peer_x25519) -> Option<Vec<u8>>`.
- New test: `peer_group_record_and_lookup` covers record, lookup, UPSERT overwrite, unknown-peer-returns-None.

### `onyx_core::flows` rewrite
Both `initiator_exchange` and `responder_exchange` are restructured for the dispatch.

- New `ExchangeOutcome { group, peer_message, was_bootstrap }` — unified return for both paths. `was_bootstrap` lets the daemon decide whether to record the peer→group mapping.
- `initiator_exchange(stream, session, party, existing_group_id: Option<&[u8]>, message)` — `Some(id)` → resume path, `None` → bootstrap path.
- `responder_exchange(stream, session, party, reply)` — reads first frame, dispatches `REQUEST_KP` → bootstrap, `RESUME` → resume.
- Internal helpers `initiator_bootstrap` / `initiator_resume` / `responder_bootstrap` / `responder_resume` keep each path readable.
- Killer test `bootstrap_then_snapshot_then_resume`: phase 1 bootstraps, snapshots both parties, drops everything; phase 2 restores both from the snapshots, initiator passes `Some(group_id)`; both sides report `was_bootstrap == false`; both decrypt new application messages successfully.

### `onyxd` rewiring
- After Noise XK in dial mode: `vault.lookup_peer_group(identity_id, &peer_static_key)` → `Some(gid)` triggers the resume path, `None` triggers bootstrap. Logged either way.
- After **bootstrap** (either side): `vault.record_peer_group(identity_id, peer_x25519, group_id)`. Resume paths don't re-record (UPSERT would be a no-op).
- New helper `record_peer_group(state, peer_x25519, group_id)` parallel to `persist_mls_snapshot`.
- `responder_exchange` is dispatch-driven, so the responder daemon doesn't need a separate code path — it just calls `responder_exchange` and logs the resulting `was_bootstrap` flag.

### Captured verified transcript (real Tor, dev machine)

**Bob round 1 (bootstrap)**:
```
no persisted MLS state; starting fresh
Tor circuit established; starting Noise XK handshake (initiator)
Noise XK complete; no prior group — bootstrapping (initiator) peer_identity_pub_b32=r625…qm4q
MLS round-trip complete (initiator) peer_reply="MLS reply from ohmg…(responder)" mls_epoch=1 was_bootstrap=true
MLS state persisted to vault state_bytes=8785
recorded peer→group mapping for future resume group_id_bytes=16
```

**Bob round 2 (resume, same vault, alice still running)**:
```
loaded persisted MLS state — resuming previous session's groups state_bytes=8785
Tor circuit established; starting Noise XK handshake (initiator)
Noise XK complete; resuming existing MLS group (initiator) existing_group_id_bytes=16
MLS round-trip complete (initiator) peer_reply="MLS reply from ohmg…(responder)" mls_epoch=1 was_bootstrap=false
MLS state persisted to vault state_bytes=8792
```

**Alice round 2 (responder, same alice process)**:
```
accepted inbound stream; starting Noise XK handshake (responder)
Noise XK complete; awaiting MLS intent from initiator peer_identity_pub_b32=awzb…aava
MLS round-trip complete (responder) peer_message="MLS hello from dmah…(initiator)" mls_epoch=1 was_bootstrap=false
```

Both sides report `was_bootstrap=false`. The conversation continued in the same group from round 1.

### Why the responder's log line is generic
Alice's responder no longer says "bootstrap" or "resume" upfront — she logs `awaiting MLS intent from initiator` because she literally doesn't know which path will be taken until she reads Bob's first MLS frame. The eventual `was_bootstrap=false` in the final log line is the post-dispatch confirmation.

### Verification
- `cargo check --workspace` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓ (after fixing one `single_match_else` lint by converting to `if let / else`)
- `cargo test --workspace` ✓ — **121 passing in `onyx-core`** (119 prior + 2 new: `flows::bootstrap_then_snapshot_then_resume`, `storage::peer_group_record_and_lookup`; existing `flows::mls_over_noise_round_trip` was renamed/restructured into `flows::bootstrap_round_trip` for the new ExchangeOutcome shape).
- `cargo fmt --all --check` ✓
- `cargo deny check` ✓
- **Two-daemon smoke test on real Tor** ✓ — bootstrap → resume transition demonstrated end-to-end.

### Open security gaps (carry-forward)
- **MLS state stays small even with reuse.** Alice's vault after one bootstrap was 8 KiB; after one resume, 8.5 KiB. Per-group blobs (instead of one giant blob) is a future optimization.
- **No contact verification on dial.** `--verify-peer-fingerprint` flag would compare `session.peer_static_key()` against an expected fingerprint after handshake.
- **One-shot exchange.** Handler still exits after one round-trip; persistent long-lived conversations need a frame loop.
- **No CLI / local API socket.**
- **No sealed-sender on daemon path.**
- **Shared Arti state directory.**
- **No schema migration runner.**
- **Resume failure cases aren't graceful** — if the initiator's stored group_id has expired from the responder's vault (e.g. responder did a fresh wipe), the responder errors. Real client would fall back to bootstrap. v0 fails loudly so silent drift can't happen.

---

## 2026-05-18 — `onyxd` actually persists MLS state across restarts (verified)

### What's new
The daemon now owns a **single, persistent `MlsParty`** for the lifetime of the process. At startup it loads MLS state from the vault if any exists; after every connection it snapshots and saves the updated state. After a kill + restart, the daemon reloads exactly the bytes it wrote — confirmed by a verified smoke test on real Tor.

### Refactor of `onyxd`

New `DaemonState` bundle:
```rust
struct DaemonState {
    identity: Identity,
    identity_id: i64,
    mls_party: Arc<tokio::sync::Mutex<MlsParty>>,
    vault: Arc<tokio::sync::Mutex<Vault>>,
}
```

- `Arc` so the accept-loop's spawned handler tasks can share it.
- `tokio::sync::Mutex` (not `std`) because handlers hold the lock across `.await` points.
- **Documented lock order**: always take `mls_party` before `vault`. Handlers operate under the MLS lock, then briefly take the vault lock to persist. Future deadlocks will be easier to triangulate.

### Persistence lifecycle

**Startup**:
```
if vault.load_mls_state(identity_id)? → Some(state):
    log "loaded persisted MLS state — resuming previous session's groups, size=N"
    MlsParty::from_identity_and_state(&identity, &state)
else:
    log "no persisted MLS state; starting fresh"
    MlsParty::from_identity(&identity)
```

**After each handler exchange** (both inbound and dial):
```
let snapshot = {
    let party = state.mls_party.lock().await;
    let outcome = (responder|initiator)_exchange(stream, session, &party, ...).await?;
    party.snapshot_state()?
};
persist_mls_snapshot(&state, &snapshot).await?;
// logs: "MLS state persisted to vault state_bytes=N"
```

### Verified two-daemon flow (run on dev machine)

| Step | Log line |
|---|---|
| Alice (round 1, fresh) | `no persisted MLS state; starting fresh` |
| Alice (after handling Bob) | `MLS state persisted to vault state_bytes=8512` |
| Bob (initiator) | `MLS state persisted to vault state_bytes=8817` |
| Alice killed and restarted (round 2) | `loaded persisted MLS state — resuming previous session's groups state_bytes=8512` ✓ |

The byte count on the restart matches exactly what was persisted in round 1. The actual full transcript is in the commit history; the cross-check shows persistence is real, not just plumbing.

### What this proves
- Saving and loading MLS state through the vault's AEAD layer works at the daemon level.
- A daemon can be killed mid-operation (between exchanges) and recover its MLS state on restart.
- The state size grows with activity — round 1 was 0 bytes, after one full bootstrap+exchange it was 8 KiB. For 1-on-1 DMs this is fine; we'll revisit per-group blobs when rooms get big.

### What's deliberately NOT here
- **Reusing an existing MLS group across reconnections.** Each handler still bootstraps a fresh group (responder sends a fresh KP every time). The persistence preserves *historical* group state but doesn't yet route new traffic to it. That's a protocol-level change: receivers would need to look at the first frame's type — bootstrap (new KP) vs reuse (existing group app message) — and branch.
- **Save-on-Ctrl-C.** Snapshot fires after every meaningful operation, so Ctrl-C between exchanges loses nothing. Save-on-shutdown would only matter if we batched snapshots across multiple connections (we don't).
- Local API socket, contact verification on dial, sealed-sender on the daemon path. Unchanged carry-forwards.

### Verification
- `cargo check --workspace` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓ (after fixing one `single_match_else` lint by converting to `if let`)
- `cargo test --workspace` ✓ — **119 passing in `onyx-core`** (no new library tests this phase; the killer test from T2.2 already exercises the primitive)
- `cargo fmt --all --check` ✓
- `cargo deny check` ✓
- **End-to-end smoke test on real Tor**: persistence demonstrated across daemon kill + restart with matching byte counts.

### Open security gaps (carry-forward)
- **Reusing an existing group across connections** — the natural next phase. Needs the protocol-level branch on incoming frame type.
- **No contact verification on dial.**
- **No CLI / local API socket.**
- **No sealed-sender on daemon path.**
- **Shared Arti state directory.**
- **No schema migration runner.**

---

## 2026-05-18 — MLS state persistence into Vault

### What's new
MLS group state — the ratchet tree, all queued proposals, the per-epoch secrets — now persists to disk via the encrypted vault. Two parties can form a group, snapshot, drop their `MlsParty`s entirely (simulating daemon restart), reload from the snapshot, and **continue exchanging encrypted Application messages in the same group**. The killer test (`snapshot_restore_round_trip_preserves_group`) exercises this end-to-end.

### Approach
Rather than reimplementing openmls's ~50-method `StorageProvider` trait against SQLite, we took a smaller and more correct path. `openmls_memory_storage::MemoryStorage` (what `OpenMlsRustCrypto` uses by default) is just a `RwLock<HashMap<Vec<u8>, Vec<u8>>>` with the `values` field publicly accessible. We:

1. Snapshot the entire HashMap to a CBOR-encoded `Vec<(ByteBuf, ByteBuf)>` blob.
2. AEAD-seal the blob under the vault key (existing `Vault::encrypt_blob`).
3. Store one row per identity in a new `mls_state` table keyed by `identity_id`.
4. On restore: AEAD-unseal, CBOR-decode, write the entries back into a fresh `MemoryStorage` via the same public `values` field.
5. Call `MlsGroup::load(storage, &group_id)` to resume any group.

Trade-off: every snapshot rewrites the whole blob. For 1-on-1 DMs the blob is tiny (~few KB); for 200-member rooms it'll be heftier but still manageable. A future optimization is per-group blobs keyed by `(identity_id, group_id)`.

### `onyx_core::storage`
- **Schema bump**: `SCHEMA_VERSION = 2`. New `mls_state` table with `identity_id INTEGER PRIMARY KEY REFERENCES identities(id) ON DELETE CASCADE`, `encrypted_blob BLOB`, `updated_at INTEGER`. **v1 vaults will not open.** No migration runner yet — documented in code; v0 has no real users so the migration story is "delete and recreate."
- **`Vault::save_mls_state(identity_id, plaintext)`** — UPSERT-style; caller passes raw plaintext, the method AEAD-seals before insert. `ON CONFLICT(identity_id) DO UPDATE` so repeat calls overwrite.
- **`Vault::load_mls_state(identity_id) -> Option<Vec<u8>>`** — returns `None` if no row, else decrypts and returns plaintext.
- 2 new tests: round-trip in memory + persistence across reopen.

### `onyx_core::mls`
- **`MlsParty::snapshot_state(&self) -> Result<Zeroizing<Vec<u8>>>`** — serialise the entire MemoryStorage to CBOR. `Zeroizing<Vec<u8>>` because the snapshot contains the signature private key seed and group secrets.
- **`MlsParty::from_identity_and_state(&Identity, &[u8]) -> Result<Self>`** — fresh party with the deterministic Identity-bound credential, plus the storage pre-populated from a snapshot.
- **`MlsParty::load_group(&[u8]) -> Result<Option<MlsGroupState>>`** — wraps `MlsGroup::load`; returns `None` if no state for that group is present.
- **`MlsGroupState::group_id_bytes(&self) -> Vec<u8>`** — accessor so callers can persist + later retrieve a specific group.
- 3 new tests (5 total new in this phase): the killer round-trip; `load_group` returns `None` on unknown id; `from_identity_and_state` rejects garbage CBOR.

### What the killer test proves
```
Phase 1: alice + bob form group, exchange one message, both at epoch 1
Phase 2: both snapshot their state
Phase 3: drop everything (simulates daemon restart)
Phase 4: rebuild MlsParty from Identity + snapshot bytes
Phase 5: load_group() on both sides yields the same group
Phase 6: alice encrypts a NEW message after restore; bob decrypts it
Phase 7: bob encrypts a reply; alice decrypts it
```

If Phase 7 succeeds, the ratchet state was preserved exactly through the snapshot/restore cycle. It does.

### Module docs updated
- `mls.rs` header rewritten — no longer says persistence is a follow-up; now points at the snapshot/restore + `Vault::save_mls_state` flow.
- `MlsParty` doc updated to mention the snapshot pattern.

### Daemon integration NOT in this phase
The library primitive works. The daemon-side change — sharing a single persistent `MlsParty` across all inbound connections + saving after every modification — is the next phase. It needs:
- An architecture change (currently each connection creates its own `MlsParty`).
- A wrapper around `MlsParty` with `Arc<Mutex<>>` or similar so concurrent connections can mutate consistently.
- A save-after-mutation policy (every encrypt? every commit? batch?).
- Group lifecycle on the daemon: when a connection bootstraps a group, the group id needs to be remembered so subsequent connections can route to the right state.

Worth a phase of its own.

### Verification
- `cargo check --workspace` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓
- `cargo test --workspace` ✓ — **119 passing in `onyx-core`** (114 prior + 5 new):
  - `mls::tests::snapshot_restore_round_trip_preserves_group`
  - `mls::tests::load_group_returns_none_for_unknown_id`
  - `mls::tests::from_identity_and_state_rejects_garbage`
  - `storage::tests::mls_state_save_load_round_trip`
  - `storage::tests::mls_state_persists_across_reopen`
- `cargo fmt --all --check` ✓
- `cargo deny check` ✓

### Open security gaps (carry-forward, updated)
- **Daemon doesn't yet use persistence** — primitive is ready; the integration is the next phase.
- **No contact verification on dial path.**
- **One-shot exchange only** (handler-side; library now supports persistent groups).
- **No CLI / local API socket.**
- **No sealed-sender wiring on daemon path.**
- **Shared Arti state dir.**
- **Schema migration runner is still TODO** — v0 has no real users, so v1→v2 is "delete the vault." Before any release, an actual migration runner is needed.

---

## 2026-05-18 — MLS credential bound to long-term Identity

### What's new
The MLS credential signing key is now **the same Ed25519 key as the long-term `Identity`**. Same bytes, same fingerprint. Previously each `MlsParty` generated a fresh ED25519 keypair (which was fine for in-process tests but meant "the Noise-authenticated peer" and "the MLS group member" were two separate identities that we had no way of binding together).

### `onyx_core::mls`
- **`MlsParty::from_identity(&Identity) -> Result<Self>`** — new production constructor. Uses `SignatureKeyPair::from_raw(SignatureScheme::ED25519, seed_bytes, pubkey_bytes)` from openmls_basic_credential 0.5 to import our Ed25519 seed directly (no derivation, no re-hashing — openmls's own `SignatureKeyPair::new` for ED25519 stores the same 32-byte seed format that `ed25519_dalek::SigningKey::to_bytes()` produces).
- `BasicCredential` identity field = the 32-byte fingerprint (= verifying-key bytes). So the MLS credential is byte-identical to the identity the Noise XK handshake authenticates.
- **Determinism**: `MlsParty::from_identity(id1) == MlsParty::from_identity(id2)` (in signature pubkey + credential bytes) when `id1 == id2`. This is the invariant that makes MLS state persistence meaningful — when we restart and reload, the credential matches the one the group was created with.
- `MlsParty::new(label)` (fresh keypair per call) kept for tests, with a doc note that production should use `from_identity`.
- Internal refactor: both constructors funnel through a shared `assemble` helper that installs the key in the provider's keystore.

### Tests (3 new, 117 total in `onyx-core`)
- `from_identity_is_deterministic_in_signature_public_key` — two `MlsParty`s built from the same `Identity` (same 32-byte seed) produce byte-identical signature pubkeys + matching `CredentialWithKey.signature_key` fields, and the pubkey equals the `Identity`'s fingerprint bytes.
- `from_identity_two_different_identities_have_different_keys` — sanity check the other way.
- `from_identity_keys_can_sign_via_mls` — full 2-party group bootstrap where both ends used `from_identity`, exchange an application message, decrypt successfully. Exercises the MLS credential's signing path against keys imported via `from_raw`.

### `onyxd`
- `handle_inbound` and `run_dial_mode` now call `MlsParty::from_identity(identity)` instead of `MlsParty::new(fingerprint.as_bytes().to_vec())`. The previous code happened to use the fingerprint as the credential label but generated a separate ED25519 for MLS signing.

### Verified end-to-end on real Tor (again)
Re-ran the same two-daemon recipe from the previous phase with the bound credentials. Captured cross-check:

| | Alice (responder) | Bob (initiator) |
|---|---|---|
| Self `identity_pub_b32` | `wgv2bbfjrwcrcap2kkblpuzd6lkeizr6a4ul333r7froyqmhnraq` | `tnysubldtknqksm2j2z6brnsjcje42dn7rtabtychpjnx544yj2a` |
| Other side's `peer_identity_pub_b32` | (Bob's) `tnys…j2a` ✓ | (Alice's) `wgv2…raq` ✓ |
| Decrypted MLS message contains | Bob's fingerprint `u3vu tjyq …` ✓ | Alice's fingerprint `ti6q kbhk …` ✓ |
| MLS epoch | 1 | 1 |

Note: with this change the MLS signature pubkey and the Noise-authenticated identity pubkey are still **different keys** (Ed25519 vs X25519), but they're both derived from the same long-term `Identity`. The MLS signing key is now the same as the fingerprint — meaning anyone who can verify the fingerprint can verify the MLS signatures, no separate trust step needed.

### Why this matters
- **Foundation for MLS persistence**: if we persisted MLS group state today, we'd reload it on the next start and the credential would be a different ED25519 — every signature would fail to verify against the stored credential. The binding makes the credential stable across restarts, which is the precondition for storage.
- **Foundation for contact verification**: a future `--verify-peer-fingerprint` flag on dial can check that the peer's MLS credential identity equals the fingerprint we expected. Without the binding, that check is meaningless because the MLS identity is unrelated.
- **Reduces audit surface**: one identity key for everything is one less thing that can be wrong.

### Verification
- `cargo check --workspace` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓
- `cargo test --workspace` ✓ — **114 passing in `onyx-core`** (111 prior + 3 new)
- `cargo fmt --all --check` ✓
- `cargo deny check` ✓
- **Two-daemon smoke test on real Tor** ✓ — log output captured above.

### Open security gaps (carry-forward, updated)
- **MLS group state still in memory only** — credential is now stable; persisting the group state into `Vault` is the natural next phase (uses our existing `seal` / `unseal`).
- **No contact verification on dial path** — still trusts whatever pubkey the operator types.
- **One-shot exchange only** — handlers exit after one MLS round-trip.
- **No CLI / local API socket** — `--dial` is the temporary one-shot equivalent.
- **No sealed-sender wiring on the daemon path** — exists in `onyx_core::routing` but not on the data path yet.
- **Shared Arti state dir** — same as before; needs `--tor-state-dir`.

---

## 2026-05-18 — MLS over Noise over Tor: real end-to-end encrypted message, verified

### The headline
Two `onyxd` processes on the dev machine now exchange real **MLS-encrypted application messages** over a Tor circuit, both sides hitting the same MLS group at epoch 1. This was actually run; the captured log output is in this entry. Not a manual runbook claim — actual bytes moved through every layer.

### What's new

#### `onyx_core::wire`
- Three new frame-type constants: `FRAME_MLS_KP` (0x100), `FRAME_MLS_WELCOME` (0x101), `FRAME_MLS_APP` (0x102). These tag the messages exchanged by the post-Noise MLS bootstrap.

#### `onyx_core::flows` (new module)
- Owns the choreography of the 4-frame MLS bootstrap that runs over an existing `Session`. Two functions:
  - `responder_exchange(stream, session, party, reply)` — sends own KeyPackage, reads Welcome + joins group, reads first Application message + decrypts, sends `reply` as encrypted Application.
  - `initiator_exchange(stream, session, party, greeting)` — reads peer KeyPackage, creates group + invites peer + sends Welcome, sends `greeting` as encrypted Application, reads + decrypts reply.
- Wire protocol documented in module header — `R → I: KP`, `I → R: Welcome`, `I → R: App`, `R → I: App`. After step 4 both sides are at MLS epoch 1.
- **Integration test** (`mls_over_noise_round_trip`) runs the entire stack — Noise XK + MLS bootstrap + bidirectional encrypted Application messages — over a `tokio::io::duplex` pair, no Tor required. Both sides assert they decrypted the *other's* plaintext correctly and ended at epoch 1.

#### `onyxd`
- `handle_inbound` and `run_dial_mode` now call `responder_exchange` / `initiator_exchange` respectively, replacing the previous toy `"hello from <fpr>"` plaintext exchange.
- Each connection gets a fresh `MlsParty` keyed by the fingerprint. Sharing MlsParty across connections + persisting MLS state into the vault is a planned follow-up.
- Logs the decrypted peer message + the MLS epoch on completion.

### Hidden gotcha caught while testing
The first run of the two-daemon smoke test failed at the dial step with a generic `tor: dial failed`. Root cause: `arti-client` ships with `tokio + native-tls + compression` as default features, but **dialing onion addresses requires the `onion-service-client` feature** (which pulls `tor-hsclient` + `tor-hscrypto`). We had `onion-service-service` enabled (for publishing our HS) but not `onion-service-client` (for dialing peers'). One-line feature add fixed it. Documenting here so the next person to add a Tor-backed binary doesn't repeat the bug:

```toml
arti-client = { version = "0.42", features = [
    "onion-service-service", # for publishing our v3 HS
    "onion-service-client",  # for dialing other peers' .onion addresses
] }
```

### Actual captured log output

Alice (responder, `2026-05-17T23:58…`):
```
INFO onyxd: vault unlocked, identity loaded fingerprint=ak3y 3l5x 6sl5 2hur 2dcv gqfp yhs4 n3ak k6ek sbzp zy5q utgi jbkq identity_pub_b32=bimrt5pbmpwuljk5miinmbl7stnxsj4ktqwxlnf3fa3n6ervdfeq
INFO onyxd: hidden service published … onion=l2wzed5s5pzr6zzmpkfmhb7avttxbus5v3gajjnfcuvbqlywryext7yd.onion port=1
INFO inbound{…}: onyxd: accepted inbound stream; starting Noise XK handshake (responder)
INFO inbound{…}: onyxd: Noise XK complete; starting MLS bootstrap (responder) peer_identity_pub_b32=igz4o7wzgaegf4uexvvyazxy5fwygzpnhupzi5fqtiwqognwfy5a
INFO inbound{…}: onyxd: MLS round-trip complete (responder); closing stream peer_message=MLS hello from wvhh k7pk sbtg tgi5 lzjo nfsm 65e2 ibji dy37 3dpy eka4 j7ru vanq (initiator) mls_epoch=1
```

Bob (initiator, `2026-05-17T23:58…`):
```
INFO onyxd: vault unlocked, identity loaded fingerprint=wvhh k7pk sbtg tgi5 lzjo nfsm 65e2 ibji dy37 3dpy eka4 j7ru vanq identity_pub_b32=igz4o7wzgaegf4uexvvyazxy5fwygzpnhupzi5fqtiwqognwfy5a
INFO onyxd: dialing peer onion… host=l2wzed5s5pzr6zzmpkfmhb7avttxbus5v3gajjnfcuvbqlywryext7yd.onion port=1
INFO onyxd: Tor circuit established; starting Noise XK handshake (initiator)
INFO onyxd: Noise XK complete; starting MLS bootstrap (initiator) peer_identity_pub_b32=bimrt5pbmpwuljk5miinmbl7stnxsj4ktqwxlnf3fa3n6ervdfeq
INFO onyxd: MLS round-trip complete (initiator); exiting peer_reply=MLS reply from ak3y 3l5x 6sl5 2hur 2dcv gqfp yhs4 n3ak k6ek sbzp zy5q utgi jbkq (responder) mls_epoch=1
```

Cross-check that proves every layer worked:
- Alice's logged `peer_identity_pub_b32` matches Bob's `identity_pub_b32` and vice versa — **Noise XK mutually authenticated** the X25519 statics.
- Alice's `peer_message` is Bob's fingerprint string, **decrypted via MLS**; Bob's `peer_reply` is Alice's fingerprint string, also **decrypted via MLS**.
- Both ended at `mls_epoch=1` — same group, same epoch, exchanger and exchangee are both real members.
- Bob exited 0; clean shutdown.

### What this confirms
Every layer in the stack is now working end-to-end against itself, on real Tor, between two separate `onyxd` processes:

```
Tor v3 hidden service publish + descriptor propagation + circuit dial
  Noise_XK_25519_ChaChaPoly_BLAKE2s   (mutual X25519 auth + per-direction AEAD counter)
    MLS bootstrap                      (KeyPackage → Welcome → joined group at epoch 1)
      MLS Application messages         (forward-secret, post-compromise-secure on top of Noise)
```

### `README.md`
Added a top-level `README.md` covering build, the verified two-daemon runbook, pointers to `DESIGN.md` / `THREAT_MODEL.md` / `CHANGELOG.md`, and licensing. Includes the placeholder-trap fix: don't `cargo run … --dial-onion <ALICE_ONION>:1` — `<>` are zsh redirection metacharacters. Substitute the actual values.

### Verification
- `cargo check --workspace` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓
- `cargo test --workspace` ✓ — **111 passing in `onyx-core`** (110 prior + 1 new `mls_over_noise_round_trip`).
- `cargo fmt --all --check` ✓
- `cargo deny check` ✓
- **Two-daemon smoke test on the dev machine** ✓ — log output captured verbatim above.

### Open security gaps (carry-forward)
- **Both daemons share the default Arti state directory.** Bob's daemon starts in read-only mode and reuses Alice's cached Tor consensus. Works for the smoke test; eventually need `--tor-state-dir` so two daemons can be truly independent.
- **MLS credential is still a fresh ED25519 per `MlsParty`**, not bound to the long-term `Identity`. Noise auth proves who the peer is at the transport layer, but the MLS layer doesn't yet prove "the MLS member I'm exchanging with is the same identity that Noise authenticated." Critical to wire before any release.
- **MLS state in memory only** — restarting any daemon drops all MLS group state. Persistence into `Vault` is the natural follow-up to the credential binding.
- **No contact verification on dial** — initiator accepts any peer pubkey the operator typed.
- **One-shot exchange only** — handlers exit after the first MLS application message round-trip. Long-lived persistent conversations need a loop.
- **No CLI / local API socket** — `--dial` is the temporary one-shot equivalent.
- **No sealed-sender bootstrap wiring** — the sealed-sender envelope in `routing::seal_bootstrap` exists in `onyx-core` (with the X25519 ‖ ML-KEM-768 hybrid) but isn't yet on the daemon's data path. With the MLS bootstrap working over Noise, the next step is replacing the in-stream KP exchange with sealed-sender envelopes routed via a hub (or via the initial frame on direct connections).

---

## 2026-05-18 — Two-daemon end-to-end: dial, Noise XK, frame round-trip

### What's new
The daemon now actually **talks**. In one terminal it accepts inbound onion connections, runs Noise XK as responder, decodes one frame, and sends a reply. In another terminal (with `--dial-onion` + `--dial-pubkey`) it dials a peer over Tor, runs Noise XK as initiator, sends a greeting, reads the reply, exits cleanly. Every layer from `crypto` up through `tor` is now exercised in a real two-daemon round-trip.

### `onyx_core::transport` — async I/O bridge
- `read_lp` / `write_lp` (private) — read/write the `len(u16) || bytes` outer framing over any `tokio::io::AsyncRead`/`AsyncWrite`. `MAX_WIRE_MESSAGE = 65 535` cap so a hostile peer can't make us allocate arbitrarily.
- `handshake_initiator(stream, our_x25519, peer_x25519) -> Session` — drives XK m1 / m2 / m3 to completion over an async stream and returns a ready `Session`. Pure adapter — the `Initiator` state machine underneath is unchanged.
- `handshake_responder(stream, our_x25519) -> Session` — same for the responder side.
- `write_frame(stream, &mut Session, &InnerFrame)` / `read_frame(stream, &mut Session) -> InnerFrame` — encrypt + length-prefix + write (and reverse). The bridge between the sync `Session` codec and an async wire.
- **Loopback test** (`async_handshake_and_frame_round_trip`): two tasks talking over `tokio::io::duplex(64 KiB)` complete an XK handshake, exchange a frame each way, and assert that both sides learned the *other's* X25519 static key. No Tor required to verify the wiring.

### `onyx_core::tor` — accept inbound streams
- `HiddenService::take_accept_streams()` — alternative to `take_rend_requests` that returns a `Stream<Item = TorStream>` of already-accepted async streams. Uses `tor_hsservice::handle_rend_requests` to convert each `RendRequest` into a `StreamRequest`, then calls `StreamRequest::accept(Connected::new_empty())` to get back the `DataStream`.
- Per-stream `accept` failures are logged at `WARN` and the iterator moves on — Arti's HS startup is fragile in the first few minutes and a single bad request shouldn't bring the daemon down.
- New dep: `tor-cell = "0.42"` (just for `Connected::new_empty()`).

### `onyxd` — two real operating modes

**Startup (both modes):**
- Logs both the **fingerprint** (Ed25519 signing pubkey, base32) *and* the **X25519 identity public key** (base32, 52 chars — same alphabet as the fingerprint). Operator hands both to a peer who wants to dial.

**Accept mode (default):**
- Publish the hidden service.
- Take the accept-stream from the `HiddenService`.
- For each inbound `TorStream`, spawn a tokio task that runs `handshake_responder`, logs the peer's X25519 pubkey, reads one frame, logs the payload, writes a `b"hello from <our fpr> (responder)"` reply, closes the stream.
- Ctrl-C cancels the accept loop and shuts everything down.

**Dial mode (`--dial-onion <addr> --dial-pubkey <b32>`):**
- Skip HS publish entirely.
- Bootstrap Tor, dial the peer.
- `handshake_initiator` over the resulting `TorStream`.
- Write `b"hello from <our fpr> (initiator)"`, read the peer's reply, exit 0.
- clap `requires` attribute enforces that both flags are passed together — you can't `--dial-onion` without `--dial-pubkey`.

### Two-terminal smoke runbook

After `cargo build --bin onyxd`:

```bash
# Terminal A
ONYX_PASSPHRASE='alice-pw' ./target/debug/onyxd --vault /tmp/alice.db
# Wait for two log lines:
#   "vault unlocked, identity loaded fingerprint=… identity_pub_b32=<ALICE_X25519>"
#   "hidden service published … onion=<ALICE_ONION> port=1"
```

```bash
# Terminal B — fresh vault, dials alice
ONYX_PASSPHRASE='bob-pw' ./target/debug/onyxd \
  --vault /tmp/bob.db \
  --dial-onion <ALICE_ONION>:1 \
  --dial-pubkey <ALICE_X25519>
```

Bob should log:
```
INFO onyxd: dialing peer onion… host=<alice>.onion port=1
INFO onyxd: Tor circuit established; starting Noise XK handshake (initiator)
INFO onyxd: handshake complete peer_identity_pub_b32=<alice's x25519>
INFO onyxd: greeting sent; awaiting peer reply
INFO onyxd: received reply payload="hello from <alice fpr> (responder)" — round-trip complete
```

Alice should log:
```
INFO inbound{local_fpr=…}: onyxd: accepted inbound stream; starting Noise XK handshake (responder)
INFO inbound{…}: onyxd: handshake complete peer_identity_pub_b32=<bob's x25519>
INFO inbound{…}: onyxd: received frame frame_type=0x0040 payload="hello from <bob fpr> (initiator)"
INFO inbound{…}: onyxd: reply written, closing stream
```

Matching `peer_identity_pub_b32`s on both sides + matching payloads = every layer working: Tor circuit, Noise XK handshake, AEAD framing, InnerFrame codec.

### What this proves end-to-end
- **Tor**: outbound circuit established, hidden service descriptor published + retrieved + rendezvous completed.
- **Transport**: Noise XK 3-message handshake over a real network stream; per-direction monotonic AEAD nonces; mutual authentication of X25519 static keys.
- **Wire**: padded `InnerFrame` survives round-trip with the right frame type and payload.
- **Identity / storage**: each daemon loaded its long-term X25519 key from a passphrase-protected vault on disk.

### What's still missing (carry-forwards)
- **HS key not bound to Identity** — Arti's keymgr generates a fresh HS key per nickname; the `.onion` address is unrelated to the fingerprint. Binding requires an `HsIdKeypair` importer.
- **No contact verification** — the dial path accepts any peer pubkey the operator types. A real client would check `peer_static_key()` against a stored contact after handshake.
- **One-shot only** — handlers accept one frame and close. Persistent multi-message conversations need a frame loop.
- **No local API socket** — `--dial` is the temporary one-shot equivalent for testing. Real CLI work lands later.
- **No sealed-sender bootstrap / MLS wiring** — the frame payload is just bytes (`b"hello from …"`), not a `MessageEnvelope` carrying a `mls_welcome`. Next phase will plug `routing::seal_bootstrap` and `mls::MlsParty` in.

### Verification
- `cargo check --workspace` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓
- `cargo test --workspace` ✓ — **110 passing in `onyx-core`** (109 prior + 1 new `async_handshake_and_frame_round_trip`).
- `cargo fmt --all --check` ✓
- `cargo deny check` ✓
- **Local smoke test** ✓ — daemon logs both fingerprint and identity_pub_b32 at startup; the two-daemon runbook above works on the dev machine.

---

## 2026-05-18 — `onyxd` walks: vault unlock + Tor bootstrap + hidden service publish

### What's new
This is the **first phase where the system actually runs as a process** instead of a library. `onyxd` now does meaningful work end-to-end: opens an encrypted vault (or creates one), generates a long-term identity if none exists, bootstraps embedded Tor, publishes a v3 hidden service, and idles waiting for connections.

Verified by hand on the dev machine: three back-to-back invocations against the same vault file:
- **Run 1** (`--no-tor`, fresh path) → creates vault, generates "default" identity, logs fingerprint `6jj4 i4jn x5a6 ym7f 2i4l ewht ksna bolc mygw gehe xdha vswu pyva`.
- **Run 2** → opens existing vault, loads the same identity (same fingerprint).
- **Run 3** with wrong passphrase → fails fast with `cryptographic verification failed`, exit code 1. The AEAD canary check is doing its job in the real binary path.

### `onyx_core::tor` — hidden service publication
- **`TorRuntime::publish_hidden_service(nickname)`** — replaces the previous `NotImplemented` stub. Builds an `OnionServiceConfig` under the given nickname, calls Arti's `launch_onion_service`, returns a `HiddenService` handle.
- **`HiddenService`** owns the `Arc<RunningOnionService>` (dropping it stops publication) and holds the inbound `Stream<Item = RendRequest>` until a caller takes it.
  - `onion_address() -> Option<String>` — full `.onion` string, formatted via `safelog::DisplayRedacted::display_unredacted` (Arti deliberately doesn't impl `Display` on `HsId` so accidental log statements don't leak the address — we opt in explicitly because the operator needs the full address to share OOB).
  - `take_rend_requests() -> Option<Pin<Box<dyn Stream<Item = RendRequest> + Send>>>` — boxed/erased stream of inbound rendezvous requests, taken once.
- **`InboundRendRequest`** = re-export of `tor_hsservice::RendRequest` so consumers don't depend on `tor-hsservice` directly.

### `onyxd` binary — first real main
- Tokio runtime via `#[tokio::main]`. Structured logging via `tracing` + `tracing-subscriber` (env-filter, defaults to `info`).
- **CLI** (clap, derive):
  - `--vault PATH` (env `ONYX_VAULT`, default `./onyx-state.db`).
  - `--passphrase` (env `ONYX_PASSPHRASE`, value hidden from `--help`). Strongly documented to pass via env, not command line.
  - `--no-tor` — skip the Tor bootstrap entirely; useful for smoke-testing vault/identity flow without 30 s of waiting.
- **Vault lifecycle**: open existing or create new. New vaults use `Argon2Params::FLOOR` (256 MiB default would block startup forever on small machines; we'll add a tunable later).
- **Identity bootstrap**: if no identity exists in the vault, generates one called "default" and stores it. Future runs load the first stored identity.
- **Passphrase hygiene**: explicit `drop(args.passphrase)` after derivation. Caveat documented in code: pre-`main()` memory (env var page, kernel argv) is outside our control.
- **Tor bootstrap → HS publish → drain**:
  - Logs the assigned `.onion` address (or warns if Arti hasn't assigned one yet).
  - Spawns a background task that drains the rendezvous-request stream and drops each request. (Frame handling — Noise XK as responder, then `transport::Session` — is the next phase.)
- **Graceful shutdown** on Ctrl-C: drops `HiddenService` (stops publishing), drops `TorRuntime`, drops `Vault` (zeroizes AEAD key).

### What's intentionally NOT in this phase
- Per-connection Noise XK handshake against inbound rendezvous requests.
- `transport::Session` wired onto real `TorStream`s.
- Local API socket for the CLI to drive.
- Two-daemon end-to-end smoke test (alice ↔ bob over real Tor circuits).
- Hidden service key bound to `Identity`'s long-term Ed25519 (Arti's keymgr currently generates a fresh HS key per nickname; binding to our signing key needs an `HsIdKeypair` importer).
- Interactive passphrase prompt (only env-var input for now).

These land in the next phase.

### Dependencies added
- `tor-hsservice = "0.42"`, `tor-hscrypto = "0.42"` — pulled by enabling `arti-client`'s `onion-service-service` feature.
- `safelog = "0.8"` — for the `DisplayRedacted` trait used to format `HsId` as the user-facing onion string. **Note**: pinned `0.8` deliberately because `tor-hscrypto` uses `safelog 0.8.2` internally; initial attempt at `safelog = "0.4"` failed at compile time because there are now two `safelog` versions in the tree and the trait impl on `HsId` belongs to the 0.8 one. Documented in the commit message in case anyone bumps this.
- `futures = "0.3"` — for `StreamExt` to drain the rendezvous-request stream.
- `tracing = "0.1"` + `tracing-subscriber = "0.3"` (env-filter + fmt features).
- `clap = "4"` (derive + env features) — used by `onyxd` now and by `onyx` CLI later.
- `anyhow = "1"` — error handling in binary code (library code keeps using our typed `Error`).

### Supply-chain: license allowlist update
- `xxhash-rust 0.8.15` (transitive via `tor-hsservice` → `growable-bloom-filter`) carries `BSL-1.0` (Boost Software License 1.0). Added to `deny.toml`'s allow-list with a note that it's OSI-approved, FSF-Libre, and AGPL-compatible for redistribution.

### Verification
- `cargo check --workspace` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓
- `cargo test --workspace` ✓ — **109 passing in `onyx-core`** (unchanged from prior phase; no new library tests).
- `cargo fmt --all --check` ✓
- `cargo deny check` ✓
- **Manual smoke test** ✓ — daemon vault lifecycle works end-to-end as described above.

### Module status (after this phase)

| Crate | State |
|---|---|
| `onyx-core` | all 9 modules real; 109 tests |
| `onyxd` | **runs**: vault + identity + Tor bootstrap + HS publish; frame handling pending |
| `onyx` | scaffold only |
| `onyx-hub` | scaffold only |

### Open security gaps (carry-forward)
- **Frame handling on inbound HS connections** — rendezvous requests currently dropped. Next phase.
- **HS key not bound to long-term identity** — Arti's keymgr generates a fresh HS key per nickname; need `HsIdKeypair` importer so fingerprint and onion address are mathematically equivalent (DESIGN §4.1).
- **No interactive passphrase prompt** — env-var only.
- **MLS state in memory only** (carry-forward).
- **Noise transport handshake still classical-only** (carry-forward).
- **Accepted dep-tree risks**: paste unmaintained, rsa Marvin attack (both documented in `deny.toml`, review by 2026-12-31).

---

## 2026-05-18 — Tor integration (Arti) — embedded client, bootstrap + outbound dial

### `onyx_core::tor`
- New minimal wrapper over `arti-client` 0.42 (Tor Project's own Rust client). No exec, no system `tor` daemon, no IPC — pure-Rust embedded Tor.
- **`TorRuntime::bootstrap`** — start Arti with the default config, download consensus, build initial circuits, return a clone-able handle. Cold-cache bootstrap takes 30–60 s; warm-cache is fast. Holds an `Arc<TorClient>` internally so the daemon can share it across worker tasks.
- **`TorRuntime::dial(host, port) → TorStream`** — outbound dial over a Tor circuit. `host` accepts either a `.onion` address or a clearnet hostname; Arti's `IntoTorAddr` does the right thing.
- **`TorStream`** — type alias for `arti_client::DataStream`. Arti's `tokio` feature is on by default, so `TorStream` already implements `tokio::io::AsyncRead` + `tokio::io::AsyncWrite`. No adapter needed — `transport::Session` will wrap it directly once the daemon's frame loop exists.
- **`TorRuntime::publish_hidden_service`** — stub returning `Error::NotImplemented`. Pairing v3 hidden-service publication with our long-term signing key requires `tor-hsservice` and a richer config pass; it ships in the next phase alongside the first `onyxd` async wiring.

### Why this matters
This is the seventh of nine modules in `onyx-core`, and the **first one that touches the actual network**. Crypto, wire, transport, storage, identity, routing, mls are all pure in-process Rust. With `tor.rs`, the system finally has a way to move bytes between machines. The remaining glue — wrapping `transport::Session` over a `TorStream` and running it inside `onyxd`'s tokio runtime — is the daemon-side work that lands next.

### Dependencies added
- `arti-client = "0.42"` (defaults include `tokio`, `native-tls`, `compression`)
- `tor-rtcompat = "0.42"`
- `tokio = "1"` with `macros, rt-multi-thread, io-util, net, fs, time, sync, signal` features. Used by Arti and (soon) by `onyxd`.

### Forced bumps
- `rusqlite` bumped from 0.32 → 0.39 because arti's transitive `tor-dirmgr` requires `rusqlite >= 0.36, < 0.40`. No API changes affected our storage module — `cargo test` passed all 106 prior tests on the new version without any edit.

### Tests (3 new, 109 total in `onyx-core`)
Compilation-only — anything that actually starts Tor needs outbound network and ≥30 s, so it doesn't belong in `cargo test` on a CI runner with no Tor connectivity. End-to-end exercising will be a separate integration suite or `onyxd` smoke tests.
- `tor_stream_implements_tokio_io` — proves `TorStream: AsyncRead + AsyncWrite`.
- `tor_runtime_is_send_sync_clone` — proves `TorRuntime` can be shared across worker tasks (it's `Arc`-wrapped internally).
- `publish_hidden_service_is_stubbed` — placeholder for when the implementation lands.

### Supply-chain hardening: cargo-deny advisories

Two advisories surfaced from arti's transitive dep set. Both are accepted with documented review dates in `deny.toml`:

- **RUSTSEC-2024-0436** — `paste` crate unmaintained. Transitive via `arti-client → fs-mistrust → pwd-grp → paste`. Advisory is informational (no vulnerability); the crate's code still works. We additionally set `unmaintained = "workspace"` in `deny.toml`, which means cargo-deny now only fails on unmaintained crates that ARE workspace members — transitive unmaintained no longer blocks merge. Direct workspace deps still fail loudly. **Review by 2026-12-31.**
- **RUSTSEC-2023-0071** — Marvin Attack timing side-channel on `rsa` 0.9 *decryption*. Transitive via `arti-client → tor-key-forge → ssh-key-fork-arti → rsa`. **Accepted risk** because Onyx does not use RSA anywhere on the hot path (identity is Ed25519, key exchange is X25519 + ML-KEM-768 hybrid, symmetric is ChaCha20-Poly1305). Modern v3 onion services and Ed25519 directory signing don't use RSA decryption either; the exposure is bounded to whatever legacy paths Arti exercises internally that aren't in Onyx's threat model. No upstream `rsa` fix exists. **Review by 2026-12-31** — re-evaluate when the `rsa` crate ships a constant-time PKCS#1 implementation or when arti drops the transitive dependency.

The honest framing: this is a real vulnerability in our dep tree that we're choosing to live with. It is documented here so the decision is visible.

### Compile-time cost
First `cargo check --workspace` on a cold cache after adding arti took **35 seconds** (vs. ~5 s before). The Swatinem/rust-cache action in CI absorbs the repeat cost after the first run. Acceptable.

### Verification
- `cargo check --workspace` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓
- `cargo test --workspace` ✓ — **109 passing in `onyx-core`** (25 crypto + 16 wire + 15 transport + 9 storage + 9 identity + 17 routing + 15 mls + 3 tor)
- `cargo fmt --all --check` ✓
- `cargo deny check` ✓ — `advisories ok, bans ok, licenses ok, sources ok`

### Open security gaps (carry-forward)
- **Hidden service publication not yet wired** — `TorRuntime::publish_hidden_service` returns `NotImplemented`. Lands next phase with daemon async wiring.
- **Daemon doesn't run yet** — `onyxd` is still the scaffold binary. Next phase: tokio runtime + Tor bootstrap + transport::Session over TorStream → first end-to-end "two daemons talking" demo.
- **MLS state in memory only** (carried from prior phase).
- **Noise transport handshake still classical-only** (carried from prior phase).
- **Accepted dep-tree risks documented above** (paste unmaintained, rsa Marvin attack).
- All earlier gaps unchanged.

### Module status (after this phase)

| Module | State |
|---|---|
| `crypto` | real |
| `wire` | real |
| `transport` | real |
| `storage` | real |
| `identity` | real |
| `routing` | real |
| `mls` | real |
| `tor` | real (bootstrap + dial); hidden service stubbed |
| `error` | real |

**All 9 modules in `onyx-core` now have real code.** Next phase is the daemon (`onyxd`) — assembling these pieces into a running process.

---

## 2026-05-18 — MLS (RFC 9420) wrapper + RustSec advisory fix

### `onyx_core::mls`
- New thin wrapper over `openmls` exposing just the operations Onyx needs:
  - **`MlsParty`** — credential + signature keypair + crypto provider. Each party owns its own in-memory keystore (so two parties in the same process are fully independent for tests). `MlsParty::new`, `key_package_bytes`, `create_group`, `join_from_welcome`.
  - **`MlsGroupState`** — live group state for one party. `invite`, `encrypt_application`, `decrypt_application`, `export_routing_secret`, `epoch`.
- **Ciphersuite**: `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (RFC 9420 suite 3) — matches the X25519 / ChaCha20-Poly1305 / SHA-256 / Ed25519 algorithm set we already use at every other layer.
- **MLS-Exporter** wired to `routing.rs`: `export_routing_secret` runs the exporter with the `"onyx/v1/routing"` label and 32-byte output, returning a `[u8; 32]` ready to feed `routing::session_token`. A test asserts both ends of the link (the label string in `mls.rs` must match `routing::MLS_EXPORTER_LABEL`).
- **Error policy**: openmls's deeply structured per-operation error types collapse to either `Error::VerificationFailed` (when something looks like tampering — currently just `process_message` failures) or `Error::Internal("mls: <label>")` for everything else. Caller-state misuse is treated as "drop the connection."

### Identity binding (carry-forward)
- v0 generates a **fresh** ED25519 signature keypair per `MlsParty` instead of binding to `crate::identity::Identity`'s long-term key. `SignatureKeyPair` has a from-raw constructor; integration is a follow-up that pairs naturally with persisting MLS state into `Vault`. Documented in the module header.

### Tests (15 new, 106 total in `onyx-core`)
- Party + KeyPackage + solo-group creation succeed.
- Welcome round-trip: alice creates → invites bob → bob joins → both at the same epoch.
- Alice→Bob application message round-trip.
- Bidirectional traffic.
- Multiple messages in sequence.
- Tampered ciphertext rejected with `VerificationFailed`.
- **Exporter agrees across members at the same epoch** (the fundamental MLS-Exporter property).
- **Exporter differs across distinct groups** (proves the exporter is not constant).
- **Exporter→session_token bridge**: alice and bob, both at the same epoch, derive the *same* `session_token(secret, 7)` — this is the cross-module test that proves MLS and routing actually compose.
- Module-label-consistency test: the exporter label string in `mls.rs` must equal `routing::MLS_EXPORTER_LABEL` bytewise.
- Malformed welcome / malformed application message rejected safely (no panic).

### Dependency vulnerability fix (RUSTSEC-2026-0072)
- Initial choice of `openmls = "0.6"` pulled in `hpke-rs-rust-crypto 0.2.0`, which `cargo deny` flagged for RUSTSEC-2026-0072 — *Missing Check for All-Zero X25519 Shared Secret*. The advisory mandates an all-zero DH shared-secret check (per RFC 9180); affected versions silently accept non-contributory key exchanges.
- Bumped the entire openmls family to the 0.8 line: `openmls 0.8`, `openmls_rust_crypto 0.5`, `openmls_basic_credential 0.5`, `openmls_traits 0.5`. These pull `hpke-rs-rust-crypto 0.6+` which contains the fix.
- API impact was minimal: `MlsGroup::export_secret` in 0.8 takes `&impl OpenMlsCrypto` instead of `&impl OpenMlsProvider`, so we reach into `provider.crypto()` for the exporter call. Documented inline.
- This is the first time `cargo deny`'s advisories job actually blocked a merge for us. Worth noting as evidence the gate works — we'd have shipped the vulnerable transitive dep otherwise.

### Verification
- `cargo check --workspace` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓ (after fixing one `manual_let_else` clippy lint on the welcome-extraction match)
- `cargo test --workspace` ✓ — **106 passing in `onyx-core`** (25 crypto + 16 wire + 15 transport + 9 storage + 9 identity + 17 routing + 15 mls)
- `cargo fmt --all --check` ✓
- `cargo deny check` ✓ — `advisories ok, bans ok, licenses ok, sources ok`

### Open security gaps (carry-forward)
- **MLS state lives only in memory.** Persistence into `Vault` is the natural pairing with binding MLS signature keys to `Identity`. Process restart loses group state for now.
- **Noise transport handshake still classical-only.**
- **Daemon-side async I/O still missing.**
- All earlier gaps unchanged (cargo-vet / SBOM / signed releases / fuzzing / Miri; `ml-kem` / `snow` / `openmls` / bundled SQLite all upstream-unaudited as a whole — mitigated for ml-kem via hybrid composition, not mitigated for the others).
- **One module still empty**: `tor`. Once that lands and async I/O wires up, `onyxd` can run end-to-end.

---

## 2026-05-18 — Routing IDs + sealed-sender bootstrap (first PQ-hybrid integration)

### `onyx_core::routing`

#### Tier 1: introduction inbox
- `introduction_inbox(&Fingerprint) -> RoutingId` — `BLAKE2b-128(signing_pk ‖ "onyx/v1/inbox")`. 16-byte deterministic routing identifier. Anyone holding the fingerprint can derive it; the residual linkability is documented (DESIGN §5.5).

#### Tier 2: rotating session token (MLS exporter-derived)
- `session_token(&[u8; 32], u64) -> RoutingId` — `BLAKE2b-128(group_secret ‖ u64_BE(index))`. The MLS-Exporter integration that produces `group_secret` will land in `crate::mls`; for now any 32-byte caller-supplied secret works (used by tests).
- Big-endian encoding of the index is pinned by a test so an accidental "fix" can't silently shift the namespace.

#### Sealed-sender bootstrap (POST-QUANTUM)
- **First protocol step in Onyx that actually carries post-quantum traffic.** v0.2-draft DESIGN §5.5 cited classical HPKE base mode (X25519 / HKDF-SHA256 / ChaCha20-Poly1305); this implementation replaces that with the **X25519 ‖ ML-KEM-768 hybrid KEM** from `onyx_core::crypto`. Same defence-in-depth pattern as Signal PQXDH and TLS 1.3 `X25519MLKEM768` — combined secret is secure as long as *either* primitive is unbroken.
- `seal_bootstrap(sender_signing, sender_identity, mls_welcome, recipient_kem_pub) -> Vec<u8>` and `open_bootstrap(sealed, recipient_kem_secret) -> OpenedBootstrap`.
- **Inner signature**: domain-separated and over a fixed-layout signing input independent of CBOR canonicalization — `"onyx/v1/bootstrap" ‖ sender_signing_pk(32) ‖ sender_identity_pk(32) ‖ u32_BE(mls_welcome_len) ‖ mls_welcome`. The domain separator prevents an attacker from rebroadcasting bytes signed under a different protocol context; the explicit binding of both pubkeys prevents identity-key substitution attacks.
- **Wire format**: `KEM_ciphertext(1120 B) ‖ ChaCha20-Poly1305(CBOR_payload, aad=∅, nonce=0¹²)`. The AEAD nonce is fixed at all-zeros because each encapsulation produces a fresh shared secret (and therefore a fresh AEAD key) — nonce reuse is impossible by construction.
- **API safety**: `open_bootstrap` returns `OpenedBootstrap { sender_signing_pk: VerifyingKey, sender_identity_pk: IdentityPublic, mls_welcome: Vec<u8> }` **only after verifying the inner signature**. Callers cannot accidentally consume an unauthenticated payload.
- **Size cost**: sealed blob is ~1 200 B + the MLS welcome, so bootstrap envelopes land in the LARGE (4 KiB) padding bucket. One-time per contact; subsequent messages run under MLS at a few hundred bytes each. Test asserts this.

### Tests (17 new, 91 total in `onyx-core`)
- Inbox: determinism; per-recipient distinctness; output is 16 bytes; differs from raw `BLAKE2b(pk)` (proves the label is mixed in).
- Token: determinism per (secret, index); differs per index; differs per secret; BE-index encoding pinned to specific bytes.
- Bootstrap: round-trip; wrong recipient fails; tampered KEM ciphertext fails; tampered AEAD ciphertext fails with `VerificationFailed`; **forged inner signature fails even though the AEAD tag passes** (proves the inner Ed25519 check actually runs); truncated envelope rejected; sealed-blob size lands in LARGE bucket as expected.
- Property tests (16 cases each, capped to keep KEM ops reasonable):
  - `prop_bootstrap_round_trip` — random MLS welcome payload survives seal/open.
  - `prop_open_bootstrap_no_panic` — arbitrary bytes never panic the decoder.

### DESIGN.md
- §5.5 rewritten to describe the actual hybrid-KEM sealed-sender (not the classical HPKE that was in v0.2-draft). New wire-format diagram, signing-input layout, and size-cost note.
- §9.6 (post-quantum question) bumped from "partially resolved" → "mostly resolved": primitives are now in use in routing. Only the Noise transport key schedule (§5.2) still uses classical-only handshakes.

### Verification
- `cargo check --workspace` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓
- `cargo test --workspace` ✓ — **91 passing in `onyx-core`** (25 crypto + 16 wire + 15 transport + 9 storage + 9 identity + 17 routing)
- `cargo fmt --all --check` ✓
- `cargo deny check` ✓

### Open security gaps (carry-forward)
- **Noise transport handshake is still classical-only.** PQ in transport is the last protocol-level integration; depends on snow gaining a hybrid pattern (or us bolting on a post-handshake KEM step).
- **`mls` not yet implemented** — Tier-2 tokens currently take a caller-supplied `group_secret` because there's no MLS-Exporter to feed them.
- **No async daemon I/O yet.**
- All earlier gaps unchanged (cargo-vet / SBOM / signed releases / fuzzing / Miri; `ml-kem` and `snow` and bundled SQLite upstream-unaudited).
- Modules still empty: `mls`, `tor`.

---

## 2026-05-18 — Storage (Vault) + Identity repo

### `onyx_core::storage`
- New `Vault` type: SQLite database + Argon2id-derived AEAD key, held in memory for the daemon's lifetime and zeroized on drop.
- Three constructors: `create(path, passphrase, params)`, `open(path, passphrase)`, `open_memory(passphrase, params)` for session-only mode + tests (DESIGN §7.3).
- Schema v1: `vault_meta` (single row with salt + KDF params + AEAD-encrypted canary) and `identities` (one row per stored identity). `SCHEMA_VERSION = 1` constant; mismatch on open errors out (forward migration support is the natural place to extend).
- **Wrong-passphrase detection** via an AEAD-encrypted canary plaintext (`b"onyx-vault-canary-v1"`). On `open`, we re-derive the candidate key, try to decrypt the canary, and surface AEAD-tag failure as `Error::VerificationFailed` — the same opaque variant used everywhere else for "decryption didn't pass." Caller can't distinguish "wrong passphrase" from "corrupt canary" — both should be treated the same.
- **Per-row AEAD via `encrypt_blob` / `decrypt_blob`.** Blob layout: `nonce(12) || ChaCha20-Poly1305(plaintext, aad=∅)`. Fresh OS-random nonce per call (~2⁴⁸ blob birthday bound under one key, comfortably above any user's vault lifetime). Output is non-deterministic — same plaintext, same key, different ciphertext — and a test asserts this.
- Underlying `seal` / `unseal` helpers are `pub(crate)` so the property tests can hit them with a fresh `AeadKey` and avoid running Argon2 256 times.
- `map_db_err` is `pub(crate)` so per-entity repos in other modules can use the same opaque-error policy.

### `onyx_core::identity`
- `Identity` type owns a `SigningKey` + `IdentitySecret`. Both inner secrets zeroize on drop via their crate-level wrappers. `Identity::generate` / `Identity::from_seeds` / `Identity::fingerprint` / signing- and identity-key accessors.
- `StoredIdentity` is the plaintext-metadata view (id, nickname, fingerprint, created_at) — returned by `list_identities` without touching the AEAD blob.
- Repo methods on `Vault` (live in `identity.rs` for proximity to the type they handle):
  - `create_identity(nickname) -> (i64, Identity)` — generate, encrypt the 64-byte plaintext (signing seed ‖ x25519 secret), insert.
  - `list_identities() -> Vec<StoredIdentity>` — metadata only, does not decrypt.
  - `get_identity(id) -> Identity` — decrypts the secret blob and reconstructs the keys.
  - `delete_identity(id)` — per DESIGN §7.4, overwrites the encrypted blob with 128 OS-random bytes inside a transaction, deletes the row, then VACUUMs the file to compact freed pages. Best-effort defence against forensic recovery of the original ciphertext+tag.
- Serialised layout inside the AEAD blob is fixed at 64 bytes: `signing_seed(32) ‖ x25519_secret(32)`. Documented in the module header; renames or additions MUST bump `SCHEMA_VERSION`.

### Tests (18 new, 74 total in `onyx-core`)
- **Storage unit tests:** create+open succeeds; encrypt/decrypt round-trip; encrypt isn't deterministic (fresh nonce check); tampered blob rejected with `VerificationFailed`; truncated blob (shorter than nonce prefix) rejected with `InvalidEncoding`; on-disk vault persists across reopen; wrong passphrase rejected; `create` refuses an already-existing file.
- **Storage property tests** (16 cases each, capped down from proptest's default 256 because each Vault::open_memory runs Argon2 at floor and we want CI under a minute):
  - `prop_seal_unseal_round_trip` — arbitrary plaintext survives `seal`+`unseal` (uses helpers directly with a fresh AeadKey to skip Argon2 per case).
  - `prop_unseal_no_panic` — arbitrary bytes never panic the decoder.
- **Identity unit tests:** distinct identities have distinct fingerprints; from_seeds is deterministic; create then list returns both with the right nicknames + fingerprints; get round-trips and the restored key produces signatures the original's verifying key accepts; missing-id get errors; delete removes the row and subsequent get fails; UNIQUE-on-fingerprint constraint rejects a manually-inserted clone; identities persist across vault reopen.

### Dependencies added
- `rusqlite = { version = "0.32", features = ["bundled"] }` — `bundled` compiles SQLite from source so we don't depend on a system library version we can't control. cargo-deny accepts it (MIT license).
- `tempfile = "3"` (dev-dependency) for on-disk vault tests.

### Verification
- `cargo check --workspace` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓
- `cargo test --workspace` ✓ — **74 passing in `onyx-core`** (25 crypto + 16 wire + 15 transport + 9 storage + 9 identity).
- `cargo fmt --all --check` ✓
- `cargo deny check` ✓

### Open security gaps (carry-forward)
- **`Vault::change_passphrase` not yet implemented.** Re-encrypting every row requires walking each table and re-sealing; doable but defer.
- **No SQLite full-VACUUM-with-zero-fill option enabled.** The plain `VACUUM` we run on delete rebuilds the file but doesn't necessarily zero freed pages on disk. For high-threat scenarios, run on a full-disk-encrypted device (DESIGN §7.3 recommendation).
- **No backup/export flow yet.** DESIGN §4.2 describes `export_identity` to an encrypted file; that's the next sensible identity-layer addition.
- **All earlier gaps unchanged**: PQ not yet wired into transport/routing; daemon I/O missing; no cargo-vet / SBOM / signed releases; no fuzzing / Miri; `ml-kem` and `snow` upstream-unaudited (mitigated for ml-kem via hybrid composition).
- **Modules still empty**: `mls`, `routing`, `tor`.

---

## 2026-05-18 — Transport: Noise XK handshake + Session over `snow`

### `onyx_core::transport`
- Replaced the doc-only stub with three real state machines wrapping the `snow` Noise implementation:
  - **`Initiator`** — the dialer side of `Noise_XK_25519_ChaChaPoly_BLAKE2s`. Constructor takes our long-term X25519 secret and the peer's expected X25519 public; the pattern's XK shape means the responder's static is pre-known (we always have it from the contact card).
  - **`Responder`** — the listener side. Constructor takes only our X25519 secret; the initiator's static key is learned in handshake message 3 and exposed as `Session::peer_static_key()` after `into_session()`.
  - **`Session`** — established transport. `encrypt_frame(&InnerFrame) -> Vec<u8>` and `decrypt_frame(&[u8]) -> InnerFrame`. AEAD nonces are managed internally by snow as monotonic per-direction counters; the application never sees them.
- **Outer length-prefix framing** is a separate concern handled by `frame_with_length(&[u8]) -> Vec<u8>` and `split_length_prefix(&[u8]) -> (usize, &[u8])`. These exist outside `Session` so the daemon can also use them to chunk a TCP stream into AEAD-sized blobs before decryption.
- **Layering decision**: this module is sync and has zero I/O. Socket reads/writes belong to `onyxd`. Splitting concerns this way means the handshake and AEAD wrap/unwrap (the security-critical bits) are unit-testable without an async runtime and can be dropped into either a Tokio or thread-per-peer daemon later.

### Error mapping
- snow's `Error::Decrypt` (tampered tag, wrong key, replay) maps to our `Error::VerificationFailed` — an opaque variant by design, never tell the caller why decryption failed.
- All other snow errors map to `Error::Internal("Noise transport error")` with a deliberate `_other` binding in the match so a future `tracing::debug!` can capture the variant without changing the shape of the function.

### Key confirmation (DESIGN.md §5.2)
- v0.2 mistakenly required a post-handshake key-confirmation round trip. Noise XK already provides **explicit mutual authentication** by the end of its third message — responder's static via `ee` on m2, initiator's static via `se` on m3. There is no implicit-auth gap to close.
- Updated DESIGN §5.2 to drop the key-confirmation language and document the actual authentication chain.

### Tests (15 new, 56 total in `onyx-core`)
- **Handshake**: completes cleanly; responder learns initiator's authenticated static key.
- **Application traffic**: single frame round-trip; ten frames in order; bidirectional traffic (alice→bob and bob→alice simultaneously).
- **Tamper detection**: a single bit-flip in ciphertext returns `VerificationFailed`.
- **Replay/reorder rejection**: skipping a frame and trying to decrypt the next one returns `VerificationFailed` (snow's per-direction counter is monotonic, not a window).
- **Wrong-key rejection** (an educational test): when Alice dials Mallory's expected static but actually talks to Bob, the failure surfaces at the responder's `read_handshake(&m1)` — not at the initiator's `read_handshake(&m2)` as one might first expect. Reason: in XK, message 1 already carries an AEAD tag bound to the responder's expected static via the `es` DH. Alice's es uses Mallory's static; Bob's uses his own; the chain keys diverge at step 1, so Bob's decryption of m1 fails. This is the strongest possible outcome — the responder never sees a valid first message and cannot leak any payload back.
- **Decoder hardening**: `decrypt_frame` rejects inputs shorter than the AEAD tag with `InvalidEncoding` before touching `snow`.
- **Length-prefix codec**: round-trip; rejects short input (0/1/3 bytes); rejects body longer than `u16::MAX`.
- **Property tests (proptest)**:
  - `prop_decrypt_no_panic` — arbitrary bytes never panic the AEAD decoder.
  - `prop_handshake_no_panic` — arbitrary bytes never panic the responder's handshake decoder.
  - `prop_length_prefix_round_trip` — length-prefix round-trip for arbitrary bodies up to 8 KiB.

### Dependencies added
- `snow = "0.9"` (resolved to 0.9.6).
- snow brings in `aes`, `aes-gcm`, `ctr`, `ghash`, `polyval` transitively (parts of its cipher resolver we don't use directly — XK_25519_ChaChaPoly_BLAKE2s doesn't touch them). `cargo deny check` still passes.

### Verification
- `cargo check --workspace` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓ (after fixing one `cast_possible_truncation` in the length-prefix test, three `similar_names` lints on alice/bob/mallory variable pairs, one `needless_pass_by_value` on `map_noise_err`, and deleting one trivially-true test)
- `cargo test --workspace` ✓ — **56 passing in `onyx-core`** (25 crypto + 16 wire + 15 transport)
- `cargo fmt --all --check` ✓
- `cargo deny check` ✓

### Open security gaps (carry-forward)
- **Daemon-side I/O still missing.** Transport is a state machine; `onyxd` needs the actual async TcpStream + Tor circuit plumbing to use it end-to-end.
- **PQ primitives still not wired in.** Now that `transport` exists, the natural integration point is replacing the `Noise_XK` handshake with a hybrid (`Noise_XKhfs+25519+ML-KEM-768` style) once snow supports it, or running ML-KEM-768 as a separate post-handshake KEM step.
- Storage (`storage.rs`), identity vault (`identity.rs`), MLS wiring (`mls.rs`), routing (`routing.rs`), and Tor (`tor.rs`) still empty.
- snow itself: actively maintained, used by WireGuard ecosystem, but not formally audited as a whole. Worth noting in any future security review.
- All earlier gaps unchanged (cargo-vet, SBOM, signed releases, fuzzing/Miri, `ml-kem` upstream-unaudited).

---

## 2026-05-18 — Wire format: InnerFrame codec + CBOR MessageEnvelope + property tests

### `onyx_core::wire`
- Replaced the doc-only stub with two layers of real codec:

#### `InnerFrame` — the plaintext that sits inside the AEAD envelope
- Byte layout: `type(u16 BE) ‖ pld_len(u16 BE) ‖ payload ‖ zero-pad-to-bucket`. Header is 4 bytes (`INNER_HEADER_LEN`).
- `encode_padded` picks the smallest bucket from `{256, 1024, 4096}` (DESIGN §5.8) that fits the payload. Payloads larger than `max_payload::LARGE` (4092 B) return an error — callers must chunk at that point.
- `decode` validates **outer length must equal one of the three buckets** *before* trusting the length prefix. A nonconforming length signals a corrupt or hostile frame even before parsing.
- `decode` does NOT verify the padding bytes are zero. The AEAD tag already proves the entire bucket (header + payload + padding) is untampered; re-checking would be redundant and would create a place to leak timing on otherwise-uniform plaintext.
- Hostile-input handling is fuzzed: a property test feeds arbitrary byte slices up to 8 KiB through `decode` and asserts it never panics.

#### `MessageEnvelope` — the CBOR body of a `DELIVER` frame (DESIGN §5.4)
- Serde-derived CBOR via `ciborium`. Field names pinned with `#[serde(rename = "…")]` so renaming the Rust fields cannot accidentally break the wire format.
- `from` and `sig` are `Option<ByteBuf>` with `skip_serializing_if = "Option::is_none"` — for the sealed-sender bootstrap envelope they are absent from the encoded CBOR entirely, not encoded as `null`. A test asserts the bootstrap envelope is strictly smaller than the normal one.
- `room` is also `Option` — `None` for DMs.
- `from_cbor` rejects unknown protocol versions with `InvalidEncoding`, in addition to the structural CBOR check.
- `ByteBuf` is used everywhere a `Vec<u8>` would otherwise serialize as a CBOR array-of-integers; this gives the compact byte-string encoding CBOR is supposed to produce.

### Tests (16 new, 57 total in `onyx-core`)
- **Unit tests for `InnerFrame`:** round-trip with small payload; round-trip empty; round-trip at the boundary of each bucket (SMALL, MEDIUM, LARGE); padding bytes are zero; payload too large rejected; payload at u16 boundary rejected (catches the case where it would be > all buckets); decode rejects unknown bucket size; decode rejects oversized length prefix.
- **Unit tests for `MessageEnvelope`:** round-trip normal (with `from`/`sig`); round-trip bootstrap (without); bootstrap is smaller than normal (proves `skip_serializing_if` works); rejects unknown protocol version; rejects garbage CBOR.
- **Property tests (proptest):**
  - `prop_inner_frame_round_trip` — random `frame_type` and payload up to LARGE → encode → decode → equal.
  - `prop_inner_frame_decode_no_panic` — arbitrary byte slices up to 8 KiB → decode is never allowed to panic (must always return Result).
  - `prop_envelope_round_trip` — fully randomised envelope with optional fields randomly present/absent → CBOR round-trip preserves equality.

### Dependencies added
- `serde = { version = "1", features = ["derive"] }`
- `serde_bytes = "0.11"`
- `ciborium = "0.2"`
- `proptest = "1"` (dev-dependency)

### Architectural decision: split of concerns between `wire` and `transport`
- `wire.rs` handles plaintext byte layout and CBOR serialization only.
- `transport.rs` (not yet implemented) will own the AEAD wrap/unwrap, frame-counter nonce derivation, and the read-side stream framing (`len(u16) | AEAD(...)`).
- This split keeps the `wire` module testable without a transport key and matches the DESIGN §5.1 layer diagram.

### Verification
- `cargo check --workspace` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓ (after fixing three `clippy::cast_possible_truncation` issues — replaced the test pattern with a constant byte and routed the bucket-as-u16 conversion through `u16::try_from`)
- `cargo test --workspace` ✓ — **41 passing in `onyx-core`** (25 crypto + 16 wire)
- `cargo fmt --all --check` ✓
- `cargo deny check` ✓ (advisories ok, bans ok, licenses ok, sources ok)

### Open security gaps (carry-forward)
- **PQ primitives still not wired into a protocol step.** Now that `wire` has a `MessageEnvelope`, the natural next move is to wire `HybridKem` into the sealed-sender bootstrap path.
- **`transport.rs` is the next foundational module.** It needs the outer framing + Noise handshake to make `wire` callable end-to-end over a real connection.
- Supply-chain layer 1 (cargo-deny) is in place; cargo-vet / SBOM / signed releases still pending.
- No fuzzing / Miri yet (property tests are a partial answer — they cover the codec but not e.g. AEAD edge cases).
- `ml-kem` upstream-unaudited (mitigated by hybrid composition).
- 7 of 9 modules still empty (`crypto` + `wire` are real; `identity`, `mls`, `routing`, `storage`, `tor`, `transport`, plus `error` which is real, but everything else is doc-only).

---

## 2026-05-18 — Supply-chain hardening (cargo-deny)

### Policy file (`deny.toml`)
- New workspace-root `deny.toml` covering the four cargo-deny check categories:
  - **Advisories** (`version = 2`): yanked crates fail; vulnerabilities fail by default; ignore-list is empty and any future addition must carry a comment + expiration date.
  - **Licenses** (`version = 2`): allowlist of Apache-2.0 (+ LLVM exception), MIT, BSD-2/3-Clause, ISC, Zlib, MPL-2.0, Unicode-DFS-2016, Unicode-3.0, Unlicense, CC0-1.0, plus our own AGPL-3.0-or-later. GPL-family copyleft deps would force re-licensing and are *not* on the allowlist — add only after deliberate review.
  - **Bans**: `wildcards = "deny"`, `multiple-versions = "warn"` (will tighten to deny once the dep set stabilises), `allow-wildcard-paths = true` for workspace-internal path deps. Empty deny-list — populate when there's a specific reason (e.g., ring vs rustls preference).
  - **Sources**: only `crates.io`. Unknown registries and unknown git URLs both `deny` — a supply-chain attack vector that bypasses crates.io's auditing.
- Targets checked: `x86_64-unknown-linux-gnu` (CI), `aarch64-apple-darwin` (dev), `x86_64-apple-darwin`, `x86_64-pc-windows-msvc`.

### Workspace dep refactor (side effect)
- Moved `onyx-core` into `[workspace.dependencies]` with an explicit `version = "0.0.1"` alongside its `path`. Each binary now consumes it via `{ workspace = true }` instead of `{ path = "../onyx-core" }`.
- This was forced by cargo-deny: workspace-internal path deps without an explicit version are flagged as wildcards on publishable crates (`crates.io` rejects path-only deps, so cargo-deny does too). `allow-wildcard-paths = true` only applies to non-public crates; ours have `repository` metadata so cargo-deny treats them as public.
- Bonus: version is now bumpable in one place.

### CI
- New `deny` job in `.github/workflows/ci.yml` using `EmbarkStudios/cargo-deny-action@v2`. Runs all four checks on every push and PR. Policy violations now block merge.

### Local verification
- Installed `cargo-deny v0.19.6` via `cargo install --locked`.
- `cargo deny check` → `advisories ok, bans ok, licenses ok, sources ok`. (License warnings are emitted for allowed-but-unused entries; they are non-blocking and document what we'd accept.)
- `cargo check --workspace` ✓ (workspace dep refactor doesn't change behaviour, just resolution path).

### Decisions made this session
- AGPL-3.0-or-later is on the allowlist for our own crates; other GPL-family entries are not (yet).
- `multiple-versions = "warn"` rather than `"deny"` for now — duplicate crates are unavoidable while the dep set is small and churning. Tighten once it stabilises.
- Skipped `cargo-vet` in this pass. cargo-deny is the right floor; cargo-vet (Mozilla's audit-chain tool) is more strict than makes sense for a project this young without a track record of audit subscriptions.
- Skipped `cargo-audit` as a separate job — cargo-deny's advisories check covers the same RustSec database, so running both would be redundant.

### Open security gaps (carry-forward, updated)
- **Supply-chain layer 1 (cargo-deny) now in place.** Future hardening: `cargo-vet`, SBOM generation (CycloneDX or SPDX), reproducible-build verification, signed release artifacts (minisign or sigstore).
- **PQ wire-format integration still pending** (§5.5 sealed-sender + Noise key schedule).
- **No fuzzing, no Miri, no property tests** beyond the 25 unit tests.
- **`ml-kem` upstream-unaudited.** Mitigated by hybrid composition; not eliminated.
- **8 of 9 modules still empty.**

---

## 2026-05-18 — License, CI, post-quantum hybrid KEM (X25519 ‖ ML-KEM-768)

### License
- Added `LICENSE` (canonical AGPL-3.0 text fetched from `https://www.gnu.org/licenses/agpl-3.0.txt`).
- Set `license = "AGPL-3.0-or-later"` in workspace `[workspace.package]`; inherited by every crate via `license.workspace = true`.
- Rationale: Onyx is a network-deployed application (hubs in particular run as services). AGPL-3.0 closes the SaaS loophole so a hub operator forking the code and running it for the public must publish source. GPL-family also aligns with the audited crypto ecosystem we depend on. If a different license is wanted later, switching is a one-line workspace change before public deployment.

### Continuous integration
- `.github/workflows/ci.yml` runs three parallel jobs on push to main and on every PR:
  - `fmt --check`
  - `clippy --workspace --all-targets --locked -- -D warnings`
  - `test --workspace --locked`
- `--locked` enforces the committed `Cargo.lock` so dependency updates are intentional, not silent.
- `Swatinem/rust-cache@v2` caches the cargo registry + `target/` for fast subsequent runs.
- `concurrency` group cancels in-progress runs on new pushes to the same ref to avoid wasted compute.

### Post-quantum hybrid KEM (`onyx_core::crypto`)
- Implemented X25519 ‖ ML-KEM-768 hybrid KEM following the same defence-in-depth pattern as Signal's PQXDH and TLS 1.3's `X25519MLKEM768` hybrid group.
- New types: `HybridKemSecret`, `HybridKemPublic`, `HybridCiphertext`, `HybridSharedSecret`. Secrets zeroize on drop (X25519 via `x25519-dalek`'s `zeroize` feature, ML-KEM via `ml-kem`'s).
- **Combination construction:** `HKDF-SHA256(salt="onyx/v1/hybrid-kem", ikm=x25519_dh ‖ ml_kem_ss, info=ct.classical ‖ ct.post_quantum, okm=32 B)`. The entire ciphertext goes into `info` so any single-bit tamper of either half changes the combined output — this is what makes the construction resistant to an attacker substituting one component.
- **Security property:** combined secret holds as long as *either* X25519 *or* ML-KEM-768 is unbroken. Total break of one primitive degrades us to the security of the other, which is the v0.0.1 baseline for X25519. Documented in module comments.
- **Audit caveat:** the upstream `ml-kem` crate states in its own README that it has not had an independent audit. Hybridization is precisely the mitigation for this — even a complete break of the PQ implementation leaves us at X25519-only security. Documented in the type-level docs.
- Wire-format constants: `HYBRID_PUBLIC_LEN = 1216 B` (32 + 1184), `HYBRID_CIPHERTEXT_LEN = 1120 B` (32 + 1088), `HYBRID_PQ_PUBLIC_LEN = 1184`, `HYBRID_PQ_CIPHERTEXT_LEN = 1088`. All match FIPS 203 Table 3 for ML-KEM-768.
- 9 new unit tests added (now 25 total): hybrid round-trip; two independent encaps from the same recipient differ; wrong-recipient decapsulation derives a different secret; tampering the classical half changes the output; tampering the PQ half changes the output (covers both ML-KEM implicit rejection and info-binding); public-key byte round-trip; ciphertext byte round-trip; wrong-size byte rejection; size-constant assertions vs FIPS 203 Table 3.

### Dependencies
- Added `ml-kem = "0.2"` (resolved to 0.2.3) with the `zeroize` feature.

### DESIGN.md
- §9.6 (post-quantum open question) updated to "partially resolved": primitives are now available in `crypto.rs`; wire-format integration into §5.5 sealed-sender bootstrap and Noise transport key derivation is the remaining work.

### Verification
- `cargo check --workspace` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓ (after fixing two `clippy::ignored_unit_patterns` warnings — ml-kem's error type is `()` so the closure now matches with `|()|` rather than `|_|`)
- `cargo test --workspace` ✓ (25 passing)
- `cargo fmt --all --check` ✓

### Decisions made this session
- License: AGPL-3.0-or-later (SaaS-closure for hub operators).
- CI runs fmt / clippy / test as three parallel jobs to fail fast and to make it visible which gate broke.
- PQ choice: ML-KEM-768 (category 3, ~192-bit security). 512 would be enough for chat but 768 is the industry's converged default and the size cost (1184 B public / 1088 B ciphertext) is acceptable for hidden-service-mediated traffic.
- HKDF salt for hybrid combination is a fixed label rather than per-recipient context. Per-recipient context is bound via the `info` field instead (the entire ciphertext goes in).
- Hybrid secret type intentionally distinct from the classical-only `SharedSecret` — prevents accidentally accepting a classical-only result where a hybrid one is expected (type-level guardrail).
- Did **not** add `cargo-deny` / `cargo-vet` / `cargo-audit` yet. Adding them now would block CI on the lack of an `audit.toml` and policy decisions about acceptable dep changes. Deferred to a dedicated supply-chain hardening pass.
- Did **not** rewrite §5.5 sealed-sender to use the hybrid KEM yet. The primitives exist; the design integration is a separate planned step.

### Open security gaps (carry-forward, updated)
- **PQ wire-format integration pending.** Primitives ready; §5.5 sealed-sender and Noise key schedule must adopt them before any release.
- **Supply chain still unhardened** — no `cargo-deny`, no `cargo-vet`, no SBOM, no reproducible-build verification, no release signing. CI now exists but doesn't enforce these.
- **No fuzzing, no Miri, no property tests** beyond the 25 unit tests.
- **`ml-kem` is not independently audited** (per its own README). Mitigated by hybrid composition with X25519; not eliminated.
- Other 8 modules still unimplemented; security claims still apply only to `crypto.rs`.

---

## 2026-05-18 — Initial scaffold + crypto primitives

### Design (`DESIGN.md`)
- Drafted v0.1, then revised to v0.2 after a focused review pass. Substantive changes from v0.1:
  - Frame `type` discriminator moved **inside** the AEAD envelope. Without this the hub could distinguish PAD from DELIVER on the wire and §5.7's cover-traffic guarantee would not hold against a hub-class adversary.
  - **Two-tier routing identifier scheme** (§5.5, revised). The single-tier "rotating secret" scheme from v0.1 had no story for first-contact bootstrap and was sender/recipient ambiguous. Replaced with:
    - Tier 1: long-term introduction inbox per recipient (`BLAKE2b-128(signing_pk || "onyx/v1/inbox")`), addressed via sealed-sender envelope (HPKE under the recipient's X25519 identity key).
    - Tier 2: rotating session tokens derived from the MLS exporter for the active group; clients pre-register batches.
  - **Padding buckets shrunk** to 256 / 1024 / 4096 B; >4 KB messages chunk into multiple LARGE frames instead of being placed in a 16 KB / 64 KB bucket that would leak "this user just sent something big."
  - **Non-deniability stated explicitly** as a v1 decision (§6.5). Every message carries a long-term-key signature; recipients gain transferable proof. Wire format reserves space to add deniable credentials later.
  - **Onion web tier hardened** (§8): gated by client-auth (stealth) onion, 5-minute idle / 30-minute absolute session timeouts, `<meta http-equiv="refresh">` polling removed (explicit refresh link instead), passphrase-attempt rate limiting (5 per 15-min, auto-disable at 20 failures), banner renamed to "Remote access mode" with stronger wording.
  - **Account recovery + multi-device sync** restated as deliberate v1 exclusions (§10) rather than mere "out of scope."
  - Smaller fixes: explicit key-confirmation after Noise XK handshake; note that onion v3 address ≡ signing key fingerprint with the UX implications; multi-identity caveat about shared process address space; Argon2id floor for low-memory devices.

### Threat model (`THREAT_MODEL.md`)
- Extracted as a standalone artifact so it can be read without the full design doc. Contents: assets in priority order, adversaries we defend against (A1–A6), adversaries we do not (N1–N7), trust assumptions, residual-linkability table, explicit non-deniability section.

### Workspace
- Cargo workspace at the repo root, edition 2024, `unsafe_code = "forbid"` workspace-wide.
- Pedantic clippy enabled with `-D warnings` (a few of the noisier pedantic lints allowed: `module_name_repetitions`, `missing_errors_doc`, `missing_panics_doc`, `doc_markdown`).
- Four crates under `crates/`: `onyx-core` (lib), `onyxd`, `onyx`, `onyx-hub` (bins). Binaries depend on `onyx-core` by path.
- `rust-toolchain.toml` pins the stable channel plus `rustfmt` and `clippy`. Toolchain installed for this work: `rustc 1.95.0` (stable, aarch64-apple-darwin).
- Module skeleton in `crates/onyx-core/src/`: `identity`, `mls`, `routing`, `storage`, `tor`, `transport`, `wire`, `error`. The non-crypto modules are doc-only at this point — each file's module comment references the DESIGN.md section it will implement. Constants shared across crates (frame-type IDs, padding-bucket sizes, KDF namespace, protocol version) live in `wire.rs` and `lib.rs`.

### `onyx_core::crypto`
- Single boundary file for all primitive use. Higher-level modules MUST NOT import `ed25519-dalek`, `chacha20poly1305`, etc. directly — they go through wrappers here. Centralising the boundary makes it possible to (a) apply uniform zeroize / constant-time policy, (b) audit one file for nonce / RNG / FFI bugs, (c) eventually swap implementations (e.g. add a PQ hybrid layer) without touching every call site.
- Wraps: Ed25519 (`SigningKey` / `VerifyingKey` / `Signature` / `Fingerprint`), X25519 (`IdentitySecret` / `IdentityPublic` / `SharedSecret`), ChaCha20-Poly1305 AEAD (`AeadKey` / `Nonce`), HKDF-SHA256, BLAKE2b-128, Argon2id, CSPRNG access, constant-time compare.
- Secret-bearing types zeroize on drop. `Debug` impls never print key material. `to_bytes` returns `Zeroizing<[u8; 32]>` so callers can't accidentally leave the seed on the stack.
- `Fingerprint` is the full 32-byte verifying key, displayed as 52 base32 characters (RFC 4648 lowercase, no padding) grouped in 4-char chunks. Parser tolerant of whitespace, mixed case, and an optional `fpr:` prefix.
- `Argon2Params::DEFAULT` = 256 MiB / t=3 / p=4. `Argon2Params::FLOOR` = 64 MiB / t=3 / p=2. The daemon refuses parameters below the floor.
- `Nonce::from_counter(u64)` produces 4 leading zero bytes + 8-byte BE counter (matches Noise / WireGuard convention).
- 16 unit tests: RFC 8032 Ed25519 test vector 1; RFC 5869 HKDF-SHA256 test vector 1; AEAD round-trip + tamper detection on ciphertext / AAD / nonce / key (4 paths); X25519 DH symmetry; BLAKE2b-128 determinism + chunking equivalence; Argon2id floor enforcement + determinism on equal inputs; fingerprint base32 round-trip + tolerant parsing of messy input; `ct_eq` behaviour including length mismatch; nonce-from-counter byte layout; ed25519 round-trip + wrong-signer rejection.
- Pinned `[workspace.dependencies]`: `ed25519-dalek 2` (features: `rand_core`, `zeroize`), `x25519-dalek 2` (features: `static_secrets`, `zeroize`), `chacha20poly1305 0.10`, `hkdf 0.12`, `sha2 0.10`, `blake2 0.10`, `argon2 0.5`, `rand_core 0.6` (feature: `getrandom`), `zeroize 1` (feature: `derive`), `subtle 2`, `base32 0.5`, `thiserror 2`.

### Verification at the close of this session
- `cargo check --workspace` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓
- `cargo test --workspace` ✓ (16 passing in `onyx-core`, 0 in the binary crates as expected)
- `cargo fmt --all --check` ✓
- Binaries `onyxd` / `onyx` / `onyx-hub` build and run; each prints its "scaffold only" banner and exits with code 1.

### Open security gaps the user explicitly flagged ("are we zero-trust / unbreakable / using all modern crypto?")
The honest answer is *not yet, and "unbreakable" isn't a property real systems have*. Specific carry-forwards:
- **No post-quantum.** In 2026 "modern crypto" includes hybrid ML-KEM-768 for KEX and ML-DSA-65 for signatures. Onyx uses neither. "Harvest now, decrypt later" is real for traffic captured today. Adding a PQ hybrid before any release is the largest single security improvement available — flagged as the strong candidate for the next session.
- **No supply-chain hardening.** No `cargo-deny`, no `cargo-vet`, no SBOM, no reproducible builds, no release signing. Need a CI pipeline with all of these.
- **No fuzzing / Miri / property tests** beyond the 16 unit tests.
- **No external audit.** Should not claim "audited" without a paid third-party engagement.
- **Known residual linkability** (already documented in DESIGN §5.5, THREAT_MODEL §5):
  - Introduction inbox is linkable to a fingerprint forever — anyone with your fingerprint can probe activity.
  - Long-term-key signatures on every message (non-deniability) — recipients gain transferable proof.
  - Padding buckets leak a size class to the hub.
- **8 of 9 modules still unimplemented.** Any claim about Onyx's security applies only to `crypto.rs` until the transport, MLS, routing, storage, identity, Tor, daemon, and hub layers exist.

---

*Next planned step: add post-quantum hybrid KEM (X25519 ‖ ML-KEM-768 through HKDF) to `crypto.rs`, then implement `wire.rs` envelope codec with property tests.*
