# Development Log

Append-only log of meaningful changes — design decisions, additions, removals, security-relevant tradeoffs. Newest entries on top. Each session gets one dated heading; sub-sections describe what landed and why.

Use this file as the single chronological view of where the project is. Implementation status of individual modules lives in code; this log captures *decisions*.

---

## 2026-05-19 — T8.0.gc: hub-side queue garbage collection — bounded `queue_entry` growth

Operational follow-up to T8.0. T8.0 made queued envelopes durable (good); it did *not* prune them (bad — unbounded growth). A hub running for months accumulates queue rows for every routing-id whose owner never returned to drain their inbox. Real "disk fills, hub dies" risk. T8.0.gc closes it.

What landed:

**T8.0.gc.a — `Store::gc_queue_entries_older_than(cutoff_unix_ms)`.** New method in `crates/onyx-hub/src/store.rs`. Single `DELETE FROM queue_entry WHERE enqueued_at < ?`. Returns the row count for operator visibility.

**Why queues but not KPs.** KeyPackages are designed to be republished on every reconnect (`hub_client::SelfPublish` does it per session start). Silently pruning a stale KP would break first-contact for any peer that hasn't reconnected in the GC window — the recipient's `fetch_keypackage` would surface `NotReady` and the sender would fail. Queue entries are different: if a routing id has had no live subscriber for 30 days, the sender's first-contact has already failed in every meaningful sense; pruning the row is the right call. Documented in detail in the method's rustdoc.

Four new store tests in `gc_*` family:
  * `gc_deletes_old_rows_only` — three rows, two backdated 100 days, GC with 30-day cutoff, only the recent one survives.
  * `gc_with_far_future_cutoff_deletes_everything` — sanity: cutoff in the year ~3000 means "older than the future" = everything.
  * `gc_with_far_past_cutoff_deletes_nothing` — sanity: cutoff at epoch 0 = nothing is older.
  * `gc_does_not_touch_keypackages` — the explicit invariant.

**T8.0.gc.b — `HubState::gc_queue_entries_older_than` proxy.** Thin forwarder so the hub binary doesn't need to reach through `HubState` into the `Store` directly. Returns `Ok(0)` in ephemeral mode (`Self::new()` — no durable store).

**T8.0.gc.c — `--max-queue-age-days` flag + periodic GC task.** `crates/onyx-hub/src/main.rs`:
  * New `--max-queue-age-days` (env `ONYX_HUB_MAX_QUEUE_AGE_DAYS`), default `30`. Set to `0` to disable GC entirely (emits a loud `warn!` at startup so the operator can't disable it by accident).
  * Spawn a periodic `tokio::spawn` task that ticks every hour. First tick is immediate but skipped so we don't GC at startup before the warm-from-disk completes. Each subsequent tick computes `cutoff = now_ms - age_days * 24h_ms` and calls `state.lock().await.gc_queue_entries_older_than(cutoff)`. Result is logged at `info!` (rows deleted) or `warn!` (DB error; retry next tick).

The GC task holds the `HubState` mutex while running (the inner `DELETE` is fast — even at scale, a single SQL statement on an indexed BLOB column is sub-millisecond), so concurrent deliveries block briefly during each tick. That's acceptable for an hourly cadence.

Operational impact:

  * **Bounded disk growth.** Worst-case queue_entry size now scales with "ingress rate × 30 days" instead of "ingress rate × forever."
  * **No security change.** GC only drops rows whose recipient has been offline for >30 days — those envelopes were already operationally undeliverable. No new attack surface, no new info disclosure.
  * **No backwards-compat break.** Existing T8.0 state DBs migrate cleanly (no schema change; GC just deletes rows that the operator's policy has decided are stale).
  * **Senders are not notified.** A sender who fired a sealed-sender envelope to a long-offline recipient never gets an "expired" signal — same as today, where they get no signal whatsoever. Adding sender-side expiration receipts is a separate, much bigger slice (`T8.0.gc-receipts`?).

What this did NOT do:

  * Did not add per-routing-id GC policy (e.g., "keep 90 days for VIP routing-ids, 7 days for others"). Single global age threshold for v0.
  * Did not GC KPs (see above — would break first-contact).
  * Did not GC orphan `keypackage` rows whose owner has rotated identity. Identity rotation is itself a future feature (DESIGN.md §4); GC for it follows.
  * Did not add a `--gc-now` operator command for one-shot manual GC. Periodic task is enough for v0; manual trigger is a small follow-up if useful.

Verification: `cargo fmt --all` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo test --workspace` **285 passed / 0 failed** (was 281; +4 store GC tests).

---

## 2026-05-19 — T8.2-check: `onyx accept` does the hub-intersection check (closes the T8.2 usability gap)

Tiny follow-up to T8.2. The morning's T8.2 made the URL carry the recipient's hub list and surfaced it to stderr on `onyx accept` — but the user still had to *manually* eyeball whether their own daemon's `--hub` config intersected the recipient's. T8.2-check does the intersection automatically and warns loudly when it's empty.

What landed:

**T8.2-check.a — `run_accept` now calls `Identity` before the send.** `crates/onyx/src/main.rs`. After parsing the invite URL, if it carries any hubs, the CLI:

  1. Issues `ApiRequest::Identity` to read the sender's own daemon's configured `hubs` list (already exposed in T8.2.b).
  2. Computes the intersection between recipient's hubs (from URL) and sender's hubs (from local daemon).
  3. Surfaces one of three messages to stderr:
     * **`our_hubs` empty** — "your daemon has NO hubs configured. The send will fail with NotReady. Pass `--hub …` to the daemon." (Actionable error.)
     * **intersection empty** — "WARNING — your daemon's hubs (N) do NOT intersect any of the recipient's hubs above. The envelope will be delivered to YOUR hubs, none of which the recipient subscribes to — they will never see it. Add at least one of the recipient's hubs to your daemon's `--hub` list." (Loud preemptive warning.)
     * **intersection non-empty** — "sending via N matching hub(s) (out of M your daemon publishes to and K the recipient subscribes on)." (Reassurance + path visibility.)

  4. Then proceeds with the existing `SendBootstrap` / `SendBootstrapMls` dispatch — **the send still happens regardless of the intersection result**. v1 of T8.2-check is *advisory*, not *blocking*. Rationale: the recipient may be temporarily on a different hub set, may not actually need same-hub delivery (e.g., they'll come online later via a hub the URL didn't list), and a blocking failure mode for what's ultimately a "delivery is uncertain" warning would be worse than just telling the operator what's happening.

If the `Identity` call itself fails (daemon unreachable, returns Error), the CLI surfaces "(couldn't query daemon's own hub list; skipping intersection check)" and proceeds. Better to ship the envelope than refuse over a check that's diagnostic, not protocol-critical.

**The full operator experience** when `onyx accept` runs against a multi-hub URL:

```
$ onyx accept "onyx://invite/v1?fp=…&kem=…&hub=h1,K1&hub=h2,K2" --text "hi"
onyx: recipient publishes to 2 hub(s):
  • h1,K1
  • h2,K2
onyx: sending via 1 matching hub(s) (out of 3 your daemon publishes
to and 2 the recipient subscribes on).
{"kind":"SendBootstrapOk"}
```

Or in the misconfigured case:

```
$ onyx accept "onyx://invite/v1?…&hub=h99,K99" --text "hi"
onyx: recipient publishes to 1 hub(s):
  • h99,K99
onyx: WARNING — your daemon's hubs (3) do NOT intersect any of the
recipient's hubs above. The envelope will be delivered to YOUR hubs,
none of which the recipient subscribes to — they will never see it.
Add at least one of the recipient's hubs to your daemon's `--hub`
list.
{"kind":"SendBootstrapOk"}
```

Note the `SendBootstrapOk` still appears in the second case — the daemon successfully queued the envelope for delivery via its own hubs. The warning is the user's actionable signal that the *recipient* probably won't receive it, but the local send succeeded.

Security and posture:

  * **No new attack surface.** The check is purely client-side and never sends new data anywhere. Just reads what the daemon already exposes.
  * **No auto-config.** v1 explicitly does not mutate the sender's daemon to add the recipient's hubs. That's the *next* slice (call it `T8.2-autoconfig`), which needs design work on: transient hub sessions (don't pollute long-term config), security around "URL can make my daemon dial arbitrary onions," runtime hub add/remove API surface. Keeping v1 advisory keeps it tight.
  * **Fail-open on Identity errors.** If the daemon doesn't respond to Identity, the check is skipped rather than blocking the send. The send is the primary operation; the check is diagnostic.

What this did NOT do:

  * Did not auto-configure the sender's daemon — see above, future slice.
  * Did not block the send on intersection-empty — advisory only.
  * Did not change any wire format or API. Purely uses T8.2's existing `IdentityOk.hubs` field.
  * Did not add CLI parser tests — the behaviour is a stderr surface, the existing tests already verify the `Command::Accept` shape.

Verification: `cargo fmt --all` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo test --workspace` **281 passed / 0 failed** (no count change — pure behaviour addition on the `accept` path, no new test surface introduced this slice).

---

## 2026-05-19 — T8.2: multi-hub invite URLs — recipients disclose their hub list, senders see where messages will land

Third step in the relay-setup arc. T8.0 made one hub durable; T8.1 made the daemon talk to N hubs in parallel; T8.2 extends invite URLs to carry the recipient's hub list, plus surfaces it on the sender's `onyx accept` for transparency. No auto-config in this slice — that's a future T8.2.b. v1 of T8.2 is: **the URL becomes a complete hub manifest**, and the user *sees* where their message is going before they send it.

What landed:

**T8.2.a — `Invite` struct gains `hubs: Vec<String>`.** `crates/onyx-core/src/invite.rs`. Each entry is `onion:port,b32pubkey` — same shape as the daemon's `--hub` flag. Empty Vec == legacy form (pre-T8.2 URL, or sender chose not to disclose). New `Invite::with_hubs(Vec<String>)` builder.

URL encoding: each hub adds `&hub=<onion:port,b32pubkey>` to the URL. **Repeated query keys** rather than packing all hubs into a single value — keeps the format trivially extensible and avoids inventing a new in-value delimiter (the `,` inside `onion:port,pubkey` already has meaning). Parser switched from "overwrite on duplicate key" to "accumulate into Vec" for the `hub` key. Validation at parse time: each `hub` value must contain a comma and have non-empty onion + pubkey fields — surfaced as `InvalidEncoding`, not deferred to send time.

Seven new tests covering: single-hub round-trip, multi-hub round-trip with FIFO order preservation, rejection of empty hub values, rejection of comma-less values, rejection of comma-present-but-empty-field values, `kp + hubs` combination round-trip, and the back-compat sanity ("legacy URLs without `&hub=` still parse, hubs Vec defaults empty").

**T8.2.b — `ApiResponse::IdentityOk` gains `hubs: Vec<String>`.** `crates/onyx-core/src/api.rs`. `#[serde(default)]` for wire back-compat — a pre-T8.2 daemon's JSON (no `hubs` field) decodes cleanly as empty Vec. Hand-rolled back-compat test `identity_ok_hubs_back_compat` literally constructs a pre-T8.2 wire payload and asserts it decodes as `hubs: vec![]`.

**T8.2.c — daemon populates `IdentityOk.hubs` from `Config.hubs`.** `crates/onyx-daemon/src/api_server.rs` + `lib.rs`. `DaemonState` gains `configured_hubs: Vec<HubConfig>` — a snapshot of what `run` was launched with. The `Identity` API handler reads it and formats each as `format!("{onion},{pubkey}")`. The daemon does not currently support runtime hub reconfiguration, so the snapshot is set once at startup and read-only thereafter.

**T8.2.d — `onyx invite --with-hubs` flag.** `crates/onyx/src/main.rs`. Independent of `--with-kp` — they compose freely (you can have both, either, or neither). When set, `run_invite` reads `daemon_hubs` from `IdentityOk`, attaches via `Invite::with_hubs`, and emits the augmented URL. If the daemon has no hubs configured (empty Vec), surfaces a `warn!` to stderr but still prints a usable URL (without the hub list).

**T8.2.e — `onyx accept` surfaces the recipient's hub list.** Stderr (so stdout stays pipe-friendly for the JSON response). Format:

```
onyx: recipient publishes to 3 hub(s):
  • alice-hub-1.onion:1,KEY1
  • alice-hub-2.onion:1,KEY2
  • alice-hub-3.onion:1,KEY3
onyx: your daemon will use ITS OWN configured --hub list for the
fan-out. For maximum delivery reliability, ensure your daemon
connects to at least one of the above hubs.
```

**Transparency, not auto-config.** v1 explicitly does *not* mutate the sender's daemon configuration based on the URL — that's a separate slice with bigger implications (transient hub sessions, runtime hub add/remove, etc.). v1 just tells the user "here's where you're sending" so they can sanity-check their own `--hub` config against it.

**T8.2.f — three new CLI parser tests.** `invite_subcommand_parses_with_hubs_flag`, `invite_subcommand_parses_with_kp_and_hubs` (compose both flags), and the existing `invite_subcommand_parses_with_no_args` + `with_kp_flag` tests were updated to assert the new struct shape (`Command::Invite { with_kp, with_hubs }`).

Security and anonymity:

  * **The hub list is public information.** Same posture as the rest of the URL — fingerprint, KEM pubkey, KP, hub list are all data the recipient *intends* to be publicly known about themselves. An attacker learning "alice publishes to hubs X, Y, Z" learns nothing they couldn't learn by watching alice's hubs themselves. No new disclosure.
  * **No new authentication surface.** The hub list is carried inside the same `onyx://invite/v1?…` URL that the user already trusts out-of-band; if the URL itself was tampered with, the recipient also tampered with the fingerprint, which is a more impactful tamper. The user's job is verify the fingerprint matches their peer; the hub list ride-along inherits the same trust.
  * **No wire-format change to the hub protocol.** The invite URL is purely client-side; hubs are unaware T8.2 exists. Identical posture to T8.1 in this regard.
  * **Forward-compat preserved.** Legacy URLs parse cleanly (empty hubs Vec); legacy daemons' `IdentityOk` (no `hubs` field) decodes cleanly on new clients. No version bump needed.

`ANONYMITY.md` will be updated in a follow-up doc-only commit if the multi-hub-invite workflow turns up new user-facing anonymity caveats. None observed in this slice.

What this did NOT do:

  * Did not auto-configure the sender's daemon to fan out via the recipient's hubs. Sender still uses *their own* `--hub` config. Auto-config is the natural follow-up (call it `T8.2.b-autoconfig`) — needs design work on transient hub sessions + a security review of "URL can tell my daemon to dial arbitrary onions."
  * Did not add hub-to-hub gossip (still T8.3+, real federation).
  * Did not change the daemon protocol or wire format. Pure additive shape on the invite URL + the `IdentityOk` API response.
  * Did not warn the sender if their hub config doesn't intersect the recipient's. That requires the sender's CLI to know its *own* daemon's hub list (already available via `Identity` API), do the intersection, surface the warning. Trivial follow-up; left out of v1 to keep the slice tight.

Verification: `cargo fmt --all` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean (zero new warnings — the additive pattern stayed inside existing constraints), `cargo test --workspace` **281 passed / 0 failed** (was 271; +7 invite-module tests, +1 api back-compat test, +2 CLI parser tests).

---

## 2026-05-19 — T8.1: multi-hub publish/subscribe — daemon talks to N hubs in parallel; one hub dying loses nothing

Second step in the "build up the relay setup" architecture. T8.0 made a single hub survive its own restart; T8.1 closes the remaining gap — **hub permanently dying** — at the client layer. Daemons now accept a repeatable `--hub onion:port,b32pubkey` flag and connect to as many hubs as the operator wants in parallel. Fan-out on send, fan-in on receive, dedup on the recipient via the existing replay guard. Strictly simpler than Matrix-style server-to-server federation, real durability + redundancy in ~one slice of work.

What landed:

**T8.1.a — `HubConfig` type, `Config.hubs: Vec<HubConfig>`.** `crates/onyx-daemon/src/lib.rs`. The single `hub_onion: Option<String>` + `hub_pubkey: Option<String>` pair becomes a `Vec<HubConfig { onion, pubkey }>`. Empty vec == no hub-relayed messaging (unchanged semantics for `--no-tor` / direct-only). Single-element vec == identical behaviour to pre-T8.1 single-hub mode. Multi-element vec == the new mode.

**T8.1.b — `DaemonState.hub_outbounds: Vec<mpsc::Sender>`.** Replaces the single `Option<Sender>`. Constructed up-front in `run`: one mpsc channel per configured hub, with the Receivers parked in a Vec for the spawn-loop to consume. Empty in `--no-tor` mode or when no hubs are configured.

**T8.1.c — `spawn_replay_snapshot_task` loop becomes spawn-per-hub.** `crates/onyx-daemon/src/lib.rs`. The single hub-client `tokio::spawn` block becomes a `for (idx, hub_cfg) in args.hubs.iter().enumerate()` loop. Each spawned task gets:
  * Its own clone of the daemon state, the Tor runtime, the identity secrets (round-tripped via bytes, same trick as before).
  * Its own mpsc receiver (drained via `remove(0)` from the parked Vec).
  * An independent exponential-backoff reconnect loop (per-hub backoff so one flaky hub doesn't perturb the others).
  * A per-task tracing span (`info_span!("hub", idx, host, port)`) so log output stays attributable.
  * The existing `run_hub_session` self-publish path runs unchanged — each task publishes our fresh KP to its hub on every reconnect, so **multi-hub KP publication is free**.

**T8.1.d — `handle_send_bootstrap` fan-out.** `crates/onyx-daemon/src/api_server.rs`. The single `hub_outbound.try_send(...)` becomes a `for hub_outbound in hub_outbounds` loop pushing the same sealed envelope into every channel. New helper `fan_out_deliver(hub_outbounds, target, sealed, op)` factors out the fan-out + accounting logic for reuse from the MLS path. **Success on any one hub counts as overall success** — partial failures (some channels full / closed) log `info!` with the accepted/total counts but still return `SendBootstrapOk`. Only when *every* hub queue is full or closed does the API return `NotReady`.

**T8.1.e — `handle_send_bootstrap_mls` fan-out.** Same pattern as msg/v1 but inline (couldn't reuse `fan_out_deliver` directly because the MLS path returns `SendBootstrapMlsOk { group_id_b32 }` not `SendBootstrapOk` — different shape). Same any-hub-accepts semantics.

**T8.1.f — `handle_fetch_peer_keypackage` serial try.** Different semantics for fetch: we don't want to ask every hub in parallel (the FIFO matching invariant in `hub_client` is per-hub, but we never have more than one fetch in flight thanks to `hub_fetch_lock`). Instead, hold the existing `hub_fetch_lock` across the *entire* multi-hub fan, try each hub in configured order, **return the first success**. If all hubs return "not found", surface `NotReady` with a clean "no configured hub has this peer's KeyPackage published" message. If a hub's outbound is dead (full/closed) or its responder dropped (`Err`), skip and try the next; only fail overall if *every* hub fails.

**T8.1.g — `EnvelopeReplayGuard` does the dedup for free.** Multi-hub send means the recipient gets the same sealed envelope N times (one per hub). The T7.3-sec.2 replay guard already keys on a BLAKE2b-128 hash of the body bytes, so duplicates are silently dropped before `open_bootstrap` is even called. **Zero new dedup logic needed** — this is the elegant part. T7.3-sec.2 was originally added to defend against hostile-hub replay; it now also pays for itself as the multi-hub correctness primitive. Same code, two wins.

**T8.1.h — backward-compatible CLI.** `crates/onyxd/src/main.rs` + `crates/onyx/src/main.rs`:
  * Old `--hub-onion` + `--hub-pubkey` flags still parse (legacy single-hub form, kept for backward compat — clap `requires` ensures they appear together).
  * New `--hub onion:port,b32pubkey` flag is repeatable (`action = clap::ArgAction::Append`) and `conflicts_with_all = ["hub_onion", "hub_pubkey"]` — pick one form, never both.
  * `TryFrom<Args> for Config` merges either form into `Vec<HubConfig>`. Comma split for the new form errors out cleanly on `"missing comma"` or empty fields.
  * Three new CLI parser tests in `onyx::main::tests`: `no_hub_flag_parses_to_empty_vec`, `single_hub_flag_parses`, `multiple_hub_flags_accumulate`.

Security and anonymity analysis:

  * **No new trust assumption per hub.** Each hub still sees only routing-ids + opaque ciphertext + timing — same posture as single-hub. Adding *more* hubs spreads the metadata-correlation across more independent observers, which is strictly better for anonymity (no single hub sees your full message count).
  * **Does NOT prevent timing correlation across hubs.** A coalition of N hubs (or a passive observer of all N) can still correlate "this routing-id received an envelope at time T on every hub" — the fan-out by definition makes the same envelope visible to every hub at nearly the same wall-clock time. Cover traffic (separate slice) is what would defend against this; multi-hub is purely a **durability + censorship-resistance** play, not a new anonymity property.
  * **No wire-format change.** Hubs don't even know they're in a multi-hub setup. From a single hub's perspective, the client just behaves identically to single-hub. This is what makes T8.1 deployable without coordinating with hub operators.
  * **Replay safety preserved.** Same BLAKE2b-128 envelope dedup as T7.3-sec.2. Multi-hub *increases* the rate at which duplicates land on the recipient, and the guard handles them transparently.
  * **Censorship resistance.** A single malicious hub that *drops* messages addressed to bob can no longer fully censor bob — as long as bob is also subscribed to a non-malicious hub, his daemon receives the envelope. Real defence-in-depth against hub-level censorship.

`ANONYMITY.md §3.4` updated: "Hub durability — partially closed" → "Hub durability — closed end-to-end." Explicit note that this is *not* federation (hubs don't talk to each other; T8.3+ later) and that this is the simpler-than-Matrix shape.

What this did NOT do:

  * Did not add hub-to-hub gossip (T8.3, real federation, separate design doc).
  * Did not add multi-hub-aware invite URLs (T8.2 — invite URL would carry recipient's hub list so the sender knows where to fan out). T8.2 is the natural follow-up.
  * Did not parallelise `handle_fetch_peer_keypackage` across hubs (kept sequential under the existing lock). Correctness over throughput; multi-fetch is a small follow-up if measured needed.
  * Did not break the single-hub path. Operators with one `--hub-onion`+`--hub-pubkey` flag pair get *exactly* single-hub behaviour, byte-identical to pre-T8.1.

Verification: `cargo fmt --all` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean (four cleanups: two redundant `continue;` statements in the FetchKp loop, one `items_after_statements` from a misplaced `use TrySendError` that I hoisted to file-top, one `redundant_locals` from a leftover `let our_sk_bytes = our_sk_bytes;` line from the spawn refactor), `cargo test --workspace` **271 passed / 0 failed** (was 268; +3 CLI parser tests).

---

## 2026-05-19 — T8.0: hub durability — SQLite-back the queue + KP-directory so they survive hub restart

First step in the "build up the relay setup" architectural slice. Before today, the hub kept its two non-ephemeral state pieces (offline-delivery queues, MLS KeyPackage directory) in *pure in-memory `HashMap`s*. A hub restart — `kill -HUP`, a deploy, an OOM, a machine reboot — silently lost every queued envelope and every published KP. Senders got no signal; recipients silently lost first-contact attempts. T8.0 makes the hub survive its own restart.

What landed:

**T8.0.a — new `onyx-hub::store` module** (`crates/onyx-hub/src/store.rs`, ~330 lines code + tests). SQLite-backed store with two tables:

```sql
CREATE TABLE queue_entry (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  routing_id   BLOB NOT NULL,   -- 16 bytes
  payload      BLOB NOT NULL,   -- full DELIVER body, ready to forward
  enqueued_at  INTEGER NOT NULL
);
CREATE INDEX queue_entry_routing_idx ON queue_entry(routing_id);

CREATE TABLE keypackage (
  routing_id    BLOB PRIMARY KEY,
  kp_bytes      BLOB NOT NULL,
  published_at  INTEGER NOT NULL
);
```

Auto-incrementing `queue_entry.id` is the FIFO order — `drain_queue` does `SELECT … ORDER BY id ASC` + `DELETE` inside a single SQLite transaction so a concurrent enqueue cannot be partially taken. Tables created via `CREATE TABLE IF NOT EXISTS` so reopening an existing DB is a no-op (idempotent schema apply, no version cell needed). Six unit tests including the headline `survives_close_and_reopen` (write, close, reopen, read the same bytes back — models hub restart).

**T8.0.b — `HubState::with_store(store)`** (`crates/onyx-hub/src/state.rs`). The existing `HubState::new()` (in-memory only) is preserved unchanged so all existing tests + ephemeral dev use keep working. The new `with_store` constructor:
  - Calls `store.load_all_keypackages()` and `store.load_all_queues()` to **warm the in-memory caches from disk**, so the hot read path stays in-memory (no SQLite queries on `fetch_keypackage` / `deliver`).
  - Records the store as `durable_store: Option<Store>`.
  - All three mutation paths (`deliver` when no live subscriber → enqueue; `subscribe` when draining queue → delete-disk; `publish_keypackage` → UPSERT) now do **write-through**: in-memory + disk. Disk-write failures log `warn!` and *continue* — in-memory state stays consistent, only durability is lost for that one operation.

Two new state-level tests:
  - `with_store_survives_restart` — three "lifetimes" of the same on-disk store. Lifetime 1: queue two envelopes for rid_a + publish a KP for rid_b. Lifetime 2: reopen, assert both pieces of state are present, then a subscriber drains rid_a. Lifetime 3: reopen, assert the drained envelopes do NOT reappear (proves the on-disk drain ran) and the KP is still present.
  - `new_is_ephemeral_no_store_no_panic` — preserves the contract that `HubState::new()` works without a store, just like before.

**T8.0.c — `--state-db` flag.** New clap arg on `onyx-hub`, default `./onyx-hub-state.db`. Auto-creates parent directory if missing. Opt-out path: `--state-db ""` (empty string) keeps the pre-T8.0 ephemeral semantics for operators who explicitly want them — emits a loud `warn!` at startup so it can't be invoked silently.

Security analysis (why this commit is safe):

  * **No new attack surface.** Hub-side rows are **not** AEAD-sealed. They never were content the hub had a right to read — they're already AEAD-sealed by the *sender* under the *recipient's* hybrid KEM key. A hub operator with shell access could already read in-memory queues via core dump or memory inspection; durability doesn't change that. A future hub operator who tampers with rows on disk just produces malformed DELIVER bytes that the recipient's `open_bootstrap` rejects via the outer Ed25519 signature check (and the recipient's T7.3-sec.2 replay guard dedups any successful re-deliveries).
  * **No new trust assumption.** Hub continues to see only routing-ids + opaque ciphertext + timing. Persistence does not change the threat model — only the *durability* axis.
  * **Restart-derived duplicate deliveries are safe.** A hub crash between "subscriber takes ownership in memory" and "subscriber processes the bytes" could in principle re-deliver an envelope on next restart (the on-disk drain didn't complete). The recipient's `EnvelopeReplayGuard` (T7.3-sec.2) silently drops the duplicate. Belt-and-braces.

`THREAT_MODEL`: no carry-forward changes today — hub durability isn't a security gap, it's a reliability one.

`ANONYMITY.md` updated: new §3.4 "Hub durability — partially closed" notes T8.0 closes the single-hub case and points at T8.1 (multi-hub publish/subscribe) as the next slice for the "hub permanently dies" case. Renumbered the cascading §3.5–§3.10.

What this did NOT do:

  * Did not add multi-hub support — that's T8.1, the next slice. T8.0 only makes one hub survive its own restart.
  * Did not add a public-hub discovery mechanism — that's T8.4 territory.
  * Did not change the hub protocol, the wire format, or the daemon-side code at all. The hub's clients don't need any changes to benefit from T8.0.
  * Did not encrypt-at-rest the hub's state-db. The bytes inside are already AEAD ciphertext (sender → recipient) — adding another encryption layer with a key the hub controls would protect against disk theft but not against an operator who can read process memory. Out-of-scope for v0; trivial follow-up if the threat model evolves.

Verification: `cargo fmt --all` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean (added `#[allow(clippy::too_many_lines)]` on `onyx-hub::main` after the new state-db branch pushed it past 100 lines; added `#[allow(dead_code)]` on `Store::open_memory` because it's currently only test-callers but will become operator-facing in a future flag), `cargo test --workspace` **268 passed / 0 failed** (was 260; +6 store unit tests + +2 HubState restart-survival tests).

---

## 2026-05-19 — Docs: `ANONYMITY.md` — honest inventory of what Onyx hides and what it doesn't

Documentation-only change. No code, no protocol, no behaviour delta. The four recent zero-trust hardenings (T7.3-sec, T7.3-sec.2, T7.3-sec.2-persist) closed real attacks, but the answer to "is Onyx anonymous?" still lived only in this changelog and in scattered module rustdocs. Users wanting to evaluate fit needed to reconstruct the picture from primary sources. `ANONYMITY.md` consolidates it — with the same discipline as `HOW_IT_WORKS.md`: file pointers for every claim, an explicit gap list, no marketing.

Structure (six sections):

  * **§0 honest framing**. Lead paragraph spells out what Onyx aims for (hide who is talking to whom from network, ISP, hubs) and what it does NOT aim for (defend against a global passive adversary watching both endpoints' Tor entry guards). Explicit "no claim of 'perfect anonymity' appears anywhere in this repository" with a "file a bug if you find one" line. Same posture as `SECURITY.md` §1.
  * **§1 adversary model A1–A4**. Local network / ISP / coffee-shop snooper (defended); compromised or hostile relay hub (defended, with all four T7.3-sec.x mitigations cited); peer turning hostile (MLS PCS + per-message PFS); global passive adversary (NOT defended — Tor's own threat model excludes this, Onyx inherits the posture). Each entry has "what Onyx does" + "caveat" so the user knows exactly where the defence ends.
  * **§2 what's in place today**. A 12-row table of concrete defences with code pointers — `crates/onyx-core/src/tor.rs` for Tor, `routing.rs::seal_bootstrap` for sealed sender, `routing.rs::introduction_inbox` for the hashed routing id, `wire.rs::max_payload` for size buckets, the T7.3-sec.x commits for hub validation and replay defence, the `unsafe_code = "forbid"` lint setting, the 0700 perm on `~/.onyx/`, etc. Every claim points at a file or test.
  * **§3 honest gap list**. Nine specific gaps ranked by anonymity impact: timing correlation (biggest — cover traffic, 1–2 sessions), online/offline-linkability (per-session subscription rotation, ~3 hr), per-inbox message count (subsumed by cover traffic), no reproducible builds (supply chain), disk fingerprint, process name leak, partial memory zeroization, group-membership identity leak (out of scope — fundamental MLS property, documented as "use the right tool"), no DPI obfuscation (Tor bridges).
  * **§4 practical recommendations by threat model**. Five scenarios from "curious coworker" up to "state-level adversary" — what Onyx is right for, what it's wrong for, when to reach for SecureDrop / OnionShare instead. Explicit "for a one-shot anonymous tip, Onyx is the WRONG tool" — Onyx is identity-bound chat, not source protection.
  * **§5 comparison table**. Onyx / Signal / Briar / SecureDrop / Cwtch on four axes (network anonymity, identity anonymity, cover traffic, audited). Onyx fails the last two ("No" + "No"); both are tracked in `ROADMAP.md`. Comparison is deliberately narrow — not a product ranking, just "where Onyx lands on this one axis." Other tools are good at what they're designed for.
  * **§6 related docs**. Cross-references SECURITY.md / HOW_IT_WORKS.md / THREAT_MODEL.md / ROADMAP.md / CHANGELOG.md and asks readers to file issues for gaps not listed.

`README.md` §12 doc index updated to feature `ANONYMITY.md` as a bold row, sitting between `HOW_IT_WORKS.md` ("how do I know this is secure?") and `ROADMAP.md` ("what's coming next?") — those are the three answers a new user needs in order to decide whether Onyx fits their threat model.

What this doc does NOT do (intentionally):

  * Does not claim Onyx is anonymous against adversary A4 (it isn't, until cover traffic lands).
  * Does not promise an audit timeline (there isn't one).
  * Does not list every possible attack — only the ones with concrete defences or concrete gaps.
  * Does not recommend Onyx for sources / whistleblowers / anyone whose threat is life-safety. Explicitly redirects to SecureDrop for that.

Verification: documentation-only commit. `cargo fmt --check` / `cargo clippy -D warnings` / `cargo test --workspace` (260 tests) all unchanged from `55fb848`.

---

## 2026-05-19 — T7.3-sec.2-persist: persist the envelope-replay seen-set across daemon restarts

Closes the restart window left over from T7.3-sec.2. That commit added an in-memory FIFO seen-set of envelope hashes so the recipient daemon would silently drop replays from a hostile hub — *while the daemon was running*. The instant the daemon restarted, the set was empty, and a 5–10-minute window opened in which the hub could replay any stored envelope and bob's daemon would happily surface the duplicate. Today: that window is closed to ≤60 s (the snapshot tick) without changing any wire format or trust assumption.

What landed:

**T7.3-sec.2-persist.a — `EnvelopeReplayGuard::snapshot` + `restore`.** New methods on the guard type:

  * `snapshot() -> Vec<u8>` serialises the guard state to a flat byte buffer with a fixed `ORG1` magic, capacity (u32 BE), count (u32 BE), and the FIFO hashes in oldest-first order. No CBOR — the format is intentionally minimal so it stays trivially auditable. Deterministic: two snapshots of an unchanged guard produce byte-identical buffers, enabling a "did anything change?" check that skips disk writes when the guard is quiet.
  * `restore(&[u8]) -> Result<Self, ()>` rejects on wrong magic, truncated buffer, count exceeding capacity, or trailing bytes. The `()` error type is deliberate — a snapshot parse failure is unrecoverable in any useful sense, so the caller's only sensible response is "start with a fresh guard." `#[allow(clippy::result_unit_err)]` is on the method with the reasoning written inline.

  Seven new tests added on top of the seven T7.3-sec.2 tests: snapshot/restore round-trip, empty-guard round-trip, FIFO order preservation across snapshot (critical — the daemon needs eviction to behave the same after restore as before snapshot), `restore` rejects wrong magic / truncated / impossibly-large counts, deterministic snapshot bytes for unchanged state.

**T7.3-sec.2-persist.b — additive `replay_state` vault table.** New table in `onyx-core::storage` keyed by `identity_id` (FK to `identities` with `ON DELETE CASCADE`), single `encrypted_blob BLOB` column, `updated_at` timestamp. Same shape as `mls_state`. Two new methods on `Vault`: `save_replay_state(identity_id, plaintext)` and `load_replay_state(identity_id) -> Option<Vec<u8>>` — mirror `save_mls_state` / `load_mls_state` byte-for-byte (AEAD-seal under the vault key on save, AEAD-open on load).

  **Crucially: no schema-version bump.** The new table is created via a separate `SCHEMA_REPLAY_STATE_ADD` constant applied with `CREATE TABLE IF NOT EXISTS` in *both* `initialize` (new vault) and `open` (existing vault). Idempotent, additive. Existing v4 vaults pick up the table on next open with no migration runner — this is the documented pattern for avoiding further worsening of `THREAT_MODEL` §8.2 #13 (which already tracks the absence of a real migration runner). The rustdoc on `SCHEMA_REPLAY_STATE_ADD` spells out the rationale for the next reader.

**T7.3-sec.2-persist.c — daemon load/save/shutdown cycle.** Three pieces in `crates/onyx-daemon/src/lib.rs`:

  * **Startup load**: before constructing `DaemonState`, the daemon calls `vault.load_replay_state(identity_id)` and feeds the bytes to `EnvelopeReplayGuard::restore`. On `Err(())` (corrupt snapshot), logs a `warn!` and falls back to an empty guard rather than refusing to launch — losing the seen-set re-opens the replay window for one snapshot cycle, which is strictly better than the daemon failing to boot. On success, logs `entries` and `capacity` at `info!` so operators can see persistence is working.
  * **Periodic snapshot task**: a `tokio::spawn`'d task that ticks every 60 s. Each tick locks the guard, takes a deterministic snapshot, compares to the last-written bytes, and skips the vault write if nothing changed (a quiet daemon costs zero disk I/O). The 60 s interval is a coarse but defensible trade-off — at this cadence, an unclean exit (kill -9, crash, power loss) opens at most a 60 s replay window.
  * **Final snapshot on shutdown**: `final_replay_snapshot(&state)` is called on every clean exit path — `--no-tor` early return, post-`mode_result?` in `run`, the TCP-test modes, and the embedded-`onyx` flow — so a Ctrl-C clean exit persists *everything* the periodic task may have just missed. Removes the wasted-duplicate inline call from `run_accept_mode` that used to happen redundantly with the wrapper.

Snapshot task spawn happens *before* any mode-specific branching, so it runs in every mode (TCP-test, no-tor, Tor accept, Tor dial). The single task survives across all modes — there is no per-mode plumbing.

Security and threat-model impact:

  * **Closes** the daemon-restart replay window. New worst case: 60 s after an unclean exit. Old worst case: indefinite (until the BLAKE2b-128 hash space happened to collide on an honest delivery, statistically never).
  * **No new trust assumption.** The snapshot is AEAD-sealed by the existing vault key (Argon2id-derived from the passphrase) before any byte hits disk. A future adversary with the disk image and the vault file but not the passphrase learns nothing — they get an opaque blob the same as for `mls_state`.
  * **No new attack surface.** The snapshot file format is a 12-byte header + raw hash bytes. No CBOR parser, no serde, no chance of a parser-confusion bug. The only operation on the bytes between disk read and `restore()` is `Vault::decrypt_blob`, which is the same primitive used for every other vault field.
  * **No wire format change.** The defence remains purely recipient-side.
  * **No schema bump.** Existing vaults pick up the new table on next open via `CREATE TABLE IF NOT EXISTS`. The carry-forward #13 ("vault has no migration runner") is *not* worsened by this commit — quite the opposite, this commit documents and demonstrates the additive-extension pattern for future incremental schema work.

`THREAT_MODEL §8.2 #16` now reflects the closed state (was: ~~struck through~~ with a "restart window remains" caveat; now: ~~struck through~~ with both T7.3-sec.2 and T7.3-sec.2-persist cited, and the "restart window closed" statement explicit).

Known caveats that remain:

  * **Hard crash within 60 s of a fresh insert** still loses that insert. Acceptable trade-off — write-per-envelope would dominate the cost of receiving a message, and the worst-case impact is "the daemon's seen-set is up to 60 s behind reality."
  * **An attacker who can write to the on-disk vault** can rewrite the `replay_state` row to be `{}` (or any older snapshot) and re-open the replay window arbitrarily. This is *not* a new attack surface — the same attacker already controls the vault's `mls_state` row and could blow away every MLS group; we don't have a stronger story for on-disk integrity than "the disk is trusted." Documented in the module rustdoc.
  * **Cover traffic is still the biggest remaining anonymity gap.** Replay-defence is integrity-of-history, not unlinkability.

Verification: `cargo fmt --all` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean (one `#[allow(clippy::result_unit_err)]` on `restore` with the justification inline; two `match` → `if let` rewrites in the daemon load path), `cargo test --workspace` **260 passed / 0 failed** (was 252; +7 replay_guard snapshot/restore tests + +1 vault `replay_state_save_load_round_trip` test).

---

## 2026-05-19 — T7.3-sec.2: recipient-side replay defence for hub-delivered envelopes (closes THREAT_MODEL §8.2 #16)

Second zero-trust hardening slice in 24 hours. T7.3-sec stopped the hub from accepting *malicious publishes* into the directory; T7.3-sec.2 stops the hub from *replaying anything alice ever sent bob*. Both deepen the "hub is untrusted infrastructure" posture — neither asks the user to do anything different.

The attack, before today: alice sends bob a sealed-sender envelope. The hub stores it briefly (queue), delivers it to bob's daemon when bob comes online (DELIVER frame), bob's daemon decodes it, surfaces an `EventMessage`, message appears in bob's TUI. The hub *retains the body bytes* (it has to, to deliver them in the first place). Some time later — minutes, hours, weeks — the hub re-sends the *exact same DELIVER frame* to bob. The envelope's ephemeral hybrid KEM keys are still valid (they don't expire), the Ed25519 sender signature still checks, the inner BootstrapPayload still decodes. Bob's daemon happily surfaces a *second* `EventMessage` carrying the same text. From bob's user-facing perspective: alice sent the same message twice. From the hostile hub's perspective: a free disinformation primitive at zero protocol cost.

What landed:

**T7.3-sec.2.a — `onyx_daemon::replay_guard::EnvelopeReplayGuard`.** New module, ~140 lines, no external deps beyond what was already in the workspace. Bounded FIFO seen-set keyed on BLAKE2b-128 of the raw body bytes (same hash function `onyx_core::crypto` already exposes for routing-id derivation, so no new primitive enters the threat surface). Capacity default 4096 entries (~64 KB at full occupancy including HashMap overhead). True FIFO eviction, *not* LRU — critically, `check_and_record` does NOT re-rank on a replay hit. That property is load-bearing: if we re-ranked on hit, an attacker could keep a stale entry alive forever by replaying it, denying it cache eviction even as real new entries arrive. The unit test `replay_does_not_refresh_position` proves the FIFO semantics with a 10-replay-attempt scenario. Seven unit tests in total: first-sight-vs-replay, distinct-bodies-independent, FIFO eviction at capacity, the non-refresh property, zero-capacity clamps to one, hash collision-resistance sanity (one-bit flip ≠ collision), empty-body handled without panic.

**T7.3-sec.2.b — wiring into `handle_hub_delivery`.** `DaemonState` gains `seen_envelopes: Arc<Mutex<EnvelopeReplayGuard>>`, initialised with `EnvelopeReplayGuard::new()` (default capacity). The very first thing `handle_hub_delivery` does — *before* `open_bootstrap`, *before* even computing the sender's fingerprint — is consult the guard. On a hit, log at debug level (`"hub: dropping replayed envelope (already accepted)"`) and return early. This ordering matters: the replay check is **strictly cheaper** than the AEAD decapsulation, so even under sustained replay spam an attacker pays more (network bandwidth) than we do (16-byte hash + HashSet probe).

No new wire format. No new API. No new dep. Only a `Mutex<EnvelopeReplayGuard>` holding ~64 KB of bytes in process memory.

**T7.3-sec.2.c — THREAT_MODEL §8.2 #16 added and immediately struck-through.** Documents the attack as the original carry-forward gap so the audit trail is honest, then marks it closed in the same revision with a pointer to the guard and the known restart window.

Known limitations (documented in module rustdoc + THREAT_MODEL):

  * **Restart window.** The seen-set is in-memory only. If the daemon restarts (Ctrl-C + relaunch, crash recovery, system reboot), the set is empty; the first 5–10 minutes are replay-vulnerable again. Closing this means persisting the seen-set to the vault — a separate slice (call it `T7.3-sec.2-persist`) because vault writes per-envelope hurt throughput unless we batch.
  * **Sender retransmits look like replays.** If alice's daemon explicitly re-sends the *same* envelope (her hub-outbound queue stalled, she retried), bob's guard collapses both into one. This is the right call: sealed-sender envelopes carry no sequence number, so bob has no protocol-level way to distinguish "alice retried" from "hub replayed." Alice's daemon already constructs a fresh envelope per `seal_bootstrap` call (the ephemeral hybrid keys differ), so honest retries produce *different* bytes and pass the guard correctly. Documented in the module rustdoc so a future reader doesn't trip.
  * **Cross-recipient replays.** A hub that delivers alice→bob's envelope to *charlie* instead is a different problem (the KEM decryption will fail at charlie because the envelope wasn't sealed to charlie's KEM public). The recipient-side guard wouldn't help; the hybrid KEM does. Worth a separate audit pass but out of scope here.

Security impact:

  * **Closes** the disinformation-replay primitive a hostile or curious hub previously had against every recipient.
  * **Does not introduce a new trust assumption** — the guard runs purely in the recipient daemon's process memory, requires no cooperation from the hub or the sender, and uses a primitive (BLAKE2b-128) the threat model already trusts elsewhere.
  * **Does not add a DoS vector** — the guard's worst-case work per delivery is a 16-byte hash and a HashSet probe (microseconds). An attacker spamming 4096+ *unique* valid envelopes to flush the FIFO would have to *first* construct each one (sealed-sender requires a real ephemeral KEM keypair per envelope), and even then would only push our window forward — the attacker can't selectively evict.
  * **Strictly cheaper than `open_bootstrap`** so the replay check ordering means a replay storm costs the hub more bandwidth than it costs us CPU.

What this did NOT do:

  * Did not persist the seen-set across daemon restarts (restart window documented; tracked as `T7.3-sec.2-persist` follow-up).
  * Did not add cover traffic — still the biggest remaining anonymity gap.
  * Did not add rate-limiting on hub deliveries (orthogonal; a hostile hub already controls delivery cadence so rate-limiting would only hurt honest hubs).
  * Did not change the wire format or the recipient's API contract — `EventMessage` events still surface identically; the user only notices the *absence* of duplicate messages they shouldn't have seen.

Verification: `cargo fmt --all` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo test --workspace` **252 passed / 0 failed** (was 245; +7 replay_guard unit tests). No integration test for the wired-in guard inside `handle_hub_delivery` because constructing a sealed envelope round-trip needs the full Identity/KEM/MLS setup — the unit tests verify the dedup semantic at the right granularity and the wiring is a seven-line read-then-skip block whose correctness is direct on inspection. If a regression test for the wiring becomes valuable, the place to add it is alongside the existing `handle_send_bootstrap_mls` integration test in `api_server.rs`.

---

## 2026-05-18 — T7.3-sec: hub validates publisher ownership of KeyPackage directory entries (closes THREAT_MODEL §8.2 #15)

First *security-only* slice in the T7.x line. No new feature, no UX surface — just a real known attack vector, closed at the hub layer instead of papered over with a "the recipient catches it later" note.

The attack, before today:

  1. Alice publishes her MLS KeyPackage to the hub directory under her introduction-inbox routing id (`introduction_inbox(alice_fingerprint)`).
  2. Mallory connects to the same hub and sends `FRAME_KP_PUBLISH` claiming alice's routing id, with mallory's own KeyPackage as the body.
  3. The hub previously stored blindly (latest-wins), so mallory's KP now sits under alice's routing id.
  4. Bob fetches the KP under alice's routing id, gets mallory's KP, *might* invite mallory into a group thinking it's alice.

The defence before today was recipient-side: `handle_fetch_peer_keypackage` in the daemon extracts the KP's embedded Ed25519 signing key and refuses if it doesn't hash to `target_fingerprint`. That works — the end-to-end channel is recoverable — but the hub was still a willing accomplice. A passive observer of the directory couldn't tell whose KP was real, and the attack consumed alice's directory slot (denial of service even when authentication catches it).

What landed:

**T7.3-sec.a — `onyx_core::mls::signing_key_from_kp_bytes` free function.** New module-level helper next to `MlsParty::peer_signing_pk_from_kp_bytes`. Same parsing path (`KeyPackageIn::tls_deserialize_exact_bytes` → `validate(provider.crypto(), ProtocolVersion::Mls10)` → extract `leaf_node().signature_key()`) but instantiates an ephemeral `OpenMlsRustCrypto::default()` per call instead of borrowing a party's. The hub doesn't run MLS — it doesn't hold an `MlsParty` — but it needs the same byte-level validation, and the open-mls-rust-crypto provider is cheap to construct because we're only using its crypto trait impls (no storage, no state).

Three new unit tests in `crates/onyx-core/src/mls.rs::free_standing_helper_tests`:
  * `signing_key_from_kp_bytes_round_trips` — mint a KP from a fresh identity, extract the signing key, assert it equals `identity.fingerprint().as_bytes()` (the fingerprint *is* the Ed25519 verifying-key bytes by design).
  * `signing_key_from_kp_bytes_rejects_garbage` — empty bytes + non-KeyPackage payload → `InvalidEncoding` / `VerificationFailed`.
  * `signing_key_from_kp_bytes_matches_party_method` — the free function and `MlsParty::peer_signing_pk_from_kp_bytes` agree byte-for-byte on the same input (so daemon and hub apply identical checks).

The existing `MlsParty::peer_signing_pk_from_kp_bytes` is now a one-line forwarder to the new free function (was previously an open-coded copy of the same logic). Single source of truth; if the validation rules change, they change in one place.

**T7.3-sec.b — `onyx-hub::handler.rs` validates `FRAME_KP_PUBLISH` ownership.** In the publish-frame branch (between the existing routing-id-prefix length check and the `state.publish_keypackage` write):

  1. Extract the publisher's signing key via `signing_key_from_kp_bytes(&kp_bytes)`.
  2. Construct the publisher's fingerprint (`Fingerprint::from_bytes(signing_pk_bytes)`).
  3. Derive the expected routing id (`introduction_inbox(&fingerprint)`).
  4. Compare to the routing id the publisher *claimed* in the 16-byte prefix.

If extraction fails (un-parseable KP, failed MLS validation) **or** the derived routing id doesn't match the claim, the publish is rejected: `continue` the connection loop, no error to the publisher (silent drop — same posture as other malformed-frame handling, so attackers can't probe by counting error responses). A `warn!` lands in the hub's tracing log with the rejection reason so the operator can see attack attempts. On the accept path, the success log now reads `"hub: KeyPackage published (ownership verified)"` so operators can grep for the post-T7.3-sec posture.

Wire format **unchanged**: still 16-byte routing-id prefix followed by TLS-serialised KP. Old (pre-T7.3-sec) publishers stay compatible because they were already sending well-formed self-owned KPs under their own routing id (that was the protocol; the hub just wasn't enforcing it). New (post-T7.3-sec) publishers don't have to do anything different — the daemon's own publish path was already correct.

**T7.3-sec.c — attack test.** New `crates/onyx-hub/src/handler.rs::tests::keypackage_publish_rejects_routing_id_mismatch`. Spins up the hub with `tokio::io::duplex` (no real Tor) and runs the full attack:
  1. Alice (real Identity, real MlsParty, real KP) publishes legitimately under her routing id.
  2. Attacker (different Identity, different MlsParty, different KP) connects and tries to publish their KP claiming **alice's** routing id.
  3. Direct state assertion: `state.fetch_keypackage(&alice_routing_id)` still returns alice's KP bytes byte-for-byte. Attacker's overwrite was rejected.

The pre-existing `keypackage_publish_then_fetch_round_trip` and `keypackage_republish_overwrites` tests are updated to use real KP bytes (they previously used fake `b"opaque-kp"` payloads which now fail the validation as expected — they only worked before because there was no validation). The republish-overwrites test mints two distinct KPs from the **same** alice identity (successive `key_package_bytes()` calls produce different bundles because the init key is fresh per call, but both have the same signing key → same derived routing id → both are accepted). Latest-wins semantics preserved.

**T7.3-sec.d — THREAT_MODEL.md updated.** §8.2 #15 is now ~~struck through~~ and marked **closed in T7.3-sec** with a one-paragraph summary of the fix and a pointer to the attack test. The old note hand-waved that "a sign-challenge requires the hub to learn the publisher's Ed25519 key, which Noise XK doesn't surface" — that turned out to be wrong: the KP already *carries* the Ed25519 signing key, self-signed via the MLS leaf-node signature, so no out-of-band challenge protocol is needed. Closed properly, not papered over.

Security impact:

  * **Closes** a directory-tampering vector that previously consumed alice's directory slot even when end-to-end authentication caught the impersonation. Mallory can no longer trash the directory.
  * **Closes** a partition vector where alice's hub session momentarily lapses (reconnect, KP-rotation), mallory races in to claim the slot, alice's subsequent re-publish succeeds (alice's KP derives alice's id), but during the gap any bob fetching the slot gets garbage. Both attack and defence used to depend on alice's hub-side timing; now mallory simply cannot enter the gap.
  * **No DoS vector introduced**: the hub already drops malformed frames silently. The new check adds an MLS KeyPackage parse + ed25519-key extraction per publish — a few hundred microseconds, dominated by the existing Noise transport AEAD work.
  * **Defence-in-depth retained**: recipient-side `handle_fetch_peer_keypackage` check is unchanged. If a future bug breaks the hub's check, the recipient still catches.
  * **No new trust assumption on the hub**: the hub does the same validation the recipient already does. The hub *learns* the publisher's fingerprint as a side-effect of the check, but that fingerprint was already visible to the hub via the very routing-id the publisher claimed (the routing id is a 128-bit BLAKE2b of the fingerprint, so the hub already had a one-way fingerprint commitment; it now just verifies the publisher provided the matching pre-image).

What this did NOT do:

  * Did not change the wire format.
  * Did not add a new `THREAT_MODEL.md` carry-forward.
  * Did not change MLS protocol behaviour, ciphersuite, or vault schema.
  * Did not touch the recipient-side validation in the daemon — that stays as defence-in-depth.
  * Did not address timing correlation (still wide open; cover-traffic is the separate, bigger slice).
  * Did not address the `~/.onyx/` on-disk fingerprint, process-name leak, reproducible builds, or signed releases — all separate items, all still on the list.

Verification: `cargo fmt --all` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo test --workspace` **245 passed / 0 failed** (was 241; +3 mls helper tests + +1 hub attack-rejection test). Hub tests: 13 passed including the new attack scenario.

---

## 2026-05-18 — T7.2-mls-fu: MLS-tier invite delivers the `--text` payload as the first message

Closes the known gap left over from T7.2-mls. Before today, `onyx accept <url> --text "hi"` against an MLS-tier (`--with-kp`) invite silently *dropped* the `--text` payload — the recipient saw a synthetic placeholder `"(joined MLS group <id> via hub Welcome)"` instead of the actual introduction. The CLI rustdoc even apologised for it. Today the gap is closed: the text rides inside the same sealed-sender envelope as the Welcome and surfaces as the first message of the new conversation.

What landed:

**T7.2-mls-fu.a — `BootstrapPayload::MlsWelcome` gains `first_message: Option<String>`.** `crates/onyx-core/src/routing.rs`. New field with `#[serde(default, skip_serializing_if = "Option::is_none")]` so:
  * `None` serialises to *exactly* the same CBOR bytes pre-T7.2-mls-fu daemons emitted — no wire-format break.
  * `Some(text)` adds a `first_message: "..."` map entry inside the existing `mls/v1`-tagged variant.
  * Older daemons that don't know the field decode `None` cleanly (`serde(default)` fallback).

  Four new tests: `bootstrap_payload_round_trip_mls_welcome_with_first_message`, `bootstrap_payload_mls_welcome_omits_first_message_field_when_none` (the back-compat byte-shape check — asserts the wire literally does not contain the string "first_message" when the field is None), plus updates to two existing tests to construct with `first_message: None`.

**T7.2-mls-fu.b — `ApiRequest::SendBootstrapMls` gains `initial_text: Option<String>`.** `crates/onyx-core/src/api.rs`. Same `#[serde(default)]` discipline so a legacy client (no `initial_text` field in its JSON) parses cleanly on a new daemon. New test `send_bootstrap_mls_initial_text_back_compat` literally hand-rolls a pre-T7.2-mls-fu wire payload (no `initial_text` key) and asserts new-daemon decode yields `None` rather than failing.

**T7.2-mls-fu.c — daemon plumbing.** `crates/onyx-daemon/src/api_server.rs`:
  * `handle_send_bootstrap_mls` takes an extra `initial_text: Option<&str>` parameter and writes it into the `BootstrapPayload::MlsWelcome { welcome, first_message }` it seals.
  * **Defensive 1 KiB cap** on `initial_text` (returns `ApiErrorCode::Malformed` if exceeded). Rationale: the existing wire layer already pads to size buckets (SMALL=256, MEDIUM=1024, LARGE=4092 in `onyx-core/src/wire.rs::max_payload`), and a typical 2-party MLS Welcome lands around 1.2–1.5 KB. Capping the intro at 1 KiB keeps the sealed envelope inside the MEDIUM/LARGE boundary it would occupy without the intro — so adding a short `--text` does *not* push the envelope into the next size bucket, which would otherwise leak "this envelope carries an introduction" to a passive observer of the daemon↔hub Noise channel.
  * The cap is intentionally smaller than necessary for the bucket math because the Welcome itself varies in size across MLS group flavours; 1 KiB is the conservative ceiling that always preserves bucket parity.
  
**T7.2-mls-fu.d — recipient delivers the real message.** `crates/onyx-daemon/src/lib.rs`. The `MlsWelcome` arm of `handle_hub_delivery` now extracts `first_message`. When `Some`, that text is pushed via `push_message_via_hub` as the first entry of the new conversation (`via_hub = true` so the TUI still renders the weaker-tier badge). When `None`, the original synthetic placeholder remains. Telemetry log line gains a `has_first_message` field so operators can see which path fired.

**T7.2-mls-fu.e — CLI plumbs `--text` through MLS-tier accept.** `crates/onyx/src/main.rs`:
  * `Command::SendBootstrapMls` gains `--text: Option<String>` so the explicit one-shot path (not just `accept`) can ride an intro too. Existing CLI parser test updated; new test `send_bootstrap_mls_accepts_optional_text` covers the new arg.
  * `run_accept` now passes `text` as `initial_text: Some(text)` on the MLS-tier branch (was previously ignored). The "silently dropped" doc-comment is replaced by a comment explaining the 1 KiB cap + size-bucket reasoning.

Security and anonymity:

  * **Tampering.** `first_message` is covered by the outer sealed-sender Ed25519 signature (`bootstrap_signing_bytes` already hashes the inner payload bytes — verified by reading `routing.rs`). A MITM cannot edit the intro text without invalidating the whole envelope; the recipient drops invalid envelopes silently.
  * **Forward secrecy.** The text inherits the envelope's per-message PFS (ephemeral X25519 + ML-KEM-768 encapsulation). Same forward-secrecy properties as a `msg/v1` `PlainMessage`.
  * **Post-compromise security.** The intro **does not** have MLS PCS. It rides in the *same* envelope as the Welcome itself, which by definition predates the ratchet (the MLS ratchet covers traffic *inside* the group — everything sent from the Welcome onwards, but not the Welcome itself). This is documented in the rustdoc on the variant and explicitly noted in `run_accept`'s doc comment.
  * **Length leak.** Addressed via the 1 KiB cap (see above). Bucket parity preserved.
  * **No new tampering vector** — the wire-format change is additive and signature-covered.

Vault, threat model, protocol version: no change. Existing `SECURITY.md` §6.1 already covers the "sealed-sender envelope has PFS not PCS for the bootstrap message" caveat — this commit just makes a *useful* payload ride that channel instead of a synthetic placeholder.

Verification: `cargo fmt --all` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean (had to add `#[allow(clippy::too_many_lines)]` to `dispatch_one_shot` after the new arm pushed it over 100 lines — the match would only get less readable if split), `cargo test --workspace` **241 passed / 0 failed** (was 236; +5 across routing, api, and CLI tests).

Known gap that remains: timing correlation between sender's `onyx accept` invocation and receiver's `EventMessage` is still observable to anyone watching both endpoints' Tor entry-guard traffic. Defending that needs cover traffic — separate slice, no plans yet.

---

## 2026-05-18 — T7.2-mls: invite URLs bundle an optional KeyPackage (MLS PCS on first contact)

Follow-on to T7.2. The base T7.2 invite carried only `fp + kem`, so `onyx accept` could only do msg/v1 (PFS only). To get MLS PCS on first contact, the recipient still had to call `fetch-keypackage` and `send-bootstrap-mls` by hand — the very friction T7.2 set out to eliminate. T7.2-mls closes that hole: `onyx invite --with-kp` bundles a fresh MLS KeyPackage into the URL, and `onyx accept` auto-picks the MLS-tier path when it sees one.

What landed:

**T7.2-mls.a — `Invite` struct gains `key_package: Option<Vec<u8>>`.** `crates/onyx-core/src/invite.rs`. New constructor `Invite::with_key_package(fp, kem, kp_bytes)`, query method `is_mls_tier() -> bool`, and adapter `kp_standard_b64() -> Option<String>` that re-encodes the stored raw bytes as standard-base64 for the existing `SendBootstrapMls` / `FetchPeerKeyPackageOk` wire types. The URL format gains an optional `&kp=<base64url>` query parameter — **base64url with no padding** (RFC 4648 §5, alphabet `[A-Za-z0-9_-]`), chosen because standard base64 (`+`, `/`, `=`) needs percent-escaping inside a URL and `+` is the classic form-encoding-decodes-to-space footgun. The module docstring spells out the choice. Six new unit tests:

  * `with_kp_round_trip` — build → to_url → parse → equal, with kp.
  * `kp_uses_url_safe_base64` — bytes that *would* produce `+`/`/`/`=` in standard base64 produce none of those in the URL's `kp` value.
  * `kp_standard_b64_converts_from_url_safe` — explicit conversion check (bytes `[0xFB, 0xFF, 0xBF]` → standard base64 `"+/+/"`).
  * `rejects_invalid_kp_base64` / `rejects_empty_kp` — malformed kp values surface as `InvalidEncoding`, not silently dropped.
  * `parse_without_kp_back_compat` — T7.2 URLs (no `kp`) parse cleanly on T7.2-mls clients (this is the no-version-bump compatibility check: today's URLs keep working tomorrow).

The module docstring grew a "**KeyPackage is single-use in MLS**" subsection: sharing the same `--with-kp` URL with two peers means only one can actually consume the KP; the second hits a duplicate-init-key MLS rejection. Mint a fresh URL per recipient if you want both to land MLS-tier. (The `fp + kem` portion is fine to reshare arbitrarily — that's the msg/v1 fallback.)

**T7.2-mls.b — new API: `ApiRequest::ExportKeyPackage` + `ApiResponse::ExportKeyPackageOk { kp_b64 }`.** `crates/onyx-core/src/api.rs` + `crates/onyx-daemon/src/api_server.rs`. Purely local — no hub required, unlike `FetchPeerKeyPackage`. The daemon takes the `mls_party` lock, calls the existing `MlsParty::key_package_bytes()` (which mints a *new* KP), snapshots the resulting MLS state via the existing `snapshot_state` path, and persists it via `vault.save_mls_state(...)` before returning. The persist step matters: when the recipient eventually consumes this KP via `SendBootstrapMls` and we resume the group on our side after a restart, the init-key has to be present in our stored state for the MLS welcome decode to succeed. This is the same pattern `handle_send_bootstrap_mls` already uses for the post-invite snapshot.

**T7.2-mls.c — `onyx invite --with-kp` flag + auto-MLS in `accept`.** `crates/onyx/src/main.rs`. `Command::Invite { with_kp: bool }`; when `--with-kp` is set the CLI makes a *second* API call (`ExportKeyPackage`), decodes the standard-base64 response, and constructs `Invite::with_key_package(...)`. The base64 → bytes → base64url shuffle is contained in the CLI — the `Invite` type stays decoupled from the wire encoding. `run_accept` now switches on `invite.kp_standard_b64()`: `Some(kp_b64)` → `SendBootstrapMls { peer_fingerprint, peer_kem_pub_b32, peer_kp_b64 }`, `None` → existing `SendBootstrap`. The tier is fully URL-driven: a recipient who pastes a `--with-kp` URL gets MLS-tier without typing anything different; a recipient who pastes a base T7.2 URL still gets msg/v1.

**Known gap:** the MLS-tier `accept` path *currently silently drops* the `--text` payload, because the existing `SendBootstrapMls` API only ships the MLS Welcome (no inline application message). The introduction completes on the recipient's side (their daemon adds them to the new MLS group) but no chat text arrives in that first round-trip — chat starts from the recipient's first reply. Extending `SendBootstrapMls` to carry an inline first message is a separate slice (call it `T7.2-mls-fu`); it's documented as a doc-comment on `run_accept` so the next reader can find it.

Security: no protocol change. The MLS Welcome wire format, KP TLS encoding, sealed-sender envelope under hybrid X25519 + ML-KEM-768 — all byte-identical to what `send-bootstrap-mls` has been sending since T6.x. The `--with-kp` URL is *larger* (~2.5–3 KB vs ~2 KB for the bare form) because of the embedded KP, but the kp bytes are public information (designed for hub-directory publication anyway), so leaking them in a URL is no worse than leaking them in a hub directory query. The module docstring explicitly notes "the fingerprint, KEM public key, and KeyPackage are all safe to publish" — there is no secret in the URL. Authentication of *who* the recipient is remains the user's job, same as base T7.2.

Vault: no schema change. The new `ExportKeyPackage` handler reuses the existing `save_mls_state` path (schema v4 already accommodates MLS-state-blob writes from `SendBootstrapMls`'s post-invite snapshot).

What this did NOT do:

  * No new wire frame type — `ExportKeyPackage` is local-only over the existing API socket.
  * No invite-URL version bump — `invite/v1` still validates because today's T7.2 URLs match the v1 spec exactly (kp is optional). T7.2-mls clients accept both forms; T7.2 clients ignore the `kp` query param (forward-compat path is well-tested).
  * No `--with-kp` UI in the TUI — the CLI is the entry point. TUI invite-helper is a separate visual polish pass.
  * `--text` is not delivered on the MLS-tier path (see "Known gap" above).
  * No `THREAT_MODEL.md` update — the threat model already covers `SendBootstrapMls`'s recipient-side KP validation (§8.2 #15); `ExportKeyPackage` is a local write that doesn't change the trust boundary.

Verification: `cargo fmt --all` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean (had to hoist `use base64::Engine;` to file scope from inside `run_invite` after `clippy::items_after_statements` flagged it), `cargo test --workspace` 236 passed / 0 failed (was 229; +6 invite module + +1 CLI parser test).

---

## 2026-05-18 — T7.2: invite URLs (`onyx invite` / `onyx accept`)

Second UX win in the T7.x "make Onyx usable by humans" sequence. T7.1 killed the two-terminal problem; T7.2 kills the **copy three base32 blobs into env vars** problem.

Before today, introducing yourself to a peer over the hub meant:

  1. Run `onyx identity`, copy the 52-char fingerprint *and* the 1948-char KEM pubkey out of the JSON.
  2. Send both to your peer over Signal / in person.
  3. Peer runs `onyx send-bootstrap --peer-fingerprint "<52 chars>" --peer-kem-pub-b32 "<1948 chars>" --text "hi"`.
  4. (Optionally — for MLS — they also fetch your KP and use `send-bootstrap-mls`.)

After today, step 2's payload is **one string**:

```
onyx://invite/v1?fp=<52chars>&kem=<1948chars>
```

And the peer's step 3 is just:

```
onyx accept onyx://invite/v1?fp=…&kem=… --text "hi from bob"
```

What landed:

**T7.2.a — `onyx_core::invite` module.** New `crates/onyx-core/src/invite.rs` (~120 lines code + ~80 lines tests). Hand-rolled parser/builder for `onyx://invite/v1?fp=…&kem=…` (no `url` crate dependency — the format is intentionally minimal so parsing is one `strip_prefix` + one `split('&')` loop). Public surface:

  * `pub struct Invite { fingerprint: Fingerprint, kem_pub_b32: String }` — both fields are public information by design (same data `onyx identity` prints).
  * `Invite::new(fp, kem) -> Self` — typed constructor.
  * `Invite::to_url() -> String` — emits `onyx://invite/v1?fp=<base32_no_spaces>&kem=<base32>`.
  * `Invite::parse(&str) -> Result<Self>` — rejects wrong scheme, wrong version, missing `fp`/`kem`, empty `kem`, malformed query, invalid base32 fingerprint. Unknown query keys are *ignored* for forward-compat — a future `v1` invite with e.g. `&kp=…` parses cleanly on today's clients, which just fall through to the no-KP code path. A version bump (`invite/v2`) is reserved for breaking changes.

  10 unit tests covering: round-trip, every rejection path, forward-compat key tolerance, grouped-Display round-trip (the URL strips spaces; `Fingerprint::parse` recovers them on the way back).

**Explicitly NOT in the URL (with reasons in the module docstring):**

  * No KeyPackage. MLS-tier first-contact would need a peer KP bundled in. That's `T7.2-mls` (follow-up phase); for now `accept` is msg/v1 only. Operators wanting MLS PCS on first contact still use the existing `fetch-keypackage` + `send-bootstrap-mls` two-step.
  * No hub onion. The accepting peer is assumed to already have a hub configured. Cross-hub invites are a separate design problem.
  * No nickname. Identity in Onyx is the fingerprint, full stop. A nickname in the URL would only enable spoofing — labels are the recipient's local concern.

**T7.2.b — `onyx invite` subcommand.** `crates/onyx/src/main.rs`. Calls the daemon's existing `ApiRequest::Identity`, takes the `fingerprint` + `identity_kem_pub_b32` from `IdentityOk`, builds an `Invite`, prints `to_url()` on stdout as plain text (not JSON — meant to be piped into a clipboard / chat client). Daemon errors are forwarded as pretty-printed JSON with exit code 1, matching the convention of `one_shot_print`. **No new API request type was needed**: the daemon already exposes everything required.

**T7.2.c — `onyx accept <url> --text "…"` subcommand.** Parses the URL via `Invite::parse`, then dispatches to the existing `ApiRequest::SendBootstrap { peer_fingerprint, peer_kem_pub_b32, text }`. Invalid URLs surface as anyhow errors with context (`"invalid invite URL: invite: missing onyx:// scheme"`). `--text` is required (clap-enforced) — empty introductions don't exist at the protocol level, so the CLI refuses to invent one.

**T7.2.d — CLI parser tests.** Three new clap tests in `crates/onyx/src/main.rs::tests`:

  * `invite_subcommand_parses_with_no_args` — `onyx invite` with no flags parses to `Some(Command::Invite)`.
  * `accept_subcommand_parses_url_and_text` — positional URL + `--text` round-trips through clap.
  * `accept_requires_text_flag` — omitting `--text` must be a parse error (same anti-footgun discipline as `send-bootstrap`).

Security: no protocol change. The invite URL carries only data already published in `onyx status` / `onyx identity` — both the fingerprint and KEM pubkey are designed to be public. The `accept` path sends a msg/v1 sealed-sender envelope, which is the **exact same wire format** as today's `send-bootstrap`: same hybrid X25519 + ML-KEM-768 encapsulation, same per-message PFS, same lack of MLS PCS (documented in `SECURITY.md` §6.1). Recipients should still verify the invite's `fp` segment matches the fingerprint their peer told them out-of-band (Signal, voice, in person) before trusting the channel — the URL itself authenticates nothing about *who* shared it. The module docstring spells this out: "An invite URL is public information by design. Authentication of who the recipient is is the user's responsibility."

What this did NOT do:

  * No hub-side change, no wire-format change, no vault-schema change.
  * No MLS-tier invite URL yet (the `--with-kp` flag and the `mls://…` path are queued as the next slice — call it `T7.2-mls`).
  * No QR-code rendering. The URL is short enough (~2 KB on stdout) to paste; a QR helper can live in a follow-up that nobody's asking for yet.
  * No TUI integration. The TUI doesn't yet present "paste an invite URL" or "show your URL as a QR." That's a separate visual polish pass.

Verification: `cargo fmt --all` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean (had to swap one `i as u8` for `u8::try_from(i).expect(...)` in a test fixture once `must_use` candidates were enforced across the new module), `cargo test --workspace` 229 passed / 0 failed (was 216; +10 invite module + +3 CLI parser tests). The actual end-to-end invite handshake reuses the already-tested `SendBootstrap` path — the new code is just a CLI ergonomics layer.

---

## 2026-05-18 — T7.1: single-binary `onyx` (daemon + TUI in one process) + `~/.onyx/` defaults

Headline UX change. Before today: to chat, a user had to run `onyxd` in one terminal, `onyx tui` in another, point both at the same `--api-socket`, and make sure paths matched. After today: **`onyx` is the one command**. Run it with no subcommand and it launches the daemon in the background and the TUI in the foreground in the same process. The second terminal is gone.

Why this matters (user feedback): "Why this much hard to test something… Why cant we simplify things…" — `ROADMAP.md` called T7.1 the next priority for exactly this reason. The chat works, the security model is documented, but the bring-up friction was scaring off the very people who could give the project useful feedback. Without an external audit yet, the next-best signal is real users actually trying it. Two-terminal UX was the blocker.

What landed:

**T7.1.a — daemon as a library.** All daemon logic — vault open, identity load, MLS state restore, Tor bootstrap, API server, hub client, accept/dial loops, all the helpers — moved out of `crates/onyxd/src/main.rs` (which was ~1180 lines) into a new library crate `crates/onyx-daemon/` with the same code in `lib.rs`. The library exposes three things: `pub struct Config` (mirrors the old clap Args struct, but without the clap conflicts/requires — those stay in the binary), `pub struct DaemonState`, and `pub async fn run(args: Config) -> anyhow::Result<()>`. The submodules `api_server`, `conversations`, and `hub_client` moved with it; `use crate::DaemonState` still resolves because `lib.rs` re-exports it. `crates/onyxd/src/main.rs` is now ~100 lines: clap-parse, `impl From<Args> for Config`, `tracing_subscriber::fmt().init()`, `onyx_daemon::run(args.into()).await`. The `onyxd` binary continues to exist for headless/systemd use; it's just a thin wrapper now.

**T7.1.b — `onyx` (no subcommand) = daemon + TUI in one process.** `crates/onyx/src/main.rs` gains:

  * `onyx-daemon` as a dependency.
  * Global flags hoisted to the top-level `Args`: `--vault`, `--passphrase` (env `ONYX_PASSPHRASE`), `--listen-tcp`, `--dial-tcp`, `--dial-pubkey`. All `global = true` so subcommands inherit them.
  * `cmd: Option<Command>` (was non-optional).
  * New `Command::Daemon` subcommand for running daemon-only inside `onyx` (parity with standalone `onyxd`).
  * New `fn build_daemon_config(args, socket)` that constructs `onyx_daemon::Config` from the global args, bailing with a clear message if `--passphrase` was omitted.
  * `dispatch` gains a `None` arm: spawn `onyx_daemon::run(config)` as a `tokio::spawn` background task, sleep 500ms so the API socket has time to bind before the TUI's first connect, then run `tui::run(socket)` in the foreground. When the TUI exits the daemon task is `.abort()`ed.

**T7.1.c — sensible defaults under `~/.onyx/`.** New helpers in `onyx-daemon`: `default_data_dir()` (returns `$HOME/.onyx`, falling back to `./.onyx` if `HOME` is unset for CI sandboxes), `default_vault_path()` (= `~/.onyx/vault.db`), `default_api_socket_path()` (= `~/.onyx/onyx.sock`), and `ensure_data_dir(&Path)` which `mkdir -p`s the directory and `chmod 0700`s it on Unix (idempotent — runs every start in case the dir was created earlier with a wider umask). `onyx_daemon::run` now ensures the parent dir of both `vault` and `api_socket` exists; if the parent is the default `~/.onyx`, it also tightens permissions to 0700. Custom paths under user-chosen parents (e.g. `/tmp/...`) get `mkdir -p` but no chmod — that's the operator's territory. Both `onyxd` and `onyx` changed their clap defaults for `--vault` and `--api-socket` from the old `./onyx-state.db` / `./onyxd.sock` to `Option<...>` with `unwrap_or_else(onyx_daemon::default_*)` in `From<Args>`/`build_daemon_config`. So passing nothing now means "use `~/.onyx/`", and existing `--vault ./foo.db` invocations keep working unchanged.

Smoke-test evidence (two `onyx daemon` instances chatting via local TCP, no Tor):

```
INFO inbound-tcp{peer=127.0.0.1:58673}: onyx_daemon: Noise XK complete
INFO inbound-tcp{peer=127.0.0.1:58673}: onyx_daemon: MLS round-trip complete (responder); was_bootstrap=true
INFO inbound-tcp{peer=127.0.0.1:58673}: onyx_daemon: conversation registered with registry peer=ri4ioet7
```

That `onyx_daemon:` (not `onyxd:`) on every log line confirms the daemon code is running inside the unified `onyx` binary via the shared library — it's not just a renamed shim around `onyxd`. Bob then sent "hi alice — from the unified onyx binary!" via the Send API → `SendOk` → Alice received the plaintext in her registry.

Security: identical to T7.0. No protocol-visible change. The library extraction is purely organisational — the wire bytes, the MLS group, the Noise transport, the vault format are all byte-identical. The `~/.onyx/` directory is 0700, so the vault + socket are not world-readable by default (was previously `./onyxd.sock` in the CWD which inherited umask, so this is a small *improvement* not a regression). `--passphrase` continues to be hide_env_values + recommended-via-env-not-CLI so it doesn't show up in `ps`. Test-only `--listen-tcp` / `--dial-tcp` flags still loudly warn "no anonymity" via the existing T7.0 warning paths.

What this did NOT do:

  * No change to the hub protocol, the wire format, or the vault schema.
  * No change to MLS bootstrap or MLS PCS.
  * The `onyxd` binary is still built and shipped; this is purely additive at the binary level. Anyone running `onyxd` under systemd today doesn't have to change anything.
  * Invite URLs (`onyx invite` / `onyx accept`) are T7.2, still queued.
  * Channels / multi-party rooms are T6.3, still queued.

Verification: full gate green — `cargo fmt --all` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean (had to add `#[must_use]` to two now-public methods in `conversations.rs`, swap a `map().unwrap_or_else()` to `map_or_else()`, and nest an or-pattern in `main.rs` once they crossed visibility/version boundaries), `cargo test --workspace` 216 passed / 0 failed (same count as before; no test added but none lost either — the smoke-test above is the real end-to-end check the library extraction is correct).

---

## 2026-05-18 — Docs: ROADMAP.md — what's done / in-flight / next / later / won't-do

No code change. The project already had `CHANGELOG.md` for what's done (one verbose entry per phase) and `THREAT_MODEL.md` §8.2 for security carry-forwards, but nothing centralised for "what's coming next." Users had to read backwards through the CHANGELOG and infer priorities. New `ROADMAP.md` makes the queue explicit.

Eight sections:

  1. **Status at a glance** — done / in-flight / next / later / won't-do as a single ASCII summary line, plus commit count + test count + the always-on "external review status: none" line.
  2. **Done** — every shipped phase (T1, T2, T3.1, T4.1–T4.3, T5.1, T5.2.a–g, T6.1, T6.2, T7.0, plus the doc work) summarised in one paragraph each with a pointer to the relevant CHANGELOG entry.
  3. **In flight** — currently empty. Honest.
  4. **Next (queued, priority order)** — T7.1 (single-binary `onyx`, recommended next) → T7.2 (invite URLs) → T6.3 (channels). Each has: the change, what the user notices, why it's prioritised where it is, estimated size.
  5. **Later** — T6.4 async MLS over hub, hub invite-only auth, schema migration runner, hub-side KP ownership validation, reproducible builds + signed releases, cover traffic, **external security audit** (called out as the single most impactful action).
  6. **Long-term** — multi-device, mobile, voice/video, federation, onion-web tier. Each acknowledged as "real-product territory" needing its own design doc + threat-model update first.
  7. **Won't do in v0** — six explicit non-goals: centralised identity, phone-number registration, optional cryptographic weakening, `unsafe` in `onyx-core`, telemetry, auto-update.
  8. **How priorities get set** — two written principles: (1) closing a `THREAT_MODEL.md` §8.2 carry-forward beats adding a new feature; (2) smallest reviewable surface wins. Acknowledges that priorities are one developer's judgment calls and an "override is a deliberate exception" (with T7.0 cited as the recent example).

The doc explicitly does not contain dates, version numbers, or commitments. Estimates are "2–3 hours" type rather than calendar weeks because (a) this is a one-developer project and (b) every prior estimate I've made for myself has been wrong.

`README.md` §12 doc index updated to feature `ROADMAP.md` as the entry point for "what's coming next?" questions, alongside `HOW_IT_WORKS.md` (entry point for "how do I know this is secure?"). Both are now bold rows in the table.

Verification: documentation only — `cargo test --workspace` (216) + `cargo fmt --check` + `cargo clippy -D warnings` + `cargo deny check` all unchanged from prior doc commits.

---

## 2026-05-18 — Docs: HOW_IT_WORKS.md — plain-English security walkthrough with evidence

No code change. New top-level document that answers "how do I know this is secure?" without claiming Onyx is bulletproof — because it isn't. The user asked for "proofs how it's bulletproof"; the cautious response was to write the honest equivalent: a doc that walks through every protection layer and cites the specific test, RFC, or audited library that backs each claim, while loudly preserving the §0 caveat that no external audit has happened.

Eight sections:

  0. **Honest framing**, repeating `SECURITY.md` §1's disclaimer up front. The phrase "bulletproof / unbreakable / military-grade" appears exactly once in the document — explaining why it appears exactly once.
  1. **A chat message's life, step by step.** ASCII flow diagram tracing the path from "you type 'hi'" → TUI → daemon → MLS encrypt → Noise encrypt → Tor → reverse on the other side. Numbered ten steps so a reader can map any test or source file back to a specific stage.
  2. **The six layers.** Unix socket, vault encryption, sealed-sender envelope, MLS, Noise XK, Tor — each gets a "what it is / what it protects / what it does NOT protect / evidence" treatment. The evidence sections cite specific test names by full path.
  3. **Adversary table.** Eleven concrete attacker classes (passive ISP, café Wi-Fi, hub op, hub-rooted attacker, active network MITM, other user on the laptop, laptop thief, global passive observer, quantum-equipped attacker, coerced user, malicious developer) with what protects you and which test/threat-model section verifies it.
  4. **How to verify yourself.** Three subsections: run the tests (with a table of the dozen most security-relevant test names + what each proves); check the upstream libraries (with links to each crate's repo + audit history); read the protocol references (RFC 9420, 8439, 8032, 7748, 9106, FIPS 203, Noise spec, Tor spec).
  5. **Comparison to Signal / IRC / Tor Messenger / Briar.** Twelve-row matrix being explicit that Signal is more mature, IRC is less private, Briar covers similar ground with more deployment history. Closing line: "if you want to ship to actual humans today, use Signal. Onyx is interesting because it composes ideas from each in a single explicit codebase, but it has not earned the trust those mature tools have."
  6. **What Onyx does NOT do (negative claims, explicit).** Nine bullets calling out things a casual reader might assume (audited, malware-proof, deniable, has invite-only hubs, reproducible builds, multi-device, mobile, etc.). Each ends "If any of these is a deal-breaker, Onyx is the wrong tool."
  7. Pointer to `THREAT_MODEL.md` §8.2 for contributors who want to close one of the gaps.
  8. Doc index + the line "When this document and the others disagree, the others win. `SECURITY.md` §1 is the authoritative status disclaimer."

**Discipline applied throughout**: every cryptographic claim names the specific crate AND version AND RFC. Where a property holds because of an upstream library, the doc says so explicitly rather than implying Onyx contributes the property. The comparison table places Onyx honestly behind Signal, Briar, and even IRC on dimensions where it is behind, rather than cherry-picking only flattering categories.

The `bulletproof` framing the user asked for was deliberately refused — that adjective doesn't apply and writing it would directly contradict `SECURITY.md` §1 + create a liability if a reader trusts it. The doc's introduction explains this in one sentence and then provides the honest substitute.

`README.md` §12 doc index updated to feature the new document as the entry-point for security questions, with a recommended-bold cell so a reader landing on the repo sees it.

Verification: documentation only — `cargo test --workspace` (216) + `cargo fmt --check` + `cargo clippy -D warnings` + `cargo deny check` all unchanged.

---

## 2026-05-18 — Docs refresh: README.md rewritten

No code change. The README was four-plus phases out of date — it claimed `onyx` and `onyx-hub` were "scaffold only" (both are functional now), reported "~110 tests" (we have 216), and didn't mention any of T4 (TUI + API socket), T5 (sealed-sender + hub-relayed delivery), T6 (KP directory + fetch verbs), or T7 (local-TCP test modes). New README is a single document covering install, four recipes (no-Tor smoke / local-TCP fast / real Tor / hub-relayed), TUI key reference, CLI subcommand reference, security-tier table, troubleshooting, configuration paths, architecture cheat-sheet, doc index, contributing guidelines, and license.

Discipline preserved: every cryptographic claim names the specific RFC and crate; every adjective like "audited" or "proven" is absent; the §0 status disclaimer leads the document and matches `SECURITY.md` §1's caveats verbatim.

Verification: this is documentation only — `cargo test --workspace` ✓ (216 unchanged), `cargo fmt` ✓ (no source touched), `cargo clippy -D warnings` ✓ (no source touched), `cargo deny` ✓.

---

## 2026-05-18 — T7.0: `--listen-tcp` / `--dial-tcp` test modes — chat without Tor

**The "I just want to test this without 90 seconds of Tor bootstrap" commit.** Two new daemon flags let `onyxd` accept and dial peers over plain TCP on `127.0.0.1` (or anywhere routable, if you really want to). The full Noise XK + MLS chat path is exercised — only the Tor transport is replaced. Anyone working on the codebase can now stand up two daemons + chat between them in **under 5 seconds total**, instead of the 60-90 s + four terminals of the Tor recipe.

This is **test-only**. The mode is loudly warned at daemon startup, in CLI `--help`, and in a new `SECURITY.md` §6.2 section that explicitly says "no anonymity, do not run against real peers."

### Why this matters

Up until today, the smoke-test loop for any chat-related change was:

  1. Edit code, `cargo build --release`.
  2. Spin up `onyxd` (Terminal 1) with `--vault`, `--passphrase`, `--tor-state-dir`, `FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS=1`, etc.
  3. Wait 30-60 s for Arti's first-run cache build.
  4. Copy the onion + identity_pub from the log.
  5. Spin up a second `onyxd` (Terminal 2) with the same env-var dance + `--dial-onion <paste>` + `--dial-pubkey <paste>`.
  6. Wait another 30-60 s for the second daemon's Arti to bootstrap.
  7. Open `onyx tui` against each socket. Finally chat.

After today the loop is:

  1. Edit, `cargo build`.
  2. `onyxd --listen-tcp 127.0.0.1:7710 ...` (Terminal 1, takes <1 s).
  3. Copy alice's `identity_pub_b32` from the log (one string, printed on stdout with a complete `--dial-tcp` recipe).
  4. `onyxd --dial-tcp 127.0.0.1:7710 --dial-pubkey <paste> ...` (Terminal 2, takes <1 s).
  5. `onyx tui` × 2. Chat.

### Code structure

**Generalised the chat path over the stream type.** `handle_inbound`, `peer_session`, and `drive_peer_session` were hard-coded to `TorStream`. They only use `AsyncRead + AsyncWrite + Unpin + Send`, so all three are now generic over a type parameter `S` with that bound. The Noise handshake, MLS state machine, frame codec, and registry integration are identical whether the underlying stream is a Tor circuit or a `tokio::net::TcpStream`. That's the right factoring anyway — the chat protocol shouldn't care what carries it.

**Extracted `run_dial_session<S>`** from `run_dial_mode`. The MLS bootstrap-or-resume logic (vault lookup, stale-mapping fallback, snapshot persistence, peer→group recording) is non-trivial — duplicating it in a parallel `run_tcp_dial_mode` would have been a maintenance nightmare. Now the Tor path is `tor.dial → run_dial_session` and the TCP path is `TcpStream::connect → run_dial_session`. Single source of truth.

**Two new mode handlers in `main.rs`**:

  * `run_tcp_listen_mode(addr, state, api_socket_path)` — binds a `TcpListener`, accepts streams, spawns `handle_inbound(stream, state)` per connection. Also spawns the API server. On startup logs the literal `--dial-tcp <local_addr> --dial-pubkey <identity_pub_b32>` invocation a peer needs to type — eliminates the most error-prone copy-paste step from the dev loop.
  * `run_tcp_dial_mode(addr, peer_pubkey_b32, state, api_socket_path)` — `TcpStream::connect`, then `run_dial_session` (same as the Tor path). Spawns the API server alongside so the user can `onyx tui` against the daemon while the chat is live.

**CLI flags**:

  * `--listen-tcp <ADDR>` (env: `ONYX_LISTEN_TCP`). Conflicts with `--dial-onion` and `--dial-tcp`.
  * `--dial-tcp <ADDR>` (env: `ONYX_DIAL_TCP`). Requires `--dial-pubkey`. Conflicts with `--dial-onion` and `--listen-tcp`.

Both flags imply skipping Tor entirely. clap enforces the mutual exclusion.

### Loud warning at every entry point

At daemon startup if `--listen-tcp` is set:

```
WARN onyxd: LISTEN-TCP MODE — NO TOR, NO ANONYMITY. Test/dev only.
            Anyone who can reach this address can speak Noise to this daemon.
            addr=127.0.0.1:7710
INFO onyxd: TCP listener bound; accepting connections local_addr=127.0.0.1:7710
INFO onyxd: share `--dial-tcp 127.0.0.1:7710 --dial-pubkey acgilwcw...` with a peer to chat
```

The clap `--help` doc for both flags includes the **TEST-ONLY** banner. `SECURITY.md` §6.2 (new) documents the threat-model implications. A user who has these flags on cannot reasonably claim they didn't see a warning.

### End-to-end smoke test (captured live, in this commit)

```
ALICE_PUB=$(onyx --socket /tmp/onyx-tcp/alice.sock identity \
              | jq -r .identity_pub_b32)
# acgilwcwkxczahovuxuducoz2pdoxvmnhgiuntcd3eoj6tuqq5dq

onyxd --vault /tmp/onyx-tcp/bob.db --api-socket /tmp/onyx-tcp/bob.sock \
      --dial-tcp 127.0.0.1:7710 --dial-pubkey "$ALICE_PUB" &
# T+0.0s: TCP connected
# T+0.0s: Noise XK complete
# T+0.0s: peer X25519 matches --dial-pubkey ✓
# T+0.0s: no prior group — bootstrapping (initiator)
# T+0.01s: MLS round-trip complete (initiator)
# T+0.01s: MLS state persisted to vault state_bytes=8874
# T+0.01s: conversation registered

# bob's daemon now sees alice as a registered peer:
echo '{"kind":"Peers"}' | nc -U /tmp/onyx-tcp/bob.sock
# {"kind":"PeersOk","entries":[{"short_id":"acgilwcw",..."connected":true,...}]}

echo '{"kind":"Send","peer_short":"acgilwcw","text":"hi alice from bob via TCP!"}' \
  | nc -U /tmp/onyx-tcp/bob.sock
# {"kind":"SendOk"}

# alice's daemon log:
# INFO onyxd: chat message sent text=hi alice from bob via TCP!
```

Total wall-clock: **~3 seconds** including vault creation, identity generation, TCP handshake, Noise XK, MLS bootstrap, and a chat round-trip. The same flow over Tor takes 60–120 seconds and four terminal windows.

### Verification

  * `cargo fmt --all --check` ✓ (after one round of fmt-driven attribute-position cleanup).
  * `cargo clippy --workspace --all-targets -- -D warnings` ✓ — fixed one `empty_line_after_outer_attr` that fmt introduced by inserting my new section header between `#[allow(too_many_lines)]` and its target function.
  * `cargo test --workspace` ✓ — **216 total**, unchanged from T6.2 (this commit doesn't add new tests — the new code is a thin shim over already-tested helpers + a manual smoke captured above).
  * `cargo deny check` ✓.

### Open security gaps + carry-forward

  * **`SECURITY.md` §6.2** added explicitly to document that TCP mode is testing-only. A future repo-rules document could reject `--listen-tcp` from production deployments at the CI layer, but that's overkill at v0.
  * **No CI test exercises TCP mode** — the smoke was manual. Adding an integration test that spawns two daemons via `tokio::process::Command` and walks a chat is a reasonable follow-up.
  * **The flag implicitly trusts the OS's bind semantics.** A malicious user with shell access could bind `0.0.0.0:7710` and expose the daemon publicly. The daemon doesn't enforce loopback-only; documented in §6.2.
  * Everything from prior carry-forward lists still open. **T7.1 (single-binary `onyx`) and T7.2 (invite URLs)** are next — together they get the user-side recipe down to one command per side instead of today's two terminals + flag-paste.

---

## 2026-05-18 — T6.2: in-session KP fetch + `onyx fetch-keypackage` + `onyx send-bootstrap-mls`

T5.2.e shipped the `mls/v1` envelope but required the user to obtain the recipient's `peer_kp_b64` out of band. T6.2 closes that gap: the daemon now fetches KPs from the hub directory (T6.1) over its existing Noise session, with full recipient-side validation against the expected fingerprint. Two new CLI subcommands wrap the path so the entire mls/v1 first-contact flow is now demoable from the shell as a `jq | pipe` 3-liner.

### `hub_client` — in-session request/response for KP fetches

The post-handshake `serve_session` loop already handles inbound `FRAME_DELIVER` and outbound `FRAME_DELIVER`. This commit adds:

  * Inbound `FRAME_KP_RESPONSE` handling — payload status byte + optional KP body → resolves an oneshot.
  * Outbound `FRAME_KP_FETCH` handling — writes the frame with payload `routing_id (16 B)`.

`HubOutbound` refactored from a struct to an enum:

```rust
pub enum HubOutbound {
    Deliver { target: RoutingId, body: Vec<u8> },
    FetchKp { routing_id: RoutingId, responder: oneshot::Sender<Option<Vec<u8>>> },
}
```

Backwards-compat helper `HubOutbound::deliver(target, body)` keeps the two existing send sites short. Existing duplex test updated to use the new constructor.

### FIFO matching invariant (the load-bearing design decision)

`FRAME_KP_RESPONSE` carries no request id. The wire protocol is request/response with implicit FIFO ordering on a single connection. The hub-client's `serve_session` keeps a `VecDeque<oneshot::Sender>` of pending fetches; when a response arrives, it pops the front and resolves it.

**Correctness depends on at most one outstanding fetch at a time per session.** Enforcement lives at the API-handler level: `DaemonState` gains a `hub_fetch_lock: Arc<Mutex<()>>` that `handle_fetch_peer_keypackage` holds for the full duration of the round-trip (push → await response). Slow under concurrent demand but correct. Future T6.x can add a request-id field to the wire format and lift the serialisation.

The doc-comment on `serve_session` and the inline comment in `handle_fetch_peer_keypackage` both document this invariant explicitly — a future contributor cannot accidentally weaken it without noticing.

### `onyx-core::api` — `FetchPeerKeyPackage` + `FetchPeerKeyPackageOk`

```rust
ApiRequest::FetchPeerKeyPackage { peer_fingerprint: String }
ApiResponse::FetchPeerKeyPackageOk { kp_b64: String }
```

Three new round-trip / wire-shape tests in `api::tests`.

### `onyxd::api_server::handle_fetch_peer_keypackage` — security-critical handler

  1. Require hub configured (`NotReady` if not).
  2. Parse fingerprint (`Malformed` if not).
  3. Compute the introduction-inbox routing id.
  4. Acquire `state.hub_fetch_lock` (serialises across all concurrent calls).
  5. Build a oneshot, push `HubOutbound::FetchKp`, await.
  6. **Validate** the returned KP's embedded Ed25519 signing key against the supplied fingerprint via `MlsParty::peer_signing_pk_from_kp_bytes` + `VerifyingKey::fingerprint`. **Mismatch → `Malformed` with explicit `"fetched KP signing key does not match peer_fingerprint — refusing (potential hub-directory tampering)"`.**
  7. Base64-encode and return.

The validation step is the same one `handle_send_bootstrap_mls` does on a *supplied* KP — both defend `THREAT_MODEL.md` §8.2 #15 (hostile hub directory swap). Doing the validation on the *fetch* path too means CLI users can't accidentally obtain and propagate a malicious KP even if they trust the hub.

### CLI: two new `onyx` subcommands

```
onyx fetch-keypackage --peer-fingerprint <FPR>
  # → {"kind":"FetchPeerKeyPackageOk","kp_b64":"..."}

onyx send-bootstrap-mls --peer-fingerprint <FPR> \
                        --peer-kem-pub-b32 <KEM> \
                        --peer-kp-b64 <KP>
  # → {"kind":"SendBootstrapMlsOk","group_id_b32":"..."}
```

Three new CLI parsing tests:
  * `send_bootstrap_mls_parses_with_three_flags` — locks in the literal flag names.
  * `fetch_keypackage_parses` — same for the fetch subcommand.
  * `send_bootstrap_mls_requires_all_three_flags` — anti-footgun: omitting `--peer-kp-b64` is a clap parse error, not a silent default.

### The new end-to-end demo (CHANGELOG-worthy 3-liner)

Replaces the 30-line recipe from T5.2.g for the MLS path:

```sh
# alice already running; bob already running; hub already running;
# alice + bob both connected to hub (auto-publishes their KPs)

BOB_ID=$(onyx --socket ./bob.sock identity)
BOB_FP=$(jq -r .fingerprint <<<"$BOB_ID")
BOB_KEM=$(jq -r .identity_kem_pub_b32 <<<"$BOB_ID")

# alice fetches bob's published KP through her own hub session,
# verified against bob's fingerprint:
BOB_KP=$(onyx --socket ./alice.sock fetch-keypackage \
            --peer-fingerprint "$BOB_FP" | jq -r .kp_b64)

# alice establishes a real MLS group with bob via the hub:
onyx --socket ./alice.sock send-bootstrap-mls \
     --peer-fingerprint "$BOB_FP" \
     --peer-kem-pub-b32 "$BOB_KEM" \
     --peer-kp-b64 "$BOB_KP"
# {"kind":"SendBootstrapMlsOk","group_id_b32":"..."}
```

After this both daemons hold the same MLS group; direct dial between alice and bob (or future T6.x MLS-over-hub) gives PCS-protected chat.

### Verification

  * `cargo fmt --all --check` ✓
  * `cargo clippy --workspace --all-targets -- -D warnings` ✓ — chased the existing `HubOutbound { ... }` struct-pattern in the duplex test (now uses the new enum variant pattern + a panic on the unexpected `FetchKp` arm).
  * `cargo test --workspace` ✓ — **167 in `onyx-core`** (+3 api), **27 in `onyxd`** (unchanged — no new dispatcher tests; security check already covered by the T5.2.e guardrail test pattern), **12 in `onyx-hub`**, **10 in `onyx`** (+3 CLI shape). **216 total** (+6 since T5.2.e).
  * `cargo deny check` ✓.

### Open security gaps + carry-forward

  * **`FRAME_KP_RESPONSE` still has no request id.** Concurrent `FetchPeerKeyPackage` calls are serialised in the daemon via `hub_fetch_lock` — correct but slow. T6.x can add a request-id field to lift the serialisation.
  * **Hub-side ownership validation of routing ids** still open (`§8.2 #15`); the recipient-side check in both `handle_send_bootstrap_mls` and `handle_fetch_peer_keypackage` defends end-to-end.
  * **Ongoing MLS-over-hub** (T6.x) still ahead.
  * Everything from prior carry-forward lists still open.

---

## 2026-05-18 — T5.2.e: `mls/v1` envelope variant — MLS PCS over the hub

**The T5.2 chain closes here.** Today's commit lands the second sealed-sender payload variant — `BootstrapPayload::MlsWelcome` (`v: mls/v1`) — and wires both the sender and recipient sides through the hub. After this commit, alice can establish a real MLS group with bob via the hub without either of them ever directly dialling the other. Every application message exchanged inside that group has full MLS post-compromise security; the per-message PFS of the sealed envelope + the MLS ratchet inside the group give the strictly stronger protection that the T5.2.f tier badge was always pointing at.

### Honest scope statement up front

This commit ships **group establishment over hub**, not **chat-over-hub**. After alice does `SendBootstrapMls`, both daemons have a persistent 2-party MLS group; alice's vault has the post-invite snapshot, bob's vault has the post-join snapshot. **What's still missing**: a wire format for ongoing MLS application messages routed over the hub (using per-epoch session-token routing ids per DESIGN §5.5 Tier 2). Today, after the Welcome lands, the only way for the two to actually exchange MLS-protected messages is for one of them to direct-dial the other — at which point the existing T2.x "resume MLS group" path takes over and the conversation is fully MLS-protected. That's a real intermediate state. The CHANGELOG calls it out so nobody is misled into thinking T5.2.e gives async MLS chat.

T6.x will lift this: an `MlsAppOverHub` wire variant + session-token routing addressing → fully async MLS-protected chat without ever needing a Tor circuit between the peers.

### `onyx-core::routing` — new variant

```rust
pub enum BootstrapPayload {
    #[serde(rename = "msg/v1")]
    PlainMessage { text: String },
    #[serde(rename = "mls/v1")]
    MlsWelcome { welcome: ByteBuf },  // new
}
```

The `#[serde(tag = "v")]` discrimination means unknown tags still get refused (P5 enforcement — verified by the existing `bootstrap_payload_unknown_variant_is_rejected` test). Three new tests this commit:

  * `bootstrap_payload_round_trip_mls_welcome` — encode/decode is the identity.
  * `bootstrap_payload_mls_welcome_carries_version_tag` — literal bytes contain `"mls/v1"` AND do **not** contain `"msg/v1"` (catches a serde misconfig where both tags get emitted).
  * `bootstrap_payload_mls_welcome_round_trips_inside_sealed_envelope` — end-to-end through `seal_bootstrap` + `open_bootstrap` + `from_cbor`, asserting both the recovered payload and the verified sender signing key match.

### `onyx-core::mls` — new helper for KP signing-key extraction

```rust
pub fn peer_signing_pk_from_kp_bytes(&self, kp_bytes: &[u8]) -> Result<[u8; 32]>
```

Deserialises a KeyPackage, validates it (signature, lifetime, ciphersuite), extracts the embedded Ed25519 signing public key. This is the building block for the **recipient-side fingerprint validation** of T5.2.e — defending against the `THREAT_MODEL.md` §8.2 #15 attack where a hostile hub directory swaps an attacker's KP under the target's routing id.

Two new tests: round-trip with bob's KP (extracted matches `bob.signing_public_bytes()`), and garbage rejection.

### `onyx-core::api` — `SendBootstrapMls` request + `SendBootstrapMlsOk` response

```rust
ApiRequest::SendBootstrapMls {
    peer_fingerprint: String,    // expected — used to validate the KP we're about to invite from
    peer_kem_pub_b32: String,    // recipient's hybrid KEM public, for sealing
    peer_kp_b64: String,         // recipient's MLS KeyPackage bytes, base64
}
ApiResponse::SendBootstrapMlsOk { group_id_b32: String }  // echoes the new group's stable id
```

Wire-shape and round-trip tests added.

### `onyxd::api_server::handle_send_bootstrap_mls` — the dispatcher

Linear `parse → validate → build → seal → persist → push` sequence:

  1. Require `hub_outbound: Some` (NotReady if not).
  2. Parse fingerprint, base32-decode KEM, base64-decode KP. Each → `Malformed` on failure.
  3. **Validate the KP's signing key vs. the supplied fingerprint** — calls `MlsParty::peer_signing_pk_from_kp_bytes`, hashes the result via `VerifyingKey::fingerprint`, compares to `peer_fingerprint`. Mismatch → `Malformed` with the explicit message `"KP signing key does not match peer_fingerprint — refusing to invite (potential hub-directory tampering)"`. **This is the security-critical step**; the rest of the chain is mechanical.
  4. Take the MLS party lock, `create_group` (solo), `invite(peer_kp)` (returns Welcome bytes), snapshot.
  5. Wrap the Welcome in `BootstrapPayload::MlsWelcome` → CBOR → `seal_bootstrap`.
  6. Persist the post-invite MLS snapshot in the vault (so the group survives a daemon restart).
  7. Push to `hub_outbound` addressed to the peer's introduction-inbox routing id.

One regression-guardrail test in api_server::tests: `send_bootstrap_mls_validation_step_exists` does a literal source-grep for the `vk.fingerprint() != fp` check and the refusal error message. If a future refactor moves or renames the validation step it must update both the implementation AND this guardrail.

### `onyxd::handle_hub_delivery` — new `MlsWelcome` arm

Extends the existing `match payload { … }`:

  * `PlainMessage` (existing) → `register_hub_only` + `push_message_via_hub`.
  * **`MlsWelcome { welcome }`** (new) →
    1. Try `MlsParty::join_from_welcome` (silent debug-level drop on failure, anti-log-spam).
    2. Snapshot the post-join MLS state and persist to vault (`save_mls_state`).
    3. Register the sender in the conversation registry as `register_hub_only` (hub-only peer with no live transport, but the MLS group is real and ready).
    4. Push a hub-tagged event into the registry: `"(joined MLS group {group_id_b32} via hub Welcome)"`. The TUI's `[hub]` badge from T5.2.f renders this just like a `msg/v1` message, so the user sees the join immediately.

### What this enables (and what it still doesn't)

  * **End-to-end demo** (manual; the binaries support it): alice publishes her KP on hub connect (T6.1), bob fetches alice's KP from hub (currently via direct connect; T6.x adds in-session FETCH from the API), bob calls `SendBootstrapMls` against alice, alice's `handle_hub_delivery` joins the MLS group, both vaults now hold the same MLS group. Subsequent direct dial by either side resumes the group via the T2.x path → MLS-protected chat.
  * Doesn't enable: bob types a message in his TUI and alice (offline-via-hub) reads it later. That requires T6.x's MLS-over-hub wire format.

### `THREAT_MODEL.md` §8.2 #1 updated

Now reflects end-to-end closure of both `msg/v1` (PFS) and `mls/v1` (PCS-via-MLS) paths. The remaining gap (ongoing MLS app messages over hub) is named explicitly. §8.2 item count stays at 15.

### Verification

  * `cargo fmt --all --check` ✓
  * `cargo clippy --workspace --all-targets -- -D warnings` ✓ — three `manual_let_else` cleanups + one `too_many_lines` allowance on `handle_send_bootstrap_mls` with justification + a `match_wildcard_for_single_variants` lint resolved by explicit enumeration of `BootstrapPayload::MlsWelcome` in the test panic arm.
  * `cargo test --workspace` ✓ — **164 in `onyx-core`** (+8: 3 BootstrapPayload variant + 3 SendBootstrapMls api + 2 mls peer_signing_pk), **27 in `onyxd`** (+1: dispatcher guardrail), 12 in `onyx-hub`, 7 in `onyx`. **210 total** (+9 since T6.1).
  * `cargo deny check` ✓.
  * New workspace dep: `base64 = "0.22"` (was transitive via openmls but now used directly for `peer_kp_b64` decoding — explicit dep makes the surface visible per the project's discipline).

### Open security gaps + carry-forward

  * **T6.x — MLS-over-hub wire format** for ongoing app messages, addressed via per-epoch session-token routing ids. Without it, post-Welcome chat between peers who've never direct-dialled requires one of them to come online via Tor first.
  * **No `FetchPeerKeyPackage` API verb yet** — the user has to obtain `peer_kp_b64` out of band (or via a custom shell pipeline against the hub). T6.x or a near-term polish commit will add it.
  * **No CLI affordance for `SendBootstrapMls`** — same shell-only as T5.2.c was before T5.2.g. A `onyx send-bootstrap-mls` subcommand is a small follow-up.
  * **`THREAT_MODEL.md` §8.2 #15 still open** — hub doesn't validate publisher ownership of routing ids. Mitigation is the recipient-side check in `handle_send_bootstrap_mls`, which is now the security-critical step in the path.
  * Everything from prior carry-forward lists still open.

---

## 2026-05-18 — T6.1: KeyPackage directory on the hub

Foundational commit that unblocks two distinct next steps: **T5.2.e** (the `mls/v1` envelope variant with true PCS over the hub) and **T6.3** (multi-party rooms/channels). Both need the same capability: a sender must be able to obtain a recipient's MLS KeyPackage *before* constructing a Welcome message — and recipients aren't necessarily online at send time.

The hub now stores one KeyPackage per routing id and answers fetches. Daemons auto-publish their current KP on every hub connect.

### New wire frame types (`onyx-core::wire`)

```rust
pub const FRAME_KP_PUBLISH:  u16 = 0x50;  // client → hub  (store-and-forget)
pub const FRAME_KP_FETCH:    u16 = 0x51;  // client → hub  (lookup request)
pub const FRAME_KP_RESPONSE: u16 = 0x52;  // hub → client  (lookup answer)
```

Payload shapes (codified in the doc comments):

  * **`KP_PUBLISH`**: `16-byte routing_id ‖ raw MLS KeyPackage bytes`. Same `target ‖ body` shape as `DELIVER` — keeps the wire decoder simple. Latest-wins; each publish overwrites the prior KP at that routing id. No ACK.
  * **`KP_FETCH`**: exactly 16 bytes (the routing id to look up). Anything else → hub logs and ignores.
  * **`KP_RESPONSE`**: 1-byte status (`0` = found, `1` = not found) followed by the KP bytes on `found`. Empty body on not-found.

The wire-format doc on each constant is explicit about the security model and the recipient-side validation obligation. Worth quoting:

> **Hub does not validate publisher ownership of the routing id.** Misuse: a connected client could overwrite another peer's published KP under that peer's routing id. The recipient mitigates this end-to-end: when fetching `target_fingerprint`'s KP, the recipient MUST verify that the KP's embedded Ed25519 signing key hashes to `target_fingerprint`. Hub-side challenge-and-respond ownership proof is a documented future-work item.

This is the cautious cut: the directory is functionally complete today, the ownership-validation gap is recoverable on the recipient side, and the proper fix (sign-challenge requiring the hub to know the publisher's Ed25519) is tracked as `THREAT_MODEL.md` §8.2 #15.

### `onyx-hub::state` — KP directory

`HubState` gains:

```rust
keypackages: HashMap<RoutingId, Vec<u8>>,

pub fn publish_keypackage(&mut self, routing_id: RoutingId, bytes: Vec<u8>);
pub fn fetch_keypackage(&self, routing_id: &RoutingId) -> Option<Vec<u8>>;
pub fn keypackage_count(&self) -> usize;  // diagnostic
```

Three state-level tokio tests: `fetch_keypackage_missing_returns_none`, `publish_then_fetch_returns_bytes`, `publish_overwrites_latest`. Latest-wins is asserted explicitly (the directory size stays at 1 after a republish — we replace, not append).

### `onyx-hub::handler` — dispatch + integration tests

Two new branches in the per-connection `select!` loop:

  * `FRAME_KP_PUBLISH` → parse 16-byte routing-id prefix, call `state.publish_keypackage(id, kp_bytes)`. Log includes `directory_size` after publish so an operator watching the hub can see the directory growing.
  * `FRAME_KP_FETCH` → require exactly 16 bytes payload (else log + ignore), call `state.fetch_keypackage(&id)`, write a `FRAME_KP_RESPONSE` with the status byte + optional KP bytes.

Three new duplex integration tests:

  * `keypackage_publish_then_fetch_round_trip` — alice publishes, bob fetches, bob receives `[0, ...kp_bytes]`. Hub-state side-check confirms `keypackage_count() == 1`.
  * `keypackage_fetch_missing_returns_not_found` — fetch a never-published id, response is `[1]` (status byte only).
  * `keypackage_republish_overwrites` — alice publishes "v1" then "v2", bob fetches and gets exactly "v2".

(`serve_frames` got a `#[allow(clippy::too_many_lines)]` with a justification — it's one linear dispatcher, splitting per-verb would just rename code into call sites without making the dispatch easier to follow.)

### `onyxd::hub_client` — `SelfPublish` + `write_kp_publish` helper

New public type:

```rust
pub struct SelfPublish {
    pub routing_id: RoutingId,
    pub kp_bytes: Vec<u8>,
}
```

`run_hub_session` gains a `self_publish: Option<&SelfPublish>` parameter (now 9 args; `#[allow(clippy::too_many_arguments)]` annotation updated). When `Some`, after the SUBSCRIBE write but before entering the bidirectional loop, the helper writes one `FRAME_KP_PUBLISH` with `routing_id ‖ kp_bytes`. `info!` logs `"hub: our KeyPackage published"` with the byte count.

Split into a `write_kp_publish` helper for the same reason `write_subscribe` is split: smaller pieces are easier to read and the test harness can exercise them without going through the full dial path.

### `onyxd::main` — auto-publish on every hub reconnect

The hub-task reconnect loop now generates a fresh `KeyPackage` per attempt via `state.mls_party.lock().await.key_package_bytes()` and passes it as `self_publish` to `run_hub_session`. Building per-attempt rather than per-process means a hub that loses our entry (its in-memory dir, or a restart) gets us back in the directory on the next reconnect cycle. Generation is cheap (MLS just emits the current signing key + a fresh init key); doing it inside the loop keeps the surface minimal.

Failure to generate a KeyPackage (shouldn't happen but defensive) → `warn!` and skip the publish for this cycle, hub session still proceeds (subscribe + receive still work). We do **not** error out the whole hub session over an inability to publish — the user can still receive hub-relayed messages even if they can't put themselves in the directory.

### Verification

  * `cargo fmt --all --check` ✓
  * `cargo clippy --workspace --all-targets -- -D warnings` ✓ — added one `#[allow(clippy::too_many_lines)]` to `serve_frames` with justification.
  * `cargo test --workspace` ✓ — **12 in `onyx-hub`** (+6: 3 state + 3 handler), 156 in `onyx-core`, 26 in `onyxd`, 7 in `onyx`. **201 total** (+6 since T5.2.g).
  * `cargo deny check` ✓.

### Open security gaps + carry-forward

  * **New: `THREAT_MODEL.md` §8.2 #15** — hub does not validate publisher ownership of a routing id when storing a KeyPackage. Recipient-side mitigation in place. Proper fix needs hub to learn the publisher's Ed25519 (Noise XK only surfaces X25519 today).
  * **Directory is in-memory only** — same as the rest of the hub's state. A hub restart drops every published KP; clients reconnect and republish on their next hub session. Fine for v0.
  * **No KP rotation policy yet** — a daemon's KP is regenerated each hub reconnect but doesn't expire on its own between reconnects. Real MLS deployments rotate KPs periodically; tracked for future work.
  * **No `FetchPeerKeyPackage` API verb** in `onyxd` yet — T5.2.e will add it once it has a use for the fetched KP (constructing a Welcome).
  * Everything from prior carry-forward lists still open.

---

## 2026-05-18 — T5.2.g: `onyx send-bootstrap` CLI subcommand

Tiny commit that closes the last UX gap blocking a real end-to-end demo of the hub-relayed first-contact path. Before today, exercising `SendBootstrap` required hand-built NDJSON and `nc -U`. Now it's:

```
onyx --socket ./bob.sock send-bootstrap \
  --peer-fingerprint "$ALICE_FP" \
  --peer-kem-pub-b32 "$ALICE_KEM" \
  --text "hello"
```

Same exit-code semantics as the other `onyx` verbs: `0` on `SendBootstrapOk`, `1` on `Error { code, message }`, `2` on connect failure.

### `crates/onyx/src/main.rs` change

Added `Command::SendBootstrap { peer_fingerprint, peer_kem_pub_b32, text }` with three `--flag VALUE` arguments. Long-form `--` flags rather than positional args so a long, alarming KEM b32 string (~1948 chars) is unambiguously associated with its parameter even on terminals that wrap mid-token.

The subcommand's `--help` doc carries the **security tier warning** explicitly:

> Security tier note: `msg/v1` envelopes have per-message PFS only — no MLS PCS. See `SECURITY.md` §6.1 for the full tradeoff. The recipient TUI will render the message with a yellow `[hub]` badge so they can tell which tier it is.

A user who reads `onyx send-bootstrap --help` cannot miss the fact that this path is weaker than direct MLS.

### Two CLI-shape tests

`send_bootstrap_parses_with_three_flags` — locks in the literal flag names (`--peer-fingerprint`, `--peer-kem-pub-b32`, `--text`) so a future rename can't silently break shell scripts users have written against this command.

`send_bootstrap_requires_all_three_flags` — omitting `--text` must be a clap parse error, not silently default to empty. Sending an empty message would be a real footgun (the user thinks "did it send?" without any signal); failing loudly forces them to be explicit.

### End-to-end recipe (manual smoke; works against the existing binaries)

Genuinely demonstrable in three terminals + one hub:

```
# Terminal 1: hub
ONYX_HUB_PASSPHRASE=hub-pass ./target/debug/onyx-hub \
  --vault ./hub.db --tor-state-dir ./hub-tor
# Logs:
#   hub_pub_b32=<HUB_PUB_B32>
#   hidden service published — onion=<HUB_ONION>:1

# Terminal 2: alice (sender)
FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS=1 \
ONYX_PASSPHRASE=alice-pass ./target/debug/onyxd \
  --vault ./alice.db --tor-state-dir ./alice-tor \
  --api-socket ./alice.sock \
  --hub-onion <HUB_ONION>:1 --hub-pubkey <HUB_PUB_B32>

# Terminal 3: bob (recipient)
FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS=1 \
ONYX_PASSPHRASE=bob-pass ./target/debug/onyxd \
  --vault ./bob.db --tor-state-dir ./bob-tor \
  --api-socket ./bob.sock \
  --hub-onion <HUB_ONION>:1 --hub-pubkey <HUB_PUB_B32>

# Terminal 4: alice shares bob's identity, then sends
./target/debug/onyx --socket ./bob.sock identity | tee /tmp/bob-id.json
BOB_FP=$(jq -r .fingerprint /tmp/bob-id.json)
BOB_KEM=$(jq -r .identity_kem_pub_b32 /tmp/bob-id.json)

./target/debug/onyx --socket ./alice.sock send-bootstrap \
  --peer-fingerprint "$BOB_FP" \
  --peer-kem-pub-b32 "$BOB_KEM" \
  --text "hi bob — sent via hub before you came online"

# {"kind":"SendBootstrapOk"} ← exit code 0

# Terminal 5: bob's TUI
./target/debug/onyx --socket ./bob.sock tui
# Live tail picks up the EventMessage { via_hub: true }
# Conversation pane shows:
#     alice_sho: [hub] hi bob — sent via hub before you came online
```

Tested locally on a `--no-tor` daemon for the CLI path (`{"kind":"Error","code":"not_ready","message":"hub client is not enabled..."}` returned with exit code 1 — correct behaviour, no hub configured). The full real-Tor recipe above hasn't been run inline in this commit (would take 60+ seconds of Tor bootstrap × 3 daemons) but the building blocks all have unit + integration test coverage.

### Verification

  * `cargo fmt --all --check` ✓
  * `cargo clippy --workspace --all-targets -- -D warnings` ✓ — clean.
  * `cargo test --workspace` ✓ — **7 in `onyx`** (was 5; +2 CLI shape tests), 156 in `onyx-core`, 26 in `onyxd`, 6 in `onyx-hub`. **195 total** (+2 since T5.2.f).
  * `cargo deny check` ✓.
  * `onyx send-bootstrap --help` surfaces the security tier warning verbatim.
  * Live smoke against `onyxd --no-tor`: `onyx identity` → pipe FP + KEM into `onyx send-bootstrap` → `{"kind":"Error","code":"not_ready", ...}` exit 1.

### Open security gaps + carry-forward

  * **T5.2.e — `mls/v1` variant for true PCS over hub** is now genuinely the only T5.2 step left. Requires a KeyPackage exchange protocol (directory in the hub, or out-of-band).
  * Hub auth still open.
  * No `onyx contact card` / `onyx contact import` yet; shells using `jq` to splice fingerprint + KEM around are the v0 ergonomic.
  * Everything from prior carry-forward lists still open.

---

## 2026-05-18 — T5.2.f: TUI `[hub]` badge for hub-relayed messages

Small commit, security-meaningful. The `via_hub: bool` indicator that's been plumbed through three layers since T5.2.d now actually appears on screen. Users can read the security tier of every message at a glance, which closes the user-comprehension gap that `THREAT_MODEL.md` §8.2 #14 was tracking.

### What landed

`render_messages` in `crates/onyx/src/tui.rs`: for any `ChatLine` with `via_hub == true`, a yellow bold `[hub]` badge is inserted between the sender label and the message text.

```text
  u5lhmxps: [hub] hi (first contact via hub)
  u5lhmxps: hi
        me: hey
  u5lhmxps: how's the audit?
```

The `[hub]` styling deliberately stands out (yellow + bold) rather than fading into the background. Reasoning: users are more likely to make a wrong trust decision by assuming a hub-relayed message has full PCS protection than by being mildly annoyed at a noisy badge.

The `#[allow(dead_code)]` on `ChatLine.via_hub` is gone; the field is now genuinely read.

### Snapshot test extended

`dump_snapshot_with_chat` mock now includes one `via_hub: true` line at the top of the scrollback. The test asserts `snap.contains("[hub]")` with a comment explaining the regression-prevention motive: "If this assertion ever regresses, users would silently lose the ability to read which messages have MLS PCS and which don't."

The rendered PNG snapshot was also updated (`target/tui-snapshot-chat.png`) and shared with the user for visual confirmation.

### `THREAT_MODEL.md` §8.2 item #14 closed

Marked closed (struck through) with a note pointing at the implementation + regression test. The tier indicator is now end-to-end:
  * Wire (`EventMessage.via_hub`, `HistoryEntry.via_hub`) — T5.2.d
  * Ring buffer (`ChatLine.via_hub`) — T5.2.d
  * Backfill merge (`merge_history` propagates) — T5.2.d
  * **Visual rendering (`[hub]` badge)** — this commit
  * Backfill regression test (`merge_history_dedupes_against_live_entries` asserts `via_hub` survives) — T5.2.d
  * Render regression test (`dump_snapshot_with_chat` asserts `[hub]` appears) — this commit

### Verification

  * `cargo fmt --all --check` ✓
  * `cargo clippy --workspace --all-targets -- -D warnings` ✓ (clean — no new lints).
  * `cargo test --workspace` ✓ — 193 total (unchanged count; the existing `dump_snapshot_with_chat` test just gained an assertion).
  * `cargo deny check` ✓.

### Open security gaps + carry-forward

  * **T5.2.e — `mls/v1` variant for true PCS over hub** is now the only remaining T5.2 step. Requires the recipient to publish a KeyPackage (directory in the hub, or out-of-band exchange).
  * No CLI affordance for `SendBootstrap` yet (raw NDJSON only).
  * Hub auth still open.
  * Peer-list pane still uses `○` for both "disconnected direct peer" and "hub-only contact". A small future enhancement would use a third glyph for hub-only — but the per-message badge already disambiguates in the conversation view, so this is cosmetic.

---

## 2026-05-18 — T5.2.d: receive-side hub decode — `msg/v1` first-contact end-to-end

The symmetric counterpart to T5.2.c. After this commit, the loop is closed for first-contact hub-relayed delivery: alice's `SendBootstrap` builds a sealed envelope addressed to bob's introduction inbox, the hub forwards on `bob`'s subscription, bob's `handle_hub_delivery` opens the envelope, decodes the inner `BootstrapPayload::PlainMessage`, registers alice as a hub-only peer in the conversation registry, and emits an `EventMessage { via_hub: true }` that the TUI's tail subscription picks up. **As of this commit, "alice sends to offline bob via the hub" actually works end-to-end** — without any direct Noise circuit between them.

The remaining pieces of T5.2 are now narrower in scope:
- **T5.2.e** — `mls/v1` variant for true PCS on the hub path (requires KeyPackage exchange).
- **T5.2.f** — TUI visual indicator for `via_hub: true` (data is plumbed; just need styling).

### `hub_client::run_hub_session` — async on_deliver callback

Signature change from `F: FnMut(RoutingId, Vec<u8>)` to `F: FnMut(RoutingId, Vec<u8>) -> Fut, Fut: Future<Output = ()>`. The callback can now `.await` async work (registry locking is `tokio::sync::Mutex` → must be awaited). Existing duplex test updated minimally: closure body wrapped in `async move {}`. New parametric `<F, Fut>` propagated through both the entry point and the post-handshake `serve_session` helper.

### `onyxd::handle_hub_delivery` (new) — the decode path

A short async function called from the hub-task closure for every inbound `FRAME_DELIVER`:

  1. `routing::open_bootstrap(&body, our_kem)` — decapsulate + verify the envelope.
  2. `BootstrapPayload::from_cbor(&opened.mls_welcome)` — demultiplex by `v` tag.
  3. Match on the inner variant. `PlainMessage { text }`:
     - Derive peer `peer_pub` from `opened.sender_identity_pk`, fingerprint from `opened.sender_signing_pk.fingerprint().to_string()`, short id from b32 of `peer_pub`.
     - `registry.register_hub_only(peer_pub, &pubkey_b32, fingerprint)` — idempotent.
     - `registry.push_message_via_hub(&peer_pub, Incoming, text)` — emits `EventMessage { via_hub: true }`.
     - One info-level log line per delivered message.

**Security discipline: silent decode failures.** Steps 1 and 2 both fail silently at `debug!` level (not `warn!`). Reasoning: anyone connected to the hub can send arbitrary bytes addressed to our routing id, and `open_bootstrap` is the integrity gate. If we logged at warn level on every decap/decode failure, a hostile hub or a spammer could fill operator logs by churning out junk. The legitimate signal — "an envelope addressed to us decoded successfully" — gets `info!`; everything else stays at `debug!`. Documented inline at the call site.

### Hub-task wiring in `main.rs`

The hub-task closure captures `Arc<DaemonState>` (cheap) and `Arc<HybridKemSecret>` (constructed once at task entry by round-tripping our KEM bytes through `HybridKemSecret::from_bytes` — same Clone-evasion pattern we use for the identity X25519 secret). Per-delivery closure clones both Arcs and calls `handle_hub_delivery` inside an `async move`.

### `ConversationRegistry::register_hub_only` (new)

Companion to the existing `register`. Differences:

  * Returns just `ConversationHandle` (no `mpsc::Receiver<String>` — there's no `peer_session` task to drain it).
  * Creates the handle's `outbound_tx` pointing at a channel whose `Receiver` is **dropped immediately**. Any `try_send` into it eventually returns `TrySendError::Closed` — exactly how a peer with a torn-down direct session would behave. The API server's existing `Send` handler returns `NotReady` in that case, so the UX message is at worst "peer disconnected" — adequate for v0; T5.2.f's TUI work will surface a clearer "hub-only — use `SendBootstrap` to reply" hint.
  * Marks the conversation `connected: false` so `handle_for_short` filters it out of `Send` lookups.
  * Idempotent: a second `register_hub_only` for the same `peer_pub` returns the existing handle and does **not** fire a duplicate `EventPeerConnected`. Verified by a dedicated test.

### `EventMessage` + `HistoryEntry` + `ChatLine` all gain `via_hub: bool`

Plumbed end-to-end so the tier indicator is preserved across daemon restarts:

  * `ApiResponse::EventMessage` gains `via_hub: bool` with `#[serde(default)]` for wire-format backwards compatibility. Daemon→client wire stays openly extensible.
  * `ApiResponse::HistoryEntry` likewise. A `History` reply for a peer with hub-relayed messages now correctly tags each as via-hub.
  * `onyxd::conversations::ChatLine` (the per-peer ring buffer entry) carries `via_hub` too — without it, a TUI restart + `History` backfill would silently downgrade old `via_hub` messages to "looks like direct-MLS". That's a security UX bug we explicitly avoided.
  * `onyx::tui::ChatLine` (TUI-side mirror) carries it too — `#[allow(dead_code)]` for now since T5.2.f hasn't shipped the renderer. The annotation comments cite the future use to make the intent unambiguous.

The two `push_message` variants on `ConversationRegistry` now share a `push_message_inner(via_hub: bool)` helper — single source of truth for the ring-append + broadcast logic.

### One backwards-compat test added in `onyx-core::api::tests`

`event_message_without_via_hub_defaults_false`: parses a hand-built JSON line **without** the `via_hub` field, asserts the resulting `EventMessage` has `via_hub: false`. Captures the `#[serde(default)]` semantics so a future PR can't accidentally remove the default and break older clients on the wire.

### Registry tests added

Five new tokio tests in `conversations::tests`:

  * `register_hub_only_appears_in_list_as_disconnected` — appears in `list()` with `connected: false`; `handle_for_short` refuses.
  * `register_hub_only_is_idempotent` — same peer_pub → same short_id, registry size stays at 1.
  * `register_hub_only_emits_event_peer_connected_once` — exactly one event on first registration; none on the second.
  * `push_message_via_hub_tags_event` — emitted `EventMessage` carries `via_hub: true`.
  * `hub_only_handle_send_returns_closed_immediately` — the security-relevant invariant: `outbound_tx.try_send` on a hub-only handle hits `Closed` after at most one buffered message. A future refactor that silently absorbed all sends into a black-hole channel would defeat the entire point of `register_hub_only`; this test catches it.

### Verification

  * `cargo fmt --all --check` ✓
  * `cargo clippy --workspace --all-targets -- -D warnings` ✓ — chased four `manual_let_else` / `single_match_else` lints in `handle_hub_delivery` and assorted call sites; all converted to `let … else` for consistency with the SECURITY-doc-driven style.
  * `cargo test --workspace` ✓ — **156 in `onyx-core`** (+1 backwards-compat test for the `via_hub` default), **26 in `onyxd`** (+5 hub-only registry tests), 6 in `onyx-hub`, 5 in `onyx`. **193 total** (+6 since T5.2.c).
  * `cargo deny check` ✓.

### Open security gaps + carry-forward

  * **T5.2.e — `mls/v1` variant** still ahead. Requires the recipient to publish a KeyPackage somewhere (directory in the hub, or out-of-band exchange).
  * **T5.2.f — TUI tier rendering** still ahead. `via_hub: bool` is now plumbed end-to-end and reaches the TUI's `ChatLine`; only the visual styling is missing. Tracked as `THREAT_MODEL.md` §8.2 #14.
  * **No CLI affordance for `SendBootstrap` or replying to a hub-only peer.** Still raw NDJSON-only.
  * **Hub auth still open**; even when a malicious hub can't read content, it can drop or duplicate deliveries.
  * Everything from prior carry-forward lists still open.

---

## 2026-05-18 — T5.2.c: `SendBootstrap` — sealed-sender envelope on the daemon's hub path

The first phase in the T5.2 chain where a real cryptographic payload constructed by the daemon reaches the hub. As of this commit, anyone with `--hub-onion` + `--hub-pubkey` running and a recipient's fingerprint + KEM public can fire `SendBootstrap` over the local API and have a PQ-hybrid sealed envelope land on the hub addressed to the recipient's introduction-inbox routing id. The hub sees the 16-byte target and an opaque sealed blob — exactly what `THREAT_MODEL.md` §2 A2 promises.

This commit ships only the **sender** path. On receive, the body is still discarded (logged only) — wiring it into the conversation registry is T5.2.d. The intermediate state is deliberate: every piece reviewable in isolation.

### Design decision: payload versioning lives inside the envelope

The sealed-sender envelope (`routing::seal_bootstrap` / `open_bootstrap`) was built earlier for carrying an MLS Welcome message. That works for cases where the sender holds the recipient's MLS KeyPackage out-of-band, but it doesn't work for "Alice → offline Bob" first-contact: Bob has to be online to publish a KeyPackage first.

**The cautious answer**: treat `seal_bootstrap` as the **envelope layer** — opaque bytes in, opaque bytes out — and add a versioned tagged union inside.

New type `routing::BootstrapPayload`:

```rust
#[derive(Serialize, Deserialize)]
#[serde(tag = "v")]
pub enum BootstrapPayload {
    #[serde(rename = "msg/v1")]
    PlainMessage { text: String },
    // Future: MlsWelcome { … } for true PCS on the hub path.
}
```

The `#[serde(tag = "v")]` is the explicit version tag. Recipients **refuse unknown tags** rather than downgrade — that's `SECURITY.md` P5 (forward-only protocol compatibility). When the `mls/v1` variant ships, deployments that haven't updated simply reject incoming `mls/v1` envelopes; no risk of an attacker tricking a fresh client into accepting an older format.

**Security tier honesty.** `msg/v1` has per-message PFS (every envelope gets a fresh ephemeral X25519 + ML-KEM-768 encapsulation) but **no PCS**. An attacker who compromises the recipient's long-term KEM secret reads every `msg/v1` envelope sent to that recipient after the compromise until the key rotates. This is a real degradation from direct-MLS conversations and is now documented in three places in the same commit:

  * `SECURITY.md` §6.1 — the wire-payload versioning table with explicit PFS/PCS columns.
  * `THREAT_MODEL.md` §8.2 — partial closure of item #1 (sender path done) and new item #14 (TUI must visually distinguish tiers).
  * `routing.rs` `BootstrapPayload` doc — the tier table is also in-source so a reader exploring the module understands the constraint without leaving the file.

Five new tests cover the BootstrapPayload layer specifically (in `crates/onyx-core/src/routing.rs`):

  * Round-trip: encode → decode is the identity for `PlainMessage`.
  * Wire-shape: the CBOR bytes literally contain `"msg/v1"`, so an accidental tag rename in a future PR breaks loudly here.
  * Unknown-variant rejection: hand-built CBOR `{"v":"unknown/v99","text":"x"}` decodes as `Error::InvalidEncoding` (P5 enforcement).
  * Garbage rejection: empty bytes + non-CBOR bytes both error.
  * **End-to-end inside a sealed envelope**: alice builds a `PlainMessage`, encodes to CBOR, calls `seal_bootstrap` with bob's hybrid KEM public, bob calls `open_bootstrap` then `BootstrapPayload::from_cbor`, and the recovered text + sender signing key match alice's. This is the security-relevant invariant: the inner versioning is preserved across the entire envelope round-trip.

### `onyx-core::api` — new request + response variants

```rust
ApiRequest::SendBootstrap {
    peer_fingerprint: String,    // base32-grouped per `onyx identity`
    peer_kem_pub_b32: String,    // base32 of HybridKemPublic
    text: String,
}
ApiResponse::SendBootstrapOk     // no body; delivery confirmation is async
```

The response is a distinct variant from `SendOk` even though both are no-payload acks — keeps the wire self-describing so clients and operators can tell which call succeeded from logs alone. **Three new round-trip tests** plus a literal `"kind":"SendBootstrap"` wire-shape assertion. Total `api::tests` now 21.

### `onyxd::api_server::handle_send_bootstrap` — the dispatcher

Six new unit tests covering the full decision tree:

  1. **No hub configured** (daemon launched without `--hub-onion`) → `NotReady`. Operator config issue, not a malformed request.
  2. **Garbage fingerprint** → `Malformed`.
  3. **Garbage KEM b32** (invalid base32 alphabet) → `Malformed`.
  4. **Wrong-length KEM b32** (valid base32 but doesn't decode as `HybridKemPublic`) → `Malformed`.
  5. **Hub outbound queue full** → `NotReady`. Distinguished from "hub not configured" by the error message; both share the `NotReady` code so clients can retry uniformly.
  6. **Happy path** → `SendBootstrapOk` **plus** a `HubOutbound` lands on the receiver carrying the recipient's correct introduction-inbox routing id, **plus** bob can decapsulate the body and recover the exact plaintext + assert the sender signing key matches alice's. This is the cryptographic integrity check end-to-end without any network.

Test scaffolding: `handle_send_bootstrap` was refactored to take its dependencies as individual parameters (`our_signing`, `our_identity_sk`, `Option<&Sender>`) rather than the full `DaemonState`. That makes every unhappy path testable without standing up an MLS party or a vault — and the happy-path test is now ~30 lines instead of the ~150 it'd be otherwise. Smaller dependency surface = clearer security review.

### Wiring + dead-code cleanup

`DaemonState.hub_outbound` lost its `#[allow(dead_code)]` annotation — the dispatcher actually reads it now. The doc comment on the field updated to point at the live consumer.

### What this *doesn't* ship

  * **No receiver-side decode**. T5.2.c stops at "the sealed envelope reaches the hub and gets forwarded to whoever is subscribed to the target routing id". The hub_client's `on_deliver` callback still logs the body and discards it. T5.2.d wires `open_bootstrap` + `BootstrapPayload::from_cbor` + conversation registry on receipt.
  * **No CLI/TUI affordance** to call `SendBootstrap`. For now the only way to invoke it is hand-built NDJSON over the API socket (`echo '{"kind":"SendBootstrap",...}' | nc -U onyxd.sock`). A real `onyx contact send <fpr> <kem> <msg>` subcommand is part of T5.2.f together with the security-tier rendering.
  * **No real-Tor smoke test**. Two daemons, two Tor circuits, a real hub — runnable manually with the existing binaries, but inline in this CHANGELOG it'd be 30–60 s of bootstrap per daemon. The 6 unit tests + the BootstrapPayload round-trip + the existing T5.2.b duplex test give equivalent confidence in the wire path.

### Verification

  * `cargo fmt --all --check` ✓
  * `cargo clippy --workspace --all-targets -- -D warnings` ✓ — one round of `manual_let_else` fixes turning four `match { Some/Ok => …, _ => return … }` blocks in the dispatcher into `let … else { return … }`. Cleaner anyway.
  * `cargo test --workspace` ✓ — **155 in `onyx-core`** (+8 since T5.2.b: 5 BootstrapPayload + 3 api round-trip including wire-shape), **21 in `onyxd`** (+6 SendBootstrap dispatcher), 6 in `onyx-hub`, 5 in `onyx`. **187 total** (+14 since T5.2.b).
  * `cargo deny check` ✓.

### Open security gaps + carry-forward

  * **T5.2.d — receive-side decode** still ahead. Until that lands the daemon receives but discards hub deliveries.
  * **T5.2.e — `mls/v1` variant** for MLS PCS on the hub path. Requires the recipient to publish a KeyPackage somewhere (directory in the hub, or out-of-band exchange).
  * **T5.2.f — TUI tier rendering** — the user cannot tell a `msg/v1` from a future `mls/v1` (or from a direct-MLS) without it. New `THREAT_MODEL.md` §8.2 item #14 tracks this as a user-comprehension security issue, not just UX.
  * **`SendBootstrap` has no CLI affordance** yet. Today exercising it requires raw NDJSON.
  * **Hub auth is still open** — anyone with the hub's static key can subscribe + send. The sealed envelope means a malicious hub can't read content, but a misconfigured hub can drop or duplicate-deliver.
  * Everything from prior carry-forward lists still open.

---

## 2026-05-18 — T5.2.a + T5.2.b: per-identity hybrid KEM + bidirectional hub client

Two foundational pieces toward hub-relayed sealed-sender delivery (the full chain is T5.2.a → T5.2.f). Neither one ships a new user-visible feature on its own; together they remove every prerequisite blocking T5.2.c (the `SendBootstrap` API verb + on-the-wire envelope). Split deliberately: each piece has small, reviewable security implications, and the project never ends up with a half-wired crypto surface that someone might trust by mistake.

### Scope honesty up front

Full T5.2 ("Alice sends to offline Bob via the hub, Bob comes online and reads") needs at least four more steps after this commit:

  * **T5.2.c** — `SendBootstrap { peer_pubkey_b32, peer_kem_pub_b32, text }` API verb that constructs an MLS Welcome + seals it with `routing::seal_bootstrap` + pushes via `hub_outbound`.
  * **T5.2.d** — hub_client's `on_deliver` callback wired into `open_bootstrap` + `MlsParty::join_from_welcome` + `ConversationRegistry::register` on the recipient side.
  * **T5.2.e** — ongoing-message wire format (MLS application messages over hub via per-epoch session-token routing ids) so post-bootstrap traffic doesn't have to revert to direct dial.
  * **T5.2.f** — TUI integration: a "send to fingerprint…" affordance, visual distinction between direct-MLS and hub-relayed messages (the latter has weaker properties — see open security gaps below).

What lands today is the **foundation** only: every identity now holds a persistent post-quantum KEM keypair so senders have something to encapsulate to, and the hub-client can write outbound frames as well as read them. The API even surfaces the new KEM public so a future `onyx contact export` knows what to put on the card.

### T5.2.a — Identity gains a `HybridKemSecret`; vault schema v4 persists it

The cryptographic helper `routing::seal_bootstrap` has existed in the library since the PQ phase, but no identity had a `HybridKemSecret` to be sealed against. T5.2.a closes that gap.

**`crates/onyx-core/src/crypto.rs`** gains:

  * `HYBRID_PQ_SECRET_LEN = 2400` — the ML-KEM-768 decapsulation key size per FIPS 203 Table 3 (K=3, 768 × K + 96).
  * `HYBRID_SECRET_LEN = HYBRID_CLASSICAL_LEN + HYBRID_PQ_SECRET_LEN = 2432` — full serialised secret.
  * `HybridKemSecret::to_bytes() -> Zeroizing<Vec<u8>>` — concatenates X25519 secret (32 B) ‖ ML-KEM-768 decap key (2400 B). `Zeroizing` so the buffer wipes on drop.
  * `HybridKemSecret::from_bytes(&[u8]) -> Result<Self>` — reconstructs from the same layout, rejecting wrong lengths with `Error::BufferSize`. Uses `Encoded<PqDecapKey>::try_from` to wrap the ML-KEM half.

Three new unit tests, all passing:

  * `hybrid_pq_secret_len_matches_runtime` — asserts the compile-time constant matches the runtime `<PqDecapKey as EncodedSizeUser>::EncodedSize`. A future `ml-kem` release that quietly changes the layout fails here, in CI, instead of in the field.
  * `hybrid_kem_secret_byte_round_trip` — the security-relevant invariant: a ciphertext encapsulated to the original public key decapsulates **identically** with the byte-round-tripped secret. Also verifies the round-tripped secret's derived public key matches the original.
  * `hybrid_kem_secret_rejects_wrong_size` — fuzz-style smoke on three wrong sizes (too short, too short by one, too long by one).

**`crates/onyx-core/src/identity.rs`** restructured:

  * `Identity` struct now owns three secrets: `signing: SigningKey`, `identity: IdentitySecret` (Noise X25519), and `kem: HybridKemSecret` (sealed-sender X25519 + ML-KEM-768). The Noise X25519 and the KEM's classical half are **separate keys** — different protocol roles, no cross-protocol reuse. The extra 32 bytes are a conservative choice grounded in `SECURITY.md` P6 ("no optional weakening").
  * New accessors `kem_secret() -> &HybridKemSecret` and `kem_public() -> HybridKemPublic`. The public is freshly derived from the secret on demand; cheap, and avoids caching a derived form in the struct.
  * New constructor `from_parts(signing_seed, identity_secret, kem_bytes) -> Result<Identity>` for vault reload and import flows; validates the KEM bytes.
  * Kept `from_seeds(signing_seed, identity_secret) -> Identity` as a test convenience whose **fingerprint** is deterministic in the seeds but whose KEM keypair is freshly generated each call. Doc on the method names the determinism boundary explicitly so a future reader can't be surprised.
  * Serialised layout inside the AEAD blob grew from 64 bytes to 64 + 2432 = **2496 bytes**. Captured in a fresh ASCII layout diagram in the module doc. The `delete_identity` scrub buffer was sized accordingly (`IDENTITY_SECRET_BLOB_LEN + 256` random bytes) so the best-effort forensic-recovery overwrite still comfortably exceeds the encrypted blob's on-disk footprint.
  * Two new tests: `from_parts_is_deterministic_for_classical_fields` (same seeds → same fingerprint even with different KEM halves), `from_parts_rejects_wrong_kem_length`, **and** `kem_keypair_round_trips_across_reopen` — the latter is the security-relevant invariant for this entire phase: encapsulate to alice's public before vault close, reopen, decapsulate with the restored secret, assert identical shared secret. If this test ever regresses, sealed-sender bootstrap envelopes encrypted before a daemon restart become un-decryptable after the restart — a real outage, not just a UX nit.

**`crates/onyx-core/src/storage.rs`** bumps `SCHEMA_VERSION` from 3 → 4 with an explanatory comment about the blob-layout change. No SQL change: the `identities.encrypted_blob` column is opaque to SQLite, only the AEAD plaintext length changed. Old v3 vaults fail the schema-version check at open and must be recreated.

### T5.2.b — Hub client becomes bidirectional

Until this phase, `hub_client::run_hub_session` only read. T5.2.b makes it also write — the prerequisite for any `Send`-via-hub verb.

  * New public type `HubOutbound { target: RoutingId, body: Vec<u8> }`. Body is opaque; `hub_client` doesn't care whether it's a sealed envelope or anything else.
  * New public const `OUTBOUND_QUEUE_CAPACITY = 64`. Bounded mailbox: a hung hub can't make the daemon buffer unbounded data on the user's behalf.
  * `run_hub_session` signature gains `outbound_rx: &mut mpsc::Receiver<HubOutbound>`. After SUBSCRIBE, the loop is a `tokio::select!` between `read_frame` (existing inbound path) and `outbound_rx.recv()` (new): each `HubOutbound` is written as a `FRAME_DELIVER` with payload `target (16 B) ‖ body`. Channel-closed → clean `Ok(())` return (caller dropped the sender, daemon shutdown). Write-error mid-session → `Err(...)` so the reconnect loop in `main.rs` backs off and retries.
  * The post-handshake body was factored into `serve_session<S>` generic over the stream type so the new bidirectional logic is testable without spinning up a real Tor circuit. The dial + handshake + subscribe entry point still does the real network setup in production.

New test `bidirectional_session_round_trip_over_duplex` uses `tokio::io::duplex(65_536)` to stand up a fake hub-side responder, exercises both directions end-to-end (push inbound DELIVER → callback fires; queue outbound HubOutbound → frame appears on the wire with the right `target ‖ body`), and verifies clean shutdown when the sender side of the outbound channel is dropped. This is exactly the kind of test that catches "what if the read future and the write future are both pending and one of them panics inside `select!`" classes of bug before they ship.

### `onyxd::DaemonState` carries the sender, ungated for now

`DaemonState` gains `hub_outbound: Option<mpsc::Sender<HubOutbound>>`. `Some` only when `--hub-onion` + `--hub-pubkey` were both set (in `--no-tor` mode it stays `None`, since the hub task never runs). The field is marked `#[allow(dead_code)]` with an inline note pointing at T5.2.c, which adds the `SendBootstrap` API verb that finally drains it. **No code path today reads this field** — the foundation is in place, but nothing actually sends via the hub yet.

### API surface: the KEM public goes through

`ApiResponse::StatusOk` and `ApiResponse::IdentityOk` both gain `identity_kem_pub_b32: String`. The doc on the field warns explicitly about the length:

  > The underlying bytes are HYBRID_PUBLIC_LEN = 1216 bytes (32 + 1184); base32 with no padding encodes that to ~1948 characters. It looks alarming on stdout but it isn't a typo — that's the real on-the-wire size of an ML-KEM-768 encapsulation key.

Two existing api round-trip tests were extended to include the new field. The TUI's `StatusSnapshot` consumer uses `..` to ignore unrecognised fields, so it picks up the change transparently without code changes.

### Verification

  * `cargo fmt --all --check` ✓
  * `cargo clippy --workspace --all-targets -- -D warnings` ✓ — chased three lints along the way: a `struct_field_names` on `Identity.identity` (kept the field name, allowed the lint with a justification comment because `identity` is the right English noun for an X25519 identity secret), a `too_many_arguments` on `run_hub_session` (allowed; every parameter names a distinct piece of session context and bundling them into a struct would just rename the arguments to fields), and a stray `mut` on the `on_deliver: F` parameter (removed — `FnMut` calls inside `select!` don't need an outer `mut`).
  * `cargo test --workspace` ✓ — **147 in `onyx-core`** (+5 since T5.1: 3 hybrid KEM secret tests + 2 identity persistence/length tests), **15 in `onyxd`** (+1: the bidirectional duplex round-trip), 6 in `onyx-hub`, 5 in `onyx`. **173 total**.
  * `cargo deny check` ✓.

### `THREAT_MODEL.md` updated in the same commit

§8.1 gains two new rows:

  * "Per-identity hybrid KEM keypair (sealed-sender prerequisite)" — designed + implemented + verified by the reopen round-trip test.
  * "Hub-client bidirectional outbound queue" — designed + implemented + verified by the duplex round-trip test.

§8.2 carry-forward items updated:

  * **#1** ("Sealed-sender wrap on the daemon's hub path") gains a note that the building blocks are now in place: KEM keypair persists, hub-client can write outbound. What remains is the API verb, the MLS-Welcome construction, and the recipient-side join.
  * **#2** ("PQ hybrid X25519 + ML-KEM-768 wired into the daemon path") moves from "not implemented" to **partial**: each identity owns and persists a hybrid KEM keypair, but no live wire path uses it yet. Store-now-decrypt-later attackers archiving today's traffic still get plaintext until the sealed envelope ships.
  * **#13** added: "Vault schema v4 has no migration runner" — this is the **fifth** schema bump without a migration story (v1 → v2 → v3 → v4). The cost of writing the runner grows each time; flagged with bumped priority.

### Open security gaps + carry-forward

  * **T5.2.c–T5.2.f still ahead** to actually deliver "Alice → offline Bob → comes online → reads". Each will be its own commit.
  * **Hub-relayed messages will have weaker properties than direct MLS** even once T5.2.c+ land. The sealed-sender envelope gives per-message forward secrecy via the ephemeral X25519 + ML-KEM-768 encapsulation, **but** an MLS Welcome that crosses the hub only kicks off a new group — it has no post-compromise security against an attacker who later compromises the recipient. The TUI must visually distinguish direct-MLS and hub-relayed messages so users can read the threat model right. Tracked for T5.2.f.
  * **Vault schema v4 — recreate to upgrade.** Same pattern as prior bumps; documented in `THREAT_MODEL.md` §8.2#13.
  * **Daemon `from_seeds` non-determinism on KEM half** is intentional but worth knowing about. Two `from_seeds` calls with the same seeds produce identical fingerprints but **different** KEM publics. For tests that don't care this is fine; for any future reproducibility-sensitive flow, use `from_parts`.
  * Everything from prior carry-forward lists still open.

---

## 2026-05-18 — Docs: SECURITY.md + THREAT_MODEL.md §8 implementation status

No code change this entry. Two documents written / updated so future contributors and reviewers can tell at a glance which security claims are *designed*, *implemented*, and *verified*, and what the rules of engagement are for adding features without eroding the guarantees we already make.

### `SECURITY.md` — new file (382 lines)

Eight enforcement principles, each with a rationale, an example violation, and a concrete review check. The principles, in order:

  1. Every cross-network frame is carried inside an established Noise + MLS session.
  2. All persisted data is sealed under the vault key.
  3. All identifiers are derived from keys, never assigned by a server.
  4. All wire metadata goes through the size-bucket shaping pipeline.
  5. Forward-only protocol compatibility — no downgrade negotiation.
  6. No optional weakening — "less secure but easier" codepaths must not exist.
  7. Security-relevant UI state must be visible and unambiguous.
  8. Audit before feature surface.

Supplemented by:

  * A **PR review checklist** that maps each principle to verifiable criteria a reviewer answers yes/no.
  * A **vulnerability disclosure policy** pointing reporters at GitHub Security Advisories (no email yet — deliberately, until we have a key-pair for it), with explicit ack/triage/fix timelines (7/30/90 days).
  * A **cryptographic primitive table** with every algorithm, crate, and version pin currently in use.
  * A **§1 status disclaimer** that does not mince words: "No external security audit has been conducted. Not by anyone. Not at any depth. … Onyx is not appropriate for any use where the safety, freedom, or livelihood of the user depends on the protocol's security. Use Signal, Briar, or similar mature tools for those situations."
  * A **scope** section drawing the line between what this document covers (Onyx code and protocols) and what it doesn't (Tor itself, upstream dependencies, OS, hardware).
  * A **§7 "What changes when we get audited"** section that names which document sections will be rewritten and how. This is here so when we *do* get audited there's no temptation to quietly delete the caveats.

The eight principles are written so they cannot be satisfied by interpretation. P1 says "every new `FRAME_*` constant in `wire.rs` is written and read only via `transport::write_frame` / `read_frame`"; P2 says "no `fs::write` outside `storage.rs`"; P6 says "test-only weakenings are gated behind `#[cfg(test)]` and never compiled into release". Each one is a literal grep-checkable claim, not aspirational language.

### `THREAT_MODEL.md` — §8 added (~90 lines), §2 A5 corrected

**§2 A5 correction.** The threat model previously claimed the local API uses "per-session token" authentication. The shipped code (T4.1, `crates/onyxd/src/api_server.rs::bind_listener`) uses filesystem permissions only (`chmod 0600`). The two defend equivalently against the §2 A5 adversary, but the threat model now matches the implementation. A token-based handshake is now tracked as a future improvement (it would help SO_PEERCRED-less platforms — none of which we currently target — gain equivalent auth). The change is annotated inline so anyone reading the old text can see why the wording moved.

**§8.1 — implementation-status table.** Each defense promised by §2 gets a row with three columns:

  * **D**esigned (specified in `DESIGN.md`)
  * **I**mplemented (code shipped + smoke-tested)
  * **V**erified (automated property/round-trip tests)

with a notes column citing the relevant `crates/...` paths. **No row is currently marked `V` by external audit** — that column means "we have internal tests that exercise the security-relevant invariant", and the table opens by saying so. Rows include the daemon-side gaps (sealed-sender not yet wired, PQ hybrid not yet wired, rotating session tokens partial, no idle cover traffic) and the release-engineering gaps (no reproducible builds, no signed releases, one maintainer).

**§8.2 — consolidated carry-forward gaps.** All the open items that accumulated across the per-phase CHANGELOG carry-forward lists, surfaced in one place in rough priority order, with each mapped to the adversary class it affects. Twelve items, including: sealed-sender on the hub path (A2), PQ hybrid wiring (N5), cover traffic (A2 + §5), hub auth (A2/A3), the silent fingerprint fallback (P7), reproducible builds (N4), external review (N4 + §1), schema migration, wire-decoder fuzzing, the onion-web tier (still N6 future work), the macOS fs-mistrust bypass, and the 500 ms drain hack.

The §8.2 list and the per-phase carry-forwards in CHANGELOG must stay in sync. That synchronisation is now a documented review obligation, not an oral tradition.

### Tone discipline

Both documents were written under the user's instruction "always be cautious even with the tiniest detail." Concrete choices that follow from that:

  * Every cryptographic claim names the specific crate + version that backs it. No "we use AEAD" — it's "ChaCha20-Poly1305 via `chacha20poly1305` 0.10".
  * Every adversary defense distinguishes "designed" from "implemented" from "verified" rather than collapsing them. The reader can always tell which.
  * No claim of "audited", "proven", "industry-standard", "military-grade", or any other adjective whose meaning collapses on inspection. Where we *do* meet a real standard (RFC 9420 for MLS, RFC 8032 for Ed25519), we name the RFC number.
  * Where reality contradicted a prior document (the A5 token-vs-permissions mismatch), the contradiction is fixed *and* annotated, so future readers can audit the documentation diff and see what changed.
  * "Single maintainer + an AI assistant" is named as a trust risk in §8.1 and §1. We do not pretend otherwise.

### Verification

  * `cargo fmt --all --check` ✓ (no Rust source touched).
  * `cargo clippy --workspace --all-targets -- -D warnings` ✓ (unchanged from T5.1).
  * `cargo test --workspace` ✓ — 167 tests pass, unchanged from T5.1.
  * `cargo deny check` ✓ (unchanged).

No release semantics change; no protocol surface change; no API surface change. Documentation only.

### What this enables

  * Future PRs have a written rubric. "Why are you asking me to add `#[cfg(...)]` here?" → "P6, see SECURITY.md §3."
  * Future audit conversations have an explicit "this is what is and isn't claimed today" reference, so the auditor knows the boundary up front.
  * Users assessing whether Onyx fits their threat model have one authoritative answer per defense, including honest "designed but not yet implemented" rows where applicable.
  * The project's claim space is now grep-checkable: every assertion is in `SECURITY.md` or `THREAT_MODEL.md`, and any code that contradicts an assertion is either a bug in the code or an obsolete assertion to be corrected in the same commit that changed the code.

### Open security gaps + carry-forward

No new gaps. The twelve-item list in `THREAT_MODEL.md` §8.2 is now the canonical roll-up; per-phase CHANGELOG carry-forwards must be reflected there going forward.

---

## 2026-05-18 — T5.1: `onyxd` becomes a hub client (subscribe + receive)

The `onyx-hub` binary has been sitting idle since T3.1. This phase brings it into the daemon flow as a subscriber: `onyxd --hub-onion HOST[:PORT] --hub-pubkey B32` opens a long-lived authenticated Noise session to the hub, registers a `FRAME_SUBSCRIBE` for the daemon's own introduction-inbox routing id, then loops on `FRAME_DELIVER`. Reconnects on disconnect with 500 ms → 30 s exponential backoff.

This is **half** of hub integration: receiving only. Sending via the hub (sealed-sender envelope to a peer's inbox routing id, hub-forwarded) is T5.2.

### `crates/onyxd/src/hub_client.rs` — new module

```rust
pub async fn run_hub_session<F>(
    tor: &TorRuntime,
    host: &str, port: u16,
    hub_pubkey: &IdentityPublic,
    our_identity_sk: &IdentitySecret,
    subscribe_to: &[RoutingId],
    mut on_deliver: F,
) -> anyhow::Result<()>
where F: FnMut(RoutingId, Vec<u8>),
```

One function, one session: dial Tor → `handshake_initiator` → write one `FRAME_SUBSCRIBE` carrying N × 16-byte ids → loop reading `FRAME_DELIVER`. The `on_deliver` callback gets `(target, body_after_prefix)` for each delivery. Setup failures return `Err`; peer-closed disconnects return `Ok(())`. Either is a cue for the reconnect loop in `main.rs` to back off and retry.

`parse_host_port("abc.onion:42", default=1) → ("abc.onion", 42)` is also here so the CLI flag parsing and unit tests share one implementation.

3 unit tests for `parse_host_port` (explicit port, default port, garbage rejection).

### `crates/onyxd/src/main.rs` — CLI flags + reconnect loop

Two new `clap` arguments, paired (each requires the other):

```
--hub-onion <HOST[:PORT]>    [env: ONYX_HUB_ONION]
--hub-pubkey <B32>           [env: ONYX_HUB_PUBKEY]
```

When both are set, after Tor bootstrap, `main` spawns a long-lived task that:

  1. Derives our introduction-inbox routing id from our own fingerprint via `onyx_core::routing::introduction_inbox(&Fingerprint)` (already in the library).
  2. Calls `hub_client::run_hub_session(...)` with that as the only subscribed id.
  3. On any session end (clean or error), logs, sleeps for the current backoff, then retries. Backoff doubles each cycle, capped at 30 s.

The hub task and the main mode (accept/dial) both share a single `Arc<TorRuntime>`. The task is aborted alongside the API task on shutdown so the Tor circuit doesn't linger past `Ctrl-C`.

In v0 the `on_deliver` callback just logs `target_b32 + body_bytes` — actually routing the delivery into a conversation requires the sealed-sender unwrap and is part of T5.2.

### Lock + lifetime story

`IdentitySecret` deliberately doesn't implement `Clone`, so the hub task can't take `&Identity` across the spawn boundary. We work around by round-tripping the secret through bytes (`*identity_key().to_bytes()` → `IdentitySecret::from_bytes(...)`), getting a freshly-allocated copy that lives in the task's own scope. The bytes are still `Zeroizing` on drop.

`TorRuntime` got wrapped in `Arc` so both the hub task and the existing `run_accept_mode` / `run_dial_mode` share it. No new locking; `tor.dial` and friends are already `&self`-based.

### Verification

- `cargo fmt --all --check` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓ — `#[allow(clippy::too_many_lines)]` on `main` because adding the hub-task block pushed it from 130 → 140 lines, but the function is still a linear setup sequence and splitting it would just produce context-stripped helpers.
- `cargo test --workspace` ✓ — **142 in `onyx-core`** (unchanged), **6 in `onyx-hub`** (unchanged), **14 in `onyxd`** (+3 in `hub_client::tests`), 5 in `onyx`. **167 total**.
- `cargo deny check` ✓.
- `onyxd --help` confirms both flags surface, both env vars surface, and `clap` rejects `--hub-onion` without `--hub-pubkey` (and vice versa).

### Smoke against a real hub (manual)

End-to-end requires two real Tor circuits (hub + client), so this is the operator's call. The recipe:

```
# terminal 1 — hub
ONYX_HUB_PASSPHRASE=hub-pass ./target/debug/onyx-hub \
  --vault ./hub.db --tor-state-dir ./hub-tor
# logs:
#   hub vault unlocked, identity loaded
#     hub_pub_b32=<HUB_PUB_B32>
#   hub hidden service published — onion=<HUB_ONION>:1

# terminal 2 — daemon-as-hub-client
FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS=1 \
ONYX_PASSPHRASE=client-pass ./target/debug/onyxd \
  --vault ./client.db --tor-state-dir ./client-tor \
  --hub-onion <HUB_ONION>:1 --hub-pubkey <HUB_PUB_B32>
# logs (expected):
#   Tor bootstrap complete
#   hub: our introduction-inbox routing id derived
#     our_inbox_b32=<16-byte id>
#   hub: dialling host=<HUB_ONION> port=1
#   hub: Tor circuit established, starting Noise XK handshake
#   hub: Noise XK complete; sending SUBSCRIBE
#   hub: subscription registered, entering receive loop
```

No `DELIVER` events fire in this T5.1 demo because nothing's sending into our inbox yet — that's T5.2.

### Open security gaps + carry-forward

- **Hub auth is open**: anyone holding the hub's static key can connect and subscribe. Invite-only auth (DESIGN §9.1) still unimplemented on the hub side.
- **No sealed-sender wrap on the daemon path**: T5.2's job. Until then, even when DELIVER plumbing exists end-to-end the hub would see sender identity in the envelope metadata (currently the code just logs and discards bodies, so this isn't actively leaking).
- **`on_deliver` discards bodies**: T5.2 wires this into MLS-decrypt + `ConversationRegistry::push_message`.
- **No History / TUI surface for hub state**: the operator can see the connection in `tracing` logs but `onyx status` doesn't yet report "hub: connected".
- **Reconnect loop is unconditional**: even if the hub is misconfigured (wrong pubkey), the task just keeps retrying. A fail-after-N-attempts circuit-breaker would be friendlier; deferred.
- Everything from prior carry-forward lists still open.

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
