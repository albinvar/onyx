# Onyx — Reliable Delivery & Scale (design)

**Status:** design / pre-implementation. No code yet — this document is the
architecture to review before building.
**Scope:** how offline messages are delivered today, the holes (silent loss,
N× storage multiplier), and a privacy-first design that converts *silent loss*
into *eventual delivery or a visible failure* while cutting the storage
multiplier — without handing anyone a new activity-timing oracle.

Companion docs: `ANONYMITY.md` (threat model), `FEDERATION.md` (hub gossip),
`DESIGN.md` §5.5 (routing identifiers).

---

## 1. How delivery works today (verified in code)

When you message an offline peer, the daemon **fans the sealed envelope out to
every hub it is currently connected to** — not one
(`api_server.rs`: `for (idx, hub_outbound) in state.hub_outbounds.iter()`).
The recipient, on coming online, subscribes to its routing-id on all *its*
hubs and drains from whichever has a copy; the per-recipient replay guard
(4096-entry FIFO seen-set, persisted every 60 s) dedups, so receiving the same
message from several hubs is harmless. Hub queues are persistent SQLite, so a
hub *restart* loses nothing.

**So durability today = "the sender copied it to several hubs," not "the hubs
guarantee delivery."** Redundancy comes entirely from sender-side fan-out; hubs
do **not** protect each other (federation gossip propagates only KeyPackages —
the *who-is-reachable* directory — never message queues).

### 1.1 The silent-loss holes

A message is lost **with no notice to the sender** if:

1. **Only one shared live hub, and it loses its disk** before pickup. (Restart
   is fine; disk loss is not.)
2. **Hub-set mismatch.** Fan-out targets the *sender's* hubs `{A,B,C}`; if the
   recipient subscribes on `{D,E,F}` the message sits in queues they never
   check — gone, though no hub crashed.
3. **No end-to-end ACK.** The hub acks *"I queued it,"* never *"the recipient
   got it."* There is no app-layer receipt back to the sender (verified: none).
   So 1 and 2 are **undetectable** to the sender, with no resend.
4. **Eviction under load.** At the global 256 MiB cap (`MAX_TOTAL_QUEUED_BYTES`)
   the H-1 fair-eviction drops the largest queue's oldest entries — a pending
   message can be evicted, silently.
5. **TTL / GC.** Offline queues expire; if the recipient doesn't pick up in
   time, the message is purged.

### 1.2 The scale holes

- **N× storage multiplier.** Every message is stored once per *sender's* hub
  (a small constant 3–10, **not** network size — fan-out does not grow with the
  number of hubs in existence). Bounded, but wasteful, and it interacts badly
  with eviction (#4) as hubs get busy.
- **Uneven hot-spots.** Users pick hubs by hand; there is no
  DHT/consistent-hashing assignment, so popular hubs get hammered while others
  idle.
- **Per-hub global mutex** serializes hub state → a single hub doesn't scale
  across cores (vertical ceiling).
- **Tor connection cost.** Each onion rendezvous is expensive; a hub's
  concurrent-client ceiling is far below a clearnet server's.

**Failure mode at scale is not a crash — it's quiet unreliability:** busier
hubs evict more, and with no ACK the sender never learns. Graceful shedding,
but shedding = drops.

---

## 2. Goals & non-goals

**Goals**
- G1. **No silent loss.** Every send ends in *delivered* or a *loud, visible
  failure* to the sender.
- G2. **Cut the storage multiplier** — deliver to a small quorum, not all hubs.
- G3. **Fix hub-set mismatch** — fan out where the recipient actually listens.
- G4. **Cost nothing extra to anonymity** — see §4.

**Non-goals (deliberate)**
- N1. **No read receipts** (message *opened* by the human). Pure activity leak,
  zero reliability value. Never build it.
- N2. **No synchronous delivery guarantee** — Onyx is store-and-forward over
  Tor; "eventual delivery or visible failure," not "instant ack."
- N3. **No hub-to-hub queue replication** in v1 (more metadata surface + cost;
  the receipt approach gets ~all the reliability with less risk — see §6).

---

## 3. Architecture

Four components. The first three deliver reliability (G1); the fourth delivers
scale (G2/G3).

### 3.1 End-to-end delivery receipts

A new sealed app-message variant the **recipient's daemon** emits automatically
on successful decrypt:

```
RoomAppMessage::DeliveryReceipt { msg_id: [u8; 16] }   // rooms
DmAppMessage::DeliveryReceipt   { msg_id: [u8; 16] }   // 1:1 DMs
```

- `msg_id` is a random 16-byte id the **sender** put *inside* the sealed
  envelope of the original message (hubs never see it; it is not the routing-id).
- The receipt rides the **existing MLS session** (or DM Noise/MLS session), so
  it is end-to-end encrypted and **shape-identical to ordinary traffic** —
  to a hub it is just another sealed envelope on the rotating per-epoch session
  token. Padded through the normal bucket pipeline.
- Emitted **only once a session exists.** First-contact bootstrap stays
  one-shot (no receipts) — bootstrap is its own reliability path.
- **Recipient opt-out:** a config flag disables sending delivery receipts
  (default ON — reliability matters for a messenger; see §4 for why this is an
  acceptable default unlike read receipts).

### 3.2 Sender pending-store (encrypted)

A new **AEAD-encrypted** vault table:

```
pending_outbound(
  msg_id BLOB PK, peer_fp TEXT, group_id BLOB,
  resend_form BLOB,        -- enough to re-seal/re-send (AEAD'd at rest)
  attempts INT, hubs_tried TEXT, next_retry_at_ms INT, created_at_ms INT
)
```

- On send: insert. On `DeliveryReceipt{msg_id}`: delete.
- **Depends on at-rest encryption (audit #1)** — this table holds
  message-equivalent content until acked, so it MUST be sealed at rest. Build
  *after* #1 lands.

### 3.3 Retry loop + loud failure

A daemon task scans `pending_outbound`:
- For entries past `next_retry_at_ms`, **re-fan-out** to the recipient's hubs,
  **widening** the hub set each attempt; exponential backoff
  (e.g. 30 s → 2 m → 10 m → 1 h …).
- Replay guard already dedups the resulting duplicates at the recipient ✓.
- After `max_attempts` / a TTL, **surface a visible "not delivered" state** in
  the TUI for that message (the conversion of silent loss → visible failure —
  **the single most important change**).

### 3.4 Quorum fan-out + recipient hub-set hint

- Carry the recipient's **preferred hub list** in the contact/invite (invites
  already carry hub data) so the sender fans out to hubs the recipient actually
  subscribes on (fixes §1.1 #2).
- First attempt: deliver to a **quorum** (e.g. `min(3, hubs)`) of the
  *overlap*, not all-my-hubs. Retry (§3.3) widens the set on miss.
- Once a receipt arrives, stop — and (optional) tell hubs they may drop the
  copies (§3.5). Cuts the N× multiplier (G2) and removes the "only shared hub
  died" hole (G1).

### 3.5 (Optional) hub "delivered, you may drop" hint

A signed, content-free hint letting hubs free queue space once the recipient
acked, instead of waiting for TTL. Pure optimization; TTL handles it otherwise.
Lower priority.

---

## 4. Threat-model delta (the privacy-critical part)

A delivery receipt is recipient→sender traffic meaning *"my daemon was online
at ~T and fetched message M."* That is an **activity-timing signal** — the
class `ANONYMITY.md` treats as sensitive. The design contains it:

| Concern | Mitigation |
|---------|-----------|
| Hub learns recipient online-time | **None new.** The hub already observes an envelope arriving + a pickup; the receipt is one more indistinguishable sealed envelope on a rotating token. No new hub-visible signal. |
| Sender learns recipient online-time | **This is the genuinely new bit.** But sender↔recipient already know they talk, and "delivered" ticks are table-stakes for a messenger. Acceptable **as a default** — with a recipient **opt-out** (unlike read receipts). |
| Read-receipt creep | **Forbidden (N1).** Only the daemon's *fetch* triggers a receipt, never the user *opening* the message. |
| Pending-store at rest | Holds message-equivalent content → **must be AEAD-sealed** (audit #1 dependency). |
| Receipt as amplification/DoS | Receipts are rate-limited like any frame; one per received message; bounded by `msg_id`. |

**Honest statement to add to `ANONYMITY.md`:** "Delivery receipts (default on,
recipient-disableable) tell the *sender* the coarse time your daemon picked up a
message. They are sealed and indistinguishable to hubs, and Onyx never sends
*read* receipts."

---

## 5. Beyond receipts — the real path to large scale

Receipts + quorum fix reliability and the storage multiplier, but the network
still piles users onto hand-picked hubs. To scale to *large*:

- **Routing-id sharding (DHT / consistent hashing).** The routing-id is already
  a hash — shard the keyspace across hubs so each serves a slice and the
  network scales by *adding hubs*, instead of every hub seeing everything. This
  is the structural change; it interacts with discovery (`DISCOVERY.md`) and
  federation (`FEDERATION.md`) and is the largest piece.
- **Per-hub lock sharding** — split the global mutex into per-routing-id-bucket
  locks so one hub uses all its cores.
- **Capacity signaling** — `onyx-metrics` is liveness-only today; a *coarse,
  bucketed* load field could let clients steer away from overloaded hubs —
  carefully, to avoid leaking user counts (see `METRICS.md`).

These are follow-on; receipts + quorum are the high-leverage first move.

---

## 6. Why not hub-to-hub queue replication?

It's the "obvious" reliability fix, but: it adds a metadata surface (hubs
learn which other hubs hold a routing-id's traffic), real cost (every queued
message replicated again), and complex consistency. The E2E-receipt + retry
approach gets **most of the reliability with less risk** — the sender, who
already holds the message, is the natural retry authority. Revisit replication
only if receipts prove insufficient.

---

## 7. Phased implementation plan

Each phase a self-contained PR, gated, honest CHANGELOG. **Order matters:**

1. **(prereq) Finish audit #1 at-rest encryption** — §3.2 depends on it.
2. **Wire + receipt emit/consume.** Add `DeliveryReceipt` variants; recipient
   auto-emits on decrypt; sender consumes (no store yet — just log/observe).
   Pure, unit-testable.
3. **Pending-store + receipt-driven delete** (encrypted table).
4. **Retry loop + loud "not delivered" TUI state.** (Delivers G1.)
5. **Recipient hub-hint in contact/invite + quorum fan-out.** (Delivers G2/G3.)
6. **(optional) hub drop-hint** (§3.5).
7. **(later, large) routing-id sharding** — its own design doc.

---

## 8. Open questions

- Q1. Delivery-receipt default — **on with opt-out** (recommended) vs off?
- Q2. Quorum size + retry/backoff schedule + max-attempts before "failed."
- Q3. Receipt for *rooms*: one receipt per member per message is N×; do rooms
  get receipts at all, or only 1:1 DMs in v1? (Recommend: **DMs only** first;
  rooms are higher-volume and the per-member receipt fan-in is costly.)
- Q4. TTL relationship — sender max-attempts must expire *before* the hub queue
  TTL, or retries chase already-purged copies.
