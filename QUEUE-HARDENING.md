# H-1 design — offline-queue-fill DoS hardening

**Status:** design doc for review (fortification Phase 3, F3.2). **No code
yet.** Lays out the attack, why today's defenses are partial, the options
(with their real trade-offs), and a recommendation — before any change to
queue semantics, because the leading fix risks *losing a real queued
message*.

Companion to `THREAT_MODEL.md` §8.4 (H-1 row) and `ANONYMITY.md` §3.3.

---

## §1 The asset and the attack

The hub holds an **offline queue**: when a recipient has no live subscriber,
an inbound envelope is stored (in memory + a SQLite write-through) keyed by
its 16-byte routing id, and drained when the recipient (re)subscribes. The
queue is the availability-critical resource an attacker wants to exhaust.

Current bounds (`onyx-hub/src/state.rs`):
- `MAX_QUEUE_DEPTH_PER_ID = 1024` envelopes per routing id.
- `MAX_TOTAL_QUEUED_BYTES = 256 MiB` across all queues (incl. a 128-byte
  per-entry overhead charge).
- On either cap, the **new** envelope is **dropped** (`can_enqueue` returns
  false) — "drop-newest."
- A per-Noise-static-key token bucket (`rate_limit.rs`, default 600
  frames/min) gates DELIVER/KP_PUBLISH/KP_FETCH; empty bucket → silent drop;
  a throttled bucket survives reconnect (HIGH-3).

Two attack shapes:

1. **Single-inbox flood.** The attacker targets one recipient's
   `introduction_inbox(fp)` — which is **fingerprint-derivable**, so any
   stranger who has the victim's (public) fingerprint can compute it. Fill
   it to the 1024 depth cap; now every *real* offline message to that victim
   is dropped (drop-newest: the junk got there first). DoS against one
   reachable user.
2. **Many-inbox global exhaustion.** Spray envelopes across thousands of
   distinct routing ids (each below the per-id cap) until the 256 MiB global
   cap is reached. Now **every** recipient's new offline messages are
   dropped hub-wide. DoS against the whole hub.

---

## §2 Why today's defenses are only partial

- **Drop-newest favours the attacker.** Whoever fills the queue *first*
  wins; legitimate later messages are refused. The cap bounds memory but not
  *who* gets to use it.
- **The per-key rate limit is evadable by key rotation.** A DELIVER is
  authenticated by the connection's Noise static key — but in the D-1
  private default the daemon uses a **fresh ephemeral** Noise key per hub
  connection. So an attacker can open many connections with fresh keys, each
  getting its own 600/min bucket; the per-key limiter does not bound the
  aggregate. (Raising the cost of *opening connections* — Tor circuits — is
  the only thing that bounds this today, and it's modest.)
- **The sealed-sender / ephemeral-key design is the tension.** Because the
  hub cannot attribute a queued envelope to a stable sender identity (by
  design — that's the unlinkability we want), it cannot enforce a per-sender
  quota without breaking sender privacy.

What *already* limits exposure (important, and it narrows H-1):
- **The private default has no targetable inbox.** A D-1 user does **not**
  publish/subscribe a fingerprint-derived intro inbox; their offline
  delivery rides **high-entropy session tokens** an attacker cannot derive
  or target. So **attack shape 1 only applies to users who opted into
  `--first-contact-reachable`.** The default user is immune to single-inbox
  flooding.
- **Multi-hub fan-out** spreads the global-exhaustion cost across N hubs.

---

## §3 Options (with trade-offs)

### Option A — fair eviction under memory pressure (recipient fairness)
When the global byte cap is hit, instead of dropping the *new* envelope,
**evict the oldest entry from the *largest* queue** to make room, then
enqueue. Rationale: the largest queue is the most likely flood target /
attacker-controlled sink; small legitimate queues are protected. Identity-
free; directly defeats **attack shape 2** (one bloated queue can't deny the
many).
- **Cost / risk:** it can **evict a real queued message** (if the largest
  queue happens to hold legit traffic) — a delivery-semantics change. Bounded
  by: it only triggers *at* the global cap (already a lossy regime today),
  and the victim's daemon re-sends on reconnect for DM-fallback / room paths.
- **Implementation surface:** needs a durable-store **delete-oldest-for-
  routing-id** operation (today the store only has `drain_queue` = delete
  all) to keep memory + disk consistent. Plus pick the largest queue
  efficiently (a max-by-len scan, or maintain a size index).
- Does **not** fix attack shape 1 (single-inbox flood stays within one
  queue under the per-id cap).

### Option B — proof-of-work to enqueue (cost asymmetry, identity-free)
Require a small PoW token bound to `(target, blake2b(body), hub_epoch)`
before the hub will *queue* an offline envelope (live delivery to an online
subscriber stays free). Hashcash-style, tunable difficulty.
- **Pros:** no identity needed (compatible with sealed-sender + ephemeral
  keys); raises the per-envelope cost of a flood by orders of magnitude;
  helps **both** attack shapes; the *recipient* and a normal sender pay it
  once, cheaply.
- **Cons:** legitimate senders pay CPU/latency/**mobile battery** on every
  offline send; a resourceful attacker (GPU/botnet) still floods, just at
  higher cost; adds a wire-format field + verification path (hub must track
  `hub_epoch` + dedup tokens to stop replay). Real design + UX work.
- **Verdict:** strong but heavy; recommend **defer** to an opt-in
  hub-operator policy (`--require-pow-difficulty N`) rather than a default.

### Option C — recipient capability tokens
The recipient hands known senders a signed delivery capability; the hub only
queues envelopes bearing a valid (unlinkable, e.g. blind-signed) token.
- **Pros:** precise; a non-authorized sender simply can't enqueue.
- **Cons:** **breaks first contact** (a stranger has no token) — defeats the
  whole point of a reachable intro inbox; blind-signature machinery is a
  large crypto addition. **Reject** for first-contact; only viable for
  established conversations, which already use opaque session tokens not
  vulnerable to shape 1.

### Option D — stable-key per-sender quota
Require a non-ephemeral Noise key to enqueue offline, then quota per key.
- **Cons:** **breaks sender privacy** (re-links the sender to the hub across
  sends) — directly contradicts D-1. **Reject.**

---

## §4 Recommendation

1. **Ship Option A (fair eviction) as the concrete F3.2 slice** — it's the
   identity-free, privacy-free fix that actually defeats the hub-wide
   exhaustion (shape 2), which is the more damaging attack. Gate it behind a
   review of the message-loss semantics (it only loses under attack, at the
   cap, where today we already drop — but now we may drop an *older* message
   instead of the *newest*). Add the durable delete-oldest op + a test that a
   bloated queue is trimmed before a small one.
2. **Document the residual for shape 1** honestly: single-inbox flooding of a
   *reachable* user's intro inbox remains possible within the per-id cap; the
   mitigations are (a) **use the private default** (no targetable inbox at
   all — the recommended posture) and (b) optional **Option B PoW** for
   operators who run reachable/bootstrap hubs. Keep B as a deferred,
   opt-in hub policy in `THREAT_MODEL.md` §8.4.
3. **Reject C and D** (break first-contact and sender-privacy respectively).

### What this does NOT claim
Fair eviction is not "the hub can't be flooded" — a determined attacker can
still churn the queue. It changes *who loses* under pressure from "everyone
(drop-newest)" to "the biggest hog (evict-largest)", which is the property
that matters for keeping a hub usable under attack. Shape-1 single-inbox DoS
of a reachable user stays partially open by design (the price of being
reachable-by-fingerprint via an untrusted relay); the private default avoids
it entirely.

---

## §5 Proposed slices

1. **F3.2a — fair eviction (Option A).** `state.rs`: when `can_enqueue`
   would refuse on the *byte* cap, evict oldest-from-largest until there's
   room (bounded eviction count); `store.rs`: add delete-oldest-for-routing-
   id; test: a 1-entry legit queue survives while a near-cap flooded queue is
   trimmed. Keep the per-id depth cap as-is.
2. **F3.2b — docs.** `THREAT_MODEL.md` §8.4 H-1: partial-resolution note +
   the private-default mitigation + PoW-as-deferred-opt-in.
3. **Deferred:** Option B PoW as an opt-in hub policy; revisit if reachable
   bootstrap hubs see real abuse.

---

## §6 Open questions for review

1. **Is evicting an older real message acceptable** under global-cap
   pressure (vs today's drop-newest)? Both lose a message; A loses an *older*
   one to protect *small* queues. I believe yes (it only triggers under
   attack/overload), but it's a delivery-semantics call worth your sign-off.
2. **Eviction granularity** — evict a single oldest entry per admission, or
   batch-trim the largest queue down to a fraction? Single-entry is simplest
   and self-limiting; batching reclaims faster under heavy flood.
3. **Is PoW (Option B) worth prototyping now**, or strictly deferred until a
   reachable/bootstrap hub actually sees abuse?
