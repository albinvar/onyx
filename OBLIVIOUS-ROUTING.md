# F2.1 design — separated publish/subscribe + oblivious-recipient routing

**Status:** design doc for review (fortification Phase 2, F2.1). **No code
yet.** This proposes *what* to build and, just as importantly, what *not*
to build, with the delivery-safety reasoning, before any protocol change.

Companion to `ROTATION.md` (which proves rotation alone is a non-fix) and
`ANONYMITY.md` §3.2 (the structural hub-linkability accounting).

---

## §1 Goal, and what's already done

ROTATION.md §3 says the hub stops knowing "who alice is" only when three
things change together:

- **(A) Ephemeral Noise keys per session** — ✅ **already shipped (D-1).**
  In the default posture (`first_contact_reachable = false`) the daemon
  already uses a fresh per-connection X25519 Noise static **and** a fresh
  SUBSCRIBE-signing key (`hub_client.rs:159-189`), publishes no KeyPackage
  (`lib.rs:886-900`), and does not subscribe to the fingerprint-derived
  intro inbox (`lib.rs:911-912`). So today, by default, the hub
  authenticates "some ephemeral peer," not alice.
- **(B) Separate connections for publish and subscribe** — ❌ not done.
  Today one bidirectional connection per hub carries SUBSCRIBE, DELIVER,
  KP_PUBLISH and KP_FETCH (`hub_client.rs:1-75`).
- **(C) Oblivious-recipient routing for first contact** — ❌ not done; the
  deep problem.

F2.1 is therefore **(B) + (C)**. This doc shows (B) is a small, safe,
shippable slice, and (C) is largely *already solved for established
conversations* and should be handled for first-contact by leaning on the
connect-code path rather than building PIR/ORAM in v0.

---

## §2 Where the leak actually is (and isn't)

Onyx has two routing tiers (`routing.rs`):

| Tier | Derivation | Used for | Oblivious to the hub? |
|------|-----------|----------|-----------------------|
| **Intro inbox** | `blake2b_128(recipient_fp ‖ "onyx/v1/inbox")` | first-contact bootstrap | **NO** — anyone with the fingerprint computes it |
| **Session token** | `blake2b_128(group_secret ‖ index)` | established rooms/DMs | **YES** — needs the shared group secret; high-entropy, per-epoch |

The critical observation the architecture review confirms: **established
conversations already route obliviously.** A room/DM message targets
`session_token(group_secret, index)` — a value only current members can
derive, rotating by epoch, with no link to any fingerprint and no way for
the hub to tell two rooms apart or count members. The hub sees "some
high-entropy inbox is active." That is exactly the property (C) asks for,
and it already exists for the steady state.

So the residual leak is **first-contact only**: the bootstrap envelope is
addressed to `introduction_inbox(bob_fp)`, derived locally by the sender
from bob's fingerprint (`api_server.rs:2940`, no directory fetch). Because
the derivation is deterministic and the fingerprint is public (it's the
invite-URL identifier), **anyone with bob's fingerprint — including the hub
— can (a) compute bob's inbox id, (b) probe it via KP_FETCH or a
DELIVER-and-observe to learn whether bob is reachable/online, and (c) link
all first-contact traffic destined for bob.**

This is inherent to "be reachable by anyone who knows my fingerprint, via
an untrusted relay." You cannot let a stranger address you without giving
the relay the same addressing information the stranger has.

---

## §3 Part B — split the identity-bearing surface from the activity surface

### Correction to the naive framing (post-architecture-review)
The first draft of this doc said "separate publish from subscribe." That is
imprecise. In **reachable** mode the daemon uses *long-term* keys by
necessity: the intro-inbox SUBSCRIBE proof must be signed by the long-term
key (HIGH-1 ownership check on a known inbox) and the published KP carries
the long-term signing key. So **both** the KP publish *and* the intro-inbox
subscribe inherently reveal the fingerprint to the hub — that is the whole
meaning of "reachable." Splitting publish from subscribe while both use the
long-term key buys nothing (the hub correlates by the identical long-term
Noise key, or just reads the fingerprint off either frame).

The property actually worth having: **decouple identity from activity.** The
hub may know "bob is reachable" (unavoidable if bob opts into hub
reachability), but it should not be able to link bob's identity to *which
rooms/DMs he participates in*. Today, in reachable mode, KP-publish +
intro-inbox-subscribe + all room session-token subscribes ride one
long-term-keyed connection, so the hub links bob → his entire room set.

### Design (corrected)
In reachable mode, run **two** sessions per hub:

- **Identity session (P):** long-term keys. Does KP_PUBLISH + SUBSCRIBE to
  `introduction_inbox(fp)`; receives first-contact bootstraps. The hub knows
  this is bob — by design, because bob chose to be reachable.
- **Activity session (S):** *fresh ephemeral* Noise + ephemeral SUBSCRIBE
  signing key. Subscribes to the per-(room, epoch) **session tokens** (which
  are high-entropy and not known inboxes, so ephemeral signing passes), and
  carries **all outbound** (DELIVER sends, KP_FETCH). The hub sees "some
  ephemeral peer is active in these high-entropy inboxes" with no link to
  bob's fingerprint.

Both sessions feed the same `on_deliver` dispatcher (routing-id keyed), so
delivery is unaffected. Different Noise keys + different Tor circuits (D-2
isolation) mean the hub cannot correlate P and S.

In the **private default** there is no KP publish and no intro-inbox
subscribe, so there is no identity session at all — the existing single
ephemeral session (which already carries only session tokens + outbound) is
*exactly* the "S" above. **Part B is therefore a no-op for the default path,
which stays byte-identical**; it only adds the second (identity) session
when the user opts into reachability.

### Risk profile (honest, post-review)
What *contains* the risk:
- **Wire protocol unchanged.** SUBSCRIBE / KP_PUBLISH / DELIVER / KP_FETCH
  frames are identical; only the daemon's connection *topology* changes.
- **Hub unchanged.** The hub already handles many independent ConnIds; two
  connections from one daemon look like two clients — which is the point.
- **Default (private) path byte-identical.** The second session only exists
  when `first_contact_reachable = true`. A bug there degrades to *current*
  behaviour (identity linked to activity), not a delivery break, as long as
  both sessions feed `on_deliver` and outbound routes to S.
- **Backward compatible** with old hubs (a hub doesn't care how many
  connections a client opens).

What makes it bigger than the first draft implied (NOT a trivial add):
- The per-hub task in `lib.rs:869-950` is a single reconnect loop around one
  `run_hub_session`. Supporting two sessions means **two independent
  reconnect/backoff loops**, **routing the one outbound channel to S only**
  (P drains nothing), splitting the subscription set by role, and making
  **both** participate in shutdown. The cover-traffic / constant-rate emitter
  (which clones the outbound Sender) must target S.
- So this is a contained but real **supervisor refactor**, not a one-liner.

### Cost
One extra long-lived Tor circuit per hub *in reachable mode only*. Idle
cost is one extra keepalive cadence; acceptable for users who opted into
reachability.

### Implementation sketch (for the eventual code slice — not this PR)
- `hub_client.rs`: factor the session spawn so it can be invoked in a
  "publish-only" and a "subscribe-only" role; today `run_hub_session` does
  both. Add a role enum; gate which verbs each role accepts.
- `lib.rs` hub-spawn (around the `ephemeral_noise`/`first_contact_reachable`
  decision, ~`lib.rs:886-939`): when reachable, spawn P and S with separate
  `IdentitySecret::generate()` keys; when private, spawn the single existing
  session unchanged.
- Tests: extend the smoke harness to assert (i) a reachable daemon opens two
  Noise sessions with distinct static keys, (ii) KP publish lands on P and
  inbox delivery arrives on S, (iii) the hub-side view shows two unrelated
  ConnIds. Add a red-team assertion that the two static keys differ.

---

## §4 Part C — oblivious first-contact routing (recommend: lean on connect-codes, defer PIR)

The honest finding (consistent with ROTATION.md §3.C): making first-contact
addressing oblivious to an untrusted relay, while still letting a stranger
reach you by a public identifier, requires either:

1. **PIR / ORAM-style bucketed mailboxes** — senders query encrypted buckets
   so the hub learns neither the recipient nor which bucket matched. Real,
   but a large cryptographic + performance + UX undertaking; ROTATION.md
   §3.C correctly calls it "not a quick slice." **Recommend: not for v0.**
2. **Out-of-band first-contact secret** — the recipient hands the sender a
   high-entropy address out of band, so the address is *not* derivable from
   the public fingerprint and the hub learns nothing linkable. **Onyx
   already has this: the connect-code** (`onyx://connect/v1?onion=…&id=…`,
   shipped v0.1.16) is a direct onion dial that bypasses the hub entirely —
   the strongest possible oblivious first contact (no relay sees it at all).

### Recommendation
- **Make connect-code direct-dial the recommended oblivious first-contact
  path** (it already is the most private; document it as *the* answer to
  "first contact without the hub learning who you are").
- **Keep hub intro-inbox first-contact as the explicit reachability
  tradeoff** it already is (opt-in via `first_contact_reachable`), now with
  Part B's separated connections so that *when* you opt in, the hub at least
  can't trivially self-correlate publish↔subscribe.
- **Optional, analyze-then-decide (do not commit to in this doc):**
  *per-epoch intro-inbox rotation from a published rotating seed.* Bob
  publishes (in his KP, or a small signed record) a rotation public seed;
  the live intro inbox becomes `blake2b_128(fp ‖ epoch ‖ seed)`. This makes
  the *live* id rotate so the hub can't use a single stable id as bob's
  presence beacon across epochs. **But** it does not stop a holder of bob's
  fingerprint+seed (every legitimate sender) from computing the current id,
  and the hub can watch KP_FETCHes to learn the mapping — i.e. it mitigates
  *passive long-horizon linking of a stable id* but not *active probing*.
  Marginal benefit; real added complexity (epoch sync, KP format change).
  **Recommendation: defer; document as a known partial measure, not a fix.**

### What this means honestly
F2.1 does **not** make Onyx "the hub can never tell who you're reaching for
first contact." It makes the *steady state* oblivious (already true via
session tokens), makes the *reachable opt-in* less self-correlating (Part
B), and points first-contact-privacy users at the connect-code path that
removes the hub from first contact entirely. PIR-grade oblivious relay is
explicitly out of scope for v0 and stays in ROTATION.md §6's deferred list.

---

## §5 Proposed slices (in order)

1. **F2.1a — identity/activity session split** (Part B). ✅ **DONE**
   (2026-06-02). Reachable mode runs an identity session (long-term keys,
   KP + intro-inbox) separate from an activity session (ephemeral keys,
   session-tokens + outbound), each on its own isolated circuit. Private
   default unchanged (single ephemeral activity session). Unified Tor + TCP
   reconnect loops behind `supervise_hub_session` / `spawn_hub_role_sessions`.
   Verified by `rooms_e2e_reachable_splits_identity_and_activity_connections`
   (reachable → 2 connections, private → 1). Wire + hub unchanged.
2. **F2.1b — docs: connect-code as the oblivious first-contact path** (Part
   C recommendation). Update ANONYMITY.md §3.2 + the recommended-config
   matrix; cross-reference connect-codes. Doc-only.
3. **Deferred (not scheduled): PIR/ORAM oblivious relay** and **per-epoch
   intro-inbox rotation** — recorded in ROTATION.md §6 with the analysis
   above; revisit only if a concrete low-cost design appears.

---

## §6 Delivery-safety checklist (for F2.1a when it is built)

- [ ] Private/default daemons keep exactly one connection — byte-identical
      behaviour (gate the second connection on `first_contact_reachable`).
- [ ] No wire-format change; old hub ⇄ new daemon and new hub ⇄ old daemon
      both work (additive connection topology only).
- [ ] Reachable daemon: KP publish + inbox subscribe verified to land on
      different Noise sessions with different static keys.
- [ ] Real-Tor smoke: a reachable daemon still receives a first-contact
      bootstrap end-to-end with the split topology (no delivery regression).
- [ ] Reconnect supervisor handles both connections independently (one can
      drop/reconnect without disturbing the other).
- [ ] Shutdown drains/*closes* both connections cleanly.

---

## §7 Open questions for review

1. **Outbound DELIVER placement** — put sends on the publish connection P,
   or a dedicated third connection? (Leaning P: sends aren't identity-
   bearing the way a long-lived subscribe is, and a third circuit is extra
   cost for little gain. Open to argument.)
2. **Is per-epoch intro-inbox rotation (§4 optional) worth even the doc
   churn**, or should it stay only in ROTATION.md §6's deferred list?
3. **Scope of F2.1a** — ship Part B alone first (recommended), or bundle the
   connect-code-documentation (F2.1b) in the same PR?
