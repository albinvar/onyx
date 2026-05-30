# Onyx — Anonymity & Untrackability Roadmap

> **North Star.** An adversary who runs the hub(s) **and** all peer-hubs,
> watches the user's Tor entry guard, **and** later seizes the device should
> learn *nothing* that links a user across sessions, to their social graph, to
> their location, or to content.

This is the anonymity-focused work backlog. It is **additive** to `ROADMAP.md`
(which tracks features/product) and grounded in the current code and the
2026-05 internal red-team + re-audits. Items are ordered by **how much they
move the North-Star property**, not by ease.

## Where we are today (honest)

| Property | Status |
|----------|--------|
| **Content confidentiality** | ✅ Safe (Noise XK + MLS RFC 9420 + PQ-hybrid sealed-sender). |
| **Linkage (hub links your sessions to one identity)** | 🟠 **Partial.** D-1 made hub connections *private by default* (ephemeral Noise static + ephemeral SUBSCRIBE signing + no intro-inbox + no KP publish). But the moment a user wants first-contact reachability (`--first-contact-reachable`) the hub re-links them, and even in private mode authorization/rate-limiting is by-connection, not anonymous-but-authorized. The **keystone (A2.1)** is what makes "unlinkable AND authorized" possible. |
| **Presence (hub learns you are online; `H(fingerprint)` probing)** | ❌ Not safe — intro-inbox is a probing oracle when reachable (A2.2). |
| **Social graph (who talks to whom)** | 🟠 Partial — sealed-sender hides sender on bootstrap; ongoing-message metadata + group membership leak (A2.3, A4.2). |
| **Timing / traffic analysis** | 🟠 Partial — opt-in Poisson + constant-rate upstream cover exist; not default, not bidirectional, unmeasured on real Tor (A3.x). |
| **Forensic (seized device)** | 🟠 Partial — vault AEAD-at-rest + log social-graph redaction; no duress vault, no deniability, no mlock (A5.x). |

## The one sentence that matters

**Until A2.1 lands and is the default, Onyx cannot honestly claim "no one can
track you" — the hub can, today, by design, the instant a user opts into
reachability (D-1).** That single feature is the line between the pitch and the
math. Everything else hardens around it.

## Three hard rules (baked in)

1. **Never invent crypto.** Use vetted primitives — KVAC, CPace/PAKE, PIR,
   openmls. The work is *novel integration*, never *novel primitives*.
2. **Default to safe.** An opt-in anonymity feature protects no one. Every
   item here is "done" only when it is the **default**.
3. **Measure, don't assert.** Every anonymity claim needs a test (or a
   documented real-circuit measurement) or it stays marked **partial** in
   `THREAT_MODEL.md` / `ANONYMITY.md`.

---

## The 18 features, by layer

### L0 — Identity & contact
- **A0.1 — PAKE first-contact (CPace/SAS).** MITM-proof first contact via a
  short shared word/number compared out of band. Properly closes T-2's
  residual (full-invite substitution that a self-signed invite can't stop).
- **A0.2 — Require signed invites by default.** v2-only accept; `onyx accept`
  already refuses unsigned v1 unless `--insecure-accept-unsigned` (done in the
  T-2 batch). Keep enforced; remove the escape hatch once A0.1 lands.
- **A0.3 — Enforce TOFU pin on send.** T-1 pins + warns; A0.3 makes a
  `key_changed` pin **block** outbound on every path (not just `accept`), with
  an explicit re-pin action.

### L1 — Network
- **A1.1 — Per-conversation Tor circuit isolation.** ✅ ~done (D-2,
  `TorRuntime::isolated()` per hub connection + per peer dial). Residual:
  isolates circuits, not guards (intentional Tor design).
- **A1.2 — No-clearnet-leak guard.** A startup + runtime assertion that no
  socket ever bypasses Tor (defense against a config/regression that dials
  clearnet). Testable.

### L2 — Hub metadata (the core)
- **A2.1 — ASC: unlinkable-but-authorized subscriptions. ⭐ KEYSTONE.**
  Anonymous-credential subscriptions so the hub can verify "this subscriber is
  entitled" **without** learning *which* user it is or linking sessions. See
  `DESIGN-ASC.md`. Interim step shipped: ephemeral-static-by-default (D-1).
- **A2.2 — Oblivious inbox.** Kill the `H(fingerprint)` presence oracle —
  retrieving first-contact envelopes without revealing which inbox you're
  reading (PIR / oblivious pseudonym lookup).
- **A2.3 — Sealed-sender for ongoing messages.** Extend the bootstrap-only
  sealed-sender to *every* hub-routed message so the hub never sees a stable
  sender id on ongoing traffic.
- **A2.4 — Provable-no-metadata.** A test that seizes a hub's full DB and
  proves zero cross-id linkage — so we can *truthfully* say "the hub holds
  nothing linkable."
- **A2.5 — Delivery off the serial path.** Move recipient-side delivery off
  the inline+serial loop (also closes P-3 HOL/junk-envelope DoS).

### L3 — Traffic analysis
- **A3.1 — Loopix-style cover by default.** Poisson mix cover traffic **on by
  default**, not opt-in. The existing `--cover-traffic-mean-secs` /
  `--constant-rate-ms` are the building blocks; A3.1 makes a sane default.
- **A3.2 — Downstream + peer-circuit cover.** Hub→client constant-rate +
  direct peer-to-peer circuit cover (today only client→hub upstream exists).
- **A3.3 — Real-circuit measurement.** `scripts/real_tor_smoke.sh` drill that
  measures whether a passive observer can distinguish active vs idle — the
  evidence behind every §3.1 claim.

### L4 — Group metadata
- **A4.1 — Committer authority.** An add/remove authorization model so not
  *any* member can add/remove *any* member (G-2). Likely an MLS-credential
  policy layer.
- **A4.2 — Membership unlinkability. ⭐ the novel research prize.** The hub /
  a peer-hub cannot learn group membership or link members across groups.
  Hardest item; genuinely novel integration.
- **A4.3 — Gossip partition resistance.** Authenticated forwarding metadata so
  a malicious peer-hub can't forge `seen_by` to suppress/partition the
  directory (H-2).

### L5 — Forensic / seized device
- **A5.1 — Finish log redaction.** D-3 moved identity/onion/social-graph to
  debug; A5.1 is the full pass + a redaction policy + a "logs are plaintext at
  rest" decision (encrypt or don't write).
- **A5.2 — Duress vault.** A second passphrase that opens a decoy.
- **A5.3 — Deniable MLS.** Reduce the non-repudiation surface of long-term
  Ed25519 signatures where the threat model wants deniability.
- **A5.4 — mlock.** Lock key material so it can't be swapped to disk.

### L6 — Assurance
- **A6.1 — Reproducible builds.** Already: sigstore-signed releases; A6.1 is
  full bit-for-bit reproducibility verification.
- **A6.2 — Unlinkability property-tests.** Property/fuzz tests that *assert*
  the unlinkability invariants (adversary-can't-link), not just functional
  correctness. `rooms_e2e_private_mode_leaks_no_identity_to_hub` is the first.
- **A6.3 — External security audit.** The single most important open item
  (`THREAT_MODEL.md` §8.2 #7). Nothing here substitutes for it.
- **A6.4 — Fix the onion≠identity claim.** Today the HS key is random
  (`OnionServiceConfigBuilder::default()`), so the documented
  "onion address == identity key" property (D-4) is not actually true. Either
  make it identity-derived or correct the docs.

---

## Critical path (do in this order)

1. **A0.1 — PAKE contact.** Low-ish effort, properly closes T-2.
2. **A2.1 — ASC / token-only subscriptions (THE keystone).** Makes the hub
   unable to link a user. Ephemeral-static-by-default (D-1) is the interim
   step and is already shipped.
3. **A2.3 + A2.4 — sealed-sender for ongoing messages + the seized-hub-DB
   no-linkage test** → we can truthfully say "the hub holds nothing linkable."
4. **A3.1 — Loopix cover, on by default** — provable timing unlinkability.
5. **A2.2 — oblivious inbox** — kills the presence oracle.
6. **A4.2 — membership unlinkability** — the hard, genuinely-novel one.

---

## Status tracking

Each item is `planned` / `designing` / `in-progress` / `partial` / `done`.
"done" requires: default-on, a test or measurement, and `THREAT_MODEL.md` +
`ANONYMITY.md` updated. Anything short of that is `partial`.

| ID | Title | Status | Notes |
|----|-------|--------|-------|
| A1.1 | Circuit isolation | partial→done | D-2 shipped; circuit-not-guard caveat documented. |
| A0.2 | Require signed invites | partial | T-2 batch refuses v1 by default; escape hatch remains until A0.1. |
| A0.3 | Enforce TOFU on send | partial | T-1 pins+warns; blocking-on-send not yet on every path. |
| A2.1 | ASC unlinkable subscriptions | **designing** | `DESIGN-ASC.md`. Interim: D-1 ephemeral-default shipped. |
| (all others) | — | planned | — |

*This document is the strategic spine of the project. It is committed and
tracked; do not treat it as scratch. The North Star above is the single
acceptance test for every line of code in Onyx.*
