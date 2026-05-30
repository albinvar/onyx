# Onyx — Anonymity & Untrackability Roadmap

**The sole purpose: a user is unlinkable and untrackable. No one — not the hub
operator, not a federated peer-hub, not a network observer, not someone who
later seizes the device — should be able to learn who a user is, who they talk
to, that they are even present, or what they say.**

This document is the anonymity-focused work backlog. It is grounded in the
current code (file:line where relevant) and the findings from the 2026-05
internal red-team. Items are ordered by *how much they move the North-Star
property*, not by ease. Everything here is additive to `ROADMAP.md`.

---

## North-Star property (the thing we are trying to make *provably true*)

> An adversary who simultaneously: (a) operates the hub(s) and all peer-hubs,
> (b) observes the network at the user's Tor guard, and (c) later seizes the
> user's device — should learn **nothing** that links a user's pseudonymous
> identity across sessions, to their social graph, to their network location,
> or to message content.

Today, content is protected. **Linkage, presence, social graph, and timing are
not** — the hub can still cluster a user's whole activity under one identity by
default. Until that is false-by-construction, the North Star is aspirational.

Status legend: 🔴 not started · 🟡 partial / opt-in · 🟢 delivered-by-default

---

## Layer 0 — Identity & contact establishment

### A0.1 — PAKE-authenticated first contact (MITM-proof) 🔴 — **DO FIRST**
- **Delivers:** two users sharing a short secret ("orange-falcon-92") establish
  authenticated keys; an active MITM who lacks the secret *cannot* complete the
  handshake. Replaces "carefully compare 52 base32 chars" (which no one does).
- **Closes:** T-2 (signed invites are self-signed → full MITM still passes with
  a green "✓"). This fixes it at the root.
- **How:** balanced PAKE (CPace / SPAKE2) layered into the invite/bootstrap
  flow (`invite.rs`, `flows.rs::initiator_exchange`/`responder_exchange`).
- **Use an existing impl. Do not roll your own PAKE.**
- **Effort:** low. **Priority: 1.**

### A0.2 — Require signed invites; kill the v1 downgrade 🔴
- **Delivers:** an attacker can't strip `invite/v2`→`invite/v1` to bypass the
  signature; the client refuses unsigned invites unless an explicit `--insecure`.
- **Closes:** NEW-1 (v1 downgrade by URL path rewrite, only a stderr warning today).
- **How:** bind the version into the signed bytes (`invite.rs::canonical_signing_bytes`);
  reject unsigned on accept. Stop printing "verified ✓" for a self-signed sig.
- **Effort:** low.

### A0.3 — TOFU pin enforcement on send (not just warn) 🟡
- **Delivers:** before the daemon sends a first-contact message, cross-check the
  invite/peer fingerprint against the pin store; block (not just `warn!`) on a
  changed key.
- **Closes:** the gap that T-1 pinning is advisory and the daemon never verifies
  invites (verification lives only in the CLI).
- **Depends:** A0.1 (a pin is only meaningful once contact is authenticated).
- **Effort:** low-medium.

---

## Layer 1 — Network / transport

### A1.1 — Per-conversation circuit isolation 🟢 (verify default)
- **State:** `TorRuntime::isolated()` added (`tor.rs:152`), used per-hub
  (`lib.rs:721`) and per-peer-dial (`lib.rs:1093`). Confirm it's the default for
  *all* dials and that no two distinct peers ever share a circuit.
- **Closes:** D-2. Mostly done — keep as a regression-tested invariant.

### A1.2 — No-clearnet-leak guard (assert at runtime) 🟡
- **Delivers:** a hard runtime assertion that no socket is ever opened outside
  Tor in a release build; `--dial-tcp`/`--listen-tcp` compiled out of release.
- **State:** audit found no clearnet path in prod, but the test-mode TCP flags
  exist in the same binary.
- **Effort:** low.

---

## Layer 2 — Hub / relay metadata (THE CORE — this is where "untrackable" is won or lost)

### A2.1 — ASC: Anonymous Subscription Credentials (token-only, unlinkable) 🔴 — **KEYSTONE**
- **Delivers:** the hub authorizes a subscription by a **zero-knowledge proof of
  entitlement**, not by authenticating a long-term identity. Two subscriptions
  by the same user are **unlinkable**; the hub learns nothing that clusters a
  user's activity.
- **Closes:** **D-1 — the single biggest tracking vector**, at the root. Today
  the hub authenticates the long-term identity key as the Noise static
  (`hub_client.rs:149`) and the signed SUBSCRIBE carries the long-term Ed25519
  (`routing.rs:119`), so the operator links everything. The `--ephemeral-noise-static`
  flag (`onyxd/main.rs:119`) is opt-in *and* insufficient (the SUBSCRIBE
  signature re-links).
- **How:** keyed-verification anonymous credentials (KVAC, the Signal private-group
  family) issued per group/epoch from the MLS exporter secret; single-show,
  rotated per epoch. Replace `encode_signed_subscribe` with a credential proof.
- **Make ephemeral Noise static the DEFAULT as the interim step before ASC lands.**
- **Use signal-zkgroup-style primitives. Do not invent the credential scheme.**
- **Effort:** high. **Priority: 2 (the most important feature in this document).**

### A2.2 — Oblivious inbox retrieval (kill the presence oracle) 🔴
- **Delivers:** the hub learns neither *which* inbox a user reads nor *whether*
  they had mail.
- **Closes:** `introduction_inbox = BLAKE2b(public fingerprint)` (`routing.rs:86`)
  is a presence oracle — anyone holding your fingerprint can probe the hub to
  confirm you exist / are active.
- **How:** Tier 1 (cheaper): batched PIR (FrodoPIR / Spiral). Tier 2 (strongest):
  Oblivious Message Retrieval (Liu–Tromer). No mainstream messenger ships OMR —
  this would be a genuine first.
- **Effort:** high; gate behind a "paranoid" tier with honest latency/bandwidth cost.

### A2.3 — Sealed-sender for *ongoing* MLS app messages over the hub 🟡
- **Delivers:** every application message routed via the hub (not just bootstrap)
  is sealed-sender + per-epoch token, so the hub never sees a stable sender.
- **State:** bootstrap is sealed (T5.2); ongoing MLS-over-hub is the open T6.4.
- **Depends:** A2.1 (per-epoch tokens are the routing substrate).
- **Effort:** medium.

### A2.4 — Operator-provable "no linkable metadata retained" 🔴
- **Delivers:** the hub store provably holds nothing that links two routing-ids
  to one user, by construction — plus a test that asserts a seized hub DB yields
  no cross-id linkage. Turns "trust me" into a testable property.
- **Closes:** the operator-honesty question — lets you truthfully say "I have
  nothing linkable to hand over."
- **Depends:** A2.1.
- **Effort:** medium (mostly schema discipline + a regression test).

### A2.5 — Hub delivery off the serial path 🔴
- **Delivers:** a hostile/known intro-inbox can't stall delivery or burn CPU by
  forcing serial KEM-decap + join attempts.
- **Closes:** P-3 (`hub_client.rs:467` `on_deliver(...).await` inline+serial).
- **Effort:** medium.

---

## Layer 3 — Traffic analysis (timing / volume)

### A3.1 — Loopix-style mix cover (provable timing unlinkability) 🔴
- **Delivers:** Poisson cover + per-message exponential mix delay + loop/drop
  cover → a *provable* unlinkability bound against the hub, replacing the current
  opt-in, upstream-only, unmeasured constant-rate mode.
- **State:** `--constant-rate-ms` covers client→hub upstream only, opt-in
  (`onyxd/main.rs:110`); downstream + peer circuits uncovered.
- **How:** adopt the Loopix design end-to-end (client + a constant-rate hub for
  downstream). Make it the default for a "high" tier.
- **Effort:** medium-high; inherent latency cost — document honestly.

### A3.2 — Downstream (hub→client) constant-rate + peer-circuit cover 🔴
- **Closes:** THREAT_MODEL §8.2 #3 remaining half.
- **Depends:** A3.1.

### A3.3 — Real-circuit measurement harness 🔴
- **Delivers:** actually *measure* the "active vs idle is indistinguishable"
  claim on real Tor, instead of asserting it. Turns a claim into evidence.

---

## Layer 4 — Group / membership metadata

### A4.1 — Committer-authority model for rooms 🔴
- **Delivers:** only authorized members can add/remove; a rogue member can't
  silently rewrite the roster.
- **Closes:** G-2 (`mls.rs` — any member can issue Add/Remove; no role check).
- **Effort:** medium (application-layer policy over MLS).

### A4.2 — Membership unlinkability over the hub 🔴
- **Delivers:** the hub cannot learn group membership or correlate who joined a
  commit (epoch-boundary intersection).
- **Closes:** THREAT_MODEL §5 #3 (epoch-boundary intersection — currently "no
  ideal mitigation in v1").
- **Depends:** A2.1, A2.3. This is the hard, genuinely-novel research item:
  *MLS groups with practical membership metadata resistance.*
- **Effort:** high / research.

### A4.3 — Gossip partition resistance 🔴
- **Closes:** H-2 (forgeable `seen_by` → a peer-hub can selectively suppress a KP
  from propagating, `handler.rs:205`). Authenticate the loop-marker.
- **Effort:** medium.

---

## Layer 5 — Local / forensic (device seizure)

### A5.1 — Finish log redaction 🟡
- **State:** peer keys moved to `debug` (D-3 mostly closed) but own `.onion`
  (`lib.rs:861`), `local_fpr`, and `our_inbox_b32` still at `info`.
- **Delivers:** nothing self-identifying in the default on-disk log.
- **Effort:** low.

### A5.2 — Plausibly-deniable / duress vault 🔴
- **Delivers:** a duress passphrase opens a decoy vault; the real one is
  indistinguishable from random. Protects against coercion (N3).
- **State:** listed in ROADMAP §4.
- **Effort:** medium-high.

### A5.3 — Deniable MLS authentication 🔴
- **Delivers:** a recipient is convinced of authorship but **cannot prove it to
  a third party** (closes the §6 non-deniability gap).
- **How:** designated-verifier / deniable authentication layered under the MLS
  credential. Active research area — most novel, highest risk; do last.
- **Effort:** high / research.

### A5.4 — Memory-locking (no-swap) + broader zeroization 🟡
- **State:** zeroization broad (T-zeroize-audit); add `mlock` of key pages.

---

## Layer 6 — Assurance (so the claims are believable)

### A6.1 — Reproducible builds + signed releases 🟡 (signing done, repro not)
### A6.2 — Property/fuzz tests for every untrackability invariant 🟡
- e.g. "two subscriptions are unlinkable", "seized hub DB has no cross-id link",
  "no log line contains a fingerprint/onion at info".
### A6.3 — External security + anonymity audit 🔴 — *the most important missing thing.*
### A6.4 — Identity↔onion binding (or formally drop the claim) 🔴
- **Closes:** D-4 — docs say onion == fingerprint; code generates a random HS key
  (`tor.rs:177`). Either implement the `HsIdKeypair` importer or delete the claim
  everywhere so users don't reason from a false model.

---

## Recommended execution order (the critical path to the North Star)

1. **A0.1 PAKE contact** — MITM-proof first contact (low effort, closes T-2 properly).
2. **A2.1 ASC / token-only subscriptions** — the keystone; makes the hub unable to
   link a user. Ship ephemeral-static-by-default as the interim.
3. **A2.3 sealed-sender ongoing messages** + **A2.4 provable-no-metadata** — so the
   operator genuinely holds nothing linkable.
4. **A3.1 Loopix cover (default)** — provable timing unlinkability.
5. **A2.2 oblivious inbox** — kill the presence oracle.
6. **A4.2 membership unlinkability** — the hard, novel one; the real research prize.
7. Cleanups in parallel: A0.2, A0.3, A2.5, A4.1, A4.3, A5.1.
8. Assurance throughout: A6.2 tests; A6.3 external audit before any "secure" claim.

**The honest gate:** until A2.1 lands and is the default, Onyx cannot truthfully
say "no one can track you" — the hub can, today, by design. That item is the
difference between the marketing and the math.

---

## Hard rules for everything above
- **Never invent crypto.** Use vetted implementations (zkgroup-style KVAC, CPace,
  published PIR/OMR libs, openmls). Novel *integration* is the goal; novel
  *primitives* are how anonymity tools get silently broken.
- **Default to safe.** An opt-in anonymity feature protects almost no one. If a
  protection isn't on by default, it doesn't count toward the North Star.
- **Measure, don't assert.** Every unlinkability claim needs a test or a
  measurement, or it stays marked 🟡.
