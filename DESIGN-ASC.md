# DESIGN-ASC — Anonymous Subscription Credentials (A2.1 keystone)

> **Status: DESIGN PROPOSAL. No code. Review-gated.**
> This is the keystone anonymity feature (`ANONYMITY_ROADMAP.md` A2.1). It
> involves anonymous-credential cryptography. **I am not a cryptographer and
> this document is not a security proof.** It MUST be reviewed by someone with
> anonymous-credential expertise (ideally the same external audit tracked as
> A6.3) before any implementation begins. Per the roadmap's hard rules: we use
> only vetted primitives (no novel crypto), the result must be default-on to
> count, and every claim needs a test before it leaves "partial."

---

## 1. The problem A2.1 solves

A hub must be able to **authorize** a subscription — otherwise:

- anyone can subscribe to anyone's known introduction inbox and steal queued
  envelopes (the HIGH-1 attack, currently closed by a *signed* SUBSCRIBE that
  proves fingerprint ownership — `routing::decode_signed_subscribe` +
  `handler.rs` ownership check);
- anyone can register unbounded subscriptions to exhaust the hub (the A-2
  attack, currently bounded by `MAX_SUBSCRIBE_IDS_PER_FRAME` /
  `MAX_SUBSCRIPTIONS_PER_CONN` and the per-static-key rate limiter HIGH-3).

But **every** mechanism above authorizes by binding the action to a *stable
identity*: the signed SUBSCRIBE carries the long-term Ed25519 signing key (=
fingerprint); the rate limiter is keyed on the Noise static key. That is
exactly the linkage D-1 set out to remove.

D-1's resolution was to go **private by default**: ephemeral Noise static +
ephemeral SUBSCRIBE-signing key, no intro-inbox, no KP. That makes the
connection unlinkable — but it also makes it **unauthenticated**:

- the SUBSCRIBE proof is now signed by a throwaway key, so the HIGH-1
  ownership check is a no-op (private mode only subscribes to per-(room,epoch)
  session tokens, which are unguessable and self-authorizing, so this is
  *safe* today — but it does not generalize to "be reachable for first
  contact while staying unlinkable");
- the rate limiter resets every reconnect (documented residual).

**A2.1 is the missing third option: unlinkable AND authorized.** The hub
verifies "this subscriber holds a valid entitlement" without learning *which*
entitlement, and without being able to link two showings of it.

This is precisely the problem **keyed-verification anonymous credentials
(KVAC)** were designed for, and it is deployed in production at Signal for
group membership. We are doing *novel integration of a vetted primitive*, not
inventing crypto.

## 2. Why KVAC (not the alternatives)

| Option | Verdict |
|--------|---------|
| **Plain blind signatures (RSA/BLS)** | Workable for "one anonymous token per action," but pairing-based or large; weaker attribute support. |
| **CL / BBS+ anonymous credentials** | Full-featured but pairing-heavy; bigger dependency + audit surface. |
| **KVAC (algebraic-MAC credentials, Chase–Meiklejohn–Zaverucha 2014; Signal's `zkgroup`)** | **Chosen.** Ristretto255 / curve25519 only (no pairings) — same curve family Onyx already uses via `curve25519-dalek`. Issuer == verifier (the hub), which is exactly our trust shape (the hub issues and later verifies). Battle-tested in `zkgroup`. |
| **Novel construction** | Forbidden by hard-rule #1. |

KVAC fits because in Onyx **the same party (the hub) both issues and verifies**
— KVAC's defining feature (a secret-key MAC the issuer can verify, vs a public
signature) is the natural match, and avoids pairing crypto entirely.

## 3. The protocol (three phases)

Notation: the hub holds a KVAC issuer secret key `sk_H` (per-hub, persisted in
its vault next to its identity key); `pk_H` is the public issuer params,
distributed in the invite/hub-config alongside the hub's existing Noise pubkey.

### Phase 1 — Enrollment (once per entitlement, linkable-but-rare)

The point where the user proves entitlement to *exist on this hub at all*.
This is the **only** linkable step, and it is deliberately decoupled in time
from any subscription so it cannot be correlated with activity.

- The user presents whatever the hub's admission policy requires. For the v0
  bootstrap hub this is likely **"anyone may enroll"** (open hub) — in which
  case enrollment is just "the hub blind-issues a credential to a fresh
  request." For an invite-only hub (A2.1 also unlocks the §8.2 #4 gap) it is
  "present a valid hub-invite token."
- The hub issues a KVAC credential over a **committed attribute**: a
  user-chosen random `cred_id` (blinded, so the hub never sees it) plus an
  `epoch_validity` range. Blind issuance = the hub signs a commitment without
  learning the value.
- Output: the user holds a credential `cred` on `(cred_id, validity)` that the
  hub can later verify but cannot link to this enrollment.

### Phase 2 — Show (every subscription, fully unlinkable)

Replaces today's `encode_signed_subscribe`. On each hub connection (recall:
the connection itself is already ephemeral-Noise per D-1):

- The client computes a **per-epoch pseudonym** `nym = PRF(cred_id, epoch)`
  and a zero-knowledge **show proof** that: (a) it holds a hub-issued
  credential on some `cred_id`, (b) `nym` is correctly derived from that
  `cred_id` for the current `epoch`, (c) the credential is within validity.
  The proof reveals **only** `nym` — not `cred_id`, not which enrollment.
- `nym` is stable within an epoch (so the hub can rate-limit and dedupe within
  the epoch) and unlinkable across epochs (so long-term tracking fails). This
  is the same shape as the existing `session_token(secret, index)` rotation,
  generalized from "per group" to "per credential."
- The SUBSCRIBE frame becomes: `nym ‖ show_proof ‖ ids`, bound to the Noise
  `handshake_hash` exactly as today (replay binding, unchanged).

### Phase 3 — Verify (hub side)

Replaces today's `decode_signed_subscribe` + ownership check:

- Verify the show proof against `pk_H` / `sk_H`. Reject if invalid.
- Rate-limit and cap **keyed on `nym`** instead of the Noise static key — so
  HIGH-3 / A-2 protections survive D-1 (the per-connection-reset residual is
  closed: a reconnect within the same epoch yields the *same* `nym`, so the
  bucket persists; across epochs it rotates, which is the intended unlinkable
  refresh).
- Ownership of a *known intro inbox* (HIGH-1): the credential's `cred_id` is
  bound at enrollment to the inbox the user is entitled to read, and the show
  proof proves "this `nym`'s credential is entitled to *these* ids" without
  revealing `cred_id`. (Exact predicate — equality of a committed inbox
  attribute to the requested id — is the part most needing expert review.)

## 4. What this closes / does not close

**Closes (when default-on):**
- The D-1 reachability re-linkage: a user can be reachable for first contact
  AND unlinkable, because the intro-inbox subscription is now authorized by an
  unlinkable credential instead of a fingerprint-bearing signature.
- The HIGH-3 per-connection-rate-reset residual (rate-limit keyed on `nym`).
- Unlocks invite-only hub registration (§8.2 #4) as the enrollment policy.

**Does NOT close (must stay honest):**
- **Enrollment linkage.** Phase 1 is linkable to *whatever the admission proof
  is*. For an open hub that's nothing; for invite-only it's the invite. We
  must document that the unlinkability is "across subscriptions," not "the hub
  never saw you enroll."
- **Presence via the inbox itself** — that's A2.2 (oblivious inbox); A2.1
  makes the *subscription* unlinkable but reading `H(fingerprint)` is still a
  probing oracle until A2.2.
- **Timing correlation** — A3.x.
- **Global passive adversary** — out of scope, as always.

## 5. Dependencies + surface

- New crate dep: a vetted ristretto255 KVAC implementation. Candidates to
  evaluate: `zkgroup`-derived crates, or `curve25519-dalek` + a reviewed KVAC
  layer. **No pairing libraries.** Decision deferred to the design review.
- `onyx-core`: new `asc` module (credential types, show/verify). Stays under
  `unsafe_code = "forbid"`.
- Wire: SUBSCRIBE frame format bumps (`nym ‖ proof ‖ ids`); needs a version
  byte so old/new hubs interoperate during rollout.
- Hub vault: persist `sk_H`; expose `pk_H` in hub config + invite `&hub=`.
- **Rollout:** ship behind the existing private-by-default; A2.1 becomes the
  authorization layer that lets `--first-contact-reachable` ALSO be private.
  Interim (already shipped): D-1 ephemeral-default.

## 6. Test plan (A6.2 obligation — no "done" without these)

1. **Unlinkability property test (adversarial):** the hub records every
   `(nym, ids, conn)` it sees across N epochs for one user; assert it cannot
   group them by user better than chance. Extends
   `rooms_e2e_private_mode_leaks_no_identity_to_hub`.
2. **Forgery test:** a client with no credential cannot produce a verifying
   show proof.
3. **Replay test:** a captured show proof from epoch e fails at epoch e+1 and
   on a different `handshake_hash` (binding unchanged from today).
4. **Rate-limit-survives-reconnect test:** same `nym` within an epoch keeps
   draining the same token bucket across reconnects (closes the HIGH-3
   residual — the concrete win we can measure).
5. **Cross-implementation KVAC test vectors** from the chosen library.

## 7. Open questions for the reviewer

1. KVAC library choice + whether issuer==verifier lets us drop any of the
   standard zero-knowledge show machinery.
2. The "entitled to *these* ids" predicate in Phase 3 — is committed-attribute
   equality the right construction, or does it leak via the id set itself?
3. Epoch length: short = more unlinkable but more enrollment-amortization
   pressure; long = better rate-limit continuity. What's the right default?
4. Does enrollment need to be over a *separate* Tor circuit from every show
   (A1.1 gives us per-connection isolation already — likely yes, enrollment on
   its own circuit, decoupled in time)?
5. Key rotation / revocation: how does the hub rotate `sk_H` without a flag
   day, and can a credential be revoked without re-linking?

---

*This is a proposal, not a plan of record. Implementation does not start until
this design has expert review sign-off. Until then, A2.1 stays `designing` in
`ANONYMITY_ROADMAP.md` and the honest claim remains: the hub can link a
reachable user today (D-1), and A2.1 is the math that fixes it.*
