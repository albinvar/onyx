# ADR: Onyx trust architecture — closing the four structural gaps

**Status:** Proposed (T-4 implemented; T-1 to T-3 designed, not built)
**Date:** 2026-11-11
**Deciders:** project maintainer
**Context docs:** `THREAT_MODEL.md` §8.6 (residuals E-1, O-1, W-1, V-3), `ANONYMITY.md`, `ROTATION.md`

## Context

The 2026-11 audit fixed the exploitable bugs. What remains are four gaps
that are not bugs: they are places where the *design* asks the user to
trust something they should not have to. This record states the target —
"the strongest trust this architecture can reach" — in concrete terms and
picks one approach per gap.

The trust principle Onyx is aiming for:

> **No party other than the two people talking should be able to learn
> that they talk, when, or how much — not a relay, not the network, not a
> former contact, and not whoever later holds either device.**

Measured against that, four things fall short today:

| # | Gap | Who learns what |
|---|-----|-----------------|
| T-1 | One permanent onion address is shared with every contact | Any current or former contact (or anyone they pass it to) can probe whether you are online, forever, and can target the service for guard discovery. You cannot revoke one contact without changing the address for all. |
| T-2 | Sealed envelopes are encrypted to a static KEM key | A relay that records traffic plus a later device compromise reveals the sender of every recorded envelope, and the content of first-contact messages. Forward secrecy holds for the sender only. |
| T-3 | The vault seals keys and message text but not the social graph | Whoever holds the file — without the passphrase — sees who you talk to, when, which rooms you are in, and can forge "verified" on a contact. |
| T-4 | Anyone who can reach your inbox can put you in a room | A stranger chooses a room name and membership for you with no consent. |

Constraints that shape every option: Tor-only (no clearnet path may
appear); relays are untrusted and must stay blind; one maintainer, so each
change has to be small enough to review and test in isolation; existing
users must not lose contacts or history.

## Decision

1. **T-1 → per-contact onion services, with Tor client authorization as
   the first step.**
2. **T-2 → a rotating KEM key with an overlap window, advertised inside
   existing authenticated channels.**
3. **T-3 → whole-database encryption (SQLCipher), keyed from the existing
   Argon2id output.**
4. **T-4 → room invitations from non-contacts are held for explicit
   acceptance.** *(Implemented with this record.)*

## Options considered

### T-1 — Reachability without a shared permanent address

**Option A: Tor client authorization on the single onion service.**
Each contact gets their own x25519 client-auth key; the service descriptor
is encrypted to the set of authorized keys. Someone without a key cannot
even fetch the descriptor, so they cannot tell whether the service is up.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium — Arti's `restricted discovery` support; key distribution rides the connect code |
| Revocation | Yes: drop a contact's key and republish |
| Hides presence from ex-contacts | Yes, after revocation |
| Hides that two contacts know the same person | No — they hold the same onion address |
| Scale | Descriptor size bounds authorized clients (order of a few hundred) |

**Option B: one onion service per contact.**
Each contact is given a different address. Addresses are unlinkable to
each other and to the identity.

| Dimension | Assessment |
|-----------|------------|
| Complexity | High — many services to publish and keep alive; more circuits, more guard exposure per service |
| Revocation | Yes: stop publishing that service |
| Hides presence from ex-contacts | Yes |
| Hides that two contacts know the same person | Yes |
| Scale | Each service costs introduction circuits; tens are fine, hundreds are not |

**Option C: status quo plus address rotation.**
Rotate the single address on a schedule and push the new one to current
contacts over existing sessions.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Low |
| Revocation | Coarse — rotation cuts off everyone who is not told |
| Hides presence from ex-contacts | Only after the next rotation |
| Hides shared-contact linkage | No |

**Choice: A first, B for contacts the user marks as sensitive.** A removes
the worst property (anyone with the address can watch your uptime) at
moderate cost and with real revocation. B is strictly stronger on
linkability but its per-service cost makes it the wrong default; offering
it per contact puts the cost where the user asks for it. C is kept only as
the migration vehicle: the first authorized descriptor is published at a
*new* address so the old, widely-known one stops answering.

### T-2 — Forward secrecy for the recipient of a sealed envelope

**Option A: rotating KEM key with overlap.**
Generate a new hybrid KEM keypair every N days. Keep the previous key for
one overlap window so envelopes sealed to it still open, then delete it.
The current public key is advertised where it already is: in signed
invites, in the in-session `KemAdvertisement`, and in the room roster.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium — key store holds (current, previous); senders use the freshest key they hold |
| Forward secrecy | Bounded: a compromise exposes at most one rotation period + overlap of recorded envelopes |
| Offline tolerance | Recipient offline longer than the overlap loses envelopes sealed to the deleted key — the sender must re-send (delivery receipts already exist for DMs) |
| Wire change | None for the envelope; the advertisement already exists |

**Option B: one-time prekeys published to the relay (Signal-style).**
The recipient uploads a batch of single-use KEM public keys; each sender
consumes one.

| Dimension | Assessment |
|-----------|------------|
| Complexity | High — relay stores and hands out prekeys; exhaustion and replay handling |
| Forward secrecy | Per message |
| Metadata cost | The relay learns each fetch; publishing prekeys requires a stable identity at the relay, which the private default deliberately does not have |

**Option C: no envelope layer for established contacts — MLS only.**
Route relayed traffic as bare MLS ciphertext with no sender-identifying
outer layer.

| Dimension | Assessment |
|-----------|------------|
| Forward secrecy | MLS's own |
| Problem | First contact still needs the envelope; and MLS framing exposes the group id to the relay |

**Choice: A.** B is the stronger primitive but contradicts the
private-by-default relay posture (no stable identity at the hub) and
doubles the relay's role. A reaches "bounded exposure" with no new relay
trust and no wire change, and its one failure mode — an envelope sealed to
an expired key — is recoverable by re-sending. Recommended parameters:
rotate every 7 days, keep the previous key for 14.

### T-3 — A vault that reveals nothing without the passphrase

**Option A: SQLCipher (whole-database encryption).**

| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium — `rusqlite` supports it via the `bundled-sqlcipher` feature; one-time migration of existing files |
| Coverage | Everything: schema, row counts, timestamps, the contact graph |
| Integrity | Per-page HMAC — closes blob swapping, rollback of single rows, and forged pin/verified/admin state |
| Cost | A C dependency with its own build requirements (affects the static musl target); the per-row AEAD becomes redundant and can be retired later |

**Option B: seal the remaining columns one by one, and add a MAC over the
trust tables.**

| Dimension | Assessment |
|-----------|------------|
| Complexity | Low per column, high in total; every new column is a chance to forget one (the rekey bug was exactly this) |
| Coverage | Never complete — row counts, order and timestamps stay visible; lookups by sealed keys need blind indexes |

**Choice: A.** B is the path that produced the current state. The
migration is the risky part and must be done with a backup-verify-swap
sequence and the vault lock held; it is the one item here that should not
be attempted unattended on a vault that matters.

### T-4 — Consent before joining

**Option A: hold room invitations from non-contacts until the user
accepts.** The Welcome is stored sealed; nothing is joined, no room is
created, no subscription is announced.

**Option B: only accept invitations from contacts; drop the rest.**
Simpler, but silently loses legitimate invitations from someone you have
not talked to directly.

**Option C: status quo** (join everything that verifies).

**Choice: A.** Invitations from an existing, unflagged contact are joined
automatically as before — that is the flow people actually use, and the
inviter is someone the user chose to talk to. Everything else waits.

## Trade-off analysis

- **Reachability versus anonymity.** Every gain in T-1 costs first-contact
  convenience: a contact must be handed a key (A) or an address made for
  them (B). The connect code already carries exactly this kind of
  material, so the user-visible change is small — the code becomes
  per-contact.
- **Forward secrecy versus offline tolerance.** T-2's overlap window is
  the dial. Longer overlap tolerates longer absences and exposes more on
  compromise.
- **Assurance versus portability.** SQLCipher brings a C dependency into a
  build that is otherwise pure Rust plus bundled SQLite. That is accepted
  because the alternative leaves the social graph readable.
- **Consent versus friction.** T-4 adds one decision per invitation from a
  stranger and none for invitations from contacts.

## Consequences

- Easier: revoking a single contact; telling a user truthfully that a
  seized vault reveals nothing; reasoning about what a relay recording
  buys an attacker.
- Harder: the connect flow carries per-contact secrets; key and address
  lifetimes become state that must be migrated and backed up.
- To revisit: whether per-contact onions (T-1 B) should become the default
  once Arti's multi-service cost is measured; whether T-2's parameters
  should be user-configurable.

## Action items

1. [x] T-4: hold non-contact room invitations for acceptance (daemon,
   API, CLI, tests).
2. [ ] T-2: `(current, previous)` KEM key store; rotation task; senders
   prefer the freshest advertised key; recipient tries both.
3. [ ] T-1 A: Arti restricted-discovery; per-contact client-auth key in
   the connect code; revocation command; migrate to a new address.
4. [ ] T-3: SQLCipher behind a feature flag; backup-verify-swap migration
   under the vault lock; retire per-row sealing afterwards.
5. [ ] T-1 B: per-contact onion for contacts marked sensitive.
6. [ ] External audit — unchanged as the largest open item; none of the
   above substitutes for it.
