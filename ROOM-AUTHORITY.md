# G-2 design — MLS room admin / committer-authority model

**Status:** design doc for review (fortification Phase 3, F3.3). **No code
yet.** G-2 / audit MED-2: *any* room member can currently add or remove
*any* member. This doc explains why that's inherent to plain MLS, what an
authority layer can and cannot achieve, and a recommended shippable MVP
with its honest residual.

Companion to `THREAT_MODEL.md` §8.4 (G-2 row).

---

## §0 Status: IMPLEMENTED (F3.3, 2026-06-02)

The MVP below is shipped. Each room has an **admin set** (seeded with the
creator) **propagated to every member in the Welcome** (`MlsWelcome.admins`,
covered by the sealed-sender signature). Enforcement is on both sides:
**send** (`handle_invite_to_room`/`handle_remove_from_room` refuse when the
local identity isn't an admin) and **receive**
(`MlsGroupState::process_incoming_with_authority` rejects — does **not**
merge — a membership-changing commit from a non-admin; the daemon resolves
the committer fingerprint against the room's admin set). Empty admin set
(legacy rooms) = unrestricted (back-compat). Tests:
`mls::authority_rejects_unauthorized_membership_commit`,
`storage::room_admins_authority_semantics`. The **inherent residual** stands
(§2.3): a patched client can still emit a valid commit and fork honest
members (they reject + warn, no auto-recovery); GroupContext-authenticated
admin sets (B1) and fork recovery (Option C) remain deferred.

## §1 Current state (no authority at all)

- **Add:** `MlsGroupState::invite()` → `group.add_members()` (mls.rs). Daemon
  path `handle_invite_to_room()` validates only that the KP signature matches
  the claimed fingerprint and that the room exists. **No check on who is
  adding.**
- **Remove:** `MlsGroupState::remove_member()` → `group.remove_members()`.
  Daemon path `handle_remove_from_room()` checks only that the target is a
  current member and the caller isn't removing themselves. **No authority
  check.**
- **Creation:** `create_group()` records no admin/owner/creator role; the
  `rooms` table has `members_b32` but **no role column**. The creator is
  just the vault row's `identity_id`, with no MLS-layer privilege.
- **On receive:** `process_incoming_with_sender()` accepts and merges any
  commit openmls validates cryptographically. The committer *is* attributable
  to a fingerprint (leaf `signature_key` == fingerprint), but **Onyx never
  gates on it.**
- **Unused MLS facilities:** GroupContext extensions / `RequiredCapabilities`
  exist in openmls 0.8 but Onyx populates none. (MLS RFC 9420 deliberately
  has **no** built-in role-based access control.)

So today every member is fully equal: anyone can invite a stranger or evict
anyone else, and all honest clients will accept it.

---

## §2 What an authority layer can and cannot do (the inherent limit)

MLS gives **cryptographic group membership** + proof of **who** committed. It
does **not** give RBAC. Layering authority means three things, and the third
is the hard one:

1. **Agree on the policy** — who the admins are. Must be authenticated and
   identical for all members, or they'll disagree about what's authorized.
2. **Enforce on receive** — each honest member checks the committer is
   authorized and **rejects** an unauthorized commit (refuses to merge it).
3. **Survive the resulting divergence.** Here's the catch: you cannot
   *prevent* a member from broadcasting a commit — openmls will sign it and
   it's cryptographically valid. You can only make honest members **reject**
   it. But a rejected commit is a **fork**: the rogue committer (and anyone
   who wrongly accepted it) advances their ratchet; honest rejecters don't.
   The group's epoch/tree diverges. Plain MLS has no built-in fork recovery.

So an authority layer's realistic guarantee is: *honest clients ignore an
unauthorized membership change* (the rogue's sockpuppet never appears in
honest members' rosters; an unauthorized eviction is not honored by honest
members). It is **not**: *the rogue is cryptographically prevented from
committing.* That distinction is the whole MED-2 difficulty.

---

## §3 Options

### Option A — creator-only authority (simplest)
Record the creator's fingerprint; only the creator may add/remove; honest
members reject add/remove commits from anyone else.
- **Pros:** trivial policy, no agreement problem (creator is known from
  group creation), closes the "any member can kick anyone" case for honest
  clients.
- **Cons:** single point — if the creator is offline/lost, the room is frozen
  (no membership changes ever again). No delegation. Too brittle for real use.

### Option B — admin set (recommended MVP)
Maintain a **set of admin fingerprints** for the room. Seed = creator. Only
admins may add/remove (incl. promoting/demoting admins). Two enforcement
points:
- **Send-side (honest-client gate):** the daemon refuses to *issue* an
  add/remove commit if we're not an admin. Closes the accidental/non-malicious
  case immediately and drives the UI ("you're not an admin").
- **Receive-side (policy enforcement):** on an incoming add/remove commit,
  resolve the committer's fingerprint (walk the tree by leaf) and **reject
  the commit if the committer ∉ admin set**, surfacing a visible warning.
- **Where the admin set lives:** two sub-choices —
  - **B1 (authenticated, harder):** a **GroupContext extension** carrying the
    admin set, changed only via commits — MLS authenticates it and all
    members provably agree. Requires registering a custom extension +
    `RequiredCapabilities` in openmls 0.8 (real but bounded work).
  - **B2 (app-layer, simpler):** store the admin set in the `rooms` record,
    seeded at creation and updated via an **in-band signed admin-change app
    message**. Less elegant (agreement is app-enforced, not MLS-enforced) but
    far smaller; adequate for v0 honest-client enforcement.
- **Residual (document loudly):** a malicious admin, or a member who patches
  their client to ignore the policy, can still broadcast an unauthorized
  commit and **fork** honest members (see §2.3). Honest members reject +
  warn; full fork *recovery* (re-merge / re-key the honest subset) is **out
  of scope** for the MVP.

### Option C — full fork-resistant authority (out of scope)
Detect divergence, re-key the honest subset into a fresh group, migrate
state. This is the "real" solution to §2.3 and is a large protocol effort
(arguably its own project). **Defer.**

---

## §3.5 Implementation finding (2026-06-02): the send-gate needs propagation

Starting the F3.3a build surfaced a correction to the "ship the send-gate
first" plan. A send-side gate checks *is the local identity an admin?* — but
that only bites if the client **knows the admin set**. If admins live in a
local-only `room_admins` table seeded with the creator (the simplest B2),
then:
- the **creator's** client knows it (and the creator is the admin anyway, so
  the gate never refuses them), and
- a **Welcome-joined** member has **no admin set locally** (it isn't carried
  in the Welcome today), so their gate **fails open** — they can still
  invite/remove.

Net: the send-gate **alone, without propagation, restricts effectively
nobody.** For it to bind, the admin set must be **shared with every member** —
carried in the invite/Welcome payload (small protocol-format change to
`BootstrapPayload::MlsWelcome` + the invite path) or as an MLS GroupContext
extension (B1). So a *useful* G-2 MVP is **propagation + send-gate +
receive-gate**, i.e. the full F3.3 — not a quick first slice. This is logged
so the build is scoped honestly rather than shipping a no-op gate.

## §4 Recommendation

1. **Ship Option B2 as the F3.3 MVP** — admin set in the room record (seed:
   creator), **send-side refusal** when not an admin, **receive-side
   rejection + warning** of commits from non-admins, and a signed in-band
   admin-change message to grow/shrink the set. This delivers the property
   users actually expect ("randos can't kick people / add strangers") for the
   honest-client case, which is the common real-world threat (a careless or
   confused member, not a cryptographer patching their client).
2. **Consider B1 (GroupContext extension) as a follow-up** once B2's policy
   shape is proven — it upgrades the admin-set agreement from app-enforced to
   MLS-authenticated.
3. **Document the fork residual** in THREAT_MODEL §8.4: an authorized-but-
   malicious admin, or a member running a patched client, can still force a
   divergence; honest clients reject + warn but do not auto-recover. Full
   fork recovery (Option C) stays deferred.
4. **Reject Option A** (creator-only is too brittle).

### Honest framing
G-2 cannot be "fixed" the way a LOW audit item can — MLS has no RBAC and you
cannot stop a member from emitting a valid commit. What we *can* ship makes
honest clients enforce a sane policy (closing the realistic threat) and makes
violations *visible*; it does not make them *impossible*. That's the true
ceiling for an MLS-based group without a fork-recovery protocol.

---

## §5 Proposed slices

1. **F3.3a — admin set + send-side gate.** `rooms` record gains an admin set
   (seed: creator fingerprint). `handle_invite_to_room`/`handle_remove_from_room`
   refuse when the local identity isn't an admin. Tests: non-admin invite/
   remove is refused; admin's is allowed.
2. **F3.3b — receive-side enforcement.** On an incoming add/remove commit,
   resolve committer fingerprint and reject + warn if not an admin. Test: a
   commit forged from a non-admin leaf is not merged.
3. **F3.3c — admin-change message.** Signed in-band promote/demote; updates
   the room admin set. Test: round-trip + only-admin-can-promote.
4. **Deferred:** B1 (GroupContext-extension authenticated admin set) and C
   (fork recovery).

---

## §6 Open questions for review

1. **MVP scope:** ship just F3.3a (send-side gate — the cheap 80%) first and
   treat receive-side (F3.3b) as a fast-follow, or do a+b together (the
   send-gate alone is bypassable by a patched client, so b is what gives the
   real honest-client property)?
2. **Admin-set storage:** accept B2 (app-layer) for v0, or invest in B1
   (GroupContext extension) up front for MLS-authenticated agreement?
3. **Default policy:** creator is sole admin by default, or all initial
   members are admins (friendlier for small peer groups, weaker control)?
4. **Is G-2 worth doing now at all**, given the fork residual means it's a
   "make violations visible/honest-client-enforced," not "prevent" — or defer
   the whole thing until rooms have real multi-party adversarial use?
