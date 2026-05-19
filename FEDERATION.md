# Hub Federation (T8.3) — Design Doc

> **Status: design phase.** No code yet. This document is the prerequisite to writing any of T8.3.b through T8.3.d. Open questions are flagged inline; resolve them before implementation begins. Last updated: 2026-05-19.

---

## 0. The honest framing

T8.1 gave us **client-side multi-hub redundancy** — each daemon fans out to N operator-chosen hubs and dedups duplicates via the recipient's replay guard. That's already a real federation property: a user with hubs A, B, C is resilient to any one hub dying.

What T8.1 did **not** give us: cross-hub user-to-user delivery. If alice publishes only to hub A and bob subscribes only to hub B, alice→bob never happens — A and B don't talk. Today the workaround is "everyone configures the same hubs" or "configure the union" (T8.2 invite manifests help discover that union).

T8.3 closes the gap properly: hubs gossip among themselves so a peer publishing to hub A reaches subscribers on hub B. This is *real* federation, in the Matrix/XMPP sense.

It is also **substantially more complex** than what we've done so far. This doc exists so we design it before we ship it.

**Goals (T8.3 must achieve):**
- A user publishing to hub A can be reached by a subscriber on hub B, given A and B have a configured peer link.
- KP fetches from hub B succeed for KPs published only to hub A.
- No new client-visible wire format. Existing daemons keep working unchanged.
- Existing single-hub deployments keep working unchanged (federation is opt-in per hub operator).

**Non-goals (T8.3 must NOT do):**
- Automatic peer-hub discovery (federation is **operator-configured only** — no DHT, no consensus, no auto-peering).
- Strong consistency. Eventual is fine; KPs are idempotent and queues are append-only.
- Replacing T8.1 client-side multi-hub. Federation **composes** with multi-hub — a user can publish to a single hub and let federation propagate, OR publish to N hubs directly. Both work; clients pick.
- Cross-organisation trust delegation. Each hub trusts only the peer hubs *its operator* configures.

---

## 1. Adversary model — what new risks does federation introduce?

We carry forward the existing hub adversaries (compromised, curious, hostile — see `THREAT_MODEL.md` §8.2 and the T7.3-sec.x line of work). Federation adds two new flavours:

### F1 — Hostile peer hub
You (hub A operator) configure hub B as a federation peer. B goes rogue: it tries to learn things or cause damage via the gossip channel.

  * **What B learns**: same as what B already learns from its own clients — routing-ids, opaque ciphertext, timing. Gossip doesn't reveal sender identity (still sealed) or message content. *No new disclosure*.
  * **What B can do**: poison A's KP directory by gossiping bogus KPs. **Defence: same as T7.3-sec** — every KP arriving via gossip MUST pass the ownership check (signing key derives the claimed routing id). The check already runs in `handler.rs::FRAME_KP_PUBLISH`; the gossip path uses the same code.
  * **What B cannot do**: forge envelopes (sealed-sender Ed25519 signature would fail at recipient), decrypt anything, see plaintext.

### F2 — Gossip-loop amplification
Hub A→B→C→A forwards the same envelope forever, exhausting bandwidth.

  * **Defence: per-message TTL or seen-by set in the gossip envelope header**. See §3.

---

## 2. Wire protocol

### 2.1 Connection establishment

Each hub-pair link is a **standard Noise XK session**, the same protocol clients use. The "client" role in the handshake is the hub initiating the link; the "server" role is the hub accepting it. Both sides know each other's static X25519 pubkey via operator config (analogous to `--hub-pubkey` for clients).

  * **Why reuse**: the protocol is already implemented, audited (well, "we've stared at it" — see SECURITY.md), and well-understood. New wire-level handshake = new attack surface.
  * **Authentication identity**: each hub's existing `vault.db`-held X25519 identity. No new keys.
  * **Reconnect**: same exponential backoff loop the daemon's hub-client uses.

**Open question Q1**: should each hub-pair use one connection or one-per-direction? Single-direction makes message origin clear (always "from the side that opened"); bidirectional saves a connection. **Recommendation: single direction**, hub A connects to hub B AND hub B connects to hub A as separate sessions. Simpler, mirrors how clients already work.

### 2.2 Frame types

The simplest design **reuses existing client frames** for gossip:

  * `FRAME_KP_PUBLISH` — hub A receives a KP from a client, forwards it as `FRAME_KP_PUBLISH` to each peer hub. Peer hub runs the ownership check, stores. Idempotent.
  * `FRAME_DELIVER` — hub A receives an envelope for routing-id X, has no local subscriber for X, forwards as `FRAME_DELIVER` to peer hubs that *might* have a subscriber. (See §3 for "might.")

**Open question Q2**: do we need a new `FRAME_GOSSIP_DELIVER` wrapping `FRAME_DELIVER` to carry the seen-by set / TTL? Or can we extend the existing DELIVER payload (16-byte routing-id prefix + body) with a TTL byte? **Recommendation: new outer frame**, because piggy-backing on DELIVER's payload format would require versioning that doesn't exist today. Cleaner to add `FRAME_GOSSIP_PUBLISH` and `FRAME_GOSSIP_DELIVER` with the loop-prevention header.

### 2.3 New frame format (draft)

```
FRAME_GOSSIP_DELIVER (type = 0x80):
  ttl:           u8                  (decrement on hop; drop at 0)
  seen_by[16]:   u128 (BLAKE2b-128 of hub-pubkey, low 16B)
  inner_target:  [u8; 16]            (the recipient routing id)
  inner_body:    Vec<u8>             (the sealed envelope, byte-identical to client DELIVER body)

FRAME_GOSSIP_PUBLISH (type = 0x81):
  ttl:           u8
  seen_by[16]:   u128
  inner_target:  [u8; 16]            (publisher's routing id)
  inner_kp:      Vec<u8>             (TLS-serialised KeyPackage)
```

`seen_by` is a single hash representing "this gossip message has been through that hub." On receive, hub C:
1. Decrement `ttl`. If zero, drop.
2. Check `seen_by`: if it equals my own hub-pubkey-hash, this is a loop — drop.
3. Process the inner message (own ownership check for KP, own queue/deliver for envelopes).
4. Forward to my own peer hubs **other than the one I received it from**, with `seen_by` set to *my* hash.

**Open question Q3**: single `seen_by` (16 bytes, tracks last hop) vs full path (every hop, grows linearly). Single is simpler + smaller; full path detects all loops, not just immediate ones. **Recommendation: single seen_by + small TTL (e.g., 3)**. With operator-configured topologies of ≤3-5 peer hubs, TTL=3 is enough; if not, operators reconfigure or we add full path later.

---

## 3. Gossip semantics

### 3.1 KP gossip

On `FRAME_KP_PUBLISH` from a client:
1. Run T7.3-sec ownership check (existing).
2. Store locally (existing).
3. **NEW**: wrap as `FRAME_GOSSIP_PUBLISH` with `ttl=3`, `seen_by=H(my-pubkey)`, forward to every peer hub.

On `FRAME_GOSSIP_PUBLISH` from a peer hub:
1. Check `seen_by != H(my-pubkey)` (drop on loop).
2. Decrement `ttl`; drop if zero.
3. Run T7.3-sec ownership check (gossip MUST be authenticated to the same standard as client publish — F1 defence).
4. Store locally.
5. Forward to every peer hub **other than the source**, with updated `seen_by` and `ttl-1`.

KPs are idempotent (UPSERT). Re-receiving the same KP via a different gossip path is fine.

### 3.2 Queue gossip

This is harder. Two modes:

**Mode A (eager)**: forward every received envelope to every peer hub, even if I have a local subscriber. Lets peer hubs queue for their own potential late-arriving subscribers.

**Mode B (lazy)**: only forward envelopes that I cannot deliver locally (no subscriber). My peer hubs might have one.

  * **Mode A pro**: stronger eventual consistency. If bob is on hub B and hub B happens to be down when alice publishes to hub A, hub C (which also peers with B) holds the envelope for B to pick up on recovery.
  * **Mode A con**: 3× bandwidth for the typical "everyone's on one hub" case.
  * **Mode B pro**: minimal bandwidth.
  * **Mode B con**: if hub B comes online *after* hub A has delivered to local subscribers, B has no record and bob's other-hub subscription misses.

**Recommendation: Mode B for v0**, with explicit operator-flag option to switch to Mode A. Most deployments are small; lazy is cheaper. Operators running high-availability federations can opt into eager.

**Open question Q4**: should the gossiped envelope go through the local queue's GC + the recipient's replay guard? **Yes** — the gossip envelope is byte-identical to the original DELIVER body, so the recipient's BLAKE2b-128 hash of body bytes catches it. **No new dedup logic needed** (same elegant property as T8.1 multi-hub fan-out).

### 3.3 What does NOT gossip

  * **SUBSCRIBE** — connection-state, ephemeral. A subscriber on hub A is invisible to hub B by design (privacy property — hubs don't disclose their subscribers).
  * **FETCH_KP responses** — fetch is request-driven, not push. If bob's daemon asks hub B for alice's KP and B doesn't have it locally, B does **not** ask peer hubs (would amplify fetch storms; the client-side T8.1 multi-hub fetch handles this at the right layer — client asks each of its hubs in order).

---

## 4. Operator surface

New flag on `onyx-hub`:

```
--peer-hub onion:port,b32pubkey    # repeatable
```

Each `--peer-hub` opens an outbound Noise XK session to that hub on startup, reconnects on disconnect with backoff. The hub also accepts inbound peer-hub connections (same Tor hidden service, same Noise listener — distinguished by the authenticated peer-pubkey matching one of the operator-configured peer hubs).

**Question Q5**: how does the hub *know* an inbound is a peer hub vs a client? **Recommendation: explicit operator allowlist.** A peer hub's pubkey is `--peer-hub`-configured; any inbound Noise session whose peer-pubkey matches that list is treated as a peer hub. Anything else is a client. No protocol distinction needed; identity decides role.

**Default**: zero peer hubs configured → no federation, identical to pre-T8.3 behaviour. Opt-in per hub operator.

---

## 5. Threat-model deltas

New entries to add to `THREAT_MODEL.md` §8.2 when T8.3.b lands:

  * **Hostile peer hub** (F1 above): defended by reusing T7.3-sec ownership check on every gossiped KP. Verified by adding `peer_hub_kp_gossip_rejects_mismatch` test.
  * **Gossip loop amplification** (F2 above): defended by TTL + seen_by. Verified by `gossip_loop_terminates_within_ttl` test.
  * **Gossip-tier traffic-analysis amplification**: a passive observer of multiple hubs sees the same envelope traverse multiple peer-hub links. Already-public information (the envelope is encrypted); reveals "these hubs are federated" but that's by design (operator-public config). No new disclosure beyond "user X published to hub A and the envelope flowed to hubs B, C" — same information any user of any of those hubs could already infer from delivery patterns.

No new adversary class. Federation is a connectivity property, not a trust transfer.

---

## 6. Slice plan

If this design holds up to review, implement in four slices:

### T8.3.b — minimum viable hub link (1 session, ~3 hr)
  * `--peer-hub` flag in `onyx-hub`
  * Outbound Noise XK session per peer hub, reconnect-with-backoff loop
  * Inbound peer-hub recognition: when a Noise session authenticates with a pubkey on the `--peer-hub` allowlist, mark as peer rather than client
  * `FRAME_GOSSIP_PUBLISH` only (KP gossip)
  * Tests: two-hub local-TCP smoke (no Tor) — hub A receives KP via client, hub B holds peer-hub session, KP appears in B's directory

### T8.3.c — queue gossip (Mode B, lazy) (~3 hr)
  * `FRAME_GOSSIP_DELIVER` with TTL + seen_by
  * Hub forwards envelopes to peer hubs only when no local subscriber
  * Tests: alice on hub A publishes for bob; bob subscribes on hub B; envelope arrives via federation

### T8.3.d — loop prevention hardening + eager-mode opt-in (~2 hr)
  * Loop-prevention test (`gossip_loop_terminates_within_ttl`)
  * `--gossip-mode eager|lazy` flag
  * Tests: 3-hub triangle topology with loop attempt

### T8.3.e — docs + THREAT_MODEL update (~1 hr)
  * Update `THREAT_MODEL.md` §8.2 with F1 and F2
  * Update `ANONYMITY.md` §3 with federation notes
  * Update `ROADMAP.md`: T8.3 → done

Total: ~9 hours of focused implementation, spread over 4 commit slices. **Not a one-shot.**

---

## 7. Open questions (block T8.3.b until resolved)

  * **Q1**: single-direction vs bidirectional hub-pair connections? *Recommendation: single-direction, two sessions per pair.*
  * **Q2**: new gossip frame types or extend DELIVER/KP_PUBLISH? *Recommendation: new frame types (FRAME_GOSSIP_DELIVER 0x80, FRAME_GOSSIP_PUBLISH 0x81).*
  * **Q3**: single seen_by vs full path? *Recommendation: single seen_by + TTL=3 for v0.*
  * **Q4**: replay-guard handles gossip duplicates? *Yes — gossiped envelope bytes are byte-identical; existing T7.3-sec.2 guard catches them. No new logic.*
  * **Q5**: how does hub distinguish inbound peer-hub from client? *Recommendation: by authenticated Noise-XK peer-pubkey matching operator's `--peer-hub` allowlist.*

These are recommendations, not decisions. Review + push back before T8.3.b begins.

---

## 8. What this design intentionally defers

  * **Auto-discovery of peer hubs** — operator-configured only in v0. Discovery is T8.4 territory.
  * **Strong consistency / quorum reads** — out of scope; eventual is fine here.
  * **Cross-organisation trust delegation** — each hub trusts only what its operator configures. No transitive trust.
  * **Gossip flow control / per-peer rate limiting** — T8.x-ratelimit's per-connection bucket applies; peer-hub connections will hit it just like client connections. May need a separate peer-hub rate cap; defer until measured.
  * **Garbage collection of stale seen_by state** — not needed; seen_by is per-message, ephemeral.

---

## 9. Related documents

  * **`SECURITY.md`** — overall security policy.
  * **`THREAT_MODEL.md`** — formal threat model; §8.2 will gain F1 and F2.
  * **`ANONYMITY.md`** — what Onyx hides; §3 will note federation doesn't change the disclosure surface.
  * **`ROADMAP.md`** — T8.3 currently "later"; this doc moves it to "in design."
  * **`CHANGELOG.md`** — T8.0, T8.1, T8.2, T8.2-check, T8.0.gc, T8.x-ratelimit (all 2026-05-19) — the foundation T8.3 builds on.

---

## 10. Decision log

  * **2026-05-19** — Design doc drafted. No implementation yet. Awaiting review of §7 open questions before T8.3.b begins.
