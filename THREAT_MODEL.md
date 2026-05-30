# Onyx — Threat Model

**Version:** 0.2-draft (mirrors `DESIGN.md` §2 + §5.5 residual analysis)
**Audience:** users deciding whether Onyx fits their threat model, reviewers, future maintainers

Security is a relationship between a defense and an attacker, not a property a system "has." This document names the attackers Onyx defends against, the attackers it does not, the specific assets it protects, and the residual linkability it cannot eliminate.

If you need a property listed under "do not defend against," **Onyx is not the right tool for your situation.** That answer is more useful than a vague claim of safety.

---

## 1. Assets

In priority order:

1. **Message content** — the words people exchange.
2. **Identity linkage** — the connection between a pseudonymous Onyx identity and a real-world person.
3. **Social graph** — who talks to whom.
4. **Activity patterns** — when, how often, how much.
5. **Membership** — which rooms a user is in.
6. **Existence** — whether a given person uses Onyx at all.

---

## 2. Adversaries we defend against

### A1. Passive network observer
ISP, employer, café Wi-Fi, country-level firewall against a single user.
- **Sees:** encrypted Tor traffic.
- **Cannot:** identify peers, read content, determine destinations.
- **Defense:** Tor.

### A2. Hub server operator (including a malicious or coerced one)
- **Sees:** encrypted message blobs in transit and at rest in offline queues; pseudonymous routing identifiers (introduction inbox per recipient + rotating session tokens per active MLS group).
- **Cannot:** decrypt content; determine real-world identity; identify the sender of bootstrap messages (sealed-sender envelope).
- **Can observe:** coarse activity on a per-inbox basis over time (see §5 below).
- **Defense:** E2E (MLS) + sealed-sender bootstrap + rotating routing tokens.

### A3. Hub server attacker (someone who roots the hub)
- **Same view as A2**, plus the ability to log future traffic.
- **Cannot:** decrypt past or future messages; recover content from disk because the hub stores only ciphertext.
- **Defense:** the hub never holds plaintext keys or messages; MLS forward secrecy.

### A4. Active network attacker
Can inject, modify, delay traffic.
- **Cannot:** read content (E2E); impersonate users (signatures); undetectably reorder messages within a session (sequence numbers + MLS epoch counter).
- **Can:** delay messages; perform denial of service.
- **Defense:** AEAD + signatures.

### A5. Local non-privileged adversary on the user's device
Other user accounts, processes without root.
- **Cannot:** read Onyx data — encrypted at rest with passphrase-derived key.
- **Cannot:** connect to a running Onyx daemon — local API socket is `chmod 0600`, accessible only to the daemon's UID.
- **Defense:** at-rest encryption + filesystem permissions on the API socket.
- **Note:** the original `0.1-draft` of this section claimed "per-session token" authentication for the local API. The shipped v0 implementation uses filesystem permissions instead (`crates/onyxd/src/api_server.rs::bind_listener`). The two defend equivalently against this adversary, but the threat model has been corrected to match what is implemented. A token-based handshake is tracked as a future improvement (it would let SO_PEERCRED-less platforms — none of which we currently target — gain equivalent auth).

### A6. Casual targeted attacker
Someone trying to deanonymize a specific Onyx user without nation-state resources.
- **Defense:** the combined stack above, assuming the user follows operational security guidance (§4).

---

## 3. Adversaries we do NOT defend against

We are honest about these. If any of these is in your model, Onyx is not enough on its own.

### N1. Global passive adversary
An entity that can observe most internet traffic simultaneously can perform traffic confirmation against Tor. Padding, cover traffic, and jitter raise the cost but do not eliminate the attack.

### N2. Endpoint compromise
If the user's device runs malware with sufficient privileges, no application-layer crypto saves them. Use Tails, Qubes, or equivalent for high-risk threat models.

### N3. Coercion of users
Legal compulsion, physical threat, or social engineering of a user to hand over their key or decrypted history is outside the technical threat model. Note: because Onyx messages are signed by long-term credentials (see §6), a recipient under coercion can produce cryptographic proof of what a sender said. Onyx v1 is not deniable.

### N4. Coercion of developers
A malicious or compelled update could backdoor users. Mitigations: reproducible builds, signed releases, public source, multiple maintainers, no auto-update. Users must verify what they install.

### N5. Cryptographic algorithm breaks
If Ed25519, X25519, ChaCha20-Poly1305, or MLS itself is broken in the future (including by quantum computers), past messages may become readable to anyone with archived ciphertext. Onyx does not currently use post-quantum primitives. This may change.

### N6. Onion web tier users
The onion-web tier explicitly does not provide full E2E. The hub-served web UI decrypts messages on the daemon side to render HTML. A daemon compromise while a user is in this mode exposes the decrypted content of their active session. Tier is gated by client-auth onion + an explicit configuration acknowledgement, but the underlying tradeoff stands.

### N7. User operational security failures
Typing a real name, photographing a screen, using Onyx on a compromised device, reusing identifiers across services — Onyx cannot prevent these. Documentation will guide users; the rest is on them.

---

## 4. Trust assumptions

The user must trust:

- The Rust standard library and toolchain
- The Tor network (specifically: at least one of their three relays is honest)
- The Arti, OpenMLS, and other audited dependencies
- Their own operating system kernel
- Their own hardware
- The Onyx maintainers (reduced via reproducible builds + signed releases + open source)
- The CPU's random number generator (mixed with other entropy sources)

This list is not optional. There is no software trust-free path.

---

## 5. Residual linkability (honest accounting)

Even with all of the above, the hub can still observe the following. None of these reveals content, but each is a metadata signal worth understanding.

| # | Signal                              | Visible to | Mitigation                                  | Defeats it? |
|---|-------------------------------------|------------|---------------------------------------------|-------------|
| 1 | Per-inbox activity rate              | Hub, anyone holding the recipient's fingerprint | Padding + cover traffic; do not publish per-inbox metrics | Partial — raises cost, does not eliminate |
| 2 | Token cluster registered in one SUBSCRIBE | Hub | Distribute SUBSCRIBE across distinct Tor circuits | Partial — costs latency + circuits |
| 3 | Epoch-boundary intersection (who was online for a commit) | Hub | None ideal in v1 | No — documented limit |
| 4 | Back-to-back bootstrap envelopes from one circuit | Hub | Rate-limit bootstraps per circuit; offer deferred-send | Partial |
| 5 | Frame timing on an active connection | Hub, network | Constant-rate cover traffic ("high" mode) | Partial — "high" mode (`--constant-rate-ms`) makes the client→hub **upstream** cadence invariant; downstream still Poisson, unverified on real Tor, no defense vs N1 |
| 6 | Padding bucket distribution per connection | Hub | Chunking all >4 KB messages into LARGE frames | Partial — N consecutive LARGE frames is a "big message" signal |
| 7 | Hidden-service descriptor liveness | Tor HSDir relays | (Standard Tor property — out of scope here) | No — inherent to onion services |

---

## 6. Non-deniability

Onyx v1 is **not deniable**. Every message a user sends carries a signature from their long-term identity key:

- the MLS credential signature inside the ciphertext, and
- (for non-bootstrap envelopes) an outer Ed25519 signature over the routing fields.

Any recipient can produce cryptographic proof to a third party of what a sender wrote. This is contained to the recipient — the hub and network do not gain this proof — but it does mean that the property "the recipient can convince a third party of what I said" is *strengthened* compared to a casual chat.

Users in coercion scenarios (N3) should be aware that screenshots and recipient honesty are already not under their control; cryptographic non-repudiation marginally worsens an already-bad situation. A future revision may add a deniable-credentials mode; the wire format reserves space for it via the optional outer signature field.

---

## 7. What to do with this document

- If your threat model is contained within §2, Onyx is appropriate.
- If it overlaps §3, layer Onyx with the appropriate complementary tool (an amnesic OS, OPSEC discipline, etc.) or use a different system.
- If you find an adversary class that belongs in §2 but is not currently defended, that's a security report — please raise an issue.
- If you find a property claimed in §2 that does not hold in the implementation, that's a vulnerability — please coordinate disclosure per `SECURITY.md`.

---

## 8. Implementation status (honest accounting)

This section maps every defense claim in §2 to its current implementation status. Every reader of the threat model should be able to tell at a glance which protections are **designed**, **implemented**, and **verified**, without inferring from CHANGELOG entries.

Statuses:

- **D** — designed: specified in `DESIGN.md`, agreed-upon approach.
- **I** — implemented: code shipped, exercised by tests or manual smoke tests.
- **V** — verified: at minimum, has automated property/round-trip tests covering the security-relevant invariant. **No row in this table is currently marked `V` by external audit.**

### 8.1 Defenses promised by §2

| §2 claim                                                              | D | I | V | Notes / file references                                                                                                                                                            |
|-----------------------------------------------------------------------|---|---|---|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| A1 — Tor transport hides peers from passive observers                 | ✓ | ✓ | self-tests + manual | Embedded Arti, `crates/onyx-core/src/tor.rs`. Verified end-to-end with two-daemon Tor sessions (see CHANGELOG entries from T1.x onward).                                          |
| A2 — Hub cannot read content (MLS E2E)                                | ✓ | ✓ | unit + integration tests | `crates/onyx-core/src/mls.rs`, exercised by 829-line module + 30+ tests. Hub only handles ciphertext frames.                                                                       |
| A2 — Sealed-sender bootstrap hides bootstrap-message sender from hub  | ✓ | partial | unit tests in `routing.rs` | `routing::seal_bootstrap` / `open_bootstrap` exist with PQ-hybrid X25519+ML-KEM-768 + property tests. **Not yet wired into the daemon-to-hub path.** T5.2 closes this gap.        |
| A2 — Rotating session tokens per active MLS group                     | ✓ | partial | unit tests | `routing::session_token(group_secret, index)` derived via MLS exporter. Daemon currently subscribes only to its introduction inbox; per-epoch rotation in daemon code is T5.x.    |
| A3 — Hub root holds no plaintext keys                                 | ✓ | ✓ | by construction | `crates/onyx-hub/src/handler.rs` never decodes payload past the 16-byte routing prefix.                                                                                            |
| A3 — Forward secrecy past hub compromise (MLS PCS)                    | ✓ | ✓ | upstream openmls tests | We use openmls 0.8 which implements RFC 9420's ratchet; we have not separately re-verified the PCS property.                                                                       |
| A4 — Active network attacker cannot read content (AEAD)               | ✓ | ✓ | unit tests + property tests | ChaCha20-Poly1305 via `chacha20poly1305` 0.10, used by Noise transport and MLS framing.                                                                                            |
| A4 — Active attacker cannot impersonate (signatures)                  | ✓ | ✓ | unit tests | Ed25519 via `ed25519-dalek` 2.x; MLS credential signatures; outer Onyx envelope signature.                                                                                         |
| A4 — Active attacker cannot reorder within session                    | ✓ | ✓ | upstream Noise/MLS | Noise uses per-direction nonces (replay-resistant); MLS uses epoch + per-message generation counters.                                                                              |
| A5 — Local non-privileged adversary cannot read vault                 | ✓ | ✓ | unit tests | `crates/onyx-core/src/storage.rs::Vault`, Argon2id KDF + AEAD-sealed rows + canary plaintext, see test `wrong_passphrase_rejected`.                                              |
| A5 — Local non-privileged adversary cannot connect to API             | ✓ | ✓ | manual smoke | `chmod 0600` on the Unix socket after bind (`crates/onyxd/src/api_server.rs::bind_listener`). Tested with `ls -la` on running daemon (see T4.1 CHANGELOG transcript).             |
| A6 — Combined defenses resist a casual targeted attacker              | ✓ | partial | not separately verified | Resists only insofar as all of A1–A5 hold simultaneously; no end-to-end red-team exercise has been performed.                                                                      |
| §5#5 — Frame timing on active connection (constant-rate cover)        | ✓ | partial | `onyx-daemon` `constant_rate_pacer_*` units + `rooms_smoke` constant-rate e2e | Frame size buckets (256/1024/4096) and constant-rate "high mode" (`--constant-rate-ms`) are both implemented. Unit tests pin the one-frame-per-slot / reals-first-FIFO / idle-emits-PAD invariant; an e2e smoke proves real routing survives pacing. **Partial**: covers the **client→hub upstream only** (downstream still Poisson), and the "a passive Tor observer can't distinguish active from idle" claim is **not measured on real circuits**. Marked Partial in §5. |
| §5#1 — Per-inbox activity rate padding                                | ✓ | ✗ | n/a | Buckets help; **no cover-traffic padding** beyond per-frame size normalisation.                                                                                                    |
| §6 — Non-deniability (long-term Ed25519 signatures)                   | ✓ | ✓ | by construction | Every MLS application message carries a credential signature; documented as a deliberate property, not a defect.                                                                  |
| §4 trust assumption — Reproducible builds                             | ✗ | ✗ | n/a | **Not yet established.** Tracked as a release-engineering work item.                                                                                                              |
| §4 trust assumption — Signed releases                                 | ✗ | ✗ | n/a | **Not yet established.** No tagged releases exist as of this writing.                                                                                                             |
| §4 trust assumption — Multiple maintainers                            | ✗ | ✗ | n/a | **One maintainer**, working with an AI assistant. This is a single-point-of-trust risk acknowledged here.                                                                          |

### 8.2 Consolidated carry-forward gaps

This is the same list that accumulated across CHANGELOG entries, surfaced in one place and mapped to the adversary classes affected. Order is rough priority for closing.

1. **Sealed-sender wrap on the daemon's hub path** (affects A2). **`msg/v1` (PFS-only) and `mls/v1` (PCS via MLS) paths both closed end-to-end as of T5.2.e**: `msg/v1` ships plaintext in `BootstrapPayload::PlainMessage`; `mls/v1` ships an MLS Welcome in `BootstrapPayload::MlsWelcome`. The recipient's `handle_hub_delivery` decodes both, registering the sender + (for `mls/v1`) joining the resulting MLS group via `MlsParty::join_from_welcome` and persisting the MLS snapshot. `mls/v1` is the strict upgrade: every application message exchanged in the resulting group has full MLS PCS. **Decode failures are silent at debug level** to prevent log-spam attacks from a hostile hub. **What remains**: the wire format for *ongoing* MLS application messages over the hub (so two peers who've never had a direct Tor circuit can chat continuously, not just bootstrap a group) — that's T6.x.
2. **PQ hybrid X25519 + ML-KEM-768 wired into the daemon path** (affects N5). **Partially closed in T5.2.a**: each identity now owns and persists a hybrid KEM keypair (`Identity::kem_public` / `Identity::kem_secret`). Not yet used in the Noise handshake or in any live envelope. Store-now-decrypt-later attackers who archive Noise + MLS traffic today still get plaintext eventually; the new KEM keypair starts protecting them only once the sealed-sender hub path goes live.
3. **Cover traffic on idle Tor circuits** (affects A2's "coarse activity" caveat and §5#1, #5). Frame buckets shape *transmitted* frames; idle circuits leak presence. **Partially closed (T-cover.const):** opt-in constant-rate "high mode" (`--constant-rate-ms`) now makes the client→hub **upstream** cadence invariant — one frame per slot whether chatting or idle — superseding the weaker Poisson mode for that direction. **Remaining**: a constant-rate *hub* for the downstream (hub→client) direction, cover on direct peer-to-peer (DM/room) Tor circuits, and real-circuit measurement of the indistinguishability claim.
4. **Hub auth — invite-only or signed-token registration** (affects A2/A3). Anyone holding the hub's static key can connect, subscribe, and DELIVER. DoS risk; no rate limits; no quotas.
5. **`derive_peer_fingerprint` silent fallback** (affects P7 / user-facing trust). If MLS member extraction fails for any reason, the TUI shows the X25519 b32 as if it were the Ed25519 fingerprint, with no visual distinction. Should log a `warn!` and render differently.
6. **Reproducible builds + signed releases** (affects N4). No release-engineering pipeline yet. Until then, "binary you downloaded matches the source you can audit" is not provable.
7. **Multiple maintainers / external review** (affects N4 + all of §1 caveats). One developer + an AI assistant is not enough oversight for security-critical infrastructure.
8. **Schema migration** (affects A5 indirectly — vault accessibility). Old vaults can't be opened by new code. Today: recreate. Future: a runner that walks schema versions.
9. **Fuzzing of wire decoders + MLS framing** (affects A4). `proptest` covers some round-trips but no targeted fuzzing campaign against malformed input.
10. **Onion-web tier** (N6) — not implemented at all yet. Listed because once it lands the explicit tradeoff documented in N6 becomes a real surface to defend.
11. **Macos `fs-mistrust` bypass workaround** (affects A5 marginally on macOS). The env var `FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS=1` skips Arti's state-file integrity checks. Acceptable in dev; should not appear in operator-facing release instructions without a documented mitigation.
12. **Protocol-level BYE+ACK** (affects A4's reordering guarantee at session-end). The 500 ms drain hack before `stream.shutdown()` (`peer_session` in `onyxd`) is a band-aid; the real fix is a final acknowledged frame.
13. **Vault schema v4 has no migration runner** (affects A5 indirectly — vault accessibility on upgrade). T5.2.a bumped the on-disk schema from v3 to v4 (identity blob grew from 64 bytes to 2496 bytes to fit the hybrid KEM secret). Existing v3 vaults fail the schema check at open and must be recreated. This is now the **fifth** schema bump without a migration story — the cost of writing the runner grows each time. Priority bumped accordingly.
14. ~~**TUI must visually distinguish hub-relayed messages from direct-MLS**~~ — **closed in T5.2.f**. The conversation pane now renders a yellow `[hub]` badge on every `via_hub: true` message. Tier indicator survives history backfill (`via_hub` round-trips through `EventMessage` + `HistoryEntry` + ring `ChatLine` + `merge_history`). Snapshot regression test `dump_snapshot_with_chat` asserts the badge renders.
16. ~~**Hub can replay any sealed-sender envelope back to the recipient**~~ — **closed in T7.3-sec.2 + T7.3-sec.2-persist.** Before today the recipient daemon decoded every DELIVER frame the hub sent it without checking whether the same bytes had arrived before; a hostile hub could store one of alice→bob's envelopes and re-deliver it at any point, causing bob's daemon to surface a duplicate `EventMessage`. The fix is recipient-side: `DaemonState` now carries an `EnvelopeReplayGuard` (FIFO seen-set of BLAKE2b-128 hashes over the raw body bytes, capacity 4096 ≈ 64 KB of state). `handle_hub_delivery` consults it before any AEAD work and drops the delivery silently on a hit. 14 unit tests cover the guard semantics including the critical "replay does NOT refresh FIFO position" property (an attacker can't keep a real entry alive by spamming replays) and the snapshot/restore round-trip. **Restart window closed in T7.3-sec.2-persist**: the seen-set is snapshotted every 60 s to a new additive `replay_state` table in the vault (AEAD-sealed at rest), plus a final snapshot on the Ctrl-C path. Worst-case restart-replay window is now ≤60 s (the snapshot-tick interval), not "until the daemon next collides on a hash" as it was before. The additive table uses `CREATE TABLE IF NOT EXISTS` rather than a schema-version bump — old v4 vaults pick up the table on next open with no migration runner required (this is the documented pattern for avoiding further worsening of carry-forward #13). Defence is *purely recipient-side* — does not trust the hub for anything new.

15. ~~**Hub does not validate publisher ownership of a routing id when storing a KeyPackage**~~ — **closed in T7.3-sec.** The hub's `FRAME_KP_PUBLISH` handler now extracts the KP's embedded Ed25519 signing key (via the new `onyx_core::mls::signing_key_from_kp_bytes` free function), reconstructs the publisher's fingerprint (the fingerprint *is* the signing-key bytes by design), derives the expected `introduction_inbox(fingerprint)`, and rejects the publish if it doesn't match the claimed routing id. The recipient-side check in `handle_fetch_peer_keypackage` remains as defence-in-depth. Attack test added: `keypackage_publish_rejects_routing_id_mismatch` — an attacker who tries to overwrite alice's directory entry with their own KP gets silently rejected by the hub; alice's entry stays intact. The earlier "sign-challenge requires the hub to learn the publisher's Ed25519 key" note turned out to be wrong: the KP already *carries* the Ed25519 signing key, signed by itself (MLS leaf-node self-signature), so no out-of-band challenge is needed. Closed properly, not papered over.

17. ~~**F1 — Hostile peer hub poisoning a federated hub's KP directory**~~ (T8.3 introduced hub-to-hub gossip; introduces a new adversary class — defended at landing) — **closed in T8.3.b.4 + T8.3.d.** When operator A configures hub B as a peer via `--peer-hub`, B can send `FRAME_GOSSIP_PUBLISH` frames to A. The same T7.3-sec ownership check that gates client-direct KP publishes is applied verbatim to gossip: A extracts the KP's embedded signing key, derives `introduction_inbox(fingerprint)`, and rejects any gossiped KP whose routing id doesn't match. Gossip is authenticated to the same standard as direct client publish. Attack test: `gossip_publish_ownership_check_propagates_to_gossip` constructs a real-but-wrong-routing-id KP, verifies it's dropped before any local store. F1 is a defended adversary class, NOT a carry-forward.

18. ~~**F2 — Gossip-loop amplification across a peer-hub mesh**~~ (T8.3) — **closed in T8.3.b.1 (format) + T8.3.b.4 (loop check) + T8.3.d (test).** Each gossip frame carries a `ttl: u8` (default 3) and a `seen_by: [u8; 16]` (low 128 bits of BLAKE2b-128 of the last forwarder's hub pubkey). Receiver drops on `seen_by == our_hash`; forwarder decrements TTL and rewrites `seen_by` to its own hash; `forward()` returns `None` when TTL would underflow to 0. Source-skip on re-fanout (the peer who sent the gossip is excluded from the forward set) prevents trivial A→B→A ping-pong. Termination proven inductively for the 3-hub triangle case in `handler::tests::gossip_publish_*`: within 3 hops the TTL hits 1, re-fanout stops via `saturating_sub(1) == 0`. Stronger ring topologies hit the same floor regardless of size. F2 is a defended adversary class, NOT a carry-forward.

Also rows in 8.1 updated this turn:

| §2 / §5 claim                                         | D | I | V | Notes                                                                                                                                |
|------------------------------------------------------|---|---|---|--------------------------------------------------------------------------------------------------------------------------------------|
| Per-identity hybrid KEM keypair (sealed-sender prerequisite) | ✓ | ✓ | unit + reopen-round-trip tests | T5.2.a. `Identity::kem_secret` / `kem_public`; persisted in vault schema v4. KEM keypair survives daemon restart. |
| Hub-client bidirectional outbound queue              | ✓ | ✓ | duplex round-trip test | T5.2.b. `hub_client::run_hub_session` accepts a `mpsc::Receiver<HubOutbound>` and writes `FRAME_DELIVER` frames via `tokio::select!`. |
| Sealed-sender `SendBootstrap` API verb               | ✓ | ✓ | 6 dispatcher tests incl. happy-path open + recover | T5.2.c. Wraps `BootstrapPayload::PlainMessage` in `seal_bootstrap` and pushes to hub. |
| Inbound hub-delivery decode → registry               | ✓ | ✓ | end-to-end registry test | T5.2.d. `handle_hub_delivery` tries `open_bootstrap` + `BootstrapPayload::from_cbor`; success → `register_hub_only` + `push_message_via_hub`. **Decode failures silent at debug level** (anti-log-spam against hostile hub). |
| `via_hub` indicator preserved across history backfill | ✓ | ✓ | `merge_history_dedupes_against_live_entries` extended | T5.2.d. `EventMessage` + `HistoryEntry` + ring `ChatLine` all carry `via_hub: bool`; restart + History fetch reconstructs the security tier. |

Each item is also enumerated in the relevant CHANGELOG entry. This list and the CHANGELOG must stay in sync.

Status updates to §8.2 items from the 2026-05 internal audit (see §8.3):

  * **#3 (cover traffic on idle circuits)** — partially closed (T-cover.const). Opt-in constant-rate "high mode" (`--constant-rate-ms`) makes the client→hub **upstream** cadence invariant — one frame per slot whether chatting or idle — superseding the weaker Poisson mode for that direction. Mechanism unit-tested (one-per-slot / reals-first / idle-PAD) + e2e-smoke-tested (real routing survives pacing). **Still open**: a constant-rate *hub* for the downstream direction, cover on direct peer-to-peer Tor circuits, and real-circuit measurement.
  * **#4 (hub auth)** — partially closed. The hub now (a) authenticates SUBSCRIBE and enforces *ownership* of any **published** introduction inbox (HIGH-1), (b) rate-limits per authenticated identity (HIGH-3), and (c) caps offline-queue memory. **Still open**: invite-only / token registration (anyone with the static key can still connect), and **session-token subscriptions remain unauthenticated by design** (see §8.3 residuals).
  * **#5 (sender-fingerprint fallback)** — closed. Incoming room messages/files are now attributed to the real Ed25519 fingerprint pulled from the MLS credential (`process_incoming_with_sender`, task 321); the `(peer/<x25519>)` placeholder only remains as a graceful fallback if the credential isn't 32 bytes.
  * **#6 (reproducible builds + signed releases)** — closed. Sigstore-keyless signed releases ship (`v0.1.0`–`v0.1.3`), verifiable via `RELEASES.md`.
  * **#9 (fuzzing wire decoders)** — closed. `crates/onyx-core/tests/fuzz_no_panic.rs` runs ~36k random-input cases against every public decoder; zero panics (see §8.3).

---

### 8.3 Internal security audit + red-team (2026-05-20/21)

A multi-agent internal review of the security-critical code, followed by an adversarial red-team pass. **All identified findings were fixed; all attacks mounted were blocked.** This is internal review — it does **not** substitute for the external audit still tracked as §8.2 #7.

**Findings fixed:**

| ID | Finding | Fix |
|----|---------|-----|
| HIGH-1 | Hub SUBSCRIBE unauthenticated — anyone could subscribe to a victim's deterministic introduction inbox and drain its queue (message theft + metadata leak) | Signed SUBSCRIBE (`signer_pk ‖ Ed25519-sig ‖ ids`), sig bound to the Noise handshake hash (replay-proof per connection); hub rejects subscribing to a **known** intro inbox not owned by the signer (`is_known_intro_inbox` vs the KP directory) |
| HIGH-2 | Sealed-sender envelope bound nothing to the recipient → a malicious legitimate recipient could reflect a signed payload to a different victim | Recipient hybrid-KEM pubkey bound into both the Ed25519 signature and the AEAD aad |
| HIGH-3 | Rate limit keyed on per-connection id → reset by reconnecting / parallel connections | Keyed on the authenticated Noise static key; full buckets evicted, throttled buckets retained |
| MED | Replay-guard dedup ignored the routing target | Dedup over `target ‖ body` |
| MED | Executable-MIME refuse trusted the sender's claimed MIME | Re-sniff the assembled bytes (`infer`) on receive |
| MED | Unbounded hub offline-queue memory | Per-id depth cap + global byte cap |
| MED | Unbounded daemon file-reassembly memory; stalled transfers pinned forever | Global in-flight byte budget + stalled-transfer reaper |
| MED | Hybrid-KEM combiner wasn't the robust (X-Wing/PQXDH) form | Bind both recipient static pubkeys into the KDF |
| LOW | Latent path traversal in the conversation key before `storage_dir.join` | `is_valid_conversation_key` guard |

**Red-team (all blocked, locked as regression tests):**

  * Live malicious-client attacks against the hub (real Noise handshake): unsigned SUBSCRIBE, subscribe-to-victim's-known-inbox, replayed SUBSCRIBE proof (wrong handshake hash), garbage-frame crash attempt — all rejected; connection survives garbage without panic.
  * Decoder fuzz: ~36k random-input cases across every untrusted-byte parser — zero panics.

**Residuals (honest accounting — what the audit did NOT close):**

  1. **Session-token subscriptions are unauthenticated by design.** Tier-2 per-epoch routing tokens are derived from a group-private MLS exporter secret the hub never sees, so the hub *cannot* authenticate a subscription to one without breaking the unlinkability the two-tier scheme exists to provide. They rely on 128-bit unguessability. An attacker who *learns* a current token (e.g. a former group member) could subscribe to it until the next epoch rotation.
  2. **Introduction inboxes are only protected once a KeyPackage is published there** (that's how the hub knows an id is an inbox). An unpublished inbox is treated as a session token. Most flows auto-publish on connect, so this is covered in practice.
  3. **No invite-only hub registration** (§8.2 #4). Anyone with the hub's static key can still open a session.
  4. **Replay guard is in-memory with a ≤60 s restart window** (§8.2 #16 detail) — unchanged.
  5. **The crypto primitives themselves** (X25519, ML-KEM-768, MLS, ChaCha20-Poly1305) are assumed correct; the underlying libraries (`snow`, `openmls`, `ml-kem`) are not fully audited (§4 trust assumptions, N5).
  6. **Timing / traffic analysis** — constant-rate "high mode" cover (`--constant-rate-ms`, T-cover.const) now exists opt-in for the client→hub **upstream**, making that cadence invariant; the **hub-side (downstream) constant-rate, direct peer-circuit cover, and real-Tor measurement remain unbuilt/unverified** (§8.2 #3, A2 caveat, N1).
  7. **External audit (§8.2 #7) remains the single most important open item.** Everything above is "survives the attacks we knew to write," not "proven secure."

### 8.4 Security review — 2026-05-29 (mixed manual + agent)

A second security review (mixed manual + agent-driven analysis). **This is not the formal third-party external audit still tracked as §8.2 #7 — that gap remains open and the "no external audit" disclaimer stands.** Verdict: crypto core and untrusted-byte parsers held up (robust hybrid KEM, reflection-safe sealed-sender, no panicking decoders); **all findings were config-hardening or DoS, not confidentiality breaks.** Each was re-verified against the code before any change. Status:

| ID | Sev | Finding | Resolution |
|----|-----|---------|------------|
| M-1 | MED | Production vaults created with Argon2 `FLOOR` (64 MiB), not `DEFAULT` (256 MiB) | **Fixed** — both production `Vault::create` sites now use `DEFAULT`. Safe: KDF params persist per-vault, so existing vaults unlock unchanged. |
| L-2 | LOW→MED | API-socket `bind`→`chmod` non-atomic | **Hardened + clarified** — the default path's UID guarantee rests on the 0700 parent dir (`~/.onyx`), not the chmod; `bind_listener` now warns if a *custom* socket parent is group/other-accessible (the only exploitable case). Avoided a process-global umask toggle (worse hazard than the finding). Audit's "default = CWD" note was stale. |
| A-1 | MED→HIGH | Peer-hub gossip path un-rate-limited (CPU-DoS / amplifier) | **Fixed** — all inbound peer-hub frames now pass the same per-static-key token bucket as client frames (default 600/min). Note: the expensive MLS KP validation already ran *lock-free*, not under the global mutex as stated; re-fanout was already TTL-bounded. |
| A-2 | MED | SUBSCRIBE accepted ~4000 ids/frame, unbounded per-conn | **Fixed** — `MAX_SUBSCRIBE_IDS_PER_FRAME` (256, drop over cap) + `MAX_SUBSCRIPTIONS_PER_CONN` (16384, per-conn-lifetime, dedup-safe). |
| A-3 | MED | Queue byte-cap ignored per-distinct-key overhead | **Fixed** — accounting charges `payload + QUEUE_ENTRY_OVERHEAD_BYTES` (128) per entry at every site (enqueue / drain / restart-warm / admission), so `MAX_TOTAL_QUEUED_BYTES` faithfully bounds real memory regardless of id distribution. |
| A-4 | MED | `SendFile*` reads an arbitrary daemon-readable path from IPC (confused-deputy exfil) | **Accepted by design** — the API socket is owner-only (0600 + 0700 parent dir, L-2), so the only caller is the same UID running the daemon; sending user-chosen files is the feature. The socket ACL is the trust boundary; a path allowlist would break the feature. |
| A-5 | MED | `MessageEnvelope::from_cbor` had no size cap / field-length validation | **Fixed** — explicit `MAX_ENVELOPE_CBOR_BYTES` (128 KiB) pre-decode cap + boundary validation of `nonce` (==12), `sig` (==64 when present), and `to`/`from`/`room` (≤`MAX_ROUTING_ID_LEN`). Was already 64 KiB-bounded on the Noise path; this is fail-fast defense-in-depth. |
| A-6 | LOW (anon) | `MessageEnvelope.pad_to` decoded but not enforced | **Not a real gap** — the on-wire padding guarantee is applied AND enforced one layer down at the `InnerFrame` bucket layer (`encode_padded` always pads to a bucket; `decode` rejects non-bucket lengths; AEAD covers the padding). `pad_to` is vestigial advisory metadata read by no decision logic; its misleading doc comment was corrected (a cross-check here would duplicate the frame layer and add the timing-leak surface `InnerFrame::decode` deliberately avoids). |
| A-7 | LOW | Replay-guard ≤60 s restart window | **Already documented** (§8.2 #16, residual #4) — unchanged. |
| A-8 | LOW | Canary compare variable-time | **Moot** — reached only *after* AEAD success, so it leaks nothing an attacker who already passed the AEAD doesn't have. |
| A-9 | LOW | KP_FETCH un-throttled presence-enumeration oracle | **Fixed** — KP_FETCH now consults the same per-static-key rate bucket as DELIVER/KP_PUBLISH. |

Tests landed with the fixes: `subscribe_enforces_per_conn_subscription_cap`, `resubscribe_same_id_does_not_double_count_against_cap`, `check_rate_throttles_any_connection_after_its_budget` (A-1/A-2), `offline_queue_byte_accounting_frees_on_drain` updated for overhead (A-3), `envelope_rejects_invalid_field_lengths` + `envelope_rejects_oversized_cbor` (A-5).

### 8.5 Security review — 2026-05-29, deep pass (mixed manual + agent)

A deeper architectural/protocol pass following §8.4. **Still not the formal third-party external audit (§8.2 #7), which remains open.** These reach past the config/DoS layer into anonymity architecture, first-contact trust, and federation correctness — so several are genuinely multi-session protocol work, not one-line fixes. Honest split:

**Fixed in this pass (contained, tested where unit-testable):**

| ID | Sev | Finding | Resolution |
|----|-----|---------|------------|
| H-3 | MED | Inbound gossip TTL not clamped → up to 255× amplification | **Fixed** — both gossip handlers clamp inbound TTL to `GOSSIP_TTL_DEFAULT` before decrementing. Test: `gossip_publish_inflated_ttl_is_clamped`. |
| G-1 | MED | `KemAdvertisement.fingerprint` persisted from the message body → KEM-directory poisoning | **Fixed** — keyed on the MLS-credential-derived `sender_fp`; a body fingerprint that disagrees is dropped as a poisoning attempt. |
| P-2 | MED | 8-char (40-bit) short id with unconditional `by_short` overwrite → grindable send-misdirection | **Fixed** — `insert_short_id` refuses to overwrite a different peer's short id (keeps the original, warns); colliding peer still reachable by full key. Test: `short_id_collision_does_not_hijack_existing_peer`. |
| T-3 | MED | X25519-as-Ed25519 silent fingerprint fallback (§8.2 #5) | **Fixed** — the core `derive_peer_fingerprint` now `warn!`s on all three fallback paths (peer signing key absent / not 32 bytes / not a valid Ed25519 point), not just the DM pin-check path; the rendering stays distinct (`(peer/<x25519>)`) and the peer's raw key is NOT logged (D-3). With T-1 pinning landed the sender binding is also now pinned/verified. Residual: the fallback still *occurs* (attribution degrades to a placeholder) when the MLS credential can't be read — by design, not silently. |
| D-3 | MED | Identifiers logged at `info` to the plaintext `~/.onyx/onyx.log` | **Fixed** — both peer identifiers (pubkeys ×4 + peer onion-dial host) AND the node's own identifiers (own `.onion`, own intro-inbox id, own fingerprint span) are now at `debug`, so **no** identity/onion/social-graph value lands in the default (info-level) log. Trade-off: a headless accept-mode operator who needs their own `.onion` for direct-dial must enable debug logging (exposing it via the Status API is the cleaner follow-up). Residual: the log file remains plaintext at rest (a vault-style encrypt-at-rest for logs is out of scope). |

**Tracked residuals — analyzed, NOT yet fixed (honest; these are real and mostly architectural):**

| ID | Sev | Finding | Status / why deferred |
|----|-----|---------|------------------------|
| D-1 | HIGH | Hub Noise static key = long-term X25519 identity → hub clusters all of a user's routing ids/tokens under one authenticated identity | **Fixed as opt-in** (`--ephemeral-noise-static`, default off). When enabled, each handshake to each hub uses a freshly-generated X25519 keypair as the Noise static — the hub never sees the long-term identity at the Noise layer. The long-term identity stays in HIGH-2 sealed-sender envelopes (running end-to-end *inside* Noise frames), so all DMs/rooms keep working. **Honest scope:** §3.2's three leaks are independent — D-1 alone closes only **leak #1** (Noise static). To actually close §3.2 the user must **compose** ephemeral Noise with `--no-intro-inbox-subscribe` (closes #2) AND avoid `KP_PUBLISH` on the connection (closes #3) — the realistic profile is "established rooms only, no first-contact reachability via this hub." The per-static-key rate limiter (HIGH-3) becomes per-connection in this mode (reconnect resets the bucket); per-frame caps still bound resource use. Default off because most users want first-contact reachability + the rate-limit continuity. Tested by `rooms_e2e_ephemeral_noise_static_does_not_break_flow` (full room flow survives ephemeral on both daemons). **Future**: separated publish/subscribe connections + oblivious-recipient routing for first-contact would let D-1 become default. |
| D-2 | HIGH | No Tor circuit isolation → all dials shared circuits | **Fixed** — `TorRuntime::isolated()` (Arti `isolated_client`) gives each hub connection and each peer dial its own circuit-isolation group, so two of the user's conversations never ride the same Tor circuit (a circuit observer can't trivially link them; one circuit's failure/compromise is scoped to one peer). Isolates *circuits*, not *guards* — sharing a small sticky guard set is intentional Tor design — and is no defense against a global timing adversary (§3.1). |
| D-4 | MED | Onion service key random (`OnionServiceConfigBuilder::default()`), not identity-derived → §4.3 onion↔identity verification can't work | Needs provisioning the HS key from the identity (arti support TBD). **Open.** |
| T-1 | HIGH | No key pinning / "key changed" warning / `Contact` command (TOFU) | **Fixed** — the vault now pins each peer's Ed25519-fingerprint → X25519-identity-key binding on first contact (`pinned_keys` table; `Vault::pin_or_verify`). At every conversation-registration point (`pin_check_peer`: direct dial, msg/v1 bootstrap, and MLS Welcome — placed before the room/DM branch so both are covered) a later key that differs from the pinned one is **kept-not-overwritten**, flagged (`key_changed`), and `warn!`'d as a possible MITM/rotation. Surfaced via `onyx contact list` (API `ListContacts`/`ContactInfo`). **Residual:** detection-only (warns, doesn't block — a chat key rotation is legitimate); no re-pin/accept UI yet; first-contact MITM itself is still T-2. |
| T-2 | HIGH | Invite has no signature/MAC/nonce/expiry → invite-channel MITM owns first contact | **Fixed for partial tampering + closed-for-the-default-user against the realistic bypasses.** v2 invite (`onyx://invite/v2?…&exp&nonce&sig`) signs a length-prefixed canonical blob (`SIGN_CONTEXT_V2 ‖ fp ‖ kem ‖ kp ‖ hubs ‖ exp ‖ nonce`) with the identity Ed25519 key. **Trust gates run inside the daemon** (new `SendInvite` API verb — the CLI is now a pass-through, so a malicious local process speaking to the API socket cannot strip the signature by calling `SendBootstrap*` directly): (a) v1 unsigned **refused by default** (caller must pass `insecure_accept_unsigned`); (b) v2 sig must verify, with the `MAX_INVITE_TTL_SECS` (90 d) max-future clamp NEW-2 applied verifier-side; (c) **pin-store cross-check** — if the invite fp is already pinned and `key_changed` is set, refuse. Acceptance message rewritten from the misleading "verified ✓" to "signature is internally consistent (self-signed — NOT a check the invite came from the human you think it did; verify the fingerprint out of band before trusting)" so the user is told the truth about what self-signing proves. **Honest residual:** full-invite substitution by a MITM who replaces the entire invite (their own fp/keys/sig) remains indistinguishable on an unauthenticated channel — that's the fundamental limit of any invite system, mitigated only by OOB-fp verification or T-1's later key-change detection. 8 tests cover round-trip, expiry, tampered-kem/hubs/fp, downgrade refusal, malformed sig, **and the new max-future clamp**. |
| T-2 NEW-1 | MED-HIGH | v1 invite downgrade by path rewrite (rewrite `/v2 → /v1` and strip the sig fields) | **Closed.** The v2 path is bound into the signed blob via `SIGN_CONTEXT_V2 = b"onyx/invite/v2"`, so any "keep sig + flip path" attack fails verification; and a "flip path + strip sig" attack now hits the **refuse-v1-by-default** gate in both the CLI and the daemon's `SendInvite` handler. |
| T-2 NEW-2 | LOW-MED | Wall-clock `unwrap_or(0)` silently disables expiry; attacker-chosen `exp` had no max-future clamp | **Closed.** Verifier-side: `verify_signature` rejects `exp > now + MAX_INVITE_TTL_SECS` (90 d). Both the CLI's `run_accept` and the daemon's `handle_send_invite` / `handle_build_invite` now **hard-error** on a broken / pre-epoch clock rather than `unwrap_or(0)`-ing into a never-expired state. Sender-side `ttl_secs` is also clamped to the same ceiling so we don't mint absurd-future invites by our own bug. Test: `v2_exp_too_far_in_future_is_rejected`. |
| T-2 NEW-3 | LOW | `derive_peer_fingerprint`'s direct-session fallback returned raw X25519 (looks like a fingerprint) → bypassed `pin_check_peer`'s `(peer/…)` skip and polluted the pinned-contacts table with junk rows | **Closed.** Caller now passes `format!("(peer/{x25519-short})")` as the fallback so the skip applies correctly. No row is pinned when MLS attribution is unavailable (right answer — there's no real identity to pin yet). |
| P-1 | HIGH | `register_hub_only` keyed on attacker-chosen `peer_pub` (X25519), not the bound Ed25519 fingerprint | **Verified closed by composition (no code change).** Traced end-to-end against the tree: (a) HIGH-2 — `open_bootstrap` (routing.rs:553) verifies the inner Ed25519 signature **before** returning, and the signed blob covers `sender_signing_pk ‖ sender_identity_pk ‖ recipient_kem ‖ mls_welcome`, so `sender_x25519` is cryptographically bound to `sender_signing_pk` (= fingerprint) — an attacker cannot present a `(victim_fp, attacker_x25519)` pair without the victim's signing key; (b) T-1 — `pin_check_peer` runs **before** every `register` / `register_hub_only` call site (direct 1344→1348, msg/v1 2473→2475, MLS-Welcome 2655→2711), so the `(fp, x25519)` binding is recorded on first contact and any later change is flagged + warned; (c) P-2 — `insert_short_id` blocks short-id collision overwrites. The keying-on-X25519 is **required by design**: inbound Noise XK authenticates X25519 (not fingerprint, they're different keys), so for a *new* peer the registry MUST look up by what Noise hands us; the fingerprint binding is established post-pin. Audit's "attacker-chosen peer_pub" framing predated the HIGH-2 + T-1 + P-2 stack. No exploitable gap found. |
| P-3 | MED | Hub deliveries processed inline + serial → junk-envelope CPU / head-of-line DoS | Architectural (bound/parallelize the recipient decode path, or fast-reject). Partly blunted by the recipient replay guard + sealed-envelope drop. **Open.** |
| G-2 | MED | No committer-authority model — any MLS member can add/remove any member | Largely inherent to plain MLS (no admin roles); an authority/policy layer is a design effort. **Documented residual** (this row). **Open.** |
| H-1 | 🟠→🟡 | Federated peer can fill a target inbox's offline queue to the cap → targeted denial-of-delivery | **Partially mitigated** by A-1 (rate-limits the fill *rate*) + the per-id depth cap; a slow fill to the cap still drops legit messages. Fundamental tension: the hub can't distinguish junk from real sealed envelopes. **Open (partial).** |
| H-2 | MED | Forgeable gossip `seen_by` → a peer can forge our hash to make us drop a frame (directory-partition / suppression) | The loop-check trusts an unauthenticated `seen_by`; a malicious peer exploits it to suppress propagation. Mitigation needs authenticated forwarding metadata. **Open.** |

**Update:** **All five deep-pass HIGH residuals are now resolved.** D-2 (circuit isolation), T-1 (TOFU pinning + Contact), T-2 (signed invites) shipped as code changes. P-1 was verified closed by composition of HIGH-2 + T-1 + P-2 (analysis only). D-1 (ephemeral Noise) is implemented as an **opt-in** (`--ephemeral-noise-static`) with an honest composition note — leak #1 of §3.2's three closed by this flag; #2 and #3 close when the user composes the existing opts. Remaining work is on the MEDs (P-3 delivery HOL, G-2 MLS committer authority, H-2 forgeable gossip `seen_by`, D-4 identity-derived onion) and the §3.2 architectural follow-ups (separated publish/subscribe connections, oblivious-recipient routing) that would let D-1 become default. The formal external audit (§8.2 #7) remains the single biggest open item.

**Bottom line (unchanged honesty):** the confidentiality core held across two review passes; the open items above are real anonymity/trust/federation hardening, several requiring protocol-level work. None are claimed fixed until they are. The formal external audit (§8.2 #7) is still the headline gap.

---

*See `DESIGN.md` for the full system specification and `SECURITY.md` for the enforcement principles and disclosure policy.*
