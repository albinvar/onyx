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
| 5 | Frame timing on an active connection | Hub, network | Constant-rate cover traffic ("high" mode) | Yes against hub at "high" mode; no against N1 |
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
| §5#5 — Frame timing on active connection (constant-rate cover)        | ✓ | ✗ | n/a | Frame size buckets (256/1024/4096) are implemented; **idle cover traffic ("high" mode) is not**. Marked Partial in §5 of this document.                                          |
| §5#1 — Per-inbox activity rate padding                                | ✓ | ✗ | n/a | Buckets help; **no cover-traffic padding** beyond per-frame size normalisation.                                                                                                    |
| §6 — Non-deniability (long-term Ed25519 signatures)                   | ✓ | ✓ | by construction | Every MLS application message carries a credential signature; documented as a deliberate property, not a defect.                                                                  |
| §4 trust assumption — Reproducible builds                             | ✗ | ✗ | n/a | **Not yet established.** Tracked as a release-engineering work item.                                                                                                              |
| §4 trust assumption — Signed releases                                 | ✗ | ✗ | n/a | **Not yet established.** No tagged releases exist as of this writing.                                                                                                             |
| §4 trust assumption — Multiple maintainers                            | ✗ | ✗ | n/a | **One maintainer**, working with an AI assistant. This is a single-point-of-trust risk acknowledged here.                                                                          |

### 8.2 Consolidated carry-forward gaps

This is the same list that accumulated across CHANGELOG entries, surfaced in one place and mapped to the adversary classes affected. Order is rough priority for closing.

1. **Sealed-sender wrap on the daemon's hub path** (affects A2). **`msg/v1` (PFS-only) and `mls/v1` (PCS via MLS) paths both closed end-to-end as of T5.2.e**: `msg/v1` ships plaintext in `BootstrapPayload::PlainMessage`; `mls/v1` ships an MLS Welcome in `BootstrapPayload::MlsWelcome`. The recipient's `handle_hub_delivery` decodes both, registering the sender + (for `mls/v1`) joining the resulting MLS group via `MlsParty::join_from_welcome` and persisting the MLS snapshot. `mls/v1` is the strict upgrade: every application message exchanged in the resulting group has full MLS PCS. **Decode failures are silent at debug level** to prevent log-spam attacks from a hostile hub. **What remains**: the wire format for *ongoing* MLS application messages over the hub (so two peers who've never had a direct Tor circuit can chat continuously, not just bootstrap a group) — that's T6.x.
2. **PQ hybrid X25519 + ML-KEM-768 wired into the daemon path** (affects N5). **Partially closed in T5.2.a**: each identity now owns and persists a hybrid KEM keypair (`Identity::kem_public` / `Identity::kem_secret`). Not yet used in the Noise handshake or in any live envelope. Store-now-decrypt-later attackers who archive Noise + MLS traffic today still get plaintext eventually; the new KEM keypair starts protecting them only once the sealed-sender hub path goes live.
3. **Cover traffic on idle Tor circuits** (affects A2's "coarse activity" caveat and §5#1, #5). Frame buckets shape *transmitted* frames; idle circuits leak presence.
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
16. ~~**Hub can replay any sealed-sender envelope back to the recipient**~~ — **closed in T7.3-sec.2.** Before today the recipient daemon decoded every DELIVER frame the hub sent it without checking whether the same bytes had arrived before; a hostile hub could store one of alice→bob's envelopes and re-deliver it at any point, causing bob's daemon to surface a duplicate `EventMessage`. The fix is recipient-side: `DaemonState` now carries an `EnvelopeReplayGuard` (FIFO seen-set of BLAKE2b-128 hashes over the raw body bytes, capacity 4096 ≈ 64 KB of state). `handle_hub_delivery` consults it before any AEAD work and drops the delivery silently on a hit. 7 unit tests cover the guard semantics including the critical "replay does NOT refresh FIFO position" property (an attacker can't keep a real entry alive by spamming replays). **Known restart window**: the seen-set is in-memory only, so the first ~5 min after a daemon restart is replay-vulnerable; persistence is tracked as a follow-up. Defence is *purely recipient-side* — does not trust the hub for anything new.

15. ~~**Hub does not validate publisher ownership of a routing id when storing a KeyPackage**~~ — **closed in T7.3-sec.** The hub's `FRAME_KP_PUBLISH` handler now extracts the KP's embedded Ed25519 signing key (via the new `onyx_core::mls::signing_key_from_kp_bytes` free function), reconstructs the publisher's fingerprint (the fingerprint *is* the signing-key bytes by design), derives the expected `introduction_inbox(fingerprint)`, and rejects the publish if it doesn't match the claimed routing id. The recipient-side check in `handle_fetch_peer_keypackage` remains as defence-in-depth. Attack test added: `keypackage_publish_rejects_routing_id_mismatch` — an attacker who tries to overwrite alice's directory entry with their own KP gets silently rejected by the hub; alice's entry stays intact. The earlier "sign-challenge requires the hub to learn the publisher's Ed25519 key" note turned out to be wrong: the KP already *carries* the Ed25519 signing key, signed by itself (MLS leaf-node self-signature), so no out-of-band challenge is needed. Closed properly, not papered over.

Also rows in 8.1 updated this turn:

| §2 / §5 claim                                         | D | I | V | Notes                                                                                                                                |
|------------------------------------------------------|---|---|---|--------------------------------------------------------------------------------------------------------------------------------------|
| Per-identity hybrid KEM keypair (sealed-sender prerequisite) | ✓ | ✓ | unit + reopen-round-trip tests | T5.2.a. `Identity::kem_secret` / `kem_public`; persisted in vault schema v4. KEM keypair survives daemon restart. |
| Hub-client bidirectional outbound queue              | ✓ | ✓ | duplex round-trip test | T5.2.b. `hub_client::run_hub_session` accepts a `mpsc::Receiver<HubOutbound>` and writes `FRAME_DELIVER` frames via `tokio::select!`. |
| Sealed-sender `SendBootstrap` API verb               | ✓ | ✓ | 6 dispatcher tests incl. happy-path open + recover | T5.2.c. Wraps `BootstrapPayload::PlainMessage` in `seal_bootstrap` and pushes to hub. |
| Inbound hub-delivery decode → registry               | ✓ | ✓ | end-to-end registry test | T5.2.d. `handle_hub_delivery` tries `open_bootstrap` + `BootstrapPayload::from_cbor`; success → `register_hub_only` + `push_message_via_hub`. **Decode failures silent at debug level** (anti-log-spam against hostile hub). |
| `via_hub` indicator preserved across history backfill | ✓ | ✓ | `merge_history_dedupes_against_live_entries` extended | T5.2.d. `EventMessage` + `HistoryEntry` + ring `ChatLine` all carry `via_hub: bool`; restart + History fetch reconstructs the security tier. |

Each item is also enumerated in the relevant CHANGELOG entry. This list and the CHANGELOG must stay in sync.

---

*See `DESIGN.md` for the full system specification and `SECURITY.md` for the enforcement principles and disclosure policy.*
