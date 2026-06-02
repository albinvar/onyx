# Onyx — External Security Audit Brief

**Status:** preparation document (F0.3 of the fortification plan). This is the
package an external auditor receives. It is maintained in-repo so it never
drifts from the code. THREAT_MODEL.md §8.2 names the external audit as the
single most important open item; this brief is the prep we own — the audit
execution itself is a third-party engagement.

> Honest framing for the auditor: the **confidentiality core has held two
> internal review passes**. What we most want challenged is (a) the
> cryptographic *composition* (sealed-sender + hybrid KEM + Noise + MLS
> binding), (b) the **anonymity / traffic-correlation** posture, and (c) the
> **hub trust boundary** under a malicious hub. We are not looking for
> reassurance; we are looking for the attack we missed.

---

## 1. What Onyx is

Onyx is an anonymous, end-to-end-encrypted chat system that runs **only over
Tor**. Peers are identified by an Ed25519 key (the fingerprint *is* the v3
onion identifier by design). Two transport paths exist:

- **Direct P2P** — each peer publishes a v3 hidden service; the other dials it
  by `.onion` (the "connect code" path). No third party.
- **Hub-relayed** — an untrusted-by-design relay (`onyx-hub`) routes opaque
  ciphertext by 16-byte routing IDs for offline/asynchronous delivery.

Message confidentiality/authentication is **MLS (RFC 9420)**; the transport is
**Noise XK**; first-contact bootstrap uses a **sealed-sender hybrid-KEM
envelope** (post-quantum X-Wing). All persisted state is sealed under an
Argon2id-derived vault key.

Full design: `DESIGN.md`. Adversary model + residual linkability:
`THREAT_MODEL.md`. Anonymity-specific accounting: `ANONYMITY.md`.

---

## 2. Audit target (freeze)

Audit a **single immutable commit**, not a moving branch. Recommended:

- Cut an annotated tag (e.g. `audit-2026-06`) at the agreed commit and hand the
  auditor that tag's hash.
- At the time of writing, `main` HEAD is **`284c83f`** (post-v0.1.19). Pick the
  freeze commit jointly with the auditor; do not rebase or force-push the
  audited tag for the engagement's duration.
- `Cargo.lock` is committed and `--locked` is enforced in CI and releases, so
  the exact dependency graph is pinned by the tag.

---

## 3. Scope

### In scope (priority order)
1. **Cryptographic composition** — `onyx-core`: hybrid KEM, sealed-sender
   envelope, Noise XK ↔ MLS key binding, vault sealing, KDF/domain separation.
2. **Protocol state machines** — handshake, group lifecycle (create/commit/
   join/welcome), replay defense, TOFU pinning + key-change enforcement.
3. **Hub trust boundary** — what a *malicious* `onyx-hub` can learn, forge,
   drop, replay, or correlate (`onyx-hub`).
4. **Anonymity posture** — traffic shaping (size buckets), cover traffic,
   circuit isolation, vanguards, the no-clearnet-leak guard; metadata leakage
   to the hub or a network observer.
5. **Memory hygiene** — secret zeroization, key lifetime, vault key in memory.

### Out of scope
- Tor itself / `arti` internals (we depend on it; we don't audit it here).
- `openmls` / `snow` / dalek internals (audited upstream; we audit our *use*).
- The TUI/CLI UX except where it changes a **security-relevant state display**
  (SECURITY.md P7) or a send-gate.
- Build/CI infrastructure beyond the reproducibility/signing claims in
  SECURITY.md §7 (those are separately attestable via
  `scripts/verify-reproducible-build.sh`).
- A global passive adversary correlating both endpoints' guard traffic — we
  state in THREAT_MODEL that no low-latency system defeats this; we want the
  *cost* assessed, not a claim that it's solved.

---

## 4. Codebase map

~34.8k lines of Rust across 5 crates; 465 `#[test]`/`#[tokio::test]` cases.
Edition 2024, MSRV 1.85. Supply-chain policy lives in `deny.toml` (cargo-deny
wired into `.github/workflows/ci.yml`).

| Crate | LOC | Role |
|-------|-----|------|
| `onyx-core` | 12.3k | **All cryptography + wire format.** The primary audit surface. |
| `onyx-daemon` | 11.0k | Session orchestration, send/receive paths, replay guard, pin enforcement, Tor wiring. |
| `onyx-hub` | 4.9k | The untrusted relay: routing-id subscribe/deliver, offline queue, rate/depth caps. |
| `onyx` | 6.4k | CLI + TUI client (talks to the daemon over a local socket). |
| `onyxd` | 0.2k | Thin daemon binary entrypoint (the library is `onyx-daemon`). |

---

## 5. Cryptographic inventory

Pinned versions from `Cargo.lock` at the freeze commit.

| Purpose | Primitive | Library (ver) | Where (file → symbol) |
|---------|-----------|---------------|------------------------|
| Identity / signing | Ed25519 | `ed25519-dalek` 2.2.0 | `onyx-core/src/crypto.rs` → `SigningKey`, `VerifyingKey::fingerprint` (fingerprint = raw vk = onion v3 id) |
| Transport handshake | Noise **XK** | `snow` 0.9.6 | `onyx-core/src/transport.rs` → `handshake_initiator/responder`, `Session`, `read/write_frame` |
| Group E2E | **MLS (RFC 9420)**, ciphersuite `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` | `openmls` 0.8.1 (+`_rust_crypto` 0.5) | `onyx-core/src/mls.rs` → `MlsParty`, `create_group`, `join_from_welcome`, `encrypt/decrypt_application`. MLS signing key == Noise auth key (deterministic binding via `MlsParty::from_identity`). |
| First-contact seal | **X-Wing hybrid KEM** (X25519 + ML-KEM-768) | `x25519-dalek` 2.0.1 + `ml-kem` 0.2.3 | `onyx-core/src/crypto.rs` → `HybridKemSecret::decapsulate`, `HybridKemPublic::encapsulate`; envelope at `onyx-core/src/routing.rs` → `seal/open_with_hybrid`, `seal/open_bootstrap` |
| AEAD (wire + vault) | ChaCha20-Poly1305 | `chacha20poly1305` 0.10.1 | `onyx-core/src/crypto.rs` → `AeadKey::encrypt/decrypt`; vault seal at `storage.rs` → `seal/unseal` (nonce‖ct‖tag) |
| Vault KDF | Argon2id | `argon2` 0.5.3 | `crypto.rs` → `Argon2Params` (**DEFAULT 256 MiB / t=3 / p=4**; FLOOR 64 MiB enforced at startup), `argon2id_kdf` |
| KDF / expand | HKDF-SHA256 | `hkdf` 0.12.4 + `sha2` 0.10.9 | key schedule in `crypto.rs` / `routing.rs` |
| Routing IDs | BLAKE2b-128 | `blake2` 0.10.6 | `routing.rs` → `introduction_inbox` (= H(fp‖"onyx/v1/inbox")), `session_token` (= H(group_secret‖idx)) |
| Wire format | CBOR | `ciborium` 0.2 | `onyx-core/src/wire.rs` → `MessageEnvelope`, size-bucket `InnerFrame`, `MAX_ENVELOPE_CBOR_BYTES` = 128 KiB |
| Constant-time | — | `subtle` 2 | comparisons of secret material |
| Memory hygiene | zeroize-on-drop | `zeroize` 1.8.2 | secret types across `crypto.rs` / `identity.rs` |

**Note on `openmls` 0.8 (deliberate):** the 0.6 line transitively pulls
`hpke-rs-rust-crypto` 0.2, which is affected by **RUSTSEC-2026-0072** (missing
all-zero X25519 shared-secret check). We track 0.8 specifically to get
`hpke-rs-rust-crypto` 0.6+. We separately want our **own** hybrid KEM decap
checked for the analogous all-zero/contributory-behaviour issue (open item,
see §7).

---

## 6. Trust boundaries

- **The hub is untrusted by design.** It sees: ciphertext envelopes, 16-byte
  routing IDs, connection timing, and the Noise static key of a *connected*
  client (used to key the per-identity rate limiter). It does **not** see:
  plaintext, group membership, fingerprints, or onion addresses. Key question
  for the auditor: *what can a malicious hub correlate or forge with exactly
  that view?* (See `onyx-hub/src/state.rs`, `rate_limit.rs`.)
- **The network observer** sees Tor traffic only. Onyx adds size-bucket padding
  (`wire.rs`) and optional cover/constant-rate traffic; the downstream
  (hub→client) cover half is still being built (Phase 1).
- **The local device** is trusted; the vault protects data at rest if the device
  is later seized *while locked*. No passphrase recovery by design.

---

## 7. Known open items (start here — don't re-find these)

Tracked in THREAT_MODEL.md §8 and our fortification plan. We disclose them so
the audit spends its time on the *unknown*:

- ✅ **Hybrid KEM all-zero / contributory check** on X25519 — **DONE** (F4.1).
  `decapsulate`/`encapsulate` now reject a non-contributory X25519 result
  (`was_contributory()`), so a low-order point can't strip the X25519 half.
- ✅ **`is_pin_compromised` now fails *closed*** on a vault read error (F4.2):
  `pin_block` refuses the send instead of allowing it.
- ✅ **Bootstrap send paths** now carry the pin cross-check (F4.3):
  `SendBootstrap`/`SendBootstrapMls` call `pin_block` at dispatch, parity
  with `SendInvite`'s Gate 3.
- ✅ **Pin-injection test** added (F4.4): `send_bootstrap_refuses_key_changed_peer`
  covers the previously-untested bootstrap path (DM/room already had A0.3 tests).
- **Traffic-correlation / timing** (partially closed, Phase 1): constant-rate
  is now available **both directions** (F1.1) and **measured at the wire
  observer** (F1.2, CV 0.002); the residual gap is *real-Tor* end-to-end
  measurement (operator drill) — cover traffic remains opt-in (F1.3 decision).
- **MLS authority model**: plain MLS lets any member add/remove any member; no
  admin/committer-authority gate yet (Phase 3 / G-2).
- **Reproducible builds**: demonstrated locally (byte-identical) but not yet
  confirmed cross-machine against *published* artifacts (SECURITY.md §7).
- **Oblivious first-contact relay**: deferred (PIR/ORAM); use connect-codes
  (ROTATION.md §6). Identity↔activity at the hub is decoupled in reachable
  mode (F2.1a).

We specifically invite: attacks on the **sealed-sender unlinkability**, the
**Noise↔MLS identity binding**, **replay** across the hub and gossip paths, and
any **metadata** a hub or observer can use to deanonymize.

---

## 8. How to build, test, and verify

```sh
cargo build --workspace --locked          # MSRV 1.85, edition 2024
cargo test  --workspace                    # 465 tests
cargo clippy --workspace --all-targets
cargo deny check                           # supply-chain policy (deny.toml)

# Reproduce a release binary from source and compare to the signed manifest:
scripts/verify-reproducible-build.sh <tag> SHA256SUMS.txt
```

Real-Tor exercises live under `scripts/` (e.g. `two-mac-connect-test.sh`,
`real_tor_smoke.sh`). Note: `arti`'s fs-mistrust rejects world-writable state
dirs — use a `0700` dir under `$HOME`, and use release builds (debug `arti`
bootstrap is slow).

---

## 9. Logistics

- **Disclosure:** see SECURITY.md §5 (preferred path + acknowledgement window).
- **Deliverable we expect:** findings with severity, affected file:line, repro,
  and recommended fix; we will track each as fixed / deferred / out-of-scope
  and update SECURITY.md §1 + THREAT_MODEL.md §8 with the audit reference on
  completion (SECURITY.md §8 describes exactly what changes post-audit).
- **License:** AGPL-3.0-or-later.
