# Onyx — Security Policy

**Version:** 0.1 (companion to `THREAT_MODEL.md` v0.2-draft and `DESIGN.md` v0.2-draft)
**Last updated:** 2026-05-18

This document is the canonical reference for two things:

1. **For users and reviewers:** what we promise, what we explicitly do NOT promise, and what the current implementation status of every claim is.
2. **For contributors:** the eight enforcement principles every PR must satisfy, with a concrete review checklist.

If you find an apparent gap between a claim here and what the code actually does, that is a finding — see **Vulnerability disclosure** below.

---

## 1. Status disclaimer (read this first)

Onyx is a pre-1.0 research and engineering project. As of the date above:

- **No external security audit has been conducted.** Not by anyone. Not at any depth.
- The codebase is approximately ten thousand lines of Rust, less than a month old.
- All cryptographic and protocol code was written by one developer in collaboration with an AI assistant. Independent review of every security-relevant module is required before any claim of production safety.
- No reproducible build pipeline exists yet. No signed releases exist yet.
- No fuzzing of wire-format decoders, vault loaders, or MLS framing has been performed beyond what `cargo test` and `proptest` cover (see `crates/onyx-core/src/*/tests`).
- No timing-side-channel analysis has been performed.

**Practical consequence:** Onyx is appropriate for learning, experimentation, hobby chat, and demonstrating that Noise + MLS + Tor compose correctly in Rust. It is **not** appropriate for any use where the safety, freedom, or livelihood of the user depends on the protocol's security. Use Signal, Briar, or similar mature tools for those situations.

We will update this section as the project matures. We will not remove a caveat that still applies.

---

## 2. Scope

### What this document covers

- The Onyx workspace: `crates/onyx-core` (the security boundary), `crates/onyxd` (the daemon), `crates/onyx` (the CLI/TUI client), `crates/onyx-hub` (the optional relay).
- Wire protocols defined in `crates/onyx-core/src/wire.rs` and `crates/onyx-core/src/api.rs`.
- Persistent storage defined in `crates/onyx-core/src/storage.rs`.
- Transport handshake + framing in `crates/onyx-core/src/transport.rs`.

### What this document does not cover

- The Tor network's own security properties (see the Tor Project's documentation).
- The Arti, OpenMLS, snow, ed25519-dalek, x25519-dalek, chacha20poly1305, argon2, rusqlite, ml-kem dependencies' internal security. We pin versions and read their advisories via `cargo deny`, but their soundness is upstream.
- Operating-system and hardware compromise. See `THREAT_MODEL.md` §3 (N2).
- The user's operational security (typing real names, screenshots, device compromise). See `THREAT_MODEL.md` §3 (N7).

---

## 3. Enforcement principles (the eight)

Every contribution to this project — code, configuration, dependency change, documentation that affects behaviour — is evaluated against these eight principles. They are not suggestions. They exist because *every* security failure in messaging-system history has been caused by violating one of them under deadline pressure.

Each principle includes a **rationale** (why it exists), an **example violation** (what it looks like when broken), and a **check** (how PR review verifies compliance).

### P1. Every cross-network frame is carried inside an established Noise + MLS session

**Rationale.** Once we admit any "control frame" or "metadata channel" that bypasses the encrypted tunnel, attackers attack it because it's the path of least resistance. There must be exactly one wire format and one cipher stack between two daemons.

**Example violation.** Adding a "ping" UDP datagram for liveness that's sent in cleartext outside the Noise session "because it's just a ping."

**Check.** Every new `FRAME_*` constant in `crates/onyx-core/src/wire.rs` is written and read only via `transport::write_frame` / `transport::read_frame`, which operate on an established `Session`. Reviewer searches the diff for any direct `stream.write_all(...)` or `stream.read_exact(...)` and questions it.

### P2. All persisted data is sealed under the vault key

**Rationale.** Plaintext on disk is the most common breach vector. There is no "low-sensitivity" data — even a list of conversation IDs reveals the social graph.

**Example violation.** Caching the peer-list response in `~/.onyx/peers.json` "for faster startup."

**Check.** New persisted data flows through `Vault::encrypt_blob` / `Vault::save_*` (see `crates/onyx-core/src/storage.rs`). Reviewer searches the diff for `fs::write`, `File::create`, `OpenOptions::write` outside the vault module and questions every one.

### P3. All identifiers are derived from keys, never assigned by a server

**Rationale.** A server that assigns names is a server that can take them away, impersonate via them, or correlate them. Identity must originate at the user's keypair and propagate via deterministic derivation.

**Example violation.** Allowing a hub to issue "friendly nicknames" mapped to fingerprints, even as a UI affordance.

**Check.** Every user-facing identifier (`short_id`, `fingerprint`, `pubkey_b32`, `inbox_routing_id`) traces back to a function in `crypto.rs` or `routing.rs` that takes only key material as input. Reviewer asks: "if the hub lied about this, would the user be misled?" If yes, the identifier is server-assigned and the PR is rejected.

### P4. All wire metadata goes through the size-bucket shaping pipeline

**Rationale.** Length leaks content. A single 64-byte frame in a sea of 256-byte buckets is a fingerprint.

**Example violation.** Adding an "ACK" frame type whose payload is one byte, exempting it from `InnerFrame::encode_padded`.

**Check.** Every `InnerFrame { frame_type, payload }` constructed in the codebase has a path to `encode_padded`. Reviewer verifies that no frame skips padding for performance, latency, or any other reason.

### P5. Forward-only protocol compatibility — no downgrade negotiation

**Rationale.** "Negotiate the best mutually-supported version" is how every major protocol downgrade attack works (POODLE, FREAK, Logjam). Always speak the latest version we know; refuse the older one outright.

**Example violation.** Reading a remote daemon's version string and falling back to `PROTOCOL_VERSION - 1` framing if it's older.

**Check.** `PROTOCOL_VERSION` in `crates/onyx-core/src/lib.rs` is constant per release. Any code that compares versions does so to *reject*, not adapt. Reviewer searches for `match` arms on version numbers that have a "compatible" branch and questions them.

### P6. No optional weakening — if a feature has a "less secure but easier" mode, that codepath must not exist

**Rationale.** Optional security becomes the default the moment a user hits a usability papercut. The Mongolian-government-issued CA bug, "downgrade to TLS 1.0," the `MD5` algorithm being available in `crypto.subtle` — all "we left it in for compatibility."

**Example violation.** A `--insecure-skip-tor` flag for testing that ships in the release binary.

**Check.** Test-only weakenings are gated behind `#[cfg(test)]` and never compiled into release. Reviewer searches the diff for any `cfg(feature = "...")` or runtime flag that changes a cryptographic choice and questions it.

### P7. Security-relevant UI state must be visible and unambiguous

**Rationale.** A user who cannot tell "this peer is verified" from "this peer might be an impostor" will eventually be tricked. Silent fallbacks are worse than loud failures.

**Example violation.** When `derive_peer_fingerprint` cannot extract the peer's Ed25519 from the MLS member list, it silently shows the peer's X25519 pubkey as if it were the fingerprint. (This is a current open issue — see `THREAT_MODEL.md` §8.)

**Check.** Every UI element that displays a peer identifier also displays its verification state. Fallback rendering must be visually distinct from the verified case. Reviewer adds a TUI snapshot test for the fallback path.

### P8. Audit before feature surface

**Rationale.** Every new user-facing feature adds protocol surface, persistent state, and UI affordances. Each is a potential vulnerability. Adding features faster than they can be reviewed accumulates security debt that compounds.

**Example violation.** Shipping voice/video before the existing text path has been externally audited.

**Check.** Before merging a PR that adds a new top-level capability (a new `ApiRequest` variant, a new wire frame type, a new persistent table), the reviewer answers in writing: "Has the current security boundary been externally reviewed since the last comparable expansion?" If no, the feature goes behind a `feature = "experimental"` gate or waits.

---

## 4. PR review checklist

Reviewer answers each of these for every non-trivial PR. "Trivial" is defined as: a one-line typo fix, a doc-only change with no code semantics, or a dependency version bump within the same minor that doesn't pull in new transitive crates.

- [ ] **P1.** Are all new cross-network frames sent inside an established Noise + MLS session?
- [ ] **P2.** Is all new persisted data sealed under the vault key? (No `fs::write` outside `storage.rs`?)
- [ ] **P3.** Are all new identifiers derived from key material, not assigned by a remote party?
- [ ] **P4.** Does every new `InnerFrame` go through `encode_padded`?
- [ ] **P5.** No new version-negotiation branches that "fall back" to older formats?
- [ ] **P6.** No new opt-in weakenings compiled into release? Test-only paths properly gated?
- [ ] **P7.** Does new UI display verification state alongside any peer identifier? Are fallback renderings visually distinct?
- [ ] **P8.** Does this PR expand the user-facing security surface? If yes, has the previous surface been audited?
- [ ] **Tests.** New security-relevant code has property-test or round-trip coverage in addition to happy-path tests?
- [ ] **Documentation.** If the PR changes a claim in `THREAT_MODEL.md` or implements a previously-deferred item, is the threat model updated in the same commit?
- [ ] **Dependency advisory.** `cargo deny check` still passes? New deps reviewed for transitive-dep risk?

A PR that fails any check is not merged. There is no "we'll fix it after." Issues opened for follow-up are not substitutes for fixing the issue before merge.

---

## 5. Vulnerability disclosure

### Preferred path

Use **GitHub Security Advisories** on the `albinvar/onyx` repository:

1. Go to `https://github.com/albinvar/onyx/security/advisories`.
2. Click "Report a vulnerability."
3. Describe the issue, the affected version (`git rev-parse HEAD` if you can), and reproduction steps.

This creates a private advisory that only repository maintainers can see. We will:

- Acknowledge receipt within **7 calendar days**.
- Provide an initial assessment (confirmed / not reproducible / out-of-scope) within **30 calendar days**.
- Coordinate on a fix and a disclosure timeline. We aim for fixes within **90 days** of confirmation for high-severity issues, longer for ones that need protocol changes.

### What counts as a vulnerability

A vulnerability is anything that contradicts a property claimed in `THREAT_MODEL.md` §2, including:

- An adversary class in §2 obtaining capabilities listed as "Cannot."
- A property claimed in §2 being unenforceable against a less-capable adversary than the one the §2 entry describes.
- A way to deanonymize, decrypt, impersonate, or replay that is not already documented in §3 or §5.
- A way to inject content as another user, or modify content in transit, that the protocol claims to prevent.
- A panic, crash, memory-safety issue, or `cargo clippy --warnings` regression that affects security-critical paths.

### What does NOT count as a vulnerability

These are known limitations, documented in `THREAT_MODEL.md` §3:

- Global passive adversary attacks (traffic confirmation).
- Endpoint compromise (root on the user's machine).
- Coercion of users (rubber-hose decryption).
- Cryptographic primitive breaks (Ed25519, X25519, ChaCha20 falling).
- The onion-web tier's documented tradeoff against daemon compromise.
- User operational-security failures (real names, screenshots, etc.).

If you're not sure whether something counts, open the advisory anyway — we'd rather triage one too many than miss something.

### What we ask of reporters

- **Do not publicly disclose** the vulnerability until we have shipped a fix (or 90 days have passed, whichever is sooner).
- **Do not exploit** the vulnerability beyond the minimum needed to demonstrate it.
- **Do not test on users you don't control.** Use your own daemon and your own peer.
- Coordinate timing for any public write-up; we will credit you.

We do not currently offer a bug bounty.

---

## 6. Cryptographic primitive choices

For transparency, the algorithms and version pins currently in use. Bumping any of these is a P5/P6/P8 review event.

| Layer | Primitive | Crate | Version | Rationale |
|---|---|---|---|---|
| Identity signing | Ed25519 | `ed25519-dalek` | 2.x | RFC 8032; ubiquitous; constant-time. |
| Identity DH | X25519 | `x25519-dalek` | 2.x | RFC 7748; pairs with the above. |
| Transport handshake | Noise XK | `snow` | (workspace pin) | `Noise_XK_25519_ChaChaPoly_BLAKE2s` — peer authentication + forward secrecy. |
| Group encryption | MLS (RFC 9420) | `openmls` | 0.8 | Post-compromise security; standardised; under active review by IETF. |
| Symmetric AEAD | ChaCha20-Poly1305 | `chacha20poly1305` | 0.10 | RFC 8439; software-fast; no timing oracles. |
| Hash (general) | SHA-256 | `sha2` | 0.10 | FIPS 180-4. |
| Hash (routing IDs, MAC) | BLAKE2b-128 | `blake2` | 0.10 | Faster than SHA-2; fixed 128-bit output for routing identifiers. |
| Vault KDF | Argon2id | `argon2` | 0.5 | Memory-hard; current RFC 9106 recommendations. |
| PQ KEM (helper, not yet wired) | ML-KEM-768 (Kyber) | `ml-kem` | 0.2 | NIST PQ standardisation; combined with X25519 via HKDF when wired. |
| Embedded Tor | Arti | `arti-client` | 0.42 | Pure-Rust Tor implementation; v3 onion services. |

No algorithm is selectable at runtime. No version is negotiable on the wire.

### 6.1 Wire-payload versioning (T5.2.c onwards)

The sealed-sender envelope's *inner payload* is a versioned tagged union (`routing::BootstrapPayload`). Today only one variant exists:

| `v` tag | variant | PFS | PCS | when used |
|---|---|---|---|---|
| `msg/v1` | `PlainMessage { text }` | yes (ephemeral KEM encap) | **no** (no MLS ratchet) | hub-relayed first-contact via `SendBootstrap` |
| *(planned)* `mls/v1` | `MlsWelcome { … }` | yes | yes | bootstrap an MLS group over the hub |

Recipients **refuse unknown `v` tags** rather than downgrade (P5 enforcement). The TUI is expected to render the tiers with distinct styling so users can read the threat model right; that rendering is tracked as a carry-forward item in `THREAT_MODEL.md` §8.2.

Hub-relayed `msg/v1` messages have **weaker forward-secrecy properties** than direct-MLS conversations:

  * Each `msg/v1` envelope gets its own fresh ephemeral X25519 + ML-KEM-768 encapsulation, so an attacker who later compromises the recipient's long-term KEM secret cannot decrypt past `msg/v1` envelopes they archived **unless** they also have the recipient's archived KEM secret at the moment of receipt. That gives per-message PFS.
  * There is no ratchet between successive `msg/v1` envelopes. An attacker who compromises the recipient's long-term KEM secret reads every `msg/v1` envelope sent to them after that compromise until the secret is rotated (the recipient gets a new KEM keypair). That's a real degradation from MLS PCS.

This tradeoff is the cost of letting "Alice → offline Bob" actually work without prior coordination. Closing the gap requires the planned `mls/v1` variant and a way for the sender to obtain the recipient's MLS KeyPackage out-of-band or via a directory service — neither of which exist today.

### 6.2 `--listen-tcp` / `--dial-tcp` test modes (T7.0)

`onyxd` has two **test-only** flags that bypass Tor entirely and run the full Noise + MLS chat path over plain TCP. Use case: development, local smoke tests, and CI exercises that can't tolerate a 30–60 s Tor bootstrap.

```
onyxd --listen-tcp 127.0.0.1:7710 ...
onyxd --dial-tcp 127.0.0.1:7710 --dial-pubkey <pub> ...
```

**Security implications, stated loudly**:

  * **No anonymity.** A plain TCP socket reveals the IP addresses of both peers to anyone on the network path. This is the whole reason Onyx normally uses Tor. The mode is named `--listen-tcp` and the daemon logs `LISTEN-TCP MODE — NO TOR, NO ANONYMITY. Test/dev only.` at startup so an operator can't miss the warning.
  * **The Noise + MLS payload encryption still applies.** A passive observer of the TCP traffic sees ciphertext, not plaintext — same as over Tor. The loss is *who is talking to whom*, not *what they're saying*.
  * **Reach is whatever the OS lets through.** `127.0.0.1` binds are local-only and safe. Binding to `0.0.0.0` would expose the daemon to anything routable to that IP. Operators should always prefer `127.0.0.1:PORT`.

Do not run `--listen-tcp` against real peers. The daemon will not stop you, but the loud log line + this section form the documented contract that this is testing-only.

---

## 7. What changes when we get audited

When an external security audit completes, this document will be updated as follows:

- **§1 (Status disclaimer)** — the "No external security audit has been conducted" line is replaced with a citation to the audit report, the date, the auditing organisation, and the commit hash audited. Findings are summarised with status (fixed / deferred / out-of-scope) and links to issues.
- **§3 (Enforcement principles)** — any principle the audit recommends adding is added. No principle is removed.
- **§5 (Vulnerability disclosure)** — the audit may shorten the acknowledgement window or add a bug-bounty section.
- **§6 (Cryptographic primitive choices)** — primitives the audit flags as insufficient are scheduled for replacement, with a deprecation window documented.
- **`THREAT_MODEL.md` §8 (Implementation status)** — each "designed / implemented / verified" row gains an audit reference where applicable.

Until then, treat every claim in this document and the threat model as **designed and implemented, but not externally verified**.

---

## 8. Related documents

- **`THREAT_MODEL.md`** — the adversary classes, defended assets, and residual-linkability accounting.
- **`DESIGN.md`** — the full protocol specification (wire formats, key derivation, frame types, group lifecycle).
- **`CHANGELOG.md`** — append-only log of every implemented change, with carry-forward security gaps explicitly listed per phase.
- **`README.md`** — getting-started orientation; not a security reference.

A security-relevant change to any of those documents accompanies the code change in the same commit.
