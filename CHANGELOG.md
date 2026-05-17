# Development Log

Append-only log of meaningful changes — design decisions, additions, removals, security-relevant tradeoffs. Newest entries on top. Each session gets one dated heading; sub-sections describe what landed and why.

Use this file as the single chronological view of where the project is. Implementation status of individual modules lives in code; this log captures *decisions*.

---

## 2026-05-18 — Initial scaffold + crypto primitives

### Design (`DESIGN.md`)
- Drafted v0.1, then revised to v0.2 after a focused review pass. Substantive changes from v0.1:
  - Frame `type` discriminator moved **inside** the AEAD envelope. Without this the hub could distinguish PAD from DELIVER on the wire and §5.7's cover-traffic guarantee would not hold against a hub-class adversary.
  - **Two-tier routing identifier scheme** (§5.5, revised). The single-tier "rotating secret" scheme from v0.1 had no story for first-contact bootstrap and was sender/recipient ambiguous. Replaced with:
    - Tier 1: long-term introduction inbox per recipient (`BLAKE2b-128(signing_pk || "onyx/v1/inbox")`), addressed via sealed-sender envelope (HPKE under the recipient's X25519 identity key).
    - Tier 2: rotating session tokens derived from the MLS exporter for the active group; clients pre-register batches.
  - **Padding buckets shrunk** to 256 / 1024 / 4096 B; >4 KB messages chunk into multiple LARGE frames instead of being placed in a 16 KB / 64 KB bucket that would leak "this user just sent something big."
  - **Non-deniability stated explicitly** as a v1 decision (§6.5). Every message carries a long-term-key signature; recipients gain transferable proof. Wire format reserves space to add deniable credentials later.
  - **Onion web tier hardened** (§8): gated by client-auth (stealth) onion, 5-minute idle / 30-minute absolute session timeouts, `<meta http-equiv="refresh">` polling removed (explicit refresh link instead), passphrase-attempt rate limiting (5 per 15-min, auto-disable at 20 failures), banner renamed to "Remote access mode" with stronger wording.
  - **Account recovery + multi-device sync** restated as deliberate v1 exclusions (§10) rather than mere "out of scope."
  - Smaller fixes: explicit key-confirmation after Noise XK handshake; note that onion v3 address ≡ signing key fingerprint with the UX implications; multi-identity caveat about shared process address space; Argon2id floor for low-memory devices.

### Threat model (`THREAT_MODEL.md`)
- Extracted as a standalone artifact so it can be read without the full design doc. Contents: assets in priority order, adversaries we defend against (A1–A6), adversaries we do not (N1–N7), trust assumptions, residual-linkability table, explicit non-deniability section.

### Workspace
- Cargo workspace at the repo root, edition 2024, `unsafe_code = "forbid"` workspace-wide.
- Pedantic clippy enabled with `-D warnings` (a few of the noisier pedantic lints allowed: `module_name_repetitions`, `missing_errors_doc`, `missing_panics_doc`, `doc_markdown`).
- Four crates under `crates/`: `onyx-core` (lib), `onyxd`, `onyx`, `onyx-hub` (bins). Binaries depend on `onyx-core` by path.
- `rust-toolchain.toml` pins the stable channel plus `rustfmt` and `clippy`. Toolchain installed for this work: `rustc 1.95.0` (stable, aarch64-apple-darwin).
- Module skeleton in `crates/onyx-core/src/`: `identity`, `mls`, `routing`, `storage`, `tor`, `transport`, `wire`, `error`. The non-crypto modules are doc-only at this point — each file's module comment references the DESIGN.md section it will implement. Constants shared across crates (frame-type IDs, padding-bucket sizes, KDF namespace, protocol version) live in `wire.rs` and `lib.rs`.

### `onyx_core::crypto`
- Single boundary file for all primitive use. Higher-level modules MUST NOT import `ed25519-dalek`, `chacha20poly1305`, etc. directly — they go through wrappers here. Centralising the boundary makes it possible to (a) apply uniform zeroize / constant-time policy, (b) audit one file for nonce / RNG / FFI bugs, (c) eventually swap implementations (e.g. add a PQ hybrid layer) without touching every call site.
- Wraps: Ed25519 (`SigningKey` / `VerifyingKey` / `Signature` / `Fingerprint`), X25519 (`IdentitySecret` / `IdentityPublic` / `SharedSecret`), ChaCha20-Poly1305 AEAD (`AeadKey` / `Nonce`), HKDF-SHA256, BLAKE2b-128, Argon2id, CSPRNG access, constant-time compare.
- Secret-bearing types zeroize on drop. `Debug` impls never print key material. `to_bytes` returns `Zeroizing<[u8; 32]>` so callers can't accidentally leave the seed on the stack.
- `Fingerprint` is the full 32-byte verifying key, displayed as 52 base32 characters (RFC 4648 lowercase, no padding) grouped in 4-char chunks. Parser tolerant of whitespace, mixed case, and an optional `fpr:` prefix.
- `Argon2Params::DEFAULT` = 256 MiB / t=3 / p=4. `Argon2Params::FLOOR` = 64 MiB / t=3 / p=2. The daemon refuses parameters below the floor.
- `Nonce::from_counter(u64)` produces 4 leading zero bytes + 8-byte BE counter (matches Noise / WireGuard convention).
- 16 unit tests: RFC 8032 Ed25519 test vector 1; RFC 5869 HKDF-SHA256 test vector 1; AEAD round-trip + tamper detection on ciphertext / AAD / nonce / key (4 paths); X25519 DH symmetry; BLAKE2b-128 determinism + chunking equivalence; Argon2id floor enforcement + determinism on equal inputs; fingerprint base32 round-trip + tolerant parsing of messy input; `ct_eq` behaviour including length mismatch; nonce-from-counter byte layout; ed25519 round-trip + wrong-signer rejection.
- Pinned `[workspace.dependencies]`: `ed25519-dalek 2` (features: `rand_core`, `zeroize`), `x25519-dalek 2` (features: `static_secrets`, `zeroize`), `chacha20poly1305 0.10`, `hkdf 0.12`, `sha2 0.10`, `blake2 0.10`, `argon2 0.5`, `rand_core 0.6` (feature: `getrandom`), `zeroize 1` (feature: `derive`), `subtle 2`, `base32 0.5`, `thiserror 2`.

### Verification at the close of this session
- `cargo check --workspace` ✓
- `cargo clippy --workspace --all-targets -- -D warnings` ✓
- `cargo test --workspace` ✓ (16 passing in `onyx-core`, 0 in the binary crates as expected)
- `cargo fmt --all --check` ✓
- Binaries `onyxd` / `onyx` / `onyx-hub` build and run; each prints its "scaffold only" banner and exits with code 1.

### Open security gaps the user explicitly flagged ("are we zero-trust / unbreakable / using all modern crypto?")
The honest answer is *not yet, and "unbreakable" isn't a property real systems have*. Specific carry-forwards:
- **No post-quantum.** In 2026 "modern crypto" includes hybrid ML-KEM-768 for KEX and ML-DSA-65 for signatures. Onyx uses neither. "Harvest now, decrypt later" is real for traffic captured today. Adding a PQ hybrid before any release is the largest single security improvement available — flagged as the strong candidate for the next session.
- **No supply-chain hardening.** No `cargo-deny`, no `cargo-vet`, no SBOM, no reproducible builds, no release signing. Need a CI pipeline with all of these.
- **No fuzzing / Miri / property tests** beyond the 16 unit tests.
- **No external audit.** Should not claim "audited" without a paid third-party engagement.
- **Known residual linkability** (already documented in DESIGN §5.5, THREAT_MODEL §5):
  - Introduction inbox is linkable to a fingerprint forever — anyone with your fingerprint can probe activity.
  - Long-term-key signatures on every message (non-deniability) — recipients gain transferable proof.
  - Padding buckets leak a size class to the hub.
- **8 of 9 modules still unimplemented.** Any claim about Onyx's security applies only to `crypto.rs` until the transport, MLS, routing, storage, identity, Tor, daemon, and hub layers exist.

---

*Next planned step: add post-quantum hybrid KEM (X25519 ‖ ML-KEM-768 through HKDF) to `crypto.rs`, then implement `wire.rs` envelope codec with property tests.*
