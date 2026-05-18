# How Onyx Works

A plain-English walkthrough of what happens when two people use Onyx to chat, what protects each piece of that exchange, and **the specific evidence** behind every security claim — so you can verify rather than trust.

---

## 0. The honest framing (read this first)

This document explains how Onyx is **designed and built**. It does not claim Onyx is unbreakable. Here's the honest one-paragraph version:

> Onyx composes well-studied cryptographic primitives (Ed25519, X25519, ChaCha20-Poly1305, Argon2id, ML-KEM-768, MLS, Noise XK) implemented by audited Rust libraries. The way Onyx *wires those primitives together* — protocol code, state machines, daemon plumbing — has not been independently reviewed. We have 216 internal tests that exercise correctness. We do not have an external audit. Claims of "bulletproof," "unbreakable," or "military-grade" don't appear anywhere in this repository because they would be false. See `SECURITY.md` §1 for the full disclaimer.

When this document says "X is verified by Y," it means there's a specific test, specific RFC, or specific upstream audit you can point at. When it says "this *aims* to prevent X," it means the design intends it but the implementation has not been audited end-to-end.

---

## 1. A chat message's life, step by step

You're Alice. You want to send "hi" to Bob. Both of you are running `onyx tui` against your own `onyxd`. Here's what happens, in order.

```
                 you type "hi" and press Enter
                            │
   ┌────────────────────────▼────────────────────────┐
   │ 1. TUI sends {"kind":"Send","peer_short":"...", │
   │              "text":"hi"} over a Unix socket    │
   │              (chmod 0600, only your UID)        │
   └────────────────────────┬────────────────────────┘
                            │
   ┌────────────────────────▼────────────────────────┐
   │ 2. onyxd looks up the peer's outbound channel,  │
   │    pushes "hi" into it.                         │
   │    The "peer_session" task running for that     │
   │    peer wakes up.                               │
   └────────────────────────┬────────────────────────┘
                            │
   ┌────────────────────────▼────────────────────────┐
   │ 3. MLS layer encrypts "hi" under the current    │
   │    group's ratchet key. Output: ciphertext +    │
   │    authenticator over (sender, epoch, gen).     │
   │    Uses openmls 0.8 implementing RFC 9420.      │
   └────────────────────────┬────────────────────────┘
                            │
   ┌────────────────────────▼────────────────────────┐
   │ 4. The MLS ciphertext is wrapped in a "frame"   │
   │    (type tag + length + zero-padded to a fixed  │
   │    bucket size: 256, 1024, or 4096 bytes).      │
   │    Hides the actual message length from anyone  │
   │    watching the Noise tunnel.                   │
   └────────────────────────┬────────────────────────┘
                            │
   ┌────────────────────────▼────────────────────────┐
   │ 5. The Noise XK session (established at         │
   │    connection time) AEAD-encrypts the frame.    │
   │    Cipher suite: ChaCha20-Poly1305. Key:        │
   │    derived from Diffie-Hellman over the two     │
   │    parties' long-term X25519 keys + a fresh     │
   │    ephemeral.                                   │
   └────────────────────────┬────────────────────────┘
                            │
   ┌────────────────────────▼────────────────────────┐
   │ 6. Bytes go out over a Tor circuit (3 hops by   │
   │    default). Bob's hidden service descriptor    │
   │    is what alice's daemon dialled originally.   │
   │    Tor itself encrypts each hop separately.     │
   └────────────────────────┬────────────────────────┘
                            │
   ┌────────────────────────▼────────────────────────┐
   │ 7. Bob's daemon receives the Noise ciphertext,  │
   │    decrypts back to the framed payload, decodes │
   │    the frame, extracts the MLS ciphertext.      │
   └────────────────────────┬────────────────────────┘
                            │
   ┌────────────────────────▼────────────────────────┐
   │ 8. MLS layer decrypts → "hi" + sender's MLS     │
   │    credential signature (verified).             │
   └────────────────────────┬────────────────────────┘
                            │
   ┌────────────────────────▼────────────────────────┐
   │ 9. Bob's daemon pushes EventMessage onto its    │
   │    internal broadcast.                          │
   └────────────────────────┬────────────────────────┘
                            │
   ┌────────────────────────▼────────────────────────┐
   │ 10. Bob's TUI (subscribed via Tail) receives    │
   │     the event over its Unix socket and renders  │
   │     "alice: hi" in the conversation pane.       │
   └─────────────────────────────────────────────────┘
```

That's six different security layers your message traverses on its way to Bob. Each protects against a different kind of attacker. Each is independently verifiable.

---

## 2. The six layers and what each one is for

### Layer 1: Local Unix-domain socket (TUI ↔ daemon)

**What it is:** A `chmod 0600` socket file at `./onyxd.sock` (or wherever you point `--api-socket`). Only the daemon's UID can read or write it.

**What it protects against:** Other users on the same machine reading your chat through the socket.

**What it does NOT protect against:** Root on your machine. Malware running as your UID. Anyone with physical access to your unlocked terminal.

**Evidence:**
- `crates/onyxd/src/api_server.rs::bind_listener` sets `Permissions::from_mode(0o600)` immediately after bind.
- Verified by `ls -la onyxd.sock` showing `srw-------`.
- Threat model entry: `THREAT_MODEL.md` §2 A5.

### Layer 2: Vault encryption (data at rest)

**What it is:** A SQLite database (`onyx-state.db`) where every secret-bearing row is AEAD-sealed under a key derived from your passphrase via Argon2id.

**What it protects against:** Someone stealing your laptop, copying the SQLite file from a backup, or accessing the file system as another user.

**What it does NOT protect against:** Brute-forcing a weak passphrase. Cold-boot attacks against the unlocked-vault key in RAM. An attacker who is *on* your machine while you're using Onyx.

**Evidence:**
- KDF: Argon2id via `argon2 = "0.5"`. Parameters: 64 MiB memory, 3 iterations, 1 lane.
- AEAD: ChaCha20-Poly1305 via `chacha20poly1305 = "0.10"`.
- Wrong-passphrase detection: a "canary" plaintext is sealed at vault creation; failure to decrypt it at open means wrong passphrase. Test: `crates/onyx-core/src/storage.rs::tests::wrong_passphrase_rejected`.
- KEM keypair round-trips across vault close+reopen. Test: `crates/onyx-core/src/identity.rs::tests::kem_keypair_round_trips_across_reopen`.

### Layer 3: Sealed-sender envelope (first contact via hub)

**What it is:** A post-quantum hybrid construction. When Alice wants to reach Bob via the hub, she:
1. Generates a fresh ephemeral X25519 keypair and a fresh ML-KEM-768 ciphertext to Bob's hybrid KEM public.
2. Derives an AEAD key from both shared secrets combined via HKDF-SHA256.
3. Signs an inner payload (CBOR) with her Ed25519 signing key, binding her signing public + her identity public + the payload bytes.
4. Seals everything with the AEAD key.

**What it protects against:** The hub seeing who Alice is or what she's sending. A passive observer of the hub's traffic learning anything about Alice. A *future* quantum computer breaking the X25519 half (the ML-KEM-768 half remains).

**What it does NOT protect against:** A complete break of *both* X25519 *and* ML-KEM-768 (vanishingly unlikely; would be a "rewrite all of cryptography" event). A bug in our composition of those primitives (un-audited).

**Evidence:**
- ML-KEM-768 implementation: `ml-kem = "0.2"`. NIST PQ standard, implements FIPS 203.
- X25519 implementation: `x25519-dalek = "2"`. Well-audited (used by Tor, WireGuard, Signal Protocol).
- The hybrid combiner is in `crates/onyx-core/src/crypto.rs::combine_hybrid_secrets`. **Security property: secure as long as *either* X25519 or ML-KEM-768 is unbroken.** Test: `hybrid_kem_tampered_classical_half` and `hybrid_kem_tampered_pq_half` both confirm that flipping a single bit in either half changes the combined output.
- Signature verification is bound to the canonical bytes (`bootstrap_signing_bytes` in `routing.rs`) so a CBOR-encoding bug can't move bytes around under the signature. Test: `bootstrap_forged_signature_fails`.

### Layer 4: MLS group encryption (RFC 9420)

**What it is:** An IETF standard for asynchronous group key agreement with forward secrecy and post-compromise security. Every message is encrypted under a key derived from the group's current ratchet state. Every committed change (member add/remove, key update) advances the ratchet — meaning a key compromise at time T can't decrypt messages from time T+1.

**What it protects against:** An attacker who compromises one peer's MLS state at time T cannot decrypt messages exchanged before T (forward secrecy) or after the next ratchet step (post-compromise security).

**What it does NOT protect against:** An attacker who has compromised your peer right now reading the messages right now. Coercion of a peer to reveal what was said.

**Evidence:**
- Implementation: `openmls = "0.8"` and `openmls_rust_crypto = "0.8"`. OpenMLS is one of the two reference implementations of RFC 9420, developed by Phoenix R&D and Cryspen.
- Cipher suite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (the recommended-default suite from RFC 9420 §17.1).
- 30+ tests in `crates/onyx-core/src/mls.rs::tests` covering: solo group creation, invite + welcome round-trip, application message encryption + decryption in both directions, peer identity extraction from group members, KeyPackage validation.
- We do **not** independently re-verify MLS's forward secrecy or post-compromise security properties — those depend on the openmls implementation, which itself depends on the RFC. If MLS is wrong, Onyx is wrong here.

### Layer 5: Noise XK transport encryption

**What it is:** A handshake pattern from the [Noise Protocol Framework](https://noiseprotocol.org/). `Noise_XK_25519_ChaChaPoly_BLAKE2s` means: X25519 Diffie-Hellman, ChaCha20-Poly1305 AEAD, BLAKE2s hash, `XK` handshake (initiator knows responder's static; responder learns initiator's static during the handshake).

**What it protects against:** Anyone watching the network reading the content. Anyone impersonating the responder (the initiator validates the responder's static key matches what they expected). Replay attacks (per-direction nonces).

**What it does NOT protect against:** Traffic-analysis attacks on the encrypted stream (size, timing). A man-in-the-middle who has compromised the responder's static key.

**Evidence:**
- Implementation: `snow = "0.10"`. The most-used Noise implementation in Rust; used by tokio's `noise-protocol` ecosystem.
- Handshake pattern: `Noise_XK_25519_ChaChaPoly_BLAKE2s` matches the WireGuard transport for one of its handshake variants.
- After-handshake assertion in `onyxd::run_dial_mode`: after Noise XK completes, we verify `peer_static == peer_pub_bytes` (the pubkey the user passed via `--dial-pubkey`). Defense-in-depth in case a future change weakens the Noise guarantee.
- Tests: `crates/onyx-core/src/transport.rs::tests` covers handshake round-trip, wrong-responder rejection, tampered-ciphertext detection.

### Layer 6: Tor circuit (network-layer anonymity)

**What it is:** The Tor anonymity network. Your connection to Bob goes through three relays (guard, middle, exit/rendezvous), each of which only knows the previous and next hop. Bob runs a v3 hidden service; his daemon doesn't reveal his IP address to anyone.

**What it protects against:** Anyone watching the network identifying who is talking to whom. Bob learning Alice's IP (or vice versa).

**What it does NOT protect against:** A global passive adversary who can observe both ends of every Tor circuit (traffic confirmation). A coerced relay operator at the right position. A daemon that you've configured `--listen-tcp` on (which bypasses Tor — see `SECURITY.md` §6.2).

**Evidence:**
- Implementation: `arti-client = "0.42"`. Arti is the official Rust port of Tor, developed by the Tor Project.
- v3 hidden service implementation: `tor-hsservice = "0.42"` (from Arti).
- Anonymity is *Tor's* property, not Onyx's. The protections and limitations are documented in the [Tor Project's design docs](https://spec.torproject.org/). We don't claim to add anonymity; we claim to faithfully use Tor for transport.

---

## 3. Adversaries and what protects you against each

| Adversary | Their capability | What stops them in Onyx | Evidence |
|---|---|---|---|
| **A passive ISP / café Wi-Fi observer** | Sees all your IP traffic | Tor (Layer 6) — they see encrypted Tor traffic, can't tell who you're connected to | Standard Tor property. |
| **Someone running a Tor relay you happen to use** | Sees one hop's encrypted traffic | Tor multi-hop encryption (Layer 6) + Noise on top (Layer 5) — they see double-encrypted bytes | Standard Tor + Noise composition. |
| **Hub server operator (malicious or coerced)** | Sees ciphertext blobs + 16-byte routing IDs | E2E encryption (Layers 3, 4, 5) means they see ciphertext only. Sealed-sender envelope (Layer 3) means they don't learn the sender of bootstrap messages. | `THREAT_MODEL.md` §2 A2; tests in `routing.rs::tests` (sealed envelope round-trip + tampering detection). |
| **Someone who breaks into the hub and reads its disk** | Same as above + can replay stored ciphertext | MLS forward secrecy (Layer 4) — past messages remain encrypted under keys the hub never had | `THREAT_MODEL.md` §2 A3; openmls implements RFC 9420's ratchet. |
| **Active network attacker (injects, modifies, delays traffic)** | Can rewrite bytes on the wire | AEAD (Layers 4, 5) detects modification; signatures (Layer 4) detect impersonation; per-direction nonces (Layer 5) prevent replay | `THREAT_MODEL.md` §2 A4. |
| **Another user on your laptop** | Can read your files (if same UID), connect to your sockets | Vault AEAD (Layer 2); `chmod 0600` socket (Layer 1) | `THREAT_MODEL.md` §2 A5; `wrong_passphrase_rejected` test. |
| **Someone who steals your unlocked laptop** | Has full filesystem + RAM access | **Onyx does NOT protect you here.** Vault is unlocked in RAM; an unlocked machine is a compromised machine. | `THREAT_MODEL.md` §3 N2 ("Endpoint compromise"). |
| **A global passive adversary watching all of Tor** | Can correlate traffic at entry and exit | **Onyx does NOT fully protect you here.** Padding + cover traffic raise the cost; they don't eliminate it. Documented limitation. | `THREAT_MODEL.md` §3 N1. |
| **A future attacker with a working quantum computer** | Could break X25519 (eventually) | Hybrid sealed-sender envelope (Layer 3) uses X25519 *and* ML-KEM-768 — secure if *either* survives. MLS application messages (Layer 4) currently use X25519 only — future quantum work could decrypt archived traffic. | `THREAT_MODEL.md` §3 N5; partial mitigation since T5.2.a. |
| **A coerced user revealing their key** | Has the victim's private key + can produce signatures | **Onyx does NOT protect against this.** Coercion is outside the technical threat model. Messages carry Ed25519 signatures over the sender's long-term key, so a coerced recipient can cryptographically prove what someone said to them (non-deniability — also documented). | `THREAT_MODEL.md` §3 N3 + §6. |
| **A malicious or compelled Onyx developer pushing a backdoored update** | Could ship malware in a future release | **Onyx does NOT fully protect against this yet.** Mitigations *planned*: reproducible builds (not done), signed releases (not done), multiple maintainers (currently one), no auto-update. Today you trust the developer. | `THREAT_MODEL.md` §3 N4. |

---

## 4. How to verify the claims yourself

Every security claim above has either a test, an RFC, or an upstream audit you can examine. Here's the index.

### Run the tests yourself

```sh
cd onyx
cargo test --workspace
```

Should show ~216 passing tests. The security-relevant ones include:

| Test | What it proves |
|---|---|
| `storage::tests::wrong_passphrase_rejected` | Wrong vault passphrase fails to open, doesn't leak which is wrong |
| `storage::tests::tampered_blob_rejected` | A modified vault blob fails AEAD authentication |
| `identity::tests::kem_keypair_round_trips_across_reopen` | The hybrid KEM secret survives vault close+reopen (a sealed envelope encrypted *before* a restart still decrypts *after*) |
| `crypto::tests::hybrid_kem_secret_byte_round_trip` | Hybrid KEM secret serialization is lossless |
| `crypto::tests::hybrid_kem_tampered_classical_half` | Tampering with the X25519 half of a hybrid ciphertext is detected |
| `crypto::tests::hybrid_kem_tampered_pq_half` | Tampering with the ML-KEM half is detected |
| `transport::tests::*` | Noise XK handshake round-trips; tampered ciphertext is detected; wrong responder is rejected |
| `mls::tests::*` (30+) | MLS group creation, welcome, application message round-trip, member enumeration |
| `routing::tests::bootstrap_round_trip` | Sealed envelope round-trips with sender verification |
| `routing::tests::bootstrap_forged_signature_fails` | An envelope with a forged signature is rejected |
| `routing::tests::bootstrap_payload_unknown_variant_is_rejected` | Unknown wire-format versions are refused (no silent downgrade) |
| `api_server::tests::send_bootstrap_mls_validation_step_exists` | The recipient-fingerprint-vs-KP-signing-key validation is present in the code (a guardrail against a future refactor accidentally removing the check) |

### Check the upstream libraries

The dependencies that do the actual cryptography:

| Crate | What it is | Where to verify |
|---|---|---|
| `ed25519-dalek = "2"` | Ed25519 signing | [Source](https://github.com/dalek-cryptography/ed25519-dalek) — used by Solana, Substrate, others. Audited by Quarkslab in 2020 (v0.x). |
| `x25519-dalek = "2"` | X25519 ECDH | [Source](https://github.com/dalek-cryptography/x25519-dalek) — used by Tor, WireGuard, Signal Protocol implementations. |
| `chacha20poly1305 = "0.10"` | AEAD | [RustCrypto AEADs](https://github.com/RustCrypto/AEADs) — pure-Rust, well-reviewed. |
| `argon2 = "0.5"` | Password hashing | [RustCrypto password hashes](https://github.com/RustCrypto/password-hashes). |
| `ml-kem = "0.2"` | NIST PQ KEM | [RustCrypto KEMs](https://github.com/RustCrypto/KEMs) — implements [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf). |
| `snow = "0.10"` | Noise Protocol Framework | [Source](https://github.com/mcginty/snow) — used by hyperswarm, vodozemac, others. |
| `openmls = "0.8"` | MLS RFC 9420 | [Source](https://github.com/openmls/openmls) — primary reference implementation; developed and reviewed by Phoenix R&D and Cryspen. |
| `arti-client = "0.42"` | Embedded Tor | [Source](https://gitlab.torproject.org/tpo/core/arti) — official Tor Project Rust port. |

### Read the protocol references

| Standard | What it covers |
|---|---|
| [RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420) | Messaging Layer Security (MLS) — group key agreement, forward secrecy, post-compromise security |
| [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) | ChaCha20 + Poly1305 AEAD |
| [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) | Ed25519 signatures |
| [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) | X25519 |
| [RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106) | Argon2 |
| [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) | ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) |
| [Noise Protocol Framework](https://noiseprotocol.org/noise.html) | Noise handshake patterns including XK |
| [Tor design](https://spec.torproject.org/) | Onion routing + v3 hidden services |

### Check the wire format yourself

Every wire-format byte sequence has its layout documented inline in `crates/onyx-core/src/wire.rs`. The doc comments on `FRAME_DELIVER`, `FRAME_SUBSCRIBE`, `FRAME_KP_PUBLISH`, etc. describe exactly what bytes appear in what order. The `BootstrapPayload` enum in `routing.rs` shows the inner-envelope versioning scheme (`v: "msg/v1"` vs `v: "mls/v1"`) with a test that asserts the literal bytes contain the right tag.

---

## 5. How Onyx compares to other tools

| Property | Onyx (today) | Signal | IRC over TLS | Tor Messenger (RIP) | Briar |
|---|---|---|---|---|---|
| End-to-end encryption | ✓ MLS | ✓ Signal Protocol | ✗ (TLS to server only) | ✓ OTR | ✓ |
| Post-compromise security | ✓ (MLS ratchet) | ✓ (Double Ratchet) | ✗ | ✗ (OTR is forward-secret but not PCS) | ✓ |
| Post-quantum readiness | partial (hybrid sealed envelope; daemon path X25519-only) | none in protocol; planned | ✗ | ✗ | ✗ |
| Anonymous transport by default | ✓ (Tor) | ✗ (Signal sees your phone number + IP) | ✗ | ✓ (Tor) | ✓ (Tor + local mesh) |
| Server / hub sees plaintext | ✗ (hub holds only ciphertext) | ✗ (Signal servers are blind) | ✓ (IRC server holds everything) | varies | ✗ |
| Server / hub knows who is talking to whom | hub sees 16-byte routing IDs (`THREAT_MODEL.md` §2 A2) | sees source phone + dest phone | yes, full nick-to-nick | varies | mesh: nobody central |
| Offline messages | partial (`msg/v1` ships; `mls/v1` group is bootstrapped; ongoing MLS-over-hub is T6.x) | ✓ | yes, via server | varies | ✓ |
| Multi-device | ✗ (single device per identity in v0) | ✓ | client-dependent | ✗ | ✗ |
| Mobile clients | ✗ | ✓ | ✓ | retired | ✓ |
| Group rooms / channels | ✗ (planned, T6.3) | ✓ | ✓ (the whole point) | ✗ | ✓ |
| Voice / video | ✗ | ✓ | ✗ | ✗ | ✗ |
| External security audit | **none yet** | multiple, ongoing | the *protocol* is decades-tested | community-reviewed | yes |
| Mature deployment history | weeks | years, billions of users | decades | retired in 2018 | years |

**The honest summary:** if you want a chat app to ship to actual humans today, use Signal. If you want one optimized for resisting metadata observation by the server operator, use Briar. Onyx is interesting because it composes ideas from each (Signal's E2E discipline + Briar's anonymity-by-default + a post-quantum bootstrap envelope) in a single explicit codebase, but it has not earned the trust those mature tools have. Use it to learn, demo, and contribute. Not to bet anything important on.

---

## 6. What Onyx does NOT do (negative claims, explicit)

Things you might hope are true that **are not**:

- **Onyx is not audited.** No security firm has reviewed it. No academic has cryptanalyzed it. The author's day job is not security research.
- **Onyx does not protect you against malware on your own machine.** If something is keylogging you, Onyx encrypts what you type after it's already been logged.
- **Onyx does not protect you against being seen using Tor.** Your ISP can tell you're using Tor. If using Tor at all is suspicious in your environment, you need additional tooling (pluggable transports — not currently supported).
- **Onyx does not provide deniability.** Every message carries an Ed25519 signature over your long-term identity key. A recipient can prove cryptographically what you said. This is the same trade-off as PGP and was a deliberate choice (`THREAT_MODEL.md` §6).
- **Onyx does not (yet) have invite-only hubs.** Anyone who knows a hub's static key can connect. The recipient-side validation catches the dangerous case (a hub feeding bad KeyPackages) but a malicious hub can still drop or duplicate messages (`THREAT_MODEL.md` §8.2 #4, #15).
- **Onyx does not have reproducible builds.** You can't yet prove the binary you downloaded matches the source in this repo. Planned.
- **Onyx does not have signed releases.** No release artifacts at all yet. Build from source.
- **Onyx does not have multi-device support.** One vault per identity per machine. Bringing a new device means generating a new identity.
- **Onyx's `--listen-tcp` / `--dial-tcp` modes turn off anonymity.** They're for development. The daemon logs a loud warning. Don't deploy them.

If any of these is a deal-breaker for your use case, Onyx is the wrong tool. That's not a flaw in this document — that's information you need.

---

## 7. Want to help close one of the gaps?

The numbered carry-forward items in `THREAT_MODEL.md` §8.2 are explicit work-tickets. Picking any one and doing it well (with tests, docs, security analysis) is the most useful thing anyone could contribute.

The biggest gaps in priority order:

1. **External security audit.** Single most important thing missing. Would shrink §0 of this document significantly.
2. **Reproducible builds + signed releases.** Lets users verify what they ran matches what's in the repo.
3. **Hub auth (invite tokens).** Today the hub trusts whoever speaks Noise to it.
4. **Cover traffic for the daemon-to-hub link.** Currently size-bucket-padded but not constant-rate.
5. **`mls/v1` ongoing-message wire format over hub.** Async MLS chat without ever needing both peers on Tor simultaneously.

See `SECURITY.md` for the eight enforcement principles every contribution is reviewed against.

---

## 8. Related documents

- `README.md` — install + usage + troubleshooting
- `SECURITY.md` — enforcement principles, vulnerability disclosure, primitive table
- `THREAT_MODEL.md` — adversaries A1-A6 + non-adversaries N1-N7 + §8 implementation status table
- `DESIGN.md` — full protocol specification, wire formats, key derivations
- `CHANGELOG.md` — one entry per substantive change with security analysis + carry-forward
- Module doc-comments in `crates/onyx-core/src/*.rs` — per-subsystem detail

When this document and the others disagree, the others win. `SECURITY.md` §1 is the authoritative status disclaimer.
