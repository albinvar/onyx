# Onyx — How It Works, In Depth

*A complete, behind-the-scenes walkthrough of every layer and feature — from the cryptographic primitives up to the interface. Written to be deep but readable: each section explains not just **what** a feature is, but **how it actually works** underneath, and **why** it exists.*

---

## 0. The thesis (read this first)

Almost every messenger encrypts **what** you say. Onyx is built to hide **that you said it at all** — the *metadata*: who talks to whom, when, how often, from where, and whether you even exist on the network.

Encrypted content is a solved problem. **Metadata resistance is the hard, unsolved one**, and it's Onyx's entire reason to exist. Every design decision below serves one goal: an adversary who runs the relays, watches the network, *and* later seizes a device should learn as little as possible about a user's identity, social graph, and presence.

Onyx is built in Rust as a workspace of crates:
- **`onyx-core`** — all cryptography, wire formats, MLS, Tor, storage. The trust-critical core.
- **`onyx-daemon`** — the background service: connections, sessions, the local API.
- **`onyx-hub`** — the optional relay server.
- **`onyx`** — the all-in-one user binary (CLI + terminal UI), runs the daemon in-process.
- **`onyxd`** — the standalone daemon binary.
- **`onyx-metrics`** — an optional, privacy-preserving hub-liveness collector.

A strict rule is enforced in the code: **no crate above `onyx-core` is allowed to touch a raw crypto library directly.** Every primitive flows through one audited module, so there is a single place to reason about nonces, randomness, and zeroization.

---

## 1. Identity — who you are without being anyone

### 1.1 No phone, no email, no account
There is no signup. On first run your device **generates** an identity locally. You are never asked for a phone number, an email, or any real-world identifier. This is the foundation of anonymity: the system literally never learns who you are because it never asks.

### 1.2 Your identity is a key (actually, three)
An Onyx identity is a small bundle of cryptographic keys, all generated from your operating system's secure random source:

- **An Ed25519 signing key** — your *long-term identity*. The 32 raw bytes of its public half **are your fingerprint**. There is no separate "user ID"; the key *is* the name. This is what signs your messages and proves authorship.
- **An X25519 identity key** — used for the encrypted transport handshake (separate from signing, so the roles can't be confused).
- **A hybrid KEM keypair** — an **X25519 + ML-KEM-768** pair (classical + post-quantum) used to seal first-contact messages so a recipient who's offline can still receive them, and so the encryption survives future quantum computers.

### 1.3 The fingerprint
Your fingerprint is those 32 Ed25519 bytes, shown as **52 base32 characters** grouped in fours for human comparison (`fpr: aaaa bbbb cccc …`). The parser is deliberately forgiving — it tolerates whitespace, mixed case, and an optional `fpr:` prefix — so a friend can read it to you over the phone or you can paste it from anywhere. Comparing fingerprints out-of-band is how two people confirm they're really talking to each other (more on this in §11).

### 1.4 Everything secret is zeroized
Every secret type wipes itself from memory when it's dropped (`ZeroizeOnDrop`), and key bytes are held in `Zeroizing` wrappers so they don't linger on the stack. Even when keys are threaded between background tasks, they're round-tripped through zeroizing buffers.

---

## 2. The vault — local encrypted storage

### 2.1 Passphrase → key, the slow way on purpose
Your local data lives in a single SQLite file. On first launch you set a passphrase, which is stretched into a 32-byte key with **Argon2id** using strong parameters (**256 MiB of memory, 3 iterations, 4 lanes**). The memory-hardness is the point: it makes brute-forcing your passphrase enormously expensive even with custom hardware. A per-vault random 16-byte salt means two users with the same passphrase get completely different keys.

### 2.2 The canary — detecting a wrong passphrase
When the vault is created, a known marker string ("the canary") is encrypted under your key and stored. On unlock, Onyx tries to decrypt the canary: if the authentication tag fails, you typed the wrong passphrase, and you get a clean error instead of a corrupted session. It cannot tell "wrong passphrase" apart from "corrupted file" — by design, that distinction would leak information.

### 2.3 Sealed blobs (AEAD at the row level)
Sensitive key material — your identity secret, your MLS group state, the replay-guard snapshot — is sealed with **ChaCha20-Poly1305** before it's written: each blob is `random-nonce ‖ ciphertext ‖ tag`. A fresh random nonce per write means the same plaintext never produces the same bytes twice.

### 2.4 Passphrase rekey and backup
- **Rekey:** you can change your passphrase. Onyx verifies the old one via the canary, derives a new key under a fresh salt, then re-seals every sealed blob **inside a single database transaction** — so either the whole change lands or none of it does. Old key material is zeroized.
- **Backup:** you can export a copy of the vault file (stop the daemon first so the copy is consistent), restricted to owner-only permissions.

### 2.5 What the vault key pins, and a frank caveat
Argon2 + AEAD protect the **key material and MLS state**. *Be aware:* in the current build the SQLite file is not whole-file-encrypted, so some metadata columns (message history, contact addresses) are not yet sealed at the row level — closing that is active work. The honest framing today is: **strong encryption in transit, and key material protected at rest; full at-rest encryption of message history is in progress.**

---

## 3. The transport — everything rides Tor

### 3.1 Embedded Tor (Arti)
Onyx embeds **Arti**, the Tor Project's Rust implementation of Tor, *in-process*. There's no separate `tor` daemon to install, no control port, no IPC. The daemon **is** a Tor client. Every connection Onyx makes is a Tor circuit.

### 3.2 You are a hidden service
Each Onyx node can publish a **v3 onion service**. That `.onion` address is how other people reach you directly. Inbound rendezvous requests from Tor are accepted, wrapped in the encrypted transport, and become live conversations.

### 3.3 Per-conversation circuit isolation
Different peers and different hubs are dialed over **isolated Tor circuits** (`isolated_client()`), so the streams can't be trivially correlated as belonging to one user by a relay that happens to sit on two of them. (The *entry guard* is intentionally shared — see vanguards.)

### 3.4 Vanguards — defending against being found
A hidden service can be attacked by forcing it to build many circuits and statistically discovering its entry guard, then attacking that relay to locate you. Onyx pins **Full vanguards** (the strongest tier: two extra layers of slow-rotating "guard" relays — L2 of 4, L3 of 8 — between you and the rest of the network), and it does so **explicitly** so a hostile network consensus can't silently downgrade it. The defense is also verified at build time (a test fails if the vanguards feature is ever compiled out) and at startup (the effective mode is logged).

### 3.5 Tor bridges
For users in censored regions, Onyx supports **vanilla Tor bridges** — unlisted entry points so a network censor can't simply block all known Tor relays. A malformed bridge line fails closed (the daemon refuses to start) rather than silently falling back to public, blockable guards.

### 3.6 The no-clearnet guard
There are test/development modes that use plain TCP instead of Tor. To make sure those never leak in production, a **clearnet guard runs first thing at startup**: if any clearnet flag is set without an explicit `--allow-clearnet` acknowledgement, the daemon **refuses to start** with a loud error. There is no path that silently sends traffic outside Tor, and no fallback to clearnet if Tor fails — it just errors and retries Tor.

---

## 4. The encrypted channel — Noise + frame shaping

### 4.1 Noise XK handshake
On top of each Tor circuit, two nodes run a **Noise XK handshake** (the same pattern family WireGuard uses). XK means: the initiator knows and verifies the responder's static key in advance, and the initiator authenticates itself during the handshake. The result is a mutually authenticated, forward-secret channel. The handshake transcript hash is captured and reused later to bind signatures to *this specific connection* (defeating replay across connections).

### 4.2 Frame size buckets
Messages are padded to fixed size **buckets** (256 / 1024 / 4096 bytes) before being sent, with the real frame type hidden *inside* the encrypted payload. So a relay watching frame sizes can't distinguish a tiny "typing" signal from a short message — they're the same bucket on the wire. Anything larger is chunked into bucket-sized frames.

### 4.3 Cover traffic (two modes, opt-in)
To fight timing analysis, Onyx can emit decoy traffic:
- **Poisson cover** — random dummy frames sprinkled on top of real traffic.
- **Constant-rate "high security" mode** — the upstream link emits **exactly one frame per time slot**, real or padding, so the cadence is *invariant*: an observer can't tell chatting from idle. A stalled slot reschedules cleanly rather than bursting.

Both are off by default (they cost latency and bandwidth) and honestly scoped: today they cover the client→hub upstream; a constant-rate downstream is future work.

---

## 5. Cryptographic primitives — the toolbox

All funnelled through one module:
- **Ed25519** — signatures / identity.
- **X25519** — Diffie-Hellman key agreement (transport + KEM classical half).
- **ChaCha20-Poly1305** — authenticated encryption (AEAD) for everything.
- **HKDF-SHA256** — key derivation, with carefully separated context labels so a key derived for one purpose can never collide with another.
- **BLAKE2b** — fast hashing; 128-bit for routing IDs, 256-bit for file integrity.
- **Argon2id** — the passphrase KDF.

### 5.1 The post-quantum hybrid KEM (the interesting one)
Onyx combines **X25519** (classical) with **ML-KEM-768** (FIPS-203 post-quantum) so a shared secret is safe as long as **either** primitive is unbroken — the same defense-in-depth pattern as Signal's PQXDH and TLS's X25519MLKEM768.

The combiner is the **robust "X-Wing" construction**: it doesn't just hash the two shared secrets together — it binds the **entire transcript** (both ciphertext halves *and* both of the recipient's public keys) into the key derivation. This means a ciphertext can't be silently re-pointed at a different recipient, and tampering with either half changes the result. It also rejects degenerate (all-zero) Diffie-Hellman contributions. ML-KEM's "implicit rejection" (a tampered ciphertext yields a pseudo-random secret instead of an error) is neutralized because the full ciphertext is bound into the hash.

---

## 6. Group encryption — MLS (RFC 9420)

### 6.1 Why MLS
Onyx uses **MLS — the IETF's Messaging Layer Security standard** — for end-to-end encryption, including 1:1 DMs (modeled as a 2-person group). MLS is the modern successor to the Signal protocol's group approach: it gives **forward secrecy** (a stolen key can't decrypt past messages) and **post-compromise security** (the group "heals" after a compromise as keys ratchet forward), and it does so efficiently even for large groups. The ciphersuite is `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`.

### 6.2 Credentials = your identity
Your MLS credential's identity field is literally your Ed25519 fingerprint bytes, and the MLS signing key is your identity key. So the sender of every message is cryptographically bound to your real long-term identity — there's no separate, spoofable "display name" used for attribution. A member **cannot** stamp another member's fingerprint on a message.

### 6.3 KeyPackages, Welcomes, Commits
- A **KeyPackage** is a signed bundle that lets others add you to a group. It's validated (signature, lifetime, ciphersuite) before use.
- A **Welcome** brings a new member into a group with the current epoch's secrets.
- A **Commit** changes the group (adds/removes a member, rotates keys) and advances the **epoch**. Every member processes commits to stay in sync.

### 6.4 Removal and post-compromise security
Removing (kicking) a member issues a real MLS Remove commit and advances the epoch, so the removed member genuinely loses access to future messages — verified by tests where an evicted member can no longer decrypt.

### 6.5 Room admin authority
Rooms have an **admin/authority model**: membership-changing commits are checked against a recorded admin set before being merged, so not every member can unilaterally rewrite the roster. (Binding that admin set fully into signed group state — so it can't be asserted by a malicious inviter — is an area of ongoing hardening.)

### 6.6 Per-message replay & ordering
MLS itself rejects replayed or stale-epoch messages via its generation counters and epoch numbers. Messages that arrive "from the future" (before a commit you haven't seen) are buffered, then retried once you catch up — with a bounded buffer so a flood can't exhaust memory.

---

## 7. Sealed-sender & routing — how the relay stays blind

### 7.1 Routing IDs, not addresses
The relay never sees "Alice → Bob." It sees opaque 16-byte **routing IDs**. There are two kinds:
- **Introduction inbox** — `BLAKE2b-128(your fingerprint ‖ label)`. Deterministic, so anyone who has your contact card can compute where to drop a first-contact message. (It's also why first-contact reachability is opt-in — see §10.)
- **Session token** — derived from a **group-private MLS exporter secret** per (group, epoch). Unguessable (128-bit) and *unlinkable*: the relay can't tie a session token to an identity because it never sees the secret, and the token rotates every epoch.

### 7.2 Sealed-sender envelope
When you send a first-contact message through a relay, it's wrapped in a **sealed-sender envelope**:
1. A fresh ephemeral hybrid (X25519+ML-KEM-768) shared secret is established to the recipient's KEM public key.
2. The payload is AEAD-encrypted under a key derived from that secret.
3. The whole thing is signed by your Ed25519 identity — but **the recipient's public key is bound into both the signature and the AEAD's associated data.**

That last point defeats a "reflection" attack: a malicious recipient can't take your signed envelope and replay it to a *different* victim, because it only opens for the public key it was sealed to. The relay sees a blob on a routing ID and nothing else — not the sender, not the content.

---

## 8. The hub — an optional, blind relay

When two people are both online they talk **directly** (onion-to-onion, no server). The **hub** exists only for when the other person is offline.

### 8.1 What a hub does
- **Offline queue:** holds sealed blobs for a routing ID until the recipient comes online and drains them (a single SELECT+DELETE transaction, so no half-reads).
- **KeyPackage directory:** stores KeyPackages so peers can be found for first contact.
- **Subscribe/Deliver:** clients subscribe to their routing IDs; senders deliver blobs to them.

### 8.2 What a hub can never do
It only ever sees `routing-id → opaque ciphertext`. It can't read content (E2E), can't determine the real sender (sealed-sender), and — in the default private mode — can't link your activity to your long-term identity. It holds no plaintext keys. Even if someone seizes the hub's disk, they get ciphertext on rotating tokens.

### 8.3 Authentication & anti-abuse (the hardening layer)
- **Signed SUBSCRIBE:** subscribing to a routing ID requires an Ed25519 proof bound to *this connection's* handshake hash (so a captured proof can't be replayed on another connection). For *published* introduction inboxes, the hub verifies you actually own the fingerprint that inbox derives from — so you can't subscribe to someone else's inbox and steal their mail.
- **KeyPackage ownership:** the hub extracts the signing key embedded in a published KeyPackage, derives the expected inbox, and rejects mismatches — you can't overwrite someone else's directory entry.
- **Rate limiting:** a token-bucket keyed on the *authenticated* connection key (not a resettable connection ID), so reconnecting doesn't reset your budget. Default ~600 frames/minute.
- **Queue caps + fair eviction:** per-recipient depth cap (1024) and a global byte cap (256 MiB). Under pressure, the hub evicts the **oldest messages from the largest queue first**, so one heavy user can't starve everyone else.
- **Replay protection (recipient side):** the daemon remembers a rolling set of recently-seen envelope hashes and silently drops byte-identical re-deliveries — so a hostile hub can't re-inject an old message.

### 8.4 Federation — hubs that cooperate
Hubs run by different operators can peer. They **gossip the KeyPackage directory** (not message queues) so people on different hubs can still find each other. Gossip is authenticated to the same ownership standard as direct publishes, carries a small TTL to bound propagation, and skips the node it came from to prevent loops. No single hub ever holds the whole network's picture.

---

## 9. The daemon — the engine room

### 9.1 The local API
The user-facing app (CLI/TUI) talks to the daemon over a **Unix-domain socket** with line-delimited JSON. The socket is `chmod 0600` inside a `0700` directory, so only your user account can drive it. Requests cover everything: send a message, create/join/leave a room, send a file, list contacts, fetch history, tail live events.

### 9.2 The conversation registry
An in-memory map of who you're talking to — by full key and by a short ID — with each conversation's outbound channel. Short-ID collisions are refused (the original owner is kept and a warning logged) so an attacker can't grind a colliding short ID to misdirect your sends.

### 9.3 Reliable delivery machinery
- **Reconnect supervisor:** if a hub or peer link drops, a supervisor reconnects with capped exponential backoff (500 ms → 30 s), re-authenticating the peer's static key every attempt.
- **Send queue:** messages typed while a link is down are held in a bounded queue and flushed on reconnect — re-encrypted under the *current* MLS epoch at send time, never replayed as stale ciphertext.
- **Delivery worker:** inbound relay messages are handed to a single bounded worker queue instead of being processed inline on the read loop — so a flood of junk can't head-of-line-block or pin CPU on the connection.

### 9.4 Direct peer dial
You can dial a peer's `.onion` on demand (concurrent with listening), establishing a live session that registers like any other conversation. Tor-only; refuses to run on a no-Tor build.

### 9.5 DM hub fallback (opt-in)
Normally DMs go direct. If you enable it, an offline DM can fall back to the hub — sealed, and routed on the **unlinkable session token** (not your identity inbox), reusing the same audited sealed-sender path. Off by default, because routing first contact through a relay is a metadata trade-off the user should choose.

---

## 10. Anonymity by default — the D-1 principle

The single most important privacy property: **by default, the hub cannot link your activity to your identity.**

In the default ("private") mode, when your daemon connects to a hub it uses:
- a **fresh ephemeral** Noise key per connection (so the hub doesn't see a stable transport identity),
- a **fresh ephemeral signing key** for the SUBSCRIBE proof (so the proof doesn't carry your long-term Ed25519 key),
- **no KeyPackage publish** and **no introduction-inbox subscription** (so nothing fingerprint-derived is registered).

The only things it subscribes to are per-epoch session tokens, which carry no identity. **To the hub, you are an anonymous connection fetching blobs for meaningless rotating tokens.** Your established rooms and direct onion dials still work fully.

If you *want* to be reachable for first contact via a hub, you opt in (`--first-contact-reachable`), which publishes your KeyPackage and subscribes your identity inbox — knowingly trading that unlinkability for discoverability. It's a conscious choice, not a silent default.

---

## 11. First contact & trust — the hardest problem

### 11.1 Invites (hub-routed)
An **invite** is a `onyx://invite/v2?…` URL bundling your fingerprint, KEM public key, optional KeyPackage, hub list, an expiry, and a nonce — **signed** so individual fields can't be tampered with in transit. The signing key lives in the daemon, so even the UI's "copy my invite" goes through the daemon to produce a properly signed v2 link. **Unsigned (v1) invites are refused by default** (they're MITM-able); accepting one requires an explicit `--insecure` flag.

### 11.2 Connect codes (hub-free, direct)
A **connect code** is the minimalist counterpart: `onyx://connect/v1?onion=…&id=…` — just an onion address and an X25519 identity key, for dialing a peer directly with no relay involved. The Noise handshake cryptographically verifies the peer holds the secret for that key, so a tampered code simply fails to connect.

### 11.3 The honest limit, and safety numbers
A signed invite or a connect code proves *internal consistency* — it doesn't, by itself, prove the person who sent it to you is who you think (an attacker could send their *own* valid code). The real defense is **out-of-band verification**: comparing a **safety number** in person or over a trusted channel, the way Signal does. Onyx computes a deterministic, order-independent safety number two people can read to each other.

### 11.4 Pinning, verification, and key-change alarms
- **Trust-on-first-use pinning:** the first time you establish contact, the peer's identity key is pinned.
- **Verified flag:** once you've compared a safety number, you can mark a contact verified; the UI shows a badge.
- **Key-change detection:** if a pinned contact's key later changes (rotation — or a MITM attempt), Onyx flags it and **blocks outbound sends** to that contact until you re-verify, failing *closed* on any doubt.

---

## 12. Files

Files are sent as **chunked, encrypted transfers** inside the same group channel:
- The content is hashed (BLAKE2b-256) for integrity.
- The receiver reassembles chunks with strict validation: exact chunk sizes, no duplicate/overflowing indices, a per-peer in-flight limit, a global memory budget enforced *before* allocation, and a reaper that cleans up stalled transfers.
- **Executable refusal re-sniffs the assembled bytes** (not the sender's claimed type), so a renamed binary is still caught.
- Save paths are sandboxed: conversation keys are validated against a strict pattern and filenames are stripped of path separators, so a remote name can't escape the storage directory.

---

## 13. Rooms — multi-party chat

Rooms are MLS groups with more than two members. On top of the MLS mechanics:
- **Members** are tracked from the authenticated group roster.
- **KEM advertisement:** members advertise their hybrid KEM public key in-room (bound to their authenticated fingerprint, so a member can't poison another's entry), which is what lets an offline member receive a hub-fallback message later.
- **Admin/kick:** see §6.5 — authority-checked membership changes.
- **History & badges:** the UI marks hub-relayed messages with a `[hub]` tier badge so you always know whether a message came over the stronger direct path or the relay fallback.

---

## 14. The interface (TUI)

The terminal UI is a full client, not a toy:
- A branded first-run **passphrase wizard** (with fail-fast on a wrong passphrase, not a frozen screen).
- A **left rail** with an onion logo, peer list with presence/online badges, and daemon status including a **Tor bootstrap progress** indicator.
- A **two-line conversation list** with presence, timestamps, unread counts, and message previews.
- **Grouped, timestamped** chat rendering with `[hub]` tier badges and verified/key-changed badges.
- A **command palette** and **slash commands** in the composer.
- A **context action menu** (Tab), a **multi-select file picker**, **local message search** across conversations, **local retention / auto-clear**, and reliable clipboard copy via native OS tools.
- **Unified "Share / Add a contact" flows** that wrap invites and connect codes into two simple actions.
- A scrollable, color-coded **daemon-log overlay** for transparency into what's happening.

---

## 15. Reliability & the durability model

When you message an **offline** peer, your sealed envelope is **fanned out to every hub you're connected to** (a small configured set, e.g. 3–10) — so losing one hub usually doesn't lose the message; the recipient drains a surviving copy and dedups via the replay guard. Persistent SQLite queues mean a hub *restart* loses nothing. (Honest note: there's no hub-to-hub queue replication and no end-to-end delivery receipt yet, so reliability rests on this sender-side redundancy — closing that with acknowledged delivery + retry is on the roadmap.)

---

## 16. Telemetry — privacy-preserving by construction

Onyx ships an **optional** hub-liveness metrics system. Crucially, the heartbeat type is *structurally* incapable of carrying user activity — it contains only software version, an up flag, Tor-reachability, a coarse uptime bucket, and a 5-minute-snapped timestamp. **No connection counts, no user counts, no per-routing-id data.** Reports are signed, allowlisted, sent **Tor-only on a fresh isolated circuit**, kept latest-only (no history), and **off by default** on both the reporting hub and the public collector. It tells the world "this hub is alive," nothing about who uses it.

---

## 17. Platform, build & supply chain

- **Pure Rust**, memory-safe, with `panic = "abort"` and symbol-stripped release binaries.
- **Runs on Android** via Termux — including a **statically-linked aarch64-musl** binary (no proot needed) using Arti with rustls.
- **Reproducible-build** tooling and **Sigstore-keyless-signed releases**, so you can verify the binary you downloaded matches the public source.
- **`cargo-deny`** runs in CI (advisories, licenses, bans, sources) so a vulnerable or unvetted dependency fails the build.
- A **pre-push git hook** mirrors CI (format, clippy with warnings-as-errors, tests) locally.
- The whole project is built around a **published, honest threat model** that documents not just what it defends against, but what it explicitly does *not*.

---

## 18. How Onyx differs from every other app

| | Mainstream (WhatsApp/Telegram) | Signal | Onyx |
|---|---|---|---|
| Hides message content | partial / yes | ✅ yes | ✅ yes |
| Requires phone/email | ✅ yes | ✅ phone | ❌ none |
| Network anonymity (hides IP/location) | ❌ | ❌ (not native) | ✅ Tor-native |
| Hides *who talks to whom* from the server | ❌ | partial (sealed sender) | ✅ by design, unlinkable-by-default |
| Onion-to-onion direct (no server when online) | ❌ | ❌ | ✅ |
| Modern group crypto (MLS) | ❌ | own protocol | ✅ RFC 9420 |
| Post-quantum | emerging | ✅ (continuous) | ✅ (first-contact) |
| Cover traffic / anti-timing | ❌ | ❌ | ✅ opt-in |
| Defends against being *located* (vanguards) | ❌ | ❌ | ✅ |

**The one-sentence difference:** other apps work hard to hide *what you say*; Onyx is architected so that — even against the people running the relays and the network itself — **no single party can build the map of who talks to whom, when, or whether you're there at all.** The content is private. The pattern is private. The identity is yours alone, and it was never tied to your real name to begin with.

---

## 19. Honest limitations (so this document ages well)

A trustworthy explainer states its gaps. As of this writing:
- **At-rest encryption of message history/contacts** is not yet complete — strong in transit and for key material; full local-database encryption is in progress.
- **First-contact MITM** is mitigated by signed invites + pinning + safety numbers, but the strongest binding (safety numbers covering the full identity key, and a PAKE-based one-step verified exchange) is still being finished.
- **Post-quantum** currently protects first contact, not yet the ongoing group ratchet.
- **No external security audit yet**, and it's an early-stage project — the design is ambitious and largely implemented, but "designed to be secure" is not the same as "independently proven secure."

Onyx is an honest, ambitious attempt at the hardest problem in messaging — metadata-resistant, anonymous communication — built in the open, with its limits documented as plainly as its strengths.
