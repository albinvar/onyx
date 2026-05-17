# Onyx — Design Document

**Version:** 0.2-draft
**Status:** Pre-implementation design
**Scope:** Threat model, architecture, identity, transport, wire protocol, storage

---

## Changes from v0.1

This revision resolves issues raised in the v0.1 review. Summary:

- **§5.3 Frame format** — moved `type` field inside the AEAD envelope so the hub cannot distinguish frame types (notably PAD vs DELIVER) on the wire.
- **§5.5 Routing identifiers** — replaced the single-tier "rotating secret" scheme with a two-tier scheme: a long-term *introduction inbox* per recipient (used to bootstrap a contact) and *rotating session tokens* (used once an MLS group exists). The bootstrap case is now specified; the linkability tradeoffs are stated explicitly.
- **§5.7 Cover traffic** — updated to reflect that with the §5.3 change, PAD frames are indistinguishable from DELIVER frames to the hub as well as to the network.
- **§5.8 Size-class leakage (new)** — explicit subsection documenting that padding buckets leak one of five size classes to the hub, and the v1 mitigation (chunking).
- **§6.5 Non-deniability (new)** — explicit acknowledgement that every message is signed by a long-term Ed25519 credential, that this provides transferable proof to recipients, and the v1 decision to accept this.
- **§8 Onion web tier** — tightened: client-auth (stealth) onion required for this tier, session timeout reduced (5 min idle / 30 min absolute), `<meta refresh>` polling removed in favor of explicit refresh, passphrase-attempt rate limiting added, banner rewritten.
- **§9 Open questions** — questions resolved by this revision are marked accordingly; remaining ones flagged for Phase 1.
- **§10 Out of scope** — restated as deliberate v1 decisions rather than omissions, especially for account recovery and multi-device sync.

---

## 1. Project overview

Onyx is an anonymous, end-to-end-encrypted chat system that operates over Tor. It targets users who need both **content confidentiality** (only intended recipients read messages) and **metadata resistance** (the network and any servers learn as little as possible about who talks to whom).

The system has three interfaces, sharing a single Rust core:

- **CLI/TUI** — primary client, full security guarantees
- **Local web** — browser UI served on the user's own machine, full security
- **Onion web** — browser UI served as a Tor hidden service, JavaScript-free, lower security tier with documented tradeoffs

Transport is hybrid: peer-to-peer where possible (each user is a hidden service), hub-relayed where necessary (offline delivery, large rooms).

---

## 2. Threat model

Security is not a property; it is a relationship between a defense and an attacker. This section names the attackers Onyx defends against, the attackers it does not, and the specific assets it protects.

### 2.1 Assets

In priority order:

1. **Message content** — the words people exchange
2. **Identity linkage** — the connection between a pseudonymous Onyx identity and a real-world person
3. **Social graph** — who talks to whom
4. **Activity patterns** — when, how often, how much
5. **Membership** — which rooms a user is in
6. **Existence** — whether a given person uses Onyx at all

### 2.2 Adversaries we defend against

**A1. Passive network observer (ISP, employer, café Wi-Fi).**
Sees encrypted Tor traffic only. Cannot identify peers, read content, or determine destinations. Tor handles this entirely.

**A2. Hub server operator (including a malicious or coerced one).**
Sees encrypted message blobs in transit and at rest in offline queues. Sees pseudonymous routing identifiers (introduction inbox per recipient; rotating session tokens per active MLS group — see §5.5). Cannot decrypt message content. Cannot determine real-world identity of users. Can observe coarse activity on a per-inbox basis over time; see §5.5 and §5.8 for residual linkability.

**A3. Hub server attacker (someone who roots the hub).**
Same view as a malicious operator. Can additionally log traffic going forward. Cannot decrypt past or future messages. Cannot recover content from disk because the hub stores only ciphertext.

**A4. Active network attacker (can inject, modify, delay).**
Cannot read content (E2E). Cannot impersonate users (signatures). Can delay messages but not undetectably reorder them within a session (sequence numbers). Can perform denial of service.

**A5. Local non-privileged adversary on the user's device (other user accounts, processes without root).**
Cannot read Onyx data — encrypted at rest with passphrase-derived key. Cannot connect to a running Onyx daemon — local API authenticated with per-session token.

**A6. Casual targeted attacker.**
Someone trying to deanonymize a specific Onyx user without nation-state resources. Defeated by the combined defenses, assuming the user follows operational security guidance.

### 2.3 Adversaries we do NOT defend against

We are honest about these.

**N1. Global passive adversary.**
An entity that can observe most internet traffic simultaneously can perform traffic confirmation against Tor. Onyx does not defeat this. Mitigations (padding, cover traffic, jitter) raise the cost but do not eliminate the attack.

**N2. Endpoint compromise.**
If the user's device runs malware with sufficient privileges, no application-layer crypto saves them. The attacker reads the screen, captures keystrokes, exfiltrates keys from memory. Onyx assumes the local device is trusted; users with high-risk threat models should use Tails, Qubes, or equivalent.

**N3. Coercion of users.**
Legal compulsion, physical threat, or social engineering of a user to hand over their key or decrypted history is outside the technical threat model. Plausible-deniability features (panic wipe, decoy vaults) may help but are not guaranteed. Note that because Onyx messages are signed by long-term credentials (§6.5), a recipient under coercion can produce cryptographic proof of what a sender said.

**N4. Coercion of developers.**
A malicious or compelled update could backdoor users. Mitigations: reproducible builds, signed releases, public source, multiple maintainers, no auto-update. Users must verify what they install.

**N5. Cryptographic algorithm breaks.**
If Ed25519, X25519, ChaCha20-Poly1305, or MLS itself is broken in the future (including by quantum computers), past messages may become readable to anyone with archived ciphertext. Onyx does not currently use post-quantum primitives. This may change.

**N6. Onion web tier users.**
The onion web tier explicitly does not provide full E2E. The hub-served web UI decrypts to render HTML. Users connecting via the onion web accept that the hub server can read their messages for that session. This is documented on every page and the tier is gated by client-auth onion (see §8).

**N7. User operational security failures.**
Typing a real name, photographing a screen, using Onyx on a compromised device, reusing identifiers across services — Onyx cannot prevent these. Documentation will guide users; the rest is on them.

### 2.4 Trust assumptions

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

## 3. Architecture

### 3.1 System diagram

```
┌────────────────────────────────────────────────────────────┐
│                     User's device                          │
│                                                            │
│  ┌──────────┐    ┌──────────────┐    ┌─────────────────┐   │
│  │  TUI     │    │  Local web   │    │  Onion web      │   │
│  │ (ratatui)│    │  (axum, html)│    │  (axum, html)   │   │
│  └────┬─────┘    └──────┬───────┘    └────────┬────────┘   │
│       │                 │                     │            │
│       └─────────────────┼─────────────────────┘            │
│                         │                                  │
│              ┌──────────▼───────────┐                      │
│              │   Onyx core (Rust)   │                      │
│              │  ──────────────────  │                      │
│              │  • identity & keys   │                      │
│              │  • MLS state         │                      │
│              │  • message router    │                      │
│              │  • encrypted SQLite  │                      │
│              │  • Arti (Tor)        │                      │
│              └──────────┬───────────┘                      │
│                         │                                  │
│              ┌──────────▼───────────┐                      │
│              │     Embedded Tor     │                      │
│              │  ─ this user's .onion│                      │
│              │  ─ outbound circuits │                      │
│              └──────────┬───────────┘                      │
└─────────────────────────┼──────────────────────────────────┘
                          │
              Tor network (3-hop circuits)
                          │
   ┌──────────────────────┼──────────────────────┐
   │                      │                      │
   ▼                      ▼                      ▼
┌─────────┐         ┌──────────┐          ┌──────────┐
│ Peer's  │         │ Onyx hub │          │ Other    │
│ .onion  │         │ (relay)  │          │ peers    │
│         │         │          │          │          │
│ Direct  │         │ Stores   │          │          │
│ P2P     │         │ offline  │          │          │
│         │         │ queues,  │          │          │
│         │         │ relays   │          │          │
│         │         │ rooms    │          │          │
└─────────┘         └──────────┘          └──────────┘
```

### 3.2 Components

**Onyx core** is a single Rust library crate containing all security-critical code: identity management, key derivation, MLS group state, the wire protocol implementation, encrypted local storage, and the embedded Arti Tor client. Everything else is a thin interface around the core.

**`onyxd`** is the long-running daemon process. It wraps the core and exposes:

- A local Unix socket / authenticated TCP API for the TUI and local web frontends
- A hidden service endpoint for inbound peer connections and inbound hub deliveries

**`onyx`** is the CLI/TUI client. It is the reference interface. All security guarantees are validated against this client.

**`onyx-hub`** is the optional relay server. Multiple instances can exist; users can connect to one or several. The hub:

- Holds an authenticated hidden service
- Maintains encrypted offline message queues per recipient pseudonym
- Hosts MLS-encrypted group rooms
- Routes messages between connected clients
- Never sees plaintext

**Onion web tier** is a sub-mode of `onyxd` that exposes a server-rendered HTML interface on its hidden service. This is the only tier where the daemon decrypts user messages for the purpose of rendering them to a remote browser. It is opt-in, off by default, gated by client-auth onion (§8.1), and clearly marked.

### 3.3 Process model

- One `onyxd` per user, per device
- One `onyx-hub` per hub operator
- TUI / local web / onion web are clients of `onyxd`, not separate trust boundaries

### 3.4 Transport selection logic

When sending a message to a recipient:

```
if recipient is a direct contact AND recipient.onion is online:
    send via P2P directly to recipient.onion
elif recipient is a direct contact AND offline:
    send via hub (encrypted blob to recipient's pseudonym queue)
elif recipient is a room:
    send via hub hosting the room
```

The choice is invisible to the user except as a status indicator: a small green dot on a message indicates P2P delivery; a yellow dot indicates hub-relayed delivery.

---

## 4. Identity

### 4.1 Keys

Each Onyx identity owns:

- **Signing key** (Ed25519) — long-term, used to sign all outbound messages and authenticate to peers and hubs
- **Identity key** (X25519) — long-term, used for initial key agreement when adding contacts
- **Onion service key** (Ed25519 v3) — the hidden service this user publishes; **derived deterministically from the signing key**. Note: this means the user's permanent identifier (fingerprint of the signing key) and their `.onion` address are mathematically equivalent. Rotating identity therefore rotates the onion, breaking inbound connections from contacts who have not been re-told the new address.
- **MLS leaf keys** — ephemeral, one per group membership, rotated frequently by MLS

The signing key is the root of identity. Its public part, displayed as a 32-character base32 fingerprint, is the user's permanent identifier. Example:

```
nick: phantom
fpr:  a3f18e2d c047b91f 5e2a6d10 4f8b9c2e
```

Users always identify each other by fingerprint, never by nickname. Nicknames are user-chosen labels with no uniqueness guarantee.

### 4.2 Identity lifecycle

- **Creation:** on first run, the daemon generates a fresh keypair, derives a hidden service from it, and stores everything encrypted with the user's passphrase.
- **Export / backup:** the user can export their identity to an encrypted file (passphrase-protected) for backup or device migration. See §10 on account recovery — this backup is the only recovery path.
- **Rotation:** advanced users can generate a new identity at any time (`/identity new`). Contacts who knew the old identity must be re-verified.
- **Multiple identities:** one daemon can hold multiple identities, switchable per-room. **Important caveat:** these identities share a process address space, so a memory-disclosure bug (in Onyx or a dependency) leaks all of them. The "burner" persona is not isolated from "work" — for hard isolation, run separate `onyxd` instances under separate OS users.
- **Destruction:** `/wipe` zeroizes all keys in memory, deletes the local database, and exits. Recoverable only from external backup.

### 4.3 Contact verification

Adding a contact requires exchanging fingerprints out of band. The chat itself cannot bootstrap trust — that would be circular.

Verification flow:

1. User A and user B exchange their fingerprints via a separate channel (Signal, in person, signed PGP email, physical paper)
2. User A enters B's fingerprint into Onyx with a nickname
3. When A's daemon first connects to B's onion, it verifies the served key matches the entered fingerprint
4. Mismatch → connection rejected, loud warning
5. Match → contact verified, persisted

For convenience, Onyx supports **safety numbers** (Signal-style emoji sequences or short word lists) for faster verbal verification: "did you read me 'horse battery staple correct' as the first four words?"

### 4.4 No central directory

There is no Onyx-wide directory of users. There is no namespace. Two users can have the same nickname; only fingerprints disambiguate. Hubs may maintain local directories of their own users, but these are not authoritative or global.

---

## 5. Transport — wire protocol

### 5.1 Layers

```
┌────────────────────────────────────────┐
│  Application messages (MLS-encrypted)  │  ← end-to-end encrypted, padded
├────────────────────────────────────────┤
│  Onyx frame protocol                   │  ← framing, sequence, type
├────────────────────────────────────────┤
│  Noise_XK handshake + transport        │  ← peer authentication
├────────────────────────────────────────┤
│  TCP over Tor (.onion ↔ .onion)        │  ← network anonymity
└────────────────────────────────────────┘
```

### 5.2 Connection handshake (peer-to-peer or client-to-hub)

Onyx uses the **Noise Protocol Framework**, specifically the `Noise_XK_25519_ChaChaPoly_BLAKE2s` pattern, for transport-level authentication and encryption.

Why Noise XK:
- **X** — initiator's static key is transmitted but encrypted
- **K** — responder's static key is known to initiator in advance (we have the fingerprint)
- Provides mutual authentication, forward secrecy, identity hiding for the initiator
- Battle-tested (WireGuard, libp2p use Noise)

Sequence:

```
Client (initiator)                           Server / Peer (responder)
       │                                              │
       │── e ────────────────────────────────────────▶│   (ephemeral pubkey)
       │                                              │
       │◀──────────────────── e, ee ──────────────────│   (their ephemeral, DH)
       │                                              │
       │── s, se ────────────────────────────────────▶│   (our static, DH)
       │                                              │
   ── transport keys derived, channel is now AEAD ──
```

Noise XK provides **explicit mutual authentication** by the end of the third message:

- the responder's static key is authenticated to the initiator via the AEAD tag on message 2 (the `ee` DH binds it),
- the initiator's static key is authenticated to the responder via the AEAD tag on message 3 (the `se` DH binds it).

There is no implicit-auth gap to close, so we do not emit an extra key-confirmation round trip after the handshake (a v0.2-draft of this document mistakenly required one). After message 3 both sides have a symmetric key for ChaCha20-Poly1305 framing on the channel and can immediately exchange application traffic.

### 5.3 Frame format

Every frame on the wire after handshake:

```
0       2                                          N
┌───────┬──────────────────────────────────────────┐
│ len   │  ChaCha20-Poly1305(type ‖ payload)       │
│ u16   │  ──────────────────────────────────────  │
│       │  AEAD: 2-byte type + CBOR payload + tag  │
└───────┴──────────────────────────────────────────┘
```

- `len` — total frame length in bytes (includes the 2-byte header)
- Everything after `len` is one AEAD block. Plaintext begins with a 2-byte `type` discriminator, then a CBOR-encoded payload. The 16-byte Poly1305 tag is appended.
- Nonce: 96-bit per-direction frame counter, never reused, reset only by re-handshake.

**The `type` field moves inside the AEAD envelope (changed from v0.1).** Consequence: an on-path observer — including the hub on its own connection to a client — cannot distinguish frame types without holding the transport key, and even with the transport key cannot distinguish PAD from DELIVER without decrypting. This is what makes the cover traffic in §5.7 effective against hub-class adversaries.

**Frame types:**

| ID    | Name              | Direction       | Purpose                              |
|-------|-------------------|-----------------|--------------------------------------|
| 0x01  | HELLO             | client → server | initial protocol version negotiation |
| 0x02  | HELLO_ACK         | server → client | accept and assign session id         |
| 0x10  | DELIVER           | either          | deliver an MLS-encrypted message     |
| 0x11  | ACK               | either          | acknowledge a DELIVER                |
| 0x20  | FETCH             | client → hub    | pull queued messages                 |
| 0x21  | FETCH_RESPONSE    | hub → client    | a batch of queued messages           |
| 0x22  | SUBSCRIBE         | client → hub    | listen for live deliveries to a room |
| 0x30  | ROOM_OP           | client → hub    | create/join/leave/admin a room       |
| 0x31  | ROOM_OP_ACK       | hub → client    | result of a room op                  |
| 0x40  | PING              | either          | keepalive                            |
| 0x41  | PONG              | either          | keepalive response                   |
| 0xF0  | PAD               | either          | cover traffic (discarded by receiver)|
| 0xFF  | ERROR             | either          | protocol error, close connection     |

To keep frame sizes uniform regardless of type, the daemon pads every frame's plaintext (inside the AEAD) to the next bucket (§5.8) before encryption. The hub therefore sees frames that are indistinguishable in size and indistinguishable in type.

### 5.4 Message envelope

The actual content of a `DELIVER` frame is an envelope:

```cbor
{
  "v":        1,                          ; protocol version
  "to":       <recipient_routing_id>,     ; introduction inbox OR rotating session token
  "from":     <sender_routing_id_or_null>,; optional; null for sealed-sender bootstrap
  "room":     <room_id_or_null>,          ; null for DM
  "ts":       <unix_ms>,                  ; sender's clock (advisory)
  "nonce":    <random_12_bytes>,
  "pad_to":   <bucket_size>,              ; 256, 1024, 4096
  "mls":      <opaque mls ciphertext>,    ; MLS application or welcome message
  "sig":      <ed25519_signature_or_null> ; over all above fields; null in sealed-sender bootstrap
}
```

The MLS layer inside provides forward secrecy, post-compromise security, and group key management. For non-bootstrap messages the Ed25519 signature is over the envelope so the hub cannot tamper with routing fields without detection by the recipient. For the bootstrap envelope (§5.5), authentication is internal to the sealed payload; the outer signature is omitted to avoid linking the sender's long-term key to the hub-visible envelope.

`pad_to` indicates the bucket the daemon will pad the frame to. See §5.8 for buckets and leakage analysis.

### 5.5 Routing identifiers (revised)

The hub needs *some* identifier to deliver each message to the right queue. We use a two-tier scheme.

#### Tier 1: introduction inbox (per recipient, long-term)

When a user first registers with a hub, they publish a single **introduction inbox identifier**:

```
inbox_id = BLAKE2b-128(recipient_signing_pk || "onyx/v1/inbox")
```

This is a 16-byte tag, deterministic from the recipient's long-term signing key. The hub stores this as the user's "front door" queue.

A sender who has only the recipient's fingerprint (i.e. just added them as a contact, no shared session state) computes the same `inbox_id` from the recipient's signing key and sends a **bootstrap envelope** addressed to it. The bootstrap envelope is a *sealed-sender* construction:

```
sealed = X25519-seal(recipient_identity_pk, payload)
payload = { sender_signing_pk, sender_identity_pk, mls_welcome, signature_over_payload }
```

- `X25519-seal` is HPKE base-mode (RFC 9180) with X25519/HKDF-SHA256/ChaCha20-Poly1305. It hides the sender entirely from anyone other than the recipient.
- The recipient decrypts, verifies the inner signature, learns who's introducing themselves, and processes the MLS welcome.
- The outer DELIVER envelope omits `from` and `sig` (both null) so the hub sees only "something arrived at inbox X."

**What the hub learns from the introduction inbox:**
- The inbox is active.
- Coarse arrival times and message sizes.
- The number of distinct ciphertexts arriving (but not who sent them — sealed-sender).
- **NOT** the sender, the social graph, or message content.

The inbox is long-term and tied to the recipient's identity. This is an acknowledged linkability cost: anyone who knows the recipient's signing key can compute their inbox and observe whether messages are arriving. Mitigation: clients SHOULD rate-limit and pad inbox traffic so an external adversary that learns a fingerprint cannot use the hub as an "is this person online?" oracle.

#### Tier 2: rotating session tokens (per MLS group, per epoch)

Once a sender and recipient share an MLS group (which happens immediately after a successful introduction, since DMs are 2-member groups), all subsequent messages use rotating session tokens instead of the long-term inbox.

For each MLS epoch *e*, every member derives a set of session tokens from the MLS exporter:

```
group_secret_e   = MLS-Exporter(group, "onyx/v1/routing", 32)
token_e_i        = BLAKE2b-128(group_secret_e || u64_be(i))
```

where `i` is a rolling counter. Each member pre-registers the next K (default 64) tokens they will accept with the hub by sending a SUBSCRIBE frame containing the token set. The hub stores the (token → queue) mapping with no information about which group or which member the tokens belong to. When a sender wants to message the group, they pick the next unused token and send DELIVER to it.

**Properties:**
- The hub sees a stream of 16-byte opaque tokens with no relation to each other from one epoch to the next (each epoch derives a fresh `group_secret_e`). Token-to-token unlinkability across epochs is contingent on the MLS exporter property.
- Rotation happens on every MLS commit (member add/remove, scheduled Update, or explicit user-requested rotation). The default is to issue a self-Update every 24 hours of activity to force epoch turnover.
- A hub that records all tokens forever can still correlate "tokens registered in the same SUBSCRIBE frame belong to the same client connection." To break this, clients SHOULD register tokens in small batches across distinct hub connections (cycling Tor circuits between batches). This is a recommended mitigation, not a default — it costs latency and circuit count.

#### Residual linkability (honest accounting)

The hub can still observe:

1. **Per-inbox activity** (Tier 1) — anyone who knows your fingerprint can derive your inbox and watch the hub's published metrics (if any) or run their own probes. **Mitigation:** padding + cover traffic; do not publish inbox metrics.
2. **Per-connection token clusters** (Tier 2) — tokens registered in one SUBSCRIBE are linked. **Mitigation:** distribute registration across circuits.
3. **Epoch-boundary intersection attacks** — if a recipient is online during epoch *e* and offline during epoch *e+1*, the set of tokens registered in *e+1* corresponds to whoever was online for the commit. **Mitigation:** none ideal at v1; documented limit.
4. **Inbox-to-inbox bootstrap correlation** — back-to-back bootstrap envelopes to two inboxes from one Tor circuit suggest a shared sender. **Mitigation:** rate-limit bootstraps per circuit; offer "send introductions later" queuing.

### 5.6 P2P direct connections

For direct contact-to-contact messaging when both are online, the same wire protocol runs directly between the two `.onion` endpoints. No hub involved. The "server" role in the handshake is whichever side accepted the inbound connection.

Each Onyx daemon listens on its own hidden service for inbound peer connections. The daemon decides whether to accept based on whether the connecting key is a known contact. Unknown connecting keys are dropped at the Noise handshake stage; their static key is captured in `s` and matched against the contact list.

### 5.7 Cover traffic (revised)

When idle, the daemon may emit `PAD` frames at randomized intervals to known peers and hubs. Because the frame `type` is inside the AEAD envelope (§5.3), an entity holding the transport key — including the hub on its own connection to the client — cannot distinguish `PAD` from `DELIVER` without decrypting the AEAD plaintext. The only signal that survives is the per-frame timing and the (fixed) frame size.

Cover traffic is configurable: off, low (1 frame/5 min), medium (1 frame/30 sec), high (constant-rate, ~1 frame/sec).

**What this defends:** the *hub* and any *network observer* cannot tell, from this connection's traffic alone, whether a user is actively sending messages or sitting idle. They see a steady stream of indistinguishable encrypted frames.

**What this does not defend:** a global adversary correlating cover-traffic timing across the entire Tor network (N1); active intersection attacks where the adversary triggers an action and observes the response.

### 5.8 Size-class leakage (new)

The daemon pads every frame to one of three buckets before encryption:

- **Small** — 256 B (typical text message)
- **Medium** — 1024 B (longer text, MLS commits in small groups)
- **Large** — 4096 B (MLS commits in larger groups; chunked payloads)

Messages above 4096 B plaintext are **chunked** at the application layer into multiple Large frames, each delivered separately. This means the hub sees a count of Large frames for big messages, but does not see the original message size beyond "≥ 4 KB, sent as N frames." This is a deliberate change from v0.1, which had 16 KB and 64 KB buckets that would have leaked file-sized signals.

**What the hub still learns:** the bucket distribution per connection (mostly Small, occasional Medium, rare Large). For pure text chat this is uniform across users and reveals little. For mixed text/file workloads it reveals "this user sends large things sometimes."

**Chunking caveat:** N consecutive Large frames to the same routing token within a short window is a "this was one big message" signal. Mitigation: spread chunks across a randomized window (cost: latency) or interleave with PAD frames (cost: bandwidth). Default is moderate interleaving.

Maximum single-message plaintext (§9.3): 64 KB → 16 Large chunks.

---

## 6. End-to-end encryption (MLS)

### 6.1 Why MLS

Messaging Layer Security (RFC 9420) is the modern standard for group end-to-end encryption. It provides:

- **Forward secrecy** — past messages remain secret if current keys leak
- **Post-compromise security** — future messages become secret again after key rotation
- **Efficient group operations** — adding or removing a member is O(log n), not O(n)
- **Authenticated group state** — all members agree on who is in the group
- **Out-of-order delivery tolerance** — messages can arrive out of order without breaking decryption

Onyx uses MLS for all conversations, treating a 1-on-1 DM as a 2-member group. This unifies the implementation.

### 6.2 OpenMLS

We use the `openmls` Rust crate, which is the most mature MLS implementation available and is actively developed by the IETF MLS working group participants.

### 6.3 Group lifecycle

- **Create:** founder generates a new MLS group, becomes member 0
- **Invite:** founder generates a "welcome" message for each invitee; invitees process welcome to join
- **Add member:** any member with permission proposes Add, commit, distribute commit; new member processes welcome
- **Remove member:** any member with permission proposes Remove, commit, distribute commit; removed member's epoch can no longer decrypt
- **Update keys:** any member can issue an Update at any time to rotate their leaf key, providing fresh post-compromise security

The hub stores the group's encrypted state (called the "ratchet tree") but cannot decrypt it. The hub MUST serve the most recent ratchet tree to rejoining clients; serving stale state is detectable by clients (they check the epoch counter) and treated as a protocol error.

### 6.4 Sender authentication

Every MLS application message carries a signature from the sender's MLS credential, which is bound to their long-term Ed25519 identity. Recipients verify both the MLS group epoch matches and the credential matches the expected member. Spoofing a sender requires breaking Ed25519.

### 6.5 Non-deniability (new)

Onyx v1 is **not deniable**. Every message a user sends carries a signature from their long-term identity key (both the MLS credential signature inside the ciphertext and, for non-bootstrap envelopes, the Ed25519 outer signature). Any recipient can produce cryptographic proof to a third party of what a sender wrote.

This is a deliberate v1 decision. Rationale:

- Deniable authentication schemes (OTR-style ring signatures, DAKEZ, etc.) are not standard in MLS today and would require extending the credential format.
- The non-deniability is contained: only *recipients* gain proof, not the hub or network. The hub still cannot tell who sent what.
- Users in coercion-risk scenarios (N3) should already be aware that screenshots and recipient honesty are not under their control. Cryptographic non-repudiation marginally worsens an already-bad situation.

A future revision may add a deniable-credentials mode. The wire format reserves space for it via the optional outer `sig` field (already used as `null` in the sealed-sender bootstrap case).

---

## 7. Storage

### 7.1 Local database

Onyx stores everything in a single SQLite database at `~/.local/share/onyx/state.db` (Linux) / appropriate paths on macOS and Windows.

Encryption: app-level AEAD on each row's sensitive fields using a key derived from the user's passphrase via Argon2id. Default parameters: memory 256 MiB, time 3, parallelism 4. **Config knob:** these can be lowered to a floor of (memory 64 MiB, time 3, parallelism 2) for memory-constrained devices; below this floor the daemon refuses to start. SQLCipher is an alternative considered; app-level is preferred because it lets us encrypt only sensitive fields, leaving indexing on non-sensitive fields fast.

The KDF is invoked once at unlock and the derived key is held in a `Zeroizing<>` buffer in memory for the daemon's lifetime.

### 7.2 Schema (abridged)

```sql
CREATE TABLE identities (
  id              INTEGER PRIMARY KEY,
  nickname        TEXT,             -- not encrypted, local only
  signing_key     BLOB NOT NULL,    -- encrypted at rest
  identity_key    BLOB NOT NULL,    -- encrypted at rest
  onion_key       BLOB NOT NULL,    -- encrypted at rest
  created_at      INTEGER NOT NULL
);

CREATE TABLE contacts (
  id              INTEGER PRIMARY KEY,
  fingerprint     BLOB NOT NULL UNIQUE,
  nickname        TEXT,
  identity_pk     BLOB NOT NULL,
  signing_pk      BLOB NOT NULL,
  onion_address   TEXT,             -- if known
  verified_at     INTEGER,
  notes           BLOB              -- encrypted at rest
);

CREATE TABLE rooms (
  id              INTEGER PRIMARY KEY,
  room_id         BLOB NOT NULL UNIQUE,
  name            TEXT,
  hub_onion       TEXT,             -- hub hosting the room
  mls_state       BLOB NOT NULL,    -- encrypted at rest
  joined_at       INTEGER NOT NULL
);

CREATE TABLE messages (
  id              INTEGER PRIMARY KEY,
  room_id         INTEGER REFERENCES rooms(id),
  contact_id      INTEGER REFERENCES contacts(id),  -- for DMs
  sender_fpr      BLOB NOT NULL,
  body            BLOB NOT NULL,    -- encrypted at rest
  ts              INTEGER NOT NULL,
  delivered       INTEGER DEFAULT 0
);

CREATE TABLE settings (
  key             TEXT PRIMARY KEY,
  value           BLOB              -- encrypted at rest
);
```

### 7.3 Session-only mode (renamed from "memory-only")

A configuration flag (`storage = "session"`) disables disk persistence entirely. All state lives in process memory. On exit, everything is forgotten. Identity and contacts must be re-entered by hand each run — importing from a disk backup is intentionally not supported in this mode, because the backup file would defeat the forensic-resistance goal. Trades convenience for forensic resistance.

If a user needs both forensic resistance *and* persistence, the correct answer is to run Onyx on a full-disk-encrypted device (e.g. Tails) and use normal storage mode.

### 7.4 Secure deletion

When messages or contacts are deleted, the relevant database rows are overwritten with random data before deletion, then the database is VACUUMed. This is best-effort against forensic recovery; on SSDs with wear leveling, true secure deletion of specific bytes is not possible at the application layer.

---

## 8. Onion web tier (no-JS) protocol

### 8.1 Threat-model constraints

This tier is for users who need remote access from a device that cannot run the Onyx daemon (e.g. a borrowed machine, a phone via Tor Browser). It deliberately reduces the security tier:

- The daemon decrypts user content to render HTML.
- A daemon compromise in this mode leaks not just keys but **live decrypted plaintext** to the attacker.
- The hidden service publishing this UI is an attack surface accessible from the entire Tor network.

To make this remotely defensible, the onion web tier is gated by two requirements:

1. **Client-auth onion required.** The hidden service serving this tier is published in stealth (client-auth) mode. Anyone reaching the address must already hold the client-auth private key, which the user adds to their Tor Browser configuration out of band. Random scanning of `.onion` addresses cannot reach the login page.
2. **Off by default.** The configuration option that enables this tier requires an explicit acknowledgement in the daemon config (`onion_web.enabled = true` and `onion_web.acknowledged_risks = true`). Both must be set.

These mitigate, but do not eliminate, the additional attack surface.

### 8.2 No-JS / no-external-resource constraints

- No JavaScript, ever
- No external resources (no Google Fonts, no CDN)
- Works in Tor Browser at the "safest" security level (which blocks JS)
- Works in `lynx`, `w3m`, and other text browsers (for fun and additional auditing)

### 8.3 Page structure

Top-level routes:

- `GET /` — login / unlock page. Form posts the passphrase to `/unlock`.
- `POST /unlock` — passphrase submission. Rate-limited (see §8.5).
- `GET /r/<room_id>` — room view. Shows last N messages, paginated. **No `<meta http-equiv="refresh">`.** A "refresh" link at the bottom of the page reloads on demand.
- `POST /r/<room_id>/send` — send a message. Form submission; redirects back to the room view.
- `GET /dm/<fingerprint>` — direct message view, same pattern
- `POST /logout` — clears session cookie, returns to `/`

**Removed from v0.1:** auto-refresh via `<meta http-equiv="refresh">`. The polling pattern signals an active session to anyone who can observe the hidden-service connection cadence and produces an "I am alive" beacon for intersection attacks. Users explicitly refresh.

### 8.4 Session model

- Session cookie is HttpOnly, SameSite=Strict, Secure, with a 256-bit random ID bound server-side to the unlocked vault.
- **Idle timeout:** 5 minutes since last request.
- **Absolute timeout:** 30 minutes since unlock, regardless of activity.
- On timeout, the cookie is invalidated and the decrypted vault key is zeroized from the session table (the daemon's main vault key is unaffected because the onion-web session uses a derived per-session key, not the master key).

### 8.5 Passphrase-attempt rate limiting

`POST /unlock` is rate-limited:

- 5 attempts allowed per rolling 15-minute window per source. Source = onion-circuit identifier (Tor sets `X-Forwarded-For`-equivalent headers; failing that, the daemon treats all unauthenticated requests as one bucket).
- After 5 failures, further attempts return 429 with no timing oracle (constant-time response).
- After 20 failures within 1 hour, the onion-web tier auto-disables until an explicit reset via the local daemon API. Disabling is logged.

This is not a substitute for a strong passphrase; it is a brake against drive-by guessing.

### 8.6 HTML aesthetics

Same aesthetic as the TUI rendered in HTML/CSS:

- Monospace font (system: `ui-monospace, "SF Mono", "JetBrains Mono", "Cascadia Code", monospace`)
- Background `#0d0e0c`, text `#d4cfb8`, accent `#d89c3e`, dim `#888780`
- "Panels" drawn with CSS borders mimicking ASCII boxes
- No images, no icons (unicode glyphs only)
- Total page weight per view: under 10 KB

### 8.7 Security banner

Every page in the onion web tier displays at the top:

```
┌───────────────────────────────────────────────────────────────┐
│  ⚠  Remote access mode. Your messages are decrypted on your   │
│     daemon to render this page. A compromise of the daemon    │
│     while you are using this mode exposes the decrypted       │
│     content of your active session. For full E2E security,    │
│     use the Onyx CLI client.                                  │
└───────────────────────────────────────────────────────────────┘
```

No exceptions, no dismissal. Always visible.

---

## 9. Open questions

These need decisions before or during Phase 1 implementation:

1. **Hub authentication.** Does a hub require an invite token to join? Or is any client with the hub's `.onion` allowed to register? Recommendation: invite-only by default, optional open-registration mode.

2. **Group size limit.** MLS scales well asymptotically but MLS commits over Tor are latency-bound. At 1000 members with active churn, commit propagation will stall regularly. **v1 cap: 200 members per room**, with the cap reviewable after measurement. Hubs SHOULD reject `ROOM_OP` create/add operations that would exceed the cap.

3. **Message size limit.** 64 KB plaintext maximum, chunked into 16 Large frames at the wire level (§5.8).

4. **File transfer.** v1 design supports up to 64 KB inline; larger files require separate "blob" protocol. Defer to v2.

5. **Stealth onion (client auth).** ~~Default for user hidden services?~~ **Resolved:** required for the onion-web tier (§8.1); optional for peer onions because it complicates "scan a QR code to add me" flows.

6. **Post-quantum.** ~~Add hybrid PQ key exchange now or wait for ecosystem maturity?~~ **Partially resolved.** Primitives are implemented in `onyx_core::crypto` as an X25519 ‖ ML-KEM-768 hybrid KEM (`HybridKemSecret` / `HybridKemPublic` / `HybridCiphertext` / `HybridSharedSecret`), combined via HKDF-SHA256 with the full ciphertext bound into `info` for transcript integrity. The construction is secure as long as *either* primitive is unbroken (same defence-in-depth as Signal PQXDH / TLS 1.3 `X25519MLKEM768`). **Remaining work:** adopt the hybrid KEM in §5.5 sealed-sender bootstrap (replacing classical HPKE base mode) and in the Noise transport key schedule. The Noise pattern designator and HKDF labels both carry a version string so the "Noise_XK + ML-KEM-768" hybrid can be negotiated without protocol surgery.

7. **Token batch size for §5.5 Tier 2.** Default 64 tokens per SUBSCRIBE. Larger batches = fewer registration round-trips but bigger per-circuit linkability cluster. Worth measuring during Phase 1.

---

## 10. v1 deliberate exclusions

These are not "out of scope" in the sense of "we forgot" — they are decisions. Each one is a real cost a v1 user pays. Documenting them so the cost is visible.

- **Voice/video calls.** Not in v1. No timeline commitment.
- **File sharing > 64 KB.** Not in v1. Recommend external tools (OnionShare, magic-wormhole over Tor).
- **Federation between hubs.** Not in v1. A user can connect to multiple hubs simultaneously and present a unified UI, but the hubs do not exchange messages with each other.
- **Mobile native apps.** Not in v1. The onion web tier is the recommended path for mobile; an Android Briar-style client is a possible v2.
- **Plugin / bot system.** Not in v1. Third-party code in the same process as identity keys is a hard security problem we will not address before the core is stable.
- **Multi-device sync.** **Decision: not in v1.** A user can hold the same identity on multiple devices by importing the encrypted identity backup, but the devices do not share MLS state — each device is treated as a distinct MLS member from the group's perspective. The user-facing consequence: messages sent before a device was online do not appear on that device. The alternative (real multi-device, e.g. Signal's account-bound device tree) requires either a central account server (against Onyx's model) or a complex peer-sync protocol we are not equipped to ship in v1.
- **Account recovery.** **Decision: not in v1.** Losing the key means losing all history. The mitigation is the encrypted identity backup (§4.2) plus user education. We will *not* ship a key-shard / social-recovery scheme in v1, because doing it badly is worse than not doing it. This is the largest UX cost in the v1 design and we are eating it deliberately.

---

*End of design document v0.2-draft*
