# Anonymity in Onyx

A plain inventory of what Onyx does and does not do for *anonymity* — distinct from confidentiality (the *content* is private) and integrity (the *content* is unaltered). All three matter; this document is about the third axis only.

> If you only read one paragraph, read this one: **Onyx aims to hide *who is talking to whom* from your network, your ISP, and the message-relay hubs you use — not from anyone watching all of those at once.** It uses Tor for transport metadata, sealed-sender envelopes so hubs can't see who sent what, and a per-recipient seen-set to stop hubs from replaying messages back at you. It does NOT have cover traffic, has not been independently audited, leaks a `~/.onyx` directory on your disk, and a sufficiently-resourced adversary watching both endpoints' Tor entry guards can still correlate your traffic with your peer's. Read on for specifics.

---

## 0. The honest framing (read this first)

Anonymity is **not** "the messages are encrypted." Anonymity is "an observer cannot tell *which two parties* are exchanging messages, or *that they are exchanging messages at all*."

The cryptographic confidentiality story is in `SECURITY.md` and `HOW_IT_WORKS.md`. This document is the orthogonal axis: even if every byte on the wire is unintelligible, can a passive observer figure out that *Alice* and *Bob* are correlating? Onyx's answer is "we try to make that expensive, but a well-resourced global adversary can probably do it anyway." That's the honest answer; this document explains exactly which adversaries we *do* defend against and which we don't.

**No claim of "perfect anonymity" appears anywhere in this repository.** If you see one, file a bug.

---

## 1. Adversary model — who are we defending against?

We list adversaries in increasing order of capability. Onyx defends against the first three. It does **not** fully defend against the fourth. Be honest with yourself about which category your real-world adversary is in.

### A1 — Your local network / ISP
Wi-Fi snoopers, captive portals, your home ISP, a coffee-shop attacker on the same router. They see your IP traffic but not its contents.

  * **What Onyx does:** all daemon-to-peer and daemon-to-hub traffic goes through Tor (`arti-client` v0.42, `crates/onyx-core/src/tor.rs`). Your network sees encrypted Tor traffic to a Tor entry guard, nothing else. No DNS leaks, no plaintext SNI to your peer's onion address, no port-fingerprinting beyond "this user has a Tor connection."
  * **Caveat:** the *existence* of Tor traffic is visible. If "this user runs Tor" is itself sensitive in your threat model (regulated environments, hostile-state networks), an obfuscated bridge is needed; Onyx does not currently configure bridges automatically.

### A2 — The message-relay hub (`onyx-hub`)
The hub forwards sealed-sender envelopes between offline peers. We assume it may be **untrusted, compromised, curious, or hostile**.

  * **What Onyx does:**
    - **Sealed-sender envelopes** (`crates/onyx-core/src/routing.rs::seal_bootstrap`). The hub sees `routing_id → opaque ciphertext`; it does not see the sender, nor the recipient's identity, nor the message content. The recipient is addressable by a BLAKE2b-128 hash of their fingerprint (the *routing id*), not by the fingerprint itself.
    - **KeyPackage ownership validation** (T7.3-sec, `crates/onyx-hub/src/handler.rs`). The hub now refuses to store a KeyPackage that doesn't derive the claimed routing id — closes a directory-tampering / DoS-by-overwrite attack that previously consumed the legitimate slot even though end-to-end auth caught the impersonation.
    - **Replay defence** (T7.3-sec.2 + T7.3-sec.2-persist, `crates/onyx-daemon/src/replay_guard.rs`). The recipient daemon keeps a FIFO seen-set of envelope hashes (4096 entries, persisted to the vault every 60 s). A hostile hub replaying a stored envelope is silently dropped. Worst case after an unclean daemon exit: ≤60 s of replay vulnerability.
    - **Per-epoch session tokens** for in-group MLS traffic (`crates/onyx-core/src/routing.rs::session_token`). Once you and a peer share an MLS group, message routing rotates per epoch — the hub cannot link successive group messages to a stable identity.
  * **Caveat:** the hub still knows **timing** (when you connect, when envelopes arrive in your inbox, when you fetch a KP). It also knows the **count** of envelopes per routing id. See §3.

### A3 — One of your peers turning hostile
A contact you've already established a group with decides to attack you, or their device is compromised after the fact.

  * **What Onyx does:**
    - **MLS post-compromise security** (RFC 9420 via `openmls` 0.8). Once an attacker leaves the group, future messages they don't see are unreadable to them, even with their old keys — the ratchet has rotated. Documented in `HOW_IT_WORKS.md` §2 Layer 4.
    - **Per-message forward secrecy** for first-contact envelopes via hybrid (X25519 + ML-KEM-768) ephemeral encapsulation. A future stolen long-term key does not retroactively decrypt past envelopes.
  * **Caveat:** the peer obviously knows *who you are* (your fingerprint). Onyx is an end-to-end-encrypted channel between named identities; it is not a "send Bob an anonymous tip" tool. For that, you need Tor + a different application (SecureDrop, OnionShare). See §5.

### A4 — Global passive adversary (state-level, multi-AS observer)
An adversary who can simultaneously observe traffic at your Tor entry guard *and* at your peer's Tor entry guard *and* correlate it.

  * **What Onyx does:** not enough. This is the genuinely hard case and Onyx does not yet have what it needs to defend against it. See §3.
  * **What Tor itself does:** Tor's threat model has always explicitly excluded this adversary — see [the Tor design paper §3.1](https://svn.torproject.org/svn/projects/design-paper/tor-design.html). Onyx inherits Tor's posture here, which means inheriting Tor's limits.

---

## 2. What's in place today

Concrete defences with file pointers, in approximate order of how much they buy you.

| Defence | What it does | Code |
|---|---|---|
| **Tor (Arti) for all transport** | Hides your IP from peers and hubs; hides peer onions from your local network | `crates/onyx-core/src/tor.rs`, `arti-client = "0.42"` |
| **v3 hidden services** | You're contactable without ever exposing your IP. Your "address" *is* the onion key | `tor-hsservice = "0.42"` |
| **Sealed-sender envelopes (PQ-hybrid)** | Hub can't see who sent a first-contact message | `crates/onyx-core/src/routing.rs::seal_bootstrap` |
| **Routing-id == hash(fingerprint)** | Hub indexes you by a one-way hash; can't enumerate fingerprints | `routing::introduction_inbox` |
| **Per-epoch MLS session tokens** | In-group traffic uses rotating routing ids; hub can't link your group messages across epochs | `routing::session_token` |
| **Wire-frame size buckets** | Every Noise frame padded to SMALL=256/MEDIUM=1024/LARGE=4092 — exact lengths not observable | `crates/onyx-core/src/wire.rs::max_payload` |
| **Hub KP ownership check** | Hostile publisher can't overwrite your directory entry | `crates/onyx-hub/src/handler.rs` (T7.3-sec) |
| **Recipient replay defence** | Hub can't replay your old envelopes back at you. Persists across restart (60 s worst case) | `crates/onyx-daemon/src/replay_guard.rs` (T7.3-sec.2 + persist) |
| **No telemetry** | The daemon never phones home. Zero analytics. | grep `crates/` for `reqwest`/`hyper`/`telemetry`/`analytics` — none. |
| **`unsafe_code = "forbid"`** in onyx-core | The security-critical crate cannot use unsafe — memory-safety boundaries enforced at compile time | `crates/onyx-core/Cargo.toml` `[lints]` |
| **No process arguments leak passphrase** | `--passphrase` is `hide_env_values = true`; recommended env-var path keeps it out of `ps` | `crates/onyx/src/main.rs`, `crates/onyxd/src/main.rs` |
| **`~/.onyx` mode 0700** | Vault + UDS not world-readable by default | `crates/onyx-daemon/src/lib.rs::ensure_data_dir` (T7.1) |

---

## 3. What's NOT in place — the honest gap list

Ranked by impact on anonymity, with the realistic effort to close each.

### 3.1 Timing correlation — **biggest open gap**

A global passive adversary watching both your Tor entry guard and your peer's can correlate "Alice's daemon emitted a sealed envelope at 09:23:14.221" with "Bob's daemon emitted an `EventMessage` at 09:23:14.398." The hub knows this trivially because it sits in the middle.

  * **What would close it: cover traffic.** Constant-rate dummy envelopes between every daemon and its hub, indistinguishable on the wire from real ones. Recipient drops dummies silently. The hub no longer learns *when* you send a real message because there's always a message.
  * **What we have today:** nothing. The hub sees real envelopes only when there is real traffic.
  * **Effort:** 1–2 sessions of focused work. Significant because it touches the generator, the recipient sink discipline (must not surface dummies as events), and the bucket strategy.

### 3.2 Hub knows online/offline timing

When your daemon connects to the hub and subscribes to your inbox routing id, the hub learns "this client is online now." The subscription routing id is **stable** across reconnects (it's `introduction_inbox(your_fingerprint)`), so the hub can link "this same id came back" → "this is the same user."

  * **What would close it: per-session subscription rotation.** Subscribe via a fresh routing id derived from a session secret + epoch, so reconnects look like different users to the hub. Recipient still learns about traffic in their real inbox via a separate (less-frequent) probe.
  * **What we have today:** nothing.
  * **Effort:** ~3 hours. Requires a small protocol change but no breaking wire-format work.

### 3.3 Hub knows per-inbox message counts

Even without cover traffic, the hub can count "inbox X received 14 envelopes today." Over time this is a statistical fingerprint of how busy a user is. **Cover traffic (§3.1) defeats this** as a side effect; documented separately because it's a distinct observable.

### 3.4 No reproducible builds, no signed releases

If someone replaces your installed `onyx` binary on disk (supply chain compromise, malicious package mirror), you lose. We have `cargo deny` advisory + license checks at the workspace gate, which catches *known-CVE* dependencies but not a maliciously-published version that has yet to be flagged.

  * **What would close it:** rust-reproducible-builds wiring, Sigstore signing on releases, `cargo audit` in CI.
  * **Effort:** 1 session for reproducibility (assuming clean dependency tree), 0.5 session for Sigstore signing pipeline.

### 3.5 Disk fingerprint — `~/.onyx/` reveals you use Onyx

Anyone with read access to your home directory sees the `~/.onyx` directory. The directory itself is mode 0700 (so other users on a shared system can't read inside), but the *name* is visible to anyone who can list your home, and the vault file's existence reveals you ran Onyx at some point.

  * **What would close it:** opt-in custom vault path (already supported via `--vault`), plausibly-deniable vault (duress passphrase that unlocks a decoy identity).
  * **Effort:** custom path is already there. PD vault is 1–2 sessions, and the threat model needs to be careful — PD vaults are notoriously hard to do without making the deniability claim worse than no vault at all.

### 3.6 Process name in `ps`

A local snooper running `ps aux` sees `onyx` / `onyxd` in your process list. Reveals usage to anyone with shell access on the same machine.

  * **What would close it:** prctl-rename on Linux, no equivalent on macOS that we'd trust. Document the limitation; rename if you care.
  * **Effort:** trivial documentation; harder if you want it actually invisible.

### 3.7 Memory zeroization is partial

We use the `zeroize` crate on vault keys and KEM secrets (`crates/onyx-core/src/crypto.rs` — see the `ZeroizeOnDrop` derives). MLS state in `openmls` and decrypted plaintext in the conversation registry / TUI are **not** aggressively scrubbed. An attacker who can read the daemon's memory (root access, coredump, swap) can recover recently-decrypted plaintext.

  * **What would close it:** broader zeroization audit, locking memory to prevent swap, secure-enclave integration.
  * **Effort:** ongoing — needs a dedicated pass through every crate.

### 3.8 No anonymous-set cover (group membership)

When you join an MLS group, every member learns your fingerprint (that's how MLS works — membership is explicit and verifiable, which is a *feature* for integrity but a *cost* for anonymity). For "I want to talk to this group of people without revealing my identity to all of them," Onyx is the wrong tool. SecureDrop, OnionShare, or Tor + a one-time identity are right tools.

### 3.9 No traffic-shape obfuscation against state-level DPI

Even though Tor wraps the bytes, the *fact that you are running Tor* is visible at the IP layer. A state-level adversary running DPI can flag you as "uses Tor." Onyx does not configure Tor bridges (obfs4, snowflake) automatically.

  * **What would close it:** bridge configuration support, snowflake integration.
  * **Effort:** Arti supports bridges; surfacing the config in Onyx is ~half session.

---

## 4. Practical recommendations

Match Onyx to your actual threat model. The right tool depends on which adversary you are realistically facing.

### If you're protecting against a curious friend or coworker
Onyx is overkill but fine. The two-terminal removed, the cover-traffic gap doesn't matter, just don't tell them your fingerprint.

### If you're protecting against your ISP or network operator
Onyx is well-fit. Tor hides the addressing; sealed envelopes hide who you're talking to from any hub you use. Make sure your local network *can* reach Tor (if it's blocked, you'll need a bridge — Onyx doesn't auto-configure that yet, see §3.9).

### If you're protecting against a compromised relay hub
Onyx is well-fit *after* T7.3-sec, T7.3-sec.2, and T7.3-sec.2-persist landed. The hub cannot: see your message content, see who sent any envelope, overwrite your directory entry, replay your old envelopes, decrypt your traffic. It *can*: see when you're online, count your envelopes, drop messages (censorship), refuse to relay.

### If you're protecting against a state-level adversary that can watch global traffic
**Onyx is not enough.** Use Onyx for content protection but assume your identity may be correlatable via timing. Pair with operational security that doesn't depend on Onyx alone (separate hardware, isolated network, time-shifted use, etc.). The cover-traffic gap (§3.1) is the single biggest improvement you can wait for.

### If you need to send a one-shot anonymous tip
Onyx is the **wrong tool**. Onyx is an identity-bound chat application — every message is signed by a fingerprint your recipient learns. For real source-protection use cases, use SecureDrop (designed for this) or OnionShare.

---

## 5. How Onyx compares on the anonymity axis

This is a deliberately narrow comparison. We're not ranking products — every tool here is well-designed for what it's designed *for*. We're showing where Onyx lands on this one axis.

| Tool | Hides "who is talking to whom" from network | Hides identity from peer | Cover traffic | Has had external audit |
|---|---|---|---|---|
| **Onyx** (this repo) | Yes via Tor + sealed sender | No (by design — identity is the fingerprint) | **No** | **No** |
| Signal | No (phone-number index, IP visible to Signal servers) | No | No | Yes (multiple) |
| Briar | Yes via Tor | No | No | Yes (Cure53, 2017) |
| SecureDrop | Yes via Tor | Yes (source-anonymous) | No | Yes (multiple) |
| Cwtch | Yes via Tor | Optional (peer-by-peer) | No | Limited |

The two columns Onyx fails today — **cover traffic** and **external audit** — are the two biggest improvements on the anonymity axis. Both are tracked: cover traffic in `ROADMAP.md`, audit as the headline "external review status: none" line.

---

## 6. Related documents

  * **`SECURITY.md`** — overall security policy and disclosure process.
  * **`HOW_IT_WORKS.md`** — the protocol walkthrough; explains *what* is encrypted at each layer.
  * **`THREAT_MODEL.md`** — the formal threat model with consolidated carry-forward gaps.
  * **`ROADMAP.md`** — what's planned next, including cover traffic.
  * **`CHANGELOG.md`** — what landed and when, with security impact statements per commit.

If you find a real anonymity gap not listed here, please file an issue. We'd rather hear "you missed X" than discover X via incident.
