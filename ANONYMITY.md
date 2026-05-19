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

### 3.1 Timing correlation — partial mitigation in place (T-cover.1–3)

A global passive adversary watching both your Tor entry guard and your peer's can correlate "Alice's daemon emitted a sealed envelope at 09:23:14.221" with "Bob's daemon emitted an `EventMessage` at 09:23:14.398." The hub knows this trivially because it sits in the middle.

  * **What we have today (T-cover.2):** opt-in client → hub cover traffic via `--cover-traffic-mean-secs <N>`. When enabled, the daemon emits a `FRAME_PAD` (empty payload, padded to bucket::SMALL so it's size-indistinguishable from a small real frame) at **exponentially-distributed intervals** with mean N seconds. Hub silently discards FRAME_PAD frames (`tracing::trace!` only — no warn/info log lines that would themselves let an operator-side observer fingerprint PAD timing). The exponential distribution is **memoryless** by design: a fixed-clock cadence would itself become a fingerprint an adversary could subtract from each user's stream. With Poisson inter-arrivals, the gap until the next frame doesn't depend on how long it's been since the last one, so there's no rhythm to subtract.
  * **What this raises the adversary's cost to do:** distinguishing "alice is actively chatting right now" vs "alice is idle but online" purely from the daemon→hub frame timing. Pre-cover, idle alice generates zero frames; chatting alice generates one frame per message. With cover at mean=20s, idle alice generates ~3 frames per minute of indistinguishable bytes; chatting alice adds her real frames *on top of* that constant noise floor.
  * **Hub→client direction (T-cover.hub)** mirrors the client→hub side: per-connection PAD emitter on the hub at the same exponential-interval cadence, configured via `--cover-traffic-mean-secs` on the hub binary. When **both** sides opt in, the daemon↔hub channel becomes traffic-shape-uniform in both directions. The smoke test `rooms_e2e_hub_cover_traffic_does_not_break_flow` pins that the hub-side emitter doesn't interfere with real DELIVER routing.
  * **What this does NOT do (be honest):**
    1. **No guarantee against multi-session correlation.** A sophisticated adversary running long enough can still distinguish "real burst plus cover" from "pure cover" by autocorrelation on the rate. The mitigation costs them more — they need many more samples to be confident — but doesn't refuse them an answer eventually.
    2. **Not verified in real-Tor smoke yet.** The TCP smoke + unit tests pin that PAD frames don't interfere with real flow and the sampler's statistical properties; the end-to-end "passive Tor-circuit observer really can't distinguish" claim still needs real-circuit measurement (`scripts/real_tor_smoke.sh` is the operator-driven harness for that).
    3. **Off by default on both sides.** Cover traffic burns bandwidth (mean=20s × N hubs × bucket::SMALL bytes per daemon, plus mean=20s × N clients × bucket::SMALL per hub). The v0 default leaves it off until the operator opts in and we have real-circuit results.
    4. **Per-connection cadence on the hub side reveals "alice connected" + "alice disconnected" by absence.** A hub-watching adversary still sees TCP open / close events. Cover on the open session doesn't change that. Closing this would need session-resume routing-id rotation (the unrelated §3.2 fix; queued for a future slice).
  * **What's left to close it fully:** real-Tor verification (operator drill via `scripts/real_tor_smoke.sh`) and the §3.2 routing-id rotation for connect-time fingerprinting.

### 3.2 Hub knows online/offline timing — structural, partially mitigated

When your daemon connects to the hub, the hub learns "this client is online now" through **three independent leaks**:

  1. **Noise XK static key** — the handshake authenticates your long-term X25519 identity before any frame is exchanged. The hub knows it's you.
  2. **Subscription to `introduction_inbox(fingerprint)`** — fingerprint-derived id; anyone with your fingerprint can probe the hub.
  3. **`FRAME_KP_PUBLISH`** — your KP carries your signing key + signature, hub indexes by your fingerprint.

Each leak independently identifies you. Closing one alone changes nothing. **See `ROTATION.md` for the full structural analysis** — including why "subscription rotation" as a single-fix doesn't close §3.2 the way the original text implied (it just moves the leak from observable to observable; the hub correlates them back).

What Onyx v0 has, in layers of contribution:

  * **Multi-hub fan-out (T8.1)** — leak is per-hub. No single hub sees your complete pattern. Pick your trust roots.
  * **Bidirectional cover traffic (T-cover, T-cover.hub)** — mutes the timing leak (`§3.1`) but doesn't close the identity leaks above.
  * **Per-(room, epoch) session-token routing (T6.3.g)** — closes §3.2 for **in-room traffic specifically**. Hub sees room activity but can't link rooms to each other or to specific members.
  * **`--no-intro-inbox-subscribe` opt-out (T-rotation.a)** — closes leak #2. Tradeoff: cannot receive first-contact bootstraps via the hub. Useful for users who've established all their peers and prefer maximum unlinkability over reachability.
  * **Onion-service direct dials** — bypass the hub entirely when both parties are online.

What would actually close all three leaks together: ephemeral Noise keys per session + separated publish/subscribe connections + oblivious-recipient routing for first-contact. Each is a substantial protocol-level change. None planned for v0. See `ROTATION.md §3` for the design discussion.

  * **Effort to close it fully**: not "~3 hours" as the original text claimed — that estimate was wrong. The full fix is medium-large protocol redesign work, deliberately deferred. The opt-out + multi-hub + cover traffic are the v0 mitigation stack.

### 3.3 Hub knows per-inbox message counts

Even without cover traffic, the hub can count "inbox X received 14 envelopes today." Over time this is a statistical fingerprint of how busy a user is. **Cover traffic (§3.1) defeats this** as a side effect; documented separately because it's a distinct observable.

### 3.4 Hub durability — closed end-to-end

Before T8.0 the hub kept queued envelopes and the KP directory in *in-memory* HashMaps. A hub restart (deploy, OOM-kill, machine reboot) silently lost every queued envelope and every published KP. T8.0 closed that for the single-hub case by SQLite-backing the two non-ephemeral state pieces — a hub now survives its own restart.

T8.1 closes the remaining gap (**hub permanently dying**) at the *client* layer. The daemon now accepts a repeatable `--hub onion:port,b32pubkey` flag and spawns one client task per configured hub. Sealed envelopes are **fanned out to every hub in parallel**; subscriptions run on **every hub** simultaneously. If hub A's disk is destroyed, hubs B and C still hold the recipient's KP and any in-flight envelopes — delivery continues uninterrupted. The recipient's existing T7.3-sec.2 replay guard dedups the resulting duplicate deliveries silently, so the user sees exactly one message regardless of how many hubs forwarded it.

What this is **not**: full hub-to-hub federation (T8.3+, long-term). Hubs don't yet talk to each other; durability comes from **user-controlled redundancy** — pick N hubs you trust, publish to all of them. Strictly simpler than Matrix-style server-to-server federation, surprisingly effective.

**Update (T8.3 — also now closed):** hub-to-hub gossip is implemented. With `--peer-hub`, two hubs establish a Noise XK link and federate KP-directory + queued envelope state via `FRAME_GOSSIP_PUBLISH` and `FRAME_GOSSIP_DELIVER` frames. Loop prevention via TTL + `seen_by`. Ownership check on incoming gossiped KPs uses the same T7.3-sec mitigation as client-direct publishes. See `FEDERATION.md` for the design and `THREAT_MODEL.md` §8.2 #17/#18 for the F1/F2 adversaries this defends against. **Anonymity disclosure surface is unchanged from T8.1**: hubs still see only routing-ids + opaque ciphertext + timing; federation just makes the storage and delivery more resilient without revealing anything new.

### 3.5 No reproducible builds, no signed releases

If someone replaces your installed `onyx` binary on disk (supply chain compromise, malicious package mirror), you lose. We have `cargo deny` advisory + license checks at the workspace gate, which catches *known-CVE* dependencies but not a maliciously-published version that has yet to be flagged.

  * **What would close it:** rust-reproducible-builds wiring, Sigstore signing on releases, `cargo audit` in CI.
  * **Effort:** 1 session for reproducibility (assuming clean dependency tree), 0.5 session for Sigstore signing pipeline.

### 3.6 Disk fingerprint — `~/.onyx/` reveals you use Onyx

Anyone with read access to your home directory sees the `~/.onyx` directory. The directory itself is mode 0700 (so other users on a shared system can't read inside), but the *name* is visible to anyone who can list your home, and the vault file's existence reveals you ran Onyx at some point.

  * **What would close it:** opt-in custom vault path (already supported via `--vault`), plausibly-deniable vault (duress passphrase that unlocks a decoy identity).
  * **Effort:** custom path is already there. PD vault is 1–2 sessions, and the threat model needs to be careful — PD vaults are notoriously hard to do without making the deniability claim worse than no vault at all.

### 3.7 Process name in `ps`

A local snooper running `ps aux` sees `onyx` / `onyxd` in your process list. Reveals usage to anyone with shell access on the same machine.

  * **What would close it:** prctl-rename on Linux, no equivalent on macOS that we'd trust. Document the limitation; rename if you care.
  * **Effort:** trivial documentation; harder if you want it actually invisible.

### 3.8 Memory zeroization — partial, with the gaps explicitly mapped

We use the `zeroize` crate on the items we **own and control**:

  * Vault key (`AeadKey`) — `ZeroizeOnDrop`.
  * Argon2-derived intermediate (`vault_key: Zeroizing<[u8; 32]>`).
  * X25519 identity secret (`IdentitySecret`) — `ZeroizeOnDrop`.
  * Hybrid KEM secret (`HybridKemSecret`) — `Zeroize + ZeroizeOnDrop`.
  * Identity-secret blob (`Identity::to_secret_bytes`) — `Zeroizing<Vec<u8>>`.
  * MLS state snapshot (`MlsParty::snapshot_state`) — `Zeroizing<Vec<u8>>`.
  * Daemon `Config.passphrase` — `Zeroizing<String>` (T-zeroize-audit).
  * Hub-client per-task seed round-trips (`our_sk_bytes`, `our_kem_bytes`) — `Zeroizing` (T-zeroize-audit).
  * TUI composer text after a successful send — `.zeroize()` called explicitly (T-zeroize-audit).

What's **still not** scrubbed (gaps remain):

  * **Decrypted plaintext in the daemon's conversation registry** — the `ChatLine` ring buffer holds decoded message text indefinitely (the user is reading it). Scrubbing on age-out is a follow-up that needs careful UX thought (when does "scroll history" become "old plaintext we can wipe"?).
  * **`openmls` internal state** — the MLS group's working set lives in `openmls`'s `MemoryStorage`. We don't control the layout, can't add zeroize hooks without upstream changes. Worth tracking as an upstream contribution.
  * **TUI composer per-keystroke** — between typing and send, the composer holds plaintext. We zeroize on successful send, not on per-keystroke edit/replace.
  * **Brief intermediate `Vec<u8>` allocations** when handing key material to upstream libraries (e.g., `private_seed.to_vec()` in `mls::from_identity` before `openmls::SignatureKeyPair::from_raw` consumes it). The original `Zeroizing` wrapper scrubs; the intermediate doesn't. Documented inline as a known upstream-dependent gap.
  * **mlock / memory-locking** — we don't mlock memory to prevent swap. An attacker with swap-file access could in principle recover state that was swapped out and not yet overwritten.

  * **What would close it further:** zeroize-aware fork of `openmls` (or upstream contribution), `mlock` integration, secure-enclave-backed key storage on platforms that have one.
  * **Effort:** the items we own took one slice (T-zeroize-audit, ~1 hr). The remaining items require upstream work or significant platform-specific code.

### 3.9 No anonymous-set cover (group membership)

When you join an MLS group, every member learns your fingerprint (that's how MLS works — membership is explicit and verifiable, which is a *feature* for integrity but a *cost* for anonymity). For "I want to talk to this group of people without revealing my identity to all of them," Onyx is the wrong tool. SecureDrop, OnionShare, or Tor + a one-time identity are right tools.

### 3.10 No traffic-shape obfuscation against state-level DPI

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
