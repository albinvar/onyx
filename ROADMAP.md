# Onyx — Roadmap

What's done, what's being worked on, what's planned, and what's explicitly out of scope. Updated when work lands; if a date is missing it's because nothing has actually shipped against that item yet.

For finished work with full design notes + verification + carry-forward, see `CHANGELOG.md`. For the canonical list of security-impacting gaps, see `THREAT_MODEL.md` §8.2.

---

## Status at a glance

```
done       ────────────────────────►  T1 T2 T3 T4 T5 T6.1 T6.2 T7.0 (+ docs)
in flight  ────────────────────────►  (none — between phases)
next       ────────────────────────►  T7.1 → T7.2 → T6.3
later      ────────────────────────►  T6.4 → security/release hardening
won't do   ────────────────────────►  see §6
```

- **Commits:** 40-ish on `main`.
- **Tests:** 216 passing, full CI gate (`fmt`, `clippy -D warnings`, `cargo deny`).
- **External review status:** none. See `SECURITY.md` §1.

---

## 1. Done

Each phase below has one or more CHANGELOG entries with full design notes. I'm only summarising here.

### T1 — `onyx-core` cryptographic foundation
9 modules, ~110 tests originally (now folded into the 216). Wrapped every primitive used elsewhere: Ed25519 (`crypto::SigningKey`), X25519 (`crypto::IdentitySecret`), ChaCha20-Poly1305 (`crypto::AeadKey`), Argon2id (`crypto::Argon2Params`), BLAKE2b-128 (`crypto::blake2b_128`), HKDF-SHA256 (`crypto::hkdf_sha256`), ML-KEM-768 (`crypto::HybridKemSecret`), and the hybrid X25519+ML-KEM-768 combiner (`crypto::combine_hybrid_secrets`).

### T2 — Vault + MLS persistence
SQLite-backed Argon2id-encrypted vault (`crates/onyx-core/src/storage.rs`). Identity round-trips across reopen. MLS party state snapshots into the vault; reconnecting peers resume their existing MLS group rather than bootstrapping a fresh one each time.

### T3.1 — `onyx-hub` becomes a real binary
In-memory store-and-forward relay. Per-conn subscribers, offline queues, bounded mailboxes. Wire protocol = SUBSCRIBE + DELIVER frames over Noise XK. Sees only ciphertext.

### T4.1–T4.3 — Local API socket + `onyx` CLI/TUI
Unix-domain socket (`./onyxd.sock`, `chmod 0600`, NDJSON wire format). `onyx status`, `onyx identity`, `onyx tui`. Four-pane Ratatui interface: peer list, conversation, composer, status bar. Live tail subscription. History backfill across restarts. Real Ed25519 fingerprints surfaced from MLS group members.

### T5.1 — `onyxd` becomes a hub client
Long-lived authenticated Noise session to the hub. Subscribes to our introduction-inbox routing id. Reconnects with backoff.

### T5.2.a–T5.2.g — Sealed-sender envelope, end-to-end
Per-identity hybrid KEM keypair (X25519+ML-KEM-768) persisted in vault schema v4. `SendBootstrap` API verb constructs + seals + sends. `handle_hub_delivery` opens + decodes + registers + pushes events. TUI renders a yellow `[hub]` badge for the weaker security tier. `mls/v1` variant for true MLS PCS over hub. `onyx send-bootstrap` CLI subcommand.

### T6.1 — KeyPackage directory on the hub
`FRAME_KP_PUBLISH`/`FRAME_KP_FETCH`/`FRAME_KP_RESPONSE`. Daemons auto-publish their KP on hub connect. Latest-wins.

### T6.2 — In-session KP fetch + CLI verbs
`onyx fetch-keypackage` and `onyx send-bootstrap-mls`. End-to-end MLS-over-hub first-contact is now a 3-line shell pipe.

### T7.0 — `--listen-tcp` / `--dial-tcp` test modes
Plain TCP transport for local testing. Bypasses Tor entirely. Loudly warned as test-only in logs + `SECURITY.md` §6.2. Two daemons on localhost can chat in ~5 seconds instead of 60-120 over Tor.

### Documentation
- `DESIGN.md` (v0.2-draft) — the protocol specification.
- `THREAT_MODEL.md` — adversaries + non-adversaries + §8 implementation status.
- `SECURITY.md` — eight enforcement principles + disclosure policy.
- `README.md` — install + recipes + troubleshooting (recently rewritten to reflect T5–T7 work).
- `HOW_IT_WORKS.md` — plain-English security walkthrough with per-claim evidence.

---

## 2. In flight

Nothing currently being worked on between commits. Pick from §3 ("next").

---

## 3. Next (queued, priority order)

These are the phases I'd recommend tackling in order. Each one is independently shippable; pick by which user-pain it most closes for you.

### T7.1 — Single-binary `onyx`  *(recommended next)*
**The change:** merge the `onyxd` crate into `onyx`. Running `onyx` (no args) opens the vault, starts Tor in the background, and renders the TUI in one process. One-shot subcommands (`onyx send`, `onyx identity`, etc.) auto-discover a running daemon's socket. `onyxd` and `onyx-hub` stay as separate binaries for advanced/server use; a normal user never touches them.

**What you'll notice:** the recipe in `README.md` §4 collapses from 4 terminals + 6 commands to 2 terminals + 1 command each.

**Why next:** every other UX gap stops mattering once the daemon-vs-client split isn't visible. Estimated 2–3 hours.

### T7.2 — Invite URLs
**The change:** `onyx invite` prints `onyx://<onion>?fp=...&kem=...` (or for `--listen-tcp` mode, `onyx://127.0.0.1:7710?fp=...`). `onyx accept <url>` (or pasting into the TUI) imports + dials in one shot.

**What you'll notice:** no more copy-pasting fingerprint + KEM public + KP separately. One URL.

**Why second:** completes the "one paste per person" UX after T7.1. Estimated 1–2 hours.

### T6.3 — Channels / multi-party rooms
**The change:** new `Room` concept in `onyxd`. New API verbs `CreateRoom`/`InviteToRoom`/`JoinRoom`/`SendToRoom`. TUI gets a `#room-name` pane alongside per-peer DMs. The MLS layer already supports N-member groups (we use it for 2-party today, same call handles 8); what's missing is the surface around it.

**What you'll notice:** Onyx becomes capable of small-group chat (e.g. five-person planning room) with all the MLS PCS properties.

**Why third:** the headline IRC feature. Big lift (estimated 4–6 hours across several commits) but the crypto is in place. T6.1's KP directory already supports the multi-invite path.

---

## 4. Later (after the next-queue lands)

### T6.4 — Async MLS application messages over hub
Today's hub path establishes an MLS group via Welcome but ongoing in-group chat requires one peer to direct-dial the other (existing T2.x resume path takes over). T6.4 adds a wire format for MLS application messages routed via per-epoch session-token routing ids (`routing::session_token`). After it lands, **fully asynchronous chat works without ever needing both peers on Tor simultaneously.**

Estimated 2–3 hours.

### Hub invite-only authentication
`THREAT_MODEL.md` §8.2 #4. Today the hub trusts any client that knows its static key. Add invite-token-based registration so only authorized clients can connect. Real security work — needs a clear admin model + token lifecycle. Estimated 3–4 hours.

### Schema migration runner
`THREAT_MODEL.md` §8.2 #13. Today every vault-schema bump requires the user to `rm` their vault. Add a migration runner that walks old → new schema versions in `Vault::open`. Quality-of-life; matters as soon as anyone has data they care about. Estimated 2–3 hours.

### Hub-side KP-ownership validation
`THREAT_MODEL.md` §8.2 #15. Today the recipient validates an inbound KP's signing key against the expected fingerprint — that's defence-in-depth, but it'd be cleaner if the hub also refused to store a KP whose embedded signing key doesn't hash to the routing id under which it's being published. Requires a sign-challenge: client signs a hub-supplied nonce with the Ed25519 key whose fingerprint maps to the target routing id. Estimated 3–4 hours.

### Reproducible builds + signed releases
`THREAT_MODEL.md` §4 trust assumptions. Without these you can't verify the binary you downloaded matches the source in this repo — a `THREAT_MODEL.md` §3 N4 (malicious-developer) attack would be undetectable. Standard tooling exists (`cargo-deb` + reproducible-builds.org guidance + cosign or minisign for signing). Estimated 4–6 hours including the GitHub Actions release pipeline.

### Cover traffic on idle Tor circuits
`THREAT_MODEL.md` §5 residual linkability rows #1, #5. Today's frame size buckets shape transmitted frames; idle circuits leak presence. Adding constant-rate cover traffic raises the cost of timing-correlation attacks against A2 (hub) and §5#5 observers. Hard to test correctness of, but a real anonymity win.

### External security audit *(the most important thing missing)*
Single most impactful action anyone could take. Until this happens, `SECURITY.md` §1 and `HOW_IT_WORKS.md` §0 both stay loud. Not something I can self-do.

---

## 5. Long-term — real-product territory

These items each open new threat surfaces and would each need a design doc + threat-model update before any code. Listed here so they're not lost.

- **Multi-device support per identity.** Today one vault = one device. Bringing a new device means a new identity. Real multi-device needs key-sync (think Signal's PNI) which is its own crypto subproject.
- **Mobile client.** Reuse `onyx-core` (pure Rust, `no_std`-ish), build native UI with Swift/Kotlin or via Tauri. Onyx-on-iOS would also need to deal with iOS push limitations (background daemon impossible) — probably needs a notification relay.
- **Voice / video.** Entirely different threat surface (real-time leaks, codec metadata, jitter analysis). Would essentially be a sibling product reusing the identity + key-agreement layer.
- **Federation between hubs.** Multi-hub trust model. Compounds the trust assumptions. Would need a clear protocol for hubs to forward sealed envelopes to each other without revealing more than the originating hub already saw.
- **Onion-web tier.** The original `DESIGN.md` §3 envisions an opt-in web UI served by the hub (with the documented PCS trade-off — N6 in `THREAT_MODEL.md`). Not started.

---

## 6. Won't do in v0

Listed explicitly so nobody wastes time proposing them:

- **Centralised identity** (any model where a server can take a name away).
- **Phone-number-based registration** (collapses the anonymity story).
- **Optional cryptographic weakening** for legacy compatibility. Per `SECURITY.md` P6 — every codepath in the binary is the strong path; if a feature can't be done strongly, it doesn't exist.
- **`unsafe` Rust** in `onyx-core`. Workspace-wide `unsafe_code = "forbid"`. Will not relax for performance.
- **Telemetry, analytics, crash reporting that phone home.** Logs stay local.
- **Auto-update.** Users must verify what they install. Documented as `THREAT_MODEL.md` §3 N4 mitigation.

---

## 7. How priorities get set

Two principles, in this order:

1. **Closing a `THREAT_MODEL.md` §8.2 carry-forward item beats adding a new feature.** Items there represent gaps between what the threat model claims and what the code does. Every one is a real loss of integrity in the project's discipline.

2. **Among feature additions: smallest reviewable surface wins.** A 2-hour focused commit beats a 10-hour mega-PR even if the mega-PR ships more features. Reviewable surface = how much code change a security-relevant reviewer has to hold in their head at once.

These principles can be overridden by user need (and have been — T7.0 jumped ahead of T6.3 because the testing UX was painfully blocking work). But the override is a deliberate exception.

Priorities are set by one developer (me + an AI assistant) and reflect one perspective. If you disagree with the order, open an issue and say so.

---

## 8. How to read this doc

- **Done means landed on `main` with full CHANGELOG entry, tests, and security analysis.** Not "code exists somewhere".
- **In flight means actively being worked on between commits.** Usually one item.
- **Next means I'd build this if I sat down right now.** Recommended order, not contracted.
- **Later means real but not imminent.** May get reordered as carry-forwards accumulate.
- **Won't do means I won't take a PR for this** without first changing the design's core assumptions.

If you want to help with a "next" or "later" item, comment on the relevant `THREAT_MODEL.md` §8.2 entry or open an issue saying which item you want to take. I'll usually say "yes please" — see `SECURITY.md` for the PR review criteria.
