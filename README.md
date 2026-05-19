# Onyx

Anonymous, end-to-end-encrypted chat over Tor. Rust core, hybrid P2P + optional hub relay, MLS group encryption with a post-quantum hybrid bootstrap.

```
┌─ onyx ──────────────────────────────────────────────────┐
│ Peers           │ #peer-short                           │
│ ─────────────── │ ──────────────────────────────────── │
│ ● peer1   live  │  peer1: hi                           │
│ ○ peer2   ──    │      me: hey                          │
│                 │  peer1: [hub] sent while you were offline
│                 │                                       │
│                 │ ┌────────────────────────────────────┐│
│                 │ │ > type to send_                    ││
│                 │ └────────────────────────────────────┘│
├─────────────────┴───────────────────────────────────────┤
│ tor ready · ● live · you abc1 234 · 2 peers · v0.0.1   │
└─────────────────────────────────────────────────────────┘
```

---

## 0. Status disclaimer (read this first)

Onyx is **pre-1.0 research and engineering**. As of writing:

- **No external security audit has been conducted.** Not by anyone. Not at any depth.
- The codebase is ~12,000 lines of Rust written by one developer working with an AI assistant over a few weeks.
- The cryptographic primitives are sound (Ed25519, X25519, ChaCha20-Poly1305, Argon2id, ML-KEM-768, MLS via openmls 0.8, Noise XK via snow). The way we *compose* them has not been independently reviewed.
- **216 internal tests pass.** They cover correctness, not metadata-resistance against an adversary.

**Practical consequence:** appropriate for **learning, demos, hobby chat, and contributing to the codebase**. Not appropriate for any communication where your safety, freedom, or livelihood depends on the protocol's security. Use Signal, Briar, or other mature tools for those.

This caveat is repeated in `SECURITY.md` §1 and will only be removed when an external audit confirms it can be.

---

## 1. What Onyx is, in one paragraph

Each user runs a long-running daemon (`onyxd`) that owns their long-term identity keys (Ed25519 signing + X25519 identity + a hybrid post-quantum KEM secret) inside an Argon2id-protected SQLite vault. The daemon runs an embedded Tor client (Arti) and publishes a v3 hidden service — that's the user's inbox. To chat, the daemon dials another user's onion, completes a `Noise_XK_25519_ChaChaPoly_BLAKE2s` handshake for transport-layer mutual auth + AEAD, then bootstraps an [MLS (RFC 9420)](https://datatracker.ietf.org/doc/html/rfc9420) group for application-layer forward secrecy and post-compromise security. Messages are exchanged as MLS application messages inside the Noise tunnel. Users interact via the `onyx` CLI/TUI which connects to their local daemon over a `chmod 0600` Unix socket. An optional `onyx-hub` binary relays sealed-sender envelopes between peers who aren't online simultaneously — the hub never sees plaintext.

---

## 2. Project status

| Binary | What it does | State |
|---|---|---|
| `onyxd` | Daemon: vault, Tor circuit, hidden service, Noise+MLS chat path, hub client | **functional end-to-end** |
| `onyx`  | CLI + multi-pane Ratatui TUI; talks to `onyxd` over Unix socket | **functional, growing CLI surface** |
| `onyx-hub` | Optional relay: stores sealed envelopes + KeyPackage directory | **functional v0** (in-memory state, no auth yet) |

What works today (verified end-to-end):

- Two daemons over real Tor: handshake, MLS bootstrap, **live two-way chat** in the TUI.
- Two daemons over **local TCP** (`--listen-tcp` / `--dial-tcp`, **test-only**) — same chat path without 60-second Tor bootstrap, useful for development.
- A hub serving sealed-sender envelopes; daemons publish their MLS KeyPackages to it; first-contact via hub works in both `msg/v1` (per-message PFS) and `mls/v1` (full MLS PCS) tiers.
- CLI subcommands: `status`, `identity`, `tui`, `send-bootstrap`, `send-bootstrap-mls`, `fetch-keypackage`.
- MLS state persistence: groups survive daemon restart; reconnects resume the same MLS epoch.
- TUI with live tail subscription, peer list, message scrollback, history backfill across restarts, and a visible `[hub]` security-tier badge for hub-relayed messages.

What's **not** done yet (carry-forward, with item numbers from `THREAT_MODEL.md` §8.2):

- Single-binary merge — today you run `onyxd` + `onyx` separately (T7.1 planned).
- Invite URLs — peer onboarding still requires copy-pasting fingerprints + KEM publics + KPs (T7.2 planned).
- Multi-party rooms / channels (T6.3 planned).
- Ongoing MLS app messages routed over hub (T6.x — needed for fully-asynchronous chat without any direct circuit).
- Hub-side ownership validation of routing IDs (§8.2 #15, mitigated recipient-side).
- Reproducible builds + signed releases.
- External security audit.

---

## 3. Install

You need **Rust stable** (we test on 1.95+) and a C toolchain (the Arti dep set pulls some C-backed crypto). On macOS that's just `xcode-select --install`.

```sh
git clone https://github.com/albinvar/onyx.git
cd onyx
cargo build --release        # ~3-5 minutes the first time; subsequent builds are seconds
```

For day-to-day use you'll want the binaries on your `$PATH`:

```sh
cargo install --path crates/onyxd   --force
cargo install --path crates/onyx    --force
cargo install --path crates/onyx-hub --force   # only if you want to run a hub
```

The `--force` flag matters if you've installed an older snapshot — `cargo install` refuses to overwrite by default. After this, `which onyxd` should report `~/.cargo/bin/onyxd` (assuming `rustup`'s defaults).

If you'd rather not install globally, replace every `onyxd` / `onyx` in the recipes below with `./target/release/onyxd` / `./target/release/onyx`.

---

## 4. Quick start — local TCP test mode (no Tor, ~5 seconds to chat)

**This is the recommended first thing to run.** It exercises the entire Noise + MLS chat path without paying Tor's 30-60 second bootstrap cost. The mode is **test-only** — see `SECURITY.md` §6.2 for the loud caveats. Don't run it against real peers.

You'll use **four terminals**: two daemons + two TUIs.

### Cleanup (do this before each fresh attempt)

```sh
# kill anything still holding the test ports
lsof -ti :7710 | xargs kill -9 2>/dev/null
pkill -9 onyxd 2>/dev/null

# wipe old vault + socket state
rm -f demo-alice.db demo-bob.db demo-alice.sock demo-bob.sock
```

### Terminal 1 — alice (listener)

```sh
ONYX_PASSPHRASE=alice onyxd \
  --vault ./demo-alice.db \
  --api-socket ./demo-alice.sock \
  --listen-tcp 127.0.0.1:7710
```

You'll see a log line like:

```
INFO onyxd: share `--dial-tcp 127.0.0.1:7710 --dial-pubkey acgilwcwkxcz...` with a peer to chat
```

**Copy that long string** (alice's `identity_pub_b32`). Leave this terminal running.

### Terminal 2 — bob (dialer)

```sh
ALICE_PUB=<paste-the-string-here-no-brackets>     # e.g. acgilwcwkxcz...

ONYX_PASSPHRASE=bob onyxd \
  --vault ./demo-bob.db \
  --api-socket ./demo-bob.sock \
  --dial-tcp 127.0.0.1:7710 \
  --dial-pubkey "$ALICE_PUB"
```

Within ~1 second you'll see `MLS round-trip complete (initiator)`. Leave it running.

### Terminals 3 + 4 — TUIs

```sh
# Terminal 3
onyx --socket ./demo-alice.sock tui

# Terminal 4
onyx --socket ./demo-bob.sock tui
```

In either TUI: press `↑` or `↓` to select the (single) peer, type a message, press `Enter`. The message appears in the other side's conversation pane within ~1 second.

Quit each TUI with `Esc`, then `Ctrl-C` the daemons.

---

## 5. Real chat over Tor (production-style, ~90 seconds to start)

Same flow as above but with real Tor circuits + hidden services. **This is the actual anonymity-providing path** — `--listen-tcp` only exists for development.

macOS users: Arti enforces strict filesystem permissions on its state directory. If you use `--tor-state-dir`, also set `FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS=1`. Linux normally Just Works.

### Terminal 1 — alice

```sh
FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS=1 \
ONYX_PASSPHRASE=alice onyxd \
  --vault ./demo-alice.db \
  --api-socket ./demo-alice.sock \
  --tor-state-dir ./demo-alice-tor
```

Wait for these two log lines (~30-60 s on a cold cache):

```
INFO onyxd: vault unlocked, identity loaded fingerprint=... identity_pub_b32=ALICE_PUB
INFO onyxd: hidden service published — onion=ALICE_ONION port=1
```

Copy `ALICE_ONION` and `ALICE_PUB`.

### Terminal 2 — bob

```sh
ALICE_ONION=<paste>.onion              # no brackets
ALICE_PUB=<paste>

FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS=1 \
ONYX_PASSPHRASE=bob onyxd \
  --vault ./demo-bob.db \
  --api-socket ./demo-bob.sock \
  --tor-state-dir ./demo-bob-tor \
  --dial-onion "$ALICE_ONION:1" \
  --dial-pubkey "$ALICE_PUB"
```

Wait for `MLS round-trip complete (initiator)`. Then open the TUIs exactly as in §4.

### Cleanup

```sh
rm -f demo-*.db demo-*.sock
rm -rf demo-*-tor
# If you also want to wipe Arti's shared cache (forces full re-bootstrap next time):
rm -rf ~/Library/Application\ Support/arti          # macOS
rm -rf ~/.local/share/arti                          # Linux
```

---

## 6. Hub-relayed first contact (when peers aren't simultaneously online)

The hub is an optional relay that stores sealed envelopes + KeyPackages, sees only ciphertext, and never holds plaintext. Use it when you want "alice sends to bob even though bob is offline; bob comes online and reads it."

**Five terminals**: hub + two daemons + two TUIs (or skip the second TUI if you're just testing the send path). Real Tor required for all three daemons.

### Terminal 1 — hub

```sh
FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS=1 \
ONYX_HUB_PASSPHRASE=hub-pass onyx-hub \
  --vault ./demo-hub.db \
  --tor-state-dir ./demo-hub-tor
```

Wait for:

```
INFO onyx-hub: hub vault unlocked ... hub_pub_b32=HUB_PUB
INFO onyx-hub: hub hidden service published — onion=HUB_ONION port=1
```

Copy both.

### Terminals 2 + 3 — alice + bob daemons (both pointed at the hub)

```sh
HUB_ONION=<paste>.onion
HUB_PUB=<paste>

# Terminal 2 — alice
FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS=1 \
ONYX_PASSPHRASE=alice onyxd \
  --vault ./demo-alice.db \
  --tor-state-dir ./demo-alice-tor \
  --api-socket ./demo-alice.sock \
  --hub-onion "$HUB_ONION:1" --hub-pubkey "$HUB_PUB"

# Terminal 3 — bob (same, different vault/socket/tor-state)
FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS=1 \
ONYX_PASSPHRASE=bob onyxd \
  --vault ./demo-bob.db \
  --tor-state-dir ./demo-bob-tor \
  --api-socket ./demo-bob.sock \
  --hub-onion "$HUB_ONION:1" --hub-pubkey "$HUB_PUB"
```

Both will log `hub: our KeyPackage published` once they connect to the hub.

### Terminal 4 — alice sends to bob via hub

```sh
# Pull bob's identity
BOB_ID=$(onyx --socket ./demo-bob.sock identity)
BOB_FP=$(jq -r .fingerprint    <<<"$BOB_ID")
BOB_KEM=$(jq -r .identity_kem_pub_b32 <<<"$BOB_ID")

# Option A: msg/v1 (PFS only, single shot)
onyx --socket ./demo-alice.sock send-bootstrap \
  --peer-fingerprint "$BOB_FP" \
  --peer-kem-pub-b32 "$BOB_KEM" \
  --text "hi bob — sent via hub"

# Option B: mls/v1 (full MLS PCS; establishes a real MLS group)
BOB_KP=$(onyx --socket ./demo-alice.sock fetch-keypackage \
              --peer-fingerprint "$BOB_FP" | jq -r .kp_b64)
onyx --socket ./demo-alice.sock send-bootstrap-mls \
  --peer-fingerprint "$BOB_FP" \
  --peer-kem-pub-b32 "$BOB_KEM" \
  --peer-kp-b64 "$BOB_KP"
```

### Terminal 5 — bob's TUI shows the message

```sh
onyx --socket ./demo-bob.sock tui
```

Bob's TUI will display alice's message with a yellow **`[hub]`** badge — visual indicator that this came via the hub path (weaker forward-secrecy than direct MLS for `msg/v1`; full MLS PCS for `mls/v1` going forward inside that group). See §8 for the tier details.

---

## 7. TUI keys

| Key | Action |
|---|---|
| `↑` / `↓` | Move peer selection in the left pane |
| `Enter` | Send the composer text to the selected peer |
| any char | Append to composer |
| `Backspace` | Delete one char from composer |
| `r` | Force immediate status + peers refresh (otherwise auto-refreshes every 2 s) |
| `Esc` | Quit the TUI cleanly |
| `Ctrl-C` | Quit the TUI cleanly |

The status bar at the bottom shows: tor state · tail liveness · your fingerprint (short) · peer count · daemon version · keybinding hints.

---

## 8. CLI reference

All `onyx` commands accept `--socket PATH` (default `./onyxd.sock`) or honor `ONYX_API_SOCKET`.

| Command | Effect |
|---|---|
| `onyx status` | Print daemon liveness, identity, Tor state as JSON |
| `onyx identity` | Print just identity pub + fingerprint + KEM public as JSON |
| `onyx tui` | Open the multi-pane Ratatui interface |
| `onyx send-bootstrap --peer-fingerprint X --peer-kem-pub-b32 Y --text Z` | First-contact send via hub, `msg/v1` tier (PFS only) |
| `onyx send-bootstrap-mls --peer-fingerprint X --peer-kem-pub-b32 Y --peer-kp-b64 Z` | First-contact send via hub, `mls/v1` tier (full MLS PCS) |
| `onyx fetch-keypackage --peer-fingerprint X` | Pull a peer's KP from the hub directory; daemon validates against `peer_fingerprint` before returning |

Every CLI command exits `0` on `*Ok` response, `1` on `{"kind":"Error", ...}`, `2` on socket connect failure.

### Security tiers (which mode protects what)

| Mode | PFS | PCS | Anonymity | Notes |
|---|---|---|---|---|
| Direct-MLS over Tor | ✓ | ✓ | ✓ | The strongest path. Both peers online; full ratchet. |
| Hub `mls/v1` | ✓ | ✓ (post-Welcome) | ✓ | Bootstraps an MLS group via hub; subsequent in-group messages have full PCS. |
| Hub `msg/v1` | ✓ (per-message) | ✗ | ✓ | Per-envelope PFS via ephemeral hybrid KEM, but no ratchet. Use for one-off contact. |
| `--listen-tcp` / `--dial-tcp` | ✓ | ✓ | ✗ | Same Noise + MLS encryption; no Tor → network observer sees IPs. **Test only.** |

The TUI renders `[hub]` (yellow, bold) on every `via_hub: true` message so users can read the security tier at a glance. Direct-MLS messages have no badge.

---

## 9. Configuration paths + environment variables

| What | CLI flag | Env var | Default |
|---|---|---|---|
| Vault file | `--vault PATH` | `ONYX_VAULT` | `./onyx-state.db` |
| Vault passphrase | `--passphrase` | `ONYX_PASSPHRASE` | (required) |
| Local API socket | `--api-socket PATH` | `ONYX_API_SOCKET` | `./onyxd.sock` |
| Tor state dir | `--tor-state-dir PATH` | `ONYX_TOR_STATE_DIR` | platform default |
| Hub onion | `--hub-onion HOST[:PORT]` | `ONYX_HUB_ONION` | (off) |
| Hub pubkey | `--hub-pubkey B32` | `ONYX_HUB_PUBKEY` | (off) |
| Local TCP listen (test) | `--listen-tcp ADDR` | `ONYX_LISTEN_TCP` | (off) |
| Local TCP dial (test) | `--dial-tcp ADDR` | `ONYX_DIAL_TCP` | (off) |

`ONYX_PASSPHRASE` should be set via the environment rather than as a CLI flag — flags show up in `ps` and shell history.

For the `onyx` CLI: `ONYX_API_SOCKET` overrides the default socket path. Useful when running multiple daemons on one machine.

---

## 10. Troubleshooting

| Symptom | Cause / Fix |
|---|---|
| `error: unexpected argument '--listen-tcp'` | You're running an old installed `onyxd`. Run `cargo install --path crates/onyxd --force`, or use `./target/debug/onyxd`. |
| `Address already in use (os error 48)` | Another daemon (yours or someone else's) holds the port. `lsof -ti :7710 \| xargs kill -9`. |
| `vault open failed (wrong passphrase?)` | Schema bumped between commits — `rm demo-*.db` and recreate. The vault format has changed several times in early development. |
| `daemon unreachable: connect API socket ./onyxd.sock` in TUI | The daemon isn't running, or you used the wrong `--socket` path. The TUI auto-refreshes every 2 s — start the daemon and the status bar flips to live data. |
| `Another process has the lock` (Arti) | Two daemons sharing one Tor state dir. Each needs its own `--tor-state-dir`. |
| `FS_MISTRUST` permissions error (macOS) | Set `FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS=1` when using `--tor-state-dir`. |
| Tor stuck at `bootstrapping` for >2 min | First-run cold cache. Subsequent runs are 5-10s. Don't kill it. |
| `zsh: parse error near '\n'` | You copied a multi-line command and `<paste>` got interpreted as input redirection. The `<...>` are placeholders — type the actual value with no `<` `>` brackets. |
| `onyx: command not found` | Binary isn't on `$PATH`. Run `cargo install --path crates/onyx`, or use `./target/release/onyx`. |
| TUI shows "no peer to send to" | No peer has been added yet. With `--no-tor` alone, you literally can't add a peer (no transport). Use `--listen-tcp` / `--dial-tcp` (test) or real Tor (real). |

---

## 11. Architecture cheat-sheet

```
                          ┌──────────────────────────────────────┐
                          │            onyxd (daemon)            │
                          │  ┌────────────┐  ┌────────────────┐  │
   ┌──────────┐    UDS    │  │  vault     │  │  MLS party     │  │
   │ onyx CLI │ ────────► │  │  (SQLite + │  │  (openmls 0.8) │  │
   │ + TUI    │  ndjson   │  │  Argon2id  │  └────────────────┘  │
   └──────────┘   0600    │  │  + AEAD)   │  ┌────────────────┐  │
                          │  └────────────┘  │ conversation   │  │
                          │  ┌────────────┐  │ registry       │  │
                          │  │ Identity:  │  │ (per peer)     │  │
                          │  │ Ed25519,   │  └────────────────┘  │
                          │  │ X25519,    │       │  ▲           │
                          │  │ hybrid KEM │       │  │            │
                          │  └────────────┘       │  │            │
                          │                       ▼  │            │
                          │  ┌────────────────────┴──┴─────────┐  │
                          │  │   peer_session (per peer)        │  │
                          │  │   Noise XK + MLS app messages    │  │
                          │  └──────────────┬───────────────────┘  │
                          │                 │                       │
                          │  ┌──────────────┴───────────┐  ┌─────┐  │
                          │  │ Tor (embedded Arti)      │  │ TCP │  │
                          │  │ - v3 hidden service      │  │ (test only)
                          │  │ - outbound onion dial    │  └─────┘  │
                          │  └──────────────────────────┘           │
                          └─────────────┬──────────────────────────┘
                                        │
                                        │  Noise+MLS over Tor (or TCP)
                                        ▼
                                  another daemon
                                  (or onyx-hub
                                   for offline relay)
```

---

## 12. Documentation index

| Doc | Purpose |
|---|---|
| `README.md` | (this file) install, run, troubleshoot |
| **`HOW_IT_WORKS.md`** | **"How do I know this is secure?" — plain-English walkthrough of every protection layer, with the specific tests / RFCs / audited libraries behind each claim. Start here if you want to understand or verify Onyx's security posture.** |
| **`ANONYMITY.md`** | **"Can my adversary tell I'm talking to X?" — honest inventory of what Onyx hides and what it doesn't. Adversary model (A1–A4), defences in place today (with file pointers), gaps not yet closed, recommendations per threat model.** |
| `FEDERATION.md` | Design doc for hub-to-hub gossip (T8.3, in design). Wire protocol, gossip semantics, loop prevention, threat-model deltas, slice plan. No code yet — review the open questions before implementation begins. |
| `DISCOVERY.md` | Why Onyx does NOT have public hub discovery yet (T8.4 deferred). Bootstrapping problem, four approaches honestly compared (bundled list / online directory / DHT / invite-based), recommendation to defer, what we'd build if/when the governance question is answerable. |
| **`ROADMAP.md`** | **"What's coming next?" — completed phases, in-flight work, prioritised next queue, long-term direction, explicit "won't do" list. Start here to see where the project is going.** |
| `DESIGN.md` | Full protocol specification — wire formats, key derivation, frame types, group lifecycle |
| `THREAT_MODEL.md` | Adversaries (A1-A6) + non-adversaries (N1-N7) + §8 implementation-status table with current carry-forward gaps |
| `SECURITY.md` | Eight enforcement principles, PR review checklist, vulnerability disclosure policy, primitive table |
| `CHANGELOG.md` | Append-only dev log, one entry per substantive session with design decisions + verification + carry-forward items |
| Module doc-comments in `crates/onyx-core/src/*.rs` | Per-subsystem detail (crypto, identity, MLS, routing, storage, transport, wire) |

---

## 13. Contributing + the CI gate

PRs must pass the same gate CI runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check                # cargo install cargo-deny --locked first
```

Before submitting, please read `SECURITY.md` — every PR is reviewed against the eight enforcement principles (forward-only protocol versioning, no optional weakening, vault-sealing of persisted data, etc.) listed there.

Vulnerability disclosure: use **GitHub Security Advisories** on the repo (`/security/advisories`). See `SECURITY.md` §5 for the SLA.

---

## 14. License

[AGPL-3.0-or-later](./LICENSE). Onyx is a network-deployed service; hub operators forking the code and running it for the public must publish source.

---

## 15. Where this came from

This project is one developer's exploration of how to compose **Noise + MLS + Tor + post-quantum hybrid KEMs** into a complete anonymous messaging system in modern Rust, with explicit threat modeling and a discipline of "no commit without security-tier accounting." Every code change has a corresponding CHANGELOG entry covering design decisions and carry-forward gaps. Every cryptographic claim names the specific RFC and crate version that backs it. The result is a credible proof-of-concept of how an Onyx-like system can be built — not a product, not a service, and not yet trustworthy enough to bet anything important on. Watch this repo if you want to follow that journey, or contribute if you'd like to help.
