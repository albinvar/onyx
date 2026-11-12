# Onyx

A Tor-only, end-to-end-encrypted messenger. Every user is an onion service;
messages are MLS ciphertext inside a Noise tunnel inside a Tor circuit.
Optional relays ("hubs") hold sealed envelopes for people who are offline and
never see plaintext. Written in Rust.

```
 ◈ onyx                                                  ● Tor    hubs 1/1    v0.1.x
   Direct                  │ ▸ mira  ·  ● direct  ·  ✓ verified
▸ ● mira        2m ✓       │──────────────────────────────────────────────────────
  ○ jonas       3d         │ mira   09:14  are you there?
   Rooms                   │ me     09:15  yes — one sec
  ◆ field-notes 1h         │ mira   09:15  [hub] sent while you were away
                           │
                           │ Compose → mira ● direct ─────────────────────────────
                           │ > _
 F1 help   Ctrl-K commands   Ctrl-E share   Ctrl-A add   Ctrl-F file   Esc quit
```

*(schematic of the terminal interface)*

---

## Read this first

Onyx is **pre-1.0** and has **not had an external security audit**.

- One maintainer, working with an AI assistant. About 47,000 lines of Rust.
- The primitives are standard (Ed25519, X25519, ML-KEM-768, ChaCha20-Poly1305,
  Argon2id, MLS via `openmls`, Noise XK via `snow`, Tor via Arti). How they are
  *composed* has only been reviewed internally.
- Two internal audits have been done. The most recent (November 2026) found and
  fixed real, exploitable bugs — including sender impersonation inside rooms
  and plaintext in logs. That is evidence the code needed review, not evidence
  that nothing is left. Known open weaknesses are listed in
  [`THREAT_MODEL.md` §8.6](./THREAT_MODEL.md) and
  [`ATTACKS.md`](./ATTACKS.md).
- About 640 tests pass, including adversarial-hub tests and a decoder fuzz.
  Tests show the attacks we thought of are blocked. They do not show the
  design resists an adversary who thinks of something else.

**Use it for** learning, experiments, and conversations where a failure would
be an inconvenience. **Do not use it** where your safety, freedom, or
livelihood depends on it — use Signal, Briar, or Cwtch, which have had years of
independent scrutiny.

---

## What it does

| | |
|---|---|
| **Direct messages** | Your daemon dials the other person's onion address, authenticates them with Noise XK, and runs a two-party MLS group. Delivery is acknowledged; unacknowledged messages are retried when the session returns. |
| **Rooms** | One MLS group per room. Each line is attributed by the sender's MLS signature key, not by anything a relay or another member can claim. Admin-gated membership changes. |
| **Files** | Sent inside the same encrypted channel, in DMs and rooms. Metadata (EXIF, filenames) is stripped unless you opt out. Received files are `0600` in a `0700` directory. |
| **Offline delivery** | A hub stores sealed, padded envelopes addressed to opaque routing tokens. Each room member has their own token, so a hub cannot count a room's members from one token. |
| **First contact** | A *connect code* (direct, no hub) or a signed *invite link* (via a hub). Both are meant to be handed over on a channel you already trust. |
| **Consent** | A room invitation from someone who is not already your contact is held until you accept it. |
| **Identity pinning** | A contact's key is pinned on first use; a changed key is flagged loudly and blocks sending until you re-verify. Safety numbers for out-of-band comparison. |
| **Local storage** | Keys and message text are sealed in an Argon2id-protected vault. One daemon per vault (lock file). `onyx vault backup` / `onyx vault rekey`. |
| **Releases** | Binaries are signed with sigstore; the installer verifies the exact release workflow identity, a signed checksum file, and refuses downgrades. |

### What it does not do

Stated plainly, because these matter more than the list above:

- **It does not hide that you use Tor**, unless you configure bridges
  ([`TOR-BRIDGES.md`](./TOR-BRIDGES.md)).
- **It does not defeat a global passive adversary.** Someone who can watch both
  ends of a Tor circuit can correlate timing. Optional cover traffic raises the
  cost; it does not remove the attack.
- **A contact can tell when you are online.** They hold your onion address and
  delivery receipts confirm receipt. Removing a contact does not take the
  address back. (Planned fix: Tor client authorization — see
  [`TRUST-ARCHITECTURE.md`](./TRUST-ARCHITECTURE.md) T-1.)
- **Envelopes relayed through a hub are sealed to a long-lived key.** A hub
  that records traffic, plus a later compromise of your device, reveals who
  sent each recorded envelope. (Planned: rotating key, T-2.)
- **The vault file shows your contact list and timestamps without the
  passphrase.** Keys and message text are sealed; the social graph is not.
  (Planned: whole-database encryption, T-3.)
- **It cannot protect a compromised device.** Malware or an unlocked, seized
  machine sees what you see.
- **No mobile app, no multi-device, no account recovery.** A forgotten
  passphrase is unrecoverable.

---

## Install

```sh
curl -fsSL https://github.com/albinvar/onyx/releases/latest/download/install.sh | bash
```

The script detects your platform (macOS arm64/x86_64, Linux x86_64/aarch64),
downloads the binary, verifies its sigstore signature and checksum, and
installs `onyx` to `~/.local/bin`. It requires `cosign`. Read
[`INSTALL.md`](./INSTALL.md) for the download-read-run recipe and
[`RELEASES.md`](./RELEASES.md) for what the signature does and does not prove.

Windows: use WSL2.

### From source

Rust 1.95 (pinned in `rust-toolchain.toml`) and a C compiler.

```sh
git clone https://github.com/albinvar/onyx.git
cd onyx
cargo build --release --locked
# binaries: target/release/onyx, onyxd, onyx-hub
```

---

## Quick start

### 1. Start

```sh
onyx
```

With no arguments, `onyx` starts the daemon and the terminal interface in one
process. On first run it asks you to set a vault passphrase. Tor takes 30–60
seconds to bootstrap the first time.

Everything lives in `~/.onyx/` (vault, socket, log, config, received files),
readable only by you.

### 2. Add a contact

Both of you online:

```sh
# you
onyx code                       # prints onyx://connect/v1?onion=…&id=…

# them
onyx connect 'onyx://connect/v1?…'
```

In the terminal interface the same thing is `Ctrl-E` (share) and `Ctrl-A`
(add). Send the code over a channel where you already know who is on the other
end; whoever holds it can reach you.

Then **verify**: compare safety numbers (`/verify` in the interface) in person
or over a call. Until you do, you are trusting the channel you sent the code
over.

### 3. Talk

```sh
onyx peers                      # who is connected, verified, or changed
onyx send <short-id> "hello"
onyx history <short-id>
```

or just type in the interface.

### If the other person is offline

Direct contact needs both of you online. A hub removes that requirement at a
privacy cost:

```sh
onyx --hub '<onion>:<port>,<hub-pubkey>'            # use a hub
onyx --hub … --first-contact-reachable              # also accept first contact via it
```

**With a hub configured, `onyx` relays a direct message through it when the
other person is offline** (on by default since v0.1.29, so contacts met by
invite link are reachable at all). The hub sees a sealed envelope on a
rotating token — not the text or who it is from — but it does learn that
*something* was sent while that person was away. To keep direct messages
strictly peer-to-peer, set `"dm_hub_fallback": false` in
`~/.onyx/config.json`; messages then wait on your machine until a direct
session returns. The headless `onyxd` has it off unless you pass
`--dm-hub-fallback`.

By default a hub cannot link your connection to your identity (fresh keys per
connection, no inbox subscription). `--first-contact-reachable` trades that
away so strangers holding your invite link can reach you. See
[`ANONYMITY.md`](./ANONYMITY.md) §3.2 before turning it on.

`onyx doctor` explains, in plain language, why messaging is not working.

---

## Terminal interface

| Key | Action |
|---|---|
| `↑` `↓` | Move between conversations |
| `Enter` | Send |
| `PgUp` `PgDn` `Home` `End` | Scroll history / jump to oldest / back to live |
| `F1` | Help — every binding |
| `Ctrl-K` | Command palette |
| `Ctrl-E` | Share my contact (connect code and invite link) |
| `Ctrl-A` | Add a contact (paste either kind) |
| `Ctrl-N` | New room |
| `Ctrl-I` | Invite a contact into the selected room |
| `Ctrl-F` | Send a file |
| `Ctrl-G` | Hubs and reachability |
| `Ctrl-L` | Log tail |
| `Esc` / `Ctrl-C` | Close the open dialog, or quit |

Composer commands: `/help`, `/share`, `/add <link>`, `/room [name]`, `/file`,
`/search`, `/verify`, `/invites`, `/join <n>`, `/decline <n>`, `/clear`, `/q`.

A message that arrived through a hub is marked; a conversation shows whether
it is direct, relayed, or has no route.

---

## Command line

Output is readable text at a terminal and JSON when piped or with `--json`.
Exit status: `0` success, `1` the daemon returned an error, `2` could not
reach the daemon.

| Command | |
|---|---|
| `onyx` | Daemon + interface in one process |
| `onyx daemon` / `onyxd` | Headless daemon (systemd, containers) |
| `onyx tui` | Interface only, against a daemon already running |
| `onyx status` · `identity` · `doctor` | Health, your keys, self-diagnosis |
| `onyx code` · `connect <code>` | Direct first contact |
| `onyx invite [--with-kp] [--with-hubs]` · `accept <url>` | First contact through a hub (signed link) |
| `onyx peers` · `send <id> <text>` · `history <id>` | Direct messages |
| `onyx contact list` | Pinned identities; flags changed keys |
| `onyx room create \| list \| invite \| send \| send-file \| rename \| leave \| remove \| delete` | Rooms |
| `onyx room pending \| accept <n> \| decline <n>` | Invitations held for your consent |
| `onyx files list \| send` | File transfer |
| `onyx vault backup \| rekey` | Offline vault maintenance (stop the daemon first) |

`onyx <command> --help` documents every flag.

### Configuration

| | Flag | Environment | Default |
|---|---|---|---|
| Vault | `--vault` | `ONYX_VAULT` | `~/.onyx/vault.db` |
| Passphrase | — | `ONYX_PASSPHRASE` | prompted |
| API socket | `--socket` | `ONYX_API_SOCKET` | `~/.onyx/onyx.sock` |
| Hub (repeatable) | `--hub onion:port,pubkey` | — | none |
| Tor bridge (repeatable) | `--bridge` | — | none |
| Cover traffic | `--cover-traffic-mean-secs`, `--constant-rate-ms` | `ONYX_COVER_TRAFFIC_MEAN_SECS`, `ONYX_CONSTANT_RATE_MS` | off |
| Reachable for first contact via hub | `--first-contact-reachable` | `ONYX_FIRST_CONTACT_REACHABLE` | off |
| Relay DMs via hub when peer offline | `--dm-hub-fallback`; config `"dm_hub_fallback": false` to disable | `ONYX_DM_HUB_FALLBACK` | **on** in `onyx` (needs a hub); off in `onyxd` |
| Tell senders their message arrived | `--no-delivery-receipts`; config `"delivery_receipts": false`; `/receipts off` | `ONYX_NO_DELIVERY_RECEIPTS` | on |

Hubs added in the interface persist in `~/.onyx/config.json`.

Prefer the prompt or the environment for the passphrase. `--passphrase`
exists, but arguments are visible in `ps` and shell history.

### Development mode (no Tor, no anonymity)

For working on the code without waiting for Tor, the daemon can speak plain
TCP on localhost. These modes refuse to start without `--allow-clearnet`,
expose your IP address, and must never be used with real contacts.
`scripts/local-hub-demo.sh` sets up a two-party local demo;
`scripts/real_tor_smoke.sh` runs the same flow over real Tor.

---

## Running a hub

```sh
ONYX_HUB_PASSPHRASE=… onyx-hub --vault ./hub.db --tor-state-dir ./hub-tor
```

The hub prints its onion address and public key; users pass both to `--hub`.
A hub sees: connection timing, envelope sizes (padded to buckets), and opaque
routing tokens. It does not see plaintext, sender identity, room names, or —
with the private default — which long-term identity a connection belongs to.
It can drop or delay messages; it cannot forge or read them. Details and the
abuse limits it enforces: [`THREAT_MODEL.md`](./THREAT_MODEL.md),
[`QUEUE-HARDENING.md`](./QUEUE-HARDENING.md).

### Monitoring hubs (optional)

`onyx-metrics` is a small collector that shows whether enrolled hubs are up.
It is off unless a hub operator turns it on.

```sh
onyx-metrics --allowlist ./allow.json           # prints its onion address
onyx-hub … --metrics-report '<collector-onion>' # on each hub that opts in
```

A hub that opts in sends a signed heartbeat over Tor every few minutes:
version, coarse uptime, whether its onion is reachable — **liveness only, no
counts of users, messages or connections**. The collector accepts only keys
on its allowlist, keeps the latest state per hub (no history), and serves a
detailed status page on `127.0.0.1:9876` for the operator only. An optional
public page (`--publish-dir`) shows just a name and up/down in five-minute
steps — no versions, keys, uptime or precise timing, so it does not double
as a guide to which relay to attack. The allowlist is a JSON file of
`{ "hubs": [ { "name": …, "sig_pub_b32": … } ] }`. Read [`METRICS.md`](./METRICS.md) before
enabling it: even liveness data is a time series someone could correlate.

---

## How it fits together

```
 onyx (CLI / interface) ──unix socket 0600──▶ onyxd
                                               ├─ vault      SQLite, Argon2id, per-row AEAD
                                               ├─ identity   Ed25519 · X25519 · X25519+ML-KEM-768
                                               ├─ MLS        one group per DM and per room
                                               ├─ sessions   Noise XK, one per connected peer
                                               └─ Tor (Arti) onion service in, onion dials out
                                                     │
                         ┌───────────────────────────┴───────────────┐
                         ▼                                           ▼
                 a contact's onyxd                         onyx-hub (optional)
                 direct, both online                       sealed envelopes, offline delivery
```

Layers, outermost first: **Tor** hides network location → **Noise XK**
authenticates the peer and encrypts the link → **MLS** gives forward secrecy
and post-compromise security per conversation → for relayed traffic, a
**hybrid post-quantum sealed envelope** hides sender and content from the hub.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Nothing happens when I message someone | Run `onyx doctor`. Usually the peer is offline, or Tor has not finished publishing your onion. |
| Tor stays at "bootstrapping" | A cold first start takes up to a minute. On a censored network, configure bridges. |
| The daemon refuses to start, saying the vault is locked | Another daemon is already running on that vault. One daemon per vault is enforced. |
| `vault open failed (wrong passphrase?)` | Wrong passphrase. There is no recovery. |
| "identity changed" on a contact | Their key differs from the pinned one: a reinstall, or an interception. Re-verify out of band before continuing. |
| A room invitation never appeared | It is waiting in `onyx room pending` because the inviter is not yet a contact. |
| The daemon refuses a plain-TCP flag | It was given without `--allow-clearnet`. That is the safeguard working. |
| Arti permission error on macOS | The Tor state directory or a parent is group/world-writable. Fix the permissions rather than disabling the check. |

Logs: `~/.onyx/onyx.log`. They are written to avoid message text,
fingerprints and room names; if you find one that does not, that is a bug
worth reporting.

---

## Documentation

**Start here**

| | |
|---|---|
| [`USER_GUIDE.md`](./USER_GUIDE.md) | A short, plain guide to installing and using Onyx |
| [`HOW_IT_WORKS.md`](./HOW_IT_WORKS.md) | Each protection layer in plain language |
| [`ANONYMITY.md`](./ANONYMITY.md) | What an observer can and cannot learn |
| [`THREAT_MODEL.md`](./THREAT_MODEL.md) | Adversaries, status table, open residuals (§8.6) |
| [`ATTACKS.md`](./ATTACKS.md) | Published attacks on messengers, Tor and release pipelines, and where Onyx stands on each |
| [`TRUST-ARCHITECTURE.md`](./TRUST-ARCHITECTURE.md) | The four structural gaps and the chosen fix for each |
| [`SECURITY.md`](./SECURITY.md) | Engineering rules, review checklist, how to report a vulnerability |

**Using and operating**

| | |
|---|---|
| [`INSTALL.md`](./INSTALL.md) · [`RELEASES.md`](./RELEASES.md) | Installing and verifying |
| [`TOR-BRIDGES.md`](./TOR-BRIDGES.md) | Censored networks |
| [`FILES.md`](./FILES.md) | File transfer and metadata stripping |
| [`METRICS.md`](./METRICS.md) | Opt-in hub liveness telemetry |
| [`MOBILE.md`](./MOBILE.md) | Termux status |

**Design records**

[`DESIGN.md`](./DESIGN.md) (protocol) ·
[`CHANNELS.md`](./CHANNELS.md) ·
[`ROOM-AUTHORITY.md`](./ROOM-AUTHORITY.md) ·
[`DELIVERY.md`](./DELIVERY.md) ·
[`ROTATION.md`](./ROTATION.md) ·
[`OBLIVIOUS-ROUTING.md`](./OBLIVIOUS-ROUTING.md) ·
[`FEDERATION.md`](./FEDERATION.md) ·
[`DISCOVERY.md`](./DISCOVERY.md) ·
[`QUEUE-HARDENING.md`](./QUEUE-HARDENING.md) ·
[`ROADMAP.md`](./ROADMAP.md) ·
[`CHANGELOG.md`](./CHANGELOG.md)

Some design records predate the code they describe; where a record and the
code disagree, the code and `THREAT_MODEL.md` are authoritative.

---

## Contributing

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check
```

Read [`SECURITY.md`](./SECURITY.md) first: every change is reviewed against
its rules (no optional weakening, everything persisted is sealed, no secrets
in logs, a threat-model entry for anything that changes what a party learns).

**Vulnerabilities:** report privately through GitHub Security Advisories on
this repository. Please do not open a public issue.

The most valuable contribution right now is independent review of the
protocol composition.

---

## License

[AGPL-3.0-or-later](./LICENSE). If you run a modified hub for other people,
you must publish your changes.
