# Tor bridges & pluggable transports

**Status:** plain bridges (F2.2a) and obfs4 / webtunnel / snowflake
(F2.2b) are built. The design notes below are kept for the record.

## Using a bridge

Use one when Tor is blocked or slow where you are, or when you don't want
your network to see that you use Tor.

1. **Install a transport program** (not needed for plain bridges):

   | System | Command |
   |---|---|
   | Debian / Ubuntu / Raspberry Pi OS | `sudo apt install obfs4proxy snowflake-client` (or `lyrebird` where packaged) |
   | macOS | Install Tor Browser. Onyx uses the copies inside it. |
   | Termux | `pkg install obfs4proxy` |

   Onyx looks on `PATH`, in `/usr/bin`, `/usr/local/bin`, Homebrew, and
   inside Tor Browser. If yours is elsewhere, tell it:
   `--pt-binary obfs4=/full/path/to/lyrebird`.

2. **Get bridge lines.** From <https://bridges.torproject.org>, by email
   to `bridges@torproject.org`, or from Tor Browser's settings. They look
   like this:

   ```
   obfs4 192.0.2.55:38114 316E6433…5F5F cert=YXJl…ZmluZC4 iat-mode=0
   ```

3. **Give them to Onyx**, either on the command line
   (`onyx --bridge "obfs4 …" --bridge "obfs4 …"`) or in
   `~/.onyx/config.json`:

   ```json
   { "bridges": ["obfs4 …", "obfs4 …"] }
   ```

   Then restart Onyx. `Ctrl-T` shows **Connects via: 2 obfs4 bridges
   (traffic disguised)**.

If a bridge needs a program Onyx cannot find, Onyx refuses to start and
says which one. It never quietly connects without the bridge.

Tested on Linux with `obfs4proxy` (obfs4) and `snowflake-client`
(snowflake). lyrebird, webtunnel and macOS have not been tested yet.

| Kind | Hides | Program |
|---|---|---|
| plain | which relay you use (beats address blocklists) | none |
| `obfs4` | that the traffic is Tor | lyrebird or obfs4proxy |
| `webtunnel` | that the traffic is Tor; looks like HTTPS to a website | lyrebird |
| `snowflake` | that the traffic is Tor; goes through volunteer browser proxies; slow | snowflake-client |

What bridges do **not** do: they change whether your network can see or
block Tor, not your anonymity once connected. The bridge operator sees
your IP address and that you use Tor, as your first relay always does.
Bridge lines you got from a public source may also be known to a censor.

---

# Design notes (F2.2)

Goal: let a user **hide that they use Tor at all** — the highest-leverage
opsec Onyx could ship. Today Onyx connects to public Tor guard relays whose
IPs are in published lists, and its channel looks like Tor to deep-packet
inspection (DPI). An ISP or national censor can therefore *block* or *flag*
"this person uses Tor," which is itself the signal a hostile network wants.

---

## §1 What arti 0.42 actually supports (verified)

Two cargo features, both currently **off** in our `arti-client` dependency:

- **`bridge-client`** → vanilla **bridges**. Exposes
  `arti_client::config::BridgeConfigBuilder` / `BridgesConfig`. A bridge is
  an **unlisted** Tor relay; you connect to it instead of a public guard, so
  the censor's *IP blocklist of public guards* doesn't catch you. The wire
  still looks like Tor, so **DPI can still fingerprint it.**
- **`pt-client`** (pulls in `tor-ptmgr`, implies `bridge-client`) →
  **pluggable transports**. Exposes
  `arti_client::config::pt::TransportConfigBuilder`. arti spawns an
  **external PT binary** (e.g. `lyrebird` for obfs4, or a snowflake client)
  via a `ManagedTransportConfig` (path to the binary + the protocol names it
  provides). The PT **obfuscates** the channel so DPI can't tell it's Tor —
  this is the real "hide that you use Tor" capability. Cost: the PT binary
  is **not** part of arti; the user must install it.

Both wire into `TorClientConfig` via the builder in
`tor.rs::build_tor_config` (alongside the existing vanguards pin):
`builder.bridges()` takes the bridge list + the transport list.

---

## §2 The two tiers (what each defeats)

| Tier | Mechanism | Defeats | Does NOT defeat |
|------|-----------|---------|------------------|
| **Vanilla bridge** (`bridge-client`) | connect via an unlisted relay | IP blocklists of public guards | DPI that fingerprints Tor's TLS |
| **obfs4 / PT** (`pt-client` + lyrebird) | obfuscated, random-looking stream | IP blocklists **and** DPI fingerprinting | active probing of the bridge IP; a censor who has the bridge line too |
| **snowflake** (PT) | ephemeral WebRTC proxies | IP blocking + DPI; very hard to enumerate | high-latency; needs the snowflake PT |

Vanilla bridges are the cheap 60%; obfs4/PT is the censorship-resistant
real answer.

---

## §3 Config surface (proposed)

Mirror the existing `--hub` config style (CLI flag + config file):

- **`--bridge "<bridge line>"`** (repeatable). A bridge line is the standard
  Tor format, parsed by `BridgeConfigBuilder::from_str`:
  - vanilla: `<ip:port> <fingerprint>`
  - obfs4: `obfs4 <ip:port> <fingerprint> cert=<...> iat-mode=<0|1|2>`
- **`--pt-binary <transport>=<path>`** (repeatable, e.g.
  `obfs4=/usr/bin/lyrebird`) → a `TransportConfigBuilder` (protocols +
  managed binary path). Only needed for PT bridges.
- Persisted in the daemon config file so `onyxd` restarts keep them.

Wiring: in `build_tor_config`, when bridges are configured, call
`builder.bridges().bridges([...]).transports([...])`. Bridges **replace**
the default guard selection; **vanguards still apply** (they're the L2/L3
layers on top — verify they compose, they should).

---

## §4 Interactions / safety

- **No-clearnet guard (A1.2):** bridges are still Tor — encrypted +
  anonymized through arti, not raw TCP. They do **not** trip the
  `--no-tor`/`--listen-tcp`/`--hub-tcp` clearnet guard (that gate is about
  bypassing Tor entirely; a bridge *is* Tor). Confirm the guard logic
  doesn't false-positive on a configured bridge.
- **Default path untouched:** with no `--bridge`, `build_tor_config` is
  byte-identical to today. Bridges are strictly opt-in.
- **Build cost:** `bridge-client` is light; `pt-client` adds `tor-ptmgr` +
  deps. Gate `pt-client` behind a cargo feature if build time matters, or
  accept it.
- **Reproducible builds / supply chain:** the PT binary is third-party and
  out of our signed-release scope — document that the user verifies it
  (Tor Project's lyrebird/snowflake releases).

---

## §5 Honest limits (state loudly)

- **The PT binary is not bundled.** lyrebird/snowflake are separate Go
  binaries; cross-platform bundling + signing them is its own project. The
  user installs the PT (we document per-platform: `apt install
  obfs4proxy`/`lyrebird`, Tor Browser ships them, Termux pkg, etc.).
- **Bridge discovery is the user's problem.** Getting *working* bridge lines
  (BridgeDB at `bridges.torproject.org`, the Telegram/email distributors,
  or built-in defaults) is out of scope to automate; we document where.
- **A bridge you don't trust can still see you're using Tor** (it's your
  guard). Bridges defeat the *network between you and the bridge*, not the
  bridge itself.
- **Not anonymity, censorship-resistance.** Bridges/PT change *whether you
  can reach Tor and whether that's detectable*; the anonymity properties are
  the same as any Tor client once connected.

---

## §6 Recommendation & slices

1. **F2.2a — vanilla bridges (`bridge-client`).** ✅ **DONE.** Enabled the
   `bridge-client` feature; added `--bridge` (onyxd + onyx, repeatable; env
   `ONYX_BRIDGE`; also `bridges` in `config.json`); parse via
   `BridgeConfigBuilder` and wire `builder.bridges()` in `build_tor_config`
   (auto-enables bridge mode when the list is non-empty); threaded through
   `TorRuntime::bootstrap_with_bridges`. Opt-in — empty list = default guard
   selection, byte-identical to before; vanguards still pinned; a malformed
   bridge line is a hard error (no silent fallback to public guards). Tests:
   `tor_config_accepts_vanilla_bridge_and_keeps_vanguards`,
   `tor_config_rejects_garbage_bridge_line`. Ships the IP-blocklist-evasion
   tier.
2. **F2.2b — pluggable transports (`pt-client`).** ✅ **DONE.** Enabled
   `pt-client`. `onyx_core::tor::resolve_transports` reads the transport
   each bridge line names and finds its program (PATH, the usual package
   directories, Homebrew, Tor Browser on macOS); `--pt-binary` /
   `pt_binaries` override. One managed transport per program, launched
   on demand. A missing program is a startup error. The Network screen
   and `onyx network` show the transports in use, never addresses.
   Answers to §7: always on (adds one crate, `tor-ptmgr`); CLI + config
   only, no bridge manager screen yet; no built-in bridge list.
3. **Defer / document:** bundling a PT binary; automatic bridge fetching
   (moat/BridgeDB client) — both their own efforts.

### Honest framing
F2.2 doesn't change Onyx's anonymity once connected; it changes *whether a
censor can see or block your use of Tor*. Vanilla bridges (F2.2a) are a
small, self-contained win; obfs4/PT (F2.2b) is the strong answer but carries
an unavoidable external-binary dependency we can only document, not bundle.

---

## §7 Open questions for review

1. **Scope now:** F2.2a (vanilla bridges) alone first, or a+b together?
   (a is contained; b needs the external binary + docs.)
2. **`pt-client` build cost:** always-on, or behind an Onyx cargo feature so
   default builds stay lean?
3. **Config ergonomics:** CLI flags + config file only, or also a TUI
   bridge-manager screen (like the existing hub manager)?
4. **Built-in default bridges:** ship a small set of well-known obfs4
   bridges as a convenience (they get blocked over time), or strictly
   user-supplied?
