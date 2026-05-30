# A1.3 — Vanguards (guard-discovery defense) — implementation handoff

**Status: NOT STARTED. This note is the spec; a parallel agent is picking it up.**

## Why this matters (one paragraph)
Onyx's daemon publishes a v3 onion service (`crates/onyx-core/src/tor.rs:177`,
`launch_onion_service`) so peers can dial it for first contact / direct rooms.
A *hidden service* is the surface most exposed to **guard-discovery attacks**: a
moderately-resourced adversary (a few Tor relays + the ability to repeatedly
connect to the user's `.onion`) can force many circuit builds and statistically
enumerate the relay adjacent to the user's entry guard → identify the guard →
attack/coerce/watch that one relay → deanonymize the user's *location*. This is
**not** the out-of-scope global adversary (THREAT_MODEL N1); it's within the A6
"casual targeted attacker" band, so it's squarely in scope for a tool whose sole
purpose is untrackability. **Vanguards** is the defense: extra pinned, slow-
rotating guard layers (L2, and for the strongest tier L3) that make enumeration
take longer than the layers' rotation periods.

## Ground truth already verified (arti 0.42, read from the vendored crate source)
- `tor-guardmgr-0.42.0/src/vanguards/config.rs:67-70` — the default
  `VanguardParams` is: `vanguards_enabled = Lite` (general circuits → L2),
  `vanguards_hs_service = Full` (onion-service circuits → **L2 + L3**). So arti's
  *intended* default is already the strongest tier for exactly our HS surface.
- **BUT `vanguards` is a cargo feature**, not unconditional:
  - `arti-client-0.42.0/Cargo.toml:235` → `vanguards = ["tor-guardmgr/vanguards", "tor-circmgr/vanguards"]`
  - `tor-circmgr/Cargo.toml:115`, `tor-guardmgr/Cargo.toml:87` gate the code.
- **Onyx currently enables only** `onion-service-service` + `onion-service-client`
  (`Cargo.toml:52-54`). **It is UNKNOWN whether either of those transitively
  pulls in `vanguards`.** If not, the Full-HS default is *not compiled in* and our
  onion service is running with no L2/L3 protection. **Resolving this is task #1.**
- The effective mode can also be set by Tor **consensus net params**
  (`from_net_parameter`, config.rs:117). Verify whether a user config can *pin*
  Full so an anomalous/hostile consensus can't silently downgrade the HS below Full.

## The relevant code
- `crates/onyx-core/src/tor.rs::bootstrap_with` (lines ~97-121) builds the
  `TorClientConfig` (currently `TorClientConfig::default()` or a near-empty
  builder). This is where any explicit `VanguardConfig` would be set.
- `crates/onyx-core/src/tor.rs::publish_hidden_service` (line ~149) launches the HS.
- `Cargo.toml:52-54` — arti-client feature list.

## Task: implement, test, verify (in order)

### 1. VERIFY current state (do this FIRST, before changing anything)
- Run `cargo tree -e features -i tor-guardmgr` and/or
  `cargo tree -f "{p} {f}"` and grep for `tor-guardmgr` / `tor-circmgr` — confirm
  whether the `vanguards` feature is active in Onyx's actual build graph.
- Conclusion must be a hard yes/no: "vanguards IS / IS NOT compiled into onyxd today."

### 2. IMPLEMENT
- If `vanguards` is NOT already pulled in: add `"vanguards"` to the arti-client
  feature list in `Cargo.toml:52-54`. Re-run the feature check to confirm.
- Make the HS-circuit mode **explicit and pinned**, not merely inherited, so it's
  visible in code and not silently downgradable by consensus:
  - In `bootstrap_with`, build a `TorClientConfig` via its builder and set the
    vanguards config sub-builder to `vanguards_hs_service = Full`
    (and `vanguards_enabled = Lite` for general). Locate the exact accessor:
    `TorClientConfigBuilder` → vanguards sub-builder (`VanguardConfigBuilder` in
    `tor-guardmgr`). Follow arti's config-builder pattern already used for
    `storage().state_dir(...)`.
  - If arti only supports raising-via-consensus and not hard-pinning, document
    that limitation honestly rather than faking a guarantee.
- Keep it correct under the existing `bootstrap_with_state_dir` multi-daemon path.

### 3. TEST
- **Build-time guarantee:** a small compile/test assertion (or CI check) that
  fails loudly if the `vanguards` feature is ever dropped from arti-client —
  e.g. a `#[cfg(not(feature = ...))]` guard isn't possible across crates, so
  instead add a test that constructs the config and asserts the configured HS
  vanguard mode is `Full`. Pin it as a regression test.
- **Runtime observability:** on daemon start, log the *effective* vanguard mode
  for HS circuits at `info` (this is config, not identity — safe to log per D-3).
  Add a test that the config-build path yields `Full` for `vanguards_hs_service`.

### 4. VERIFY against real Tor (best-effort, document the method)
- Launch a daemon that publishes the HS; from arti's tracing at `debug`/`trace`
  for `tor_guardmgr`/`tor_circmgr`, confirm L2 (and L3, since Full) guard sets are
  selected and that HS circuits use the layered path. Capture a short transcript.
- Document in `ANONYMITY.md` §3 and `THREAT_MODEL.md`: guard-discovery is a
  defended (A6-band) attack via Full vanguards on the HS; note the residual
  (vanguards slows, does not eliminate, guard discovery).

## Definition of done
- A hard yes/no on whether vanguards was compiled before this change.
- `vanguards` feature confirmed active; HS circuits use `Full` (L2+L3), pinned in
  code, logged at startup, covered by a regression test.
- Real-Tor transcript showing layered guards on an HS circuit.
- `ANONYMITY.md` / `THREAT_MODEL.md` updated; `cargo test --workspace` green;
  clippy `-D warnings` clean.

## Honest framing to preserve (do not overclaim)
- Full vanguards **slows** guard discovery; it does not make it impossible.
- The strongest posture is **not publishing an HS at all** — a private-default
  daemon (`first_contact_reachable = false`, D-1) that never launches an onion
  service has a near-zero guard-discovery surface. Vanguards protects the users
  who *opt into* reachability and therefore run an HS.
- Do NOT touch guard config for outbound-only client circuits beyond Lite; more
  guards make discovery *easier*, not harder (see the comment at `tor.rs:144-146`).
