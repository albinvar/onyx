# Onyx

Anonymous, end-to-end-encrypted chat over Tor. Rust core, hybrid P2P + hub relay, MLS group encryption with a post-quantum hybrid bootstrap.

> **Status — pre-alpha.** The cryptographic library is essentially complete and the daemon now demonstrates a real two-party MLS-over-Noise-over-Tor round-trip. The CLI client, hub server, and browser UIs are scaffolds. **Do not use this for any communication you'd be unhappy to see published.** No external security audit has been performed.

## What's here

| Crate | Status |
|---|---|
| `onyx-core` | **complete** — 9 modules, ~110 tests, all crypto primitives wrapped, MLS over Noise XK working end-to-end in memory |
| `onyxd` | **walks** — vault unlock, Tor bootstrap, v3 hidden service publish, per-connection Noise XK + MLS bootstrap + first encrypted application-message exchange |
| `onyx` (CLI/TUI) | scaffold only |
| `onyx-hub` (relay) | scaffold only |

## Architecture, in one paragraph

Each user runs `onyxd`, a long-running daemon that owns their long-term identity keys (Ed25519 signing + X25519 identity + a future hybrid post-quantum KEM secret) inside an Argon2id-protected SQLite vault, and runs an embedded Tor client (Arti) that both **publishes a v3 hidden service** (their inbox) and **dials peers' onions** for outbound traffic. Connections are wrapped in `Noise_XK_25519_ChaChaPoly_BLAKE2s` for transport-layer mutual auth + AEAD. On top of that, [MLS (RFC 9420)](https://datatracker.ietf.org/doc/html/rfc9420) provides the actual end-to-end-encrypted group state — forward secrecy, post-compromise security, member add/remove. A separate `onyx-hub` will accept encrypted offline-message queues and host MLS rooms; it sees only ciphertext. First contact between two users uses a **post-quantum hybrid sealed-sender envelope** (X25519 ‖ ML-KEM-768) — see `DESIGN.md` §5.5.

## Build

You need Rust stable (we test on 1.95). The build is hefty because Arti pulls a large transitive dep set on first compile.

```sh
cargo build --workspace
```

To build only the daemon:

```sh
cargo build --bin onyxd
```

## Run the two-daemon smoke test

This demonstrates the entire stack: vault unlock → Tor bootstrap → hidden service publish → outbound dial → Noise XK handshake → MLS bootstrap (Welcome + first Application message in both directions).

### Terminal A — Alice (accept mode)

```sh
ONYX_PASSPHRASE='alice-pw' ./target/debug/onyxd --vault /tmp/alice.db
```

Wait for these two log lines (the Tor bootstrap takes ~30 s on a cold cache):

```
… vault unlocked, identity loaded fingerprint=… identity_pub_b32=ALICE_PUB
… hidden service published … onion=ALICE_ONION port=1
```

Copy `ALICE_ONION` and `ALICE_PUB` (these are the real values from Alice's log — *not* the literal placeholders above).

### Terminal B — Bob (dial mode)

```sh
ONYX_PASSPHRASE='bob-pw' ./target/debug/onyxd \
  --vault /tmp/bob.db \
  --dial-onion ALICE_ONION:1 \
  --dial-pubkey ALICE_PUB
```

(Substitute the actual `ALICE_ONION` and `ALICE_PUB` values into the command — without angle brackets, which zsh would try to parse as redirection.)

After Bob bootstraps Tor and dials, both daemons should log:

- **Bob (initiator):**
  ```
  Tor circuit established; starting Noise XK handshake (initiator)
  Noise XK complete; starting MLS bootstrap (initiator) peer_identity_pub_b32=…
  MLS round-trip complete (initiator); exiting peer_reply="MLS reply from … (responder)" mls_epoch=1
  ```
- **Alice (responder):**
  ```
  accepted inbound stream; starting Noise XK handshake (responder)
  Noise XK complete; starting MLS bootstrap (responder) peer_identity_pub_b32=…
  MLS round-trip complete (responder); closing stream peer_message="MLS hello from … (initiator)" mls_epoch=1
  ```

If you see matching `peer_identity_pub_b32` values on both sides and matching plaintext payloads, every layer in the stack just worked end to end: Tor (rendezvous + circuit), Noise XK (mutual X25519 auth + AEAD), MLS (KeyPackage → Welcome → joined group at epoch 1 → encrypted Application messages).

### Known gotchas

- **Both daemons share `~/Library/Application Support/arti/` by default** — Bob's daemon will start in read-only mode and reuse Alice's cached Tor consensus. Fine for the smoke test. A per-daemon `--tor-state-dir` flag is a planned follow-up.
- **Hidden service descriptor takes ~30-60 s to propagate** after Alice publishes. If Bob's dial fails with `dial failed`, give Alice a bit longer between her "hidden service published" log and Bob's launch.
- **`zsh: parse error near '\n'`** when copy-pasting the Bob command: that means the multi-line backslash continuation got mangled. Either run it all on one line, or copy each line individually.

### Cleanup

```sh
rm -f /tmp/alice.db /tmp/bob.db
# If you want a truly cold Tor cache for the next run:
rm -rf ~/Library/Application\ Support/arti
```

## Documentation

- **`DESIGN.md`** — full protocol specification (currently v0.2-draft). Threat model summary, architecture diagram, wire formats, identity model, routing IDs, MLS integration, post-quantum hybrid construction, deliberate v1 exclusions.
- **`THREAT_MODEL.md`** — standalone artifact: adversaries we defend against (A1–A6), adversaries we don't (N1–N7), trust assumptions, residual linkability table, non-deniability note.
- **`CHANGELOG.md`** — append-only development log; one entry per substantive session. The closest thing to a "how did we get here" walkthrough.
- Module-level doc comments inside `crates/onyx-core/src/*.rs` describe each subsystem in detail.

## Contributing / running the CI gate locally

The same gate CI runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

`cargo deny check` requires `cargo install cargo-deny --locked` first.

## License

[AGPL-3.0-or-later](./LICENSE). Onyx is a network-deployed service; hub operators forking the code and running it for the public must publish source.
