# Installing Onyx

There are three install paths, in increasing order of how much you trust me (the author) versus how much you want to verify yourself.

| Path | Effort | Trust model |
| --- | --- | --- |
| **One-liner installer** | 1 command | Trust the script + sigstore (script verifies binaries) |
| **Manual download + verify** | ~5 commands | Trust sigstore directly (you verify the binaries) |
| **Build from source** | clone + cargo build | Trust the source code you can read |

Whichever you pick, the install puts three things in scope:

- `onyx` — the user-facing binary. CLI + TUI in one process; `onyx` with no args boots the daemon + TUI together (T7.1).
- `onyxd` *(optional)* — headless daemon, for systemd / Docker / detached use.
- `onyx-hub` *(optional)* — the relay. Only install this if you want to run a hub for yourself or others.

## §0 Supported platforms

| OS | Arch | Status |
| --- | --- | --- |
| macOS | arm64 (Apple Silicon) | ✅ built + signed |
| macOS | x86_64 (Intel) | ✅ built + signed |
| Linux | x86_64 | ✅ built + signed |
| Linux | aarch64 | ✅ built + signed |
| Windows | x86_64 | ❌ not built yet — use WSL2 or build from source |
| FreeBSD / OpenBSD | * | ❌ build from source |

If your platform isn't here, the build-from-source path works on anything Rust supports.

## §1 The one-liner installer (recommended for most people)

```sh
curl -fsSL https://github.com/albinvar/onyx/releases/latest/download/install.sh | bash
```

What this does, step-by-step:

1. Detects your OS + CPU architecture from `uname`.
2. Asks GitHub for the latest tagged release (you can pin it with `ONYX_VERSION=v0.1.0 ...`).
3. Downloads the right `onyx-vX.Y.Z-<target>` binary + its `.cosign-bundle`.
4. Fetches `SHA256SUMS.txt` from the same release and verifies the binary hash matches.
5. Calls `cosign verify-blob` (if `cosign` is installed) to confirm the binary was built by THIS repo's release workflow.
6. On macOS, removes the `com.apple.quarantine` extended attribute so Gatekeeper doesn't block it.
7. Installs to `~/.local/bin/onyx` (`chmod 0755`).
8. Tells you if `~/.local/bin` needs adding to your `$PATH`.

### Customising the install

Environment variables (all optional):

```sh
# Pin a specific version (recommended for reproducibility):
ONYX_VERSION=v0.1.0 curl -fsSL .../install.sh | bash

# Install to a different directory:
ONYX_INSTALL_DIR=/usr/local/bin curl -fsSL .../install.sh | sudo -E bash

# Install all three binaries (default is just `onyx`):
ONYX_BINS="onyx onyxd onyx-hub" curl -fsSL .../install.sh | bash

# Skip sigstore (NOT recommended — but useful in air-gapped CI):
ONYX_NO_VERIFY=1 curl -fsSL .../install.sh | bash
```

### What the script protects you against — honestly

**Catches:**
- Transport corruption / partial downloads (SHA256 against the manifest).
- A backdoored binary in the GitHub release tab (sigstore signature won't verify because the attacker doesn't hold an OIDC token bound to this repo's `release.yml`).
- A fake binary on a doppelganger repo with a similar name (the `--certificate-identity-regexp` is pinned to `https://github.com/albinvar/onyx/`).

**Does NOT catch:**
- A backdoor committed to the source code before the tag was cut. Sigstore signs what CI built; it doesn't tell you the source is honest.
- A compromise of GitHub Actions, sigstore Fulcio, or the Rekor transparency log.
- A tampered `install.sh` if you fetch it from the mutable `raw.githubusercontent.com/.../main/` URL. **Always fetch from a release-tag URL** — `.../releases/latest/download/install.sh` redirects to an immutable tag URL.

For the strongest threat model: download → read the script → run it.

```sh
curl -fsSL https://github.com/albinvar/onyx/releases/latest/download/install.sh -o install.sh
less install.sh                  # read it
bash install.sh                  # run it
```

The script itself is signed too — verify it with cosign first if you want:

```sh
curl -fsSL https://github.com/albinvar/onyx/releases/latest/download/install.sh.cosign-bundle -o install.sh.cosign-bundle
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/albinvar/onyx/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --bundle install.sh.cosign-bundle \
  install.sh
```

## §2 Manual download + verify

If you want to do every step yourself:

```sh
# 1. Pick your target. For Apple Silicon:
TARGET=aarch64-apple-darwin
VERSION=v0.1.0

# 2. Download the binary, its sigstore bundle, and SHA256SUMS.
curl -LO https://github.com/albinvar/onyx/releases/download/${VERSION}/onyx-${VERSION}-${TARGET}
curl -LO https://github.com/albinvar/onyx/releases/download/${VERSION}/onyx-${VERSION}-${TARGET}.cosign-bundle
curl -LO https://github.com/albinvar/onyx/releases/download/${VERSION}/SHA256SUMS.txt
curl -LO https://github.com/albinvar/onyx/releases/download/${VERSION}/SHA256SUMS.txt.cosign-bundle

# 3. Verify the SHA256SUMS manifest itself is signed by THIS repo.
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/albinvar/onyx/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --bundle SHA256SUMS.txt.cosign-bundle \
  SHA256SUMS.txt

# 4. Confirm the binary hash matches the (signed) manifest.
sha256sum --ignore-missing -c SHA256SUMS.txt
# → onyx-v0.1.0-aarch64-apple-darwin: OK

# 5. (Optional, defence-in-depth) verify the binary's own sigstore bundle.
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/albinvar/onyx/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --bundle onyx-${VERSION}-${TARGET}.cosign-bundle \
  onyx-${VERSION}-${TARGET}

# 6. Drop the macOS quarantine xattr (macOS only).
xattr -d com.apple.quarantine onyx-${VERSION}-${TARGET} 2>/dev/null || true

# 7. Install.
chmod +x onyx-${VERSION}-${TARGET}
mv onyx-${VERSION}-${TARGET} /usr/local/bin/onyx
```

See `RELEASES.md` for the complete verification cookbook including what each cosign flag means.

## §3 Build from source

If you don't trust any prebuilt binary, build it yourself:

```sh
# 1. Install Rust toolchain (1.85+).
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# 2. Clone the repo at a tagged release (immutable).
git clone --branch v0.1.0 --depth 1 https://github.com/albinvar/onyx.git
cd onyx

# 3. Read the diff against the previous tag if you want.
git log --oneline v0.0.1..v0.1.0   # or browse on GitHub

# 4. Build the release binary. --locked = use the exact Cargo.lock
#    from the tag, no dependency updates.
cargo build --release --locked

# 5. Run the test suite as a sanity check (447 tests at v0.1.0).
cargo test --workspace

# 6. Install.
install -m 0755 target/release/onyx ~/.local/bin/
# Optionally:
install -m 0755 target/release/onyxd ~/.local/bin/
install -m 0755 target/release/onyx-hub ~/.local/bin/
```

Source-built binaries are NOT bit-for-bit identical to the released ones (your laptop has a different libc / glibc / TLS root store / etc.), but they're built from the same Cargo.lock, so functionally equivalent.

## §4 First run

```sh
$ onyx
```

That boots the embedded daemon, Tor (via Arti — no separate Tor install needed), and the TUI in one process. On first run it'll:

1. Create `~/.onyx/` and ask for a vault passphrase (used for Argon2id-derived AEAD; protects your identity keys at rest).
2. Open a Tor circuit (10–90 seconds depending on network).
3. Drop you into the TUI with an empty peer/room list.

From the TUI:

- `Ctrl-N` — create a room
- `Ctrl-I` — invite a peer to a room (paste their fingerprint + KEM pubkey + KeyPackage)
- `Ctrl-F` — send a file to the selected room
- `↑/↓` — switch conversations
- `PgUp/PgDn` — scroll messages
- `Enter` — send what's in the composer
- `Esc` — quit

To exchange first-contact info with a friend, use invite URLs:

```sh
onyx invite --with-kp --with-hubs > invite.txt    # share this out-of-band
# friend runs:
onyx accept "$(cat invite.txt)" --text "hi"
```

The hub address used is whatever's in `~/.onyx/config.toml` (or set via `--hub` on launch). **You need at least one hub for store-and-forward to work** — see `README.md` for the bootstrap recipe and `FEDERATION.md` for multi-hub setup.

## §5 Uninstall

```sh
rm ~/.local/bin/onyx
rm ~/.local/bin/onyxd      # if installed
rm ~/.local/bin/onyx-hub   # if installed
rm -rf ~/.onyx             # ☠ deletes vault, identity, scrollback, files
```

The vault is encrypted at rest, but if you have any reason to suspect device compromise, also wipe free disk space (`diskutil secureErase` on macOS, `shred` / `dd if=/dev/zero` on Linux) — `zeroize` scrubs RAM but can't reach what's already been swapped or written to disk pages.

## §6 Reporting install bugs

Please open a GitHub issue with:

- Your OS + `uname -a` output.
- The full command you ran.
- The full stderr (including `set -x` output if you have it: `bash -x install.sh`).
- The release tag you tried to install.

For security issues with the installer itself (e.g. you found a way to make it install a tampered binary), please follow `SECURITY.md`'s private-disclosure process instead.
