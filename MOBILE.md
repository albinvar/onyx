# Running Onyx on Android (Termux) — Phase 5 (F5.1 + F5.2)

**Status:** there are now **two** paths. The native static-musl binary
(F5.2) runs on **bare Termux with no proot** and is the recommended path;
the proot-glibc helper (F5.1) remains as a fallback.

> **Verification (honest):** the static `aarch64-unknown-linux-musl`
> binaries (onyx/onyxd/onyx-hub) are **confirmed to build and to be fully
> static** (`ELF … statically linked`, no INTERP) in CI — that was F5.2's
> open question and it's answered. What is **not yet confirmed on a
> physical phone** (the test device was offline this round): that the
> static binary *runs* under Termux/bionic end-to-end, and that
> `install.sh`'s new Termux branch picks it + verifies it on-device. Treat
> the steps below as "builds + should run, pending a real-device
> confirmation."

## The problem (why the normal binary won't run)

Onyx's released Linux binaries are **glibc** (`*-unknown-linux-gnu`). Bare
**Termux** is an Android app: its libc is Android's **bionic**, and it does
**not** ship glibc's dynamic loader (`/lib/ld-linux-aarch64.so.1`). So the
glibc `onyx` binary fails to exec with the classic, confusing:

```
cannot execute: required file not found
```

This is *not* an Onyx bug — it's the glibc-vs-bionic mismatch every glibc
binary hits on bare Termux.

## Three ways to fix it

| Approach | Works today? | Cost | Notes |
|----------|--------------|------|-------|
| **B. static musl binary** (`aarch64-unknown-linux-musl`, fully static) | **Yes** (shipped F5.2) | none for the user | The real fix — runs on **bare Termux, no proot**. Same cosign-signing + `SHA256SUMS` flow as every other target. `install.sh` auto-selects it on Termux. |
| **A. proot-glibc** (run the glibc binary inside a proot Linux distro) | **Yes** (fallback) | ~500 MB distro download; runtime overhead | No new build; reuses the *signed* glibc release binary, verified *inside* the distro. Use if the static binary ever misbehaves on your device. |
| **C. native Android (bionic, NDK)** | Needs NDK cross-build | higher | `aarch64-linux-android` via the NDK; more toolchain friction than musl for little extra benefit. Not pursued. |

### Recommended: **B (static musl)** — just run `install.sh`
The static `aarch64-unknown-linux-musl` binary needs no proot and no glibc.
`install.sh` detects Termux (via `$TERMUX_VERSION` / a `com.termux` `$PREFIX`)
and downloads that target instead of the glibc one. cosign verification still
applies — cosign's `linux/arm64` release is itself a static Go binary, so it
runs on bare Termux; put it on your PATH first (the installer prints this hint
if it's missing).

```
# In Termux:
pkg install -y curl
# install cosign (static Go binary — runs on bionic):
curl -fsSL -o "$PREFIX/bin/cosign" \
  https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-arm64
chmod +x "$PREFIX/bin/cosign"
# verified install (auto-picks the musl target on Termux):
curl -fsSL https://github.com/albinvar/onyx/releases/latest/download/install.sh | bash
onyx --version
```

How F5.2 was made to work: the only thing that blocked a static musl build
was `openssl-sys` (pulled in by arti's default `native-tls` backend) — its C
library doesn't cross-compile for musl without a target OpenSSL install. The
crypto stack (libcrux/ring) and bundled-sqlite cross-compile fine. Switching
arti to its pure-Rust **rustls** backend (`default-features = false` +
`rustls`, with the `ring` CryptoProvider pinned tree-wide) removed OpenSSL
for *every* target, after which `aarch64-unknown-linux-musl` builds fully
static (`-C target-feature=+crt-static`) and signs through the normal flow.
It's now the 5th target in `release.yml` (cross-compiled via
`taiki-e/setup-cross-toolchain-action`; `fail-fast: false` keeps it from ever
blocking the four native targets).

### Fallback: **A (proot-glibc)** — `scripts/termux-onyx.sh`
If the static binary misbehaves on your device, the proot path reuses the
**signed** glibc release, verified the normal way (cosign + SHA256) *inside* a
proot distro:

```
# In Termux:
pkg install -y proot-distro curl
curl -fsSL https://raw.githubusercontent.com/albinvar/onyx/main/scripts/termux-onyx.sh | bash
proot-distro login onyx-ubuntu -- onyx --version
```

## Honest limits

- **proot adds overhead + a big first-time download** (a whole minimal
  distro). It's a compatibility shim, not a native port.
- **Tor on mobile**: arti bootstrap works under proot, but mobile networks +
  battery make it slower; background execution is subject to Android's
  process limits (keep Termux awake / use a wake-lock for a long-running
  daemon).
- **Not yet a real Android app.** This is "run the Linux build on your
  phone," not a packaged APK with a touch UI — that's a separate project.
