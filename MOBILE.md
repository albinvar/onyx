# Running Onyx on Android (Termux) — Phase 5 / F5.1

**Status:** the works-today path (proot-glibc) is implemented + scripted
below; the "native binary" path is analysed as the follow-up (F5.2).

> **Verification (honest):** the helper (`scripts/termux-onyx.sh`) is
> syntax- + logic-validated and uses the standard Termux mechanism
> (`proot-distro` + a glibc distro + the normal verified `install.sh`
> inside it). It has **not yet been run end-to-end on a physical phone**
> this round — the test device was offline. Treat the steps below as
> "should work, pending a real-device confirmation"; if anything snags on
> your phone, that's the gap to close.

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
| **A. proot-glibc** (run the glibc binary inside a proot Linux distro) | **Yes** (scripted below) | ~500 MB distro download; small runtime overhead | No new build; reuses the *signed* release binary, verified *inside* the distro where cosign is installable |
| **B. static musl binary** (`aarch64-unknown-linux-musl`, fully static) | Needs a CI build target | one-time release-engineering | The *real* fix — a static musl binary runs on bare Termux with **no** proot. Risk: arti/ring/libcrux C deps must cross-compile for musl. **F5.2.** |
| **C. native Android (bionic, NDK)** | Needs NDK cross-build | higher | `aarch64-linux-android` via the NDK; more toolchain friction than musl for little extra benefit. Not recommended. |

### Recommended now: **A (proot-glibc)** — `scripts/termux-onyx.sh`
It reuses the **signed** release and verifies it the normal way (cosign +
SHA256) *inside* the proot distro (where `apt install cosign` works), so the
F0.2 fail-closed install guarantees still hold — unlike running `install.sh`
on bare Termux, where cosign isn't packaged and the binary couldn't exec
anyway.

```
# In Termux:
pkg install -y proot-distro curl
curl -fsSL https://raw.githubusercontent.com/albinvar/onyx/main/scripts/termux-onyx.sh | bash
# then:
proot-distro login onyx-ubuntu -- onyx --version
```

### The real fix (F5.2): static musl binary
Add `aarch64-unknown-linux-musl` to `release.yml` as a **fully static**
build (`RUSTFLAGS="-C target-feature=+crt-static"` with the musl target).
If arti + ring + libcrux cross-compile cleanly for musl (the open question —
ring's asm + libcrux's C need a musl C toolchain in CI), the resulting
binary runs directly on bare Termux with no proot, and slots into the same
cosign-signing + `SHA256SUMS` flow. Deferred because it needs a CI build
spike to confirm the C-dep cross-compile, and a failed target must not break
the existing 4-target release.

## Honest limits

- **proot adds overhead + a big first-time download** (a whole minimal
  distro). It's a compatibility shim, not a native port.
- **Tor on mobile**: arti bootstrap works under proot, but mobile networks +
  battery make it slower; background execution is subject to Android's
  process limits (keep Termux awake / use a wake-lock for a long-running
  daemon).
- **Not yet a real Android app.** This is "run the Linux build on your
  phone," not a packaged APK with a touch UI — that's a separate project.
