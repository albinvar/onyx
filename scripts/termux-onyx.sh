#!/data/data/com.termux/files/usr/bin/bash
# termux-onyx.sh — run Onyx on Android/Termux via proot-glibc (Phase 5 / F5.1).
#
# Bare Termux is bionic libc + has no glibc loader, so the released glibc
# `onyx` binary can't exec ("cannot execute: required file not found"). This
# sets up a small glibc Linux distro under proot-distro and installs Onyx
# *inside* it — where `install.sh` can cosign+SHA verify it the normal way
# (so the F0.2 fail-closed guarantees still hold).
#
# Usage (in Termux):
#   pkg install -y proot-distro curl
#   curl -fsSL https://raw.githubusercontent.com/albinvar/onyx/main/scripts/termux-onyx.sh | bash
#   proot-distro login onyx-ubuntu -- onyx --version
#
# Idempotent: re-running re-installs Onyx inside the existing distro.
set -euo pipefail

DISTRO_ALIAS="onyx-ubuntu"
BASE_DISTRO="ubuntu"

say()  { printf '\033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# 1. Sanity: must be Termux with proot-distro available.
command -v proot-distro >/dev/null 2>&1 \
  || die "proot-distro not found. In Termux run:  pkg install -y proot-distro curl"

# 2. Install the base distro once (idempotent — skip if the alias exists).
if proot-distro list 2>/dev/null | grep -q "^${DISTRO_ALIAS}\b" \
   || [ -d "${PREFIX:-/data/data/com.termux/files/usr}/var/lib/proot-distro/installed-rootfs/${DISTRO_ALIAS}" ]; then
  say "==> proot distro '${DISTRO_ALIAS}' already installed; reusing it."
else
  say "==> Installing the '${BASE_DISTRO}' glibc distro as '${DISTRO_ALIAS}' (~500 MB, one time)…"
  proot-distro install "${BASE_DISTRO}" --override-alias "${DISTRO_ALIAS}"
fi

# 3. Inside the distro: deps + the verified Onyx install.
#    install.sh fail-closes without cosign, so we install cosign there first.
say "==> Installing tools + Onyx inside '${DISTRO_ALIAS}' (verified via cosign + SHA256)…"
proot-distro login "${DISTRO_ALIAS}" -- bash -lc '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl ca-certificates >/dev/null
  # cosign: Sigstore ships a static linux/arm64 binary; fetch it so the
  # Onyx installer can verify signatures (F0.2 fail-closed).
  if ! command -v cosign >/dev/null 2>&1; then
    arch="$(dpkg --print-architecture)"   # arm64 on most phones
    case "$arch" in
      arm64) cosign_arch=arm64 ;;
      amd64) cosign_arch=amd64 ;;
      *) cosign_arch="$arch" ;;
    esac
    curl -fsSL -o /usr/local/bin/cosign \
      "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-${cosign_arch}"
    chmod +x /usr/local/bin/cosign
  fi
  # Now the normal verified installer (it cosign-verifies + SHA-checks).
  curl -fsSL https://raw.githubusercontent.com/albinvar/onyx/main/scripts/install.sh | bash
'

say ""
say "✓ Onyx installed inside the '${DISTRO_ALIAS}' distro."
say "  Run it with:"
say "    proot-distro login ${DISTRO_ALIAS} -- onyx --version"
say "    proot-distro login ${DISTRO_ALIAS} -- onyx        # the TUI"
say ""
warn "Tor bootstrap on mobile can be slow; keep Termux awake (termux-wake-lock)"
warn "for a long-running session. See MOBILE.md for the honest limits."
