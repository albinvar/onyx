#!/usr/bin/env bash
# Onyx — one-shot installer.
#
# Usage (the boring user path):
#   curl -fsSL https://raw.githubusercontent.com/albinvar/onyx/main/scripts/install.sh | bash
#
# Or, pinned to a release (RECOMMENDED — the raw.githubusercontent path
# is mutable, whatever is on `main` today is what runs; a release tag is
# immutable):
#   curl -fsSL https://github.com/albinvar/onyx/releases/download/v0.1.0/install.sh | bash
#
# Or download + read first (RECOMMENDED for the security-aware):
#   curl -fsSL https://github.com/albinvar/onyx/releases/download/v0.1.0/install.sh -o install.sh
#   less install.sh                 # read it
#   bash install.sh                 # run it
#
# Environment knobs (all optional):
#   ONYX_VERSION       — pin to a specific tag (default: latest GitHub release)
#   ONYX_INSTALL_DIR   — where to put the binaries (default: ~/.local/bin)
#   ONYX_REPO          — override github repo slug (default: albinvar/onyx)
#   ONYX_BINS          — which binaries to install (default: "onyx")
#                        Set to "onyx onyxd onyx-hub" to grab them all.
#   ONYX_NO_VERIFY     — set to 1 to skip cosign verification (NOT RECOMMENDED).
#                        SHA256 of the binary against SHA256SUMS still happens.
#   ONYX_SKIP_PATH_HINT — set to 1 to suppress the "add to PATH" message
#
# Threat model:
#
#   Catches:
#     - Transport corruption / partial download (SHA256 check vs the manifest).
#     - Tampered binary in the GitHub release tab (cosign signature won't verify
#       because the attacker doesn't have an OIDC token bound to this repo's
#       release.yml).
#     - Attacker who serves a fake `install.sh` (you should fetch this from a
#       release-tag URL, not raw.githubusercontent.com — release tags are
#       immutable, raw URLs follow whatever's on main).
#
#   Does NOT catch:
#     - Backdoor committed to the source code before the tag was cut. Sigstore
#       signs what CI built; it doesn't tell you the source is honest.
#     - GitHub Actions / sigstore infra compromise.
#     - You running this script as root for no reason. We don't ask for root
#       and we install to your home directory by default.
#
# See RELEASES.md and INSTALL.md for the full story.

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────

ONYX_REPO="${ONYX_REPO:-albinvar/onyx}"
ONYX_VERSION="${ONYX_VERSION:-}"
ONYX_INSTALL_DIR="${ONYX_INSTALL_DIR:-$HOME/.local/bin}"
ONYX_BINS="${ONYX_BINS:-onyx}"
ONYX_NO_VERIFY="${ONYX_NO_VERIFY:-0}"
ONYX_SKIP_PATH_HINT="${ONYX_SKIP_PATH_HINT:-0}"

# Tput colors — degrade gracefully when stdout isn't a tty.
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
  C_BOLD="$(tput bold)"
  C_DIM="$(tput dim)"
  C_RED="$(tput setaf 1)"
  C_GREEN="$(tput setaf 2)"
  C_YELLOW="$(tput setaf 3)"
  C_BLUE="$(tput setaf 4)"
  C_RESET="$(tput sgr0)"
else
  C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_RESET=""
fi

say()  { printf "%s\n" "${C_BOLD}${*}${C_RESET}"; }
info() { printf "  %s\n" "$*"; }
warn() { printf "%s\n" "${C_YELLOW}⚠ $*${C_RESET}" >&2; }
err()  { printf "%s\n" "${C_RED}✗ $*${C_RESET}" >&2; }
ok()   { printf "%s\n" "${C_GREEN}✓ $*${C_RESET}"; }

die() {
  err "$*"
  exit 1
}

# ── Pre-flight ────────────────────────────────────────────────────────

require() {
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      die "required command not found: $cmd (please install it and re-run)"
    fi
  done
}

# `curl` does most of the work; `tar` is unused today (binaries ship raw,
# not as archives) but reserved for the day we tarball them; `shasum` /
# `sha256sum` for SHA verification.
require curl

if command -v sha256sum >/dev/null 2>&1; then
  SHA256_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA256_CMD="shasum -a 256"
else
  die "need sha256sum (Linux) or shasum (macOS) for verification"
fi

# ── Platform detection ────────────────────────────────────────────────

detect_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Darwin)
      case "$arch" in
        arm64)   echo "aarch64-apple-darwin" ;;
        x86_64)  echo "x86_64-apple-darwin" ;;
        *)       die "unsupported macOS architecture: $arch" ;;
      esac
      ;;
    Linux)
      case "$arch" in
        x86_64|amd64)   echo "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64)  echo "aarch64-unknown-linux-gnu" ;;
        *)              die "unsupported Linux architecture: $arch" ;;
      esac
      ;;
    MINGW*|MSYS*|CYGWIN*)
      die "Windows install is not yet supported. Use WSL2 with the Linux installer, or build from source."
      ;;
    *)
      die "unsupported OS: $os (supported: Darwin, Linux)"
      ;;
  esac
}

# ── Version resolution ────────────────────────────────────────────────

resolve_version() {
  if [ -n "$ONYX_VERSION" ]; then
    # Allow either "v0.1.0" or "0.1.0".
    case "$ONYX_VERSION" in
      v*) echo "$ONYX_VERSION" ;;
      *)  echo "v$ONYX_VERSION" ;;
    esac
    return
  fi
  local tag
  # GitHub redirects the /releases/latest browser URL to /releases/tag/<tag>;
  # follow the redirect and pluck the tag from the final URL, since this
  # avoids needing jq.
  tag="$(curl -fsSL -o /dev/null -w '%{url_effective}' \
        "https://github.com/${ONYX_REPO}/releases/latest" 2>/dev/null \
        | sed -E 's|.*/tag/(.+)$|\1|')"
  if [ -z "$tag" ] || [ "$tag" = "latest" ]; then
    die "could not resolve latest release for ${ONYX_REPO} — has v0.1.0+ been tagged? Pin a version: ONYX_VERSION=v0.1.0 $0"
  fi
  echo "$tag"
}

# ── Download + verify a single binary ─────────────────────────────────

# verify_sigstore <binary-path> <bundle-path> <repo>
verify_sigstore() {
  local bin="$1" bundle="$2" repo="$3"
  if [ "$ONYX_NO_VERIFY" = "1" ]; then
    warn "skipping sigstore verification (ONYX_NO_VERIFY=1) — you are on your own"
    return 0
  fi
  if ! command -v cosign >/dev/null 2>&1; then
    warn "cosign not installed — sigstore signature NOT checked."
    warn "this means: SHA256 catches transport corruption, but an attacker"
    warn "who tampered with the binary in the GitHub release tab will not"
    warn "be detected. install cosign and re-run for full verification:"
    warn "  macOS:   brew install cosign"
    warn "  Linux:   https://docs.sigstore.dev/cosign/installation/"
    return 0
  fi
  info "verifying sigstore signature with cosign..."
  if cosign verify-blob \
       --certificate-identity-regexp "https://github.com/${repo}/" \
       --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
       --bundle "$bundle" \
       "$bin" >/dev/null 2>&1; then
    ok "sigstore signature verifies"
  else
    die "sigstore signature FAILED to verify. do NOT run this binary. report at https://github.com/${repo}/issues"
  fi
}

# fetch_and_install <binary-name> <version> <target> <tmpdir>
fetch_and_install() {
  local bin_name="$1" version="$2" target="$3" tmpdir="$4"
  local asset="${bin_name}-${version}-${target}"
  local url="https://github.com/${ONYX_REPO}/releases/download/${version}/${asset}"
  local bundle_url="${url}.cosign-bundle"

  info "fetching ${bin_name} from ${version}/${target}..."
  curl -fSL --progress-bar "$url" -o "${tmpdir}/${asset}" \
    || die "download failed: ${url}"
  curl -fsSL "$bundle_url" -o "${tmpdir}/${asset}.cosign-bundle" \
    || warn "no .cosign-bundle for ${asset} (was the release signed?)"

  # SHA verification against the combined SHA256SUMS manifest.
  # The release workflow uploads a single SHA256SUMS.txt covering every
  # binary in the release, so we fetch it once and check our line.
  if [ ! -f "${tmpdir}/SHA256SUMS.txt" ]; then
    curl -fsSL "https://github.com/${ONYX_REPO}/releases/download/${version}/SHA256SUMS.txt" \
         -o "${tmpdir}/SHA256SUMS.txt" 2>/dev/null \
      || warn "no SHA256SUMS.txt at the release — skipping hash verification"
  fi
  if [ -f "${tmpdir}/SHA256SUMS.txt" ]; then
    local expected actual
    expected="$(grep " ${asset}\$" "${tmpdir}/SHA256SUMS.txt" \
                | awk '{print $1}' || true)"
    if [ -z "$expected" ]; then
      warn "no hash for ${asset} in SHA256SUMS.txt — skipping hash check"
    else
      actual="$(cd "$tmpdir" && $SHA256_CMD "$asset" | awk '{print $1}')"
      if [ "$expected" = "$actual" ]; then
        ok "sha256 matches manifest"
      else
        die "sha256 MISMATCH for ${asset}. expected=${expected} actual=${actual}"
      fi
    fi
  fi

  # Sigstore verification.
  if [ -f "${tmpdir}/${asset}.cosign-bundle" ]; then
    verify_sigstore "${tmpdir}/${asset}" "${tmpdir}/${asset}.cosign-bundle" "$ONYX_REPO"
  fi

  # macOS quarantine xattr — applied by curl when downloading. Strip
  # it so the user doesn't see Gatekeeper's "cannot be opened" dialog.
  # (We're an unsigned binary today; without removing the xattr the
  # user has to right-click → Open or run xattr themselves. We'll add
  # proper Apple Developer ID notarization in a future release.)
  if [ "$(uname -s)" = "Darwin" ] && command -v xattr >/dev/null 2>&1; then
    xattr -d com.apple.quarantine "${tmpdir}/${asset}" 2>/dev/null || true
  fi

  # Install.
  chmod +x "${tmpdir}/${asset}"
  install -d "$ONYX_INSTALL_DIR"
  install -m 0755 "${tmpdir}/${asset}" "${ONYX_INSTALL_DIR}/${bin_name}"
  ok "installed ${bin_name} → ${ONYX_INSTALL_DIR}/${bin_name}"
}

# ── PATH hint ─────────────────────────────────────────────────────────

print_path_hint() {
  if [ "$ONYX_SKIP_PATH_HINT" = "1" ]; then
    return 0
  fi
  case ":$PATH:" in
    *":$ONYX_INSTALL_DIR:"*)
      return 0
      ;;
  esac
  printf "\n"
  warn "${ONYX_INSTALL_DIR} is not in your PATH."
  printf "  Add it by appending this line to your shell rc file:\n\n"
  printf "    %sexport PATH=\"%s:\$PATH\"%s\n\n" "$C_BLUE" "$ONYX_INSTALL_DIR" "$C_RESET"
  printf "  Then either reopen your terminal or run: %ssource ~/.zshrc%s (or ~/.bashrc).\n" \
         "$C_DIM" "$C_RESET"
}

# ── Main ──────────────────────────────────────────────────────────────

main() {
  printf "\n"
  say "Onyx installer"
  printf "  %srepository:%s   https://github.com/%s\n" "$C_DIM" "$C_RESET" "$ONYX_REPO"

  local target version tmpdir
  target="$(detect_target)"
  printf "  %starget:%s       %s\n" "$C_DIM" "$C_RESET" "$target"

  version="$(resolve_version)"
  printf "  %sversion:%s      %s\n" "$C_DIM" "$C_RESET" "$version"
  printf "  %sinstall dir:%s  %s\n" "$C_DIM" "$C_RESET" "$ONYX_INSTALL_DIR"
  printf "  %sbinaries:%s     %s\n" "$C_DIM" "$C_RESET" "$ONYX_BINS"
  printf "\n"

  tmpdir="$(mktemp -d -t onyx-install.XXXXXX)"
  trap 'rm -rf "$tmpdir"' EXIT

  # Install each requested binary.
  for bin in $ONYX_BINS; do
    case "$bin" in
      onyx|onyxd|onyx-hub) ;;
      *) die "unknown binary: $bin (valid: onyx, onyxd, onyx-hub)" ;;
    esac
    fetch_and_install "$bin" "$version" "$target" "$tmpdir"
  done

  printf "\n"
  ok "Onyx ${version} installed."
  print_path_hint

  printf "\n"
  say "Next steps"
  info "  run ${C_BLUE}onyx${C_RESET} — boots daemon + TUI in one process."
  info "  read ${C_BLUE}https://github.com/${ONYX_REPO}/blob/main/README.md${C_RESET} for hub setup."
  info "  verify a friend's fingerprint out-of-band before chatting (Signal-style)."
  printf "\n"
}

main "$@"
