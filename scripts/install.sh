#!/usr/bin/env bash
# Onyx — one-shot installer.
#
# Usage (the boring user path):
#   curl -fsSL https://raw.githubusercontent.com/albinvar/onyx/main/scripts/install.sh | bash
#
# Or, pinned to a release (better — the raw.githubusercontent path follows
# whatever is on `main` today; a release asset changes only if someone with
# write access to the release replaces it):
#   curl -fsSL https://github.com/albinvar/onyx/releases/download/v0.1.0/install.sh | bash
#
# Or download, VERIFY, then run (RECOMMENDED). Piping this script straight
# into a shell trusts whatever the release page serves; the script's own
# signature is the only thing that authenticates it, and nothing checks
# that for you when you pipe:
#   base=https://github.com/albinvar/onyx/releases/download/v0.1.0
#   curl -fsSLO "$base/install.sh" -O "$base/install.sh.cosign-bundle"
#   cosign verify-blob \
#     --certificate-identity 'https://github.com/albinvar/onyx/.github/workflows/release.yml@refs/tags/v0.1.0' \
#     --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
#     --bundle install.sh.cosign-bundle install.sh
#   bash install.sh
#
# Environment knobs (all optional):
#   ONYX_VERSION       — pin to a specific tag (default: latest GitHub release)
#   ONYX_ALLOW_DOWNGRADE — set to 1 to install a version older than the
#                        one already installed (refused by default).
#   ONYX_INSTALL_DIR   — where to put the binaries (default: ~/.local/bin)
#   ONYX_REPO          — override github repo slug (default: albinvar/onyx)
#   ONYX_BINS          — which binaries to install (default: "onyx")
#                        Set to "onyx onyxd onyx-hub" to grab them all.
#   ONYX_NO_VERIFY     — set to 1 to skip cosign verification (NOT RECOMMENDED).
#                        SHA256 of the binary against SHA256SUMS still happens.
#                        WITHOUT this, the install ABORTS if cosign is missing
#                        or a signature bundle is absent — it is fail-closed
#                        (per SECURITY.md P6: no "less secure but easier" path).
#   ONYX_SKIP_PATH_HINT — set to 1 to suppress the "add to PATH" message
#
# Threat model:
#
#   Catches:
#     - Transport corruption / partial download (SHA256 check vs the manifest).
#     - Tampered binary in the GitHub release tab (cosign signature won't verify
#       because the attacker doesn't have an OIDC token bound to this repo's
#       release.yml).
#     - A release asset swapped for one from a DIFFERENT release or a
#       different binary: the signing identity is pinned to this exact tag
#       and the signed manifest binds each asset name to its hash.
#
#   Does NOT catch:
#     - A fake copy of THIS SCRIPT. If you pipe it into a shell unverified,
#       an attacker who can replace release assets controls everything it
#       does. Verify install.sh with cosign first (see the top of this file).
#     - Backdoor committed to the source code before the tag was cut. Sigstore
#       signs what CI built; it doesn't tell you the source is honest.
#     - GitHub Actions / sigstore infra compromise.
#     - You running this script as root for no reason. We don't ask for root
#       and we install to your home directory by default.
#
# See RELEASES.md and INSTALL.md for the full story.

# POSIX sh compatible: `pipefail` is a bash-ism that dash/ash (Debian's
# `sh`, BusyBox) reject with "Illegal option -o pipefail", which broke
# `curl … | sh`. We don't rely on pipefail anyway — every curl in a
# pipe is buffered + exit-checked explicitly (see resolve_version). Keep
# errexit + nounset, which are POSIX.
set -eu

# ── Config ────────────────────────────────────────────────────────────

ONYX_REPO="${ONYX_REPO:-albinvar/onyx}"
ONYX_VERSION="${ONYX_VERSION:-}"
ONYX_INSTALL_DIR="${ONYX_INSTALL_DIR:-$HOME/.local/bin}"
ONYX_BINS="${ONYX_BINS:-onyx}"
ONYX_NO_VERIFY="${ONYX_NO_VERIFY:-0}"
ONYX_SKIP_PATH_HINT="${ONYX_SKIP_PATH_HINT:-0}"

# Scratch dir for downloads. Declared at global scope (not `local` in
# main) so the EXIT trap can still see it — a `local` would be out of
# scope when the trap fires, tripping `set -u` ("tmpdir: unbound") and
# leaking the temp dir.
tmpdir=""
cleanup() { [ -n "${tmpdir:-}" ] && rm -rf "${tmpdir}"; }
trap cleanup EXIT

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
      # Termux (Android) uses bionic libc and ships no glibc loader, so the
      # glibc `*-linux-gnu` binary can't exec there ("cannot execute:
      # required file not found"). On Termux/aarch64 select the fully-static
      # musl build (F5.2), which runs on bare Termux with no proot. Detect
      # Termux via its env: $TERMUX_VERSION, or a $PREFIX under com.termux.
      if [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ]; then
        if [ -n "${TERMUX_VERSION:-}" ] || case "${PREFIX:-}" in *com.termux*) true ;; *) false ;; esac; then
          echo "aarch64-unknown-linux-musl"
          return 0
        fi
      fi
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
  # Resolve the latest release tag from the GitHub API's
  # `releases/latest` endpoint, which returns the most recent
  # published (non-prerelease, non-draft) release. We parse
  # `"tag_name": "vX.Y.Z"` with sed (no jq dependency).
  #
  # An earlier version parsed the `/releases/latest` *browser*
  # redirect for `/tag/<v>`, but GitHub doesn't always redirect there
  # (it fell back to the releases-list page, yielding a garbage
  # "version" = the whole URL and a broken download path). The API's
  # tag_name is the reliable source.
  #
  # **macOS shell footgun (don't undo this).** We deliberately buffer
  # the curl response into a variable before parsing, instead of
  # piping curl directly into a tag-extraction filter. The previous
  # `curl | grep -m1 | sed` form silently fails under `set -e -o
  # pipefail` on BSD shells: `grep -m1`'s early exit closes the pipe,
  # curl gets SIGPIPE → non-zero pipeline exit → assignment "fails"
  # under set -e → the function returns mid-way *with `tag` already
  # set* and the caller sees an empty `version`. Buffering breaks
  # the pipeline so SIGPIPE cannot propagate.
  local resp tag
  resp="$(curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
          "https://api.github.com/repos/${ONYX_REPO}/releases/latest" 2>/dev/null \
          || printf '')"
  tag="$(printf '%s' "$resp" \
        | sed -nE 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' \
        | sed -n '1p')"
  # Sanity-check the shape: a real tag starts with a digit or `v`.
  # Anything else (empty, an HTML error body, a stray URL) is a
  # resolution failure, not a usable version.
  if ! is_release_tag "$tag"; then
    die "could not resolve latest release for ${ONYX_REPO} — has a non-prerelease vX.Y.Z been published? Pin a version: ONYX_VERSION=v0.1.0 $0"
  fi
  echo "$tag"
}

# ── Download + verify a single binary ─────────────────────────────────

# is_release_tag <tag> — a strict vX.Y.Z[-prerelease] shape. The tag is
# interpolated into URLs, local paths and the expected signing identity,
# so anything looser (path separators, whitespace, shell or regex
# metacharacters) is refused.
is_release_tag() {
  printf '%s' "$1" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$'
}

# fetch <url> <dest> — HTTPS only, including across redirects.
fetch() {
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL "$1" -o "$2"
}

# verify_sigstore <file-path> <bundle-path> <repo> <version>
#
# Verifies that <file> was signed by THIS repo's release workflow running
# on THIS tag. The identity is matched exactly:
#
#   https://github.com/<repo>/.github/workflows/release.yml@refs/tags/<version>
#
# A prefix match on the repo (the previous behaviour) accepted any workflow
# on any branch of the repo, and — because a signature covers only the
# bytes — let a genuine artifact from an OLD release be re-uploaded under a
# new release's name and still verify. Pinning the tag closes both: a
# signature made for v0.1.5 does not verify for v0.1.31.
verify_sigstore() {
  local bin="$1" bundle="$2" repo="$3" version="$4"
  if [ "$ONYX_NO_VERIFY" = "1" ]; then
    warn "skipping sigstore verification (ONYX_NO_VERIFY=1) — you are on your own"
    return 0
  fi
  if ! command -v cosign >/dev/null 2>&1; then
    err "cosign not installed — cannot verify the sigstore signature."
    err "SHA256 alone is NOT protection here: the binary and SHA256SUMS.txt"
    err "come from the same GitHub release, so an attacker who tampers with"
    err "one tampers with both. refusing to install an unverified binary."
    err "either install cosign and re-run (RECOMMENDED):"
    err "  macOS:        brew install cosign"
    err "  Linux:        https://docs.sigstore.dev/cosign/installation/"
    err "  Termux/arm64: download the linux/arm64 cosign binary from"
    err "                https://github.com/sigstore/cosign/releases (it is a"
    err "                static Go binary) and put it on your PATH"
    err "or accept the risk explicitly by re-running with ONYX_NO_VERIFY=1."
    die "aborting: no cosign and no ONYX_NO_VERIFY override"
  fi
  local identity="https://github.com/${repo}/.github/workflows/release.yml@refs/tags/${version}"
  info "verifying sigstore signature with cosign..."
  if cosign verify-blob \
       --certificate-identity "$identity" \
       --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
       --bundle "$bundle" \
       "$bin" >/dev/null 2>&1; then
    ok "sigstore signature verifies (release.yml @ ${version})"
  else
    die "sigstore signature FAILED to verify for ${version}. do NOT run this file. report at https://github.com/${repo}/issues"
  fi
}

# fetch_manifest <version> <tmpdir>
#
# Downloads SHA256SUMS.txt and verifies ITS signature. The manifest is what
# binds an artifact's NAME (binary, version, target) to its hash, so it is
# mandatory: without it a correctly-signed `onyx-hub` could be served as
# `onyx`. Only skippable with the explicit ONYX_NO_VERIFY=1 override.
fetch_manifest() {
  local version="$1" tmpdir="$2"
  local base="https://github.com/${ONYX_REPO}/releases/download/${version}"
  [ -f "${tmpdir}/SHA256SUMS.txt" ] && return 0
  if [ "$ONYX_NO_VERIFY" = "1" ]; then
    fetch "${base}/SHA256SUMS.txt" "${tmpdir}/SHA256SUMS.txt" 2>/dev/null \
      || warn "no SHA256SUMS.txt at the release (ONYX_NO_VERIFY=1 — continuing unverified)"
    return 0
  fi
  fetch "${base}/SHA256SUMS.txt" "${tmpdir}/SHA256SUMS.txt" \
    || die "release ${version} has no SHA256SUMS.txt — refusing to install without the signed manifest."
  fetch "${base}/SHA256SUMS.txt.cosign-bundle" "${tmpdir}/SHA256SUMS.txt.cosign-bundle" \
    || die "release ${version} has no signature for SHA256SUMS.txt — refusing to install."
  verify_sigstore "${tmpdir}/SHA256SUMS.txt" "${tmpdir}/SHA256SUMS.txt.cosign-bundle" \
    "$ONYX_REPO" "$version"
}

# fetch_and_install <binary-name> <version> <target> <tmpdir>
fetch_and_install() {
  local bin_name="$1" version="$2" target="$3" tmpdir="$4"
  local asset="${bin_name}-${version}-${target}"
  local url="https://github.com/${ONYX_REPO}/releases/download/${version}/${asset}"
  local bundle_url="${url}.cosign-bundle"

  info "fetching ${bin_name} from ${version}/${target}..."
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fSL --progress-bar "$url" \
       -o "${tmpdir}/${asset}" \
    || die "download failed: ${url}"
  fetch "$bundle_url" "${tmpdir}/${asset}.cosign-bundle" 2>/dev/null \
    || warn "no .cosign-bundle for ${asset} (was the release signed?)"

  # 1. The signed manifest binds this exact asset name to a hash. A missing
  #    manifest or a missing line is fatal (it used to be a warning).
  fetch_manifest "$version" "$tmpdir"
  if [ -f "${tmpdir}/SHA256SUMS.txt" ]; then
    local expected actual
    expected="$(grep " ${asset}\$" "${tmpdir}/SHA256SUMS.txt" \
                | awk '{print $1}' || true)"
    if [ -z "$expected" ]; then
      if [ "$ONYX_NO_VERIFY" = "1" ]; then
        warn "no hash for ${asset} in SHA256SUMS.txt (ONYX_NO_VERIFY=1 — continuing)"
      else
        die "SHA256SUMS.txt has no entry for ${asset} — refusing to install."
      fi
    else
      actual="$(cd "$tmpdir" && $SHA256_CMD "$asset" | awk '{print $1}')"
      if [ "$expected" = "$actual" ]; then
        ok "sha256 matches the signed manifest"
      else
        die "sha256 MISMATCH for ${asset}. expected=${expected} actual=${actual}"
      fi
    fi
  fi

  # 2. Sigstore verification of the binary itself. Fail-closed: a missing
  #    signature bundle is refused (not silently skipped) unless the user
  #    has explicitly accepted the risk with ONYX_NO_VERIFY=1.
  if [ -f "${tmpdir}/${asset}.cosign-bundle" ]; then
    verify_sigstore "${tmpdir}/${asset}" "${tmpdir}/${asset}.cosign-bundle" "$ONYX_REPO" "$version"
  elif [ "$ONYX_NO_VERIFY" = "1" ]; then
    warn "no signature bundle for ${asset} and ONYX_NO_VERIFY=1 — installing unverified."
  else
    die "no sigstore bundle for ${asset} — refusing to install an unverified binary (set ONYX_NO_VERIFY=1 to override)."
  fi

  # macOS quarantine xattr — applied by curl when downloading. Strip
  # it so the user doesn't see Gatekeeper's "cannot be opened" dialog.
  # (We're an unsigned binary today; without removing the xattr the
  # user has to right-click → Open or run xattr themselves. We'll add
  # proper Apple Developer ID notarization in a future release.)
  # Only for a binary we verified: never clear Gatekeeper's flag on
  # something installed under ONYX_NO_VERIFY.
  if [ "$ONYX_NO_VERIFY" != "1" ] && [ "$(uname -s)" = "Darwin" ] \
     && command -v xattr >/dev/null 2>&1; then
    xattr -d com.apple.quarantine "${tmpdir}/${asset}" 2>/dev/null || true
  fi

  # Install.
  chmod +x "${tmpdir}/${asset}"
  install -d "$ONYX_INSTALL_DIR"
  install -m 0755 "${tmpdir}/${asset}" "${ONYX_INSTALL_DIR}/${bin_name}"
  ok "installed ${bin_name} → ${ONYX_INSTALL_DIR}/${bin_name}"
}

# ── Public hubs (v0.1.14) ─────────────────────────────────────────────
#
# Download the release's signed `hubs.json`, cosign-verify it (same trust
# path as the binaries), and — ONLY on a clean verify — write it to
# ~/.onyx/public-hubs.json. Then OFFER (default NO) to enable it in
# config.json. Default-off is deliberate: an anonymity tool must not
# silently route first contact through a central relay. The daemon never
# fetches anything itself; it just reads this locally-cached, pre-verified
# copy when the user has opted in.
fetch_public_hubs() {
  local version="$1" tmpdir="$2"
  local base="https://github.com/${ONYX_REPO}/releases/download/${version}"
  local cfg_dir="${HOME}/.onyx"

  # The hub list decides where first-contact traffic goes, so it is only
  # ever installed after a real signature check. ONYX_NO_VERIFY skips
  # verification of the binaries at the user's own risk; it must not also
  # write an unverified hub list that the app then describes as verified.
  if [ "$ONYX_NO_VERIFY" = "1" ]; then
    warn "ONYX_NO_VERIFY=1 — not installing the public hub list (it cannot be verified)."
    warn "add a hub manually in the app with ^G."
    return 0
  fi

  info "fetching public hub list (hubs.json)..."
  if ! fetch "${base}/hubs.json" "${tmpdir}/hubs.json" 2>/dev/null; then
    warn "no hubs.json in ${version} — skipping public hubs (add a hub manually with ^G)."
    return 0
  fi
  fetch "${base}/hubs.json.cosign-bundle" "${tmpdir}/hubs.json.cosign-bundle" 2>/dev/null \
    || warn "no hubs.json.cosign-bundle (was the release signed?)"

  # Verify the signature. If cosign is present and the signature does NOT
  # verify, verify_sigstore() calls die — we must NOT install an unverified
  # hub list. If cosign is absent, verify_sigstore warns + returns 0 (same
  # policy as the binaries); we then refuse to write the list, because an
  # unverified hub list is exactly the substitution attack we care about.
  if [ ! -f "${tmpdir}/hubs.json.cosign-bundle" ]; then
    warn "hubs.json has no signature bundle — refusing to install it."
    return 0
  fi
  if ! command -v cosign >/dev/null 2>&1; then
    warn "cosign not installed — cannot verify hubs.json; refusing to install"
    warn "the public hub list (install cosign + re-run, or add a hub via ^G)."
    return 0
  fi
  verify_sigstore "${tmpdir}/hubs.json" "${tmpdir}/hubs.json.cosign-bundle" "$ONYX_REPO" "$version"

  install -d "$cfg_dir"
  install -m 0600 "${tmpdir}/hubs.json" "${cfg_dir}/public-hubs.json"
  ok "verified public hub list → ${cfg_dir}/public-hubs.json"

  # Offer to enable. Read from /dev/tty because stdin is the piped script
  # body in the `curl … | sh` install path. If there's no tty (fully
  # non-interactive), leave it OFF — the user can flip it later with ^P.
  if [ ! -t 0 ] && [ ! -r /dev/tty ]; then
    info "public hubs installed but left OFF (non-interactive). Enable in the TUI: ^G then ^P."
    return 0
  fi
  # Don't clobber an existing config.json (a returning user's settings win).
  if [ -f "${cfg_dir}/config.json" ]; then
    info "existing config.json found — leaving use_public_hubs as-is. Toggle with ^G/^P."
    return 0
  fi
  printf "  %sUse the public hub list so you can reach others out of the box?%s\n" "$C_DIM" "$C_RESET"
  printf "  %s(routes first-contact through a community relay; default no)%s " "$C_DIM" "$C_RESET"
  local ans=""
  read -r ans </dev/tty 2>/dev/null || ans=""
  case "$ans" in
    y | Y | yes | YES)
      printf '{\n  "use_public_hubs": true\n}\n' > "${cfg_dir}/config.json"
      chmod 600 "${cfg_dir}/config.json"
      ok "public hubs ENABLED (config.json). Disable anytime: ^G then ^P."
      ;;
    *)
      info "public hubs left OFF. Enable later in the TUI: ^G then ^P."
      ;;
  esac
}

# ── Downgrade guard ───────────────────────────────────────────────────

# version_lt <a> <b> — true when release a sorts strictly before b
# (numeric major.minor.patch; a pre-release suffix is ignored).
version_lt() {
  local a="${1#v}" b="${2#v}"
  a="${a%%-*}"; b="${b%%-*}"
  local IFS=.
  # shellcheck disable=SC2086
  set -- $a $b
  [ "$1" -lt "$4" ] && return 0
  [ "$1" -gt "$4" ] && return 1
  [ "$2" -lt "$5" ] && return 0
  [ "$2" -gt "$5" ] && return 1
  [ "$3" -lt "$6" ]
}

# refuse_downgrade <version>
#
# "latest" is whatever the release page says it is. Every release is
# genuinely signed, so re-pointing "latest" at an old, vulnerable version
# would pass every signature check. If an older version than the one
# already installed is about to go in, stop unless the user asked for it.
refuse_downgrade() {
  local target_version="$1" current=""
  [ "${ONYX_ALLOW_DOWNGRADE:-0}" = "1" ] && return 0
  [ -x "${ONYX_INSTALL_DIR}/onyx" ] || return 0
  current="$("${ONYX_INSTALL_DIR}/onyx" --version 2>/dev/null \
             | sed -nE 's/.*[^0-9]([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | sed -n '1p')"
  [ -n "$current" ] || return 0
  if version_lt "$target_version" "v${current}"; then
    die "installed onyx is v${current}; refusing to DOWNGRADE to ${target_version}. If you really want that, re-run with ONYX_ALLOW_DOWNGRADE=1."
  fi
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

  local target version
  target="$(detect_target)"
  printf "  %starget:%s       %s\n" "$C_DIM" "$C_RESET" "$target"

  version="$(resolve_version)"
  is_release_tag "$version" \
    || die "refusing version '${version}': expected a vX.Y.Z release tag."
  refuse_downgrade "$version"
  printf "  %sversion:%s      %s\n" "$C_DIM" "$C_RESET" "$version"
  printf "  %sinstall dir:%s  %s\n" "$C_DIM" "$C_RESET" "$ONYX_INSTALL_DIR"
  printf "  %sbinaries:%s     %s\n" "$C_DIM" "$C_RESET" "$ONYX_BINS"
  printf "\n"

  tmpdir="$(mktemp -d -t onyx-install.XXXXXX)"

  # Install each requested binary.
  for bin in $ONYX_BINS; do
    case "$bin" in
      onyx|onyxd|onyx-hub) ;;
      *) die "unknown binary: $bin (valid: onyx, onyxd, onyx-hub)" ;;
    esac
    fetch_and_install "$bin" "$version" "$target" "$tmpdir"
  done

  # v0.1.14: optional public hub list (signed + verified, opt-in).
  printf "\n"
  fetch_public_hubs "$version" "$tmpdir"

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
