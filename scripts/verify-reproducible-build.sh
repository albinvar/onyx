#!/usr/bin/env bash
# verify-reproducible-build.sh — prove a published Onyx binary was built
# from this exact source tree (Phase 0 / F0.1 of the fortification plan).
#
# Reproducible builds turn "trust the maintainer didn't slip something in"
# into "rebuild it yourself and check the bytes match." This is the
# concrete defense against the supply-chain class of attack — including the
# real one that bit us (a binary that didn't match its claimed source/
# platform). install.sh verifies a *downloaded* binary's signature; this
# verifies the *build itself* is reproducible from source.
#
# What it does:
#   1. Checks out the given tag (or uses the current tree).
#   2. Builds with the SAME deterministic flags release.yml uses
#      (SOURCE_DATE_EPOCH, --remap-path-prefix, --locked, version stamp).
#   3. Computes the SHA256 of the resulting binaries.
#   4. If a published SHA256SUMS is available (downloaded or passed in),
#      diffs ours against the published one and reports MATCH / MISMATCH.
#
# Usage:
#   scripts/verify-reproducible-build.sh                 # build current tree, print hashes
#   scripts/verify-reproducible-build.sh v0.1.19         # checkout + build that tag
#   scripts/verify-reproducible-build.sh v0.1.19 <SHA256SUMS-file>   # build + compare
#
# Exit: 0 = built (and matched, if a manifest was given); 1 = mismatch/err.
set -euo pipefail

# Same fixed epoch as release.yml's env block — pins file mtimes so the
# build output doesn't embed wall-clock time. MUST match release.yml.
export SOURCE_DATE_EPOCH=1700000000

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TAG="${1:-}"
MANIFEST="${2:-}"

if [ -n "$TAG" ]; then
  echo "==> Checking out $TAG (clean tree required)"
  if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "ERROR: working tree is dirty; commit/stash first for a faithful verify." >&2
    exit 1
  fi
  git checkout --quiet "$TAG"
  # Stamp the version exactly as the release job does (tag minus leading v).
  export ONYX_RELEASE_VERSION="${TAG#v}"
else
  echo "==> Building current working tree (no tag checkout)"
fi

# The exact reproducible RUSTFLAGS from release.yml. --remap-path-prefix
# rewrites build-host paths to stable prefixes so two machines' outputs
# match; -C link-arg=-s strips the symbol table (Linux).
HOST_TARGET="$(rustc -vV | sed -n 's/host: //p')"
export RUSTFLAGS="--remap-path-prefix ${ROOT}=/onyx --remap-path-prefix ${HOME}/.cargo=/cargo -C link-arg=-s"

echo "==> Reproducible build (target: ${HOST_TARGET})"
echo "    SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
echo "    ONYX_RELEASE_VERSION=${ONYX_RELEASE_VERSION:-<unset: dev build>}"
cargo build --release --locked --target "$HOST_TARGET" -p onyx -p onyxd -p onyx-hub

BINDIR="target/${HOST_TARGET}/release"
SHA_CMD="sha256sum"; command -v sha256sum >/dev/null 2>&1 || SHA_CMD="shasum -a 256"

echo
echo "==> Local build SHA256 (this machine, this source):"
LOCAL_SUMS="$(mktemp)"
for b in onyx onyxd onyx-hub; do
  [ -f "$BINDIR/$b" ] && $SHA_CMD "$BINDIR/$b" | sed "s#$BINDIR/##"
done | tee "$LOCAL_SUMS"

if [ -z "$MANIFEST" ]; then
  echo
  echo "No published SHA256SUMS given — printed local hashes only."
  echo "To verify against a release: download its SHA256SUMS-<target>.txt and pass it as arg 2,"
  echo "or compare these hashes to the release page. A byte-identical match proves the published"
  echo "binary was built from this exact source."
  exit 0
fi

echo
echo "==> Comparing against published manifest: $MANIFEST"
mismatch=0
for b in onyx onyxd onyx-hub; do
  [ -f "$BINDIR/$b" ] || continue
  ours="$($SHA_CMD "$BINDIR/$b" | awk '{print $1}')"
  # Published manifest lines look like: <hash>  <name-v0.1.19-target>
  theirs="$(grep -E "(^|[[:space:]])${b}[-_]" "$MANIFEST" | awk '{print $1}' | head -1)"
  if [ -z "$theirs" ]; then
    echo "  $b: (no entry in manifest — skipped)"
    continue
  fi
  if [ "$ours" = "$theirs" ]; then
    echo "  $b: MATCH ✓  ($ours)"
  else
    echo "  $b: MISMATCH ✗"
    echo "      ours:      $ours"
    echo "      published: $theirs"
    mismatch=1
  fi
done

echo
if [ "$mismatch" -eq 0 ]; then
  echo "RESULT: REPRODUCIBLE ✓ — local build matches the published binaries."
  exit 0
else
  echo "RESULT: MISMATCH ✗ — local build does NOT match. Investigate before trusting the release."
  exit 1
fi
