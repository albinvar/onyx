# Verifying an Onyx release

Every binary in an Onyx GitHub release is signed with [sigstore](https://www.sigstore.dev/)'s cosign tool, keyless, bound to the GitHub Actions workflow that built it. This means you can verify cryptographically that:

1. The binary you downloaded was built by THIS repository,
2. From a specific tagged commit,
3. By the [`.github/workflows/release.yml`](.github/workflows/release.yml) workflow file you can see in the repo,
4. Without an attacker who got write access to the GitHub release tab being able to swap in a tampered binary.

This document walks through how to verify a release. **If you're installing Onyx for actual use, do this.** No exceptions.

## §0 What this catches and what it doesn't

**Catches**:
- An attacker who compromised the GitHub release UI and uploaded a backdoored binary under the same filename.
- An attacker who replaced a download mid-flight (CDN compromise, network MitM, etc.) — the sigstore bundle has to be served from a trusted source (the release page itself), but a swapped binary won't verify.
- A typo'd download URL that points at a doppelganger repo with a similar name.

**Does NOT catch**:
- An attacker who compromised this repository's CI secrets or workflow file. If they can push commits that modify `release.yml`, they can sign tampered binaries with the legitimate workflow identity. Mitigation: branch protection on `main`, mandatory PR review, monitoring of workflow file changes. This is an upstream-of-Onyx problem (GitHub's security model).
- A backdoor that was committed to the source code BEFORE the tag. Sigstore signs what CI built; it doesn't tell you the source is honest. Mitigation: read the diff, check `cargo deny check`, run the smoke harness, build from source yourself.
- A flaw in the Sigstore transparency log itself. Sigstore is a young system with significant production usage but no end-of-history audit. We accept this trust because the alternative (uploading PGP-signed binaries with a key whose private half lives somewhere) has a worse threat model in practice.

## §1 Prerequisites

```sh
# Install cosign. The github.com/sigstore/cosign release page has builds
# for every platform. Or via package manager:
brew install cosign            # macOS
# debian/ubuntu: see https://docs.sigstore.dev/cosign/installation/
```

`cosign` version 2.x or later. Earlier versions don't understand the bundle format Onyx uses.

## §2 Verifying a single binary

Download the binary AND its `.cosign-bundle` file from the GitHub release page:

```sh
# Example for the Linux x86_64 binary at tag v0.0.1
curl -LO https://github.com/<repo>/releases/download/v0.0.1/onyx-v0.0.1-x86_64-unknown-linux-gnu
curl -LO https://github.com/<repo>/releases/download/v0.0.1/onyx-v0.0.1-x86_64-unknown-linux-gnu.cosign-bundle
```

Verify:

```sh
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/<repo>/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --bundle onyx-v0.0.1-x86_64-unknown-linux-gnu.cosign-bundle \
  onyx-v0.0.1-x86_64-unknown-linux-gnu
```

You should see `Verified OK` and details of which workflow + commit produced the binary. **If verification fails, do not run the binary.** Open an issue against this repo.

Replace `<repo>` with the actual repository path (e.g. `albinvar/onyx`).

## §3 Verifying via the combined SHA256SUMS

Faster if you're downloading multiple binaries. Verify the manifest once, then check binary hashes against it:

```sh
curl -LO https://github.com/<repo>/releases/download/v0.0.1/SHA256SUMS.txt
curl -LO https://github.com/<repo>/releases/download/v0.0.1/SHA256SUMS.txt.cosign-bundle

cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/<repo>/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --bundle SHA256SUMS.txt.cosign-bundle \
  SHA256SUMS.txt

# Then check each binary against the verified manifest:
sha256sum -c SHA256SUMS.txt --ignore-missing
```

`--ignore-missing` skips entries for binaries you haven't downloaded.

## §4 Reproducible builds

The release workflow uses three knobs to make builds reproducible across runners:

- `SOURCE_DATE_EPOCH=1700000000` — pins file mtimes embedded in archives / debug info.
- `--remap-path-prefix` — strips absolute source + cargo cache paths from the binary so two runners' outputs match.
- `--locked` — refuses to update `Cargo.lock`; same dep set every time.
- `-C link-arg=-s` (Linux) / `strip` (macOS) — removes the symbol table.

This means a third-party rebuilder can run the same workflow on a different runner and produce a byte-identical binary. Today nobody has set up an independent reproducer for Onyx; if you do, please open a PR linking your reproducer's output.

## §5 What sigstore actually proves

The cosign certificate embedded in each bundle is bound (via GitHub Actions OIDC) to:

- The exact repository (`https://github.com/<repo>/`).
- The exact workflow file (`.github/workflows/release.yml`).
- The exact ref (the tag `v0.0.1`).
- The commit SHA the workflow ran against.

You can inspect this with:

```sh
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/<repo>/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --bundle onyx-v0.0.1-x86_64-unknown-linux-gnu.cosign-bundle \
  --output text \
  onyx-v0.0.1-x86_64-unknown-linux-gnu
```

The output names the workflow + ref + commit. If you have any reason to doubt the release (e.g. it appeared between announced releases), you can check the workflow run on GitHub Actions to see the build logs.

## §6 Future-proofing

If sigstore's infrastructure ever goes away or becomes untrustworthy:
- The signing certificates and Rekor transparency-log entries are publicly archived; existing signed releases remain verifiable.
- Future releases would switch to whatever the community settles on next (cosign supports multiple key-providers; we'd update this doc).

If you want belt-and-braces verification today, you can ALSO build from source:

```sh
git clone https://github.com/<repo>/ onyx
cd onyx
git checkout v0.0.1
cargo build --release --locked
# Then sha256sum target/release/onyx and compare to the manifest.
```

The two values should match (modulo the reproducibility caveats in §4 — `--remap-path-prefix` and `SOURCE_DATE_EPOCH` need to be set on your local build too if you want byte-identical output).

## §7 Reporting verification failures

If `cosign verify-blob` reports failure for an officially-announced release:

1. **Do not run the binary.**
2. Open a GitHub issue: title `[security] release verification failure for vX.Y.Z`.
3. Include the exact `cosign` command output and the binary's SHA256.
4. We'll either confirm a release problem (and rebuild + republish) or explain what went wrong (e.g. you fetched a `.cosign-bundle` from a different tag).

See `SECURITY.md` for vulnerability-disclosure flow if you find a deeper supply-chain issue.
