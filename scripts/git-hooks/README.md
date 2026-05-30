# Git hooks

Repo-managed hooks that mirror CI so a red tree can't reach `main`.

## Install (once per clone)

```sh
git config core.hooksPath scripts/git-hooks
```

That's it — `pre-push` then runs on every `git push`.

## What `pre-push` does

When the push includes `main`, it runs the **same three gates as
`.github/workflows/ci.yml`** and aborts the push if any fail:

1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace`

Feature-branch pushes are not gated (WIP is fine there; CI still runs).

## Escape hatches

- Docs-only push (skip the slow test step):
  `ONYX_PREPUSH_SKIP_TESTS=1 git push`
- Genuine emergency bypass (you own the result):
  `git push --no-verify`

## Why this exists

Pushing clippy-/test-RED to `main` happened repeatedly when the commit
and push were issued in the same step as the gates, so the push ran
before the gate result was read. A machine check is the durable fix.
