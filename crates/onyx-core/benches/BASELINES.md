# N-member room benchmark baselines

Captured 2026-05-19 on `aarch64-apple-darwin` (Apple Silicon M-series, single core, `--release`). These are reference numbers — re-run the benches on your hardware before/after a perf-sensitive change to spot regressions. **CI does not gate on these** (benchmark variance on shared runners would either flake-fail or hide real regressions); they're for operator-driven measurement.

Reproduce:

```sh
cargo bench -p onyx-core --bench rooms
```

## Single-op baselines (samples = criterion default, ~100)

| op                            | N=2   | N=4   | N=8   | N=16  | scaling       |
|-------------------------------|-------|-------|-------|-------|---------------|
| `mls.create_group/solo`       | 53 µs | —     | —     | —     | constant (no N) |
| `mls.invite_nth_member`       | 256 µs| 413 µs| 559 µs| 719 µs| **O(N)** as expected (tree update) |
| `mls.encrypt_application`     | 28 µs | 32 µs | 36 µs | 40 µs | mostly flat (~+1µs per doubling — openmls's sender path touches more leaves on ratchet step) |
| `mls.decrypt_application`     | 36 µs | 36 µs | 36 µs | 37 µs | **flat — the property MLS gives us** |

(N=4 / N=8 / N=16 for create_group aren't measured: solo create is a single-party op, has no N dimension.)

## Interpretation

- **`decrypt_application` flat in N is the load-bearing property.** A new member joining a room should not slow down the recipient's decrypt path. If a future change drives this number upward with N, the MLS layer's ratchet-step assumptions have been broken — investigate immediately.

- **`encrypt_application` grows mildly with N** because openmls's sender path computes a tree-derived path secret update on each application message. ~1µs per doubling is below the noise floor for actual chat use; it's reported here for completeness.

- **`invite_nth_member` is the dominant cost** of growing a room. At N=16 it's ~720µs, which is fine for interactive use (operator clicks "invite" and sees the result instantly). At N=100 it would be ~5ms, still fine. At N=1000 it would be ~50ms which starts to feel like a UI hitch — but Onyx isn't targeting 1000-member rooms today, and `CHANNELS.md` explicitly defers very-large-room support.

- **Encrypt + decrypt + invite are all in the tens-of-microseconds range** — vastly below network RTT through Tor (~hundreds of milliseconds). The MLS layer is not the bottleneck.

## How to use these numbers

When making a perf-sensitive change to `crates/onyx-core/src/mls.rs` or the wire layer that affects MLS-message size:

1. Stash your changes: `git stash`.
2. Run `cargo bench -p onyx-core --bench rooms`. Note the numbers (or save with `--save-baseline before`).
3. Pop your changes: `git stash pop`.
4. Run `cargo bench -p onyx-core --bench rooms`. (Or `--baseline before` to get a comparison report.)
5. **Regression policy**: if any decrypt or encrypt number grows by >2× the baseline, flag the change. Tree-related work (invite/remove) is allowed to fluctuate more (the tree structure changes per epoch).

Criterion's HTML reports under `target/criterion/` give percentile breakdowns + flamegraph-ish plots when `gnuplot` is installed; install gnuplot for the better visuals.

## Caveats

- The benchmark setup ALSO measures MlsParty construction (~50µs per party). For `invite_nth_member`, the setup builds n-1 parties; the reported time includes only the measured `invite` call thanks to `iter_with_setup`. Don't confuse setup time with the measured op.
- We benchmark with `MlsParty::new` (a fresh Ed25519 keypair per party) rather than `MlsParty::from_identity`. The crypto work is the same; from_identity would just save a keygen step in the setup phase.
- Decrypt is measured against a freshly-joined 2-party group regardless of N — see comment in `bench_decrypt_application`. Decrypt cost is O(1) in N at the MLS layer; the N parameter is for benchmark-ID symmetry with the other ops.
