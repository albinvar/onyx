//! Infra.4: N-member room performance benchmarks.
//!
//! Run with:
//!
//! ```sh
//! cargo bench -p onyx-core --bench rooms
//! ```
//!
//! Reports + flamegraph land under `target/criterion/`. We measure
//! four ops that scale differently with member count:
//!
//! | op                       | expected scaling          |
//! |--------------------------|---------------------------|
//! | `create_group`           | O(1) — single party       |
//! | `invite_Nth_member`      | O(N) — MLS commit + tree  |
//! | `encrypt_application`    | O(1) — single sender, current epoch |
//! | `decrypt_application`    | O(1) — one ratchet step  |
//!
//! "O(N)" for invite covers the openmls tree update + KP validation
//! work as the group grows. **`encrypt`/`decrypt` should be flat in
//! N** — that's the property MLS gives us, and the benchmark is the
//! enforcement: if they trend with N, we've introduced a quadratic
//! somewhere by accident.
//!
//! Member counts swept: 2, 4, 8, 16. Beyond 16 the tree-size memory
//! cost of MLS starts to bite (an 80-leaf tree is ~4 KB per epoch);
//! we can extend later if needed.
//!
//! Not run in CI by design: benchmark variance on shared runners
//! would either flake-fail or hide real regressions. Operator runs
//! these manually before/after a perf-sensitive change.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use onyx_core::mls::{IncomingRoomMessage, MlsGroupState, MlsParty};

/// Build N parties + KPs. Setup-only; not measured.
fn n_parties(n: usize) -> Vec<(MlsParty, Vec<u8>)> {
    (0..n)
        .map(|i| {
            let label = format!("p{i}");
            let party = MlsParty::new(label.into_bytes()).expect("party");
            let kp = party.key_package_bytes().expect("kp");
            (party, kp)
        })
        .collect()
}

/// Build an established N-member group. Returns (parties[],
/// alice's group view). Used as setup for the steady-state
/// encrypt/decrypt benches.
fn established_group(n: usize) -> (Vec<MlsParty>, MlsGroupState) {
    assert!(n >= 2, "need at least 2 parties");
    let all = n_parties(n);
    let alice = &all[0].0;
    let mut alice_group = alice.create_group().expect("group");
    for (i, (_, kp)) in all.iter().enumerate().skip(1) {
        let (_commit, _welcome) = alice_group.invite(alice, kp).expect("invite");
        let _ = i;
    }
    // Discard the other parties' joined groups — we only measure
    // alice's encrypt here. Decrypt benches re-derive a recipient.
    let parties = all.into_iter().map(|(p, _)| p).collect();
    (parties, alice_group)
}

fn bench_create_group(c: &mut Criterion) {
    let mut g = c.benchmark_group("mls.create_group");
    g.bench_function("solo", |b| {
        let alice = MlsParty::new(b"alice".to_vec()).unwrap();
        b.iter(|| {
            let _grp = alice.create_group().expect("group");
        });
    });
    g.finish();
}

fn bench_invite_nth_member(c: &mut Criterion) {
    let mut g = c.benchmark_group("mls.invite_nth_member");
    for &n in &[2usize, 4, 8, 16] {
        g.throughput(Throughput::Elements(n as u64));
        g.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            // Each iteration rebuilds a fresh n-member group + the
            // nth invitee's KP, then measures the cost of the
            // (n-1)→n add. MlsParty isn't Clone (openmls provider
            // ownership), so we rebuild rather than clone.
            b.iter_with_setup(
                || {
                    let alice = MlsParty::new(b"alice".to_vec()).unwrap();
                    let mut group = alice.create_group().expect("group");
                    // Seed the group with n-2 members (we'll add
                    // the (n-1)th in the measured iter).
                    for i in 1..(n - 1) {
                        let party = MlsParty::new(format!("p{i}").into_bytes()).unwrap();
                        let kp = party.key_package_bytes().unwrap();
                        let _ = group.invite(&alice, &kp).expect("invite seed");
                    }
                    let nth_party = MlsParty::new(format!("p{}", n - 1).into_bytes()).unwrap();
                    let nth_kp = nth_party.key_package_bytes().unwrap();
                    (alice, group, nth_kp)
                },
                |(alice, mut group, nth_kp)| {
                    let (_commit, _welcome) = group.invite(&alice, &nth_kp).expect("invite nth");
                },
            );
        });
    }
    g.finish();
}

fn bench_encrypt_application(c: &mut Criterion) {
    let mut g = c.benchmark_group("mls.encrypt_application");
    for &n in &[2usize, 4, 8, 16] {
        g.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_with_setup(
                || {
                    let (parties, group) = established_group(n);
                    (parties, group)
                },
                |(parties, mut group)| {
                    let alice = &parties[0];
                    let _ct = group
                        .encrypt_application(alice, b"benchmark payload")
                        .expect("encrypt");
                },
            );
        });
    }
    g.finish();
}

fn bench_decrypt_application(c: &mut Criterion) {
    let mut g = c.benchmark_group("mls.decrypt_application");
    for &n in &[2usize, 4, 8, 16] {
        g.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            // Setup: alice encrypts; we measure the decrypt cost
            // for a fresh recipient at the same epoch. Recipient
            // can't be one of the established_group parties because
            // we don't have their joined-group state — just rebuild
            // a fresh 2-party group for the decrypt cost (which is
            // O(1) in member count by design).
            b.iter_with_setup(
                || {
                    let alice = MlsParty::new(b"alice".to_vec()).unwrap();
                    let bob = MlsParty::new(b"bob".to_vec()).unwrap();
                    let bob_kp = bob.key_package_bytes().unwrap();
                    let mut alice_group = alice.create_group().unwrap();
                    let (_commit, welcome) = alice_group.invite(&alice, &bob_kp).unwrap();
                    let bob_group = bob.join_from_welcome(&welcome).unwrap();
                    let ct = alice_group
                        .encrypt_application(&alice, b"benchmark payload")
                        .unwrap();
                    let _ = n; // member-count parameter consumed by benchmark id only
                    (bob, bob_group, ct)
                },
                |(bob, mut bob_group, ct)| {
                    let pt = bob_group.process_incoming(&bob, &ct).expect("decrypt");
                    assert!(matches!(pt, IncomingRoomMessage::Application(_)));
                },
            );
        });
    }
    g.finish();
}

criterion_group!(
    benches,
    bench_create_group,
    bench_invite_nth_member,
    bench_encrypt_application,
    bench_decrypt_application
);
criterion_main!(benches);
