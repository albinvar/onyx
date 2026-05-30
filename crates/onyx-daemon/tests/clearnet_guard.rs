//! A1.2 integration test: prove that `run()` actually INVOKES the
//! no-clearnet-leak guard and refuses to start a clearnet transport
//! without `allow_clearnet`.
//!
//! Why this exists: the guard logic (`clearnet_guard`) has unit tests,
//! but those only test the pure classifier — they do NOT prove `run()`
//! calls it. In fact the wiring silently failed to apply for several
//! commits (the `match clearnet_guard(...)` block never made it into
//! `run()`), so the daemon shipped accepting clearnet transport with no
//! acknowledgement while the unit tests stayed green. This test closes
//! that gap: it drives the real `run()` entry point.
//!
//! The refuse path is side-effect-free by design — the guard runs
//! BEFORE vault open / Tor bootstrap — so these tests touch no real
//! vault and complete in milliseconds. The `timeout` wrapper is the
//! regression teeth: if the guard wiring is ever removed, `run()` would
//! fall through to opening the vault and serving the API forever
//! (no_tor mode), so the test would TIME OUT rather than get a quick
//! refusal — a clean failure either way.

use std::time::Duration;

use onyx_daemon::{Config, HubConfig};
use zeroize::Zeroizing;

/// Build a Config that requests a clearnet transport (the given
/// closure sets the offending flag) with `allow_clearnet = false`. The
/// vault/socket paths point inside a tempdir that is never touched on
/// the refuse path.
fn clearnet_config(dir: &std::path::Path, set_flag: impl FnOnce(&mut Config)) -> Config {
    let mut cfg = Config {
        vault: dir.join("vault.db"),
        passphrase: Zeroizing::new("integration-test-pass".to_string()),
        no_tor: false,
        tor_state_dir: None,
        dial_onion: None,
        dial_pubkey: None,
        api_socket: dir.join("api.sock").to_string_lossy().into_owned(),
        hubs: Vec::new(),
        hub_tcp_addrs: Vec::new(),
        listen_tcp: None,
        dial_tcp: None,
        cover_traffic_mean_secs: None,
        constant_rate_ms: None,
        first_contact_reachable: false,
        allow_clearnet: false,
    };
    set_flag(&mut cfg);
    cfg
}

/// Run `run(cfg)` with a hard timeout. Returns:
///   `Some(Ok/Err)` if it resolved in time, `None` if it timed out
///   (i.e. `run` did NOT bail early — the guard did not fire).
async fn run_with_timeout(cfg: Config) -> Option<anyhow::Result<()>> {
    tokio::time::timeout(Duration::from_secs(10), onyx_daemon::run(cfg))
        .await
        .ok()
}

/// `--hub-tcp` set + no ack ⇒ run() must refuse before any side effect.
/// This is the realistic footgun (`--hub-tcp` typed for `--hub`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_refuses_hub_tcp_without_ack() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = clearnet_config(dir.path(), |c| {
        c.hub_tcp_addrs = vec![HubConfig {
            onion: "127.0.0.1:9999".to_string(),
            pubkey: "aaaa".to_string(),
        }];
    });

    let result = run_with_timeout(cfg)
        .await
        .expect("run() must return quickly (guard refuses before vault/Tor), not hang");
    let err = result.expect_err("run() must REFUSE a clearnet --hub-tcp without --allow-clearnet");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("REFUSING TO START"),
        "refusal must be the clearnet guard, got: {msg}"
    );
    assert!(
        msg.contains("--hub-tcp"),
        "refusal must name the offending flag, got: {msg}"
    );

    // The guard runs before any side effect: the vault file must NOT
    // have been created.
    assert!(
        !dir.path().join("vault.db").exists(),
        "guard must refuse BEFORE opening/creating the vault"
    );
}

/// `--no-tor` set + no ack ⇒ refuse. Covers a second clearnet flag so
/// the test isn't tied to one code path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_refuses_no_tor_without_ack() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = clearnet_config(dir.path(), |c| c.no_tor = true);

    let result = run_with_timeout(cfg)
        .await
        .expect("run() must return quickly, not hang");
    let err = result.expect_err("run() must REFUSE --no-tor without --allow-clearnet");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("REFUSING TO START") && msg.contains("--no-tor"),
        "refusal must be the clearnet guard naming --no-tor, got: {msg}"
    );
    assert!(
        !dir.path().join("vault.db").exists(),
        "guard must refuse BEFORE opening/creating the vault"
    );
}

/// A Tor-only config (no clearnet flags) must NOT be refused by the
/// guard. We can't let `run()` complete a real Tor bootstrap in a unit
/// test, so we assert the *negative*: whatever happens within the
/// timeout window, it is NOT a clearnet refusal. (If it times out, that
/// is fine — it means the guard let it through and it proceeded toward
/// vault/Tor, which is the correct behaviour; the point is purely that
/// the guard did not bail with REFUSING.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_does_not_refuse_tor_only_config() {
    let dir = tempfile::tempdir().expect("tempdir");
    // No clearnet flags at all ⇒ ClearnetDecision::AllTor.
    let cfg = clearnet_config(dir.path(), |_c| {});

    // Only an early Err could be a clearnet refusal. Ok(()) is
    // implausible here (no hubs, would idle) but harmless; a timeout
    // means it proceeded past the guard toward vault/Tor — also correct,
    // since the point is purely that the guard did not refuse.
    if let Some(Err(err)) = run_with_timeout(cfg).await {
        let msg = format!("{err:#}");
        assert!(
            !msg.contains("REFUSING TO START"),
            "a Tor-only config must never hit the clearnet guard, got: {msg}"
        );
    }
}
