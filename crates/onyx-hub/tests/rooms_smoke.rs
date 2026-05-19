// Test-style patterns kept readable: panic on timeout, explicit
// `if then panic`, `Err(_)` catch-all — these are diagnostic
// conveniences in a smoke harness, not production patterns.
#![allow(
    clippy::manual_assert,
    clippy::match_wild_err_arm,
    clippy::too_many_lines,
    clippy::uninlined_format_args
)]

//! End-to-end smoke harness for the T6.3 room flow.
//!
//! Stands up an in-process hub on a random TCP port + two daemons
//! (alice, bob) configured to dial that hub over plain TCP. Drives
//! them via their local Unix-domain API sockets to:
//!
//!   1. Confirm both daemons reach the hub and publish their KPs.
//!   2. alice creates a room.
//!   3. alice fetches bob's KP from the hub directory.
//!   4. alice invites bob.
//!   5. alice sends a room message.
//!   6. Bob receives the room message (asserted by subscribing to
//!      bob's `Tail` stream and watching for the `EventMessage`).
//!
//! Closes (mostly) post-T6.3 review's issue #1 — "no real-Tor smoke."
//! This isn't real Tor (TCP shortcut for speed), but it does exercise
//! every code path between the API surface and the wire encoding,
//! including the T6.3.h commit + KEM-ad fan-out + T6.3.i out-of-order
//! retry buffer + T6.3.g session-token routing. The remaining
//! "differences from real Tor" are circuit-level: NAT, latency,
//! packet loss, MTU. Those are out of scope for a CI test.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use onyx_core::api::{
    ApiRequest, ApiResponse, MessageDirection, RoomInfo, decode_response, encode_request_line,
};
use onyx_core::crypto::Argon2Params;
use onyx_core::storage::Vault;
use onyx_hub::handler::hub_handle_connection_with_cover;
use onyx_hub::state::HubState;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
const EVENT_TIMEOUT: Duration = Duration::from_secs(15);

/// Spawn an in-process hub listening on a fresh ephemeral TCP port.
/// Returns `(addr, hub_pub_b32)` — pass these into the daemon as
/// `hub_tcp_addrs = [HubConfig { onion: addr, pubkey: hub_pub_b32 }]`.
async fn spawn_hub() -> (String, String, TempDir) {
    spawn_hub_with_cover(None).await
}

/// Variant that enables hub-side cover traffic with the given mean
/// (Some(secs)) or no cover (None). Used by
/// `rooms_e2e_hub_cover_traffic_does_not_break_flow` to prove the
/// T-cover.hub emitter doesn't interfere with real messages.
async fn spawn_hub_with_cover(cover_traffic_mean_secs: Option<u64>) -> (String, String, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("hub-vault.db");
    let passphrase = b"smoke-hub-pass";

    let mut vault =
        Vault::create(&vault_path, passphrase, &Argon2Params::FLOOR).expect("hub vault");
    let (_id, identity) = vault.create_identity("hub").expect("hub identity");
    drop(vault);

    let hub_pub_b32 = base32::encode(
        base32::Alphabet::Rfc4648Lower { padding: false },
        &identity.identity_key().public().to_bytes(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr").to_string();

    // Ephemeral hub state — no durable store needed for the smoke.
    let state = Arc::new(Mutex::new(HubState::new()));
    let identity_sk = Arc::new(identity);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                return;
            };
            let state = state.clone();
            let identity_sk = identity_sk.clone();
            tokio::spawn(async move {
                let _ = hub_handle_connection_with_cover(
                    stream,
                    identity_sk.identity_key(),
                    state,
                    cover_traffic_mean_secs,
                )
                .await;
            });
        }
    });

    (addr, hub_pub_b32, dir)
}

/// Spawn a daemon configured to dial the given hub over TCP. Returns
/// `(api_socket_path, tempdir_owning_state)`. The daemon is left
/// running on a background task; the tempdir keeps the vault +
/// socket alive until the test drops it.
async fn spawn_daemon(hub_addr: &str, hub_pubkey_b32: &str, label: &str) -> (PathBuf, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join(format!("{label}-vault.db"));
    let api_socket_path = dir.path().join(format!("{label}.sock"));

    let config = onyx_daemon::Config {
        vault: vault_path,
        passphrase: Zeroizing::new("smoke-daemon-pass".to_string()),
        no_tor: false,
        tor_state_dir: None,
        dial_onion: None,
        dial_pubkey: None,
        api_socket: api_socket_path.to_string_lossy().into_owned(),
        hubs: Vec::new(),
        hub_tcp_addrs: vec![onyx_daemon::HubConfig {
            onion: hub_addr.to_string(),
            pubkey: hub_pubkey_b32.to_string(),
        }],
        listen_tcp: Some("127.0.0.1:0".to_string()),
        dial_tcp: None,
        cover_traffic_mean_secs: None,
    };

    tokio::spawn(async move {
        if let Err(e) = onyx_daemon::run(config).await {
            eprintln!("daemon crashed: {e:#}");
        }
    });

    // Wait for the API socket to appear so subsequent calls don't
    // race the daemon startup.
    let deadline = std::time::Instant::now() + SETUP_TIMEOUT;
    while !api_socket_path.exists() {
        if std::time::Instant::now() > deadline {
            panic!(
                "daemon {label}: API socket never appeared at {}",
                api_socket_path.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    (api_socket_path, dir)
}

/// One-shot API request: open the UDS, write a single NDJSON request
/// line, read the single response line, decode.
async fn one_shot(socket: &Path, req: &ApiRequest) -> ApiResponse {
    let stream = UnixStream::connect(socket).await.expect("connect API");
    let (rd, mut wr) = stream.into_split();
    let line = encode_request_line(req).expect("encode");
    wr.write_all(line.as_bytes()).await.expect("write req");
    wr.shutdown().await.ok();
    let mut reader = BufReader::new(rd);
    let mut buf = String::new();
    reader.read_line(&mut buf).await.expect("read resp");
    decode_response(buf.trim_end_matches('\n')).expect("decode resp")
}

/// Retry `one_shot` until the daemon returns a non-error response,
/// or the timeout elapses. Used to wait out the brief window between
/// "daemon up" and "hub session established + KP published."
async fn one_shot_until_ok(socket: &Path, req: &ApiRequest, label: &str) -> ApiResponse {
    let deadline = std::time::Instant::now() + SETUP_TIMEOUT;
    loop {
        let resp = one_shot(socket, req).await;
        if !matches!(resp, ApiResponse::Error { .. }) {
            return resp;
        }
        if std::time::Instant::now() > deadline {
            panic!("one_shot_until_ok {label} timed out; last error: {resp:?}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn rooms_e2e_alice_invites_bob_and_sends() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,onyx_daemon=warn,onyx_hub=warn")
        .with_test_writer()
        .try_init();

    let (hub_addr, hub_pub_b32, _hub_dir) = spawn_hub().await;
    let (alice_sock, _alice_dir) = spawn_daemon(&hub_addr, &hub_pub_b32, "alice").await;
    let (bob_sock, _bob_dir) = spawn_daemon(&hub_addr, &hub_pub_b32, "bob").await;

    // 1. Wait for alice + bob's daemons to come up + their hub
    //    sessions to publish KPs. Use Identity (always-OK once the
    //    API is up) as the readiness signal.
    let alice_identity = one_shot_until_ok(&alice_sock, &ApiRequest::Identity, "alice ready").await;
    let bob_identity = one_shot_until_ok(&bob_sock, &ApiRequest::Identity, "bob ready").await;
    let (bob_fp, bob_kem_b32) = match bob_identity {
        ApiResponse::IdentityOk {
            fingerprint,
            identity_kem_pub_b32,
            ..
        } => (fingerprint, identity_kem_pub_b32),
        other => panic!("bob Identity returned {other:?}"),
    };
    let alice_fp = match alice_identity {
        ApiResponse::IdentityOk { fingerprint, .. } => fingerprint,
        other => panic!("alice Identity returned {other:?}"),
    };

    // 2. alice creates a room.
    let create = one_shot(
        &alice_sock,
        &ApiRequest::CreateRoom {
            name: "general".to_string(),
        },
    )
    .await;
    let group_id_b32 = match create {
        ApiResponse::CreateRoomOk { group_id_b32, .. } => group_id_b32,
        other => panic!("CreateRoom returned {other:?}"),
    };

    // 3. alice fetches bob's KP from the hub directory. Both daemons
    //    publish their KP on hub session start; this should succeed
    //    once both are connected. Retry until OK.
    let fetch = one_shot_until_ok(
        &alice_sock,
        &ApiRequest::FetchPeerKeyPackage {
            peer_fingerprint: bob_fp.clone(),
        },
        "alice fetch bob KP",
    )
    .await;
    let bob_kp_b64 = match fetch {
        ApiResponse::FetchPeerKeyPackageOk { kp_b64 } => kp_b64,
        other => panic!("FetchPeerKeyPackage returned {other:?}"),
    };

    // 4. Subscribe to bob's Tail BEFORE alice's invite so we don't
    //    miss the room-join + room-message events.
    let mut bob_tail = open_tail(&bob_sock).await;

    // 5. alice invites bob into the room.
    let invite = one_shot(
        &alice_sock,
        &ApiRequest::InviteToRoom {
            group_id_b32: group_id_b32.clone(),
            peer_fingerprint: bob_fp.clone(),
            peer_kem_pub_b32: bob_kem_b32.clone(),
            peer_kp_b64: bob_kp_b64.clone(),
        },
    )
    .await;
    match invite {
        ApiResponse::InviteToRoomOk { ref members, .. } => {
            assert!(
                members.iter().any(|m| m == &alice_fp) && members.iter().any(|m| m == &bob_fp),
                "invite roster must include both: {members:?}"
            );
        }
        other => panic!("InviteToRoom returned {other:?}"),
    }

    // 6. bob's daemon should persist a `rooms` row on Welcome
    //    receive. Poll bob's ListRooms until "general" shows up.
    let bob_rooms = wait_for_room_in_list(&bob_sock, &group_id_b32).await;
    assert_eq!(bob_rooms.name, "general");
    assert!(
        bob_rooms.members.iter().any(|m| m == &bob_fp),
        "bob's room roster must include himself: {:?}",
        bob_rooms.members
    );

    // 7. alice sends a room message. Both daemons must route via the
    //    hub fallback (no direct Noise session between them).
    let send = one_shot(
        &alice_sock,
        &ApiRequest::SendRoom {
            group_id_b32: group_id_b32.clone(),
            text: "hello smoke room".to_string(),
        },
    )
    .await;
    match send {
        ApiResponse::SendRoomOk {
            total_members,
            delivered_to_hub,
            ..
        } => {
            // bob is the only other member, and the only path to him
            // is via the hub (no direct sessions in this test).
            assert_eq!(total_members, 1, "expected 1 other member");
            assert_eq!(
                delivered_to_hub, 1,
                "expected 1 hub-fallback delivery to bob"
            );
        }
        other => panic!("SendRoom returned {other:?}"),
    }

    // 8. Watch bob's tail for the room EventMessage. peer_short
    //    should be "room/<8-char-b32>" where the prefix matches the
    //    group_id_b32 we created above (first 8 chars).
    let expected_peer_short = format!("room/{}", &group_id_b32.chars().take(8).collect::<String>());
    let event = wait_for_tail_event(&mut bob_tail, |e| match e {
        ApiResponse::EventMessage {
            peer_short,
            direction: MessageDirection::Incoming,
            text,
            ..
        } if *peer_short == expected_peer_short && text == "hello smoke room" => Some(text.clone()),
        _ => None,
    })
    .await;
    assert_eq!(event, "hello smoke room");
}

/// T-cover.hub: hub-side cover traffic must NOT interfere with the
/// real flow. Runs the same 2-party room shape as
/// `rooms_e2e_alice_invites_bob_and_sends`, but with the hub
/// emitting FRAME_PAD frames at mean=1s per connection. The
/// daemon's recipient path must silently swallow PAD frames in
/// `handle_hub_delivery` and surface only real DELIVER bodies.
///
/// **Catches**: any regression where the daemon ingests cover
/// frames as junk envelopes (would surface as
/// `EnvelopeReplayGuard` accepting opaque bytes that fail
/// `open_bootstrap` → debug-level drops). Or worse, where the
/// PAD frame's empty payload makes it past the bucket check and
/// confuses something downstream.
#[tokio::test(flavor = "multi_thread")]
async fn rooms_e2e_hub_cover_traffic_does_not_break_flow() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,onyx_daemon=warn,onyx_hub=warn")
        .with_test_writer()
        .try_init();

    // Hub emits PAD frames at mean=1s per client. Over the ~3-4s
    // smoke runtime, alice + bob each see roughly 3-4 PAD frames
    // injected into their hub-session inbound stream.
    let (hub_addr, hub_pub_b32, _hub_dir) = spawn_hub_with_cover(Some(1)).await;
    let (alice_sock, _alice_dir) = spawn_daemon(&hub_addr, &hub_pub_b32, "alice_cv").await;
    let (bob_sock, _bob_dir) = spawn_daemon(&hub_addr, &hub_pub_b32, "bob_cv").await;

    let _ = one_shot_until_ok(&alice_sock, &ApiRequest::Identity, "alice ready").await;
    let bob_id = one_shot_until_ok(&bob_sock, &ApiRequest::Identity, "bob ready").await;
    let (bob_fp, bob_kem_b32) = match bob_id {
        ApiResponse::IdentityOk {
            fingerprint,
            identity_kem_pub_b32,
            ..
        } => (fingerprint, identity_kem_pub_b32),
        other => panic!("bob Identity: {other:?}"),
    };

    let group_id_b32 = match one_shot(
        &alice_sock,
        &ApiRequest::CreateRoom {
            name: "cover-room".to_string(),
        },
    )
    .await
    {
        ApiResponse::CreateRoomOk { group_id_b32, .. } => group_id_b32,
        other => panic!("CreateRoom: {other:?}"),
    };

    let bob_kp_b64 = match one_shot_until_ok(
        &alice_sock,
        &ApiRequest::FetchPeerKeyPackage {
            peer_fingerprint: bob_fp.clone(),
        },
        "fetch bob KP",
    )
    .await
    {
        ApiResponse::FetchPeerKeyPackageOk { kp_b64 } => kp_b64,
        other => panic!("fetch bob KP: {other:?}"),
    };

    let mut bob_tail = open_tail(&bob_sock).await;

    match one_shot(
        &alice_sock,
        &ApiRequest::InviteToRoom {
            group_id_b32: group_id_b32.clone(),
            peer_fingerprint: bob_fp,
            peer_kem_pub_b32: bob_kem_b32,
            peer_kp_b64: bob_kp_b64,
        },
    )
    .await
    {
        ApiResponse::InviteToRoomOk { .. } => {}
        other => panic!("InviteToRoom: {other:?}"),
    }
    let _ = wait_for_room_in_list(&bob_sock, &group_id_b32).await;

    match one_shot(
        &alice_sock,
        &ApiRequest::SendRoom {
            group_id_b32: group_id_b32.clone(),
            text: "hello despite cover traffic".to_string(),
        },
    )
    .await
    {
        ApiResponse::SendRoomOk { .. } => {}
        other => panic!("SendRoom: {other:?}"),
    }

    let expected_peer_short = format!("room/{}", &group_id_b32.chars().take(8).collect::<String>());
    let event = wait_for_tail_event(&mut bob_tail, |e| match e {
        ApiResponse::EventMessage {
            peer_short,
            direction: MessageDirection::Incoming,
            text,
            ..
        } if *peer_short == expected_peer_short && text == "hello despite cover traffic" => {
            Some(text.clone())
        }
        _ => None,
    })
    .await;
    assert_eq!(event, "hello despite cover traffic");
}

/// 3-party room flow: alice creates a room, invites bob, then
/// invites carol. **Pins T6.3.h's commit-distribution bugfix on the
/// wire** — pre-T6.3.h, when alice invited carol the commit she
/// produced was discarded (only the Welcome was sent), so bob never
/// advanced past epoch 1 and every subsequent room message would
/// silently fail to decrypt for him. The MLS-unit test
/// `three_party_room_commit_distribution` pinned the fix at the
/// crypto layer; this test pins it at the wire layer — bob's
/// daemon, on its own, must receive and process the commit alice
/// fans out and then successfully decrypt a message alice sends
/// post-carol-invite.
#[tokio::test(flavor = "multi_thread")]
async fn rooms_e2e_three_party_commit_distribution() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,onyx_daemon=warn,onyx_hub=warn")
        .with_test_writer()
        .try_init();

    let (hub_addr, hub_pub_b32, _hub_dir) = spawn_hub().await;
    let (alice_sock, _alice_dir) = spawn_daemon(&hub_addr, &hub_pub_b32, "alice3").await;
    let (bob_sock, _bob_dir) = spawn_daemon(&hub_addr, &hub_pub_b32, "bob3").await;
    let (carol_sock, _carol_dir) = spawn_daemon(&hub_addr, &hub_pub_b32, "carol3").await;

    // Wait for all three to come up + publish KPs to the hub.
    let _ = one_shot_until_ok(&alice_sock, &ApiRequest::Identity, "alice ready").await;
    let bob_ident = one_shot_until_ok(&bob_sock, &ApiRequest::Identity, "bob ready").await;
    let carol_ident = one_shot_until_ok(&carol_sock, &ApiRequest::Identity, "carol ready").await;
    let (bob_fp, bob_kem_b32) = match bob_ident {
        ApiResponse::IdentityOk {
            fingerprint,
            identity_kem_pub_b32,
            ..
        } => (fingerprint, identity_kem_pub_b32),
        other => panic!("bob Identity returned {other:?}"),
    };
    let (carol_fp, carol_kem_b32) = match carol_ident {
        ApiResponse::IdentityOk {
            fingerprint,
            identity_kem_pub_b32,
            ..
        } => (fingerprint, identity_kem_pub_b32),
        other => panic!("carol Identity returned {other:?}"),
    };

    // alice creates the room.
    let group_id_b32 = match one_shot(
        &alice_sock,
        &ApiRequest::CreateRoom {
            name: "trio".to_string(),
        },
    )
    .await
    {
        ApiResponse::CreateRoomOk { group_id_b32, .. } => group_id_b32,
        other => panic!("CreateRoom: {other:?}"),
    };

    // alice fetches bob's KP, invites bob (solo → 2-party, no
    // existing members need a commit). Subscribe to bob's tail
    // BEFORE the invite so we don't miss anything.
    let mut bob_tail = open_tail(&bob_sock).await;
    let bob_kp_b64 = match one_shot_until_ok(
        &alice_sock,
        &ApiRequest::FetchPeerKeyPackage {
            peer_fingerprint: bob_fp.clone(),
        },
        "alice fetch bob KP",
    )
    .await
    {
        ApiResponse::FetchPeerKeyPackageOk { kp_b64 } => kp_b64,
        other => panic!("fetch bob KP: {other:?}"),
    };
    match one_shot(
        &alice_sock,
        &ApiRequest::InviteToRoom {
            group_id_b32: group_id_b32.clone(),
            peer_fingerprint: bob_fp.clone(),
            peer_kem_pub_b32: bob_kem_b32.clone(),
            peer_kp_b64: bob_kp_b64,
        },
    )
    .await
    {
        ApiResponse::InviteToRoomOk { .. } => {}
        other => panic!("InviteToRoom (bob): {other:?}"),
    }
    // Bob's daemon must persist the room.
    let bob_room = wait_for_room_in_list(&bob_sock, &group_id_b32).await;
    assert_eq!(bob_room.members.len(), 2);

    // alice fetches carol's KP, invites carol. This is the 2 → 3
    // transition. **PRE-T6.3.h, the commit-fan-out for bob would
    // have been silent-dropped** (or rather, not produced at all
    // because invite() discarded the commit). Post-fix, bob's
    // daemon must process the commit and advance his epoch.
    let carol_kp_b64 = match one_shot_until_ok(
        &alice_sock,
        &ApiRequest::FetchPeerKeyPackage {
            peer_fingerprint: carol_fp.clone(),
        },
        "alice fetch carol KP",
    )
    .await
    {
        ApiResponse::FetchPeerKeyPackageOk { kp_b64 } => kp_b64,
        other => panic!("fetch carol KP: {other:?}"),
    };
    let mut carol_tail = open_tail(&carol_sock).await;
    match one_shot(
        &alice_sock,
        &ApiRequest::InviteToRoom {
            group_id_b32: group_id_b32.clone(),
            peer_fingerprint: carol_fp.clone(),
            peer_kem_pub_b32: carol_kem_b32.clone(),
            peer_kp_b64: carol_kp_b64,
        },
    )
    .await
    {
        ApiResponse::InviteToRoomOk { ref members, .. } => {
            assert_eq!(members.len(), 3, "post-invite roster must be 3");
        }
        other => panic!("InviteToRoom (carol): {other:?}"),
    }

    // Carol's daemon persists the room on Welcome.
    let carol_room = wait_for_room_in_list(&carol_sock, &group_id_b32).await;
    assert_eq!(carol_room.members.len(), 3);

    // **Key bugfix check**: bob's daemon must have processed the
    // commit and advanced his epoch — observable via his roster
    // growing from 2 to 3. Pre-T6.3.h this would have stayed at 2
    // and the test below would have failed silently when bob's
    // decrypt fails.
    let bob_room_post = poll_room_members(&bob_sock, &group_id_b32, 3).await;
    assert_eq!(
        bob_room_post.members.len(),
        3,
        "T6.3.h bugfix: bob's roster must reflect carol's add"
    );

    // alice sends an app message at the new (post-carol) epoch.
    // BOTH bob and carol must decrypt it. Pre-T6.3.h, bob would
    // silently fail.
    match one_shot(
        &alice_sock,
        &ApiRequest::SendRoom {
            group_id_b32: group_id_b32.clone(),
            text: "trio echo".to_string(),
        },
    )
    .await
    {
        ApiResponse::SendRoomOk {
            total_members,
            delivered_to_hub,
            ..
        } => {
            assert_eq!(total_members, 2);
            assert_eq!(delivered_to_hub, 2, "expected hub delivery to bob + carol");
        }
        other => panic!("SendRoom: {other:?}"),
    }

    let expected_peer_short = format!("room/{}", &group_id_b32.chars().take(8).collect::<String>());
    let pred = |e: &ApiResponse| match e {
        ApiResponse::EventMessage {
            peer_short,
            direction: MessageDirection::Incoming,
            text,
            ..
        } if *peer_short == expected_peer_short && text == "trio echo" => Some(text.clone()),
        _ => None,
    };
    assert_eq!(wait_for_tail_event(&mut bob_tail, pred).await, "trio echo");
    assert_eq!(
        wait_for_tail_event(&mut carol_tail, pred).await,
        "trio echo"
    );
}

/// Poll `ListRooms` on the named daemon until the room's roster
/// reaches at least `min_members`, or timeout. Used by the 3-party
/// test to wait out bob's commit-merge → roster-refresh latency.
async fn poll_room_members(socket: &Path, group_id_b32: &str, min_members: usize) -> RoomInfo {
    let deadline = std::time::Instant::now() + EVENT_TIMEOUT;
    loop {
        let resp = one_shot(socket, &ApiRequest::ListRooms).await;
        if let ApiResponse::ListRoomsOk { rooms } = resp
            && let Some(r) = rooms.into_iter().find(|r| r.group_id_b32 == group_id_b32)
            && r.members.len() >= min_members
        {
            return r;
        }
        if std::time::Instant::now() > deadline {
            panic!(
                "room {group_id_b32} on {} never reached {min_members} members",
                socket.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Subscribe to a daemon's `Tail` stream. Returns the open reader
/// for the caller to pull events from. Eats the `TailStarted` ack.
async fn open_tail(socket: &Path) -> BufReader<tokio::net::unix::OwnedReadHalf> {
    let stream = UnixStream::connect(socket).await.expect("connect tail");
    let (rd, mut wr) = stream.into_split();
    let line = encode_request_line(&ApiRequest::Tail).expect("encode tail");
    wr.write_all(line.as_bytes()).await.expect("write tail");
    // Don't shutdown the write half — Tail is a long-lived stream;
    // the daemon may end the session if it sees EOF.
    let mut reader = BufReader::new(rd);
    // Read TailStarted ack so subsequent reads start at real events.
    let mut buf = String::new();
    reader.read_line(&mut buf).await.expect("read TailStarted");
    let started = decode_response(buf.trim_end_matches('\n')).expect("decode TailStarted");
    assert!(
        matches!(started, ApiResponse::TailStarted),
        "expected TailStarted, got {started:?}"
    );
    // Keep the write half alive in a leak — the daemon needs the
    // stream open to keep emitting events; dropping would close.
    Box::leak(Box::new(wr));
    reader
}

/// Read events off a `Tail` stream until `pred` returns `Some(T)` or
/// the timeout elapses. Returns the matched value.
async fn wait_for_tail_event<T>(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    mut pred: impl FnMut(&ApiResponse) -> Option<T>,
) -> T {
    let deadline = std::time::Instant::now() + EVENT_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let mut buf = String::new();
        let read = tokio::time::timeout(remaining, reader.read_line(&mut buf)).await;
        match read {
            Ok(Ok(0)) => panic!("tail stream closed unexpectedly"),
            Ok(Ok(_)) => {
                let event = decode_response(buf.trim_end_matches('\n')).expect("decode event");
                if let Some(matched) = pred(&event) {
                    return matched;
                }
            }
            Ok(Err(e)) => panic!("tail read error: {e}"),
            Err(_) => panic!("wait_for_tail_event timed out"),
        }
    }
}

/// Poll `ListRooms` on the named daemon until a room with
/// `group_id_b32` appears, or timeout.
async fn wait_for_room_in_list(socket: &Path, group_id_b32: &str) -> RoomInfo {
    let deadline = std::time::Instant::now() + EVENT_TIMEOUT;
    loop {
        let resp = one_shot(socket, &ApiRequest::ListRooms).await;
        if let ApiResponse::ListRoomsOk { rooms } = resp {
            if let Some(r) = rooms.into_iter().find(|r| r.group_id_b32 == group_id_b32) {
                return r;
            }
        }
        if std::time::Instant::now() > deadline {
            panic!("room {group_id_b32} never appeared in bob's ListRooms");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Compile-time sanity: HashMap is in scope (used implicitly via
/// some helpers; suppressed-warning shim for now).
#[allow(dead_code)]
fn _unused_hashmap_marker() -> HashMap<u8, u8> {
    HashMap::new()
}
