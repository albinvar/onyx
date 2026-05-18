//! Post-Noise protocol flows.
//!
//! Once [`crate::transport::handshake_initiator`] /
//! [`crate::transport::handshake_responder`] has produced an
//! authenticated [`Session`] between two daemons, both sides need to
//! either **bootstrap** a fresh MLS group or **resume** an existing
//! one. This module owns that choreography.
//!
//! ## Wire protocol (initiator writes first)
//!
//! The initiator decides up front whether to bootstrap or resume,
//! based on its local state (does it have a record of a prior group
//! with this peer's X25519 static?). The initiator's **first frame
//! after Noise XK** announces the choice:
//!
//! ### Bootstrap (no prior group)
//! ```text
//! 1. I → R : FRAME_MLS_REQUEST_KP  (empty payload)
//! 2. R → I : FRAME_MLS_KP          (responder's MLS KeyPackage)
//! 3. I → R : FRAME_MLS_WELCOME     (welcome from initiator's invite)
//! 4. I → R : FRAME_MLS_APP         (first encrypted Application message)
//! 5. R → I : FRAME_MLS_APP         (reply)
//! ```
//!
//! ### Resume (existing group)
//! ```text
//! 1. I → R : FRAME_MLS_RESUME      (payload = group_id bytes)
//! 2. I → R : FRAME_MLS_APP         (encrypted Application message)
//! 3. R → I : FRAME_MLS_APP         (reply)
//! ```
//!
//! The responder reads the first frame, dispatches on its type, and
//! runs the matching path. After either path completes both sides
//! hold an [`MlsGroupState`] for the same group at the same epoch
//! (bootstrap → epoch 1; resume → whatever epoch the group is on).
//!
//! ## Identity-binding caveat (carry-forward)
//!
//! Each [`MlsParty`] still generates its own ED25519 — see
//! [`crate::mls`]'s module docs for the binding story.

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Error, Result};
use crate::mls::{MlsGroupState, MlsParty};
use crate::transport::{Session, read_frame, write_frame};
use crate::wire::{
    FRAME_MLS_APP, FRAME_MLS_KP, FRAME_MLS_REQUEST_KP, FRAME_MLS_RESUME, FRAME_MLS_WELCOME,
    InnerFrame,
};

/// Result of a successful flow. Unified across bootstrap and resume.
#[derive(Debug)]
pub struct ExchangeOutcome {
    /// The MLS group both sides are now operating in.
    pub group: MlsGroupState,
    /// Decrypted plaintext of the peer's message.
    pub peer_message: Vec<u8>,
    /// `true` if this exchange just *created* the group (bootstrap),
    /// `false` if it *resumed* an existing one. Daemons use this to
    /// decide whether to call `Vault::record_peer_group`.
    pub was_bootstrap: bool,
}

/// Drive the initiator side.
///
/// * `existing_group_id = None` → bootstrap path.
/// * `existing_group_id = Some(id)` → resume path: load that group
///   from the party's storage, send `FRAME_MLS_RESUME`, exchange
///   application messages directly.
///
/// `message` is sent as the initiator's first (encrypted) application
/// message in the group. The peer's reply is decrypted and returned
/// in [`ExchangeOutcome::peer_message`].
pub async fn initiator_exchange<S>(
    stream: &mut S,
    session: &mut Session,
    party: &MlsParty,
    existing_group_id: Option<&[u8]>,
    message: &[u8],
) -> Result<ExchangeOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Some(group_id) = existing_group_id {
        initiator_resume(stream, session, party, group_id, message).await
    } else {
        initiator_bootstrap(stream, session, party, message).await
    }
}

async fn initiator_bootstrap<S>(
    stream: &mut S,
    session: &mut Session,
    party: &MlsParty,
    greeting: &[u8],
) -> Result<ExchangeOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. Signal intent: bootstrap.
    write_frame(
        stream,
        session,
        &InnerFrame {
            frame_type: FRAME_MLS_REQUEST_KP,
            payload: Vec::new(),
        },
    )
    .await?;

    // 2. Receive peer's KeyPackage.
    let kp_frame = read_frame(stream, session).await?;
    if kp_frame.frame_type != FRAME_MLS_KP {
        return Err(Error::InvalidEncoding(
            "flows::initiator: expected FRAME_MLS_KP after REQUEST_KP",
        ));
    }

    // 3. Build group, invite, send Welcome.
    let mut group = party.create_group()?;
    let welcome_bytes = group.invite(party, &kp_frame.payload)?;
    write_frame(
        stream,
        session,
        &InnerFrame {
            frame_type: FRAME_MLS_WELCOME,
            payload: welcome_bytes,
        },
    )
    .await?;

    // 4. First encrypted application message.
    let app_ct = group.encrypt_application(party, greeting)?;
    write_frame(
        stream,
        session,
        &InnerFrame {
            frame_type: FRAME_MLS_APP,
            payload: app_ct,
        },
    )
    .await?;

    // 5. Read + decrypt reply.
    let reply_frame = read_frame(stream, session).await?;
    if reply_frame.frame_type != FRAME_MLS_APP {
        return Err(Error::InvalidEncoding(
            "flows::initiator: expected FRAME_MLS_APP reply",
        ));
    }
    let peer_message = group.decrypt_application(party, &reply_frame.payload)?;

    Ok(ExchangeOutcome {
        group,
        peer_message,
        was_bootstrap: true,
    })
}

async fn initiator_resume<S>(
    stream: &mut S,
    session: &mut Session,
    party: &MlsParty,
    group_id: &[u8],
    message: &[u8],
) -> Result<ExchangeOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Load the group BEFORE announcing — if we can't load it, fail
    // locally rather than starting a session the peer can't complete.
    let mut group = party.load_group(group_id)?.ok_or(Error::Internal(
        "flows::initiator: resume requested but group not in storage",
    ))?;

    // 1. Announce resume.
    write_frame(
        stream,
        session,
        &InnerFrame {
            frame_type: FRAME_MLS_RESUME,
            payload: group_id.to_vec(),
        },
    )
    .await?;

    // 2. Send encrypted application message.
    let app_ct = group.encrypt_application(party, message)?;
    write_frame(
        stream,
        session,
        &InnerFrame {
            frame_type: FRAME_MLS_APP,
            payload: app_ct,
        },
    )
    .await?;

    // 3. Read + decrypt reply.
    let reply_frame = read_frame(stream, session).await?;
    if reply_frame.frame_type != FRAME_MLS_APP {
        return Err(Error::InvalidEncoding(
            "flows::initiator: expected FRAME_MLS_APP reply on resume",
        ));
    }
    let peer_message = group.decrypt_application(party, &reply_frame.payload)?;

    Ok(ExchangeOutcome {
        group,
        peer_message,
        was_bootstrap: false,
    })
}

/// Drive the responder side.
///
/// Reads the first frame to dispatch:
/// * `FRAME_MLS_REQUEST_KP` → bootstrap path (send our KP, accept
///   Welcome, exchange).
/// * `FRAME_MLS_RESUME` → resume path (load the group named by the
///   payload, exchange).
pub async fn responder_exchange<S>(
    stream: &mut S,
    session: &mut Session,
    party: &MlsParty,
    reply: &[u8],
) -> Result<ExchangeOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let first = read_frame(stream, session).await?;
    match first.frame_type {
        FRAME_MLS_REQUEST_KP => responder_bootstrap(stream, session, party, reply).await,
        FRAME_MLS_RESUME => responder_resume(stream, session, party, &first.payload, reply).await,
        _ => Err(Error::InvalidEncoding(
            "flows::responder: unexpected first frame type (want REQUEST_KP or RESUME)",
        )),
    }
}

async fn responder_bootstrap<S>(
    stream: &mut S,
    session: &mut Session,
    party: &MlsParty,
    reply: &[u8],
) -> Result<ExchangeOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Send our KeyPackage.
    let kp_bytes = party.key_package_bytes()?;
    write_frame(
        stream,
        session,
        &InnerFrame {
            frame_type: FRAME_MLS_KP,
            payload: kp_bytes,
        },
    )
    .await?;

    // Receive Welcome + join group.
    let welcome_frame = read_frame(stream, session).await?;
    if welcome_frame.frame_type != FRAME_MLS_WELCOME {
        return Err(Error::InvalidEncoding(
            "flows::responder: expected FRAME_MLS_WELCOME",
        ));
    }
    let mut group = party.join_from_welcome(&welcome_frame.payload)?;

    // Receive + decrypt initiator's first application message.
    let app_frame = read_frame(stream, session).await?;
    if app_frame.frame_type != FRAME_MLS_APP {
        return Err(Error::InvalidEncoding(
            "flows::responder: expected FRAME_MLS_APP after WELCOME",
        ));
    }
    let peer_message = group.decrypt_application(party, &app_frame.payload)?;

    // Encrypt + send our reply.
    let reply_ct = group.encrypt_application(party, reply)?;
    write_frame(
        stream,
        session,
        &InnerFrame {
            frame_type: FRAME_MLS_APP,
            payload: reply_ct,
        },
    )
    .await?;

    Ok(ExchangeOutcome {
        group,
        peer_message,
        was_bootstrap: true,
    })
}

async fn responder_resume<S>(
    stream: &mut S,
    session: &mut Session,
    party: &MlsParty,
    group_id: &[u8],
    reply: &[u8],
) -> Result<ExchangeOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Load the named group from our storage. If we don't have it,
    // the connection cannot continue — surface as Internal so the
    // caller closes the connection. (A real client would probably
    // fall back to bootstrap; v0 just fails loudly so state drift
    // doesn't go silent.)
    let mut group = party.load_group(group_id)?.ok_or(Error::Internal(
        "flows::responder: resume request names a group we don't have",
    ))?;

    // Receive + decrypt application message.
    let app_frame = read_frame(stream, session).await?;
    if app_frame.frame_type != FRAME_MLS_APP {
        return Err(Error::InvalidEncoding(
            "flows::responder: expected FRAME_MLS_APP after RESUME",
        ));
    }
    let peer_message = group.decrypt_application(party, &app_frame.payload)?;

    // Encrypt + send our reply.
    let reply_ct = group.encrypt_application(party, reply)?;
    write_frame(
        stream,
        session,
        &InnerFrame {
            frame_type: FRAME_MLS_APP,
            payload: reply_ct,
        },
    )
    .await?;

    Ok(ExchangeOutcome {
        group,
        peer_message,
        was_bootstrap: false,
    })
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::IdentitySecret;
    use crate::transport::{handshake_initiator, handshake_responder};

    /// First flow: bootstrap. Same as the original
    /// `mls_over_noise_round_trip`, modulo the new ExchangeOutcome
    /// shape and the new bootstrap-direction frames.
    #[allow(clippy::similar_names)]
    #[tokio::test]
    async fn bootstrap_round_trip() {
        let alice_sk = IdentitySecret::generate();
        let bob_sk = IdentitySecret::generate();
        let bob_pk = bob_sk.public();

        let (mut alice_io, mut bob_io) = tokio::io::duplex(65_536);

        let alice_task = tokio::spawn(async move {
            let mut session = handshake_initiator(&mut alice_io, &alice_sk, &bob_pk)
                .await
                .unwrap();
            let alice_party = MlsParty::new(b"alice".to_vec()).unwrap();
            let outcome = initiator_exchange(
                &mut alice_io,
                &mut session,
                &alice_party,
                None,
                b"hello bob",
            )
            .await
            .unwrap();
            (
                outcome.group.epoch(),
                outcome.peer_message,
                outcome.was_bootstrap,
            )
        });

        let bob_task = tokio::spawn(async move {
            let mut session = handshake_responder(&mut bob_io, &bob_sk).await.unwrap();
            let bob_party = MlsParty::new(b"bob".to_vec()).unwrap();
            let outcome = responder_exchange(&mut bob_io, &mut session, &bob_party, b"hello alice")
                .await
                .unwrap();
            (
                outcome.group.epoch(),
                outcome.peer_message,
                outcome.was_bootstrap,
            )
        });

        let (alice, bob) = tokio::join!(alice_task, bob_task);
        let (alice_epoch, alice_peer, alice_bootstrap) = alice.unwrap();
        let (bob_epoch, bob_peer, bob_bootstrap) = bob.unwrap();

        assert_eq!(bob_peer, b"hello bob");
        assert_eq!(alice_peer, b"hello alice");
        assert_eq!(alice_epoch, bob_epoch);
        assert_eq!(alice_epoch, 1);
        assert!(alice_bootstrap);
        assert!(bob_bootstrap);
    }

    /// The killer test for T2.4: bootstrap a group, snapshot both
    /// parties, drop everything, restore from snapshots, **then
    /// resume** the same group via the new FRAME_MLS_RESUME path.
    /// Both sides exchange a new application message in the resumed
    /// group, decrypt correctly, and report `was_bootstrap == false`.
    #[allow(clippy::similar_names)]
    #[tokio::test]
    async fn bootstrap_then_snapshot_then_resume() {
        use crate::identity::Identity;

        // Fixed seeds so we can reconstruct the same identities twice
        // (Identity is intentionally not Clone — secrets aren't
        // casually duplicated — so we rebuild from the seeds).
        let alice_signing = [7u8; 32];
        let alice_x = [8u8; 32];
        let bob_signing = [17u8; 32];
        let bob_x_seed = [18u8; 32];

        // ── Round 1: bootstrap ────────────────────────────────────────────
        let bob_x_pub_round1 = IdentitySecret::from_bytes(bob_x_seed).public();
        let alice_id1 = Identity::from_seeds(&alice_signing, alice_x);
        let bob_id1 = Identity::from_seeds(&bob_signing, bob_x_seed);
        let alice_noise_sk1 = IdentitySecret::from_bytes(alice_x);
        let bob_noise_sk1 = IdentitySecret::from_bytes(bob_x_seed);
        let (mut a_io, mut b_io) = tokio::io::duplex(65_536);

        let alice_handle = tokio::spawn(async move {
            let mut session = handshake_initiator(&mut a_io, &alice_noise_sk1, &bob_x_pub_round1)
                .await
                .unwrap();
            let party = MlsParty::from_identity(&alice_id1).unwrap();
            let outcome = initiator_exchange(&mut a_io, &mut session, &party, None, b"hello bob 1")
                .await
                .unwrap();
            assert!(outcome.was_bootstrap);
            let group_id = outcome.group.group_id_bytes();
            let snap = party.snapshot_state().unwrap();
            (group_id, (*snap).clone())
        });

        let bob_handle = tokio::spawn(async move {
            let mut session = handshake_responder(&mut b_io, &bob_noise_sk1)
                .await
                .unwrap();
            let party = MlsParty::from_identity(&bob_id1).unwrap();
            let outcome = responder_exchange(&mut b_io, &mut session, &party, b"hello alice 1")
                .await
                .unwrap();
            assert!(outcome.was_bootstrap);
            let snap = party.snapshot_state().unwrap();
            (*snap).clone()
        });

        let (alice_result, bob_state) = tokio::join!(alice_handle, bob_handle);
        let (group_id_bytes, alice_state) = alice_result.unwrap();
        let bob_state = bob_state.unwrap();
        assert!(!group_id_bytes.is_empty());

        // ── Round 2: resume — fresh duplex, parties restored from snapshots ──
        let bob_x_pub_round2 = IdentitySecret::from_bytes(bob_x_seed).public();
        let alice_id2 = Identity::from_seeds(&alice_signing, alice_x);
        let bob_id2 = Identity::from_seeds(&bob_signing, bob_x_seed);
        let alice_noise_sk2 = IdentitySecret::from_bytes(alice_x);
        let bob_noise_sk2 = IdentitySecret::from_bytes(bob_x_seed);
        let (mut a_io, mut b_io) = tokio::io::duplex(65_536);

        let group_id_for_alice = group_id_bytes.clone();
        let alice2 = tokio::spawn(async move {
            let mut session = handshake_initiator(&mut a_io, &alice_noise_sk2, &bob_x_pub_round2)
                .await
                .unwrap();
            let party = MlsParty::from_identity_and_state(&alice_id2, &alice_state).unwrap();
            let outcome = initiator_exchange(
                &mut a_io,
                &mut session,
                &party,
                Some(&group_id_for_alice),
                b"hello bob 2 (resumed)",
            )
            .await
            .unwrap();
            (outcome.peer_message, outcome.was_bootstrap)
        });

        let bob2 = tokio::spawn(async move {
            let mut session = handshake_responder(&mut b_io, &bob_noise_sk2)
                .await
                .unwrap();
            let party = MlsParty::from_identity_and_state(&bob_id2, &bob_state).unwrap();
            let outcome =
                responder_exchange(&mut b_io, &mut session, &party, b"hello alice 2 (resumed)")
                    .await
                    .unwrap();
            (outcome.peer_message, outcome.was_bootstrap)
        });

        let (a, b) = tokio::join!(alice2, bob2);
        let (alice_peer, alice_bootstrap) = a.unwrap();
        let (bob_peer, bob_bootstrap) = b.unwrap();

        assert!(
            !alice_bootstrap,
            "alice resumed; bootstrap flag must be false"
        );
        assert!(!bob_bootstrap, "bob resumed; bootstrap flag must be false");
        assert_eq!(bob_peer, b"hello bob 2 (resumed)");
        assert_eq!(alice_peer, b"hello alice 2 (resumed)");
    }
}
