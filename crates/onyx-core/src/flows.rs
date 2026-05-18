//! Post-Noise protocol flows.
//!
//! Once [`crate::transport::handshake_initiator`] /
//! [`crate::transport::handshake_responder`] has produced an
//! authenticated [`Session`] between two daemons, both sides need to
//! bootstrap a shared MLS group before any **content** can travel
//! end-to-end-encrypted. This module owns that choreography.
//!
//! ## Why an extra layer
//!
//! Noise XK already gives us:
//!
//!   * Mutual authentication of long-term X25519 static keys.
//!   * Forward-secret AEAD framing for the lifetime of the connection.
//!
//! On top of that, MLS adds:
//!
//!   * A group (1-on-1 at v0 = 2-member group, scales to rooms later).
//!   * Per-message forward secrecy + post-compromise security via
//!     ratchet trees and per-commit epoch transitions.
//!   * A persistent group identity that survives reconnection — the
//!     Noise channel is bound to one TCP/Tor circuit; MLS state isn't.
//!
//! Wrapping MLS inside Noise means even a hub that proxies our frames
//! sees only encrypted MLS ciphertexts, not even who is sending what
//! within the connection.
//!
//! ## Wire protocol
//!
//! After Noise XK completes, this 4-frame exchange runs over the
//! Session:
//!
//! ```text
//!   1. R → I : FRAME_MLS_KP        (responder's MLS KeyPackage)
//!   2. I → R : FRAME_MLS_WELCOME   (welcome from initiator's group invite)
//!   3. I → R : FRAME_MLS_APP       (first encrypted Application message)
//!   4. R → I : FRAME_MLS_APP       (reply Application message)
//! ```
//!
//! After step 4 both sides are members of the same MLS group at the
//! same epoch. Subsequent `FRAME_MLS_APP` frames can flow freely in
//! either direction without further state exchange.
//!
//! ## Identity-binding caveat (v0)
//!
//! Each [`MlsParty`] currently generates a fresh ED25519 signature
//! keypair for its MLS credential, separate from the Noise X25519
//! static. So the MLS credential is *not* yet provably bound to the
//! same identity that authenticated at the Noise layer. The Noise
//! handshake provides X25519-static auth; until we bind the MLS
//! credential to our long-term Ed25519 fingerprint, an attacker who
//! controls the network between two trusting daemons could not
//! inject — but a malicious **endpoint** could lie about which MLS
//! identity it owns. This is fine for the smoke tests; it needs to
//! land before any release.

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Error, Result};
use crate::mls::{MlsGroupState, MlsParty};
use crate::transport::{Session, read_frame, write_frame};
use crate::wire::{FRAME_MLS_APP, FRAME_MLS_KP, FRAME_MLS_WELCOME, InnerFrame};

/// Result of a successful initiator-side exchange.
#[derive(Debug)]
pub struct InitiatorExchange {
    /// The MLS group the initiator has just created and the responder
    /// has just joined.
    pub group: MlsGroupState,
    /// The decrypted plaintext of the responder's reply message.
    pub peer_reply: Vec<u8>,
}

/// Drive the initiator side of the post-Noise MLS bootstrap.
///
/// Steps (1 → 2 → 3 → 4 in the module-level diagram):
///
/// 1. Read the responder's KeyPackage.
/// 2. Create an MLS group, invite the responder using their KP, send
///    the resulting Welcome message.
/// 3. Encrypt `greeting` as the first Application message in the
///    new group and send it.
/// 4. Read the responder's encrypted reply, decrypt it.
pub async fn initiator_exchange<S>(
    stream: &mut S,
    session: &mut Session,
    party: &MlsParty,
    greeting: &[u8],
) -> Result<InitiatorExchange>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. Receive peer's KeyPackage.
    let kp_frame = read_frame(stream, session).await?;
    if kp_frame.frame_type != FRAME_MLS_KP {
        return Err(Error::InvalidEncoding(
            "flows::initiator: expected FRAME_MLS_KP from responder",
        ));
    }

    // 2. Build the group and invite the peer.
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

    // 3. Send the first encrypted application message in the group.
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

    // 4. Receive and decrypt the responder's reply.
    let reply_frame = read_frame(stream, session).await?;
    if reply_frame.frame_type != FRAME_MLS_APP {
        return Err(Error::InvalidEncoding(
            "flows::initiator: expected FRAME_MLS_APP reply from responder",
        ));
    }
    let peer_reply = group.decrypt_application(party, &reply_frame.payload)?;

    Ok(InitiatorExchange { group, peer_reply })
}

/// Result of a successful responder-side exchange.
#[derive(Debug)]
pub struct ResponderExchange {
    /// The MLS group the responder has just joined.
    pub group: MlsGroupState,
    /// The decrypted plaintext of the initiator's greeting.
    pub peer_message: Vec<u8>,
}

/// Drive the responder side of the post-Noise MLS bootstrap.
///
/// Steps (mirror of [`initiator_exchange`]):
///
/// 1. Send our KeyPackage to the initiator.
/// 2. Receive the Welcome and join the group it describes.
/// 3. Receive the initiator's first encrypted Application message,
///    decrypt it.
/// 4. Encrypt `reply` and send it as our first Application message.
pub async fn responder_exchange<S>(
    stream: &mut S,
    session: &mut Session,
    party: &MlsParty,
    reply: &[u8],
) -> Result<ResponderExchange>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. Send our KeyPackage so the initiator can invite us.
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

    // 2. Receive the Welcome and join the group.
    let welcome_frame = read_frame(stream, session).await?;
    if welcome_frame.frame_type != FRAME_MLS_WELCOME {
        return Err(Error::InvalidEncoding(
            "flows::responder: expected FRAME_MLS_WELCOME from initiator",
        ));
    }
    let mut group = party.join_from_welcome(&welcome_frame.payload)?;

    // 3. Receive and decrypt the initiator's first application message.
    let app_frame = read_frame(stream, session).await?;
    if app_frame.frame_type != FRAME_MLS_APP {
        return Err(Error::InvalidEncoding(
            "flows::responder: expected FRAME_MLS_APP from initiator",
        ));
    }
    let peer_message = group.decrypt_application(party, &app_frame.payload)?;

    // 4. Send our encrypted reply.
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

    Ok(ResponderExchange {
        group,
        peer_message,
    })
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::IdentitySecret;
    use crate::transport::{handshake_initiator, handshake_responder};

    /// Full end-to-end exercise of every layer in the daemon's data
    /// path, minus only the Tor stream itself (which we replace with a
    /// `tokio::io::duplex` pair):
    ///
    ///   * Noise XK handshake produces a [`Session`] on each side.
    ///   * `responder_exchange` + `initiator_exchange` complete the
    ///     MLS bootstrap.
    ///   * Both sides decrypt the other's first MLS Application message
    ///     and the plaintext matches what was sent.
    ///   * Both sides end up at MLS epoch 1 (group created at epoch 0,
    ///     advanced once by the add).
    #[allow(clippy::similar_names)] // alice / bob _sk / _pk are intentional
    #[tokio::test]
    async fn mls_over_noise_round_trip() {
        let alice_sk = IdentitySecret::generate();
        let bob_sk = IdentitySecret::generate();
        let bob_pk = bob_sk.public();

        let (mut alice_io, mut bob_io) = tokio::io::duplex(65_536);

        let alice_task = tokio::spawn(async move {
            let mut session = handshake_initiator(&mut alice_io, &alice_sk, &bob_pk)
                .await
                .expect("alice noise");
            let alice_party = MlsParty::new(b"alice".to_vec()).expect("alice mls");
            let outcome = initiator_exchange(
                &mut alice_io,
                &mut session,
                &alice_party,
                b"hello bob via mls",
            )
            .await
            .expect("alice flow");
            (outcome.group.epoch(), outcome.peer_reply)
        });

        let bob_task = tokio::spawn(async move {
            let mut session = handshake_responder(&mut bob_io, &bob_sk)
                .await
                .expect("bob noise");
            let bob_party = MlsParty::new(b"bob".to_vec()).expect("bob mls");
            let outcome = responder_exchange(
                &mut bob_io,
                &mut session,
                &bob_party,
                b"hello alice via mls",
            )
            .await
            .expect("bob flow");
            (outcome.group.epoch(), outcome.peer_message)
        });

        let (alice_result, bob_result) = tokio::join!(alice_task, bob_task);
        let (alice_epoch, alice_peer_reply) = alice_result.unwrap();
        let (bob_epoch, bob_peer_message) = bob_result.unwrap();

        assert_eq!(bob_peer_message, b"hello bob via mls");
        assert_eq!(alice_peer_reply, b"hello alice via mls");
        assert_eq!(
            alice_epoch, bob_epoch,
            "both members must be at the same MLS epoch after the bootstrap"
        );
        assert_eq!(alice_epoch, 1, "epoch should advance from 0 to 1 on add");
    }
}
