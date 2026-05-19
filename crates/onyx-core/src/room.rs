//! Room-tier in-group application messages (T6.3.h).
//!
//! Every room app message — the plaintext that goes into
//! `MlsGroupState::encrypt_application` — is a CBOR-encoded
//! [`RoomAppMessage`] rather than raw UTF-8. The tagged-union shape
//! gives us a forward-compatible plaintext-side wire format for the
//! room: we can add new message types (typing, presence, room
//! metadata changes) without coordinated upgrades, because pre-
//! existing recipients drop unknown tags.
//!
//! v0 carries two variants:
//!
//!   * [`RoomAppMessage::Text`] — what the user typed. This is what
//!     `onyx room send` produces and what the TUI surfaces.
//!   * [`RoomAppMessage::KemAdvertisement`] — sender announces a
//!     room member's hybrid KEM public key to every other member.
//!     Driven by `handle_invite_to_room` so existing members learn
//!     a new joiner's KEM and can hub-fallback to them. Recipients
//!     persist the (fingerprint, kem_pub) pair into
//!     `Vault::save_room_member_kem`.
//!
//! ## Why a structured plaintext, not raw bytes
//!
//! T6.3.d shipped with raw UTF-8 as the room app plaintext. That
//! choice did not survive contact with T6.3.h's KEM-advertisement
//! need — we want existing members to learn new members' KEMs over
//! the same MLS ratchet they use for chat, but a raw-UTF-8
//! plaintext leaves no room for a structured "this is metadata, not
//! a chat line" discriminator. Reaching for "wrap it in JSON or
//! some sentinel prefix" works but is brittle.
//!
//! CBOR with serde-tagged enums was already the choice for
//! `BootstrapPayload` (the hub envelope's inner format) so the
//! pattern is familiar. The tagged-enum layout means recipients
//! that don't know a tag fail at decode-time with `InvalidEncoding`
//! and surface a debug log — never a misinterpretation.
//!
//! ## Wire-format compatibility
//!
//! T6.3.h supersedes T6.3.d's raw-UTF-8 plaintext **with no back-
//! compat layer**. v0 has no installed base of room messages — T6.3
//! only just shipped, so a coordinated cutover is the simplest and
//! cleanest path. Recipients on the CBOR-aware code (post-T6.3.h)
//! drop pre-T6.3.h plaintexts as `InvalidEncoding` at debug level
//! (no user-visible message, no log spam).

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::error::{Error, Result};

/// One in-room application message, before MLS encryption. CBOR-
/// encoded with `#[serde(tag = "kind")]` so every encoded payload
/// is self-describing — recipients that don't know a variant fail
/// at decode-time rather than misinterpreting bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum RoomAppMessage {
    /// User-typed chat text. The only variant that surfaces to the
    /// TUI / `Tail` subscribers as an `EventMessage`.
    Text { text: String },
    /// KEM-public-key advertisement (T6.3.h). The sender tells every
    /// other room member "member `fingerprint` has hybrid KEM pub
    /// `kem_pub`" so they can hub-fallback to that member when the
    /// member is offline. Recipients persist this to
    /// `Vault::save_room_member_kem` keyed by the room's group_id
    /// and `fingerprint`.
    ///
    /// Authenticity comes from the MLS ratchet itself — the message
    /// is encrypted under the group's epoch keys, so only a current
    /// member could have produced it. A malicious member *could*
    /// advertise a wrong KEM under another member's fingerprint, but
    /// the worst-case outcome is "messages to that member via hub
    /// don't decrypt on the victim's side" — sender authenticity
    /// is preserved by the outer Ed25519 sealed-envelope signature,
    /// and the victim's MLS state stays intact. This is not a
    /// trust-boundary expansion: any room member could already
    /// silently drop messages or commit a malicious epoch.
    KemAdvertisement {
        fingerprint: String,
        kem_pub: ByteBuf,
    },
}

impl RoomAppMessage {
    /// Encode as CBOR for MLS encryption.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out)
            .map_err(|_| Error::Internal("room-app: CBOR encode failed"))?;
        Ok(out)
    }

    /// Decode an MLS-decrypted plaintext into a typed message.
    /// Returns [`Error::InvalidEncoding`] on non-CBOR bytes or an
    /// unknown tag.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes)
            .map_err(|_| Error::InvalidEncoding("room-app: CBOR decode failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trip() {
        let m = RoomAppMessage::Text {
            text: "hello room".into(),
        };
        let bytes = m.to_cbor().unwrap();
        assert_eq!(RoomAppMessage::from_cbor(&bytes).unwrap(), m);
    }

    #[test]
    fn kem_advertisement_round_trip() {
        let m = RoomAppMessage::KemAdvertisement {
            fingerprint: "AAAA-BBBB-CCCC-DDDD".into(),
            kem_pub: ByteBuf::from(vec![0x42u8; 1216]),
        };
        let bytes = m.to_cbor().unwrap();
        assert_eq!(RoomAppMessage::from_cbor(&bytes).unwrap(), m);
    }

    #[test]
    fn text_carries_kind_tag() {
        let m = RoomAppMessage::Text { text: "x".into() };
        let bytes = m.to_cbor().unwrap();
        let s = String::from_utf8_lossy(&bytes);
        assert!(
            s.contains("Text") && s.contains("kind"),
            "Text variant must carry its kind tag; got {bytes:?}"
        );
    }

    #[test]
    fn kem_ad_carries_kind_tag() {
        let m = RoomAppMessage::KemAdvertisement {
            fingerprint: "fp".into(),
            kem_pub: ByteBuf::from(vec![1u8; 4]),
        };
        let bytes = m.to_cbor().unwrap();
        let s = String::from_utf8_lossy(&bytes);
        assert!(
            s.contains("KemAdvertisement"),
            "KemAdvertisement variant must carry its kind tag; got {bytes:?}"
        );
    }

    #[test]
    fn from_cbor_rejects_garbage() {
        assert!(RoomAppMessage::from_cbor(&[]).is_err());
        assert!(RoomAppMessage::from_cbor(b"definitely not cbor").is_err());
    }

    #[test]
    fn from_cbor_rejects_unknown_tag() {
        // Build a CBOR map with kind="UnknownFuture" — recipients
        // must drop rather than misinterpret.
        let mut bytes = Vec::new();
        ciborium::into_writer(
            &ciborium::Value::Map(vec![(
                ciborium::Value::Text("kind".into()),
                ciborium::Value::Text("UnknownFuture".into()),
            )]),
            &mut bytes,
        )
        .unwrap();
        assert!(RoomAppMessage::from_cbor(&bytes).is_err());
    }
}
