//! Wire envelope, frame types, and CBOR codec.
//!
//! Two concerns live in this module:
//!
//!   * [`InnerFrame`] — the byte layout that sits **inside** the AEAD
//!     envelope (DESIGN.md §5.3, revised in v0.2). It owns the
//!     `type ‖ length ‖ payload ‖ zero-pad` plaintext that
//!     [`crate::transport`] later wraps in ChaCha20-Poly1305.
//!   * [`MessageEnvelope`] — the CBOR-encoded body of a `DELIVER` frame
//!     (DESIGN.md §5.4). Carries the MLS ciphertext, routing IDs, padding
//!     hint, and (for non-bootstrap) the sender's Ed25519 signature.
//!
//! Both layers refuse to silently truncate or grow input; size limits are
//! checked at the function boundary and surface as [`Error::InvalidEncoding`]
//! or [`Error::BufferSize`].

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::error::{Error, Result};

// ── Frame-type discriminators ──────────────────────────────────────────────

/// `HELLO` — client → server, initial protocol version negotiation.
pub const FRAME_HELLO: u16 = 0x01;
/// `HELLO_ACK` — server → client, accept and assign session id.
pub const FRAME_HELLO_ACK: u16 = 0x02;
/// `DELIVER` — either direction, MLS-encrypted application message.
///
/// **Hub-mode payload layout**: `target_routing_id (16 B) ‖ body`.
/// The body is opaque to the hub — typically a [`MessageEnvelope`]
/// CBOR encoding but the hub doesn't parse it. The hub preserves the
/// target prefix when forwarding to subscribers so a client listening
/// on more than one routing ID can tell which subscription matched;
/// the receiving client strips the prefix before decrypting.
///
/// **P2P payload layout**: the full [`MessageEnvelope`] CBOR (no
/// target prefix — the connection itself identifies the peer).
pub const FRAME_DELIVER: u16 = 0x10;
/// `ACK` — either direction, acknowledges a DELIVER.
pub const FRAME_ACK: u16 = 0x11;
/// `FETCH` — client → hub, pull queued messages.
pub const FRAME_FETCH: u16 = 0x20;
/// `FETCH_RESPONSE` — hub → client, batch of queued messages.
pub const FRAME_FETCH_RESPONSE: u16 = 0x21;
/// `SUBSCRIBE` — client → hub, register routing tokens for live delivery.
///
/// Payload is **N × 16-byte routing IDs concatenated** (no length
/// prefix; the outer frame length gives the total). On receipt the
/// hub registers this connection for live delivery to each routing
/// ID and immediately flushes any queued messages for them.
pub const FRAME_SUBSCRIBE: u16 = 0x22;
/// `ROOM_OP` — client → hub, create/join/leave/admin a room.
pub const FRAME_ROOM_OP: u16 = 0x30;
/// `ROOM_OP_ACK` — hub → client, result of a room op.
pub const FRAME_ROOM_OP_ACK: u16 = 0x31;
/// `PING` — either direction, keepalive.
pub const FRAME_PING: u16 = 0x40;
/// `PONG` — either direction, keepalive response.
pub const FRAME_PONG: u16 = 0x41;
/// `PAD` — either direction, cover traffic. Discarded by receiver.
pub const FRAME_PAD: u16 = 0xF0;
/// `ERROR` — either direction, protocol error; receiver closes the connection.
pub const FRAME_ERROR: u16 = 0xFF;
/// `MLS_KP` — payload is a TLS-serialised MLS KeyPackage. Sent by a
/// peer announcing it can be invited to an MLS group. See
/// [`crate::flows`] for the surrounding protocol.
pub const FRAME_MLS_KP: u16 = 0x100;
/// `MLS_WELCOME` — payload is a TLS-serialised MLS Welcome message.
/// Sent by the inviter so the invitee can join the group.
pub const FRAME_MLS_WELCOME: u16 = 0x101;
/// `MLS_APP` — payload is an MLS application-message ciphertext. Both
/// directions; safe to send any number of times once both sides are in
/// the same MLS group at the same epoch.
pub const FRAME_MLS_APP: u16 = 0x102;
/// `MLS_REQUEST_KP` — initiator → responder, empty payload. Signals
/// "I want to bootstrap a fresh MLS group with you; send your
/// KeyPackage." Sent as the very first frame after Noise XK when the
/// initiator has no prior MLS group with this peer.
pub const FRAME_MLS_REQUEST_KP: u16 = 0x103;
/// `MLS_RESUME` — initiator → responder, payload is the bytes of an
/// existing MLS `GroupId`. Signals "let's continue using group X
/// (which both of us should already have state for); next frame is
/// an `MLS_APP` ciphertext." Sent as the very first frame after Noise
/// XK when the initiator has a prior MLS group with this peer.
pub const FRAME_MLS_RESUME: u16 = 0x104;

// ── Padding buckets (DESIGN.md §5.8) ───────────────────────────────────────

/// Plaintext bucket sizes. Inner plaintext is zero-padded to one of these
/// before AEAD encryption, so the on-wire size always reveals only the
/// bucket — not the payload length within it.
pub mod bucket {
    pub const SMALL: usize = 256;
    pub const MEDIUM: usize = 1024;
    pub const LARGE: usize = 4096;
}

/// Inner header size: 2-byte frame type + 2-byte payload length.
pub const INNER_HEADER_LEN: usize = 4;

/// Maximum payload (after the inner header) for each bucket.
pub mod max_payload {
    use super::{INNER_HEADER_LEN, bucket};
    pub const SMALL: usize = bucket::SMALL - INNER_HEADER_LEN; // 252
    pub const MEDIUM: usize = bucket::MEDIUM - INNER_HEADER_LEN; // 1020
    pub const LARGE: usize = bucket::LARGE - INNER_HEADER_LEN; // 4092
}

// ── InnerFrame ─────────────────────────────────────────────────────────────

/// The plaintext that goes inside the AEAD envelope on the wire.
///
/// Byte layout after [`encode_padded`]:
///
/// ```text
/// 0       2         4                              N
/// ┌───────┬─────────┬──────────────────────────────┐
/// │ type  │ pld_len │ payload                      │
/// │ u16BE │ u16BE   │ pld_len bytes                │
/// └───────┴─────────┴──────────────────────────────┘
///                    │← zero-padded to bucket size →│
/// ```
///
/// `N` is one of `bucket::{SMALL, MEDIUM, LARGE}` — never anything else.
/// The receiver MUST validate this before trusting the length prefix.
///
/// [`encode_padded`]: InnerFrame::encode_padded
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerFrame {
    pub frame_type: u16,
    pub payload: Vec<u8>,
}

impl InnerFrame {
    /// Smallest bucket that fits `header + payload`. `None` if the payload
    /// is larger than [`max_payload::LARGE`] — callers must chunk at that
    /// point (DESIGN.md §5.8).
    #[must_use]
    pub fn smallest_bucket(payload_len: usize) -> Option<usize> {
        let needed = INNER_HEADER_LEN.checked_add(payload_len)?;
        if needed <= bucket::SMALL {
            Some(bucket::SMALL)
        } else if needed <= bucket::MEDIUM {
            Some(bucket::MEDIUM)
        } else if needed <= bucket::LARGE {
            Some(bucket::LARGE)
        } else {
            None
        }
    }

    /// Bucket this frame will land in. Mirrors [`Self::smallest_bucket`] on
    /// `self.payload.len()`.
    #[must_use]
    pub fn bucket(&self) -> Option<usize> {
        Self::smallest_bucket(self.payload.len())
    }

    /// Encode to plaintext bytes, zero-padded to the smallest bucket that
    /// fits. The output length is always one of `bucket::*`.
    pub fn encode_padded(&self) -> Result<Vec<u8>> {
        let payload_len = self.payload.len();
        // u16 is the on-wire length encoding; we cap at u16::MAX before even
        // looking at the bucket so we never quietly truncate.
        if payload_len > u16::MAX as usize {
            return Err(Error::InvalidEncoding(
                "InnerFrame: payload longer than u16::MAX",
            ));
        }
        let bucket = Self::smallest_bucket(payload_len).ok_or(Error::InvalidEncoding(
            "InnerFrame: payload too large for any bucket — caller must chunk",
        ))?;

        let mut out = vec![0u8; bucket];
        out[0..2].copy_from_slice(&self.frame_type.to_be_bytes());
        // payload_len already validated to fit u16.
        #[allow(clippy::cast_possible_truncation)]
        let plen = payload_len as u16;
        out[2..4].copy_from_slice(&plen.to_be_bytes());
        out[INNER_HEADER_LEN..INNER_HEADER_LEN + payload_len].copy_from_slice(&self.payload);
        // Bytes past `INNER_HEADER_LEN + payload_len` are already zero from
        // the `vec![0u8; bucket]` initialisation. Padding is part of the
        // AEAD plaintext so any tamper there fails the tag.
        Ok(out)
    }

    /// Decode AEAD-decrypted plaintext into an [`InnerFrame`].
    ///
    /// Validates:
    ///   * `bytes.len()` is exactly one of `bucket::{SMALL, MEDIUM, LARGE}`.
    ///     A nonconforming length signals a hostile or corrupt frame even
    ///     before we touch its contents.
    ///   * The length prefix doesn't claim a payload longer than the bucket
    ///     can hold.
    ///
    /// We do NOT verify that the padding bytes are zero. The AEAD tag has
    /// already proven the entire bucket (header + payload + padding) is
    /// untampered; re-checking the pad would be redundant and would create
    /// a place to leak timing on otherwise-uniform plaintext.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != bucket::SMALL
            && bytes.len() != bucket::MEDIUM
            && bytes.len() != bucket::LARGE
        {
            return Err(Error::InvalidEncoding(
                "InnerFrame: length is not a recognised bucket",
            ));
        }
        // Bucket check above guarantees we have at least INNER_HEADER_LEN bytes.
        let frame_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        let pld_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;

        let max_allowed = bytes.len() - INNER_HEADER_LEN;
        if pld_len > max_allowed {
            return Err(Error::InvalidEncoding(
                "InnerFrame: declared payload length exceeds bucket",
            ));
        }

        let payload = bytes[INNER_HEADER_LEN..INNER_HEADER_LEN + pld_len].to_vec();
        Ok(Self {
            frame_type,
            payload,
        })
    }
}

// ── MessageEnvelope (DESIGN §5.4) ──────────────────────────────────────────

/// Current envelope protocol version. Bump when the field set changes.
pub const ENVELOPE_VERSION: u8 = 1;

/// Body of a `DELIVER` frame.
///
/// `from` and `sig` are `None` for the sealed-sender bootstrap envelope
/// addressed to an introduction inbox (DESIGN.md §5.5 Tier 1): there is no
/// stable sender-side routing identifier yet, and the recipient
/// authenticates the sender from the inner sealed-sender payload instead.
/// For all other deliveries — DMs after bootstrap, and rooms — both fields
/// MUST be present.
///
/// Field names are short ASCII strings (`"v"`, `"to"`, …) so the CBOR
/// encoding stays compact; the rename attributes pin them so renaming the
/// Rust fields cannot accidentally break the wire format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageEnvelope {
    /// Protocol version. Must equal [`ENVELOPE_VERSION`] on receipt.
    #[serde(rename = "v")]
    pub version: u8,

    /// Recipient routing identifier (introduction inbox OR rotating
    /// session token — DESIGN.md §5.5). 16 bytes when produced by
    /// `crate::crypto::blake2b_128`, but the type is variable-length to
    /// stay forward-compatible with longer IDs.
    #[serde(rename = "to")]
    pub to: ByteBuf,

    /// Sender routing identifier; `None` in the sealed-sender bootstrap case.
    #[serde(rename = "from", default, skip_serializing_if = "Option::is_none")]
    pub from: Option<ByteBuf>,

    /// Room identifier; `None` for DMs.
    #[serde(rename = "room", default, skip_serializing_if = "Option::is_none")]
    pub room: Option<ByteBuf>,

    /// Sender's clock, milliseconds since UNIX epoch. Advisory only —
    /// recipients should not enforce skew limits because that would let a
    /// hub-controlled clock censor messages.
    #[serde(rename = "ts")]
    pub timestamp_ms: u64,

    /// 12-byte anti-replay nonce. Typed as a byte string for serde compactness.
    #[serde(rename = "nonce")]
    pub nonce: ByteBuf,

    /// Padding bucket size the sender claims. The receiver also sees the
    /// actual on-wire length and SHOULD reject a mismatch.
    #[serde(rename = "pad_to")]
    pub pad_to: u16,

    /// MLS application or welcome ciphertext. Opaque at this layer —
    /// [`crate::mls`] does the actual decryption.
    #[serde(rename = "mls")]
    pub mls: ByteBuf,

    /// Ed25519 signature over the CBOR-canonical form of the envelope
    /// *without* this field. `None` for sealed-sender bootstrap.
    #[serde(rename = "sig", default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<ByteBuf>,
}

impl MessageEnvelope {
    /// Encode to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|_| Error::Internal("CBOR encode failed"))?;
        Ok(out)
    }

    /// Decode from CBOR bytes. Verifies the protocol version is one we
    /// recognise; everything else is a structural check via serde.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let envelope: Self = ciborium::from_reader(bytes)
            .map_err(|_| Error::InvalidEncoding("envelope: malformed CBOR"))?;
        if envelope.version != ENVELOPE_VERSION {
            return Err(Error::InvalidEncoding(
                "envelope: unrecognised protocol version",
            ));
        }
        Ok(envelope)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── InnerFrame ─────────────────────────────────────────────────────────

    #[test]
    fn inner_frame_round_trip_small() {
        let f = InnerFrame {
            frame_type: FRAME_DELIVER,
            payload: vec![0xAB; 100],
        };
        let bytes = f.encode_padded().unwrap();
        assert_eq!(bytes.len(), bucket::SMALL);
        let g = InnerFrame::decode(&bytes).unwrap();
        assert_eq!(f, g);
    }

    #[test]
    fn inner_frame_round_trip_empty() {
        let f = InnerFrame {
            frame_type: FRAME_PAD,
            payload: vec![],
        };
        let bytes = f.encode_padded().unwrap();
        assert_eq!(bytes.len(), bucket::SMALL);
        assert_eq!(InnerFrame::decode(&bytes).unwrap(), f);
    }

    #[test]
    fn inner_frame_round_trip_at_bucket_boundaries() {
        for size in [
            max_payload::SMALL,
            max_payload::SMALL + 1,
            max_payload::MEDIUM,
            max_payload::MEDIUM + 1,
            max_payload::LARGE,
        ] {
            let f = InnerFrame {
                frame_type: FRAME_DELIVER,
                payload: vec![0xAB; size],
            };
            let bytes = f.encode_padded().unwrap();
            let expected_bucket = match size {
                s if s <= max_payload::SMALL => bucket::SMALL,
                s if s <= max_payload::MEDIUM => bucket::MEDIUM,
                _ => bucket::LARGE,
            };
            assert_eq!(bytes.len(), expected_bucket, "size {size}");
            assert_eq!(InnerFrame::decode(&bytes).unwrap(), f);
        }
    }

    #[test]
    fn inner_frame_payload_too_large() {
        let f = InnerFrame {
            frame_type: FRAME_DELIVER,
            payload: vec![0; max_payload::LARGE + 1],
        };
        assert!(matches!(f.encode_padded(), Err(Error::InvalidEncoding(_))));
    }

    #[test]
    fn inner_frame_payload_at_u16_boundary() {
        // Larger than any bucket — should error on the bucket check, not panic.
        let f = InnerFrame {
            frame_type: FRAME_DELIVER,
            payload: vec![0; u16::MAX as usize],
        };
        assert!(matches!(f.encode_padded(), Err(Error::InvalidEncoding(_))));
    }

    #[test]
    fn inner_frame_padding_is_zero() {
        let f = InnerFrame {
            frame_type: FRAME_DELIVER,
            payload: vec![0xAB, 0xCD],
        };
        let bytes = f.encode_padded().unwrap();
        // Header(4) + payload(2) = 6; bytes 6..256 should all be zero.
        for (i, b) in bytes.iter().enumerate().skip(INNER_HEADER_LEN + 2) {
            assert_eq!(*b, 0, "padding at index {i} was {b:#x}, expected zero");
        }
    }

    #[test]
    fn inner_frame_decode_rejects_unknown_bucket() {
        let bytes = vec![0u8; 500]; // not a recognised bucket
        assert!(matches!(
            InnerFrame::decode(&bytes),
            Err(Error::InvalidEncoding(_))
        ));
    }

    #[test]
    fn inner_frame_decode_rejects_oversized_length() {
        let mut bytes = vec![0u8; bucket::SMALL];
        bytes[0..2].copy_from_slice(&FRAME_DELIVER.to_be_bytes());
        // Claim a payload exactly equal to the bucket — exceeds the
        // header+payload limit by 4 bytes, so decode must reject.
        let oversize = u16::try_from(bucket::SMALL).expect("bucket fits in u16");
        bytes[2..4].copy_from_slice(&oversize.to_be_bytes());
        assert!(matches!(
            InnerFrame::decode(&bytes),
            Err(Error::InvalidEncoding(_))
        ));
    }

    // ── MessageEnvelope ────────────────────────────────────────────────────

    fn sample_envelope_normal() -> MessageEnvelope {
        MessageEnvelope {
            version: ENVELOPE_VERSION,
            to: ByteBuf::from(vec![0x11; 16]),
            from: Some(ByteBuf::from(vec![0x22; 16])),
            room: Some(ByteBuf::from(vec![0x33; 16])),
            timestamp_ms: 1_715_000_000_000,
            nonce: ByteBuf::from(vec![0x44; 12]),
            pad_to: 1024,
            mls: ByteBuf::from(b"opaque-mls-ciphertext".to_vec()),
            sig: Some(ByteBuf::from(vec![0x55; 64])),
        }
    }

    fn sample_envelope_bootstrap() -> MessageEnvelope {
        MessageEnvelope {
            version: ENVELOPE_VERSION,
            to: ByteBuf::from(vec![0xAA; 16]),
            from: None,
            room: None,
            timestamp_ms: 1_715_000_001_000,
            nonce: ByteBuf::from(vec![0xBB; 12]),
            pad_to: 4096,
            mls: ByteBuf::from(b"sealed-sender-welcome".to_vec()),
            sig: None,
        }
    }

    #[test]
    fn envelope_round_trip_normal() {
        let e = sample_envelope_normal();
        let bytes = e.to_cbor().unwrap();
        let f = MessageEnvelope::from_cbor(&bytes).unwrap();
        assert_eq!(e, f);
    }

    #[test]
    fn envelope_round_trip_bootstrap() {
        let e = sample_envelope_bootstrap();
        let bytes = e.to_cbor().unwrap();
        let f = MessageEnvelope::from_cbor(&bytes).unwrap();
        assert_eq!(e, f);
        assert!(f.from.is_none());
        assert!(f.sig.is_none());
    }

    #[test]
    fn envelope_bootstrap_is_smaller_than_normal() {
        // Sanity check that `skip_serializing_if` actually trims absent
        // fields rather than serialising `null`s.
        let normal = sample_envelope_normal().to_cbor().unwrap();
        let boot = sample_envelope_bootstrap().to_cbor().unwrap();
        assert!(
            boot.len() < normal.len(),
            "bootstrap envelope ({}) should be smaller than normal ({})",
            boot.len(),
            normal.len()
        );
    }

    #[test]
    fn envelope_rejects_unknown_version() {
        let mut e = sample_envelope_normal();
        e.version = 99;
        let bytes = e.to_cbor().unwrap();
        assert!(matches!(
            MessageEnvelope::from_cbor(&bytes),
            Err(Error::InvalidEncoding(_))
        ));
    }

    #[test]
    fn envelope_rejects_garbage_cbor() {
        assert!(matches!(
            MessageEnvelope::from_cbor(b"not cbor"),
            Err(Error::InvalidEncoding(_))
        ));
    }

    // ── Property tests ─────────────────────────────────────────────────────

    proptest! {
        /// Any frame whose payload fits a bucket survives encode/decode.
        #[test]
        fn prop_inner_frame_round_trip(
            frame_type in any::<u16>(),
            payload in prop::collection::vec(any::<u8>(), 0..=max_payload::LARGE),
        ) {
            let f = InnerFrame { frame_type, payload: payload.clone() };
            let bytes = f.encode_padded().unwrap();
            // Encoded length is always one of the buckets.
            prop_assert!(
                bytes.len() == bucket::SMALL
                    || bytes.len() == bucket::MEDIUM
                    || bytes.len() == bucket::LARGE
            );
            let g = InnerFrame::decode(&bytes).unwrap();
            prop_assert_eq!(g.frame_type, frame_type);
            prop_assert_eq!(g.payload, payload);
        }

        /// Arbitrary bytes of arbitrary length never panic the decoder.
        /// They either decode (rare — only at exact bucket sizes with a
        /// valid length prefix) or return an error.
        #[test]
        fn prop_inner_frame_decode_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..=8192)) {
            let _ = InnerFrame::decode(&bytes); // must not panic
        }

        /// Envelope round-trip with arbitrary byte fields and an arbitrary
        /// presence pattern for the optional fields.
        #[test]
        fn prop_envelope_round_trip(
            to in prop::collection::vec(any::<u8>(), 0..64),
            from in prop::option::of(prop::collection::vec(any::<u8>(), 0..64)),
            room in prop::option::of(prop::collection::vec(any::<u8>(), 0..64)),
            ts in any::<u64>(),
            nonce in prop::collection::vec(any::<u8>(), 12..=12),
            pad_to in any::<u16>(),
            mls in prop::collection::vec(any::<u8>(), 0..256),
            sig in prop::option::of(prop::collection::vec(any::<u8>(), 64..=64)),
        ) {
            let e = MessageEnvelope {
                version: ENVELOPE_VERSION,
                to: ByteBuf::from(to),
                from: from.map(ByteBuf::from),
                room: room.map(ByteBuf::from),
                timestamp_ms: ts,
                nonce: ByteBuf::from(nonce),
                pad_to,
                mls: ByteBuf::from(mls),
                sig: sig.map(ByteBuf::from),
            };
            let bytes = e.to_cbor().unwrap();
            let f = MessageEnvelope::from_cbor(&bytes).unwrap();
            prop_assert_eq!(e, f);
        }
    }
}
