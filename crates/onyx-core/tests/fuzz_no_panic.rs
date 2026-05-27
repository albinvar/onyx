//! Red-team fuzz: throw random/adversarial bytes at every public
//! decoder and assert NONE panic. A panic on attacker-controlled input
//! is a remote denial-of-service (a peer or hub can crash the daemon by
//! sending crafted bytes), so "decodes cleanly to Ok or Err, never
//! panics" is a security property, not just robustness.
//!
//! proptest fails the test if any case panics, which is exactly the
//! signal we want.

use proptest::prelude::*;

use onyx_core::crypto::{Fingerprint, HybridKemPublic, HybridKemSecret};
use onyx_core::invite::Invite;
use onyx_core::room::RoomAppMessage;
use onyx_core::routing::{BootstrapPayload, decode_signed_subscribe};
use onyx_core::wire::{GossipFrame, InnerFrame};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// Length-prefixed Noise inner frame decoder — the first thing that
    /// touches bytes off the wire.
    #[test]
    fn inner_frame_decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..70_000)) {
        let _ = InnerFrame::decode(&bytes);
    }

    /// Federation gossip frame decoder (peer-hub trust boundary).
    #[test]
    fn gossip_frame_decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..70_000)) {
        let _ = GossipFrame::decode(&bytes);
    }

    /// Room application message (CBOR tagged union) — decrypted MLS
    /// plaintext from any group member.
    #[test]
    fn room_app_message_decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..20_000)) {
        let _ = RoomAppMessage::from_cbor(&bytes);
    }

    /// Sealed-sender inner payload (CBOR tagged union).
    #[test]
    fn bootstrap_payload_decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..20_000)) {
        let _ = BootstrapPayload::from_cbor(&bytes);
    }

    /// Signed SUBSCRIBE codec (HIGH-1) — attacker-supplied hub frame.
    #[test]
    fn signed_subscribe_decode_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..4_000),
        hh in proptest::array::uniform32(any::<u8>()),
    ) {
        let _ = decode_signed_subscribe(&bytes, &hh);
    }

    /// Hybrid KEM public/secret key parsers.
    #[test]
    fn hybrid_kem_parsers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..3_000)) {
        let _ = HybridKemPublic::from_bytes(&bytes);
        let _ = HybridKemSecret::from_bytes(&bytes);
    }

    /// Fingerprint base32 parser.
    #[test]
    fn fingerprint_parse_never_panics(s in ".{0,200}") {
        let _ = Fingerprint::parse(&s);
    }

    /// Invite-URL parser (handles attacker-supplied `onyx://` links).
    #[test]
    fn invite_parse_never_panics(s in ".{0,4000}") {
        let _ = Invite::parse(&s);
    }

    /// Invite parser specifically on well-formed-ish prefixes (steer
    /// the fuzzer toward the parsing logic rather than instant scheme
    /// rejection).
    #[test]
    fn invite_parse_with_prefix_never_panics(tail in ".{0,2000}") {
        let url = format!("onyx://invite/v1?{tail}");
        let _ = Invite::parse(&url);
    }
}
