//! Routing identifiers + sealed-sender bootstrap envelope.
//!
//! See DESIGN.md §5.5 (revised) for the full scheme. Two tiers:
//!
//! **Tier 1 — introduction inbox** (long-term, per recipient):
//! `inbox_id = BLAKE2b-128(recipient_signing_pk ‖ "onyx/v1/inbox")`.
//! Used as the routing identifier on the **first** message to a
//! recipient before any MLS group exists. The hub stores this as the
//! recipient's "front door" queue. Anyone holding the recipient's
//! fingerprint can derive the same inbox id — see DESIGN.md §5.5 for
//! the linkability tradeoff and the documented mitigations.
//!
//! **Tier 2 — rotating session tokens** (per MLS epoch):
//! `token_e_i = BLAKE2b-128(group_secret_e ‖ u64_BE(i))` where
//! `group_secret_e` is produced by the MLS exporter with label
//! [`MLS_EXPORTER_LABEL`]. The MLS integration lives in
//! [`crate::mls`] (not yet implemented); this module exposes the pure
//! [`session_token`] derivation.
//!
//! ## Sealed-sender bootstrap (post-quantum)
//!
//! The first message to a fresh contact must address the introduction
//! inbox — which gives the hub no information about who the sender is.
//! To match that on the cryptographic side, the bootstrap envelope is
//! sealed under the recipient's **hybrid KEM public key** (X25519 ‖
//! ML-KEM-768; see [`crate::crypto::HybridKemPublic`]). The outer
//! `MessageEnvelope` carries no `from` and no `sig`; sender
//! authentication happens entirely inside the sealed payload via a
//! domain-separated Ed25519 signature.
//!
//! This is the **first place** in Onyx where the post-quantum primitive
//! actually carries protocol traffic. v0.2-draft of DESIGN §5.5 cited
//! classical HPKE; the hybrid is a strict upgrade — combined secret is
//! secure as long as *either* X25519 *or* ML-KEM-768 is unbroken.
//!
//! Cost: the sealed blob is ~1 200 bytes + the MLS welcome size, so
//! sealed-sender envelopes land in the LARGE (4 KiB) padding bucket
//! (see [`crate::wire::bucket::LARGE`]). This is a one-time cost per
//! contact bootstrap; subsequent messages run under MLS at a few
//! hundred bytes each.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::crypto::{
    AeadKey, Fingerprint, HybridCiphertext, HybridKemPublic, HybridKemSecret, HybridSharedSecret,
    IdentityPublic, IdentitySecret, Nonce, Signature, SigningKey, VerifyingKey, blake2b_128,
    hkdf_sha256,
};
use crate::error::{Error, Result};

/// 16-byte routing identifier used as the storage key inside the hub
/// for both Tier-1 introduction inboxes and Tier-2 session tokens.
pub type RoutingId = [u8; 16];

/// Label for [`introduction_inbox`]. Changing this string breaks
/// compatibility with every existing inbox; rev it only with a
/// protocol-incompatible change.
pub const INBOX_LABEL: &[u8] = b"onyx/v1/inbox";

/// Label passed to MLS-Exporter to derive a group's per-epoch routing
/// secret. The hash that turns that secret + an index into a token
/// happens in [`session_token`].
pub const MLS_EXPORTER_LABEL: &[u8] = b"onyx/v1/routing";

/// Domain separator for the sealed-sender bootstrap signature. Without
/// this, an attacker could rebroadcast bytes signed under a different
/// protocol context.
const BOOTSTRAP_SIG_CONTEXT: &[u8] = b"onyx/v1/bootstrap";

/// HKDF salt used to derive the AEAD key for the sealed-sender envelope
/// from the hybrid KEM shared secret.
const BOOTSTRAP_AEAD_SALT: &[u8] = b"onyx/v1/bootstrap-seal";

// ── Tier 1: introduction inbox ─────────────────────────────────────────────

/// Derive a recipient's introduction inbox identifier.
///
/// `inbox_id = BLAKE2b-128(recipient_fingerprint ‖ "onyx/v1/inbox")`
///
/// The fingerprint is the recipient's Ed25519 signing public key bytes.
/// Anyone holding the fingerprint can derive the same inbox; this is
/// part of the v1 design (DESIGN.md §5.5) and the residual linkability
/// is documented there.
#[must_use]
pub fn introduction_inbox(recipient: &Fingerprint) -> RoutingId {
    blake2b_128(&[recipient.as_bytes().as_slice(), INBOX_LABEL])
}

// ── Tier 2: rotating session token ─────────────────────────────────────────

/// Derive a session-token routing identifier from a group's per-epoch
/// secret and an index.
///
/// `token = BLAKE2b-128(group_secret ‖ u64_BE(index))`
///
/// `group_secret` is the 32-byte output of
/// `MLS-Exporter(group, "onyx/v1/routing", 32)`. We don't yet have the
/// MLS layer; callers that need to test this in isolation can pass any
/// 32-byte value as `group_secret`.
#[must_use]
pub fn session_token(group_secret: &[u8; 32], index: u64) -> RoutingId {
    blake2b_128(&[group_secret.as_slice(), &index.to_be_bytes()])
}

// ── Sealed-sender inner payload (T5.2.c) ──────────────────────────────────
//
// The sealed-sender envelope is the **envelope layer** — opaque bytes
// in, opaque bytes out. What lives *inside* the envelope is the
// `BootstrapPayload` enum below, a versioned tagged union that the
// recipient demultiplexes after `open_bootstrap` verifies the
// signature.
//
// Today only `PlainMessage` ("msg/v1") is implemented; a future
// variant will carry an MLS Welcome for true post-compromise security
// on the hub path. The `#[serde(tag = "v")]` is the explicit version
// tag — per `SECURITY.md` P5 (forward-only protocol compatibility),
// recipients refuse unknown tags rather than downgrade.

/// Inner payload of a sealed-sender envelope. After `open_bootstrap`
/// returns the inner bytes, callers `BootstrapPayload::from_cbor`
/// to recover the typed payload.
///
/// ## Security tiers
///
/// | variant       | PFS | PCS  | when to use                                       |
/// |---------------|-----|------|---------------------------------------------------|
/// | `PlainMessage`| yes | **no** | first-contact, no MLS group available yet       |
/// | (future `MlsWelcome`) | yes | yes | hands over an MLS Welcome to start a ratchet |
///
/// PFS comes from the ephemeral X25519 + ML-KEM-768 encapsulation
/// every envelope does. PCS requires the recipient to actually start
/// running an MLS ratchet after the message, which `PlainMessage`
/// alone does not arrange. The TUI must render the two tiers
/// differently so users can read the threat model right — that
/// rendering is T5.2.f.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "v")]
pub enum BootstrapPayload {
    /// "msg/v1" — single-shot plaintext message wrapped in the sealed
    /// envelope. No MLS state is created by sending or receiving.
    #[serde(rename = "msg/v1")]
    PlainMessage { text: String },
}

impl BootstrapPayload {
    /// Encode as CBOR for embedding in a sealed-sender envelope.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out)
            .map_err(|_| Error::Internal("bootstrap-payload: CBOR encode failed"))?;
        Ok(out)
    }

    /// Decode bytes returned by `open_bootstrap` into a typed payload.
    /// Unknown `v` tags surface as [`Error::InvalidEncoding`] —
    /// recipients refuse rather than downgrade (`SECURITY.md` P5).
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes)
            .map_err(|_| Error::InvalidEncoding("bootstrap-payload: CBOR decode failed"))
    }
}

// ── Sealed-sender bootstrap ────────────────────────────────────────────────

/// Wire-format bootstrap payload — CBOR-encoded inside the sealed
/// envelope. Not part of the public API; the public face is
/// [`seal_bootstrap`] / [`open_bootstrap`] / [`OpenedBootstrap`].
#[derive(Debug, Serialize, Deserialize)]
struct BootstrapWire {
    #[serde(rename = "signpk")]
    sender_signing_pk: ByteBuf,
    #[serde(rename = "idpk")]
    sender_identity_pk: ByteBuf,
    #[serde(rename = "mls")]
    mls_welcome: ByteBuf,
    #[serde(rename = "sig")]
    signature: ByteBuf,
}

/// What the recipient gets back after a successful `open_bootstrap`. The
/// inner Ed25519 signature has already been verified before this is
/// handed out; the typed keys are safe to trust at the protocol level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedBootstrap {
    pub sender_signing_pk: VerifyingKey,
    pub sender_identity_pk: IdentityPublic,
    pub mls_welcome: Vec<u8>,
}

/// Bytes the sender signs over. Layout (deliberately fixed and
/// independent of CBOR — a canonical-encoding bug must not be able to
/// move bytes around under our signature):
///
/// ```text
/// "onyx/v1/bootstrap"
///   ‖ sender_signing_pk (32)
///   ‖ sender_identity_pk (32)
///   ‖ u32_BE(mls_welcome_len)
///   ‖ mls_welcome
/// ```
fn bootstrap_signing_bytes(
    sender_signing_pk: &VerifyingKey,
    sender_identity_pk: &IdentityPublic,
    mls_welcome: &[u8],
) -> Result<Vec<u8>> {
    let mls_len = u32::try_from(mls_welcome.len())
        .map_err(|_| Error::InvalidEncoding("bootstrap: mls_welcome longer than u32::MAX"))?;
    let mut out = Vec::with_capacity(BOOTSTRAP_SIG_CONTEXT.len() + 32 + 32 + 4 + mls_welcome.len());
    out.extend_from_slice(BOOTSTRAP_SIG_CONTEXT);
    out.extend_from_slice(&sender_signing_pk.to_bytes());
    out.extend_from_slice(&sender_identity_pk.to_bytes());
    out.extend_from_slice(&mls_len.to_be_bytes());
    out.extend_from_slice(mls_welcome);
    Ok(out)
}

fn derive_aead_key(shared: &HybridSharedSecret) -> Result<AeadKey> {
    let mut key_bytes = [0u8; 32];
    hkdf_sha256(shared.as_bytes(), BOOTSTRAP_AEAD_SALT, b"", &mut key_bytes)?;
    Ok(AeadKey::from_bytes(key_bytes))
}

fn seal_with_hybrid(plaintext: &[u8], pub_key: &HybridKemPublic) -> Result<Vec<u8>> {
    let (ciphertext, shared) = pub_key.encapsulate()?;
    let aead_key = derive_aead_key(&shared)?;
    // One-shot key: fresh shared secret per encapsulation means nonce
    // reuse is impossible, so all-zero nonce is fine.
    let nonce = Nonce::from_bytes([0u8; 12]);
    let aead_ct = aead_key.encrypt(&nonce, b"", plaintext)?;

    let ct_bytes = ciphertext.to_bytes();
    let mut out = Vec::with_capacity(ct_bytes.len() + aead_ct.len());
    out.extend_from_slice(&ct_bytes);
    out.extend_from_slice(&aead_ct);
    Ok(out)
}

fn open_with_hybrid(sealed: &[u8], secret: &HybridKemSecret) -> Result<Vec<u8>> {
    use crate::crypto::HYBRID_CIPHERTEXT_LEN;

    if sealed.len() < HYBRID_CIPHERTEXT_LEN {
        return Err(Error::InvalidEncoding(
            "sealed bootstrap: shorter than KEM ciphertext",
        ));
    }
    let (ct_bytes, aead_ct) = sealed.split_at(HYBRID_CIPHERTEXT_LEN);
    let hybrid_ct = HybridCiphertext::from_bytes(ct_bytes)?;
    let shared = secret.decapsulate(&hybrid_ct)?;
    let aead_key = derive_aead_key(&shared)?;
    let nonce = Nonce::from_bytes([0u8; 12]);
    aead_key.decrypt(&nonce, b"", aead_ct)
}

/// Seal a bootstrap envelope for `recipient_kem_pub`.
///
/// Steps:
/// 1. Sign over the canonical bytes (`bootstrap_signing_bytes`) with
///    the sender's long-term Ed25519 key. The signature is bound to
///    the sender's identity X25519 pub via the input, so an attacker
///    can't repurpose one signed identity-pk for another.
/// 2. CBOR-encode the payload (`BootstrapWire`).
/// 3. Encapsulate to the recipient's hybrid KEM (X25519 ‖ ML-KEM-768),
///    derive an AEAD key via HKDF, encrypt the CBOR.
/// 4. Output: `KEM ciphertext (1120 B) ‖ AEAD ciphertext`.
///
/// On the wire this goes into [`crate::wire::MessageEnvelope::mls`] of
/// a frame addressed to the recipient's introduction inbox; the outer
/// envelope's `from` and `sig` are `None`.
pub fn seal_bootstrap(
    sender_signing: &SigningKey,
    sender_identity: &IdentitySecret,
    mls_welcome: &[u8],
    recipient_kem_pub: &HybridKemPublic,
) -> Result<Vec<u8>> {
    let sender_signing_pk = sender_signing.verifying_key();
    let sender_identity_pk = sender_identity.public();

    let sig_input = bootstrap_signing_bytes(&sender_signing_pk, &sender_identity_pk, mls_welcome)?;
    let signature = sender_signing.sign(&sig_input);

    let wire = BootstrapWire {
        sender_signing_pk: ByteBuf::from(sender_signing_pk.to_bytes().to_vec()),
        sender_identity_pk: ByteBuf::from(sender_identity_pk.to_bytes().to_vec()),
        mls_welcome: ByteBuf::from(mls_welcome.to_vec()),
        signature: ByteBuf::from(signature.to_bytes().to_vec()),
    };

    let mut cbor = Vec::new();
    ciborium::into_writer(&wire, &mut cbor)
        .map_err(|_| Error::Internal("bootstrap: CBOR encode failed"))?;

    seal_with_hybrid(&cbor, recipient_kem_pub)
}

/// Open a sealed-sender bootstrap envelope.
///
/// Decapsulates with the recipient's hybrid KEM secret, decrypts the
/// inner CBOR, parses the typed fields, **and verifies the inner
/// signature** before returning. The returned [`OpenedBootstrap`] is
/// safe to trust at the protocol level.
///
/// Wrong recipient, tampered ciphertext, or invalid signature all
/// surface as [`Error::VerificationFailed`] or [`Error::InvalidEncoding`].
/// We do not distinguish — the caller has no useful action to take
/// other than "drop this envelope" in any of those cases.
pub fn open_bootstrap(
    sealed: &[u8],
    recipient_kem_secret: &HybridKemSecret,
) -> Result<OpenedBootstrap> {
    let cbor = open_with_hybrid(sealed, recipient_kem_secret)?;

    let wire: BootstrapWire = ciborium::from_reader(cbor.as_slice())
        .map_err(|_| Error::InvalidEncoding("sealed bootstrap: CBOR decode"))?;

    let signing_pk = parse_ed25519_pk(wire.sender_signing_pk.as_ref())?;
    let identity_pk = parse_x25519_pk(wire.sender_identity_pk.as_ref())?;
    let signature = parse_signature(wire.signature.as_ref())?;

    let sig_input = bootstrap_signing_bytes(&signing_pk, &identity_pk, &wire.mls_welcome)?;
    signing_pk.verify(&sig_input, &signature)?;

    Ok(OpenedBootstrap {
        sender_signing_pk: signing_pk,
        sender_identity_pk: identity_pk,
        mls_welcome: wire.mls_welcome.into_vec(),
    })
}

// ── Byte-array parsers ────────────────────────────────────────────────────

fn parse_ed25519_pk(bytes: &[u8]) -> Result<VerifyingKey> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::InvalidEncoding("bootstrap: sender_signing_pk must be 32 B"))?;
    VerifyingKey::from_bytes(arr)
}

fn parse_x25519_pk(bytes: &[u8]) -> Result<IdentityPublic> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::InvalidEncoding("bootstrap: sender_identity_pk must be 32 B"))?;
    Ok(IdentityPublic::from_bytes(arr))
}

fn parse_signature(bytes: &[u8]) -> Result<Signature> {
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| Error::InvalidEncoding("bootstrap: signature must be 64 B"))?;
    Ok(Signature::from_bytes(arr))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── Tier 1: inbox ──────────────────────────────────────────────────────

    #[test]
    fn inbox_is_deterministic() {
        let fpr = SigningKey::generate().verifying_key().fingerprint();
        assert_eq!(introduction_inbox(&fpr), introduction_inbox(&fpr));
    }

    #[test]
    fn inbox_differs_per_recipient() {
        let a = SigningKey::generate().verifying_key().fingerprint();
        let b = SigningKey::generate().verifying_key().fingerprint();
        assert_ne!(introduction_inbox(&a), introduction_inbox(&b));
    }

    #[test]
    fn inbox_is_16_bytes() {
        let fpr = SigningKey::generate().verifying_key().fingerprint();
        assert_eq!(introduction_inbox(&fpr).len(), 16);
    }

    #[test]
    fn inbox_doesnt_equal_raw_blake2b_of_pk_alone() {
        // Sanity: the label is actually mixed in. Without the label, two
        // protocols that both hash pks would collide on routing IDs.
        let fpr = SigningKey::generate().verifying_key().fingerprint();
        let with_label = introduction_inbox(&fpr);
        let without_label = blake2b_128(&[fpr.as_bytes().as_slice()]);
        assert_ne!(with_label, without_label);
    }

    // ── Tier 2: session token ──────────────────────────────────────────────

    #[test]
    fn token_deterministic() {
        let secret = [42u8; 32];
        assert_eq!(session_token(&secret, 0), session_token(&secret, 0));
        assert_eq!(session_token(&secret, 999), session_token(&secret, 999));
    }

    #[test]
    fn token_differs_per_index() {
        let secret = [42u8; 32];
        assert_ne!(session_token(&secret, 0), session_token(&secret, 1));
        assert_ne!(session_token(&secret, 1), session_token(&secret, 2));
    }

    #[test]
    fn token_differs_per_secret() {
        let s1 = [1u8; 32];
        let s2 = [2u8; 32];
        assert_ne!(session_token(&s1, 0), session_token(&s2, 0));
    }

    #[test]
    fn token_index_endianness_is_big() {
        // u64_BE(1) starts with seven zero bytes — different from
        // u64_LE(1) which would start with a 0x01. This test pins the
        // wire encoding so an accidental "fix" doesn't silently shift
        // the namespace.
        let secret = [0u8; 32];
        let t = session_token(&secret, 1);
        let expected = blake2b_128(&[secret.as_slice(), &[0, 0, 0, 0, 0, 0, 0, 1]]);
        assert_eq!(t, expected);
    }

    // ── BootstrapPayload (T5.2.c) ──────────────────────────────────────────

    #[test]
    fn bootstrap_payload_round_trip_plain_message() {
        let p = BootstrapPayload::PlainMessage {
            text: "hello bob — sent through the hub".into(),
        };
        let bytes = p.to_cbor().expect("encode");
        let p2 = BootstrapPayload::from_cbor(&bytes).expect("decode");
        assert_eq!(p, p2);
    }

    #[test]
    fn bootstrap_payload_wire_shape_includes_version_tag() {
        // Literal-shape assertion: the CBOR must contain "msg/v1"
        // somewhere in its bytes. If anyone renames the serde tag
        // accidentally this test catches it loudly.
        let p = BootstrapPayload::PlainMessage { text: "x".into() };
        let bytes = p.to_cbor().unwrap();
        let s = String::from_utf8_lossy(&bytes);
        assert!(
            s.contains("msg/v1"),
            "BootstrapPayload CBOR must carry the 'msg/v1' version tag; got bytes {bytes:?}"
        );
        assert!(s.contains('v'), "version field 'v' must appear");
    }

    #[test]
    fn bootstrap_payload_unknown_variant_is_rejected() {
        // Hand-build a CBOR map {"v": "unknown/v99", "text": "x"} using
        // ciborium::Value, then assert BootstrapPayload refuses to
        // deserialise it. This is the "no downgrade" property
        // (SECURITY.md P5).
        use ciborium::Value as CborValue;
        let cbor_value = CborValue::Map(vec![
            (
                CborValue::Text("v".into()),
                CborValue::Text("unknown/v99".into()),
            ),
            (CborValue::Text("text".into()), CborValue::Text("x".into())),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&cbor_value, &mut bytes).unwrap();

        let err = BootstrapPayload::from_cbor(&bytes)
            .expect_err("unknown version tag must be rejected, not silently downgraded");
        // Just check the variant; message is intentionally generic
        // (no protocol-version oracle leaked to attackers).
        assert!(matches!(err, Error::InvalidEncoding(_)));
    }

    #[test]
    fn bootstrap_payload_garbage_is_rejected() {
        assert!(matches!(
            BootstrapPayload::from_cbor(&[]),
            Err(Error::InvalidEncoding(_))
        ));
        assert!(matches!(
            BootstrapPayload::from_cbor(b"definitely not cbor"),
            Err(Error::InvalidEncoding(_))
        ));
    }

    #[test]
    fn bootstrap_payload_round_trips_inside_sealed_envelope() {
        // End-to-end: BootstrapPayload → CBOR → seal_bootstrap →
        // open_bootstrap → CBOR → BootstrapPayload, identical at both ends.
        let (alice_sign, alice_id, bob_kem, _unused_mls) = alice_to_bob_setup();
        let payload = BootstrapPayload::PlainMessage {
            text: "first-contact via hub".into(),
        };
        let payload_bytes = payload.to_cbor().unwrap();

        let sealed =
            seal_bootstrap(&alice_sign, &alice_id, &payload_bytes, &bob_kem.public()).unwrap();
        let opened = open_bootstrap(&sealed, &bob_kem).unwrap();
        assert_eq!(opened.sender_signing_pk, alice_sign.verifying_key());
        assert_eq!(opened.sender_identity_pk, alice_id.public());

        let recovered = BootstrapPayload::from_cbor(&opened.mls_welcome).unwrap();
        assert_eq!(recovered, payload);
    }

    // ── Sealed-sender bootstrap ────────────────────────────────────────────

    #[allow(clippy::similar_names)] // alice / bob _sign / _id pairs are intentional
    fn alice_to_bob_setup() -> (SigningKey, IdentitySecret, HybridKemSecret, Vec<u8>) {
        let alice_sign = SigningKey::generate();
        let alice_id = IdentitySecret::generate();
        let bob_kem = HybridKemSecret::generate();
        let mls = b"opaque mls welcome bytes".to_vec();
        (alice_sign, alice_id, bob_kem, mls)
    }

    #[test]
    fn bootstrap_round_trip() {
        let (alice_sign, alice_id, bob_kem, mls) = alice_to_bob_setup();
        let sealed = seal_bootstrap(&alice_sign, &alice_id, &mls, &bob_kem.public()).unwrap();
        let opened = open_bootstrap(&sealed, &bob_kem).unwrap();

        assert_eq!(opened.sender_signing_pk, alice_sign.verifying_key());
        assert_eq!(opened.sender_identity_pk, alice_id.public());
        assert_eq!(opened.mls_welcome, mls);
    }

    #[test]
    fn bootstrap_wrong_recipient_fails() {
        let (alice_sign, alice_id, bob_kem, mls) = alice_to_bob_setup();
        let mallory_kem = HybridKemSecret::generate();
        let sealed = seal_bootstrap(&alice_sign, &alice_id, &mls, &bob_kem.public()).unwrap();
        // Mallory's decapsulation yields a different shared secret →
        // different AEAD key → tag fails.
        assert!(open_bootstrap(&sealed, &mallory_kem).is_err());
    }

    #[test]
    fn bootstrap_tampered_kem_ciphertext_fails() {
        let (alice_sign, alice_id, bob_kem, mls) = alice_to_bob_setup();
        let mut sealed = seal_bootstrap(&alice_sign, &alice_id, &mls, &bob_kem.public()).unwrap();
        // Flip a bit inside the KEM ciphertext (the first 1120 bytes).
        sealed[5] ^= 0x01;
        assert!(open_bootstrap(&sealed, &bob_kem).is_err());
    }

    #[test]
    fn bootstrap_tampered_aead_ciphertext_fails() {
        use crate::crypto::HYBRID_CIPHERTEXT_LEN;
        let (alice_sign, alice_id, bob_kem, mls) = alice_to_bob_setup();
        let mut sealed = seal_bootstrap(&alice_sign, &alice_id, &mls, &bob_kem.public()).unwrap();
        // Flip a bit after the KEM ciphertext — inside the AEAD payload.
        sealed[HYBRID_CIPHERTEXT_LEN + 5] ^= 0x01;
        assert!(matches!(
            open_bootstrap(&sealed, &bob_kem),
            Err(Error::VerificationFailed)
        ));
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn bootstrap_forged_signature_fails() {
        // Construct a bootstrap payload that *claims* to be from Alice
        // (her signing pk + identity pk) but is actually signed by
        // Mallory. Decryption succeeds — the AEAD tag passes — but the
        // inner Ed25519 verification on the payload rejects it.
        let (alice_sign, alice_id, bob_kem, mls) = alice_to_bob_setup();
        let mallory_sign = SigningKey::generate();

        let wire = BootstrapWire {
            sender_signing_pk: ByteBuf::from(alice_sign.verifying_key().to_bytes().to_vec()),
            sender_identity_pk: ByteBuf::from(alice_id.public().to_bytes().to_vec()),
            mls_welcome: ByteBuf::from(mls),
            // Mallory signs something — anything — under her own key,
            // pretending it's Alice's signature over this payload.
            signature: ByteBuf::from(
                mallory_sign
                    .sign(b"this is not the right sig input")
                    .to_bytes()
                    .to_vec(),
            ),
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&wire, &mut cbor).unwrap();
        let sealed = seal_with_hybrid(&cbor, &bob_kem.public()).unwrap();

        assert!(matches!(
            open_bootstrap(&sealed, &bob_kem),
            Err(Error::VerificationFailed)
        ));
    }

    #[test]
    fn bootstrap_truncated_envelope_rejected() {
        let (alice_sign, alice_id, bob_kem, mls) = alice_to_bob_setup();
        let sealed = seal_bootstrap(&alice_sign, &alice_id, &mls, &bob_kem.public()).unwrap();
        // Shorter than even the KEM ciphertext.
        assert!(matches!(
            open_bootstrap(&sealed[..100], &bob_kem),
            Err(Error::InvalidEncoding(_))
        ));
    }

    #[test]
    fn bootstrap_sealed_size_lands_in_large_bucket() {
        // The sealed-blob size is ~1 200 B + mls_welcome. Document the
        // expectation that a typical bootstrap envelope outgrows the
        // MEDIUM bucket and therefore lives in LARGE (DESIGN §5.8).
        use crate::wire::bucket;
        let (alice_sign, alice_id, bob_kem, _) = alice_to_bob_setup();
        let small_mls = b"x".to_vec();
        let sealed = seal_bootstrap(&alice_sign, &alice_id, &small_mls, &bob_kem.public()).unwrap();
        assert!(
            sealed.len() > bucket::MEDIUM,
            "sealed bootstrap of {} B is larger than MEDIUM ({}), as expected — \
             LARGE bucket is the right home",
            sealed.len(),
            bucket::MEDIUM,
        );
        assert!(
            sealed.len() < bucket::LARGE,
            "but it still fits in LARGE ({})",
            bucket::LARGE
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            // PQ KEM operations are not as slow as Argon2 but still
            // expensive enough that we don't want proptest's default 256
            // cases on each. 16 is enough to surface byte-handling bugs.
            cases: 16,
            .. ProptestConfig::default()
        })]

        /// Any byte-string survives sealing and opening as a payload.
        #[test]
        fn prop_bootstrap_round_trip(mls in prop::collection::vec(any::<u8>(), 0..=512)) {
            let alice_sign = SigningKey::generate();
            let alice_id = IdentitySecret::generate();
            let bob_kem = HybridKemSecret::generate();
            let sealed = seal_bootstrap(&alice_sign, &alice_id, &mls, &bob_kem.public()).unwrap();
            let opened = open_bootstrap(&sealed, &bob_kem).unwrap();
            prop_assert_eq!(opened.mls_welcome, mls);
        }

        /// Arbitrary bytes never panic `open_bootstrap`; rejection is
        /// fine, crashing is not.
        #[test]
        fn prop_open_bootstrap_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..=2048)) {
            let bob_kem = HybridKemSecret::generate();
            let _ = open_bootstrap(&bytes, &bob_kem);
        }
    }
}
