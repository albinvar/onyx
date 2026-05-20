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
/// | `MlsWelcome`  | yes | **yes** (post-Welcome) | hands the recipient an MLS Welcome to start a ratchet — every subsequent message exchanged inside that group has full MLS PCS |
///
/// PFS comes from the ephemeral X25519 + ML-KEM-768 encapsulation
/// every envelope does. PCS requires the recipient to actually start
/// running an MLS ratchet after the message: `PlainMessage` alone
/// does not arrange that; `MlsWelcome` does. The TUI renders the
/// `[hub]` badge on every `via_hub` message; future polish (T6.x)
/// may differentiate `msg/v1` vs `mls/v1` more loudly.
/// One entry of [`BootstrapPayload::MlsWelcome::member_kems`]
/// (T6.3.h). Plain struct — both fields are public protocol values.
/// `fingerprint` is the same base32-grouped form printed by `onyx
/// identity`; `kem_pub` is the raw bytes of a hybrid X25519 +
/// ML-KEM-768 public key (1216 bytes).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoomMemberKem {
    pub fingerprint: String,
    pub kem_pub: ByteBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "v")]
pub enum BootstrapPayload {
    /// "msg/v1" — single-shot plaintext message wrapped in the sealed
    /// envelope. No MLS state is created by sending or receiving.
    #[serde(rename = "msg/v1")]
    PlainMessage { text: String },
    /// "mls/v1" — carries an MLS Welcome message (RFC 9420). Once
    /// the recipient calls `MlsParty::join_from_welcome` on the
    /// inner bytes both parties share an MLS group; every subsequent
    /// application message in that group has full MLS post-compromise
    /// security. The Welcome itself only authenticates the sender
    /// via the outer sealed-envelope signature (Ed25519 over the
    /// canonical bytes — see `bootstrap_signing_bytes`).
    ///
    /// `first_message` is an *optional* plaintext "introduction"
    /// payload the sender wants delivered alongside the Welcome
    /// (T7.2-mls-fu). When `Some`, the recipient renders it as the
    /// first message of the new conversation — same as if the sender
    /// had immediately followed the Welcome with an app-level message
    /// — instead of a synthetic placeholder. The text inherits the
    /// envelope's per-message PFS but, like the Welcome itself,
    /// predates the MLS ratchet so it does **not** have MLS PCS
    /// (that kicks in for everything sent *inside* the group from
    /// here on). Skipped in serialization when `None` so old wire
    /// payloads round-trip byte-identically.
    #[serde(rename = "mls/v1")]
    MlsWelcome {
        welcome: ByteBuf,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        first_message: Option<String>,
        /// Optional local display name of the multi-party room the
        /// Welcome is for (T6.3.c). When `Some`, the recipient saves
        /// a `rooms` row with this name on join so the new member
        /// sees the same name the inviter sees. When `None` (current
        /// 2-party DM bootstrap, and any pre-T6.3.c sender), the
        /// recipient treats the Welcome as a 2-party DM and does not
        /// surface a room. `#[serde(default, skip_serializing_if)]`
        /// so old wire payloads round-trip byte-identically — pre-
        /// T6.3.c daemons that don't know about the field still parse
        /// the envelope and ignore the unknown key (CBOR maps).
        ///
        /// **Security note.** This field is covered by the outer
        /// sealed-sender Ed25519 signature alongside the Welcome and
        /// `first_message`, so a hostile hub cannot rename the room
        /// the recipient sees without invalidating the envelope. It
        /// is *not* a cryptographic identifier — the binding
        /// identifier is the MLS `group_id` recovered from the
        /// joined `MlsGroupState`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        room_name: Option<String>,
        /// Optional roster of current room members' (fingerprint,
        /// hybrid KEM pub) pairs (T6.3.h). When present, the
        /// recipient persists each pair to
        /// `Vault::save_room_member_kem` on join so they can
        /// hub-fallback to any current member, not just the inviter
        /// — closes the structural gap noted in T6.3.e's CHANGELOG.
        ///
        /// `#[serde(default, skip_serializing_if = "Vec::is_empty")]`
        /// for back-compat: pre-T6.3.h Welcomes (which lack the
        /// field) decode cleanly, and an empty roster (e.g. self-
        /// invite, never expected to actually happen) round-trips
        /// byte-identically to the pre-T6.3.h form. Sender includes
        /// every current member — including themselves — so a fresh
        /// joiner has the full hub-fallback graph.
        ///
        /// **Security note.** The roster is covered by the outer
        /// sealed-sender Ed25519 signature alongside `welcome` and
        /// `room_name`, so a hostile hub cannot tamper. The inviter
        /// is trusted to be honest about the roster — a malicious
        /// inviter could omit a member's KEM or substitute an
        /// attacker's KEM under a member's fingerprint, but the
        /// worst-case outcome is "hub-fallback messages to that
        /// member don't decrypt." Same trust scope as any room
        /// member: see [`crate::room::RoomAppMessage::KemAdvertisement`].
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        member_kems: Vec<RoomMemberKem>,
    },
    /// "mlsapp/v1" (T6.3.e) — already-encrypted MLS application
    /// message routed via the hub. Wraps a single ciphertext
    /// produced by [`crate::mls::MlsGroupState::encrypt_application`]
    /// against a room's MLS group state, addressed at the routing
    /// layer to one specific member's introduction inbox.
    ///
    /// `group_id` is duplicated here at the bootstrap layer so the
    /// recipient daemon can route the inner ciphertext to the right
    /// `MlsGroupState` without first parsing the MLS framing
    /// (`crate::mls::peek_group_id` does the same on the direct
    /// path; carrying it explicitly here saves a TLS-decode for
    /// the hub path). This is the same group_id MLS already carries
    /// in the ciphertext's cleartext header, so it leaks nothing
    /// extra: the bytes are observable to anyone with access to
    /// the sealed envelope's *inner* CBOR, which means the
    /// recipient and only the recipient (the outer envelope is
    /// sealed under their hybrid KEM).
    ///
    /// **Security tier**: the inner ciphertext has full MLS PCS
    /// for everything that follows in the room's ratchet. The outer
    /// sealed-sender envelope adds per-message PFS via the hybrid
    /// X25519 + ML-KEM-768 encapsulation, identical to
    /// `BootstrapPayload::MlsWelcome`'s envelope properties.
    ///
    /// Unlike `MlsWelcome`, `MlsApp` does NOT create new MLS state
    /// on receive — both sides must already share the group (i.e.
    /// the recipient must have processed a prior `MlsWelcome` for
    /// this `group_id`). Recipients that don't have the group drop
    /// the envelope silently at debug level — could be the
    /// recipient hasn't joined the room yet, or a hostile sender
    /// trying to probe whether we're in a given room (which we
    /// refuse to reveal).
    #[serde(rename = "mlsapp/v1")]
    MlsApp {
        group_id: ByteBuf,
        ciphertext: ByteBuf,
    },
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
///   ‖ u32_BE(recipient_kem_pub_len) ‖ recipient_kem_pub
///   ‖ u32_BE(mls_welcome_len)       ‖ mls_welcome
/// ```
///
/// HIGH-2 fix: `recipient_kem_pub` (the intended recipient's hybrid
/// KEM public key) is bound into the signature. Without it the signed
/// payload was recipient-independent — a malicious *legitimate*
/// recipient could re-seal the identical signed bytes to a different
/// victim, who would accept a Welcome/message "from Alice" that Alice
/// never sent *them*. With the binding, re-sealing to a new recipient
/// fails verification: the opener recomputes these bytes using *its
/// own* KEM pubkey, which won't match the one the sender signed over.
fn bootstrap_signing_bytes(
    sender_signing_pk: &VerifyingKey,
    sender_identity_pk: &IdentityPublic,
    recipient_kem_pub: &[u8],
    mls_welcome: &[u8],
) -> Result<Vec<u8>> {
    let kem_len = u32::try_from(recipient_kem_pub.len())
        .map_err(|_| Error::InvalidEncoding("bootstrap: recipient_kem_pub longer than u32::MAX"))?;
    let mls_len = u32::try_from(mls_welcome.len())
        .map_err(|_| Error::InvalidEncoding("bootstrap: mls_welcome longer than u32::MAX"))?;
    let mut out = Vec::with_capacity(
        BOOTSTRAP_SIG_CONTEXT.len() + 32 + 32 + 4 + recipient_kem_pub.len() + 4 + mls_welcome.len(),
    );
    out.extend_from_slice(BOOTSTRAP_SIG_CONTEXT);
    out.extend_from_slice(&sender_signing_pk.to_bytes());
    out.extend_from_slice(&sender_identity_pk.to_bytes());
    out.extend_from_slice(&kem_len.to_be_bytes());
    out.extend_from_slice(recipient_kem_pub);
    out.extend_from_slice(&mls_len.to_be_bytes());
    out.extend_from_slice(mls_welcome);
    Ok(out)
}

fn derive_aead_key(shared: &HybridSharedSecret) -> Result<AeadKey> {
    let mut key_bytes = [0u8; 32];
    hkdf_sha256(shared.as_bytes(), BOOTSTRAP_AEAD_SALT, b"", &mut key_bytes)?;
    Ok(AeadKey::from_bytes(key_bytes))
}

fn seal_with_hybrid(plaintext: &[u8], pub_key: &HybridKemPublic, aad: &[u8]) -> Result<Vec<u8>> {
    let (ciphertext, shared) = pub_key.encapsulate()?;
    let aead_key = derive_aead_key(&shared)?;
    // One-shot key: fresh shared secret per encapsulation means nonce
    // reuse is impossible, so all-zero nonce is fine.
    let nonce = Nonce::from_bytes([0u8; 12]);
    // HIGH-2: `aad` carries the recipient KEM pubkey, binding the
    // ciphertext layer to the intended recipient (defense-in-depth
    // alongside the signature binding).
    let aead_ct = aead_key.encrypt(&nonce, aad, plaintext)?;

    let ct_bytes = ciphertext.to_bytes();
    let mut out = Vec::with_capacity(ct_bytes.len() + aead_ct.len());
    out.extend_from_slice(&ct_bytes);
    out.extend_from_slice(&aead_ct);
    Ok(out)
}

fn open_with_hybrid(sealed: &[u8], secret: &HybridKemSecret, aad: &[u8]) -> Result<Vec<u8>> {
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
    aead_key.decrypt(&nonce, aad, aead_ct)
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

    // HIGH-2: bind the recipient's KEM pubkey into both the signature
    // and the AEAD aad so the envelope is cryptographically addressed
    // to exactly this recipient and can't be reflected to another.
    let recipient_kem_bytes = recipient_kem_pub.to_bytes();

    let sig_input = bootstrap_signing_bytes(
        &sender_signing_pk,
        &sender_identity_pk,
        &recipient_kem_bytes,
        mls_welcome,
    )?;
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

    seal_with_hybrid(&cbor, recipient_kem_pub, &recipient_kem_bytes)
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
    // HIGH-2: recompute our own KEM pubkey to use as the AEAD aad and
    // signature binding. An envelope sealed for a different recipient
    // (reflection attack) will fail the AEAD open and/or the signature
    // verify because these bytes won't match what the sender bound.
    let recipient_kem_bytes = recipient_kem_secret.public().to_bytes();

    let cbor = open_with_hybrid(sealed, recipient_kem_secret, &recipient_kem_bytes)?;

    let wire: BootstrapWire = ciborium::from_reader(cbor.as_slice())
        .map_err(|_| Error::InvalidEncoding("sealed bootstrap: CBOR decode"))?;

    let signing_pk = parse_ed25519_pk(wire.sender_signing_pk.as_ref())?;
    let identity_pk = parse_x25519_pk(wire.sender_identity_pk.as_ref())?;
    let signature = parse_signature(wire.signature.as_ref())?;

    let sig_input = bootstrap_signing_bytes(
        &signing_pk,
        &identity_pk,
        &recipient_kem_bytes,
        &wire.mls_welcome,
    )?;
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
    fn bootstrap_payload_round_trip_mls_welcome() {
        let p = BootstrapPayload::MlsWelcome {
            welcome: ByteBuf::from(b"opaque-mls-welcome-bytes-from-rfc9420".to_vec()),
            first_message: None,
            room_name: None,
            member_kems: vec![],
        };
        let bytes = p.to_cbor().expect("encode");
        let p2 = BootstrapPayload::from_cbor(&bytes).expect("decode");
        assert_eq!(p, p2);
    }

    #[test]
    fn bootstrap_payload_round_trip_mls_welcome_with_first_message() {
        let p = BootstrapPayload::MlsWelcome {
            welcome: ByteBuf::from(b"opaque-welcome".to_vec()),
            first_message: Some("hi from the invite URL".to_string()),
            room_name: None,
            member_kems: vec![],
        };
        let bytes = p.to_cbor().expect("encode");
        let p2 = BootstrapPayload::from_cbor(&bytes).expect("decode");
        assert_eq!(p, p2);
    }

    #[test]
    fn bootstrap_payload_round_trip_mls_welcome_with_room_name() {
        // T6.3.c: room_name must round-trip alongside the Welcome.
        let p = BootstrapPayload::MlsWelcome {
            welcome: ByteBuf::from(b"opaque-welcome".to_vec()),
            first_message: None,
            room_name: Some("#general".to_string()),
            member_kems: vec![],
        };
        let bytes = p.to_cbor().expect("encode");
        let p2 = BootstrapPayload::from_cbor(&bytes).expect("decode");
        assert_eq!(p, p2);
    }

    #[test]
    fn bootstrap_payload_round_trip_mls_welcome_with_member_kems() {
        // T6.3.h: member_kems must round-trip alongside the Welcome.
        let p = BootstrapPayload::MlsWelcome {
            welcome: ByteBuf::from(b"opaque-welcome".to_vec()),
            first_message: None,
            room_name: Some("#general".to_string()),
            member_kems: vec![
                RoomMemberKem {
                    fingerprint: "fp_alice".into(),
                    kem_pub: ByteBuf::from(vec![0xA1u8; 1216]),
                },
                RoomMemberKem {
                    fingerprint: "fp_bob".into(),
                    kem_pub: ByteBuf::from(vec![0xB2u8; 1216]),
                },
            ],
        };
        let bytes = p.to_cbor().expect("encode");
        let p2 = BootstrapPayload::from_cbor(&bytes).expect("decode");
        assert_eq!(p, p2);
    }

    #[test]
    fn bootstrap_payload_mls_welcome_omits_member_kems_field_when_empty() {
        // Wire back-compat (T6.3.h): an empty member_kems must NOT
        // be emitted so pre-T6.3.h daemons that lack the field
        // entirely round-trip byte-identically to what they'd emit.
        let p = BootstrapPayload::MlsWelcome {
            welcome: ByteBuf::from(b"w".to_vec()),
            first_message: None,
            room_name: None,
            member_kems: vec![],
        };
        let bytes = p.to_cbor().unwrap();
        let s = String::from_utf8_lossy(&bytes);
        assert!(
            !s.contains("member_kems"),
            "member_kems must be skipped from the wire when empty; got {bytes:?}"
        );
    }

    #[test]
    fn bootstrap_payload_mls_welcome_omits_first_message_field_when_none() {
        // Wire back-compat: a None first_message must serialise to
        // *exactly* the byte sequence pre-T7.2-mls-fu daemons emit,
        // so older clients (none today, but future minor-version
        // daemons that haven't picked up this code yet) can still
        // decode it.
        let p = BootstrapPayload::MlsWelcome {
            welcome: ByteBuf::from(b"w".to_vec()),
            first_message: None,
            room_name: None,
            member_kems: vec![],
        };
        let bytes = p.to_cbor().unwrap();
        let s = String::from_utf8_lossy(&bytes);
        assert!(
            !s.contains("first_message"),
            "first_message must be skipped from the wire when None; got {bytes:?}"
        );
    }

    #[test]
    fn bootstrap_payload_mls_welcome_omits_room_name_field_when_none() {
        // Wire back-compat (T6.3.c): None room_name must NOT be
        // emitted, so pre-T6.3.c daemons (which lack the field
        // entirely) round-trip the bytes byte-identically to what
        // they would emit themselves.
        let p = BootstrapPayload::MlsWelcome {
            welcome: ByteBuf::from(b"w".to_vec()),
            first_message: None,
            room_name: None,
            member_kems: vec![],
        };
        let bytes = p.to_cbor().unwrap();
        let s = String::from_utf8_lossy(&bytes);
        assert!(
            !s.contains("room_name"),
            "room_name must be skipped from the wire when None; got {bytes:?}"
        );
    }

    #[test]
    fn bootstrap_payload_mls_welcome_carries_version_tag() {
        let p = BootstrapPayload::MlsWelcome {
            welcome: ByteBuf::from(b"w".to_vec()),
            first_message: None,
            room_name: None,
            member_kems: vec![],
        };
        let bytes = p.to_cbor().unwrap();
        let s = String::from_utf8_lossy(&bytes);
        assert!(
            s.contains("mls/v1"),
            "mls/v1 variant must carry its version tag; got bytes {bytes:?}"
        );
        // Crucial: must NOT also contain msg/v1 (would mean both tags
        // got serialised, indicating a serde misconfiguration).
        assert!(
            !s.contains("msg/v1"),
            "mls/v1 variant must not leak msg/v1 tag; got {bytes:?}"
        );
    }

    #[test]
    fn bootstrap_payload_round_trip_mls_app() {
        // T6.3.e: MlsApp must round-trip the group_id + ciphertext.
        let p = BootstrapPayload::MlsApp {
            group_id: ByteBuf::from(b"group-id-bytes".to_vec()),
            ciphertext: ByteBuf::from(b"opaque-mls-application-ciphertext".to_vec()),
        };
        let bytes = p.to_cbor().expect("encode");
        let p2 = BootstrapPayload::from_cbor(&bytes).expect("decode");
        assert_eq!(p, p2);
    }

    #[test]
    fn bootstrap_payload_mls_app_carries_version_tag() {
        let p = BootstrapPayload::MlsApp {
            group_id: ByteBuf::from(b"g".to_vec()),
            ciphertext: ByteBuf::from(b"c".to_vec()),
        };
        let bytes = p.to_cbor().unwrap();
        let s = String::from_utf8_lossy(&bytes);
        assert!(
            s.contains("mlsapp/v1"),
            "mlsapp/v1 variant must carry its version tag; got {bytes:?}"
        );
    }

    #[test]
    fn bootstrap_payload_mls_app_round_trips_inside_sealed_envelope() {
        let (alice_sign, alice_id, bob_kem, _) = alice_to_bob_setup();
        let payload = BootstrapPayload::MlsApp {
            group_id: ByteBuf::from(b"shared-room-gid".to_vec()),
            ciphertext: ByteBuf::from(b"opaque-app-msg".to_vec()),
        };
        let payload_bytes = payload.to_cbor().unwrap();
        let sealed =
            seal_bootstrap(&alice_sign, &alice_id, &payload_bytes, &bob_kem.public()).unwrap();
        let opened = open_bootstrap(&sealed, &bob_kem).unwrap();
        let recovered = BootstrapPayload::from_cbor(&opened.mls_welcome).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn bootstrap_payload_mls_welcome_round_trips_inside_sealed_envelope() {
        let (alice_sign, alice_id, bob_kem, _) = alice_to_bob_setup();
        let payload = BootstrapPayload::MlsWelcome {
            welcome: ByteBuf::from(b"opaque-welcome".to_vec()),
            first_message: None,
            room_name: None,
            member_kems: vec![],
        };
        let payload_bytes = payload.to_cbor().unwrap();

        let sealed =
            seal_bootstrap(&alice_sign, &alice_id, &payload_bytes, &bob_kem.public()).unwrap();
        let opened = open_bootstrap(&sealed, &bob_kem).unwrap();
        let recovered = BootstrapPayload::from_cbor(&opened.mls_welcome).unwrap();
        assert_eq!(recovered, payload);
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
        // Seal to bob with the correct aad so the AEAD layer opens
        // (we want the INNER signature verification to be what fails,
        // not the AEAD tag).
        let sealed =
            seal_with_hybrid(&cbor, &bob_kem.public(), &bob_kem.public().to_bytes()).unwrap();

        assert!(matches!(
            open_bootstrap(&sealed, &bob_kem),
            Err(Error::VerificationFailed)
        ));
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn bootstrap_reflection_to_other_recipient_fails() {
        // HIGH-2: a malicious legitimate recipient (bob) who holds the
        // inner signed payload tries to reflect it to a different
        // victim (carol) by re-sealing the *same* signed BootstrapWire
        // to carol's KEM key. Carol must reject it: the signature was
        // bound to bob's KEM pubkey, but carol recomputes the signing
        // bytes with HER OWN pubkey, so verification fails.
        let (alice_sign, alice_id, bob_kem, mls) = alice_to_bob_setup();
        let carol_kem = HybridKemSecret::generate();

        // Alice seals legitimately to bob; bob opens to recover the
        // genuine signed inner wire.
        let sealed_for_bob =
            seal_bootstrap(&alice_sign, &alice_id, &mls, &bob_kem.public()).unwrap();
        let opened_by_bob = open_bootstrap(&sealed_for_bob, &bob_kem).unwrap();

        // Bob reconstructs the exact signed BootstrapWire he received
        // (he has all four fields, including alice's genuine signature)
        // and re-seals it to carol's KEM key.
        let reflected_wire = BootstrapWire {
            sender_signing_pk: ByteBuf::from(opened_by_bob.sender_signing_pk.to_bytes().to_vec()),
            sender_identity_pk: ByteBuf::from(opened_by_bob.sender_identity_pk.to_bytes().to_vec()),
            mls_welcome: ByteBuf::from(opened_by_bob.mls_welcome.clone()),
            // The genuine signature alice produced — but it was bound
            // to BOB's kem pubkey, not carol's.
            signature: ByteBuf::from(extract_signature(&sealed_for_bob, &bob_kem)),
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&reflected_wire, &mut cbor).unwrap();
        let reflected =
            seal_with_hybrid(&cbor, &carol_kem.public(), &carol_kem.public().to_bytes()).unwrap();

        // Carol opens: AEAD succeeds (bob sealed to her correctly), but
        // the inner signature, recomputed against carol's pubkey, fails.
        assert!(matches!(
            open_bootstrap(&reflected, &carol_kem),
            Err(Error::VerificationFailed)
        ));
    }

    // Test helper: pull alice's genuine signature back out of an
    // envelope by opening it as the intended recipient.
    fn extract_signature(sealed: &[u8], recipient: &HybridKemSecret) -> Vec<u8> {
        let cbor = open_with_hybrid(sealed, recipient, &recipient.public().to_bytes()).unwrap();
        let wire: BootstrapWire = ciborium::from_reader(cbor.as_slice()).unwrap();
        wire.signature.into_vec()
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
