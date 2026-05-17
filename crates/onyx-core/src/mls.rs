//! MLS (RFC 9420) group state and message processing — wrapper over `openmls`.
//!
//! See DESIGN.md §6. This module deliberately hides almost all of
//! `openmls`'s surface and exposes just the operations Onyx needs:
//!
//!   * **identity** — wrap our long-term signing key as an MLS credential
//!     (currently a fresh ED25519 key per [`MlsParty`] — binding it to
//!     [`crate::identity::Identity`] is a follow-up; see
//!     [`MlsParty::new`] notes),
//!   * **bootstrap** — generate a KeyPackage to be invited, create a
//!     group, invite a peer, accept a Welcome,
//!   * **traffic** — encrypt and decrypt application messages,
//!   * **exporter** — pull the per-epoch secret that
//!     [`crate::routing::session_token`] consumes.
//!
//! ## Ciphersuite
//!
//! Onyx uses `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`
//! (RFC 9420 suite 3) — matches our transport and at-rest AEAD choices.
//!
//! ## Storage
//!
//! Each [`MlsParty`] carries its own [`OpenMlsRustCrypto`] provider with
//! an in-memory key/state store. Persistence into [`crate::storage::Vault`]
//! is a follow-up. **Implication for v0**: process restart loses MLS
//! group state. Acceptable for the daemon process not yet existing.
//!
//! ## Audit caveat
//!
//! Like `snow` and `ml-kem`, `openmls` is widely used (it's the IETF
//! reference Rust implementation) but is not formally audited as a
//! whole. Worth flagging in any future security review.

use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::framing::{MlsMessageIn, MlsMessageOut, ProcessedMessageContent, ProtocolMessage};
use openmls::group::{MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, StagedWelcome};
use openmls::key_packages::KeyPackage;
use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use openmls::prelude::{
    Ciphersuite, DeserializeBytes, KeyPackageIn, MlsMessageBodyIn, ProtocolVersion,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use openmls_traits::types::SignatureScheme;

use crate::error::{Error, Result};

/// Onyx-wide MLS ciphersuite. X25519 / ChaCha20-Poly1305 / SHA-256 /
/// Ed25519 — keeps the algorithm set consistent with our other layers.
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

/// MLS-Exporter label that produces the routing-token base secret.
/// MUST match [`crate::routing::MLS_EXPORTER_LABEL`] (kept in sync by
/// the test below).
const ROUTING_EXPORTER_LABEL: &str = "onyx/v1/routing";

fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build()
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build()
}

// Concise error mapping. openmls's error types are deeply structured
// per operation — for the wrapper's surface we collapse them to either
// `VerificationFailed` (anything that looks like tampering / wrong key)
// or `Internal` (everything else, including caller-state misuse).
fn internal<E>(label: &'static str) -> impl FnOnce(E) -> Error {
    move |_| Error::Internal(label)
}

// ── MlsParty ───────────────────────────────────────────────────────────────

/// An MLS participant — credential + signature keypair + crypto provider.
/// Each party owns its own in-memory key/state store; calling
/// [`MlsParty::new`] twice gives two independent participants suitable
/// for in-process round-trip tests.
///
/// **Identity binding to our Ed25519 long-term key is not wired yet.**
/// v0 generates a fresh MLS signature keypair per party so the
/// integration with `openmls`'s default keystore is straightforward.
/// Once we have the daemon, the natural change is to back the MLS
/// signature key with [`crate::crypto::SigningKey`] — `SignatureKeyPair`
/// has a from-raw constructor that accepts the seed bytes.
pub struct MlsParty {
    credential_with_key: CredentialWithKey,
    signature_keys: SignatureKeyPair,
    provider: OpenMlsRustCrypto,
}

impl MlsParty {
    /// Create a new party with the given byte label as the
    /// `BasicCredential` identity. In v0 this label is the only
    /// caller-supplied input; v1 will use the Ed25519 fingerprint.
    pub fn new(identity_label: Vec<u8>) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let credential = BasicCredential::new(identity_label);
        let signature_keys = SignatureKeyPair::new(SignatureScheme::ED25519)
            .map_err(internal("mls: signature key generation failed"))?;
        signature_keys
            .store(provider.storage())
            .map_err(internal("mls: signature key store failed"))?;

        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        };
        Ok(Self {
            credential_with_key,
            signature_keys,
            provider,
        })
    }

    /// Generate a fresh `KeyPackage` for this party and serialise it.
    /// Send the bytes to a peer who wants to invite us into a group.
    pub fn key_package_bytes(&self) -> Result<Vec<u8>> {
        let kp_bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signature_keys,
                self.credential_with_key.clone(),
            )
            .map_err(internal("mls: KeyPackage build failed"))?;
        kp_bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(internal("mls: KeyPackage serialise failed"))
    }

    /// Create a new MLS group containing only this party.
    pub fn create_group(&self) -> Result<MlsGroupState> {
        let group = MlsGroup::new(
            &self.provider,
            &self.signature_keys,
            &create_config(),
            self.credential_with_key.clone(),
        )
        .map_err(internal("mls: group creation failed"))?;
        Ok(MlsGroupState { group })
    }

    /// Join an existing group from a serialised Welcome (the bytes that
    /// arrived inside a sealed-sender bootstrap envelope —
    /// [`crate::routing::OpenedBootstrap::mls_welcome`]).
    pub fn join_from_welcome(&self, welcome_bytes: &[u8]) -> Result<MlsGroupState> {
        let mls_in = MlsMessageIn::tls_deserialize_exact_bytes(welcome_bytes)
            .map_err(|_| Error::InvalidEncoding("mls: welcome bytes not TLS-encoded"))?;
        let MlsMessageBodyIn::Welcome(welcome) = mls_in.extract() else {
            return Err(Error::InvalidEncoding("mls: expected Welcome message"));
        };
        let staged = StagedWelcome::new_from_welcome(&self.provider, &join_config(), welcome, None)
            .map_err(internal("mls: welcome staging failed"))?;
        let group = staged
            .into_group(&self.provider)
            .map_err(internal("mls: group construction from welcome failed"))?;
        Ok(MlsGroupState { group })
    }
}

impl std::fmt::Debug for MlsParty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlsParty").finish_non_exhaustive()
    }
}

// ── MlsGroupState ──────────────────────────────────────────────────────────

/// Live MLS group state for one party. Pass the same [`MlsParty`] back
/// in for every operation — operations use that party's provider /
/// keystore, which is where the group state actually lives.
pub struct MlsGroupState {
    group: MlsGroup,
}

impl MlsGroupState {
    /// Add a member by their serialised KeyPackage. Returns the
    /// serialised Welcome to forward to the new member. Internally
    /// commits the change and updates this group's epoch.
    pub fn invite(&mut self, party: &MlsParty, peer_kp_bytes: &[u8]) -> Result<Vec<u8>> {
        let kp_in = KeyPackageIn::tls_deserialize_exact_bytes(peer_kp_bytes)
            .map_err(|_| Error::InvalidEncoding("mls: peer KeyPackage not TLS-encoded"))?;
        let kp = kp_in
            .validate(party.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(internal("mls: peer KeyPackage validation failed"))?;

        let (_commit, welcome_out, _group_info) = self
            .group
            .add_members(&party.provider, &party.signature_keys, &[kp])
            .map_err(internal("mls: add_members failed"))?;

        // Solo group becoming 2-person: the commit has no other existing
        // members to distribute to; we just merge it locally so our
        // group state moves to the new epoch.
        self.group
            .merge_pending_commit(&party.provider)
            .map_err(internal("mls: merge_pending_commit failed"))?;

        serialize_mls_message(&welcome_out)
    }

    /// Encrypt an application message for the group.
    pub fn encrypt_application(&mut self, party: &MlsParty, plaintext: &[u8]) -> Result<Vec<u8>> {
        let out = self
            .group
            .create_message(&party.provider, &party.signature_keys, plaintext)
            .map_err(internal("mls: create_message failed"))?;
        serialize_mls_message(&out)
    }

    /// Decrypt an incoming application message. Tampered ciphertext or
    /// a wrong-key sender surface as [`Error::VerificationFailed`].
    pub fn decrypt_application(&mut self, party: &MlsParty, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mls_in = MlsMessageIn::tls_deserialize_exact_bytes(ciphertext)
            .map_err(|_| Error::InvalidEncoding("mls: incoming message not TLS-encoded"))?;

        let protocol_msg: ProtocolMessage = match mls_in.extract() {
            MlsMessageBodyIn::PrivateMessage(pm) => pm.into(),
            MlsMessageBodyIn::PublicMessage(pm) => pm.into(),
            _ => {
                return Err(Error::InvalidEncoding(
                    "mls: incoming message is not a PrivateMessage / PublicMessage",
                ));
            }
        };

        let processed = self
            .group
            .process_message(&party.provider, protocol_msg)
            .map_err(|_| Error::VerificationFailed)?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(am) => Ok(am.into_bytes()),
            _ => Err(Error::InvalidEncoding(
                "mls: processed message is not an ApplicationMessage",
            )),
        }
    }

    /// Per-epoch 32-byte routing-token base secret. Identical across
    /// all members of the group at the same epoch — that's what makes
    /// the token namespace consistent for routing.
    ///
    /// Consumed by [`crate::routing::session_token`].
    pub fn export_routing_secret(&self, party: &MlsParty) -> Result<[u8; 32]> {
        // openmls 0.8 takes `&impl OpenMlsCrypto` here (was `&impl
        // OpenMlsProvider` in 0.6). Reach into the provider for the
        // crypto component.
        let v = self
            .group
            .export_secret(party.provider.crypto(), ROUTING_EXPORTER_LABEL, &[], 32)
            .map_err(internal("mls: exporter failed"))?;
        v.as_slice()
            .try_into()
            .map_err(|_| Error::Internal("mls: exporter returned wrong length"))
    }

    /// Current MLS group epoch counter. Useful for diagnostics and for
    /// keying per-epoch derivations.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }
}

impl std::fmt::Debug for MlsGroupState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlsGroupState")
            .field("epoch", &self.epoch())
            .finish_non_exhaustive()
    }
}

fn serialize_mls_message(msg: &MlsMessageOut) -> Result<Vec<u8>> {
    msg.tls_serialize_detached()
        .map_err(internal("mls: message serialise failed"))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing;

    fn alice_and_bob() -> (MlsParty, MlsParty) {
        let alice = MlsParty::new(b"alice".to_vec()).unwrap();
        let bob = MlsParty::new(b"bob".to_vec()).unwrap();
        (alice, bob)
    }

    /// Set up a 2-party group via the welcome flow and return both
    /// sides at the same epoch.
    fn established_2party() -> (MlsParty, MlsParty, MlsGroupState, MlsGroupState) {
        let (alice, bob) = alice_and_bob();
        let bob_kp = bob.key_package_bytes().unwrap();

        let mut alice_group = alice.create_group().unwrap();
        let welcome = alice_group.invite(&alice, &bob_kp).unwrap();
        let bob_group = bob.join_from_welcome(&welcome).unwrap();

        // Sanity: epochs match (both at epoch 1 after the add).
        assert_eq!(alice_group.epoch(), bob_group.epoch());
        (alice, bob, alice_group, bob_group)
    }

    #[test]
    fn party_can_be_created() {
        let _alice = MlsParty::new(b"alice".to_vec()).unwrap();
    }

    #[test]
    fn key_package_bytes_are_nonempty() {
        let alice = MlsParty::new(b"alice".to_vec()).unwrap();
        let kp = alice.key_package_bytes().unwrap();
        assert!(
            !kp.is_empty(),
            "KeyPackage serialisation must produce bytes"
        );
    }

    #[test]
    fn solo_group_can_be_created() {
        let alice = MlsParty::new(b"alice".to_vec()).unwrap();
        let group = alice.create_group().unwrap();
        assert_eq!(group.epoch(), 0);
    }

    #[test]
    fn invite_produces_welcome_and_advances_epoch() {
        let (alice, bob) = alice_and_bob();
        let bob_kp = bob.key_package_bytes().unwrap();
        let mut alice_group = alice.create_group().unwrap();
        assert_eq!(alice_group.epoch(), 0);
        let welcome = alice_group.invite(&alice, &bob_kp).unwrap();
        assert!(!welcome.is_empty());
        assert_eq!(alice_group.epoch(), 1, "add+merge should advance the epoch");
    }

    #[test]
    fn welcome_round_trip_creates_matching_groups() {
        let (_alice, _bob, alice_group, bob_group) = established_2party();
        assert_eq!(alice_group.epoch(), bob_group.epoch());
    }

    #[test]
    fn alice_to_bob_application_message() {
        let (alice, bob, mut alice_group, mut bob_group) = established_2party();
        let plaintext = b"hello bob, this is the first real E2E message in Onyx";
        let ct = alice_group.encrypt_application(&alice, plaintext).unwrap();
        let pt = bob_group.decrypt_application(&bob, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn bidirectional_application_messages() {
        let (alice, bob, mut alice_group, mut bob_group) = established_2party();
        let ct_a = alice_group
            .encrypt_application(&alice, b"hello bob")
            .unwrap();
        let ct_b = bob_group.encrypt_application(&bob, b"hello alice").unwrap();
        assert_eq!(
            bob_group.decrypt_application(&bob, &ct_a).unwrap(),
            b"hello bob"
        );
        assert_eq!(
            alice_group.decrypt_application(&alice, &ct_b).unwrap(),
            b"hello alice"
        );
    }

    #[test]
    fn multiple_messages_in_sequence() {
        let (alice, bob, mut alice_group, mut bob_group) = established_2party();
        for i in 0..5u8 {
            let msg = vec![i; 32];
            let ct = alice_group.encrypt_application(&alice, &msg).unwrap();
            let pt = bob_group.decrypt_application(&bob, &ct).unwrap();
            assert_eq!(pt, msg);
        }
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (alice, bob, mut alice_group, mut bob_group) = established_2party();
        let mut ct = alice_group
            .encrypt_application(&alice, b"do not modify")
            .unwrap();
        // Tamper inside the AEAD-protected portion. The exact byte index
        // doesn't matter — any flip should break the per-message tag.
        let mid = ct.len() / 2;
        ct[mid] ^= 0x01;
        assert!(matches!(
            bob_group.decrypt_application(&bob, &ct),
            Err(Error::VerificationFailed)
        ));
    }

    #[test]
    fn exporter_agrees_across_members_at_same_epoch() {
        let (alice, bob, alice_group, bob_group) = established_2party();
        let a = alice_group.export_routing_secret(&alice).unwrap();
        let b = bob_group.export_routing_secret(&bob).unwrap();
        assert_eq!(a, b, "MLS exporter at same epoch must agree across members");
    }

    #[test]
    fn exporter_differs_across_groups() {
        let (alice1, _bob1, g1, _) = established_2party();
        let (alice2, _bob2, g2, _) = established_2party();
        let s1 = g1.export_routing_secret(&alice1).unwrap();
        let s2 = g2.export_routing_secret(&alice2).unwrap();
        assert_ne!(
            s1, s2,
            "different groups must derive different exporter secrets"
        );
    }

    #[test]
    fn exporter_secret_feeds_session_token() {
        // Stitches MLS to routing: the exporter secret is exactly the
        // input that routing::session_token expects.
        let (alice, bob, alice_group, bob_group) = established_2party();
        let alice_secret = alice_group.export_routing_secret(&alice).unwrap();
        let bob_secret = bob_group.export_routing_secret(&bob).unwrap();
        assert_eq!(alice_secret, bob_secret);

        let alice_token = routing::session_token(&alice_secret, 7);
        let bob_token = routing::session_token(&bob_secret, 7);
        assert_eq!(
            alice_token, bob_token,
            "both members at the same epoch must derive the same session token \
             for any given index — this is how the hub routes Tier-2 messages"
        );
    }

    #[test]
    fn exporter_label_matches_routing_module() {
        // If anyone bumps the MLS_EXPORTER_LABEL in routing.rs without
        // updating ROUTING_EXPORTER_LABEL here (or vice versa), this
        // test fails loudly.
        assert_eq!(
            ROUTING_EXPORTER_LABEL.as_bytes(),
            routing::MLS_EXPORTER_LABEL,
            "MLS exporter label MUST match the label routing.rs documents"
        );
    }

    #[test]
    fn malformed_welcome_rejected_safely() {
        let bob = MlsParty::new(b"bob".to_vec()).unwrap();
        let result = bob.join_from_welcome(b"not a welcome");
        assert!(matches!(result, Err(Error::InvalidEncoding(_))));
    }

    #[test]
    fn malformed_application_message_rejected_safely() {
        let (alice, bob, _, mut bob_group) = established_2party();
        let _ = alice; // alice not needed once group is established
        let result = bob_group.decrypt_application(&bob, b"definitely not TLS-encoded");
        assert!(matches!(result, Err(Error::InvalidEncoding(_))));
    }
}
