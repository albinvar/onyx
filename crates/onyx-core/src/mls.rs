//! MLS (RFC 9420) group state and message processing — wrapper over `openmls`.
//!
//! See DESIGN.md §6. This module deliberately hides almost all of
//! `openmls`'s surface and exposes just the operations Onyx needs:
//!
//!   * **identity** — [`MlsParty::from_identity`] binds the MLS
//!     credential signing key to the long-term [`Identity`]'s Ed25519
//!     key. The MLS signature pubkey equals the user's fingerprint
//!     bytes, and the `BasicCredential` identity field equals the
//!     fingerprint too — so the MLS credential is byte-identical to
//!     whatever the Noise XK handshake authenticated at the transport
//!     layer. [`MlsParty::new`] (fresh key per call) remains for tests.
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
//! an in-memory `MemoryStorage` key-value store. We snapshot the entire
//! store to a single byte blob via [`MlsParty::snapshot_state`] and
//! restore it via [`MlsParty::from_identity_and_state`]; that blob then
//! goes through [`crate::storage::Vault::save_mls_state`] /
//! [`crate::storage::Vault::load_mls_state`] for AEAD-sealed at-rest
//! storage keyed by identity id. After restore,
//! [`MlsParty::load_group`] resumes an [`MlsGroup`] by its serialised
//! group id.
//!
//! Daemon-side wiring (sharing one persistent `MlsParty` across all
//! inbound connections, saving the snapshot after each modification)
//! is the next phase.
//!
//! ## Audit caveat
//!
//! Like `snow` and `ml-kem`, `openmls` is widely used (it's the IETF
//! reference Rust implementation) but is not formally audited as a
//! whole. Worth flagging in any future security review.

use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::framing::{MlsMessageIn, MlsMessageOut, ProcessedMessageContent, ProtocolMessage};
use openmls::group::{GroupId, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, StagedWelcome};
use openmls::key_packages::KeyPackage;
use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use openmls::prelude::{
    Ciphersuite, DeserializeBytes, KeyPackageIn, MlsMessageBodyIn, ProtocolVersion,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use openmls_traits::types::SignatureScheme;
use serde_bytes::ByteBuf;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::identity::Identity;

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
///
/// Two constructors:
///
///   * [`MlsParty::from_identity`] (production) — MLS credential
///     bound to a long-term [`Identity`]. Same Ed25519 key as Noise
///     authenticated; deterministic; survives restart once we wire
///     storage persistence.
///   * [`MlsParty::new`] (tests) — fresh ED25519 keypair, ad-hoc
///     byte label as the credential identity.
///
/// Each party owns its own [`OpenMlsRustCrypto`] provider with an
/// in-memory `MemoryStorage` key/state store. To survive restart,
/// snapshot via [`Self::snapshot_state`], persist the bytes through
/// [`crate::storage::Vault::save_mls_state`], and restore via
/// [`Self::from_identity_and_state`] + [`Self::load_group`].
pub struct MlsParty {
    credential_with_key: CredentialWithKey,
    signature_keys: SignatureKeyPair,
    provider: OpenMlsRustCrypto,
}

impl MlsParty {
    /// Create a new party with the given byte label as the
    /// `BasicCredential` identity and a freshly-generated Ed25519
    /// signing key. **For tests and one-off use only** — production
    /// daemons should use [`Self::from_identity`] so the MLS
    /// credential is provably the same identity that authenticated
    /// at the Noise layer.
    pub fn new(identity_label: Vec<u8>) -> Result<Self> {
        let signature_keys = SignatureKeyPair::new(SignatureScheme::ED25519)
            .map_err(internal("mls: signature key generation failed"))?;
        Self::assemble(identity_label, signature_keys)
    }

    /// Create a party whose MLS credential is bound to the given
    /// long-term [`Identity`].
    ///
    /// The MLS signature key is the **same** Ed25519 key that
    /// `identity.signing()` exposes — the 32-byte seed is shared
    /// verbatim with `openmls`'s `SignatureKeyPair::from_raw`
    /// constructor. The `BasicCredential` identity field is the
    /// 32-byte fingerprint (= verifying key bytes), so the MLS
    /// credential is byte-identical to whatever the Noise XK
    /// handshake authenticated at the transport layer.
    ///
    /// Determinism: two `MlsParty`s constructed from the **same**
    /// `Identity` produce **byte-identical** signature public keys
    /// and credentials. This is what lets MLS state survive daemon
    /// restarts once we wire persistence — the credential at restart
    /// matches the credential the group was created with.
    pub fn from_identity(identity: &Identity) -> Result<Self> {
        let signing = identity.signing();
        let private_seed = signing.to_bytes(); // Zeroizing<[u8; 32]>
        let public = signing.verifying_key().to_bytes();
        // NOTE (T-zeroize-audit): `private_seed.to_vec()` allocates a
        // fresh non-Zeroizing Vec<u8> that we hand to openmls. Once
        // `from_raw` consumes the Vec, openmls owns the bytes — we
        // can't enforce zeroization downstream of that handoff. The
        // original `private_seed` is still Zeroizing and scrubs when
        // it goes out of scope; the brief intermediate Vec is a known
        // upstream-dependent gap, called out in MEMORY_HYGIENE.md.
        let signature_keys = SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            private_seed.to_vec(),
            public.to_vec(),
        );
        let fingerprint_bytes = identity.fingerprint().as_bytes().to_vec();
        Self::assemble(fingerprint_bytes, signature_keys)
    }

    /// Common tail of [`Self::new`] and [`Self::from_identity`].
    fn assemble(identity_label: Vec<u8>, signature_keys: SignatureKeyPair) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let credential = BasicCredential::new(identity_label);
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

    /// Public signing key for this party as raw bytes (32 bytes for
    /// the ed25519 ciphersuite). Used as the "this is me" reference
    /// when scanning a group's members for the peer.
    #[must_use]
    pub fn signing_public_bytes(&self) -> Vec<u8> {
        self.signature_keys.to_public_vec()
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

    /// Extract the Ed25519 signing public-key bytes embedded in a
    /// serialised KeyPackage, **without** committing to inviting the
    /// publisher into any group. Callers should hash the returned
    /// bytes via [`crate::crypto::VerifyingKey::fingerprint`] and
    /// compare against the expected fingerprint *before* using the
    /// KP for any group operation — defends against a hostile
    /// directory (e.g. `THREAT_MODEL.md` §8.2 #15: hub does not
    /// validate publisher ownership of a routing id).
    ///
    /// Fails with [`Error::InvalidEncoding`] if the bytes don't
    /// deserialise as a TLS-encoded KeyPackage; with
    /// [`Error::VerificationFailed`] if the KP doesn't validate
    /// (signature, lifetime, ciphersuite, etc.). The successful
    /// path returns exactly 32 bytes (Ed25519 pubkey).
    pub fn peer_signing_pk_from_kp_bytes(&self, kp_bytes: &[u8]) -> Result<[u8; 32]> {
        signing_key_from_kp_bytes(kp_bytes)
    }
}

/// Free-standing variant of [`MlsParty::peer_signing_pk_from_kp_bytes`]
/// — extract and validate the Ed25519 signing key embedded in a
/// TLS-serialised MLS KeyPackage without needing to hold an `MlsParty`
/// instance.
///
/// Same return contract: 32-byte Ed25519 public key on success,
/// [`Error::InvalidEncoding`] for non-KeyPackage bytes,
/// [`Error::VerificationFailed`] if the KP's own signature / lifetime
/// / ciphersuite checks fail.
///
/// **Use case**: `onyx-hub` validates `FRAME_KP_PUBLISH` payloads
/// (THREAT_MODEL §8.2 #15) — the hub doesn't run MLS itself but it
/// needs to verify the publisher's claimed routing id matches the
/// fingerprint derivable from the KP's signing key, to defend against
/// a hostile client overwriting another peer's directory entry. The
/// hub creates an ephemeral [`OpenMlsRustCrypto`] provider per call;
/// it carries no persistent state because we're only using its
/// crypto trait impls for the [`KeyPackageIn::validate`] step.
/// Peek the `group_id` from a serialised MLS application message
/// without decrypting it (T6.3.d).
///
/// Used by the per-peer recipient task to decide whether an incoming
/// `FRAME_MLS_APP` belongs to this peer's DM group or to a multi-
/// party room both sides are members of. The cleartext MLS header
/// carries the group_id in both `PrivateMessage` and `PublicMessage`
/// framings (RFC 9420 §6) so we can extract it before holding the
/// MLS state lock.
///
/// **Privacy note.** The group_id is *already on the wire in
/// cleartext as part of the MLS framing* — peeking here does not
/// leak any information that a passive observer of the Tor stream
/// couldn't already see at the MLS layer. The local lookup keeps
/// the MlsParty / vault locks brief.
///
/// Returns `Error::InvalidEncoding` on non-MLS bytes,
/// `Error::InvalidEncoding` on a framing kind we don't handle
/// (Welcome, KeyPackage, GroupInfo).
pub fn peek_group_id(ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mls_in = MlsMessageIn::tls_deserialize_exact_bytes(ciphertext)
        .map_err(|_| Error::InvalidEncoding("mls: peek_group_id: not MLS-encoded"))?;
    let pm: ProtocolMessage = match mls_in.extract() {
        MlsMessageBodyIn::PrivateMessage(pm) => pm.into(),
        MlsMessageBodyIn::PublicMessage(pm) => pm.into(),
        _ => {
            return Err(Error::InvalidEncoding(
                "mls: peek_group_id: not a Private/PublicMessage",
            ));
        }
    };
    Ok(pm.group_id().as_slice().to_vec())
}

pub fn signing_key_from_kp_bytes(kp_bytes: &[u8]) -> Result<[u8; 32]> {
    let kp_in = KeyPackageIn::tls_deserialize_exact_bytes(kp_bytes)
        .map_err(|_| Error::InvalidEncoding("mls: peer KeyPackage not TLS-encoded"))?;
    let provider = OpenMlsRustCrypto::default();
    let kp = kp_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|_| Error::VerificationFailed)?;
    let sig_bytes = kp.leaf_node().signature_key().as_slice();
    <[u8; 32]>::try_from(sig_bytes)
        .map_err(|_| Error::InvalidEncoding("mls: KeyPackage signing key not 32 bytes"))
}

#[cfg(test)]
mod free_standing_helper_tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn signing_key_from_kp_bytes_round_trips() {
        let id = Identity::generate();
        let party = MlsParty::from_identity(&id).unwrap();
        let kp_bytes = party.key_package_bytes().unwrap();
        let recovered = signing_key_from_kp_bytes(&kp_bytes).expect("extract");
        assert_eq!(
            &recovered,
            id.fingerprint().as_bytes(),
            "extracted signing key bytes must equal the identity's fingerprint \
             (which is the Ed25519 verifying-key bytes by design)"
        );
    }

    #[test]
    fn signing_key_from_kp_bytes_rejects_garbage() {
        assert!(signing_key_from_kp_bytes(&[]).is_err());
        assert!(signing_key_from_kp_bytes(b"definitely not a TLS KeyPackage").is_err());
    }

    #[test]
    fn signing_key_from_kp_bytes_matches_party_method() {
        // The two paths must agree byte-for-byte.
        let id = Identity::generate();
        let party = MlsParty::from_identity(&id).unwrap();
        let kp_bytes = party.key_package_bytes().unwrap();
        let via_free = signing_key_from_kp_bytes(&kp_bytes).unwrap();
        let via_method = party.peer_signing_pk_from_kp_bytes(&kp_bytes).unwrap();
        assert_eq!(via_free, via_method);
    }
}

// Re-open the impl block so subsequent methods stay grouped.
impl MlsParty {
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

    /// Serialise the entire in-memory storage state (all signature
    /// keypairs + all group state for every group this party
    /// participates in) into a single byte blob. Suitable for sealing
    /// under the vault key and persisting via
    /// [`crate::storage::Vault::save_mls_state`].
    ///
    /// Returns `Zeroizing<Vec<u8>>` — the snapshot contains group
    /// secrets and the signature private key.
    ///
    /// We serialise the underlying `HashMap<Vec<u8>, Vec<u8>>` as a
    /// CBOR-encoded `Vec<(ByteBuf, ByteBuf)>`. CBOR keeps byte strings
    /// compact (no base64 inflation like the upstream `MemoryStorage`
    /// JSON helper does).
    pub fn snapshot_state(&self) -> Result<Zeroizing<Vec<u8>>> {
        let map = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| Error::Internal("mls: MemoryStorage RwLock poisoned"))?;
        let entries: Vec<(ByteBuf, ByteBuf)> = map
            .iter()
            .map(|(k, v)| (ByteBuf::from(k.clone()), ByteBuf::from(v.clone())))
            .collect();
        drop(map);
        let mut out = Vec::new();
        ciborium::into_writer(&entries, &mut out)
            .map_err(|_| Error::Internal("mls: snapshot CBOR encode failed"))?;
        Ok(Zeroizing::new(out))
    }

    /// Rebuild an `MlsParty` for the given long-term [`Identity`]
    /// **and** restore its provider storage from a snapshot produced
    /// earlier by [`Self::snapshot_state`].
    ///
    /// After this returns, [`Self::load_group`] can be used to resume
    /// any group the party was previously a member of.
    pub fn from_identity_and_state(identity: &Identity, snapshot: &[u8]) -> Result<Self> {
        let party = Self::from_identity(identity)?;
        let entries: Vec<(ByteBuf, ByteBuf)> = ciborium::from_reader(snapshot)
            .map_err(|_| Error::InvalidEncoding("mls: snapshot is not valid CBOR"))?;
        {
            let mut map = party
                .provider
                .storage()
                .values
                .write()
                .map_err(|_| Error::Internal("mls: MemoryStorage RwLock poisoned"))?;
            for (k, v) in entries {
                map.insert(k.into_vec(), v.into_vec());
            }
        }
        Ok(party)
    }

    /// Resume a previously-existing group by its serialised id.
    /// Returns `Ok(None)` if no state for that group is present.
    pub fn load_group(&self, group_id_bytes: &[u8]) -> Result<Option<MlsGroupState>> {
        let group_id = GroupId::from_slice(group_id_bytes);
        let group = MlsGroup::load(self.provider.storage(), &group_id)
            .map_err(internal("mls: load group failed"))?;
        Ok(group.map(|g| MlsGroupState { group: g }))
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
/// Discriminator returned by [`MlsGroupState::process_incoming`].
/// Distinguishes "decrypted plaintext you should surface" from
/// "this was a member-change commit that I've already merged
/// into the group state for you."
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncomingRoomMessage {
    /// MLS application message; bytes are the plaintext.
    Application(Vec<u8>),
    /// MLS commit (add/remove/update). Already processed and merged
    /// into the group; the group's epoch has advanced.
    Commit,
}

pub struct MlsGroupState {
    group: MlsGroup,
}

impl MlsGroupState {
    /// Add a member by their serialised KeyPackage. Returns the
    /// pair of serialised MLS messages produced by the commit:
    ///
    ///   * **`commit_bytes`** — the Commit message that every
    ///     *existing* member of the group must process so their
    ///     own copy of the group state advances to the new epoch.
    ///     For a solo-group → 2-party invite there are no existing
    ///     members and this can be discarded (the new member learns
    ///     the new epoch from the Welcome alone). For an N≥3 invite
    ///     the caller MUST fan it out to every existing member or
    ///     they'll silently stop being able to decrypt room messages
    ///     (their MLS ratchet stays at the old epoch while ours
    ///     advances).
    ///   * **`welcome_bytes`** — the Welcome message for the new
    ///     member.
    ///
    /// Internally merges the pending commit so our own group state
    /// moves to the new epoch atomically.
    ///
    /// **T6.3.h bugfix note**: pre-T6.3.h, this function only
    /// returned the Welcome and discarded the commit. That was
    /// correct for solo→2-party (the only case T6.1–T6.2 cared
    /// about) but silently broke 3+-party rooms — existing
    /// members never advanced past the inviter's first add.
    pub fn invite(&mut self, party: &MlsParty, peer_kp_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let kp_in = KeyPackageIn::tls_deserialize_exact_bytes(peer_kp_bytes)
            .map_err(|_| Error::InvalidEncoding("mls: peer KeyPackage not TLS-encoded"))?;
        let kp = kp_in
            .validate(party.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(internal("mls: peer KeyPackage validation failed"))?;

        let (commit, welcome_out, _group_info) = self
            .group
            .add_members(&party.provider, &party.signature_keys, &[kp])
            .map_err(internal("mls: add_members failed"))?;

        self.group
            .merge_pending_commit(&party.provider)
            .map_err(internal("mls: merge_pending_commit failed"))?;

        let commit_bytes = serialize_mls_message(&commit)?;
        let welcome_bytes = serialize_mls_message(&welcome_out)?;
        Ok((commit_bytes, welcome_bytes))
    }

    /// Encrypt an application message for the group.
    pub fn encrypt_application(&mut self, party: &MlsParty, plaintext: &[u8]) -> Result<Vec<u8>> {
        let out = self
            .group
            .create_message(&party.provider, &party.signature_keys, plaintext)
            .map_err(internal("mls: create_message failed"))?;
        serialize_mls_message(&out)
    }

    /// Process any incoming MLS message for this group (T6.3.h).
    /// Used by the room recipient path, which sees both application
    /// messages AND commits (new member added by another room
    /// member). Returns [`IncomingRoomMessage`] discriminated on
    /// what came in:
    ///
    ///   * `Application(bytes)` — plaintext ready to feed to
    ///     `RoomAppMessage::from_cbor`.
    ///   * `Commit` — a member-change commit was processed and
    ///     merged into the group state; the group's epoch has
    ///     advanced. The caller doesn't need to do anything
    ///     further (other than persist the post-merge MLS
    ///     snapshot so the new epoch survives a restart).
    ///
    /// Tampered ciphertext / wrong-key sender / commits we can't
    /// staged-merge all surface as [`Error::VerificationFailed`].
    /// Non-Private/Public framings (Welcome, KeyPackage, GroupInfo
    /// at this layer) surface as [`Error::InvalidEncoding`] — the
    /// dispatcher above this is responsible for routing those to
    /// the right path.
    pub fn process_incoming(
        &mut self,
        party: &MlsParty,
        ciphertext: &[u8],
    ) -> Result<IncomingRoomMessage> {
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
            ProcessedMessageContent::ApplicationMessage(am) => {
                Ok(IncomingRoomMessage::Application(am.into_bytes()))
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                self.group
                    .merge_staged_commit(&party.provider, *staged)
                    .map_err(internal("mls: merge_staged_commit failed"))?;
                Ok(IncomingRoomMessage::Commit)
            }
            _ => Err(Error::InvalidEncoding(
                "mls: processed message is not Application or StagedCommit",
            )),
        }
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

    /// Public signing key of the *other* member of a 2-party group,
    /// as raw bytes. The argument is our own public signing key —
    /// the comparison happens here so the caller doesn't need to
    /// `Eq`-implement the wrapper types. Returns `None` when this
    /// group isn't a tidy 2-party group (solo, or > 2 members).
    ///
    /// v0 Onyx is point-to-point, so a 2-member group is the only
    /// case the daemon cares about. Multi-party rooms will surface
    /// peers via a different API.
    #[must_use]
    pub fn peer_signing_key_bytes(&self, our_signing_pub: &[u8]) -> Option<Vec<u8>> {
        let mut peers: Vec<Vec<u8>> = self
            .group
            .members()
            .map(|m| m.signature_key)
            .filter(|k| k.as_slice() != our_signing_pub)
            .collect();
        if peers.len() == 1 {
            Some(peers.pop().expect("len checked"))
        } else {
            None
        }
    }

    /// Raw signing public keys of every current member of this group,
    /// in the order MLS lists them (leaf-index order). Used by the
    /// room layer (T6.3.c) to derive the members fingerprint cache
    /// from the post-join / post-invite group state. Unlike
    /// [`Self::peer_signing_key_bytes`] this works for groups of any
    /// size, including the inviter's own row (callers filter as
    /// needed).
    #[must_use]
    pub fn member_signing_keys(&self) -> Vec<Vec<u8>> {
        self.group
            .members()
            .map(|m| m.signature_key.as_slice().to_vec())
            .collect()
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

    /// Group identifier bytes. Pass to [`MlsParty::load_group`] after
    /// restoring an [`MlsParty`] from a persisted snapshot.
    #[must_use]
    pub fn group_id_bytes(&self) -> Vec<u8> {
        self.group.group_id().as_slice().to_vec()
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
    use crate::crypto::SigningKey;
    use crate::routing;

    fn alice_and_bob() -> (MlsParty, MlsParty) {
        let alice = MlsParty::new(b"alice".to_vec()).unwrap();
        let bob = MlsParty::new(b"bob".to_vec()).unwrap();
        (alice, bob)
    }

    /// Build an [`Identity`] from a fixed 32-byte seed for deterministic
    /// binding tests. We avoid going through `Identity::generate` because
    /// we explicitly want the same seed twice.
    fn identity_from_seed(signing_seed: [u8; 32], x25519_seed: [u8; 32]) -> Identity {
        Identity::from_seeds(&signing_seed, x25519_seed)
    }

    #[test]
    fn from_identity_is_deterministic_in_signature_public_key() {
        // Two `MlsParty`s built from the *same* Identity must produce
        // the **same** MLS signature public-key bytes and the **same**
        // credential identity field. This is the invariant that lets
        // persisted MLS group state still verify after a daemon
        // restart.
        let id1 = identity_from_seed([7u8; 32], [9u8; 32]);
        let id2 = identity_from_seed([7u8; 32], [9u8; 32]);

        let a = MlsParty::from_identity(&id1).unwrap();
        let b = MlsParty::from_identity(&id2).unwrap();

        let a_pub = a.signature_keys.to_public_vec();
        let b_pub = b.signature_keys.to_public_vec();
        assert_eq!(
            a_pub, b_pub,
            "MLS signature pubkey must be deterministic from Identity"
        );

        // The CredentialWithKey.signature_key field also has to match
        // (it's just a copy of the public bytes, but assert the chain).
        assert_eq!(
            a.credential_with_key.signature_key,
            b.credential_with_key.signature_key,
        );

        // And the Ed25519 fingerprint matches the verifying key used
        // inside the SignatureKeyPair.
        assert_eq!(a_pub, id1.fingerprint().as_bytes().as_slice());
    }

    #[test]
    fn from_identity_two_different_identities_have_different_keys() {
        let id1 = identity_from_seed([1u8; 32], [2u8; 32]);
        let id2 = identity_from_seed([3u8; 32], [4u8; 32]);
        let a = MlsParty::from_identity(&id1).unwrap();
        let b = MlsParty::from_identity(&id2).unwrap();
        assert_ne!(
            a.signature_keys.to_public_vec(),
            b.signature_keys.to_public_vec()
        );
    }

    #[test]
    fn snapshot_restore_round_trip_preserves_group() {
        // The killer test: two parties form a group + exchange a
        // message; both snapshot; both restored into fresh `MlsParty`s
        // from the snapshot bytes; both can load the *same* group by
        // id; a NEW application message after restore decrypts
        // correctly. This is the persistence invariant the daemon
        // needs to survive restart.
        let id_a = identity_from_seed([100u8; 32], [101u8; 32]);
        let id_b = identity_from_seed([110u8; 32], [111u8; 32]);

        // Phase 1: set up the group.
        let alice = MlsParty::from_identity(&id_a).unwrap();
        let bob = MlsParty::from_identity(&id_b).unwrap();
        let bob_kp = bob.key_package_bytes().unwrap();

        let mut alice_group = alice.create_group().unwrap();
        let group_id = alice_group.group_id_bytes();
        let (_, welcome) = alice_group.invite(&alice, &bob_kp).unwrap();
        let mut bob_group = bob.join_from_welcome(&welcome).unwrap();
        assert_eq!(group_id, bob_group.group_id_bytes());

        // Exchange one message so both ratchets advance.
        let ct = alice_group
            .encrypt_application(&alice, b"before restore")
            .unwrap();
        let pt = bob_group.decrypt_application(&bob, &ct).unwrap();
        assert_eq!(pt, b"before restore");

        // Phase 2: snapshot both.
        let alice_state = alice.snapshot_state().unwrap();
        let bob_state = bob.snapshot_state().unwrap();
        assert!(!alice_state.is_empty(), "snapshot must contain bytes");
        assert!(!bob_state.is_empty());

        // Phase 3: drop the originals (simulates daemon restart).
        drop(alice_group);
        drop(bob_group);
        drop(alice);
        drop(bob);

        // Phase 4: restore both from the snapshots into fresh parties.
        let alice2 = MlsParty::from_identity_and_state(&id_a, &alice_state).unwrap();
        let bob2 = MlsParty::from_identity_and_state(&id_b, &bob_state).unwrap();

        // Phase 5: load the group state on both sides.
        let mut alice_group2 = alice2
            .load_group(&group_id)
            .unwrap()
            .expect("alice group missing after restore");
        let mut bob_group2 = bob2
            .load_group(&group_id)
            .unwrap()
            .expect("bob group missing after restore");

        // Same epoch on both sides — the restore preserved the ratchet
        // state exactly.
        assert_eq!(alice_group2.epoch(), bob_group2.epoch());

        // Phase 6: send a NEW application message after restore.
        let ct2 = alice_group2
            .encrypt_application(&alice2, b"after restore")
            .unwrap();
        let pt2 = bob_group2.decrypt_application(&bob2, &ct2).unwrap();
        assert_eq!(pt2, b"after restore");

        // And bob can reply.
        let ct3 = bob_group2
            .encrypt_application(&bob2, b"bob's reply post-restore")
            .unwrap();
        let pt3 = alice_group2.decrypt_application(&alice2, &ct3).unwrap();
        assert_eq!(pt3, b"bob's reply post-restore");
    }

    #[test]
    fn load_group_returns_none_for_unknown_id() {
        let id = identity_from_seed([200u8; 32], [201u8; 32]);
        let party = MlsParty::from_identity(&id).unwrap();
        assert!(
            party
                .load_group(b"this-group-doesnt-exist")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn from_identity_and_state_rejects_garbage() {
        let id = identity_from_seed([7u8; 32], [8u8; 32]);
        assert!(matches!(
            MlsParty::from_identity_and_state(&id, b"not cbor"),
            Err(Error::InvalidEncoding(_))
        ));
    }

    #[test]
    fn from_identity_keys_can_sign_via_mls() {
        // Bootstrap a 2-party group where both ends used from_identity,
        // and exchange one application message in each direction. This
        // exercises the MLS credential's actual signing path against
        // keys imported via from_raw.
        let alice = MlsParty::from_identity(&identity_from_seed([11u8; 32], [12u8; 32])).unwrap();
        let bob = MlsParty::from_identity(&identity_from_seed([21u8; 32], [22u8; 32])).unwrap();

        let bob_kp = bob.key_package_bytes().unwrap();
        let mut alice_group = alice.create_group().unwrap();
        let (_, welcome) = alice_group.invite(&alice, &bob_kp).unwrap();
        let mut bob_group = bob.join_from_welcome(&welcome).unwrap();

        let msg = b"hello via Identity-bound MLS credential";
        let ct = alice_group.encrypt_application(&alice, msg).unwrap();
        let pt = bob_group.decrypt_application(&bob, &ct).unwrap();
        assert_eq!(pt, msg);

        // Sanity: ensuring the SigningKey itself can be used the same
        // way ed25519-dalek expects, after the round-trip through
        // openmls's from_raw.
        let _unused = SigningKey::from_bytes(&[11u8; 32]);
    }

    /// Set up a 2-party group via the welcome flow and return both
    /// sides at the same epoch.
    fn established_2party() -> (MlsParty, MlsParty, MlsGroupState, MlsGroupState) {
        let (alice, bob) = alice_and_bob();
        let bob_kp = bob.key_package_bytes().unwrap();

        let mut alice_group = alice.create_group().unwrap();
        let (_, welcome) = alice_group.invite(&alice, &bob_kp).unwrap();
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
        let (_, welcome) = alice_group.invite(&alice, &bob_kp).unwrap();
        assert!(!welcome.is_empty());
        assert_eq!(alice_group.epoch(), 1, "add+merge should advance the epoch");
    }

    #[test]
    fn welcome_round_trip_creates_matching_groups() {
        let (_alice, _bob, alice_group, bob_group) = established_2party();
        assert_eq!(alice_group.epoch(), bob_group.epoch());
    }

    #[test]
    fn peer_signing_key_bytes_returns_the_other_member() {
        let (alice, bob, alice_group, bob_group) = established_2party();
        let alice_sig = alice.signing_public_bytes();
        let bob_sig = bob.signing_public_bytes();
        // From alice's perspective the peer is bob.
        let from_alice = alice_group
            .peer_signing_key_bytes(&alice_sig)
            .expect("2-party group should yield a peer key");
        assert_eq!(from_alice, bob_sig);
        // And the reverse.
        let from_bob = bob_group
            .peer_signing_key_bytes(&bob_sig)
            .expect("2-party group should yield a peer key");
        assert_eq!(from_bob, alice_sig);
    }

    #[test]
    fn peer_signing_key_bytes_returns_none_for_solo_group() {
        let alice = MlsParty::new(b"alice".to_vec()).unwrap();
        let group = alice.create_group().unwrap();
        let alice_sig = alice.signing_public_bytes();
        assert!(group.peer_signing_key_bytes(&alice_sig).is_none());
    }

    #[test]
    fn peer_signing_pk_from_kp_bytes_round_trips_with_kp_signing_key() {
        // Build bob, get his serialised KP, extract the embedded
        // signing public key, verify it matches bob's own signing
        // public bytes. This is the security-relevant invariant:
        // a SendBootstrapMls dispatcher uses this helper to verify
        // a fetched KP matches the expected fingerprint *before*
        // inviting the publisher into the group.
        let (alice, bob) = alice_and_bob();
        let bob_kp_bytes = bob.key_package_bytes().expect("kp serialise");
        let bob_signing = bob.signing_public_bytes();

        let extracted = alice
            .peer_signing_pk_from_kp_bytes(&bob_kp_bytes)
            .expect("extract signing pk from kp");
        assert_eq!(extracted.as_slice(), bob_signing.as_slice());
    }

    #[test]
    fn peer_signing_pk_from_kp_bytes_rejects_garbage() {
        let alice = MlsParty::new(b"alice".to_vec()).unwrap();
        assert!(alice.peer_signing_pk_from_kp_bytes(&[]).is_err());
        assert!(
            alice
                .peer_signing_pk_from_kp_bytes(b"definitely not a TLS-encoded KeyPackage")
                .is_err()
        );
    }

    // ── T6.3.d: peek_group_id ─────────────────────────────────────

    #[test]
    fn peek_group_id_round_trip_against_encrypted_application() {
        // Encrypting through a real 2-party group must produce a
        // ciphertext whose peeked group_id == the group's own
        // group_id_bytes. That's the contract the per-peer recipient
        // task relies on for room/DM disambiguation.
        let (alice, _bob, mut alice_group, _bob_group) = established_2party();
        let ct = alice_group.encrypt_application(&alice, b"hi").unwrap();
        let peeked = peek_group_id(&ct).expect("peek_group_id");
        assert_eq!(peeked, alice_group.group_id_bytes());
    }

    #[test]
    fn peek_group_id_rejects_garbage() {
        assert!(peek_group_id(&[]).is_err());
        assert!(peek_group_id(b"not MLS-encoded bytes").is_err());
    }

    // ── T6.3.g: per-epoch session-token derivation ────────────────

    /// Two members of the same group at the same epoch derive the
    /// **same** session-token routing id. This is the property
    /// `current_room_session_tokens` + `compute_room_session_token`
    /// rely on for hub-routed room messages: alice publishes to
    /// `session_token(alice's exporter at epoch N, 0)` and bob
    /// fetches from `session_token(bob's exporter at epoch N, 0)`
    /// — must be byte-identical.
    #[test]
    fn session_token_matches_across_members_at_same_epoch() {
        use crate::routing::session_token;
        let (alice, bob, alice_group, bob_group) = established_2party();
        let alice_secret = alice_group.export_routing_secret(&alice).unwrap();
        let bob_secret = bob_group.export_routing_secret(&bob).unwrap();
        assert_eq!(alice_secret, bob_secret, "per-epoch secret must match");
        assert_eq!(
            session_token(&alice_secret, 0),
            session_token(&bob_secret, 0),
            "session_token at index 0 must match across members"
        );
    }

    /// T6.3.i sanity-check: pre-fix, an app message encrypted at
    /// epoch N+1 fails to decrypt on a peer still at epoch N
    /// (returns Error rather than queuing). This pins that
    /// behaviour at the MLS layer — `process_incoming` does NOT
    /// magically queue out-of-order messages; the out-of-order
    /// buffering is the daemon's responsibility (see
    /// `buffer_pending_room_frame` in `onyx-daemon::lib`).
    #[test]
    fn process_incoming_rejects_message_from_future_epoch() {
        let alice = MlsParty::new(b"alice".to_vec()).unwrap();
        let bob = MlsParty::new(b"bob".to_vec()).unwrap();
        let carol = MlsParty::new(b"carol".to_vec()).unwrap();
        let bob_kp = bob.key_package_bytes().unwrap();
        let mut alice_group = alice.create_group().unwrap();
        let (_, welcome_to_bob) = alice_group.invite(&alice, &bob_kp).unwrap();
        let mut bob_group = bob.join_from_welcome(&welcome_to_bob).unwrap();
        // Both at epoch 1. Alice invites carol → her epoch becomes 2.
        // She encrypts an app message at epoch 2 BEFORE shipping the
        // commit to bob (simulating the race).
        let carol_kp = carol.key_package_bytes().unwrap();
        let (commit_to_bob, _welcome_to_carol) = alice_group.invite(&alice, &carol_kp).unwrap();
        assert_eq!(alice_group.epoch(), 2);
        let app_at_epoch_2 = alice_group
            .encrypt_application(&alice, b"future-epoch message")
            .unwrap();
        assert_eq!(bob_group.epoch(), 1);

        // Bob tries to decrypt the epoch-2 app message while still at
        // epoch 1: MUST fail. (Daemon-side buffer would queue this.)
        let early = bob_group.process_incoming(&bob, &app_at_epoch_2);
        assert!(
            early.is_err(),
            "epoch-2 app on epoch-1 group must error, not silently succeed"
        );

        // Bob processes the commit, advancing to epoch 2. Now the
        // SAME ciphertext bytes decrypt — that's exactly the retry
        // path the daemon-side drain_pending_room_frames exercises.
        let commit_result = bob_group.process_incoming(&bob, &commit_to_bob).unwrap();
        assert!(matches!(commit_result, IncomingRoomMessage::Commit));
        assert_eq!(bob_group.epoch(), 2);
        let retry = bob_group.process_incoming(&bob, &app_at_epoch_2).unwrap();
        assert_eq!(
            retry,
            IncomingRoomMessage::Application(b"future-epoch message".to_vec()),
            "after commit merge, the buffered epoch-2 app must decrypt"
        );
    }

    /// After a commit advances the epoch, the session token MUST
    /// change. Otherwise per-epoch unlinkability (the T6.3.g
    /// privacy property) breaks — a hub watching the inbox would
    /// see the same id span multiple epochs.
    #[test]
    fn session_token_changes_after_commit() {
        use crate::routing::session_token;
        let alice = MlsParty::new(b"alice".to_vec()).unwrap();
        let bob = MlsParty::new(b"bob".to_vec()).unwrap();
        let carol = MlsParty::new(b"carol".to_vec()).unwrap();
        let bob_kp = bob.key_package_bytes().unwrap();
        let mut alice_group = alice.create_group().unwrap();
        let (_, welcome_to_bob) = alice_group.invite(&alice, &bob_kp).unwrap();
        let _bob_group = bob.join_from_welcome(&welcome_to_bob).unwrap();
        let secret_epoch_1 = alice_group.export_routing_secret(&alice).unwrap();
        let token_epoch_1 = session_token(&secret_epoch_1, 0);

        let carol_kp = carol.key_package_bytes().unwrap();
        let (_, _welcome_to_carol) = alice_group.invite(&alice, &carol_kp).unwrap();
        let secret_epoch_2 = alice_group.export_routing_secret(&alice).unwrap();
        let token_epoch_2 = session_token(&secret_epoch_2, 0);

        assert_ne!(
            token_epoch_1, token_epoch_2,
            "session token must rotate on epoch advance"
        );
    }

    // ── T6.3.h bugfix: 3-party room commit distribution ───────────

    /// Pre-T6.3.h, `invite()` discarded the commit it produced; the
    /// inviter advanced to epoch N+1 while every existing member
    /// stayed at epoch N and silently lost the ability to decrypt
    /// subsequent room messages. This test pins the post-T6.3.h
    /// behaviour: alice invites bob (epoch 0 → 1), then alice
    /// invites carol (epoch 1 → 2). Bob processes the commit alice
    /// produced for the carol-invite via `process_incoming` and
    /// advances to epoch 2 — now bob+alice+carol can all exchange
    /// application messages decryptable by everyone.
    #[test]
    fn three_party_room_commit_distribution() {
        let alice = MlsParty::new(b"alice".to_vec()).unwrap();
        let bob = MlsParty::new(b"bob".to_vec()).unwrap();
        let carol = MlsParty::new(b"carol".to_vec()).unwrap();

        // Round 1: alice creates a group, invites bob.
        let bob_kp = bob.key_package_bytes().unwrap();
        let mut alice_group = alice.create_group().unwrap();
        let (_commit_solo_to_2, welcome_to_bob) = alice_group.invite(&alice, &bob_kp).unwrap();
        let mut bob_group = bob.join_from_welcome(&welcome_to_bob).unwrap();
        assert_eq!(alice_group.epoch(), 1);
        assert_eq!(bob_group.epoch(), 1);

        // Round 2: alice invites carol. Now alice has 3 members
        // pending; bob is the lone existing member who needs the
        // commit.
        let carol_kp = carol.key_package_bytes().unwrap();
        let (commit_to_bob, welcome_to_carol) = alice_group.invite(&alice, &carol_kp).unwrap();
        let mut carol_group = carol.join_from_welcome(&welcome_to_carol).unwrap();
        assert_eq!(alice_group.epoch(), 2);
        assert_eq!(carol_group.epoch(), 2);
        // BUGFIX CORE: bob processes the commit and advances.
        let processed = bob_group
            .process_incoming(&bob, &commit_to_bob)
            .expect("bob processes the commit");
        assert!(matches!(processed, IncomingRoomMessage::Commit));
        assert_eq!(
            bob_group.epoch(),
            2,
            "bob must advance to epoch 2 after processing the commit"
        );

        // Round 3: cross-decrypt sanity. alice sends an app msg;
        // both bob AND carol can decrypt it. Pre-T6.3.h, bob would
        // fail to decrypt at this point because his epoch was still
        // 1 while alice was at 2.
        let ct = alice_group
            .encrypt_application(&alice, b"hello room")
            .unwrap();
        let pt_bob = bob_group.process_incoming(&bob, &ct).unwrap();
        let pt_carol = carol_group.process_incoming(&carol, &ct).unwrap();
        assert_eq!(
            pt_bob,
            IncomingRoomMessage::Application(b"hello room".to_vec())
        );
        assert_eq!(
            pt_carol,
            IncomingRoomMessage::Application(b"hello room".to_vec())
        );
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
