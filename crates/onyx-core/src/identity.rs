//! Identity — long-term keys + repo methods on [`Vault`].
//!
//! See DESIGN.md §4.
//!
//! An [`Identity`] in memory owns:
//!
//!   * an Ed25519 signing key (signs outbound messages; its public part
//!     is the [`Fingerprint`] and, in v1, the Tor v3 onion address),
//!   * an X25519 long-term identity key (used by the Noise XK
//!     transport handshake for peer authentication),
//!   * a hybrid (X25519 ‖ ML-KEM-768) KEM keypair used as the
//!     **recipient half** of the sealed-sender bootstrap envelope
//!     (DESIGN.md §5.5 Tier 1; `routing::seal_bootstrap` /
//!     `open_bootstrap`).
//!
//! The Noise-handshake X25519 key and the hybrid KEM's classical
//! X25519 key are intentionally **separate keys** — different protocol
//! roles, no cross-protocol reuse. The extra 32 bytes are a worthwhile
//! conservative choice (P6 of `SECURITY.md`: no optional weakening).
//!
//! On disk all three secrets live inside a single AEAD-encrypted blob
//! in the `identities` table. The fingerprint is stored plaintext so
//! the daemon can look up identities by it without unlocking the vault.
//!
//! ## Serialised layout (inside the AEAD blob)
//!
//! ```text
//! 0       32                64                   64 + HYBRID_SECRET_LEN
//! ┌───────────────┬───────────────────────┬─────────────────────────┐
//! │ signing seed  │ x25519 secret (Noise) │ HybridKemSecret bytes   │
//! │ 32 B          │ 32 B                  │ 2432 B                  │
//! └───────────────┴───────────────────────┴─────────────────────────┘
//! Total: 2496 bytes
//! ```
//!
//! Renames or additions to this layout MUST bump the storage schema
//! version ([`crate::storage::SCHEMA_VERSION`]). v3 → v4 added the
//! hybrid KEM tail in T5.2.a.

use rusqlite::params;
use zeroize::Zeroizing;

use crate::crypto::{
    Fingerprint, HYBRID_SECRET_LEN, HybridKemPublic, HybridKemSecret, IdentitySecret, SigningKey,
};
use crate::error::{Error, Result};
use crate::storage::{Vault, map_db_err};

/// Full serialised length of an unlocked identity: signing seed +
/// Noise x25519 secret + hybrid KEM secret.
const IDENTITY_SECRET_BLOB_LEN: usize = 32 + 32 + HYBRID_SECRET_LEN;

/// Unlocked, in-memory identity. All three secret keys zeroize on
/// drop via their respective wrappers.
// `identity` field name is the right English word for what it holds
// (the X25519 identity secret) — renaming to satisfy
// `clippy::struct_field_names` would make the code less readable for
// no real gain. Keep the name, suppress the lint.
#[allow(clippy::struct_field_names)]
pub struct Identity {
    signing: SigningKey,
    identity: IdentitySecret,
    kem: HybridKemSecret,
}

impl Identity {
    /// Generate a fresh identity from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(),
            identity: IdentitySecret::generate(),
            kem: HybridKemSecret::generate(),
        }
    }

    /// Reconstruct from raw seed bytes + a serialised hybrid KEM
    /// secret. Used by [`Vault::get_identity`] and by import flows.
    /// Validation: `kem_bytes` must be exactly [`HYBRID_SECRET_LEN`].
    pub fn from_parts(
        signing_seed: &[u8; 32],
        identity_secret: [u8; 32],
        kem_bytes: &[u8],
    ) -> Result<Self> {
        Ok(Self {
            signing: SigningKey::from_bytes(signing_seed),
            identity: IdentitySecret::from_bytes(identity_secret),
            kem: HybridKemSecret::from_bytes(kem_bytes)?,
        })
    }

    /// Convenience constructor whose **fingerprint is deterministic**
    /// in the seeds but whose hybrid KEM keypair is generated freshly
    /// each call. Useful for tests that want a reproducible
    /// fingerprint without caring about the KEM half.
    ///
    /// For full reproducibility (round-tripping through bytes), use
    /// [`Self::from_parts`] and supply the serialised KEM bytes.
    #[must_use]
    pub fn from_seeds(signing_seed: &[u8; 32], identity_secret: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(signing_seed),
            identity: IdentitySecret::from_bytes(identity_secret),
            kem: HybridKemSecret::generate(),
        }
    }

    #[must_use]
    pub fn signing(&self) -> &SigningKey {
        &self.signing
    }

    #[must_use]
    pub fn identity_key(&self) -> &IdentitySecret {
        &self.identity
    }

    /// The hybrid KEM secret. Used by `routing::open_bootstrap` to
    /// decapsulate sealed-sender envelopes addressed to this identity.
    #[must_use]
    pub fn kem_secret(&self) -> &HybridKemSecret {
        &self.kem
    }

    /// The hybrid KEM public, freshly derived. Hand this out so senders
    /// can address sealed-sender envelopes to this identity. Safe to
    /// publish — the public bytes contain no key material.
    #[must_use]
    pub fn kem_public(&self) -> HybridKemPublic {
        self.kem.public()
    }

    /// The user's permanent identifier. Equal to the Ed25519 signing
    /// public key bytes (and, in v1, equal to the Tor v3 onion address
    /// before its base32 encoding).
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        self.signing.verifying_key().fingerprint()
    }

    /// Serialise all three secrets into the
    /// [`IDENTITY_SECRET_BLOB_LEN`]-byte plaintext that the vault will
    /// AEAD-seal. Returns a [`Zeroizing`] buffer so the caller can't
    /// accidentally leak the secret on the stack.
    fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(IDENTITY_SECRET_BLOB_LEN));
        out.extend_from_slice(self.signing.to_bytes().as_slice());
        out.extend_from_slice(self.identity.to_bytes().as_slice());
        out.extend_from_slice(self.kem.to_bytes().as_slice());
        debug_assert_eq!(out.len(), IDENTITY_SECRET_BLOB_LEN);
        out
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

/// Plaintext metadata for an identity row. Excludes the secret keys —
/// use [`Vault::get_identity`] to materialise the full [`Identity`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredIdentity {
    /// Primary key in the `identities` table.
    pub id: i64,
    /// User-chosen nickname. Not unique — only the [`Fingerprint`] is.
    pub nickname: String,
    pub fingerprint: Fingerprint,
    /// Creation time in milliseconds since UNIX epoch.
    pub created_at: u64,
}

fn now_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[allow(clippy::cast_possible_wrap)] // u64 millis fits i64 until ≈ year 292,277,026
fn u64_to_sql_i64(v: u64) -> i64 {
    v as i64
}

#[allow(clippy::cast_sign_loss)] // SQLite returns i64; we stored a non-negative u64
fn sql_i64_to_u64(v: i64) -> u64 {
    v as u64
}

impl Vault {
    /// Generate a new identity, store the encrypted secret + plaintext
    /// fingerprint, and return both the DB id and the in-memory
    /// [`Identity`].
    pub fn create_identity(&mut self, nickname: &str) -> Result<(i64, Identity)> {
        let identity = Identity::generate();
        let fingerprint = identity.fingerprint();
        let secret_bytes = identity.to_secret_bytes();
        let encrypted = self.encrypt_blob(secret_bytes.as_slice())?;

        let id: i64 = self
            .connection()
            .query_row(
                "INSERT INTO identities (nickname, fingerprint, encrypted_blob, created_at) \
                 VALUES (?, ?, ?, ?) RETURNING id",
                params![
                    nickname,
                    fingerprint.as_bytes().to_vec(),
                    encrypted,
                    u64_to_sql_i64(now_unix_millis()),
                ],
                |r| r.get(0),
            )
            .map_err(map_db_err)?;

        Ok((id, identity))
    }

    /// List all stored identities (metadata only — does not decrypt).
    pub fn list_identities(&self) -> Result<Vec<StoredIdentity>> {
        let mut stmt = self
            .connection()
            .prepare("SELECT id, nickname, fingerprint, created_at FROM identities ORDER BY id")
            .map_err(map_db_err)?;

        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .map_err(map_db_err)?;

        let mut out = Vec::new();
        for row in rows {
            let (id, nickname, fpr_vec, created_at) = row.map_err(map_db_err)?;
            let fpr_arr: [u8; 32] = fpr_vec
                .try_into()
                .map_err(|_| Error::InvalidEncoding("identity row: fingerprint not 32 bytes"))?;
            out.push(StoredIdentity {
                id,
                nickname,
                fingerprint: Fingerprint::from_bytes(fpr_arr),
                created_at: sql_i64_to_u64(created_at),
            });
        }
        Ok(out)
    }

    /// Materialise the full identity (decrypts the secret blob). Errors
    /// if no row exists with that id.
    pub fn get_identity(&self, id: i64) -> Result<Identity> {
        let encrypted: Vec<u8> = self
            .connection()
            .query_row(
                "SELECT encrypted_blob FROM identities WHERE id = ?",
                params![id],
                |r| r.get(0),
            )
            .map_err(map_db_err)?;

        let plaintext = self.decrypt_blob(&encrypted)?;
        if plaintext.len() != IDENTITY_SECRET_BLOB_LEN {
            return Err(Error::InvalidEncoding(
                "identity blob: wrong length (expected signing ‖ x25519 ‖ hybrid-kem)",
            ));
        }
        let signing_seed: [u8; 32] = plaintext[..32]
            .try_into()
            .map_err(|_| Error::InvalidEncoding("identity blob: signing seed slice"))?;
        let identity_secret: [u8; 32] = plaintext[32..64]
            .try_into()
            .map_err(|_| Error::InvalidEncoding("identity blob: identity secret slice"))?;
        let kem_bytes = &plaintext[64..];

        Identity::from_parts(&signing_seed, identity_secret, kem_bytes)
    }

    /// Delete an identity. Per DESIGN.md §7.4 we overwrite the encrypted
    /// blob with random bytes first (best-effort defence against
    /// forensic recovery of the cipherext + tag), then DELETE, then
    /// VACUUM to compact freed pages out of the file.
    pub fn delete_identity(&mut self, id: i64) -> Result<()> {
        // Size the scrub buffer to comfortably exceed the encrypted
        // blob (IDENTITY_SECRET_BLOB_LEN plaintext + AEAD overhead).
        // Best-effort forensic-recovery defence; SQLite may still
        // leave fragments in WAL/rollback journals until VACUUM.
        let mut scrub = vec![0u8; IDENTITY_SECRET_BLOB_LEN + 256];
        crate::crypto::fill_random(&mut scrub);

        let tx = self.connection_mut().transaction().map_err(map_db_err)?;
        tx.execute(
            "UPDATE identities SET encrypted_blob = ? WHERE id = ?",
            params![scrub, id],
        )
        .map_err(map_db_err)?;
        tx.execute("DELETE FROM identities WHERE id = ?", params![id])
            .map_err(map_db_err)?;
        tx.commit().map_err(map_db_err)?;

        // VACUUM rebuilds the DB file, dropping freed pages. Cannot
        // run inside a transaction.
        self.connection()
            .execute("VACUUM", [])
            .map_err(map_db_err)?;
        Ok(())
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Argon2Params;

    fn fresh_vault() -> Vault {
        Vault::open_memory(b"correct-horse", &Argon2Params::FLOOR).unwrap()
    }

    #[test]
    fn generate_produces_distinct_identities() {
        let a = Identity::generate();
        let b = Identity::generate();
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn from_parts_is_deterministic_for_classical_fields() {
        // The signing + identity seeds determine the fingerprint
        // deterministically. The hybrid KEM secret is non-deterministic
        // (no seeded constructor in ml-kem), so two `Identity::generate`d
        // KEM halves are used; the fingerprint must still match because
        // it derives from the signing key only.
        let signing_seed = [7u8; 32];
        let identity_secret = [9u8; 32];
        let kem_a = HybridKemSecret::generate();
        let kem_b = HybridKemSecret::generate();
        let a = Identity::from_parts(&signing_seed, identity_secret, &kem_a.to_bytes()).unwrap();
        let b = Identity::from_parts(&signing_seed, identity_secret, &kem_b.to_bytes()).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn from_parts_rejects_wrong_kem_length() {
        let signing_seed = [7u8; 32];
        let identity_secret = [9u8; 32];
        let bad = vec![0u8; 10];
        assert!(Identity::from_parts(&signing_seed, identity_secret, &bad).is_err());
    }

    #[test]
    fn create_then_list() {
        let mut v = fresh_vault();
        let (id_a, alice) = v.create_identity("alice").unwrap();
        let (id_b, bob) = v.create_identity("bob").unwrap();
        assert_ne!(id_a, id_b);
        assert_ne!(alice.fingerprint(), bob.fingerprint());

        let list = v.list_identities().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].nickname, "alice");
        assert_eq!(list[0].fingerprint, alice.fingerprint());
        assert_eq!(list[1].nickname, "bob");
        assert_eq!(list[1].fingerprint, bob.fingerprint());
    }

    #[test]
    fn get_round_trips_keys() {
        let mut v = fresh_vault();
        let (id, alice) = v.create_identity("alice").unwrap();

        let restored = v.get_identity(id).unwrap();
        assert_eq!(restored.fingerprint(), alice.fingerprint());

        // The restored identity can sign and produce signatures that the
        // original's verifying key accepts.
        let msg = b"the keys really are equivalent";
        let sig = restored.signing().sign(msg);
        alice.signing().verifying_key().verify(msg, &sig).unwrap();
    }

    #[test]
    fn get_missing_id_errors() {
        let v = fresh_vault();
        assert!(v.get_identity(9999).is_err());
    }

    #[test]
    fn delete_removes_row() {
        let mut v = fresh_vault();
        let (id, _alice) = v.create_identity("alice").unwrap();
        assert_eq!(v.list_identities().unwrap().len(), 1);
        v.delete_identity(id).unwrap();
        assert_eq!(v.list_identities().unwrap().len(), 0);
        assert!(v.get_identity(id).is_err());
    }

    #[test]
    fn duplicate_fingerprint_rejected() {
        // Two `create_identity` calls would each generate a fresh key,
        // so they will never collide in practice. Force the case by
        // serializing the same identity twice via the underlying SQL.
        let mut v = fresh_vault();
        let (_id, alice) = v.create_identity("alice").unwrap();
        let secret = alice.to_secret_bytes();
        let encrypted = v.encrypt_blob(secret.as_slice()).unwrap();
        let dup_result = v.connection().execute(
            "INSERT INTO identities (nickname, fingerprint, encrypted_blob, created_at) \
             VALUES (?, ?, ?, ?)",
            params![
                "alice-clone",
                alice.fingerprint().as_bytes().to_vec(),
                encrypted,
                0_i64,
            ],
        );
        assert!(
            dup_result.is_err(),
            "UNIQUE constraint on fingerprint must reject"
        );
    }

    #[test]
    fn persists_across_reopen() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        tmp.close().unwrap();

        let stored_fpr;
        let stored_id;
        {
            let mut v = Vault::create(&path, b"pw", &Argon2Params::FLOOR).unwrap();
            let (id, alice) = v.create_identity("alice").unwrap();
            stored_id = id;
            stored_fpr = alice.fingerprint();
        }

        {
            let v = Vault::open(&path, b"pw").unwrap();
            let restored = v.get_identity(stored_id).unwrap();
            assert_eq!(restored.fingerprint(), stored_fpr);
        }

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn kem_keypair_round_trips_across_reopen() {
        // The security-relevant invariant for T5.2.a: a sealed-sender
        // envelope encapsulated to alice's KEM public BEFORE the daemon
        // restarts must still decapsulate to the same shared secret
        // AFTER the daemon restarts (i.e. the persisted KEM secret
        // really is the same key, not a freshly-generated one).
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        tmp.close().unwrap();

        let alice_kem_pub;
        let alice_id;
        let (ct, ss_send);
        {
            let mut v = Vault::create(&path, b"pw", &Argon2Params::FLOOR).unwrap();
            let (id, alice) = v.create_identity("alice").unwrap();
            alice_id = id;
            alice_kem_pub = alice.kem_public();
            // Sender encapsulates to alice's public before reopen.
            (ct, ss_send) = alice_kem_pub.encapsulate().unwrap();
        }

        {
            let v = Vault::open(&path, b"pw").unwrap();
            let restored = v.get_identity(alice_id).unwrap();
            let ss_recv = restored.kem_secret().decapsulate(&ct).unwrap();
            assert_eq!(
                ss_send.as_bytes(),
                ss_recv.as_bytes(),
                "KEM secret must survive vault reopen — \
                 otherwise sealed envelopes encrypted before restart \
                 cannot be opened after restart"
            );
        }

        std::fs::remove_file(&path).ok();
    }
}
