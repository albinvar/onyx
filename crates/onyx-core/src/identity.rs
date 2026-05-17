//! Identity — long-term keys + repo methods on [`Vault`].
//!
//! See DESIGN.md §4.
//!
//! An [`Identity`] in memory owns:
//!
//!   * an Ed25519 signing key (signs outbound messages; its public part
//!     is the [`Fingerprint`] and, in v1, the Tor v3 onion address),
//!   * an X25519 long-term identity key (initial key agreement for the
//!     sealed-sender bootstrap envelope — DESIGN.md §5.5 Tier 1).
//!
//! On disk both secrets live inside a single AEAD-encrypted blob in the
//! `identities` table. The fingerprint is stored plaintext so the
//! daemon can look up identities by it without unlocking the vault.
//!
//! ## Serialised layout (inside the AEAD blob)
//!
//! ```text
//! 0       32                              64
//! ┌───────────────┬───────────────────────┐
//! │ signing seed  │ x25519 secret         │
//! │ 32 B          │ 32 B                  │
//! └───────────────┴───────────────────────┘
//! ```
//!
//! Renames or additions to this layout MUST bump the storage schema
//! version ([`crate::storage::SCHEMA_VERSION`]).

use rusqlite::params;
use zeroize::Zeroizing;

use crate::crypto::{Fingerprint, IdentitySecret, SigningKey};
use crate::error::{Error, Result};
use crate::storage::{Vault, map_db_err};

/// Unlocked, in-memory identity. The two secret keys zeroize on drop
/// via their respective wrappers.
pub struct Identity {
    signing: SigningKey,
    identity: IdentitySecret,
}

impl Identity {
    /// Generate a fresh identity from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(),
            identity: IdentitySecret::generate(),
        }
    }

    /// Reconstruct from raw seeds — used by [`Vault::get_identity`] and
    /// for import flows.
    #[must_use]
    pub fn from_seeds(signing_seed: &[u8; 32], identity_secret: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(signing_seed),
            identity: IdentitySecret::from_bytes(identity_secret),
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

    /// The user's permanent identifier. Equal to the Ed25519 signing
    /// public key bytes (and, in v1, equal to the Tor v3 onion address
    /// before its base32 encoding).
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        self.signing.verifying_key().fingerprint()
    }

    /// Serialise both secrets into the 64-byte plaintext that the vault
    /// will AEAD-seal. Returns a `Zeroizing` buffer so the caller can't
    /// accidentally leak the secret on the stack.
    fn to_secret_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut out = Zeroizing::new([0u8; 64]);
        out[..32].copy_from_slice(self.signing.to_bytes().as_slice());
        out[32..].copy_from_slice(self.identity.to_bytes().as_slice());
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
        if plaintext.len() != 64 {
            return Err(Error::InvalidEncoding(
                "identity blob: expected 64 bytes (signing seed || x25519 secret)",
            ));
        }
        let signing_seed: [u8; 32] = plaintext[..32]
            .try_into()
            .map_err(|_| Error::InvalidEncoding("identity blob: signing seed slice"))?;
        let identity_secret: [u8; 32] = plaintext[32..]
            .try_into()
            .map_err(|_| Error::InvalidEncoding("identity blob: identity secret slice"))?;

        Ok(Identity::from_seeds(&signing_seed, identity_secret))
    }

    /// Delete an identity. Per DESIGN.md §7.4 we overwrite the encrypted
    /// blob with random bytes first (best-effort defence against
    /// forensic recovery of the cipherext + tag), then DELETE, then
    /// VACUUM to compact freed pages out of the file.
    pub fn delete_identity(&mut self, id: i64) -> Result<()> {
        // 128 bytes is comfortably larger than our 64-byte plaintext
        // plus tag/nonce overhead — overwriting with the same length
        // would be a marginal improvement; we don't try.
        let mut scrub = vec![0u8; 128];
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
    fn from_seeds_is_deterministic() {
        let signing_seed = [7u8; 32];
        let identity_secret = [9u8; 32];
        let a = Identity::from_seeds(&signing_seed, identity_secret);
        let b = Identity::from_seeds(&signing_seed, identity_secret);
        assert_eq!(a.fingerprint(), b.fingerprint());
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
}
