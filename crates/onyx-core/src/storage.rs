//! Encrypted local storage (SQLite + app-level AEAD).
//!
//! See DESIGN.md §7. The vault holds a SQLite database where sensitive
//! columns are AEAD-encrypted at the row level using a key derived from
//! the user's passphrase via Argon2id. Non-sensitive columns (nicknames,
//! timestamps, fingerprints, schema version) stay plaintext so SQLite
//! can index them.
//!
//! ## Anatomy of an encrypted blob
//!
//! ```text
//! 0       12                                       N
//! ┌───────┬───────────────────────────────────────┐
//! │ nonce │  ChaCha20-Poly1305(plaintext, aad=∅)  │
//! │ 12 B  │  ciphertext + 16-byte tag             │
//! └───────┴───────────────────────────────────────┘
//! ```
//!
//! The nonce is fresh OS-random per call. With 96 bits of randomness the
//! birthday bound is ~2⁴⁸ blobs under one key — comfortably above the
//! lifetime of any user's vault. Repeating a nonce under one key would
//! catastrophically break confidentiality and authenticity, so the
//! random source is the OS CSPRNG via [`crate::crypto::fill_random`],
//! never a counter.
//!
//! ## Wrong-passphrase detection
//!
//! On `create` the vault stores an AEAD-encrypted **canary** plaintext
//! ([`CANARY_PLAINTEXT`]) in the metadata row. On `open` we re-derive
//! the candidate key from the supplied passphrase and try to decrypt the
//! canary. AEAD-tag failure → [`Error::VerificationFailed`], surfaced to
//! the caller without distinguishing "wrong passphrase" from "corrupted
//! canary" (both should be treated the same).

use std::path::Path;

use rusqlite::{Connection, params};
use zeroize::Zeroizing;

use crate::crypto::{AeadKey, Argon2Params, Nonce, argon2id_derive, random_array};
use crate::error::{Error, Result};

/// On-disk schema version. Bumped when migrations land.
pub const SCHEMA_VERSION: i32 = 1;

const SCHEMA_V1: &str = "
CREATE TABLE vault_meta (
  id              INTEGER PRIMARY KEY CHECK (id = 1),
  schema_version  INTEGER NOT NULL,
  kdf_salt        BLOB NOT NULL,
  kdf_memory_kib  INTEGER NOT NULL,
  kdf_iterations  INTEGER NOT NULL,
  kdf_parallelism INTEGER NOT NULL,
  canary          BLOB NOT NULL
);

CREATE TABLE identities (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  nickname        TEXT NOT NULL,
  fingerprint     BLOB NOT NULL UNIQUE,
  encrypted_blob  BLOB NOT NULL,
  created_at      INTEGER NOT NULL
);
";

/// Known plaintext used to detect a wrong passphrase. Encrypted under
/// the vault key at creation; failure to decrypt at open means the
/// passphrase doesn't match (or the file is corrupted — we don't
/// distinguish).
pub const CANARY_PLAINTEXT: &[u8] = b"onyx-vault-canary-v1";

const NONCE_PREFIX_LEN: usize = Nonce::SIZE;

/// Map any rusqlite error to our opaque `Internal` variant. Detail is
/// dropped on purpose — the caller does not need to act on the specific
/// SQLite error and we do not want to leak schema details into error
/// strings. Detail goes through `tracing` later.
pub(crate) fn map_db_err(_err: rusqlite::Error) -> Error {
    Error::Internal("storage: SQLite error")
}

/// AEAD-seal `plaintext` under `key`. Output is `nonce(12) ‖ ct‖tag`.
pub(crate) fn seal(key: &AeadKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = Nonce::random();
    let ct = key.encrypt(&nonce, b"", plaintext)?;
    let mut out = Vec::with_capacity(NONCE_PREFIX_LEN + ct.len());
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// AEAD-open a blob produced by [`seal`].
pub(crate) fn unseal(key: &AeadKey, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_PREFIX_LEN {
        return Err(Error::InvalidEncoding(
            "vault blob: shorter than nonce prefix",
        ));
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_PREFIX_LEN);
    // SAFETY of `try_into`: we just split at NONCE_PREFIX_LEN, so the
    // left half is exactly that many bytes. The try_into can't fail.
    let nonce_arr: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| Error::InvalidEncoding("vault blob: nonce slice"))?;
    let nonce = Nonce::from_bytes(nonce_arr);
    key.decrypt(&nonce, b"", ct)
}

/// The unlocked vault. Holds an open SQLite connection plus the derived
/// AEAD key. Dropping the vault zeroizes the key (via [`AeadKey`]'s
/// `ZeroizeOnDrop`) and closes the SQLite connection.
pub struct Vault {
    conn: Connection,
    aead: AeadKey,
}

impl Vault {
    /// Create a new vault at `path`. Fails if the file already exists —
    /// we do not silently overwrite a possibly-already-populated vault.
    pub fn create(path: &Path, passphrase: &[u8], params: &Argon2Params) -> Result<Self> {
        if path.exists() {
            return Err(Error::Internal("vault path already exists"));
        }
        let conn = Connection::open(path).map_err(map_db_err)?;
        Self::initialize(conn, passphrase, params)
    }

    /// Create a transient in-memory vault. Used for session-only mode
    /// (DESIGN.md §7.3) and for tests.
    pub fn open_memory(passphrase: &[u8], params: &Argon2Params) -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(map_db_err)?;
        Self::initialize(conn, passphrase, params)
    }

    /// Open an existing vault at `path`. Wrong passphrase surfaces as
    /// [`Error::VerificationFailed`] via the canary check.
    pub fn open(path: &Path, passphrase: &[u8]) -> Result<Self> {
        let conn = Connection::open(path).map_err(map_db_err)?;

        let (schema_version, salt_bytes, mem_kib, iters, parallel, canary): (
            i32,
            Vec<u8>,
            u32,
            u32,
            u32,
            Vec<u8>,
        ) = conn
            .query_row(
                "SELECT schema_version, kdf_salt, kdf_memory_kib, kdf_iterations, \
                 kdf_parallelism, canary FROM vault_meta WHERE id = 1",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .map_err(map_db_err)?;

        if schema_version != SCHEMA_VERSION {
            return Err(Error::Internal("vault: schema version mismatch"));
        }
        let salt: [u8; 16] = salt_bytes
            .try_into()
            .map_err(|_| Error::InvalidEncoding("vault: salt must be 16 bytes"))?;
        let params = Argon2Params {
            memory_kib: mem_kib,
            iterations: iters,
            parallelism: parallel,
        };
        params.validate()?;

        let mut vault_key = Zeroizing::new([0u8; 32]);
        argon2id_derive(passphrase, &salt, &params, vault_key.as_mut_slice())?;
        let aead = AeadKey::from_bytes(*vault_key);

        // Canary check. Wrong passphrase → unseal returns
        // VerificationFailed because the AEAD tag won't validate.
        let decrypted = unseal(&aead, &canary)?;
        if decrypted != CANARY_PLAINTEXT {
            // The canary decrypted (so tags matched) but the plaintext
            // doesn't match what we expect — vault corrupted or some
            // unrelated process wrote here.
            return Err(Error::VerificationFailed);
        }

        Ok(Self { conn, aead })
    }

    fn initialize(conn: Connection, passphrase: &[u8], params: &Argon2Params) -> Result<Self> {
        params.validate()?;
        conn.execute_batch(SCHEMA_V1).map_err(map_db_err)?;

        let salt: [u8; 16] = random_array();
        let mut vault_key = Zeroizing::new([0u8; 32]);
        argon2id_derive(passphrase, &salt, params, vault_key.as_mut_slice())?;
        let aead = AeadKey::from_bytes(*vault_key);

        let canary = seal(&aead, CANARY_PLAINTEXT)?;

        conn.execute(
            "INSERT INTO vault_meta \
             (id, schema_version, kdf_salt, kdf_memory_kib, kdf_iterations, \
              kdf_parallelism, canary) \
             VALUES (1, ?, ?, ?, ?, ?, ?)",
            params![
                SCHEMA_VERSION,
                salt.to_vec(),
                params.memory_kib,
                params.iterations,
                params.parallelism,
                canary,
            ],
        )
        .map_err(map_db_err)?;

        Ok(Self { conn, aead })
    }

    /// Encrypt arbitrary bytes for at-rest storage. Output format is
    /// `nonce(12) ‖ ciphertext+tag`. Each call uses a fresh random
    /// nonce, so the same plaintext produces different ciphertext.
    pub fn encrypt_blob(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        seal(&self.aead, plaintext)
    }

    /// Decrypt bytes previously produced by [`Self::encrypt_blob`].
    pub fn decrypt_blob(&self, blob: &[u8]) -> Result<Vec<u8>> {
        unseal(&self.aead, blob)
    }

    /// Read-only access to the underlying SQLite connection for
    /// implementing per-entity repos (identity, contacts, …). Repos
    /// MUST NOT bypass [`Self::encrypt_blob`]/[`Self::decrypt_blob`]
    /// when writing sensitive columns.
    pub(crate) fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Mutable access for repos that need transactions (e.g.
    /// secure-deletion `UPDATE`-then-`DELETE` pairs).
    pub(crate) fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").finish_non_exhaustive()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Argon2Params, random_array};
    use proptest::prelude::*;

    /// Argon2 at the floor is what the daemon actually accepts; running
    /// it twice per test is the slow part of this file. All tests use
    /// `open_memory` so we don't touch the disk.
    fn fresh_vault() -> Vault {
        Vault::open_memory(b"correct-horse-battery-staple", &Argon2Params::FLOOR).unwrap()
    }

    #[test]
    fn create_open_memory_succeeds() {
        let _v = fresh_vault();
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let v = fresh_vault();
        let blob = v.encrypt_blob(b"top secret").unwrap();
        let pt = v.decrypt_blob(&blob).unwrap();
        assert_eq!(pt, b"top secret");
    }

    #[test]
    fn encrypt_is_not_deterministic() {
        // Same plaintext, same key — different ciphertext. Confirms a
        // fresh random nonce per call.
        let v = fresh_vault();
        let a = v.encrypt_blob(b"same plaintext").unwrap();
        let b = v.encrypt_blob(b"same plaintext").unwrap();
        assert_ne!(
            a, b,
            "AEAD with random nonce must not produce equal ciphertexts"
        );
    }

    #[test]
    fn tampered_blob_rejected() {
        let v = fresh_vault();
        let mut blob = v.encrypt_blob(b"data").unwrap();
        let idx = blob.len() - 1; // tamper inside the AEAD tag
        blob[idx] ^= 0x01;
        assert!(matches!(
            v.decrypt_blob(&blob),
            Err(Error::VerificationFailed)
        ));
    }

    #[test]
    fn truncated_blob_rejected() {
        let v = fresh_vault();
        let blob = v.encrypt_blob(b"data").unwrap();
        // Strip the AEAD tag — anything shorter than nonce+ct fails.
        assert!(matches!(
            v.decrypt_blob(&blob[..5]),
            Err(Error::InvalidEncoding(_))
        ));
    }

    #[test]
    fn persists_across_reopen() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        // tempfile creates the file; Vault::create refuses an existing
        // path, so delete it first.
        tmp.close().unwrap();

        {
            let v = Vault::create(&path, b"pw", &Argon2Params::FLOOR).unwrap();
            let blob = v.encrypt_blob(b"persist me").unwrap();
            assert_eq!(v.decrypt_blob(&blob).unwrap(), b"persist me");
        }

        {
            // Reopen with the same passphrase — canary must verify.
            let _v = Vault::open(&path, b"pw").unwrap();
        }

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        tmp.close().unwrap();

        {
            let _v = Vault::create(&path, b"correct", &Argon2Params::FLOOR).unwrap();
        }

        assert!(matches!(
            Vault::open(&path, b"wrong"),
            Err(Error::VerificationFailed)
        ));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn create_refuses_existing_path() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        // Don't delete — the existing file should make `create` refuse.
        assert!(matches!(
            Vault::create(&path, b"pw", &Argon2Params::FLOOR),
            Err(Error::Internal(_))
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 16,
            .. ProptestConfig::default()
        })]

        /// `seal` + `unseal` round-trip for arbitrary plaintexts. We
        /// exercise the helper directly to avoid running Argon2 on every
        /// case (proptest defaults to 256 cases — too expensive at floor).
        #[test]
        fn prop_seal_unseal_round_trip(plaintext in prop::collection::vec(any::<u8>(), 0..1024)) {
            let key = AeadKey::from_bytes(random_array());
            let blob = seal(&key, &plaintext).unwrap();
            let got = unseal(&key, &blob).unwrap();
            prop_assert_eq!(got, plaintext);
        }

        /// `unseal` of arbitrary bytes never panics; rejection is fine,
        /// crashing is not.
        #[test]
        fn prop_unseal_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
            let key = AeadKey::from_bytes([0u8; 32]);
            let _ = unseal(&key, &bytes);
        }
    }
}
