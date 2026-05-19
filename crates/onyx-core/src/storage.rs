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

use rusqlite::{Connection, OptionalExtension, params};
use zeroize::Zeroizing;

use crate::crypto::{AeadKey, Argon2Params, Nonce, argon2id_derive, random_array};
use crate::error::{Error, Result};

/// On-disk schema version. Bumped when migrations land.
///
/// **v1 → v2**: added `mls_state` table for per-identity MLS provider
/// snapshots.
///
/// **v2 → v3**: added `mls_peer_groups` table — per-(identity, peer)
/// mapping to a shared MLS `GroupId`. Lets the daemon resume an
/// existing group instead of bootstrapping a fresh one on every
/// reconnect.
///
/// v4 (T5.2.a): the AEAD plaintext inside `identities.encrypted_blob`
/// grew from 64 bytes (signing seed ‖ x25519 secret) to
/// 64 + HYBRID_SECRET_LEN = 2496 bytes — the hybrid KEM secret
/// (X25519 + ML-KEM-768) was appended. No SQL change; the blob
/// column is opaque to SQLite. Old v3 vaults fail the schema-version
/// check at open and must be recreated.
///
/// No migration runner yet; old vaults won't open. v0 has no real
/// users so the migration story is "delete the vault and recreate."
pub const SCHEMA_VERSION: i32 = 4;

const SCHEMA_V3: &str = "
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

-- One row per identity that has any MLS state. Snapshot is the
-- AEAD-encrypted serialised form of openmls's MemoryStorage hashmap
-- (see crate::mls). Pinned by identity_id with ON DELETE CASCADE so
-- deleting an identity also clears its MLS state.
CREATE TABLE mls_state (
  identity_id     INTEGER PRIMARY KEY REFERENCES identities(id) ON DELETE CASCADE,
  encrypted_blob  BLOB NOT NULL,
  updated_at      INTEGER NOT NULL
);

-- One row per (our identity, peer X25519 static pubkey). Records the
-- MLS GroupId we share with that peer so the next reconnect can
-- resume the group instead of bootstrapping a fresh one. peer_x25519
-- is the bytes the Noise XK handshake authenticates; group_id is the
-- bytes from MlsGroupState::group_id_bytes().
CREATE TABLE mls_peer_groups (
  identity_id     INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  peer_x25519     BLOB NOT NULL,
  group_id        BLOB NOT NULL,
  established_at  INTEGER NOT NULL,
  PRIMARY KEY (identity_id, peer_x25519)
);
";

/// Additive extension applied via `CREATE TABLE IF NOT EXISTS` on
/// every `open`/`initialize` rather than being part of the
/// version-pinned `SCHEMA_V3`. Stores the recipient-side hub-envelope
/// replay-defence snapshot (T7.3-sec.2-persist).
///
/// We deliberately do **not** bump [`SCHEMA_VERSION`] for this — it
/// is a pure additive change to vaults that already passed the schema
/// check, no rows in any other table are touched. Existing v4 vaults
/// pick up the table on next open with no migration runner required.
/// (`THREAT_MODEL` §8.2 #13 already tracks the absence of a real
/// migration runner; this additive pattern is what we do when a bump
/// would not be worth the upgrade-friction cost.)
const SCHEMA_REPLAY_STATE_ADD: &str = "
CREATE TABLE IF NOT EXISTS replay_state (
  identity_id     INTEGER PRIMARY KEY REFERENCES identities(id) ON DELETE CASCADE,
  encrypted_blob  BLOB NOT NULL,
  updated_at      INTEGER NOT NULL
);
";

/// Additive extension for T6.3.b — multi-party rooms. Same pattern
/// as [`SCHEMA_REPLAY_STATE_ADD`]: applied via
/// `CREATE TABLE IF NOT EXISTS` on every `open`/`initialize`,
/// **no** schema-version bump. Existing vaults pick up the table on
/// next open with no migration runner required.
///
/// One row per (our identity, MLS group_id) pair. `name` is local-
/// only — each member can call the same MLS group whatever they
/// like (FEDERATION-style member metadata is not propagated over
/// the wire). `members_b32` is a comma-separated list of member
/// fingerprints in base32; a cache of what we'd otherwise have to
/// walk the MLS tree to recover, refreshed on every commit.
const SCHEMA_ROOMS_ADD: &str = "
CREATE TABLE IF NOT EXISTS rooms (
  identity_id     INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  group_id        BLOB NOT NULL,
  name            TEXT NOT NULL,
  members_b32     TEXT NOT NULL,
  created_at_ms   INTEGER NOT NULL,
  PRIMARY KEY (identity_id, group_id)
);
";

/// Additive extension for T6.3.e — per-room cache of member hybrid
/// KEM public keys, used by [`Vault::lookup_room_member_kem`] for
/// the hub-fallback path. Same `CREATE TABLE IF NOT EXISTS` pattern
/// as the other additive tables — no schema-version bump.
///
/// One row per (our identity, MLS group_id, peer fingerprint). The
/// inviter persists each invitee's KEM pub at invite time (we
/// already accept it on the wire via `InviteToRoom`'s
/// `peer_kem_pub_b32`). Recipients of a Welcome don't yet receive
/// other members' KEM pubs — they hub-fallback only to members
/// they've directly invited; KEM-pub exchange via the hub
/// directory (or in-Welcome bundling) is a separate follow-up
/// (CHANNELS.md §6 / §8). Plaintext columns (the bytes are public
/// keys; their privacy property is "anyone who has them can send
/// you sealed envelopes," not confidentiality of the bytes
/// themselves).
const SCHEMA_ROOM_MEMBER_KEMS_ADD: &str = "
CREATE TABLE IF NOT EXISTS room_member_kems (
  identity_id     INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  group_id        BLOB NOT NULL,
  fingerprint     TEXT NOT NULL,
  kem_pub         BLOB NOT NULL,
  PRIMARY KEY (identity_id, group_id, fingerprint)
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

        // Apply additive table extensions. Idempotent — safe on every
        // open. Does NOT bump the schema-version pin (see
        // SCHEMA_REPLAY_STATE_ADD rustdoc).
        conn.execute_batch(SCHEMA_REPLAY_STATE_ADD)
            .map_err(map_db_err)?;
        conn.execute_batch(SCHEMA_ROOMS_ADD).map_err(map_db_err)?;
        conn.execute_batch(SCHEMA_ROOM_MEMBER_KEMS_ADD)
            .map_err(map_db_err)?;

        Ok(Self { conn, aead })
    }

    fn initialize(conn: Connection, passphrase: &[u8], params: &Argon2Params) -> Result<Self> {
        params.validate()?;
        conn.execute_batch(SCHEMA_V3).map_err(map_db_err)?;
        conn.execute_batch(SCHEMA_REPLAY_STATE_ADD)
            .map_err(map_db_err)?;
        conn.execute_batch(SCHEMA_ROOMS_ADD).map_err(map_db_err)?;
        conn.execute_batch(SCHEMA_ROOM_MEMBER_KEMS_ADD)
            .map_err(map_db_err)?;

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

    /// Persist (or overwrite) the MLS state blob for `identity_id`.
    /// The plaintext bytes are sealed under the vault key before being
    /// written; callers do NOT need to encrypt themselves. Typically
    /// the plaintext is whatever [`crate::mls::MlsParty::snapshot_state`]
    /// produced.
    pub fn save_mls_state(&self, identity_id: i64, plaintext: &[u8]) -> Result<()> {
        let encrypted = self.encrypt_blob(plaintext)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_millis()).ok())
            .unwrap_or(0);
        self.conn
            .execute(
                "INSERT INTO mls_state (identity_id, encrypted_blob, updated_at) \
                 VALUES (?, ?, ?) \
                 ON CONFLICT(identity_id) DO UPDATE SET \
                   encrypted_blob = excluded.encrypted_blob, \
                   updated_at = excluded.updated_at",
                params![identity_id, encrypted, now],
            )
            .map_err(map_db_err)?;
        Ok(())
    }

    /// Record that we share MLS `group_id` with the peer identified by
    /// `peer_x25519` (their long-term X25519 identity public key —
    /// what Noise XK authenticates). UPSERT: subsequent calls for the
    /// same `(identity_id, peer_x25519)` overwrite the group id, so
    /// re-bootstrapping with the same peer rotates to the new group
    /// cleanly.
    pub fn record_peer_group(
        &self,
        identity_id: i64,
        peer_x25519: &[u8; 32],
        group_id: &[u8],
    ) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_millis()).ok())
            .unwrap_or(0);
        self.conn
            .execute(
                "INSERT INTO mls_peer_groups (identity_id, peer_x25519, group_id, established_at) \
                 VALUES (?, ?, ?, ?) \
                 ON CONFLICT(identity_id, peer_x25519) DO UPDATE SET \
                   group_id = excluded.group_id, \
                   established_at = excluded.established_at",
                params![identity_id, peer_x25519.as_slice(), group_id, now],
            )
            .map_err(map_db_err)?;
        Ok(())
    }

    /// Delete a previously-recorded peer→group mapping. Used by the
    /// initiator when a stored `group_id` turns out to be stale (our
    /// local MLS state for that group no longer exists), so the next
    /// connection re-bootstraps instead of repeatedly trying to
    /// resume a group we can't load.
    ///
    /// Returns `Ok(())` whether or not a row was present — the call
    /// is idempotent.
    pub fn forget_peer_group(&self, identity_id: i64, peer_x25519: &[u8; 32]) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM mls_peer_groups \
                 WHERE identity_id = ? AND peer_x25519 = ?",
                params![identity_id, peer_x25519.as_slice()],
            )
            .map_err(map_db_err)?;
        Ok(())
    }

    /// Look up the MLS `group_id` we previously recorded for this
    /// peer. Returns `None` if no prior group exists — the caller
    /// should then go through the bootstrap path.
    pub fn lookup_peer_group(
        &self,
        identity_id: i64,
        peer_x25519: &[u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT group_id FROM mls_peer_groups \
                 WHERE identity_id = ? AND peer_x25519 = ?",
                params![identity_id, peer_x25519.as_slice()],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(map_db_err)
    }

    /// Load and decrypt the MLS state for `identity_id`, returning
    /// `None` if no row exists. The returned `Vec` is plaintext bytes
    /// suitable for [`crate::mls::MlsParty::from_identity_and_state`].
    pub fn load_mls_state(&self, identity_id: i64) -> Result<Option<Vec<u8>>> {
        let encrypted: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT encrypted_blob FROM mls_state WHERE identity_id = ?",
                params![identity_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_db_err)?;
        match encrypted {
            Some(blob) => Ok(Some(self.decrypt_blob(&blob)?)),
            None => Ok(None),
        }
    }

    /// Persist (or overwrite) the recipient-side hub-envelope replay
    /// seen-set snapshot for `identity_id` (T7.3-sec.2-persist). The
    /// plaintext shape is whatever
    /// [`crate::routing`]-adjacent client code produced via its
    /// `EnvelopeReplayGuard::snapshot` — opaque to the vault.
    pub fn save_replay_state(&self, identity_id: i64, plaintext: &[u8]) -> Result<()> {
        let encrypted = self.encrypt_blob(plaintext)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_millis()).ok())
            .unwrap_or(0);
        self.conn
            .execute(
                "INSERT INTO replay_state (identity_id, encrypted_blob, updated_at) \
                 VALUES (?, ?, ?) \
                 ON CONFLICT(identity_id) DO UPDATE SET \
                   encrypted_blob = excluded.encrypted_blob, \
                   updated_at = excluded.updated_at",
                params![identity_id, encrypted, now],
            )
            .map_err(map_db_err)?;
        Ok(())
    }

    /// Load and decrypt the replay-state snapshot for `identity_id`.
    /// Returns `None` if no row exists (first run, or vault never
    /// snapshotted the guard). Caller decides what to do with a
    /// decode failure of the plaintext — typically: start with an
    /// empty guard rather than refuse to launch.
    pub fn load_replay_state(&self, identity_id: i64) -> Result<Option<Vec<u8>>> {
        let encrypted: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT encrypted_blob FROM replay_state WHERE identity_id = ?",
                params![identity_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_db_err)?;
        match encrypted {
            Some(blob) => Ok(Some(self.decrypt_blob(&blob)?)),
            None => Ok(None),
        }
    }

    // ── T6.3.b: Rooms (multi-party MLS groups) ─────────────────────

    /// UPSERT a room for `identity_id`. Idempotent on
    /// `(identity_id, group_id)`. Updates `name`, `members_b32`,
    /// `created_at_ms` to the supplied values on conflict.
    ///
    /// `members_b32` is a comma-separated list of fingerprints in
    /// base32 (the same form `Fingerprint::to_base32()` produces).
    /// Empty string is permitted (a freshly-created room before
    /// invite has only the creator, but [`Self::save_room`] takes
    /// the caller's word for what's in members_b32 — typically the
    /// daemon includes its own fingerprint).
    pub fn save_room(
        &self,
        identity_id: i64,
        group_id: &[u8],
        name: &str,
        members_b32: &str,
        created_at_ms: i64,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO rooms (identity_id, group_id, name, members_b32, created_at_ms) \
                 VALUES (?, ?, ?, ?, ?) \
                 ON CONFLICT(identity_id, group_id) DO UPDATE SET \
                   name = excluded.name, \
                   members_b32 = excluded.members_b32, \
                   created_at_ms = excluded.created_at_ms",
                params![identity_id, group_id, name, members_b32, created_at_ms],
            )
            .map_err(map_db_err)?;
        Ok(())
    }

    /// List every room for `identity_id`, ordered by `created_at_ms`
    /// ascending (older first). Returns the rows verbatim — the
    /// daemon decides how to project them into API responses.
    pub fn list_rooms(&self, identity_id: i64) -> Result<Vec<RoomRow>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT group_id, name, members_b32, created_at_ms \
                 FROM rooms WHERE identity_id = ? \
                 ORDER BY created_at_ms ASC",
            )
            .map_err(map_db_err)?;
        let rows = stmt
            .query_map(params![identity_id], |r| {
                Ok(RoomRow {
                    group_id: r.get(0)?,
                    name: r.get(1)?,
                    members_b32: r.get(2)?,
                    created_at_ms: r.get(3)?,
                })
            })
            .map_err(map_db_err)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(map_db_err)?);
        }
        Ok(out)
    }

    /// Delete a room by `(identity_id, group_id)`. Idempotent — no
    /// error if the row didn't exist. Note: this does NOT drop the
    /// underlying MLS state (that's `mls_state`); a future `leave-
    /// room` flow may want to forget both.
    pub fn delete_room(&self, identity_id: i64, group_id: &[u8]) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM rooms WHERE identity_id = ? AND group_id = ?",
                params![identity_id, group_id],
            )
            .map_err(map_db_err)?;
        Ok(())
    }

    /// Stash a room member's hybrid KEM public key keyed by
    /// `(identity_id, group_id, fingerprint)` (T6.3.e). The inviter
    /// calls this after a successful invite so the hub-fallback
    /// `handle_send_room` path can seal sealed-sender envelopes to
    /// the member even when they're offline. Upsert by primary key.
    pub fn save_room_member_kem(
        &self,
        identity_id: i64,
        group_id: &[u8],
        fingerprint: &str,
        kem_pub: &[u8],
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO room_member_kems \
                 (identity_id, group_id, fingerprint, kem_pub) \
                 VALUES (?, ?, ?, ?)",
                params![identity_id, group_id, fingerprint, kem_pub],
            )
            .map_err(map_db_err)?;
        Ok(())
    }

    /// Look up a room member's stashed KEM pub. Returns `Ok(None)` if
    /// we don't have one cached — caller should skip hub-fallback for
    /// that member (a Warning-level log is appropriate; the missing
    /// cache entry is structural for non-inviter members today).
    pub fn lookup_room_member_kem(
        &self,
        identity_id: i64,
        group_id: &[u8],
        fingerprint: &str,
    ) -> Result<Option<Vec<u8>>> {
        let row = self
            .conn
            .query_row(
                "SELECT kem_pub FROM room_member_kems \
                 WHERE identity_id = ? AND group_id = ? AND fingerprint = ?",
                params![identity_id, group_id, fingerprint],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(map_db_err)?;
        Ok(row)
    }
}

/// One row of [`Vault::list_rooms`]. Plain data; the daemon
/// translates this into the API-level `RoomInfo` shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomRow {
    pub group_id: Vec<u8>,
    pub name: String,
    /// Comma-separated base32 fingerprints; see [`Vault::save_room`].
    pub members_b32: String,
    pub created_at_ms: i64,
}

impl Vault {
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
    fn mls_state_save_load_round_trip() {
        // The mls_state table is keyed by identity_id with a FK to
        // identities — use an in-memory vault and create an identity
        // first so the FK is satisfied. (Schema FK enforcement isn't
        // on by default in SQLite, but the test exercises the round-
        // trip either way.)
        let mut v = fresh_vault();
        let (id, _identity) = v.create_identity("alice").unwrap();

        // No state yet.
        assert!(v.load_mls_state(id).unwrap().is_none());

        // Save and read back.
        let blob = b"opaque MLS snapshot bytes \xff\x00\x42";
        v.save_mls_state(id, blob).unwrap();
        let loaded = v.load_mls_state(id).unwrap().expect("must be Some");
        assert_eq!(loaded, blob);

        // Overwrite via UPSERT.
        let blob2 = b"replacement bytes";
        v.save_mls_state(id, blob2).unwrap();
        assert_eq!(v.load_mls_state(id).unwrap().unwrap(), blob2);
    }

    #[test]
    fn replay_state_save_load_round_trip() {
        // Mirror mls_state_save_load_round_trip for the additive
        // replay_state table. UPSERT semantics on (identity_id) PK,
        // AEAD-sealed at rest, in-memory vault sufficient.
        let mut v = fresh_vault();
        let (id, _identity) = v.create_identity("alice").unwrap();

        assert!(v.load_replay_state(id).unwrap().is_none());

        let snap = b"opaque replay-guard snapshot \x00\xde\xad\xbe\xef";
        v.save_replay_state(id, snap).unwrap();
        let loaded = v.load_replay_state(id).unwrap().expect("must be Some");
        assert_eq!(loaded, snap);

        // UPSERT overwrites.
        let snap2 = b"replacement snapshot";
        v.save_replay_state(id, snap2).unwrap();
        assert_eq!(v.load_replay_state(id).unwrap().unwrap(), snap2);
    }

    // ── T6.3.b: rooms ───────────────────────────────────────────────

    #[test]
    fn room_save_list_round_trip() {
        let mut v = fresh_vault();
        let (id, _identity) = v.create_identity("alice").unwrap();

        // Empty to start.
        assert!(v.list_rooms(id).unwrap().is_empty());

        // Insert one room.
        let gid_1 = vec![0x01, 0x02, 0x03];
        v.save_room(id, &gid_1, "alpha", "fp_alice,fp_bob", 1_000)
            .unwrap();
        let rooms = v.list_rooms(id).unwrap();
        assert_eq!(rooms.len(), 1);
        assert_eq!(rooms[0].group_id, gid_1);
        assert_eq!(rooms[0].name, "alpha");
        assert_eq!(rooms[0].members_b32, "fp_alice,fp_bob");
        assert_eq!(rooms[0].created_at_ms, 1_000);

        // Insert a second room — list now sorted by created_at ASC.
        let gid_2 = vec![0x10, 0x20, 0x30];
        v.save_room(id, &gid_2, "beta", "fp_alice", 2_000).unwrap();
        let rooms = v.list_rooms(id).unwrap();
        assert_eq!(rooms.len(), 2);
        assert_eq!(rooms[0].name, "alpha"); // older
        assert_eq!(rooms[1].name, "beta"); // newer
    }

    #[test]
    fn room_save_is_upsert_on_group_id() {
        let mut v = fresh_vault();
        let (id, _identity) = v.create_identity("alice").unwrap();

        let gid = vec![0xAA, 0xBB];
        v.save_room(id, &gid, "alpha", "fp_alice", 1_000).unwrap();
        // Same group_id, updated name + members.
        v.save_room(id, &gid, "alpha-renamed", "fp_alice,fp_bob", 1_500)
            .unwrap();

        let rooms = v.list_rooms(id).unwrap();
        assert_eq!(rooms.len(), 1, "UPSERT must not duplicate");
        assert_eq!(rooms[0].name, "alpha-renamed");
        assert_eq!(rooms[0].members_b32, "fp_alice,fp_bob");
        assert_eq!(rooms[0].created_at_ms, 1_500);
    }

    #[test]
    fn room_delete_is_idempotent() {
        let mut v = fresh_vault();
        let (id, _identity) = v.create_identity("alice").unwrap();
        let gid = vec![0x42; 32];

        // Deleting a never-inserted room is a no-op.
        v.delete_room(id, &gid).unwrap();
        assert!(v.list_rooms(id).unwrap().is_empty());

        // Insert + delete + verify gone.
        v.save_room(id, &gid, "alpha", "fp_alice", 1).unwrap();
        assert_eq!(v.list_rooms(id).unwrap().len(), 1);
        v.delete_room(id, &gid).unwrap();
        assert!(v.list_rooms(id).unwrap().is_empty());

        // Double-delete still fine.
        v.delete_room(id, &gid).unwrap();
    }

    #[test]
    fn rooms_isolated_across_identities() {
        // FK to identities means each identity has its own room set.
        let mut v = fresh_vault();
        let (alice, _) = v.create_identity("alice").unwrap();
        let (bob, _) = v.create_identity("bob").unwrap();

        v.save_room(alice, &[0xA1], "alice-room", "fp_alice", 100)
            .unwrap();
        v.save_room(bob, &[0xB1], "bob-room", "fp_bob", 200)
            .unwrap();

        let alice_rooms = v.list_rooms(alice).unwrap();
        assert_eq!(alice_rooms.len(), 1);
        assert_eq!(alice_rooms[0].name, "alice-room");

        let bob_rooms = v.list_rooms(bob).unwrap();
        assert_eq!(bob_rooms.len(), 1);
        assert_eq!(bob_rooms[0].name, "bob-room");
    }

    // ── T6.3.e: room_member_kems ─────────────────────────────────

    #[test]
    fn room_member_kem_save_lookup_round_trip() {
        let mut v = fresh_vault();
        let (id, _) = v.create_identity("alice").unwrap();
        let group_id = b"room-1";
        let fp = "AAAA-BBBB-CCCC";
        let kem = vec![7u8; 1216];

        v.save_room_member_kem(id, group_id, fp, &kem).unwrap();
        let got = v.lookup_room_member_kem(id, group_id, fp).unwrap();
        assert_eq!(got, Some(kem));
    }

    #[test]
    fn room_member_kem_lookup_missing_is_none() {
        let mut v = fresh_vault();
        let (id, _) = v.create_identity("alice").unwrap();
        let got = v
            .lookup_room_member_kem(id, b"room-x", "fp-never-saved")
            .unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn room_member_kem_save_is_upsert() {
        let mut v = fresh_vault();
        let (id, _) = v.create_identity("alice").unwrap();
        let group_id = b"room-1";
        let fp = "fp_bob";

        v.save_room_member_kem(id, group_id, fp, &[1u8; 10])
            .unwrap();
        v.save_room_member_kem(id, group_id, fp, &[2u8; 10])
            .unwrap();
        let got = v.lookup_room_member_kem(id, group_id, fp).unwrap();
        // Upsert: second call's bytes win.
        assert_eq!(got, Some(vec![2u8; 10]));
    }

    #[test]
    fn peer_group_forget_is_idempotent_and_clears_lookup() {
        let mut v = fresh_vault();
        let (id, _) = v.create_identity("alice").unwrap();
        let peer_pub = [0x55u8; 32];

        // Forget when nothing's there: must succeed silently.
        v.forget_peer_group(id, &peer_pub).unwrap();

        // Record, confirm it's there, forget, confirm it's gone.
        v.record_peer_group(id, &peer_pub, b"some-group").unwrap();
        assert!(v.lookup_peer_group(id, &peer_pub).unwrap().is_some());
        v.forget_peer_group(id, &peer_pub).unwrap();
        assert!(v.lookup_peer_group(id, &peer_pub).unwrap().is_none());

        // Idempotent on a second call.
        v.forget_peer_group(id, &peer_pub).unwrap();
    }

    #[test]
    fn peer_group_record_and_lookup() {
        let mut v = fresh_vault();
        let (id, _) = v.create_identity("alice").unwrap();
        let peer_pub = [0x42u8; 32];
        let group_id = b"group-bytes-here";

        assert!(v.lookup_peer_group(id, &peer_pub).unwrap().is_none());

        v.record_peer_group(id, &peer_pub, group_id).unwrap();
        let loaded = v.lookup_peer_group(id, &peer_pub).unwrap();
        assert_eq!(loaded.as_deref(), Some(&group_id[..]));

        // UPSERT: re-record with a different group_id overwrites.
        let group_id2 = b"different-group";
        v.record_peer_group(id, &peer_pub, group_id2).unwrap();
        let loaded2 = v.lookup_peer_group(id, &peer_pub).unwrap();
        assert_eq!(loaded2.as_deref(), Some(&group_id2[..]));

        // A different peer key returns None.
        let other_peer = [0x99u8; 32];
        assert!(v.lookup_peer_group(id, &other_peer).unwrap().is_none());
    }

    #[test]
    fn mls_state_persists_across_reopen() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        tmp.close().unwrap();

        let identity_id;
        let saved_blob = b"persisted MLS snapshot";

        {
            let mut v = Vault::create(&path, b"pw", &Argon2Params::FLOOR).unwrap();
            let (id, _identity) = v.create_identity("alice").unwrap();
            v.save_mls_state(id, saved_blob).unwrap();
            identity_id = id;
        }

        {
            let v = Vault::open(&path, b"pw").unwrap();
            let loaded = v
                .load_mls_state(identity_id)
                .unwrap()
                .expect("MLS state lost across reopen");
            assert_eq!(loaded, saved_blob);
        }

        std::fs::remove_file(&path).ok();
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
