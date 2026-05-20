//! Cryptographic primitive wrappers.
//!
//! This module is the single point where raw third-party crypto crates enter
//! `onyx-core`. Higher-level modules ([`crate::identity`], [`crate::transport`],
//! [`crate::routing`], [`crate::storage`]) MUST NOT depend on `ed25519-dalek`,
//! `chacha20poly1305`, etc. directly — they consume the wrappers defined here.
//!
//! Centralising the boundary lets us:
//!   * apply uniform zeroize / constant-time policies,
//!   * audit a single file for nonce / RNG / FFI bugs,
//!   * swap implementations (e.g. add a PQ-hybrid layer — DESIGN.md §9.6)
//!     without touching every call site.
//!
//! See DESIGN.md §4.1 (key types) and §5 (transport primitives).

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use blake2::Digest;
use blake2::digest::consts::{U16, U32};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as AeadRawKey, Nonce as AeadRawNonce};
use ed25519_dalek::{Signer, Verifier};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate, EncapsulationKey as MlKemEk};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};

// ── Random ──────────────────────────────────────────────────────────────────

/// Fill `bytes` with cryptographically-secure random data from the operating
/// system's CSPRNG (via `getrandom`).
pub fn fill_random(bytes: &mut [u8]) {
    OsRng.fill_bytes(bytes);
}

/// Generate a random byte array of compile-time-known length.
#[must_use]
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

// ── Ed25519 (signing) ───────────────────────────────────────────────────────

/// An Ed25519 secret signing key. Zeroized on drop by the inner `dalek` type.
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    /// Generate a fresh key from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        Self(ed25519_dalek::SigningKey::generate(&mut OsRng))
    }

    /// Reconstruct a key from its 32-byte seed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(bytes))
    }

    /// Export the 32-byte seed in a `Zeroizing` wrapper so callers can't
    /// accidentally leave the secret on the stack.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key().to_bytes())
    }

    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message).to_bytes())
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material — show only a marker.
        f.debug_struct("SigningKey").finish_non_exhaustive()
    }
}

/// An Ed25519 public verifying key. The raw 32 bytes ARE the user's fingerprint
/// (DESIGN.md §4.1 — onion v3 key is derived from the same bytes).
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct VerifyingKey([u8; 32]);

impl VerifyingKey {
    /// Validate that `bytes` is a point on the Ed25519 curve, then store it.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| Error::VerificationFailed)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&self.0)
            .map_err(|_| Error::VerificationFailed)?;
        let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
        vk.verify(message, &sig)
            .map_err(|_| Error::VerificationFailed)
    }

    /// Compute the [`Fingerprint`] for this key. Currently the identity
    /// function — the design pins the fingerprint to the raw signing-key
    /// bytes so it is also the onion v3 identifier.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint(self.0)
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey({})", self.fingerprint())
    }
}

/// A 64-byte Ed25519 signature.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Signature([u8; 64]);

impl Signature {
    #[must_use]
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature").finish_non_exhaustive()
    }
}

// ── Fingerprint ─────────────────────────────────────────────────────────────

/// A 32-byte identity fingerprint — the raw Ed25519 verifying-key bytes.
///
/// Displayed as 52 base32 characters (RFC 4648 lowercase, no padding) grouped
/// in chunks of four for human comparison:
///
/// ```text
/// fpr: aaaa bbbb cccc dddd eeee ffff gggg hhhh iiii jjjj kkkk llll mmmm
/// ```
///
/// The parser is tolerant of whitespace, casing, and the optional `fpr:` prefix.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub const BYTE_LEN: usize = 32;

    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encode as 52 base32 characters with no padding.
    #[must_use]
    pub fn to_base32(&self) -> String {
        base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, &self.0)
    }

    /// Encode as base32, grouped in chunks of 4 separated by a single space.
    /// The final group may be shorter than 4.
    #[must_use]
    pub fn to_base32_grouped(&self) -> String {
        let raw = self.to_base32();
        let mut out = String::with_capacity(raw.len() + raw.len() / 4);
        for (i, ch) in raw.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push(' ');
            }
            out.push(ch);
        }
        out
    }

    /// Parse the grouped or ungrouped base32 form. Tolerates whitespace,
    /// mixed case, and an optional `fpr:` prefix.
    pub fn parse(s: &str) -> Result<Self> {
        // Normalize first (strip whitespace, lowercase), then strip the optional
        // prefix from the normalized string. Doing it the other way means the
        // prefix has to appear verbatim at byte 0 of the user's input.
        let cleaned: String = s
            .chars()
            .filter(|c| !c.is_whitespace())
            .flat_map(char::to_lowercase)
            .collect();
        let body = cleaned.strip_prefix("fpr:").unwrap_or(&cleaned);

        let bytes = base32::decode(base32::Alphabet::Rfc4648Lower { padding: false }, body)
            .ok_or(Error::InvalidEncoding("fingerprint: not valid base32"))?;

        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidEncoding("fingerprint: must decode to 32 bytes"))?;
        Ok(Self(array))
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base32_grouped())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.to_base32_grouped())
    }
}

// ── X25519 (identity DH) ────────────────────────────────────────────────────

/// An X25519 long-term identity secret. Zeroized on drop.
pub struct IdentitySecret(x25519_dalek::StaticSecret);

impl IdentitySecret {
    #[must_use]
    pub fn generate() -> Self {
        Self(x25519_dalek::StaticSecret::random_from_rng(OsRng))
    }

    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(x25519_dalek::StaticSecret::from(bytes))
    }

    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    #[must_use]
    pub fn public(&self) -> IdentityPublic {
        IdentityPublic(x25519_dalek::PublicKey::from(&self.0).to_bytes())
    }

    /// Diffie–Hellman with a counterparty's public key. The resulting shared
    /// secret is **not** suitable for direct use as a key — feed it through
    /// [`hkdf_sha256`] first.
    #[must_use]
    pub fn diffie_hellman(&self, other: &IdentityPublic) -> SharedSecret {
        let pk = x25519_dalek::PublicKey::from(other.0);
        let shared = self.0.diffie_hellman(&pk);
        SharedSecret(shared.to_bytes())
    }
}

impl fmt::Debug for IdentitySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentitySecret").finish_non_exhaustive()
    }
}

/// An X25519 public identity key.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct IdentityPublic([u8; 32]);

impl IdentityPublic {
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for IdentityPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityPublic").finish_non_exhaustive()
    }
}

/// A 32-byte X25519 shared secret. Zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedSecret").finish_non_exhaustive()
    }
}

// ── AEAD (ChaCha20-Poly1305) ────────────────────────────────────────────────

/// A 32-byte ChaCha20-Poly1305 AEAD key. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AeadKey([u8; 32]);

impl AeadKey {
    pub const KEY_LEN: usize = 32;

    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// AEAD-encrypt `plaintext` under `nonce` with associated data `aad`.
    /// Returns ciphertext concatenated with the 16-byte Poly1305 tag.
    ///
    /// Caller is responsible for nonce uniqueness under this key — reusing a
    /// nonce catastrophically breaks both confidentiality and authenticity.
    pub fn encrypt(&self, nonce: &Nonce, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(AeadRawKey::from_slice(&self.0));
        cipher
            .encrypt(
                AeadRawNonce::from_slice(&nonce.0),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::Internal("AEAD encrypt failed"))
    }

    /// AEAD-decrypt. Returns the plaintext on a valid tag; returns
    /// [`Error::VerificationFailed`] on any tampering of ciphertext, AAD,
    /// nonce, or key.
    pub fn decrypt(&self, nonce: &Nonce, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(AeadRawKey::from_slice(&self.0));
        cipher
            .decrypt(
                AeadRawNonce::from_slice(&nonce.0),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| Error::VerificationFailed)
    }
}

impl fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadKey").finish_non_exhaustive()
    }
}

/// 12-byte AEAD nonce. Not secret; not zeroized.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct Nonce([u8; 12]);

impl Nonce {
    pub const SIZE: usize = 12;

    #[must_use]
    pub fn from_bytes(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// Build a nonce from a 64-bit counter (Noise-style: 4 leading zero bytes,
    /// then the counter big-endian). Suitable for stream-of-frame use.
    #[must_use]
    pub fn from_counter(counter: u64) -> Self {
        let mut out = [0u8; 12];
        out[4..].copy_from_slice(&counter.to_be_bytes());
        Self(out)
    }

    #[must_use]
    pub fn random() -> Self {
        Self(random_array::<12>())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

// ── HKDF-SHA256 ─────────────────────────────────────────────────────────────

/// Derive `okm.len()` bytes via HKDF-SHA256 from input keying material `ikm`,
/// optional `salt`, and a context-binding `info` string.
///
/// `info` is the place to namespace derivations — see [`crate::KDF_NAMESPACE`].
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, okm)
        .map_err(|_| Error::Internal("HKDF expand: output too long"))
}

// ── BLAKE2b-128 ─────────────────────────────────────────────────────────────

/// Compute BLAKE2b with a 16-byte (128-bit) output over the concatenation of
/// all `inputs`. Used for routing-ID derivation (DESIGN.md §5.5).
///
/// Taking a slice-of-slices lets callers avoid an intermediate `Vec` for the
/// `signing_pk || "onyx/v1/inbox"` pattern.
#[must_use]
pub fn blake2b_128(inputs: &[&[u8]]) -> [u8; 16] {
    type Blake2b128 = blake2::Blake2b<U16>;
    let mut hasher = Blake2b128::new();
    for chunk in inputs {
        hasher.update(chunk);
    }
    let out = hasher.finalize();
    let mut result = [0u8; 16];
    result.copy_from_slice(&out);
    result
}

/// Compute BLAKE2b with a 32-byte (256-bit) output over the
/// concatenation of all `inputs`. Used for file content-hash
/// verification (`FILES.md §2.8`); 256-bit is the standard collision
/// resistance for an integrity hash and matches what most modern
/// HASH-of-file workflows expect.
#[must_use]
pub fn blake2b_256(inputs: &[&[u8]]) -> [u8; 32] {
    type Blake2b256 = blake2::Blake2b<U32>;
    let mut hasher = Blake2b256::new();
    for chunk in inputs {
        hasher.update(chunk);
    }
    let out = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

// ── Argon2id ────────────────────────────────────────────────────────────────

/// Argon2id parameters for the passphrase-derived vault key (DESIGN.md §7.1).
#[derive(Copy, Clone, Debug)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of passes.
    pub iterations: u32,
    /// Parallelism (lanes).
    pub parallelism: u32,
}

impl Argon2Params {
    /// Workspace default: 256 MiB / t=3 / p=4.
    pub const DEFAULT: Self = Self {
        memory_kib: 256 * 1024,
        iterations: 3,
        parallelism: 4,
    };

    /// Workspace floor for low-memory devices: 64 MiB / t=3 / p=2.
    /// The daemon refuses to start with parameters weaker than this.
    pub const FLOOR: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 2,
    };

    /// Verify that `self` is at or above [`Self::FLOOR`] on every dimension.
    pub fn validate(&self) -> Result<()> {
        if self.memory_kib < Self::FLOOR.memory_kib {
            return Err(Error::KdfParamsTooWeak("memory_kib below floor"));
        }
        if self.iterations < Self::FLOOR.iterations {
            return Err(Error::KdfParamsTooWeak("iterations below floor"));
        }
        if self.parallelism < Self::FLOOR.parallelism {
            return Err(Error::KdfParamsTooWeak("parallelism below floor"));
        }
        Ok(())
    }
}

/// Derive `output.len()` bytes from `passphrase` and `salt` via Argon2id.
/// `salt` is exactly 16 bytes by convention; callers should generate it with
/// [`random_array::<16>()`] and store it alongside the vault.
///
/// Refuses to run if `params` is below [`Argon2Params::FLOOR`].
pub fn argon2id_derive(
    passphrase: &[u8],
    salt: &[u8; 16],
    params: &Argon2Params,
    output: &mut [u8],
) -> Result<()> {
    params.validate()?;

    let p = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(output.len()),
    )
    .map_err(|_| Error::Internal("Argon2 params construction failed"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    argon2
        .hash_password_into(passphrase, salt, output)
        .map_err(|_| Error::Internal("Argon2 derivation failed"))
}

// ── Post-quantum hybrid KEM (X25519 ‖ ML-KEM-768) ──────────────────────────
//
// Onyx combines a classical X25519 ephemeral DH with FIPS 203 ML-KEM-768 so
// the resulting shared secret is secure as long as **either** primitive is
// unbroken. This is the same defence-in-depth pattern as Signal's PQXDH and
// the TLS 1.3 `X25519MLKEM768` hybrid group.
//
// **Audit status.** The upstream `ml-kem` crate states in its own README that
// it has not been independently audited. Hybrid composition mitigates this:
// even a complete break of the PQ implementation degrades us to the security
// of X25519 alone, which is what unmodified Onyx provided in v0.0.1. We DO
// rely on the audited X25519 implementation never silently degrading.

/// X25519 public-key half of a hybrid public key or ciphertext.
pub const HYBRID_CLASSICAL_LEN: usize = 32;
/// ML-KEM-768 encapsulation-key size (FIPS 203, K=3): 384 K + 32 = 1184 bytes.
pub const HYBRID_PQ_PUBLIC_LEN: usize = 1184;
/// ML-KEM-768 ciphertext size (FIPS 203, K=3): 32 (Du K + Dv) = 1088 bytes.
pub const HYBRID_PQ_CIPHERTEXT_LEN: usize = 1088;
/// ML-KEM-768 decapsulation-key size (FIPS 203, K=3): 768 K + 96 = 2400 bytes.
///
/// The test `hybrid_pq_secret_len_matches_runtime` in this module
/// asserts this constant matches the live `<PqDecapKey as
/// EncodedSizeUser>::EncodedSize` so a future ml-kem release that
/// changes the layout fails loudly here rather than at runtime in
/// the field.
pub const HYBRID_PQ_SECRET_LEN: usize = 2400;
/// Combined hybrid public-key size on the wire: X25519 pk ‖ ML-KEM EK.
pub const HYBRID_PUBLIC_LEN: usize = HYBRID_CLASSICAL_LEN + HYBRID_PQ_PUBLIC_LEN;
/// Combined hybrid ciphertext size on the wire: ephemeral X25519 pk ‖ ML-KEM CT.
pub const HYBRID_CIPHERTEXT_LEN: usize = HYBRID_CLASSICAL_LEN + HYBRID_PQ_CIPHERTEXT_LEN;
/// Serialised size of a [`HybridKemSecret`]: X25519 sk ‖ ML-KEM-768 dk.
/// Used as the chunk size when persisting hybrid KEM keys to the vault.
pub const HYBRID_SECRET_LEN: usize = HYBRID_CLASSICAL_LEN + HYBRID_PQ_SECRET_LEN;

/// HKDF salt for combining the classical and post-quantum shared secrets.
/// Bumping this string invalidates every prior hybrid derivation, so it only
/// changes with a protocol-incompatible revision.
const HYBRID_HKDF_SALT: &[u8] = b"onyx/v1/hybrid-kem";

type PqDecapKey = <MlKem768 as KemCore>::DecapsulationKey;
type PqEncapKey = MlKemEk<MlKem768Params>;
type PqCiphertextArray = ml_kem::Ciphertext<MlKem768>;

/// A hybrid KEM secret combining an X25519 long-term identity secret with an
/// ML-KEM-768 decapsulation key. Both halves zeroize on drop (X25519 via
/// `x25519-dalek`'s `zeroize` feature, ML-KEM via `ml-kem`'s).
pub struct HybridKemSecret {
    classical: x25519_dalek::StaticSecret,
    post_quantum: PqDecapKey,
}

impl HybridKemSecret {
    #[must_use]
    pub fn generate() -> Self {
        let classical = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let (post_quantum, _ek) = MlKem768::generate(&mut OsRng);
        Self {
            classical,
            post_quantum,
        }
    }

    /// Derive the matching hybrid public key. The PQ encapsulation key is
    /// embedded in the decapsulation key (FIPS 203 §6.1), so no KeyGen-style
    /// recomputation is required.
    #[must_use]
    pub fn public(&self) -> HybridKemPublic {
        HybridKemPublic {
            classical: x25519_dalek::PublicKey::from(&self.classical).to_bytes(),
            post_quantum: self.post_quantum.encapsulation_key().clone(),
        }
    }

    /// Serialise both halves into a [`HYBRID_SECRET_LEN`]-byte buffer
    /// for vault persistence. Returns a [`Zeroizing`] buffer so the
    /// caller can't accidentally leak the secret on the stack.
    ///
    /// Layout: `X25519 secret (32 B) ‖ ML-KEM-768 decapsulation key (2400 B)`.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(HYBRID_SECRET_LEN));
        out.extend_from_slice(&self.classical.to_bytes());
        let pq_encoded = self.post_quantum.as_bytes();
        out.extend_from_slice(pq_encoded.as_slice());
        debug_assert_eq!(out.len(), HYBRID_SECRET_LEN);
        out
    }

    /// Reconstruct from a buffer produced by [`Self::to_bytes`].
    ///
    /// Errors:
    ///   * [`Error::InvalidEncoding`] if the buffer is the wrong length
    ///     (the only validation we can do — ML-KEM-768's decapsulation key
    ///     itself accepts any 2400-byte input; correctness only surfaces
    ///     when an actual decapsulation runs).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HYBRID_SECRET_LEN {
            return Err(Error::BufferSize {
                expected: HYBRID_SECRET_LEN,
                actual: bytes.len(),
            });
        }
        let mut classical_bytes = [0u8; HYBRID_CLASSICAL_LEN];
        classical_bytes.copy_from_slice(&bytes[..HYBRID_CLASSICAL_LEN]);
        let classical = x25519_dalek::StaticSecret::from(classical_bytes);
        classical_bytes.zeroize();

        let pq_slice = &bytes[HYBRID_CLASSICAL_LEN..];
        // `Encoded<PqDecapKey>` is `Array<u8, N>`. Construct it from the
        // slice; ml-kem's `from_bytes` then maps the byte array into the
        // internal key representation.
        let pq_encoded =
            Encoded::<PqDecapKey>::try_from(pq_slice).map_err(|_| Error::BufferSize {
                expected: HYBRID_PQ_SECRET_LEN,
                actual: pq_slice.len(),
            })?;
        let post_quantum = PqDecapKey::from_bytes(&pq_encoded);

        Ok(Self {
            classical,
            post_quantum,
        })
    }

    /// Decapsulate a hybrid ciphertext to the combined shared secret.
    ///
    /// Note that ML-KEM-768 uses *implicit rejection* — a tampered PQ
    /// ciphertext does not error, it returns a pseudo-random shared secret.
    /// In the hybrid construction this is harmless: any tampering of either
    /// half of the ciphertext changes the combined output, because the entire
    /// ciphertext bytes are bound into the HKDF `info` field.
    pub fn decapsulate(&self, ct: &HybridCiphertext) -> Result<HybridSharedSecret> {
        let their_classical = x25519_dalek::PublicKey::from(ct.classical);
        let x_ss = self.classical.diffie_hellman(&their_classical);

        let pq_ct_array = PqCiphertextArray::from(ct.post_quantum);
        let pq_ss = Decapsulate::decapsulate(&self.post_quantum, &pq_ct_array)
            .map_err(|()| Error::VerificationFailed)?;

        let mut pq_ss_bytes = [0u8; 32];
        pq_ss_bytes.copy_from_slice(pq_ss.as_ref());

        // Derive our own public key to bind into the combiner, matching
        // what the encapsulator did with the same recipient pubkey.
        let combined = combine_hybrid_secrets(&x_ss.to_bytes(), &pq_ss_bytes, ct, &self.public())?;

        // Zeroize the borrowed-by-value PQ secret bytes; X25519 SharedSecret
        // zeroizes itself on drop via the dalek zeroize feature.
        pq_ss_bytes.zeroize();

        Ok(combined)
    }
}

impl fmt::Debug for HybridKemSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridKemSecret").finish_non_exhaustive()
    }
}

/// A hybrid KEM public key: X25519 long-term pk ‖ ML-KEM-768 encapsulation key.
/// Not secret; the bytes are safe to publish in routing tables, contact cards,
/// and onion-service descriptors.
#[derive(Clone)]
pub struct HybridKemPublic {
    classical: [u8; HYBRID_CLASSICAL_LEN],
    post_quantum: PqEncapKey,
}

impl HybridKemPublic {
    /// Encapsulate a fresh shared secret to this public key. Generates an
    /// ephemeral X25519 keypair (used only for this one encapsulation, then
    /// dropped + zeroized) and a fresh ML-KEM-768 ciphertext.
    pub fn encapsulate(&self) -> Result<(HybridCiphertext, HybridSharedSecret)> {
        // Ephemeral X25519 — `EphemeralSecret` consumes itself on
        // `diffie_hellman`, so capture the public bytes first.
        let eph_secret = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
        let eph_public_bytes = x25519_dalek::PublicKey::from(&eph_secret).to_bytes();
        let recipient_classical = x25519_dalek::PublicKey::from(self.classical);
        let x_ss = eph_secret.diffie_hellman(&recipient_classical);

        // ML-KEM encapsulation.
        let (pq_ct_array, pq_ss) = Encapsulate::encapsulate(&self.post_quantum, &mut OsRng)
            .map_err(|()| Error::Internal("ML-KEM encapsulate failed"))?;

        let mut pq_ct_bytes = [0u8; HYBRID_PQ_CIPHERTEXT_LEN];
        pq_ct_bytes.copy_from_slice(pq_ct_array.as_ref());

        let ct = HybridCiphertext {
            classical: eph_public_bytes,
            post_quantum: pq_ct_bytes,
        };

        let mut pq_ss_bytes = [0u8; 32];
        pq_ss_bytes.copy_from_slice(pq_ss.as_ref());
        // `self` IS the recipient public key for an encapsulation.
        let combined = combine_hybrid_secrets(&x_ss.to_bytes(), &pq_ss_bytes, &ct, self)?;
        pq_ss_bytes.zeroize();

        Ok((ct, combined))
    }

    /// Wire encoding: X25519 pk (32 B) ‖ ML-KEM-768 EK (1184 B) = 1216 B.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_PUBLIC_LEN);
        out.extend_from_slice(&self.classical);
        out.extend_from_slice(self.post_quantum.as_bytes().as_ref());
        out
    }

    /// Parse a hybrid public key from its wire encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HYBRID_PUBLIC_LEN {
            return Err(Error::BufferSize {
                expected: HYBRID_PUBLIC_LEN,
                actual: bytes.len(),
            });
        }
        let mut classical = [0u8; HYBRID_CLASSICAL_LEN];
        classical.copy_from_slice(&bytes[..HYBRID_CLASSICAL_LEN]);

        let pq_slice = &bytes[HYBRID_CLASSICAL_LEN..];
        let pq_encoded =
            Encoded::<PqEncapKey>::try_from(pq_slice).map_err(|_| Error::BufferSize {
                expected: HYBRID_PQ_PUBLIC_LEN,
                actual: pq_slice.len(),
            })?;
        let post_quantum = PqEncapKey::from_bytes(&pq_encoded);

        Ok(Self {
            classical,
            post_quantum,
        })
    }
}

impl fmt::Debug for HybridKemPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridKemPublic").finish_non_exhaustive()
    }
}

/// A hybrid ciphertext: sender's ephemeral X25519 pk ‖ ML-KEM-768 ciphertext.
#[derive(Clone)]
pub struct HybridCiphertext {
    classical: [u8; HYBRID_CLASSICAL_LEN],
    post_quantum: [u8; HYBRID_PQ_CIPHERTEXT_LEN],
}

impl HybridCiphertext {
    /// Wire encoding: ephemeral X25519 pk (32 B) ‖ ML-KEM-768 CT (1088 B) = 1120 B.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_CIPHERTEXT_LEN);
        out.extend_from_slice(&self.classical);
        out.extend_from_slice(&self.post_quantum);
        out
    }

    /// Parse a hybrid ciphertext from its wire encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HYBRID_CIPHERTEXT_LEN {
            return Err(Error::BufferSize {
                expected: HYBRID_CIPHERTEXT_LEN,
                actual: bytes.len(),
            });
        }
        let mut classical = [0u8; HYBRID_CLASSICAL_LEN];
        classical.copy_from_slice(&bytes[..HYBRID_CLASSICAL_LEN]);
        let mut post_quantum = [0u8; HYBRID_PQ_CIPHERTEXT_LEN];
        post_quantum.copy_from_slice(&bytes[HYBRID_CLASSICAL_LEN..]);
        Ok(Self {
            classical,
            post_quantum,
        })
    }
}

impl fmt::Debug for HybridCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridCiphertext").finish_non_exhaustive()
    }
}

/// 32-byte combined shared secret from the hybrid KEM. Zeroized on drop.
///
/// Suitable as input keying material for a follow-on KDF (transport key
/// schedule, MLS welcome, etc.). Do not use as an AEAD key directly — feed
/// it through [`hkdf_sha256`] with a use-specific `info` first.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSharedSecret([u8; 32]);

impl HybridSharedSecret {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for HybridSharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridSharedSecret").finish_non_exhaustive()
    }
}

/// Combine the classical and post-quantum shared secrets through HKDF-SHA256.
///
/// Audit hardening (X-Wing / PQXDH-style binding): the KDF `info` binds
/// the full transcript of the encapsulation —
///
/// ```text
///   info = ct.classical (eph X25519 pub)
///        ‖ ct.post_quantum (ML-KEM ciphertext)
///        ‖ recipient X25519 static pub
///        ‖ recipient ML-KEM encapsulation key
/// ```
///
/// Previously only the ciphertext halves were bound. Binding the
/// recipient's *static public keys* as well makes this a robust
/// combiner in the sense of Giacon–Heuer–Poettering / the X-Wing
/// construction: the combined secret commits to which recipient the
/// encapsulation was for, so the output stays secure as long as
/// *either* X25519 *or* ML-KEM-768 is unbroken, and a ciphertext can't
/// be silently re-pointed at a different recipient public key. Both
/// `encapsulate` (has the recipient pubkey as `self`) and
/// `decapsulate` (derives it via `self.public()`) feed the identical
/// bytes, so the two sides agree.
fn combine_hybrid_secrets(
    x_ss: &[u8; 32],
    pq_ss: &[u8; 32],
    ct: &HybridCiphertext,
    recipient_pub: &HybridKemPublic,
) -> Result<HybridSharedSecret> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(x_ss);
    ikm[32..].copy_from_slice(pq_ss);

    let recipient_pq_ek = recipient_pub.post_quantum.as_bytes();
    let mut info = Vec::with_capacity(
        HYBRID_CIPHERTEXT_LEN + HYBRID_CLASSICAL_LEN + recipient_pq_ek.as_slice().len(),
    );
    info.extend_from_slice(&ct.classical);
    info.extend_from_slice(&ct.post_quantum);
    info.extend_from_slice(&recipient_pub.classical);
    info.extend_from_slice(recipient_pq_ek.as_slice());

    let mut out = [0u8; 32];
    hkdf_sha256(&ikm[..], HYBRID_HKDF_SALT, &info, &mut out)?;
    Ok(HybridSharedSecret(out))
}

// ── Constant-time comparison ────────────────────────────────────────────────

/// Constant-time equality. Use this for any comparison whose timing must not
/// reveal the operand contents (tags, fingerprints under attacker control,
/// authentication tokens, …).
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032 §7.1 test 1 — empty message under the all-zero+ish seed.
    #[test]
    fn ed25519_rfc8032_test_1() {
        let seed: [u8; 32] = hex32(
            "9d61b19deffd5a60ba844af492ec2cc4\
             4449c5697b326919703bac031cae7f60",
        );
        let expected_pub: [u8; 32] = hex32(
            "d75a980182b10ab7d54bfed3c964073a\
             0ee172f3daa62325af021a68f707511a",
        );
        let sk = SigningKey::from_bytes(&seed);
        assert_eq!(sk.verifying_key().to_bytes(), expected_pub);

        let sig = sk.sign(b"");
        sk.verifying_key().verify(b"", &sig).unwrap();
    }

    #[test]
    fn ed25519_round_trip_and_tamper() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();
        let msg = b"the design says fingerprint == pubkey";
        let sig = sk.sign(msg);

        vk.verify(msg, &sig).unwrap();

        // Tamper with the message → verification fails.
        let mut bad_msg = msg.to_vec();
        bad_msg[0] ^= 1;
        assert!(matches!(
            vk.verify(&bad_msg, &sig),
            Err(Error::VerificationFailed)
        ));

        // Tamper with the signature → verification fails.
        let mut bad_sig = sig.to_bytes();
        bad_sig[0] ^= 1;
        assert!(matches!(
            vk.verify(msg, &Signature::from_bytes(bad_sig)),
            Err(Error::VerificationFailed)
        ));
    }

    #[test]
    fn verifying_key_round_trips_bytes() {
        // ed25519-dalek 2.x in non-strict mode accepts non-canonical y-values,
        // so testing that "all 0xFF gets rejected" is implementation-defined and
        // not a useful contract. Instead, exercise the round-trip we actually
        // care about: a valid key's bytes parse back to an equal key, and a
        // signature made by the original verifies under the parsed copy.
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();
        let bytes = vk.to_bytes();
        let vk2 = VerifyingKey::from_bytes(bytes).unwrap();
        assert_eq!(vk, vk2);

        let sig = sk.sign(b"round-trip");
        vk2.verify(b"round-trip", &sig).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_signer() {
        let msg = b"who signed this?";
        let alice = SigningKey::generate();
        let mallory = SigningKey::generate();
        let sig_by_mallory = mallory.sign(msg);
        // Alice's verifying key must reject a signature Mallory made.
        assert!(matches!(
            alice.verifying_key().verify(msg, &sig_by_mallory),
            Err(Error::VerificationFailed)
        ));
    }

    #[test]
    fn x25519_dh_is_symmetric() {
        let a = IdentitySecret::generate();
        let b = IdentitySecret::generate();
        let s_ab = a.diffie_hellman(&b.public());
        let s_ba = b.diffie_hellman(&a.public());
        assert_eq!(s_ab.as_bytes(), s_ba.as_bytes());
    }

    #[test]
    fn aead_round_trip_and_tamper() {
        let key = AeadKey::from_bytes(random_array());
        let nonce = Nonce::random();
        let aad = b"associated";
        let plaintext = b"in vino veritas, in tor anonymitas";

        let ct = key.encrypt(&nonce, aad, plaintext).unwrap();
        let pt = key.decrypt(&nonce, aad, &ct).unwrap();
        assert_eq!(pt, plaintext);

        // Tampered ciphertext.
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 1;
        assert!(matches!(
            key.decrypt(&nonce, aad, &bad_ct),
            Err(Error::VerificationFailed)
        ));

        // Wrong AAD.
        assert!(matches!(
            key.decrypt(&nonce, b"other", &ct),
            Err(Error::VerificationFailed)
        ));

        // Wrong nonce.
        let other_nonce = Nonce::from_counter(99);
        assert!(matches!(
            key.decrypt(&other_nonce, aad, &ct),
            Err(Error::VerificationFailed)
        ));

        // Wrong key.
        let other_key = AeadKey::from_bytes(random_array());
        assert!(matches!(
            other_key.decrypt(&nonce, aad, &ct),
            Err(Error::VerificationFailed)
        ));
    }

    #[test]
    fn nonce_from_counter_is_be_padded() {
        let n = Nonce::from_counter(0x0102_0304_0506_0708);
        assert_eq!(
            n.as_bytes(),
            &[0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    /// RFC 5869 §A.1 — Test Case 1, basic SHA-256.
    #[test]
    fn hkdf_rfc5869_test_1() {
        let ikm: [u8; 22] = [0x0b; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let mut okm = [0u8; 42];
        hkdf_sha256(&ikm, &salt, &info, &mut okm).unwrap();
        let expected: [u8; 42] = hex42(
            "3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865",
        );
        assert_eq!(okm, expected);
    }

    #[test]
    fn blake2b_128_is_deterministic_and_sized() {
        let a = blake2b_128(&[b"hello"]);
        let b = blake2b_128(&[b"hello"]);
        let c = blake2b_128(&[b"world"]);
        assert_eq!(a, b);
        assert_ne!(a, c);

        // Concatenation of slices == single slice of concatenation.
        let split = blake2b_128(&[b"foo", b"bar"]);
        let joined = blake2b_128(&[b"foobar"]);
        assert_eq!(split, joined);

        assert_eq!(a.len(), 16);
    }

    #[test]
    fn fingerprint_round_trip() {
        let bytes: [u8; 32] = random_array();
        let fpr = Fingerprint::from_bytes(bytes);
        let parsed = Fingerprint::parse(&fpr.to_base32_grouped()).unwrap();
        assert_eq!(fpr, parsed);
    }

    #[test]
    fn fingerprint_parser_is_tolerant() {
        let bytes: [u8; 32] = random_array();
        let fpr = Fingerprint::from_bytes(bytes);
        let grouped = fpr.to_base32_grouped();
        let messy = format!("  FPR:  {}\n", grouped.to_uppercase());
        let parsed = Fingerprint::parse(&messy).unwrap();
        assert_eq!(fpr, parsed);
    }

    #[test]
    fn fingerprint_grouped_is_52_plus_12_spaces() {
        let fpr = Fingerprint::from_bytes([0; 32]);
        let s = fpr.to_base32_grouped();
        // 52 base32 chars + a space after every 4th char (positions 4,8,…,48) = 12 spaces.
        assert_eq!(s.len(), 52 + 12);
        assert_eq!(s.chars().filter(|c| *c == ' ').count(), 12);
    }

    #[test]
    fn fingerprint_rejects_garbage() {
        assert!(Fingerprint::parse("not base32!").is_err());
        // Right alphabet but wrong length.
        assert!(Fingerprint::parse("aaaa").is_err());
    }

    #[test]
    fn argon2_floor_enforced() {
        let weak = Argon2Params {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        let mut out = [0u8; 32];
        let salt = [0_u8; 16];
        assert!(matches!(
            argon2id_derive(b"pw", &salt, &weak, &mut out),
            Err(Error::KdfParamsTooWeak(_))
        ));
    }

    #[test]
    fn argon2_default_derives_nonzero_and_is_deterministic() {
        // Use the floor for test speed (256 MiB default is too slow for CI).
        let params = Argon2Params::FLOOR;
        let salt: [u8; 16] = *b"onyx-test-salt!!";
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        argon2id_derive(b"correct horse battery staple", &salt, &params, &mut a).unwrap();
        argon2id_derive(b"correct horse battery staple", &salt, &params, &mut b).unwrap();
        assert_eq!(a, b, "Argon2 must be deterministic on same inputs");
        assert_ne!(a, [0_u8; 32], "Argon2 output must not be all zeros");

        let mut c = [0u8; 32];
        argon2id_derive(b"different passphrase", &salt, &params, &mut c).unwrap();
        assert_ne!(a, c, "different passphrase must yield different output");
    }

    #[test]
    fn hybrid_kem_round_trip() {
        let sk = HybridKemSecret::generate();
        let pk = sk.public();
        let (ct, ss_send) = pk.encapsulate().unwrap();
        let ss_recv = sk.decapsulate(&ct).unwrap();
        assert_eq!(
            ss_send.as_bytes(),
            ss_recv.as_bytes(),
            "encap and decap must produce the same shared secret"
        );
    }

    #[test]
    fn hybrid_kem_different_encaps_differ() {
        let sk = HybridKemSecret::generate();
        let pk = sk.public();
        let (_ct1, ss1) = pk.encapsulate().unwrap();
        let (_ct2, ss2) = pk.encapsulate().unwrap();
        assert_ne!(
            ss1.as_bytes(),
            ss2.as_bytes(),
            "two fresh encaps to the same recipient must use distinct randomness"
        );
    }

    #[test]
    fn hybrid_kem_wrong_recipient() {
        let sk_a = HybridKemSecret::generate();
        let sk_b = HybridKemSecret::generate();
        let (ct, ss_send) = sk_a.public().encapsulate().unwrap();
        let ss_recv_wrong = sk_b.decapsulate(&ct).unwrap();
        assert_ne!(
            ss_send.as_bytes(),
            ss_recv_wrong.as_bytes(),
            "a recipient whose key was not the encapsulation target must derive a different secret"
        );
    }

    #[test]
    fn hybrid_kem_tampered_classical_half() {
        let sk = HybridKemSecret::generate();
        let pk = sk.public();
        let (mut ct, ss_send) = pk.encapsulate().unwrap();
        // Flip one bit in the X25519 ephemeral.
        ct.classical[0] ^= 0x01;
        let ss_recv = sk.decapsulate(&ct).unwrap();
        assert_ne!(
            ss_send.as_bytes(),
            ss_recv.as_bytes(),
            "tampering the classical half must change the combined secret"
        );
    }

    #[test]
    fn hybrid_kem_tampered_pq_half() {
        let sk = HybridKemSecret::generate();
        let pk = sk.public();
        let (mut ct, ss_send) = pk.encapsulate().unwrap();
        // Flip one bit in the PQ ciphertext (ML-KEM implicit rejection +
        // info-binding both ensure the output differs).
        ct.post_quantum[0] ^= 0x01;
        let ss_recv = sk.decapsulate(&ct).unwrap();
        assert_ne!(
            ss_send.as_bytes(),
            ss_recv.as_bytes(),
            "tampering the PQ half must change the combined secret"
        );
    }

    #[test]
    fn hybrid_kem_public_byte_round_trip() {
        let sk = HybridKemSecret::generate();
        let pk = sk.public();
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), HYBRID_PUBLIC_LEN);

        let pk2 = HybridKemPublic::from_bytes(&bytes).unwrap();
        // We can't compare HybridKemPublic directly (no Eq), so check that
        // the round-tripped key is usable: encap with it, decap with original sk.
        let (ct, ss_send) = pk2.encapsulate().unwrap();
        let ss_recv = sk.decapsulate(&ct).unwrap();
        assert_eq!(ss_send.as_bytes(), ss_recv.as_bytes());
    }

    #[test]
    fn hybrid_kem_ciphertext_byte_round_trip() {
        let sk = HybridKemSecret::generate();
        let pk = sk.public();
        let (ct, ss_send) = pk.encapsulate().unwrap();
        let bytes = ct.to_bytes();
        assert_eq!(bytes.len(), HYBRID_CIPHERTEXT_LEN);

        let ct2 = HybridCiphertext::from_bytes(&bytes).unwrap();
        let ss_recv = sk.decapsulate(&ct2).unwrap();
        assert_eq!(ss_send.as_bytes(), ss_recv.as_bytes());
    }

    #[test]
    fn hybrid_kem_rejects_wrong_size_bytes() {
        assert!(matches!(
            HybridKemPublic::from_bytes(&[0u8; 10]),
            Err(Error::BufferSize { .. })
        ));
        assert!(matches!(
            HybridCiphertext::from_bytes(&[0u8; 10]),
            Err(Error::BufferSize { .. })
        ));
    }

    #[test]
    fn hybrid_kem_size_constants() {
        // These match FIPS 203 Table 3 for ML-KEM-768 (K=3).
        assert_eq!(HYBRID_CLASSICAL_LEN, 32);
        assert_eq!(HYBRID_PQ_PUBLIC_LEN, 1184);
        assert_eq!(HYBRID_PQ_CIPHERTEXT_LEN, 1088);
        assert_eq!(HYBRID_PQ_SECRET_LEN, 2400);
        assert_eq!(HYBRID_PUBLIC_LEN, 1216);
        assert_eq!(HYBRID_CIPHERTEXT_LEN, 1120);
        assert_eq!(HYBRID_SECRET_LEN, 2432);
    }

    #[test]
    fn hybrid_pq_secret_len_matches_runtime() {
        // Catches a future ml-kem release that changes the encoded
        // size — the test asserts that our compile-time constant
        // matches what the crate actually produces.
        let sk = HybridKemSecret::generate();
        let bytes = sk.to_bytes();
        let pq_bytes = &bytes[HYBRID_CLASSICAL_LEN..];
        assert_eq!(pq_bytes.len(), HYBRID_PQ_SECRET_LEN);
    }

    #[test]
    fn hybrid_kem_secret_byte_round_trip() {
        let sk = HybridKemSecret::generate();
        let pk = sk.public();

        // Establish a baseline shared secret with the original.
        let (ct, ss_send) = pk.encapsulate().unwrap();
        let ss_orig = sk.decapsulate(&ct).unwrap();
        assert_eq!(ss_send.as_bytes(), ss_orig.as_bytes());

        // Round-trip the secret through bytes and re-decapsulate the
        // same ciphertext; we must recover the identical shared secret.
        let bytes = sk.to_bytes();
        assert_eq!(bytes.len(), HYBRID_SECRET_LEN);
        let sk2 = HybridKemSecret::from_bytes(&bytes).expect("round-trip");
        let ss_after = sk2.decapsulate(&ct).unwrap();
        assert_eq!(
            ss_after.as_bytes(),
            ss_orig.as_bytes(),
            "round-tripped secret must decapsulate to the same shared secret"
        );
        // The round-tripped secret should also produce an identical
        // public key (since both halves are derived deterministically).
        let pk2 = sk2.public();
        assert_eq!(pk.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn hybrid_kem_secret_rejects_wrong_size() {
        assert!(matches!(
            HybridKemSecret::from_bytes(&[0u8; 10]),
            Err(Error::BufferSize { .. })
        ));
        assert!(matches!(
            HybridKemSecret::from_bytes(&[0u8; HYBRID_SECRET_LEN - 1]),
            Err(Error::BufferSize { .. })
        ));
        assert!(matches!(
            HybridKemSecret::from_bytes(&[0u8; HYBRID_SECRET_LEN + 1]),
            Err(Error::BufferSize { .. })
        ));
    }

    #[test]
    fn ct_eq_matches_eq_for_equal_inputs() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];
        assert!(ct_eq(&a, &b));
        assert!(!ct_eq(&a, &c));
        // Different lengths must always be false.
        assert!(!ct_eq(&a, &[1, 2, 3]));
    }

    // ── helpers ────────────────────────────────────────────────────────────

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        decode_hex(s, &mut out);
        out
    }

    fn hex42(s: &str) -> [u8; 42] {
        let mut out = [0u8; 42];
        decode_hex(s, &mut out);
        out
    }

    /// Tiny hex decoder for test vectors. Ignores whitespace; panics on bad input.
    fn decode_hex(s: &str, out: &mut [u8]) {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(
            cleaned.len(),
            out.len() * 2,
            "hex literal length mismatch: got {}, expected {}",
            cleaned.len(),
            out.len() * 2,
        );
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16).expect("valid hex");
        }
    }
}
