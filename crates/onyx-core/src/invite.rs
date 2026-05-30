//! Invite URLs — `onyx://invite/v1?fp=…&kem=…[&kp=…]`.
//!
//! A single shareable string that bundles everything a peer needs to
//! send a first-contact message to *us*:
//!
//!   * `fp`  — our [`Fingerprint`] (base32, no spaces).
//!   * `kem` — our hybrid (X25519 ‖ ML-KEM-768) KEM public key, base32.
//!   * `kp`  — *optional* MLS KeyPackage, base64url (no padding). When
//!     present, [`Invite::is_mls_tier`] is `true` and the accepting
//!     peer should use the MLS-tier bootstrap (`SendBootstrapMls`)
//!     instead of the PFS-only msg/v1 path.
//!
//! That's the same two-or-three pieces of data the user used to copy
//! by hand out of `onyx identity` (+ `onyx fetch-keypackage`) before
//! this module existed. Shipping them as one URL means: copy once,
//! paste once, peer runs `onyx accept <url> --text "hi"` and the
//! introduction is done — *with full MLS PCS on first contact* if the
//! `kp` segment is present.
//!
//! ## What this URL does **not** contain
//!
//!   * **No hub address.** The accepting peer is assumed to already
//!     know which hub their daemon is configured against. Cross-hub
//!     invites are a separate design problem.
//!   * **No nickname.** Identity in Onyx is the fingerprint, full stop.
//!     A nickname would be a free-text label the *recipient* assigns
//!     locally; surfacing it in the URL would only enable spoofing.
//!
//! ## Encoding choice: base64url for `kp`
//!
//! The KP is a TLS-serialised MLS object — roughly 1.5–2 KB of opaque
//! bytes. Standard base64 uses `+`, `/`, and `=` which all need
//! percent-escaping inside a query string (and `+` is a footgun
//! because form-encoded URLs decode it as space). We use **base64url
//! with no padding** (RFC 4648 §5) instead — character set is
//! `[A-Za-z0-9_-]`, all URL-safe, no escaping needed. The conversion
//! to/from the standard-base64 form used by the existing
//! [`crate::api::ApiRequest::SendBootstrapMls`] / `FetchPeerKeyPackage`
//! wire types is done by [`Invite::kp_standard_b64`].
//!
//! ## Security
//!
//! An invite URL is **public information by design** — it carries no
//! secrets. The fingerprint, KEM public key, and KeyPackage are all
//! safe to publish. Anyone holding the URL can send the named
//! identity a sealed-sender envelope; that's the *point*.
//! Authentication of *who* the recipient is is the user's
//! responsibility — verify the `fp` segment matches the fingerprint
//! your peer told you out-of-band (Signal, voice, in person) before
//! trusting the channel.
//!
//! A KeyPackage is **single-use** in MLS: once the recipient consumes
//! it to join a group, it cannot be reused. Sharing the same invite
//! URL with two peers is fine for the `fp+kem` path (which has no
//! ratchet to consume) but only one of them can actually use the `kp`
//! to bootstrap an MLS group with the named identity — the second
//! will get a duplicate-init-key MLS rejection. Mint a fresh URL per
//! recipient if you care about both getting MLS-tier on first contact.
//!
//! Forward-compat note: unknown query keys are ignored on parse so a
//! future `v1` invite carrying e.g. `&hub=…` still parses on today's
//! clients — they'll just fall through to the no-hub code path. A
//! version bump (`invite/v2`) is reserved for breaking changes.

use base64::Engine;

use crate::crypto::{Fingerprint, Signature, SigningKey, VerifyingKey};
use crate::error::{Error, Result};

const SCHEME: &str = "onyx://";
const PATH_V1: &str = "invite/v1";
const PATH_V2: &str = "invite/v2";

/// T-2: domain-separation tag for v2 invite signatures. Bumped if the
/// canonical signing-bytes layout in [`Invite::canonical_signing_bytes`]
/// ever changes incompatibly. Prevents a signature minted in another
/// context (e.g. an envelope signature) from being misread as a valid
/// invite signature.
const SIGN_CONTEXT_V2: &[u8] = b"onyx/invite/v2";

/// T-2 NEW-2: hard ceiling on how far in the future a v2 invite's
/// `exp_ms` is allowed to be. `exp` is set by the inviter — without a
/// verifier-side clamp, a malicious sender can claim `exp = year 3000`
/// and use the invite forever. 90 days is plenty for any reasonable
/// invite + leaves room for time-zone slop and legitimately offline
/// recipients; anything beyond it is more likely a bug or an attack
/// than a real use case.
pub const MAX_INVITE_TTL_SECS: u64 = 90 * 86_400;

/// T-2: signature material attached to a v2 invite. Binds every other
/// field of the invite (fingerprint, KEM, optional KP, hubs, exp,
/// nonce) into a single Ed25519 signature by the inviter's identity
/// key, so an attacker who intercepts the invite URL on the side-
/// channel cannot tamper with *part* of it (swap the KEM or KP, splice
/// in different hubs) without invalidating the signature.
///
/// **What this does not solve (T-2 honest scope):** an attacker who
/// substitutes the **entire** invite (their own fingerprint + their own
/// keys + their own signature) is still indistinguishable on the
/// channel — first-contact MITM over an unauthenticated channel is
/// fundamental, mitigated by out-of-band fingerprint verification and
/// caught later by T-1 pinning if the substituted identity ever
/// re-appears as a key change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteSig {
    /// Wall-clock (unix-ms) at which this invite expires. Verifier
    /// rejects when `now_ms >= exp_ms` — limits how long a leaked
    /// invite stays usable.
    pub exp_ms: u64,
    /// 16 random bytes that make every signed blob unique even when
    /// the rest of the invite (fp, kem, kp, hubs, exp) is identical.
    /// Stateless verifier does not track nonces; one-time-use
    /// enforcement is future work.
    pub nonce: [u8; 16],
    /// Ed25519 signature by the inviter's identity signing key over
    /// [`Invite::canonical_signing_bytes`] for this `exp_ms` + `nonce`.
    pub sig: Signature,
}

/// A parsed or freshly-built invite. Construct via [`Invite::new`] for
/// the no-KP path, [`Invite::with_key_package`] to add an MLS KP, or
/// [`Invite::parse`] to validate an incoming URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// The recipient's long-term Ed25519 fingerprint.
    pub fingerprint: Fingerprint,
    /// The recipient's hybrid KEM public key, base32 (RFC 4648 lower,
    /// no padding). Kept as a string because callers always pass it
    /// through to the wire format unmodified.
    pub kem_pub_b32: String,
    /// *Optional* raw MLS KeyPackage bytes (TLS-serialised). When
    /// present, the URL was produced by `onyx invite --with-kp` and
    /// the accepting peer should use MLS-tier bootstrap.
    pub key_package: Option<Vec<u8>>,
    /// *Optional* list of hubs the recipient publishes to (T8.2+).
    /// Each entry is `onion:port,b32pubkey` — the same shape as the
    /// daemon's `--hub` flag. Empty list == legacy form (URL was
    /// produced before T8.2, or sender chose not to disclose).
    ///
    /// Used for transparency on the sender side: `onyx accept` shows
    /// the recipient's hubs so the user knows where their first-
    /// contact message will land. A future slice will let the sender
    /// auto-configure their daemon to fan out via the recipient's
    /// hubs; v1 just surfaces the list to stderr.
    pub hubs: Vec<String>,
    /// T-2: v2 signature material. `None` for an unsigned (v1) invite;
    /// `Some(_)` for a v2 invite produced by [`Invite::sign`] or parsed
    /// from an `onyx://invite/v2?...` URL. Callers should prefer signed
    /// invites — see [`Invite::sign`] / [`Invite::verify_signature`].
    pub signature: Option<InviteSig>,
}

impl Invite {
    /// Build an invite with no KeyPackage. Accepting peer will fall
    /// back to msg/v1 (per-message PFS only) sealed-sender bootstrap.
    #[must_use]
    pub fn new(fingerprint: Fingerprint, kem_pub_b32: String) -> Self {
        Self {
            fingerprint,
            kem_pub_b32,
            key_package: None,
            hubs: Vec::new(),
            signature: None,
        }
    }

    /// Build an MLS-tier invite carrying a fresh KeyPackage. Accepting
    /// peer will use `SendBootstrapMls` and the resulting MLS group
    /// has full post-compromise security on every application message.
    #[must_use]
    pub fn with_key_package(
        fingerprint: Fingerprint,
        kem_pub_b32: String,
        key_package: Vec<u8>,
    ) -> Self {
        Self {
            fingerprint,
            kem_pub_b32,
            key_package: Some(key_package),
            hubs: Vec::new(),
            signature: None,
        }
    }

    /// Builder: attach the recipient's hub list (T8.2+). Each entry
    /// must be `onion:port,b32pubkey` shape (same as the daemon's
    /// `--hub` flag). Empty entries / missing commas are rejected
    /// at parse time, not here — callers are trusted.
    #[must_use]
    pub fn with_hubs(mut self, hubs: Vec<String>) -> Self {
        self.hubs = hubs;
        self
    }

    /// Whether this invite carries an MLS KeyPackage (i.e. the
    /// accepting peer should use `SendBootstrapMls`).
    #[must_use]
    pub fn is_mls_tier(&self) -> bool {
        self.key_package.is_some()
    }

    /// Re-encode `key_package` as standard base64 — the format the
    /// daemon API (`SendBootstrapMls.peer_kp_b64`,
    /// `FetchPeerKeyPackageOk.kp_b64`) consumes. Returns `None` for
    /// no-KP invites.
    #[must_use]
    pub fn kp_standard_b64(&self) -> Option<String> {
        self.key_package
            .as_ref()
            .map(|b| base64::engine::general_purpose::STANDARD.encode(b))
    }

    /// Serialize to `onyx://invite/v1?fp=…&kem=…[&kp=…][&hub=…]…`.
    /// The fingerprint loses its display-only space grouping; the
    /// round-trip via [`Fingerprint::parse`] recovers it. The KP, if
    /// present, is base64url-encoded (no padding) so the URL needs no
    /// percent-escaping anywhere. The hub list (T8.2+) is emitted as
    /// one `&hub=<onion:port,b32pubkey>` per entry — repeating the
    /// query key rather than packing all hubs into a single value
    /// keeps the format trivially extensible and avoids inventing a
    /// new in-value delimiter (the `,` inside `onion:port,pubkey`
    /// already has meaning).
    #[must_use]
    pub fn to_url(&self) -> String {
        // T-2: signed invites land on the v2 path; unsigned stay on v1
        // for backward compat. The query schema is otherwise additive —
        // v2 just appends `exp`/`nonce`/`sig`.
        let path = if self.signature.is_some() {
            PATH_V2
        } else {
            PATH_V1
        };
        let mut url = format!(
            "{SCHEME}{path}?fp={fp}&kem={kem}",
            fp = self.fingerprint.to_base32(),
            kem = self.kem_pub_b32,
        );
        if let Some(kp) = &self.key_package {
            let kp_url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(kp);
            url.push_str("&kp=");
            url.push_str(&kp_url);
        }
        for hub in &self.hubs {
            url.push_str("&hub=");
            url.push_str(hub);
        }
        if let Some(s) = &self.signature {
            // exp is a decimal u64 (matches the rest of the wire — `exp`
            // is plain enough to read in a log); nonce + sig are
            // base64url-no-pad like `kp`.
            let nonce_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.nonce);
            let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.sig.to_bytes());
            url.push_str("&exp=");
            url.push_str(&s.exp_ms.to_string());
            url.push_str("&nonce=");
            url.push_str(&nonce_b64);
            url.push_str("&sig=");
            url.push_str(&sig_b64);
        }
        url
    }

    /// T-2: canonical bytes the v2 signature covers. The layout is
    /// length-prefixed so it round-trips bit-for-bit regardless of URL
    /// query-pair ordering — verifier and signer reconstruct the
    /// same bytes from the same logical Invite.
    ///
    /// Layout: `SIGN_CONTEXT_V2 ‖ fp(32) ‖ kem_len(u16BE) ‖ kem_bytes
    /// ‖ kp_len(u32BE) ‖ kp_bytes (empty if no KP) ‖ hubs_count(u16BE)
    /// ‖ for each hub: hub_len(u16BE) ‖ hub_bytes ‖ exp_ms(u64BE) ‖
    /// nonce(16)`.
    fn canonical_signing_bytes(&self, exp_ms: u64, nonce: &[u8; 16]) -> Vec<u8> {
        let kem_bytes = self.kem_pub_b32.as_bytes();
        let kp = self.key_package.as_deref().unwrap_or(&[]);
        let mut out = Vec::with_capacity(
            SIGN_CONTEXT_V2.len()
                + 32
                + 2
                + kem_bytes.len()
                + 4
                + kp.len()
                + 2
                + self.hubs.iter().map(|h| 2 + h.len()).sum::<usize>()
                + 8
                + 16,
        );
        out.extend_from_slice(SIGN_CONTEXT_V2);
        out.extend_from_slice(self.fingerprint.as_bytes());
        out.extend_from_slice(
            &u16::try_from(kem_bytes.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(kem_bytes);
        out.extend_from_slice(&u32::try_from(kp.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(kp);
        out.extend_from_slice(
            &u16::try_from(self.hubs.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        for hub in &self.hubs {
            let hb = hub.as_bytes();
            out.extend_from_slice(&u16::try_from(hb.len()).unwrap_or(u16::MAX).to_be_bytes());
            out.extend_from_slice(hb);
        }
        out.extend_from_slice(&exp_ms.to_be_bytes());
        out.extend_from_slice(nonce);
        out
    }

    /// T-2: sign this invite under the inviter's identity key,
    /// attaching the v2 `exp_ms` + `nonce` + signature. After this the
    /// invite will [`to_url`] as `onyx://invite/v2?…`.
    #[must_use]
    pub fn sign(mut self, signing: &SigningKey, exp_ms: u64, nonce: [u8; 16]) -> Self {
        let blob = self.canonical_signing_bytes(exp_ms, &nonce);
        let sig = signing.sign(&blob);
        self.signature = Some(InviteSig { exp_ms, nonce, sig });
        self
    }

    /// T-2: `true` if this invite carries a v2 signature. Acceptors
    /// MUST check this and call [`Invite::verify_signature`]; an
    /// unsigned (v1) invite still parses but offers no protection
    /// against the side-channel tampering described in [`InviteSig`].
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// T-2: verify the v2 signature against the embedded fingerprint
    /// AND check that the invite isn't expired. Returns `Ok(())` only
    /// when both pass.
    ///
    /// **The fingerprint IS the verifying key** ([`Fingerprint`] /
    /// `VerifyingKey` are the raw 32 bytes by design — see
    /// `crypto.rs`), so verification needs no out-of-band key.
    ///
    /// Errors: not signed, fingerprint not a valid Ed25519 point,
    /// signature doesn't verify, or expired (`now_ms >= exp_ms`).
    pub fn verify_signature(&self, now_ms: u64) -> Result<()> {
        let sig_info = self.signature.as_ref().ok_or(Error::InvalidEncoding(
            "invite: unsigned (v1) — caller must check is_signed() first",
        ))?;
        if now_ms >= sig_info.exp_ms {
            return Err(Error::InvalidEncoding("invite: expired"));
        }
        // NEW-2: verifier-side max-future clamp. `exp_ms` is set by the
        // inviter; without this a malicious sender can mint an invite
        // claiming `exp = year 3000` and use it forever. Bound is
        // [`MAX_INVITE_TTL_SECS`].
        let max_exp_ms = now_ms.saturating_add(MAX_INVITE_TTL_SECS.saturating_mul(1000));
        if sig_info.exp_ms > max_exp_ms {
            return Err(Error::InvalidEncoding(
                "invite: exp is further in the future than MAX_INVITE_TTL_SECS allows",
            ));
        }
        let vk = VerifyingKey::from_bytes(*self.fingerprint.as_bytes()).map_err(|_| {
            Error::InvalidEncoding("invite: fingerprint is not a valid Ed25519 key")
        })?;
        let blob = self.canonical_signing_bytes(sig_info.exp_ms, &sig_info.nonce);
        vk.verify(&blob, &sig_info.sig)
            .map_err(|_| Error::InvalidEncoding("invite: signature does not verify"))?;
        Ok(())
    }

    /// Parse an `onyx://invite/v1?…` or `onyx://invite/v2?…` URL.
    /// Unknown query keys are ignored for forward-compat; both
    /// versions require `fp` and `kem`. `kp` and `hub` are optional in
    /// both. v2 additionally **requires** `exp` + `nonce` + `sig`
    /// (T-2); their presence sets [`Invite::signature`] and callers
    /// MUST then call [`Invite::verify_signature`] before trusting the
    /// invite. v1 invites parse with `signature = None`; callers
    /// should treat them as MITM-vulnerable on the side-channel and
    /// either warn or refuse.
    ///
    /// **This function does NOT verify the v2 signature** — it just
    /// decodes the bytes. Verification needs the current wall-clock
    /// (to check expiry), so it's a separate explicit step the caller
    /// performs after parse.
    // The query-pair loop + every field's validation + the v2/v1
    // signature-section branch all live inline; splitting into per-key
    // helpers would just rename the work into one-line callers.
    #[allow(clippy::too_many_lines)]
    pub fn parse(s: &str) -> Result<Self> {
        let rest = s
            .strip_prefix(SCHEME)
            .ok_or(Error::InvalidEncoding("invite: missing onyx:// scheme"))?;
        // Try v2 first (signed); fall back to v1 (unsigned). Any other
        // path is an unsupported version.
        let (is_v2, rest) = if let Some(rest) = rest.strip_prefix(PATH_V2) {
            (true, rest)
        } else if let Some(rest) = rest.strip_prefix(PATH_V1) {
            (false, rest)
        } else {
            return Err(Error::InvalidEncoding(
                "invite: unsupported version (expected invite/v1 or invite/v2)",
            ));
        };
        let query = rest
            .strip_prefix('?')
            .ok_or(Error::InvalidEncoding("invite: missing query string"))?;

        let mut fp: Option<&str> = None;
        let mut kem: Option<&str> = None;
        let mut kp: Option<&str> = None;
        let mut hubs: Vec<String> = Vec::new();
        // T-2: v2 fields. Required only when the path is invite/v2.
        let mut exp: Option<&str> = None;
        let mut nonce: Option<&str> = None;
        let mut sig: Option<&str> = None;
        for pair in query.split('&') {
            let (k, v) = pair
                .split_once('=')
                .ok_or(Error::InvalidEncoding("invite: malformed query pair"))?;
            match k {
                "fp" => fp = Some(v),
                "kem" => kem = Some(v),
                "kp" => kp = Some(v),
                "hub" => {
                    // Validate shape here so a malformed entry fails
                    // parse instead of surfacing at "send to this
                    // hub" time. Format: `onion:port,b32pubkey`.
                    if v.is_empty() {
                        return Err(Error::InvalidEncoding("invite: empty hub parameter"));
                    }
                    let (onion, pubkey) = v.split_once(',').ok_or(Error::InvalidEncoding(
                        "invite: hub must be `onion:port,b32pubkey`",
                    ))?;
                    if onion.is_empty() || pubkey.is_empty() {
                        return Err(Error::InvalidEncoding(
                            "invite: hub onion or pubkey field is empty",
                        ));
                    }
                    hubs.push(v.to_string());
                }
                "exp" => exp = Some(v),
                "nonce" => nonce = Some(v),
                "sig" => sig = Some(v),
                _ => {} // forward-compat: ignore unknown keys
            }
        }
        let fp = fp.ok_or(Error::InvalidEncoding("invite: missing fp parameter"))?;
        let kem = kem.ok_or(Error::InvalidEncoding("invite: missing kem parameter"))?;
        if kem.is_empty() {
            return Err(Error::InvalidEncoding("invite: empty kem parameter"));
        }
        let fingerprint = Fingerprint::parse(fp)?;
        let key_package = match kp {
            Some("") => return Err(Error::InvalidEncoding("invite: empty kp parameter")),
            Some(kp_b64url) => Some(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(kp_b64url)
                    .map_err(|_| Error::InvalidEncoding("invite: kp not valid base64url"))?,
            ),
            None => None,
        };

        // T-2: v2 invites MUST carry exp + nonce + sig; v1 invites MUST
        // NOT (a v1 path with sig fields is suspicious — refuse rather
        // than silently dropping them, otherwise a downgrade attack
        // could strip the version and we'd silently accept it as v1).
        let signature = if is_v2 {
            let exp_str = exp.ok_or(Error::InvalidEncoding("invite v2: missing exp parameter"))?;
            let nonce_str =
                nonce.ok_or(Error::InvalidEncoding("invite v2: missing nonce parameter"))?;
            let sig_str = sig.ok_or(Error::InvalidEncoding("invite v2: missing sig parameter"))?;
            let exp_ms: u64 = exp_str
                .parse()
                .map_err(|_| Error::InvalidEncoding("invite v2: exp not a u64"))?;
            let nonce_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(nonce_str)
                .map_err(|_| Error::InvalidEncoding("invite v2: nonce not valid base64url"))?;
            let nonce_arr: [u8; 16] = nonce_bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidEncoding("invite v2: nonce must be 16 bytes"))?;
            let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(sig_str)
                .map_err(|_| Error::InvalidEncoding("invite v2: sig not valid base64url"))?;
            let sig_arr: [u8; 64] = sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidEncoding("invite v2: sig must be 64 bytes"))?;
            Some(InviteSig {
                exp_ms,
                nonce: nonce_arr,
                sig: Signature::from_bytes(sig_arr),
            })
        } else {
            if exp.is_some() || nonce.is_some() || sig.is_some() {
                return Err(Error::InvalidEncoding(
                    "invite v1: signature fields present on v1 path — refuse to silently \
                     downgrade (re-emit on invite/v2)",
                ));
            }
            None
        };

        Ok(Self {
            fingerprint,
            kem_pub_b32: kem.to_string(),
            key_package,
            hubs,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_fp() -> Fingerprint {
        // Deterministic 32-byte pattern so the encoded form is stable.
        let mut b = [0u8; 32];
        for (i, slot) in b.iter_mut().enumerate() {
            *slot = u8::try_from(i).expect("i < 32 fits in u8");
        }
        Fingerprint::from_bytes(b)
    }

    #[test]
    fn round_trip() {
        let inv = Invite::new(sample_fp(), "aaaabbbbcccc".to_string());
        let url = inv.to_url();
        assert!(url.starts_with("onyx://invite/v1?"));
        let parsed = Invite::parse(&url).expect("round-trip parse");
        assert_eq!(parsed, inv);
    }

    #[test]
    fn rejects_wrong_scheme() {
        let bad = "https://invite/v1?fp=x&kem=y";
        let err = Invite::parse(bad).unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(msg) if msg.contains("scheme")));
    }

    #[test]
    fn rejects_wrong_version() {
        let bad = "onyx://invite/v9?fp=x&kem=y";
        let err = Invite::parse(bad).unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(msg) if msg.contains("version")));
    }

    #[test]
    fn rejects_missing_query() {
        let err = Invite::parse("onyx://invite/v1").unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(msg) if msg.contains("query")));
    }

    #[test]
    fn rejects_missing_fp() {
        let inv = Invite::new(sample_fp(), "abcd".to_string());
        let url = inv.to_url();
        let without_fp = url.replace(&format!("fp={}&", sample_fp().to_base32()), "");
        let err = Invite::parse(&without_fp).unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(msg) if msg.contains("fp")));
    }

    #[test]
    fn rejects_missing_kem() {
        let url = format!("onyx://invite/v1?fp={}", sample_fp().to_base32());
        let err = Invite::parse(&url).unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(msg) if msg.contains("kem")));
    }

    #[test]
    fn rejects_empty_kem() {
        let url = format!("onyx://invite/v1?fp={}&kem=", sample_fp().to_base32());
        let err = Invite::parse(&url).unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(msg) if msg.contains("kem")));
    }

    #[test]
    fn rejects_bad_fp_base32() {
        // `!` is not a base32 character.
        let url = "onyx://invite/v1?fp=!!!!&kem=abcd";
        assert!(Invite::parse(url).is_err());
    }

    #[test]
    fn ignores_unknown_query_keys_forward_compat() {
        let url = format!(
            "onyx://invite/v1?fp={}&kem=abcd&future=xyz",
            sample_fp().to_base32()
        );
        let parsed = Invite::parse(&url).expect("unknown keys must be ignored");
        assert_eq!(parsed.fingerprint, sample_fp());
        assert_eq!(parsed.kem_pub_b32, "abcd");
        assert!(!parsed.is_mls_tier());
    }

    #[test]
    fn with_kp_round_trip() {
        let kp = vec![0xDEu8, 0xAD, 0xBE, 0xEF, 0xFA, 0xCE];
        let inv = Invite::with_key_package(sample_fp(), "abcd".to_string(), kp.clone());
        let url = inv.to_url();
        assert!(url.contains("&kp="));
        let parsed = Invite::parse(&url).expect("with-kp round-trip");
        assert!(parsed.is_mls_tier());
        assert_eq!(parsed.key_package.as_deref(), Some(kp.as_slice()));
        assert_eq!(parsed, inv);
    }

    #[test]
    fn kp_uses_url_safe_base64() {
        // Bytes that produce `+` and `/` in standard base64; the `kp`
        // query value must NOT contain either of those (which would
        // need percent-escaping) — base64url uses `-` and `_` instead.
        let kp = vec![0xFBu8, 0xFF, 0xBF, 0xFE, 0xFF, 0xFE];
        let inv = Invite::with_key_package(sample_fp(), "abcd".to_string(), kp);
        let url = inv.to_url();
        let kp_value = url.split("&kp=").nth(1).expect("kp= present in url");
        assert!(
            !kp_value.contains('+'),
            "kp value must not contain + ({kp_value})"
        );
        assert!(
            !kp_value.contains('/'),
            "kp value must not contain / ({kp_value})"
        );
        assert!(
            !kp_value.contains('='),
            "kp value must not contain = padding ({kp_value})"
        );
        // And it must still round-trip.
        let parsed = Invite::parse(&url).unwrap();
        assert_eq!(parsed, inv);
    }

    #[test]
    fn rejects_invalid_kp_base64() {
        let url = format!(
            "onyx://invite/v1?fp={}&kem=abcd&kp=!!!notbase64!!!",
            sample_fp().to_base32()
        );
        let err = Invite::parse(&url).unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(msg) if msg.contains("kp")));
    }

    #[test]
    fn rejects_empty_kp() {
        // `&kp=` (empty value) should be rejected — caller meant to
        // include a KP but the value is missing, that's not the same
        // as omitting the field entirely.
        let url = format!(
            "onyx://invite/v1?fp={}&kem=abcd&kp=",
            sample_fp().to_base32()
        );
        let err = Invite::parse(&url).unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(msg) if msg.contains("kp")));
    }

    #[test]
    fn kp_standard_b64_converts_from_url_safe() {
        // Bytes that diverge between standard and URL-safe base64.
        let kp = vec![0xFBu8, 0xFF, 0xBF];
        let inv = Invite::with_key_package(sample_fp(), "abcd".to_string(), kp.clone());
        let std = inv.kp_standard_b64().expect("kp present");
        // Standard base64 of [0xFB, 0xFF, 0xBF] is "+/+/".
        assert_eq!(std, "+/+/");
        // No-KP invite returns None.
        let bare = Invite::new(sample_fp(), "abcd".to_string());
        assert!(bare.kp_standard_b64().is_none());
    }

    #[test]
    fn parse_without_kp_back_compat() {
        // T7.2 URLs (no kp) must still parse cleanly on T7.2-mls
        // clients. Same v1 path, just no `kp` query param.
        let url = format!("onyx://invite/v1?fp={}&kem=abcd", sample_fp().to_base32());
        let parsed = Invite::parse(&url).expect("legacy no-kp URL parses");
        assert!(!parsed.is_mls_tier());
        assert!(parsed.key_package.is_none());
        assert!(parsed.hubs.is_empty(), "no hub keys → empty hubs Vec");
    }

    // ── T8.2: hubs in invite URL ──────────────────────────────────────

    #[test]
    fn with_hubs_round_trip_single() {
        let inv = Invite::new(sample_fp(), "abcd".to_string())
            .with_hubs(vec!["alice.onion:1,ALICEKEY".to_string()]);
        let url = inv.to_url();
        assert!(url.contains("&hub=alice.onion:1,ALICEKEY"));
        let parsed = Invite::parse(&url).expect("single-hub round-trip");
        assert_eq!(parsed.hubs, vec!["alice.onion:1,ALICEKEY".to_string()]);
        assert_eq!(parsed, inv);
    }

    #[test]
    fn with_hubs_round_trip_multiple() {
        let inv = Invite::new(sample_fp(), "abcd".to_string()).with_hubs(vec![
            "hub1.onion:1,KEY1".to_string(),
            "hub2.onion:1,KEY2".to_string(),
            "hub3.onion:1,KEY3".to_string(),
        ]);
        let url = inv.to_url();
        let parsed = Invite::parse(&url).expect("multi-hub round-trip");
        assert_eq!(parsed.hubs.len(), 3);
        assert_eq!(parsed.hubs, inv.hubs);
        // FIFO order preserved (matters for sender's fan-out priority).
        assert_eq!(parsed.hubs[0], "hub1.onion:1,KEY1");
        assert_eq!(parsed.hubs[2], "hub3.onion:1,KEY3");
    }

    #[test]
    fn parse_rejects_empty_hub_value() {
        let url = format!(
            "onyx://invite/v1?fp={}&kem=abcd&hub=",
            sample_fp().to_base32()
        );
        let err = Invite::parse(&url).unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(msg) if msg.contains("hub")));
    }

    #[test]
    fn parse_rejects_hub_without_comma() {
        let url = format!(
            "onyx://invite/v1?fp={}&kem=abcd&hub=onion-only-no-pubkey",
            sample_fp().to_base32()
        );
        let err = Invite::parse(&url).unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(msg) if msg.contains("hub")));
    }

    #[test]
    fn parse_rejects_hub_with_empty_field() {
        // Comma present but one side is empty.
        let url = format!(
            "onyx://invite/v1?fp={}&kem=abcd&hub=,JUSTPUBKEY",
            sample_fp().to_base32()
        );
        let err = Invite::parse(&url).unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(msg) if msg.contains("hub")));
    }

    #[test]
    fn hubs_combine_with_kp() {
        // Both query keys present; both round-trip.
        let inv = Invite::with_key_package(
            sample_fp(),
            "abcd".to_string(),
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        )
        .with_hubs(vec!["h.onion:1,K".to_string()]);
        let url = inv.to_url();
        let parsed = Invite::parse(&url).expect("kp+hubs round-trip");
        assert!(parsed.is_mls_tier());
        assert_eq!(parsed.hubs, vec!["h.onion:1,K".to_string()]);
        assert_eq!(parsed, inv);
    }

    #[test]
    fn legacy_no_hub_url_parses_on_new_client() {
        // Pre-T8.2 URLs (no &hub=) still parse cleanly. Back-compat
        // sanity — the new field defaults to empty Vec.
        let url = format!("onyx://invite/v1?fp={}&kem=abcd", sample_fp().to_base32());
        let parsed = Invite::parse(&url).expect("legacy URL parses");
        assert!(parsed.hubs.is_empty());
    }

    #[test]
    fn fingerprint_round_trip_recovers_grouped_display() {
        let inv = Invite::new(sample_fp(), "abcd".to_string());
        let url = inv.to_url();
        let parsed = Invite::parse(&url).unwrap();
        // The grouped Display form (what `onyx identity` shows) must
        // come back identically after round-trip.
        assert_eq!(parsed.fingerprint.to_string(), sample_fp().to_string(),);
    }

    // ── T-2: signed invites ───────────────────────────────────────────

    #[test]
    fn v2_signed_round_trip_and_verify() {
        // Use a real signing key so the fingerprint and verifying key
        // line up (Fingerprint = raw VerifyingKey bytes by design).
        let signing = SigningKey::generate();
        let fp = signing.verifying_key().fingerprint();
        let exp_ms: u64 = 2_000_000;
        let nonce = [0x42u8; 16];

        let inv = Invite::new(fp, "kemb32value".into()).sign(&signing, exp_ms, nonce);
        assert!(inv.is_signed());
        let url = inv.to_url();
        assert!(
            url.starts_with("onyx://invite/v2?"),
            "signed invites must emit on the v2 path: {url}"
        );

        let parsed = Invite::parse(&url).expect("v2 round-trip parse");
        assert_eq!(parsed, inv, "v2 round-trip must preserve every field");
        assert!(parsed.is_signed());

        // Verifies before expiry.
        parsed
            .verify_signature(exp_ms - 1)
            .expect("signature must verify before expiry");
        // Refuses at and past expiry.
        assert!(matches!(
            parsed.verify_signature(exp_ms),
            Err(Error::InvalidEncoding(_))
        ));
        assert!(matches!(
            parsed.verify_signature(exp_ms + 1),
            Err(Error::InvalidEncoding(_))
        ));
    }

    #[test]
    fn v2_signature_rejects_tampered_kem() {
        // Partial tampering — change a single field on the wire — must
        // be caught by the signature, which covers every field.
        let signing = SigningKey::generate();
        let fp = signing.verifying_key().fingerprint();
        let inv = Invite::new(fp, "originalkemvalue".into()).sign(&signing, 9_999_999, [1u8; 16]);
        let url = inv.to_url();
        let tampered = url.replace("kem=originalkemvalue", "kem=attackerkemvalue");
        let parsed = Invite::parse(&tampered).expect("tampered URL still parses");
        assert!(matches!(
            parsed.verify_signature(1),
            Err(Error::InvalidEncoding(_))
        ));
    }

    #[test]
    fn v2_signature_rejects_swapped_fingerprint() {
        // Swap the fingerprint to a different identity (still a valid
        // Ed25519 point so parse succeeds) — verification under the
        // new fingerprint must fail because the signature was made by
        // the original key.
        let signing_a = SigningKey::generate();
        let signing_b = SigningKey::generate();
        let fp_a = signing_a.verifying_key().fingerprint();
        let fp_b = signing_b.verifying_key().fingerprint();

        let inv = Invite::new(fp_a, "kemb32".into()).sign(&signing_a, 9_999_999, [0u8; 16]);
        let url = inv.to_url();
        let tampered = url.replace(&fp_a.to_base32(), &fp_b.to_base32());
        let parsed = Invite::parse(&tampered).expect("parse OK — fp_b is a valid key");
        assert!(matches!(
            parsed.verify_signature(1),
            Err(Error::InvalidEncoding(_))
        ));
    }

    #[test]
    fn v2_signature_rejects_tampered_hubs() {
        // The hub list is part of the signed blob — splicing in an
        // attacker-controlled hub must break verification.
        let signing = SigningKey::generate();
        let fp = signing.verifying_key().fingerprint();
        let inv = Invite::new(fp, "kemb32".into())
            .with_hubs(vec!["alice.onion:1,KEY1".into()])
            .sign(&signing, 9_999_999, [0xAB; 16]);
        let url = inv.to_url();
        let tampered = url.replace("hub=alice.onion:1,KEY1", "hub=attacker.onion:1,EVIL1");
        let parsed = Invite::parse(&tampered).expect("tampered URL still parses");
        assert!(matches!(
            parsed.verify_signature(1),
            Err(Error::InvalidEncoding(_))
        ));
    }

    #[test]
    fn v1_with_signature_fields_is_rejected_no_downgrade() {
        // Defense against a downgrade: someone rewrites the path from
        // invite/v2 to invite/v1 to skip verification. Silently
        // dropping the sig fields would let it through; we refuse.
        let fp = sample_fp().to_base32();
        let url = format!("onyx://invite/v1?fp={fp}&kem=k&sig=AAAA&exp=1&nonce=AAAA");
        let err = Invite::parse(&url).unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(_)));
    }

    #[test]
    fn v2_missing_sig_field_is_rejected() {
        // A v2 path MUST carry exp + nonce + sig — missing any → reject.
        let fp = sample_fp().to_base32();
        let url = format!("onyx://invite/v2?fp={fp}&kem=k");
        let err = Invite::parse(&url).unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(_)));
    }

    #[test]
    fn v2_exp_too_far_in_future_is_rejected() {
        // T-2 NEW-2: even a perfectly-valid signature is refused if
        // the inviter set `exp` further than MAX_INVITE_TTL_SECS in
        // the future. Without this, a malicious sender could mint an
        // invite claiming year-3000 expiry and have it stay valid
        // forever.
        let signing = SigningKey::generate();
        let fp = signing.verifying_key().fingerprint();
        // 200 days in ms — well past the 90-day cap.
        let now_ms: u64 = 1_700_000_000_000;
        let exp_ms: u64 = now_ms + 200 * 86_400 * 1000;
        let inv = Invite::new(fp, "k".into()).sign(&signing, exp_ms, [0u8; 16]);
        let parsed = Invite::parse(&inv.to_url()).expect("parse");
        let err = parsed
            .verify_signature(now_ms)
            .expect_err("verify must refuse exp beyond MAX_INVITE_TTL_SECS");
        // Sanity: the error message mentions the clamp by name (so
        // operators can tell this is the clamp tripping, not "expired").
        let msg = format!("{err}");
        assert!(
            msg.contains("future"),
            "error should mention 'future'-clamp: {msg}"
        );

        // And the same invite WITHIN the cap (60 days) verifies fine.
        let exp_ms_ok: u64 = now_ms + 60 * 86_400 * 1000;
        let inv_ok = Invite::new(signing.verifying_key().fingerprint(), "k".into())
            .sign(&signing, exp_ms_ok, [0u8; 16]);
        Invite::parse(&inv_ok.to_url())
            .unwrap()
            .verify_signature(now_ms)
            .expect("60-day invite must verify");
    }

    #[test]
    fn v2_malformed_sig_length_is_rejected() {
        // sig must decode to exactly 64 bytes.
        let signing = SigningKey::generate();
        let fp = signing.verifying_key().fingerprint();
        let inv = Invite::new(fp, "k".into()).sign(&signing, 9_999_999, [0u8; 16]);
        let url = inv.to_url();
        // Replace the full sig= base64 segment with too-short bytes.
        let tampered = {
            let sig_idx = url.find("&sig=").unwrap();
            let mut s = url[..sig_idx].to_string();
            s.push_str("&sig=AAAA"); // 3 bytes decoded
            s
        };
        let err = Invite::parse(&tampered).unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(_)));
    }
}
