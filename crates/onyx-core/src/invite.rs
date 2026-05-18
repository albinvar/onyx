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

use crate::crypto::Fingerprint;
use crate::error::{Error, Result};

const SCHEME: &str = "onyx://";
const PATH_V1: &str = "invite/v1";

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
        }
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

    /// Serialize to `onyx://invite/v1?fp=…&kem=…[&kp=…]`. The
    /// fingerprint loses its display-only space grouping; the
    /// round-trip via [`Fingerprint::parse`] recovers it. The KP, if
    /// present, is base64url-encoded (no padding) so the URL needs no
    /// percent-escaping anywhere.
    #[must_use]
    pub fn to_url(&self) -> String {
        let mut url = format!(
            "{SCHEME}{PATH_V1}?fp={fp}&kem={kem}",
            fp = self.fingerprint.to_base32(),
            kem = self.kem_pub_b32,
        );
        if let Some(kp) = &self.key_package {
            let kp_url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(kp);
            url.push_str("&kp=");
            url.push_str(&kp_url);
        }
        url
    }

    /// Parse an `onyx://invite/v1?…` URL. Unknown query keys are
    /// ignored for forward-compat; the v1 contract only requires
    /// `fp` and `kem`. `kp` is optional and validated as base64url
    /// (no padding) bytes — its MLS structure is *not* validated here
    /// (the daemon does that on `SendBootstrapMls`).
    pub fn parse(s: &str) -> Result<Self> {
        let rest = s
            .strip_prefix(SCHEME)
            .ok_or(Error::InvalidEncoding("invite: missing onyx:// scheme"))?;
        let rest = rest.strip_prefix(PATH_V1).ok_or(Error::InvalidEncoding(
            "invite: unsupported version (expected invite/v1)",
        ))?;
        let query = rest
            .strip_prefix('?')
            .ok_or(Error::InvalidEncoding("invite: missing query string"))?;

        let mut fp: Option<&str> = None;
        let mut kem: Option<&str> = None;
        let mut kp: Option<&str> = None;
        for pair in query.split('&') {
            let (k, v) = pair
                .split_once('=')
                .ok_or(Error::InvalidEncoding("invite: malformed query pair"))?;
            match k {
                "fp" => fp = Some(v),
                "kem" => kem = Some(v),
                "kp" => kp = Some(v),
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
        Ok(Self {
            fingerprint,
            kem_pub_b32: kem.to_string(),
            key_package,
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
}
