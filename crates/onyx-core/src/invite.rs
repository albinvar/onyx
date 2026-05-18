//! Invite URLs — `onyx://invite/v1?fp=…&kem=…`.
//!
//! A single shareable string that bundles everything a peer needs to
//! send a first-contact message to *us*:
//!
//!   * `fp`  — our [`Fingerprint`] (base32, no spaces).
//!   * `kem` — our hybrid (X25519 ‖ ML-KEM-768) KEM public key, base32.
//!
//! That's the same two pieces of data the user used to copy by hand
//! out of `onyx identity` before this module existed. Shipping them as
//! one URL means: copy once, paste once, peer runs `onyx accept <url>
//! --text "hi"` and the introduction is done.
//!
//! ## What this URL does **not** contain
//!
//!   * **No KeyPackage.** MLS-tier bootstraps (`SendBootstrapMls`)
//!     need a peer KP, which the recipient currently obtains via
//!     `onyx fetch-keypackage`. A `--with-kp` variant that bundles the
//!     KP into the URL is queued for a follow-up phase (ROADMAP).
//!   * **No hub address.** The accepting peer is assumed to already
//!     know which hub their daemon is configured against. Cross-hub
//!     invites are a separate design problem.
//!   * **No nickname.** Identity in Onyx is the fingerprint, full stop.
//!     A nickname would be a free-text label the *recipient* assigns
//!     locally; surfacing it in the URL would only enable spoofing.
//!
//! ## Security
//!
//! An invite URL is **public information by design** — it carries no
//! secrets. The fingerprint and KEM public key are exactly what `onyx
//! status` prints to stdout. Anyone holding the URL can send the named
//! identity a sealed-sender envelope; that's the *point*. Authentication
//! of *who* the recipient is is the user's responsibility — verify the
//! `fp` segment matches the fingerprint your peer told you out-of-band
//! (Signal, voice, in person) before trusting the channel.
//!
//! Forward-compat note: unknown query keys are ignored on parse so a
//! future `v1` invite carrying e.g. `&kp=…` still parses on today's
//! clients — they'll just fall through to the no-KP code path. A
//! version bump (`invite/v2`) is reserved for breaking changes.

use crate::crypto::Fingerprint;
use crate::error::{Error, Result};

const SCHEME: &str = "onyx://";
const PATH_V1: &str = "invite/v1";

/// A parsed or freshly-built invite. Construct via [`Invite::new`] for
/// the typical "bundle our identity" path, or via [`Invite::parse`] to
/// validate an incoming URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// The recipient's long-term Ed25519 fingerprint.
    pub fingerprint: Fingerprint,
    /// The recipient's hybrid KEM public key, base32 (RFC 4648 lower,
    /// no padding). Kept as a string because callers always pass it
    /// through to the wire format unmodified.
    pub kem_pub_b32: String,
}

impl Invite {
    /// Build an invite from the two pieces every sealed-sender bootstrap
    /// needs. Does **not** validate `kem_pub_b32` — that's the daemon's
    /// job when it tries to decode it as a hybrid KEM pubkey.
    #[must_use]
    pub fn new(fingerprint: Fingerprint, kem_pub_b32: String) -> Self {
        Self {
            fingerprint,
            kem_pub_b32,
        }
    }

    /// Serialize to `onyx://invite/v1?fp=…&kem=…`. The fingerprint
    /// loses its display-only space grouping; the round-trip via
    /// [`Fingerprint::parse`] recovers it.
    #[must_use]
    pub fn to_url(&self) -> String {
        format!(
            "{SCHEME}{PATH_V1}?fp={fp}&kem={kem}",
            fp = self.fingerprint.to_base32(),
            kem = self.kem_pub_b32,
        )
    }

    /// Parse an `onyx://invite/v1?…` URL. Unknown query keys are
    /// ignored for forward-compat; the v1 contract only requires
    /// `fp` and `kem`.
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
        for pair in query.split('&') {
            let (k, v) = pair
                .split_once('=')
                .ok_or(Error::InvalidEncoding("invite: malformed query pair"))?;
            match k {
                "fp" => fp = Some(v),
                "kem" => kem = Some(v),
                _ => {} // forward-compat: ignore unknown keys
            }
        }
        let fp = fp.ok_or(Error::InvalidEncoding("invite: missing fp parameter"))?;
        let kem = kem.ok_or(Error::InvalidEncoding("invite: missing kem parameter"))?;
        if kem.is_empty() {
            return Err(Error::InvalidEncoding("invite: empty kem parameter"));
        }
        let fingerprint = Fingerprint::parse(fp)?;
        Ok(Self {
            fingerprint,
            kem_pub_b32: kem.to_string(),
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
