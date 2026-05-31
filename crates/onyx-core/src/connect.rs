//! v0.1.16 connect code: the direct-dial bundle.
//!
//! A *connect code* is everything one peer needs to dial another
//! **directly** over Tor — their `.onion` address plus their X25519
//! identity public key. It is the hub-less counterpart to
//! [`crate::invite`] (which routes first contact through a hub).
//!
//! ## Why no signature
//!
//! Unlike a hub invite, a connect code carries no KeyPackage, hub list,
//! or expiry — just an address and an identity key. It is exchanged
//! out-of-band (QR, paste, in person), and the Noise XK handshake on
//! dial cryptographically verifies that the peer actually holds the
//! secret for `identity_pub_b32`. So a tampered code can't impersonate
//! anyone: the dial simply fails the handshake. (Out-of-band
//! fingerprint comparison remains the defence against a swapped *whole*
//! code, exactly as for invites.)
//!
//! ## Wire form
//!
//! `onyx://connect/v1?onion=<addr>&id=<identity_pub_b32>`

/// A peer's direct-dial coordinates: onion address + X25519 identity
/// public key (base32). Build one from your own
/// [`crate::api`]-surfaced onion + identity key and share it; parse a
/// peer's to dial them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectCode {
    /// The peer's hidden-service address (`<addr>.onion`, optionally
    /// `:port`). Dialled directly over Tor.
    pub onion: String,
    /// The peer's X25519 identity public key, base32 — the same value
    /// `onyx identity` prints as `identity_pub_b32`. Verified by Noise
    /// XK at dial time.
    pub identity_pub_b32: String,
}

impl ConnectCode {
    /// Construct a connect code from an onion address and a base32
    /// X25519 identity public key.
    #[must_use]
    pub fn new(onion: impl Into<String>, identity_pub_b32: impl Into<String>) -> Self {
        Self {
            onion: onion.into(),
            identity_pub_b32: identity_pub_b32.into(),
        }
    }

    /// Render as a shareable `onyx://connect/v1?…` URL.
    #[must_use]
    pub fn to_url(&self) -> String {
        format!(
            "onyx://connect/v1?onion={}&id={}",
            self.onion, self.identity_pub_b32
        )
    }

    /// Parse an `onyx://connect/v1?…` URL back into a [`ConnectCode`].
    ///
    /// Errors (as human-readable strings) when the scheme/version is
    /// wrong or either field is missing/empty. Whitespace around the
    /// whole string is trimmed first so a pasted code with a trailing
    /// newline still parses.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let query = s
            .strip_prefix("onyx://connect/v1?")
            .ok_or_else(|| "not an onyx://connect/v1 connect code".to_string())?;

        let mut onion: Option<String> = None;
        let mut id: Option<String> = None;
        for pair in query.split('&') {
            if let Some(v) = pair.strip_prefix("onion=") {
                onion = Some(v.to_string());
            } else if let Some(v) = pair.strip_prefix("id=") {
                id = Some(v.to_string());
            }
        }

        let onion = onion
            .filter(|v| !v.is_empty())
            .ok_or_else(|| "connect code is missing the `onion` field".to_string())?;
        let identity_pub_b32 = id
            .filter(|v| !v.is_empty())
            .ok_or_else(|| "connect code is missing the `id` field".to_string())?;
        Ok(Self {
            onion,
            identity_pub_b32,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_roundtrips() {
        let c = ConnectCode::new(
            "gqaiiwjuhvryo477zdcmoeadae7v346pbzgdp7vzm6b32f66mmwhrbqd.onion",
            "bpkryicngcgr6wrsbztg6mey2ugx6dvii53jnrqavov3h36vpafa",
        );
        let parsed = ConnectCode::parse(&c.to_url()).expect("roundtrip parses");
        assert_eq!(parsed, c);
    }

    #[test]
    fn trims_surrounding_whitespace() {
        let url = "  onyx://connect/v1?onion=a.onion&id=abc\n";
        let parsed = ConnectCode::parse(url).expect("trimmed parse");
        assert_eq!(parsed.onion, "a.onion");
        assert_eq!(parsed.identity_pub_b32, "abc");
    }

    #[test]
    fn rejects_wrong_scheme() {
        assert!(ConnectCode::parse("onyx://invite/v2?fp=x&kem=y").is_err());
        assert!(ConnectCode::parse("https://example.com").is_err());
    }

    #[test]
    fn rejects_missing_field() {
        assert!(ConnectCode::parse("onyx://connect/v1?onion=a.onion").is_err());
        assert!(ConnectCode::parse("onyx://connect/v1?id=abc").is_err());
        assert!(ConnectCode::parse("onyx://connect/v1?onion=&id=abc").is_err());
    }
}
