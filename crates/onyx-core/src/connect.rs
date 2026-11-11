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

/// Length of a v3 onion address label (base32 of 35 bytes), without the
/// `.onion` suffix.
const ONION_V3_LABEL_LEN: usize = 56;

/// Is `target` a syntactically valid **v3 onion** dial target —
/// `<56 base32 chars>.onion`, optionally followed by `:<port>` (1–65535)?
///
/// Every dial target that originates outside the local operator's own
/// config (a pasted connect code, a `reply_onion` inside a received
/// Welcome, a value revived from the vault) MUST pass this before it is
/// handed to Tor. Arti will happily connect to a clearnet hostname
/// through an exit relay, so an unvalidated target let a remote party
/// make the daemon open — and endlessly re-open — exit connections to an
/// arbitrary host and port.
#[must_use]
pub fn is_valid_onion_target(target: &str) -> bool {
    let host = match target.rsplit_once(':') {
        Some((host, port)) => {
            if !port.parse::<u16>().is_ok_and(|p| p != 0) {
                return false;
            }
            host
        }
        None => target,
    };
    host.strip_suffix(".onion").is_some_and(|label| {
        label.len() == ONION_V3_LABEL_LEN
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    })
}

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
        if !is_valid_onion_target(&onion) {
            return Err("connect code `onion` is not a valid v3 .onion address".to_string());
        }
        let key_ok = base32::decode(
            base32::Alphabet::Rfc4648Lower { padding: false },
            &identity_pub_b32,
        )
        .is_some_and(|bytes| bytes.len() == 32);
        if !key_ok {
            return Err("connect code `id` is not a base32 X25519 public key".to_string());
        }
        Ok(Self {
            onion,
            identity_pub_b32,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION: &str = "gqaiiwjuhvryo477zdcmoeadae7v346pbzgdp7vzm6b32f66mmwhrbqd.onion";
    const KEY: &str = "bpkryicngcgr6wrsbztg6mey2ugx6dvii53jnrqavov3h36vpafa";

    #[test]
    fn url_roundtrips() {
        let c = ConnectCode::new(ONION, KEY);
        let parsed = ConnectCode::parse(&c.to_url()).expect("roundtrip parses");
        assert_eq!(parsed, c);
    }

    #[test]
    fn trims_surrounding_whitespace() {
        let url = format!("  onyx://connect/v1?onion={ONION}&id={KEY}\n");
        let parsed = ConnectCode::parse(&url).expect("trimmed parse");
        assert_eq!(parsed.onion, ONION);
        assert_eq!(parsed.identity_pub_b32, KEY);
    }

    #[test]
    fn rejects_wrong_scheme() {
        assert!(ConnectCode::parse("onyx://invite/v2?fp=x&kem=y").is_err());
        assert!(ConnectCode::parse("https://example.com").is_err());
    }

    #[test]
    fn rejects_missing_field() {
        assert!(ConnectCode::parse(&format!("onyx://connect/v1?onion={ONION}")).is_err());
        assert!(ConnectCode::parse(&format!("onyx://connect/v1?id={KEY}")).is_err());
        assert!(ConnectCode::parse(&format!("onyx://connect/v1?onion=&id={KEY}")).is_err());
    }

    /// A connect code must name a v3 onion: a clearnet host would be
    /// dialled through a Tor exit.
    #[test]
    fn rejects_non_onion_targets() {
        for bad in [
            "example.com",
            "example.com:443",
            "10.0.0.1:22",
            "a.onion",
            "GQAIIWJUHVRYO477ZDCMOEADAE7V346PBZGDP7VZM6B32F66MMWHRBQD.onion",
            "gqaiiwjuhvryo477zdcmoeadae7v346pbzgdp7vzm6b32f66mmwhrbqd.onion:0",
            "gqaiiwjuhvryo477zdcmoeadae7v346pbzgdp7vzm6b32f66mmwhrbqd.onion:99999",
            "gqaiiwjuhvryo477zdcmoeadae7v346pbzgdp7vzm6b32f66mmwhrbqd.onion.evil.com",
        ] {
            assert!(!is_valid_onion_target(bad), "{bad} must be rejected");
            assert!(
                ConnectCode::parse(&format!("onyx://connect/v1?onion={bad}&id={KEY}")).is_err()
            );
        }
        assert!(is_valid_onion_target(ONION));
        assert!(is_valid_onion_target(&format!("{ONION}:1")));
        // A malformed identity key is refused too.
        assert!(ConnectCode::parse(&format!("onyx://connect/v1?onion={ONION}&id=abc")).is_err());
    }
}
