//! Hub liveness telemetry — the deliberately-minimal, privacy-preserving
//! heartbeat a hub *may* (opt-in) report to a central collector.
//!
//! # Why this is safe
//!
//! Onyx hubs are blind relays: they see only sealed envelopes on
//! unlinkable per-epoch tokens. Any telemetry that left a hub and tracked
//! *user activity* — connection counts, frames delivered, subscriptions,
//! queue depth, keypackage-directory size, bandwidth — would, when sampled
//! repeatedly, form a **time series** that can be correlated against a
//! target's known online windows to deanonymize them. Bucketing the values
//! does not help: a *sequence* of buckets still reveals the shape of
//! activity over time.
//!
//! So this module reports **none of those**. A [`HubHeartbeat`] carries only
//! signals that are either static (software version), hub-self health (Tor
//! reachability), monotonic-and-activity-independent (a coarse uptime
//! bucket), or a coarsened timestamp. Every one of these is *already
//! publicly observable* for a listed public hub (anyone can connect to see
//! it is up and which version it runs; a restart is not user data). The
//! heartbeat therefore adds no new observable about users — it cannot be
//! reversed to an individual, time-series-correlated, or used to
//! deanonymize.
//!
//! **Do not add an activity-correlated field to [`HubHeartbeat`].** Doing so
//! silently breaks the guarantee above; the field set *is* the privacy
//! contract.
//!
//! # Transport & authentication (enforced by callers, not here)
//!
//! The hub reporter sends a [`SignedHeartbeat`] over Tor to the collector's
//! `.onion` (so the hub's IP is never exposed), signs it with the hub's
//! Ed25519 identity key, and the collector authorises by checking the
//! embedded verifying key against its own enrollment allowlist. This module
//! only defines the wire type and the cryptographic sign/verify; it performs
//! no I/O.

use serde::{Deserialize, Serialize};

use crate::crypto::{Signature, SigningKey, VerifyingKey};
use crate::error::{Error, Result};

/// Wire schema version for [`HubHeartbeat`]. Bump on any field change so a
/// collector can reject reports it does not understand.
pub const HEARTBEAT_SCHEMA: u8 = 1;

/// Self-reported timestamps are snapped down to this granularity (seconds)
/// so a heartbeat can never carry fine timing. 300 s = 5 minutes.
pub const COARSE_TS_SECS: u64 = 300;

/// Snap a unix-seconds timestamp down to the [`COARSE_TS_SECS`] boundary.
#[must_use]
pub fn coarse_ts(unix_secs: u64) -> u64 {
    unix_secs - (unix_secs % COARSE_TS_SECS)
}

/// Coarse uptime bucket. Reveals only that the hub has (or hasn't) recently
/// restarted, at hour/day/week resolution — never anything about users.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UptimeBucket {
    /// Up for less than one hour (recently (re)started).
    UnderHour,
    /// Up for at least an hour but less than a day.
    UnderDay,
    /// Up for at least a day but less than a week.
    UnderWeek,
    /// Up for a week or more.
    OverWeek,
}

impl UptimeBucket {
    /// Classify a raw uptime (seconds) into its coarse bucket.
    #[must_use]
    pub fn from_secs(secs: u64) -> Self {
        const HOUR: u64 = 3600;
        const DAY: u64 = 24 * HOUR;
        const WEEK: u64 = 7 * DAY;
        if secs < HOUR {
            Self::UnderHour
        } else if secs < DAY {
            Self::UnderDay
        } else if secs < WEEK {
            Self::UnderWeek
        } else {
            Self::OverWeek
        }
    }

    /// A short human label for dashboards.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnderHour => "<1h",
            Self::UnderDay => "<1d",
            Self::UnderWeek => "<1w",
            Self::OverWeek => ">1w",
        }
    }
}

/// The **complete** set of data a hub emits.
///
/// By construction it contains no counter that tracks user activity. See the
/// module docs for why every field here is safe and why nothing
/// activity-correlated may be added.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubHeartbeat {
    /// Wire schema version ([`HEARTBEAT_SCHEMA`]).
    pub schema: u8,
    /// The hub's public X25519 identity key (base32) — the same value
    /// published in `hubs.json`. Already public; used only as a friendly
    /// label so a dashboard can match a heartbeat to a listed hub.
    pub hub_id_b32: String,
    /// Onyx software version string, e.g. `"0.1.25"`.
    pub software_version: String,
    /// Always `true` — a heartbeat is only sent while the hub is up, so the
    /// *absence* of heartbeats is what signals "down". Kept explicit for
    /// dashboard clarity.
    pub up: bool,
    /// Whether the hub's onion service is currently reachable/published.
    pub tor_reachable: bool,
    /// Coarse uptime bucket.
    pub uptime: UptimeBucket,
    /// Unix seconds, snapped to [`COARSE_TS_SECS`]. Lets the collector dedupe
    /// and reject stale replays without the report carrying fine timing.
    pub coarse_ts: u64,
}

impl HubHeartbeat {
    /// Build a heartbeat from live values. `uptime_secs` and `now_unix_secs`
    /// are coarsened here so callers can pass raw values.
    #[must_use]
    pub fn new(
        hub_id_b32: impl Into<String>,
        software_version: impl Into<String>,
        tor_reachable: bool,
        uptime_secs: u64,
        now_unix_secs: u64,
    ) -> Self {
        Self {
            schema: HEARTBEAT_SCHEMA,
            hub_id_b32: hub_id_b32.into(),
            software_version: software_version.into(),
            up: true,
            tor_reachable,
            uptime: UptimeBucket::from_secs(uptime_secs),
            coarse_ts: coarse_ts(now_unix_secs),
        }
    }

    /// Deterministic CBOR bytes that the signature covers.
    fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out)
            .map_err(|_| Error::Internal("heartbeat CBOR encode failed"))?;
        Ok(out)
    }
}

/// A [`HubHeartbeat`] plus the hub's Ed25519 signature over it and the
/// verifying key needed to check it.
///
/// The collector **authenticates** a report by verifying the signature (see
/// [`SignedHeartbeat::verify`]) and **authorises** it by checking
/// `hub_sig_pub_b32` against its own allowlist of enrolled hub keys — the
/// latter is the collector's responsibility, not this type's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHeartbeat {
    /// The signed payload.
    pub heartbeat: HubHeartbeat,
    /// Ed25519 verifying key (base32) that produced `sig` — the hub's stable
    /// reporting identity, which the operator enrolls in the collector's
    /// allowlist.
    pub hub_sig_pub_b32: String,
    /// 64-byte Ed25519 signature over the heartbeat's signing bytes.
    pub sig: Vec<u8>,
}

impl SignedHeartbeat {
    /// Sign a heartbeat with the hub's Ed25519 signing key.
    pub fn sign(heartbeat: HubHeartbeat, signing: &SigningKey) -> Result<Self> {
        let sig = signing.sign(&heartbeat.signing_bytes()?);
        Ok(Self {
            heartbeat,
            hub_sig_pub_b32: base32::encode(
                base32::Alphabet::Rfc4648Lower { padding: false },
                &signing.verifying_key().to_bytes(),
            ),
            sig: sig.to_bytes().to_vec(),
        })
    }

    /// Serialize to CBOR for the wire.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out)
            .map_err(|_| Error::Internal("signed-heartbeat CBOR encode failed"))?;
        Ok(out)
    }

    /// Parse a CBOR-encoded signed heartbeat.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes)
            .map_err(|_| Error::InvalidEncoding("signed-heartbeat CBOR decode failed"))
    }

    /// Verify the embedded signature over the embedded heartbeat using the
    /// embedded verifying key.
    ///
    /// Returns `Ok(())` only when the signature is cryptographically valid.
    /// This proves the holder of `hub_sig_pub_b32` produced the report; it
    /// does **not** decide whether that key is *authorised* — the caller
    /// (collector) must check it against an enrollment allowlist.
    pub fn verify(&self) -> Result<()> {
        let key_bytes = base32::decode(
            base32::Alphabet::Rfc4648Lower { padding: false },
            &self.hub_sig_pub_b32,
        )
        .ok_or(Error::InvalidEncoding(
            "hub_sig_pub_b32 is not valid base32",
        ))?;
        let key_arr: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| Error::InvalidEncoding("hub_sig_pub_b32 must be 32 bytes"))?;
        let vk = VerifyingKey::from_bytes(key_arr)?;

        let sig_arr: [u8; 64] = self
            .sig
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidEncoding("signature must be 64 bytes"))?;
        let sig = Signature::from_bytes(sig_arr);

        vk.verify(&self.heartbeat.signing_bytes()?, &sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_heartbeat() -> HubHeartbeat {
        HubHeartbeat::new(
            "7xseki3556r4uyykmxmqx2tf6wuwmyfenfkjmivncikz77hoafiq",
            "0.1.25",
            true,
            90_000, // ~25h → UnderWeek
            1_700_000_123,
        )
    }

    #[test]
    fn coarse_ts_snaps_to_five_minute_boundary() {
        assert_eq!(coarse_ts(1_700_000_123), 1_700_000_100);
        assert_eq!(coarse_ts(1_700_000_100), 1_700_000_100);
        assert_eq!(coarse_ts(0), 0);
        // Never carries sub-COARSE_TS_SECS precision.
        for t in [1u64, 299, 300, 301, 599, 600] {
            assert_eq!(coarse_ts(t) % COARSE_TS_SECS, 0);
        }
    }

    #[test]
    fn uptime_buckets_are_coarse() {
        assert_eq!(UptimeBucket::from_secs(0), UptimeBucket::UnderHour);
        assert_eq!(UptimeBucket::from_secs(3599), UptimeBucket::UnderHour);
        assert_eq!(UptimeBucket::from_secs(3600), UptimeBucket::UnderDay);
        assert_eq!(UptimeBucket::from_secs(90_000), UptimeBucket::UnderWeek);
        assert_eq!(UptimeBucket::from_secs(7 * 86_400), UptimeBucket::OverWeek);
        assert_eq!(UptimeBucket::OverWeek.as_str(), ">1w");
    }

    #[test]
    fn new_coarsens_inputs() {
        let hb = sample_heartbeat();
        assert_eq!(hb.schema, HEARTBEAT_SCHEMA);
        assert!(hb.up);
        assert!(hb.tor_reachable);
        assert_eq!(hb.uptime, UptimeBucket::UnderWeek);
        // timestamp snapped, never the raw 1_700_000_123.
        assert_eq!(hb.coarse_ts, 1_700_000_100);
    }

    #[test]
    fn sign_then_verify_roundtrips_through_cbor() {
        let sk = SigningKey::generate();
        let signed = SignedHeartbeat::sign(sample_heartbeat(), &sk).unwrap();

        // The embedded key matches the signer.
        let expected_pub = base32::encode(
            base32::Alphabet::Rfc4648Lower { padding: false },
            &sk.verifying_key().to_bytes(),
        );
        assert_eq!(signed.hub_sig_pub_b32, expected_pub);

        let bytes = signed.to_cbor().unwrap();
        let parsed = SignedHeartbeat::from_cbor(&bytes).unwrap();
        assert_eq!(parsed, signed);
        parsed.verify().expect("valid signature must verify");
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let sk = SigningKey::generate();
        let mut signed = SignedHeartbeat::sign(sample_heartbeat(), &sk).unwrap();
        // Flip a field after signing.
        signed.heartbeat.tor_reachable = false;
        assert!(
            signed.verify().is_err(),
            "a modified heartbeat must not verify"
        );
    }

    #[test]
    fn wrong_key_fails_verification() {
        let sk = SigningKey::generate();
        let other = SigningKey::generate();
        let mut signed = SignedHeartbeat::sign(sample_heartbeat(), &sk).unwrap();
        // Swap in a different verifying key (impersonation attempt).
        signed.hub_sig_pub_b32 = base32::encode(
            base32::Alphabet::Rfc4648Lower { padding: false },
            &other.verifying_key().to_bytes(),
        );
        assert!(
            signed.verify().is_err(),
            "signature must not verify under a different key"
        );
    }

    #[test]
    fn malformed_signature_length_is_rejected() {
        let sk = SigningKey::generate();
        let mut signed = SignedHeartbeat::sign(sample_heartbeat(), &sk).unwrap();
        signed.sig.truncate(10);
        assert!(signed.verify().is_err());
    }
}
