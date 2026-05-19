//! Per-connection token-bucket rate limiter for the hub.
//!
//! ## What this defends against
//!
//! Before today the hub accepted DELIVER and KP_PUBLISH frames from
//! any authenticated client as fast as the wire could carry them.
//! That meant a single hostile (or buggy, or misconfigured) client
//! could:
//!
//!   * Saturate the hub's CPU / I/O with KeyPackage validation work
//!     (every KP_PUBLISH triggers a TLS-deserialise + MLS-validate
//!     in `handler.rs::FRAME_KP_PUBLISH` — non-trivial).
//!   * Fill the `queue_entry` table at line rate, racing T8.0.gc's
//!     30-day cutoff.
//!   * Starve other clients of hub attention via the shared `Mutex`
//!     on `HubState`.
//!
//! The fix is a standard token bucket per connection. Each bucket
//! refills at a fixed rate up to a cap; each DELIVER / KP_PUBLISH
//! frame consumes one token. Empty bucket → frame is silently
//! dropped (no error to the sender — matches the hub's existing
//! "fail closed, log loudly" posture for malformed frames).
//!
//! ## What this does NOT defend against
//!
//!   * **Coordinated attack from many connections.** Each connection
//!     gets its own bucket, so N attackers can sustain N × rate. The
//!     defence here is per-connection only; a global per-IP limit
//!     would need to know about IPs (we run behind Tor, so the IP is
//!     always 127.0.0.1 to the hub process — useless as a key).
//!     Adding a per-identity limit (keyed on the Noise XK
//!     authenticated pubkey) is a reasonable follow-up.
//!   * **Subscribe-storm attacks.** SUBSCRIBE frames are not rate-
//!     limited because they don't trigger heavy work (just a HashSet
//!     insert). If that turns out to be wrong, the limiter is
//!     trivially applied to SUBSCRIBE too.
//!   * **A slow-loris-style drip.** This limiter caps *peak* rate,
//!     not aggregate work. A connection that sends one DELIVER per
//!     second forever still adds 86 400 rows/day to `queue_entry`
//!     — bounded by the GC slice's 30-day cap, but not by this
//!     limiter. The two defences compose.
//!
//! ## Sizing
//!
//! Default `--max-frames-per-minute = 600` ≈ 10 frames/sec sustained,
//! with capacity = the same number (burst tolerance: ~1 minute of
//! held-up traffic delivered at once). For a normal client this is
//! never near the limit — a real chat session is maybe 1-2
//! frames/minute. For a misbehaving client this is enough to do real
//! work without monopolising the hub.

use std::collections::HashMap;
use std::time::Instant;

use crate::state::ConnId;

/// A classic token bucket. Tokens regenerate continuously at
/// `refill_per_sec` up to `capacity`. `try_consume()` returns `true`
/// iff a token was available + consumed.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    refill_per_sec: f64,
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// Build a bucket with the given capacity (= burst tolerance) and
    /// `refill_per_sec` (= sustained rate). Starts full.
    ///
    /// `capacity` and `refill_per_sec` are clamped to a minimum of
    /// `0.001` to avoid divide-by-zero in pathological configs; a
    /// fully-zero bucket would mean "drop everything" which is more
    /// usefully expressed as "don't install a rate limiter at all"
    /// (the operator opts out via the binary flag, not via this
    /// type).
    #[must_use]
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self::new_at(capacity, refill_per_sec, Instant::now())
    }

    /// Like [`Self::new`] but takes the starting time explicitly.
    /// Tests use this; production calls [`Self::new`].
    #[must_use]
    pub fn new_at(capacity: f64, refill_per_sec: f64, now: Instant) -> Self {
        let cap = capacity.max(0.001);
        let refill = refill_per_sec.max(0.001);
        Self {
            capacity: cap,
            refill_per_sec: refill,
            tokens: cap,
            last_refill: now,
        }
    }

    /// Try to consume one token. Returns `true` if a token was
    /// available (frame should be processed), `false` if the bucket
    /// was empty (frame should be dropped).
    pub fn try_consume(&mut self) -> bool {
        self.try_consume_at(Instant::now())
    }

    /// Like [`Self::try_consume`] but takes the current time
    /// explicitly. Tests use this.
    pub fn try_consume_at(&mut self, now: Instant) -> bool {
        let elapsed_secs = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed_secs * self.refill_per_sec).min(self.capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Current tokens (after applying any pending refill, computed
    /// lazily here so tests can observe state without burning a
    /// token). Returns the count rounded to one decimal for log
    /// readability.
    #[allow(dead_code)] // used by tests + future ops endpoints
    pub fn tokens_now(&self) -> f64 {
        let elapsed_secs = Instant::now()
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        (self.tokens + elapsed_secs * self.refill_per_sec).min(self.capacity)
    }
}

/// Per-connection bucket registry. Lives inside `HubState` so the
/// hub's existing `Mutex` serialises access. Keyed by `ConnId`.
///
/// Buckets are **lazily** instantiated on first frame from a
/// connection (avoids a default bucket per `register_conn` for
/// connections that never send DELIVER/KP_PUBLISH — e.g.,
/// subscribe-only clients). They're removed when the connection is
/// `unregister_conn`'d so the map doesn't leak entries across
/// disconnects.
#[derive(Debug, Default)]
pub struct RateLimiter {
    buckets: HashMap<ConnId, TokenBucket>,
    capacity: f64,
    refill_per_sec: f64,
}

impl RateLimiter {
    /// Build a rate limiter that hands every new connection a bucket
    /// of the given `frames_per_minute` cap. Refill is `cap / 60.0`
    /// tokens per second, capacity is the same `cap` (so a freshly-
    /// arrived connection can burst up to a minute's worth of frames
    /// before throttling kicks in).
    #[must_use]
    pub fn with_frames_per_minute(frames_per_minute: u32) -> Self {
        let cap = f64::from(frames_per_minute);
        Self {
            buckets: HashMap::new(),
            capacity: cap,
            refill_per_sec: cap / 60.0,
        }
    }

    /// Check whether `conn` has a token available; consume one if
    /// yes. Returns `true` if the caller should process the frame,
    /// `false` if it should be dropped.
    pub fn check(&mut self, conn: ConnId) -> bool {
        let bucket = self
            .buckets
            .entry(conn)
            .or_insert_with(|| TokenBucket::new(self.capacity, self.refill_per_sec));
        bucket.try_consume()
    }

    /// Drop the bucket for `conn` (called on connection teardown).
    pub fn forget(&mut self, conn: ConnId) {
        self.buckets.remove(&conn);
    }

    /// Number of connections that have at least one frame on record.
    /// Diagnostic.
    #[allow(dead_code)] // used by tests + future ops endpoints
    #[must_use]
    pub fn known_connections(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn bucket_starts_full_and_drains_one_per_call() {
        let mut b = TokenBucket::new(3.0, 1.0);
        // Three consumes succeed (capacity is 3 from start).
        assert!(b.try_consume());
        assert!(b.try_consume());
        assert!(b.try_consume());
        // Fourth fails — bucket is empty and no time has elapsed.
        assert!(!b.try_consume());
    }

    #[test]
    fn bucket_refills_over_time() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new_at(2.0, 1.0, t0); // 1 token/sec
        // Drain.
        assert!(b.try_consume_at(t0));
        assert!(b.try_consume_at(t0));
        assert!(!b.try_consume_at(t0));
        // Half a second later — still not enough for 1 token.
        assert!(!b.try_consume_at(t0 + Duration::from_millis(500)));
        // One full second after the LAST refill (which happened at
        // t0+500ms) — exactly one token added. Consume it.
        assert!(b.try_consume_at(t0 + Duration::from_millis(1500)));
        // Drained again.
        assert!(!b.try_consume_at(t0 + Duration::from_millis(1500)));
    }

    #[test]
    fn bucket_refill_capped_at_capacity() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new_at(2.0, 1.0, t0);
        // Drain.
        b.try_consume_at(t0);
        b.try_consume_at(t0);
        // Wait 100 seconds — would naively add 100 tokens, but cap=2.
        let t100 = t0 + Duration::from_secs(100);
        assert!(b.try_consume_at(t100));
        assert!(b.try_consume_at(t100));
        assert!(
            !b.try_consume_at(t100),
            "third call must fail — refill should have been capped"
        );
    }

    #[test]
    fn rate_limiter_isolates_connections() {
        let mut rl = RateLimiter::with_frames_per_minute(2);
        // Two distinct connections; each gets its own bucket.
        assert!(rl.check(1));
        assert!(rl.check(1));
        assert!(!rl.check(1), "conn 1 exhausted");
        // conn 2 still has full capacity.
        assert!(rl.check(2));
        assert!(rl.check(2));
        assert!(!rl.check(2), "conn 2 exhausted independently");
        assert_eq!(rl.known_connections(), 2);
    }

    #[test]
    fn rate_limiter_forget_removes_bucket() {
        let mut rl = RateLimiter::with_frames_per_minute(2);
        assert!(rl.check(7));
        assert!(rl.check(7));
        assert!(!rl.check(7));
        rl.forget(7);
        assert_eq!(rl.known_connections(), 0);
        // After forget, a new check creates a fresh full bucket.
        assert!(rl.check(7));
        assert!(rl.check(7));
        assert!(!rl.check(7));
    }

    #[test]
    fn rate_limiter_zero_capacity_clamps() {
        // Operators that try to set 0 in code (not via flag — flag
        // would mean "disable" at a different layer) should get a
        // floor that doesn't divide-by-zero.
        let _b = TokenBucket::new(0.0, 0.0); // must not panic
        let mut b = TokenBucket::new(0.0, 0.0);
        // Even with the floor, there's so little capacity that
        // try_consume must return false (we only had 0.001 tokens
        // total, can't subtract 1).
        assert!(!b.try_consume());
    }

    #[test]
    fn tokens_now_reflects_lazy_refill() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new_at(10.0, 2.0, t0);
        // Drain to half.
        for _ in 0..5 {
            b.try_consume_at(t0);
        }
        // tokens_now() observes (state is now 5 tokens, plus tiny
        // refill from real wall-clock between create + observe). At
        // least 4.9 + ~0 = 4.9 or so. We just check it's in [4, 10].
        let t = b.tokens_now();
        assert!(t >= 4.0, "tokens_now too low: {t}");
        assert!(t <= 10.0, "tokens_now exceeds capacity: {t}");
    }
}
