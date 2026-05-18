//! Recipient-side replay defence for hub-delivered envelopes (T7.3-sec.2).
//!
//! ## What this defends against
//!
//! A hostile (or compromised, or curious) hub can replay any
//! sealed-sender envelope it has previously seen by re-sending the
//! same DELIVER frame to the same subscriber. The ciphertext is
//! still valid — the ephemeral hybrid keys baked into the envelope
//! haven't expired — so `open_bootstrap` succeeds, the inner
//! [`BootstrapPayload`] decodes, and the recipient surfaces a
//! duplicate `EventMessage` to the CLI/TUI. From the user's
//! perspective: alice "sent" the same message twice; from the
//! attacker's perspective: a free disinformation primitive.
//!
//! [`EnvelopeReplayGuard`] closes this by maintaining a bounded
//! FIFO of envelope hashes the recipient has already accepted.
//! Hash function is BLAKE2b-128 over the raw body bytes the hub
//! delivered (after the 16-byte routing-id prefix is stripped) —
//! same primitive Onyx uses elsewhere for routing-id derivation,
//! `THREAT_MODEL.md` already trusts it.
//!
//! ## What this does NOT defend against
//!
//!   * **Replays across a daemon restart.** The guard's seen-set is
//!     in-memory only. If the daemon restarts, the set is empty and
//!     the first 5–10 minutes of a hostile hub's replay attempts
//!     succeed. Persistence would push this into the vault; tracked
//!     as a separate item.
//!   * **First-contact replays the *sender* wants you to see.** If
//!     alice sends bob the *same* envelope twice (re-send because no
//!     ack), the guard collapses them into one. That's the right
//!     call — sealed-sender envelopes carry no sequence number, so
//!     "alice retransmits" and "hub replays" are indistinguishable
//!     to bob. If alice wants to re-send, she should construct a
//!     fresh envelope (her daemon does this automatically because
//!     each call to `seal_bootstrap` mints fresh ephemeral keys, so
//!     the envelope bytes differ).
//!   * **Cross-recipient replay tracking.** This is purely a
//!     per-recipient cache. A hub that holds an envelope and delivers
//!     it to a *different* subscriber later is a separate problem
//!     (mostly mitigated by the recipient KEM decryption failing —
//!     wrong recipient — but worth a future audit).
//!
//! ## Sizing
//!
//! The default capacity is `DEFAULT_CAPACITY = 4096`. Each entry
//! holds a 16-byte hash, so the set costs ~64 KB at full occupancy
//! (HashMap overhead included). At Onyx's expected first-contact
//! rate that's *months* of unique envelopes before FIFO eviction
//! starts to expire entries; even under denial-of-service spam, an
//! attacker would need to deliver 4096 *unique* valid envelopes to
//! push a real one out of the window — costly enough to flag.

use std::collections::{HashSet, VecDeque};

use onyx_core::crypto::blake2b_128;

/// Default number of envelope hashes to remember. ~64 KB of state.
pub const DEFAULT_CAPACITY: usize = 4096;

/// Bounded FIFO seen-set of envelope-body hashes. `insert` is the
/// only mutating operation; it returns `true` on first sight and
/// `false` on replay so the caller can drop the duplicate.
///
/// Capacity is fixed at construction. Once full, the oldest entry
/// is evicted before each new insert (true FIFO; not LRU — we don't
/// re-rank on hit because a hit is a *rejection*, not an accept).
#[derive(Debug)]
pub struct EnvelopeReplayGuard {
    seen: HashSet<[u8; 16]>,
    order: VecDeque<[u8; 16]>,
    capacity: usize,
}

impl EnvelopeReplayGuard {
    /// Construct a guard with the given capacity. Capacity of 0 is
    /// clamped to 1 (a guard that can't remember anything is a bug,
    /// not a use case).
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            seen: HashSet::with_capacity(cap),
            order: VecDeque::with_capacity(cap),
            capacity: cap,
        }
    }

    /// Convenience: build with [`DEFAULT_CAPACITY`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Try to record the given envelope body. Returns `true` if this
    /// is the first time we've seen it (caller should process), and
    /// `false` if it's a replay (caller should drop silently).
    ///
    /// Hash is BLAKE2b-128 over the raw `body` bytes — the same body
    /// the recipient would pass to `open_bootstrap`. Caller does NOT
    /// need to strip any prefix; the body the hub delivers is already
    /// post-routing-id (the daemon's hub-client splits it).
    pub fn check_and_record(&mut self, body: &[u8]) -> bool {
        let hash = blake2b_128(&[body]);
        if !self.seen.insert(hash) {
            // Already in the set; we deliberately do NOT re-rank
            // (replay shouldn't refresh the FIFO position — that
            // would let an attacker keep a real entry alive by
            // replaying it).
            return false;
        }
        self.order.push_back(hash);
        // Evict oldest while over capacity. Usually one iteration;
        // the loop guards against capacity changing across calls.
        while self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }

    /// Current number of remembered envelopes (≤ capacity).
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Capacity the guard was constructed with.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Whether the guard remembers nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl Default for EnvelopeReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sight_returns_true_replay_returns_false() {
        let mut g = EnvelopeReplayGuard::with_capacity(8);
        let body = b"sealed envelope bytes";
        assert!(g.check_and_record(body), "first sight must accept");
        assert!(!g.check_and_record(body), "exact replay must be rejected");
    }

    #[test]
    fn distinct_bodies_independent() {
        let mut g = EnvelopeReplayGuard::with_capacity(8);
        assert!(g.check_and_record(b"envelope A"));
        assert!(g.check_and_record(b"envelope B"));
        assert!(g.check_and_record(b"envelope C"));
        assert_eq!(g.len(), 3);
        // Replay A → reject; B and C still in the set.
        assert!(!g.check_and_record(b"envelope A"));
        assert_eq!(g.len(), 3);
    }

    #[test]
    fn fifo_eviction_drops_oldest_at_capacity() {
        let mut g = EnvelopeReplayGuard::with_capacity(3);
        assert!(g.check_and_record(b"1"));
        assert!(g.check_and_record(b"2"));
        assert!(g.check_and_record(b"3"));
        assert_eq!(g.len(), 3);
        // Fourth pushes the oldest ("1") out. State: {2, 3, 4}.
        assert!(g.check_and_record(b"4"));
        assert_eq!(g.len(), 3, "still capped");
        // "2", "3", "4" are still in the set.
        assert!(!g.check_and_record(b"2"));
        assert!(!g.check_and_record(b"3"));
        assert!(!g.check_and_record(b"4"));
        // But "1" is forgotten — re-seeing it counts as first sight
        // (eviction window exposed; documented in module rustdoc).
        // This is also the moment "2" gets evicted to make room.
        assert!(
            g.check_and_record(b"1"),
            "after FIFO eviction, oldest entry is forgotten"
        );
        // State now: {3, 4, 1}.
        assert!(
            g.check_and_record(b"2"),
            "the next-oldest entry has now been evicted too"
        );
    }

    #[test]
    fn replay_does_not_refresh_position() {
        // Critical: an attacker who keeps replaying an old entry
        // must NOT be able to keep it alive past the FIFO window.
        // If we re-ranked on replay (LRU semantics), they could.
        let mut g = EnvelopeReplayGuard::with_capacity(3);
        g.check_and_record(b"target"); // position: oldest
        g.check_and_record(b"fill1");
        g.check_and_record(b"fill2");
        // Attacker replays "target" repeatedly:
        for _ in 0..10 {
            assert!(!g.check_and_record(b"target"));
        }
        // A genuine new entry should evict "target" because replay
        // didn't refresh its position.
        g.check_and_record(b"new");
        assert!(
            g.check_and_record(b"target"),
            "after eviction, target is forgotten — replay never refreshed position"
        );
    }

    #[test]
    fn zero_capacity_clamps_to_one() {
        let mut g = EnvelopeReplayGuard::with_capacity(0);
        assert_eq!(g.capacity(), 1, "zero clamped to 1");
        assert!(g.check_and_record(b"a"));
        assert!(g.check_and_record(b"b")); // evicts "a"
        // "a" forgotten:
        assert!(g.check_and_record(b"a"));
    }

    #[test]
    fn hashing_is_collision_resistant_in_practice() {
        // We rely on BLAKE2b-128 to never collide on honest inputs.
        // Sanity: two near-identical inputs hash to different values
        // (a one-bit flip changes ~half the output bits).
        let mut g = EnvelopeReplayGuard::with_capacity(8);
        let body_a = b"sealed envelope bytes \x00";
        let body_b = b"sealed envelope bytes \x01";
        assert!(g.check_and_record(body_a));
        assert!(
            g.check_and_record(body_b),
            "one-byte difference must not collide"
        );
    }

    #[test]
    fn empty_body_handled() {
        // Edge case: a hub that delivers a zero-byte body. The
        // sealed envelope decode will reject downstream; here we
        // only care that the guard handles the input without panic.
        let mut g = EnvelopeReplayGuard::with_capacity(4);
        assert!(g.check_and_record(b""));
        assert!(!g.check_and_record(b""), "even empty bodies dedup");
    }
}
