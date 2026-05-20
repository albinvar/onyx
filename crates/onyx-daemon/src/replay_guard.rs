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
//! Hash function is BLAKE2b-128 over `target ‖ body` — the routing
//! id the envelope was delivered under, concatenated with the body
//! bytes — same primitive Onyx uses elsewhere for routing-id
//! derivation, `THREAT_MODEL.md` already trusts it. Scoping the hash
//! to the target (rather than body alone) means a recipient that
//! subscribes to several routing ids never falsely drops a genuinely
//! distinct delivery that happens to share body bytes across two of
//! its own targets.
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
//!     wrong recipient). Within a single recipient, replays are now
//!     scoped per delivery target (see `check_and_record`), so the
//!     same body re-delivered under a different one of our targets is
//!     judged as a distinct event rather than silently coalesced.
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

    /// Try to record the given envelope, scoped to the routing
    /// `target` it was delivered under. Returns `true` if this is the
    /// first time we've seen this `(target, body)` pair (caller should
    /// process), and `false` if it's a replay (caller should drop
    /// silently).
    ///
    /// Hash is BLAKE2b-128 over `target ‖ body`. Including the target
    /// matters because a recipient can subscribe to more than one
    /// routing id (introduction inbox + per-epoch session tokens): a
    /// genuinely distinct delivery that happens to share body bytes
    /// across two of our own targets must NOT be falsely dropped as a
    /// replay, and a hostile hub re-delivering one inbox's envelope
    /// under a different target is a distinct event we want to judge
    /// on its own merits. Dedup is therefore over what was actually
    /// delivered: the target prefix plus the body.
    pub fn check_and_record(&mut self, target: &[u8], body: &[u8]) -> bool {
        let hash = blake2b_128(&[target, body]);
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

    /// Serialise the current guard state to a flat byte buffer for
    /// vault persistence (T7.3-sec.2-persist). Format is intentionally
    /// minimal — fixed-size header + raw hashes in FIFO order — so it
    /// stays trivially audit-able:
    ///
    /// ```text
    ///   magic(4) = "ORG1"   // Onyx Replay Guard v1
    ///   capacity(u32 BE)
    ///   count(u32 BE)
    ///   hashes[count][16]   // oldest first
    /// ```
    ///
    /// The buffer is plaintext; the vault layer AEAD-seals it before
    /// writing to disk. Snapshots are idempotent (no entropy) so
    /// successive snapshots of an unchanged guard produce identical
    /// bytes — useful for "did anything change?" detection.
    #[must_use]
    pub fn snapshot(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.order.len() * 16);
        out.extend_from_slice(b"ORG1");
        out.extend_from_slice(
            &u32::try_from(self.capacity)
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(
            &u32::try_from(self.order.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for hash in &self.order {
            out.extend_from_slice(hash);
        }
        out
    }

    /// Restore a guard from a [`Self::snapshot`] buffer. Returns
    /// `Ok(guard)` on a well-formed buffer; returns `Err(())` on any
    /// parse failure (wrong magic, truncated, count exceeds capacity,
    /// trailing bytes). Callers should fall back to a fresh guard on
    /// `Err` rather than refusing to launch — losing the seen-set is
    /// a worse outcome than re-opening the restart window for one
    /// snapshot cycle.
    ///
    /// The `()` error type is deliberate: there is nothing a caller
    /// can do with the failure beyond "use the default guard" — we
    /// don't want to encourage retry loops or partial-recovery code.
    /// Diagnostic detail goes through `tracing` at the call site.
    #[allow(clippy::result_unit_err)]
    pub fn restore(bytes: &[u8]) -> std::result::Result<Self, ()> {
        if bytes.len() < 12 || &bytes[..4] != b"ORG1" {
            return Err(());
        }
        let capacity = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let count = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        let expected = 12usize
            .checked_add(count.checked_mul(16).ok_or(())?)
            .ok_or(())?;
        if bytes.len() != expected {
            return Err(());
        }
        if count > capacity {
            return Err(());
        }
        let mut g = Self::with_capacity(capacity.max(1));
        for i in 0..count {
            let start = 12 + i * 16;
            let mut h = [0u8; 16];
            h.copy_from_slice(&bytes[start..start + 16]);
            // Bypass check_and_record's BLAKE2b step — we're restoring
            // already-hashed entries. Insert directly; if the on-disk
            // snapshot contained a duplicate (shouldn't happen but
            // belt-and-braces), the HashSet collapses it and the
            // VecDeque ordering reflects whatever was on disk.
            if g.seen.insert(h) {
                g.order.push_back(h);
            }
        }
        Ok(g)
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
        assert!(g.check_and_record(b"t", body), "first sight must accept");
        assert!(
            !g.check_and_record(b"t", body),
            "exact replay must be rejected"
        );
    }

    #[test]
    fn distinct_bodies_independent() {
        let mut g = EnvelopeReplayGuard::with_capacity(8);
        assert!(g.check_and_record(b"t", b"envelope A"));
        assert!(g.check_and_record(b"t", b"envelope B"));
        assert!(g.check_and_record(b"t", b"envelope C"));
        assert_eq!(g.len(), 3);
        // Replay A → reject; B and C still in the set.
        assert!(!g.check_and_record(b"t", b"envelope A"));
        assert_eq!(g.len(), 3);
    }

    #[test]
    fn fifo_eviction_drops_oldest_at_capacity() {
        let mut g = EnvelopeReplayGuard::with_capacity(3);
        assert!(g.check_and_record(b"t", b"1"));
        assert!(g.check_and_record(b"t", b"2"));
        assert!(g.check_and_record(b"t", b"3"));
        assert_eq!(g.len(), 3);
        // Fourth pushes the oldest ("1") out. State: {2, 3, 4}.
        assert!(g.check_and_record(b"t", b"4"));
        assert_eq!(g.len(), 3, "still capped");
        // "2", "3", "4" are still in the set.
        assert!(!g.check_and_record(b"t", b"2"));
        assert!(!g.check_and_record(b"t", b"3"));
        assert!(!g.check_and_record(b"t", b"4"));
        // But "1" is forgotten — re-seeing it counts as first sight
        // (eviction window exposed; documented in module rustdoc).
        // This is also the moment "2" gets evicted to make room.
        assert!(
            g.check_and_record(b"t", b"1"),
            "after FIFO eviction, oldest entry is forgotten"
        );
        // State now: {3, 4, 1}.
        assert!(
            g.check_and_record(b"t", b"2"),
            "the next-oldest entry has now been evicted too"
        );
    }

    #[test]
    fn replay_does_not_refresh_position() {
        // Critical: an attacker who keeps replaying an old entry
        // must NOT be able to keep it alive past the FIFO window.
        // If we re-ranked on replay (LRU semantics), they could.
        let mut g = EnvelopeReplayGuard::with_capacity(3);
        g.check_and_record(b"t", b"target"); // position: oldest
        g.check_and_record(b"t", b"fill1");
        g.check_and_record(b"t", b"fill2");
        // Attacker replays "target" repeatedly:
        for _ in 0..10 {
            assert!(!g.check_and_record(b"t", b"target"));
        }
        // A genuine new entry should evict "target" because replay
        // didn't refresh its position.
        g.check_and_record(b"t", b"new");
        assert!(
            g.check_and_record(b"t", b"target"),
            "after eviction, target is forgotten — replay never refreshed position"
        );
    }

    #[test]
    fn zero_capacity_clamps_to_one() {
        let mut g = EnvelopeReplayGuard::with_capacity(0);
        assert_eq!(g.capacity(), 1, "zero clamped to 1");
        assert!(g.check_and_record(b"t", b"a"));
        assert!(g.check_and_record(b"t", b"b")); // evicts "a"
        // "a" forgotten:
        assert!(g.check_and_record(b"t", b"a"));
    }

    #[test]
    fn hashing_is_collision_resistant_in_practice() {
        // We rely on BLAKE2b-128 to never collide on honest inputs.
        // Sanity: two near-identical inputs hash to different values
        // (a one-bit flip changes ~half the output bits).
        let mut g = EnvelopeReplayGuard::with_capacity(8);
        let body_a = b"sealed envelope bytes \x00";
        let body_b = b"sealed envelope bytes \x01";
        assert!(g.check_and_record(b"t", body_a));
        assert!(
            g.check_and_record(b"t", body_b),
            "one-byte difference must not collide"
        );
    }

    #[test]
    fn same_body_under_distinct_targets_both_accepted() {
        // The target-scoping property (MEDIUM fix): a recipient
        // subscribed to two routing ids that receives the SAME body
        // bytes under each must accept both — they're distinct
        // deliveries, not a replay. Body-only hashing would have
        // falsely dropped the second.
        let mut g = EnvelopeReplayGuard::with_capacity(8);
        assert!(g.check_and_record(b"target-A", b"identical body"));
        assert!(
            g.check_and_record(b"target-B", b"identical body"),
            "same body under a different target is a distinct delivery"
        );
        // But a true replay (same target AND body) is still dropped.
        assert!(!g.check_and_record(b"target-A", b"identical body"));
        assert!(!g.check_and_record(b"target-B", b"identical body"));
    }

    #[test]
    fn empty_body_handled() {
        // Edge case: a hub that delivers a zero-byte body. The
        // sealed envelope decode will reject downstream; here we
        // only care that the guard handles the input without panic.
        let mut g = EnvelopeReplayGuard::with_capacity(4);
        assert!(g.check_and_record(b"t", b""));
        assert!(!g.check_and_record(b"t", b""), "even empty bodies dedup");
    }

    #[test]
    fn snapshot_then_restore_preserves_seen_set() {
        let mut original = EnvelopeReplayGuard::with_capacity(8);
        original.check_and_record(b"t", b"alpha");
        original.check_and_record(b"t", b"beta");
        original.check_and_record(b"t", b"gamma");
        let snap = original.snapshot();

        let restored = EnvelopeReplayGuard::restore(&snap).expect("snapshot must round-trip");
        assert_eq!(restored.capacity(), 8);
        assert_eq!(restored.len(), 3);

        // Hashes that *were* in the original are still rejected:
        let mut restored = restored;
        assert!(!restored.check_and_record(b"t", b"alpha"));
        assert!(!restored.check_and_record(b"t", b"beta"));
        assert!(!restored.check_and_record(b"t", b"gamma"));
        // A new hash is accepted:
        assert!(restored.check_and_record(b"t", b"delta"));
    }

    #[test]
    fn snapshot_empty_guard_round_trips() {
        let g = EnvelopeReplayGuard::with_capacity(4);
        let snap = g.snapshot();
        let restored = EnvelopeReplayGuard::restore(&snap).unwrap();
        assert_eq!(restored.capacity(), 4);
        assert!(restored.is_empty());
    }

    #[test]
    fn snapshot_preserves_fifo_order_for_eviction() {
        // Order matters: restoring must put the oldest hashes at the
        // FIFO front so they evict first when new entries arrive.
        let mut g = EnvelopeReplayGuard::with_capacity(3);
        g.check_and_record(b"t", b"oldest");
        g.check_and_record(b"t", b"middle");
        g.check_and_record(b"t", b"newest");
        let snap = g.snapshot();

        let mut restored = EnvelopeReplayGuard::restore(&snap).unwrap();
        // Insert one new entry. The oldest should evict first, not
        // the newest — same as if we'd never snapshotted.
        // State before: [oldest, middle, newest]
        // After "fourth": [middle, newest, fourth] (oldest evicted)
        restored.check_and_record(b"t", b"fourth");
        assert!(
            !restored.check_and_record(b"t", b"middle"),
            "middle survived (one slot back)"
        );
        assert!(
            !restored.check_and_record(b"t", b"newest"),
            "newest survived (two slots back)"
        );
        assert!(
            !restored.check_and_record(b"t", b"fourth"),
            "fourth survived (just added)"
        );
        assert!(
            restored.check_and_record(b"t", b"oldest"),
            "oldest must have been evicted — first-sight again"
        );
    }

    #[test]
    fn restore_rejects_wrong_magic() {
        // Different magic word → not our snapshot.
        let bad = b"XXXX\x00\x00\x00\x08\x00\x00\x00\x00".to_vec();
        assert!(EnvelopeReplayGuard::restore(&bad).is_err());
    }

    #[test]
    fn restore_rejects_truncated() {
        let g = {
            let mut g = EnvelopeReplayGuard::with_capacity(8);
            g.check_and_record(b"t", b"a");
            g.check_and_record(b"t", b"b");
            g
        };
        let snap = g.snapshot();
        // Lop off the last 5 bytes — count claims 2 entries but body
        // only has space for ~1.7.
        let truncated = &snap[..snap.len() - 5];
        assert!(EnvelopeReplayGuard::restore(truncated).is_err());
    }

    #[test]
    fn restore_rejects_count_exceeding_capacity() {
        // Hand-craft a snapshot claiming count > capacity.
        let mut bad = Vec::new();
        bad.extend_from_slice(b"ORG1");
        bad.extend_from_slice(&4u32.to_be_bytes()); // capacity = 4
        bad.extend_from_slice(&10u32.to_be_bytes()); // count = 10 (impossible)
        bad.extend_from_slice(&[0u8; 16 * 10]);
        assert!(EnvelopeReplayGuard::restore(&bad).is_err());
    }

    #[test]
    fn snapshot_is_deterministic_when_state_unchanged() {
        // Two snapshots of the same guard state produce identical
        // bytes. Lets the daemon skip a vault write if nothing has
        // changed since the last snapshot (efficiency, not security).
        let mut g = EnvelopeReplayGuard::with_capacity(4);
        g.check_and_record(b"t", b"a");
        g.check_and_record(b"t", b"b");
        let s1 = g.snapshot();
        let s2 = g.snapshot();
        assert_eq!(s1, s2);
    }
}
