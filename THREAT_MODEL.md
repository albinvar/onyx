# Onyx — Threat Model

**Version:** 0.2-draft (mirrors `DESIGN.md` §2 + §5.5 residual analysis)
**Audience:** users deciding whether Onyx fits their threat model, reviewers, future maintainers

Security is a relationship between a defense and an attacker, not a property a system "has." This document names the attackers Onyx defends against, the attackers it does not, the specific assets it protects, and the residual linkability it cannot eliminate.

If you need a property listed under "do not defend against," **Onyx is not the right tool for your situation.** That answer is more useful than a vague claim of safety.

---

## 1. Assets

In priority order:

1. **Message content** — the words people exchange.
2. **Identity linkage** — the connection between a pseudonymous Onyx identity and a real-world person.
3. **Social graph** — who talks to whom.
4. **Activity patterns** — when, how often, how much.
5. **Membership** — which rooms a user is in.
6. **Existence** — whether a given person uses Onyx at all.

---

## 2. Adversaries we defend against

### A1. Passive network observer
ISP, employer, café Wi-Fi, country-level firewall against a single user.
- **Sees:** encrypted Tor traffic.
- **Cannot:** identify peers, read content, determine destinations.
- **Defense:** Tor.

### A2. Hub server operator (including a malicious or coerced one)
- **Sees:** encrypted message blobs in transit and at rest in offline queues; pseudonymous routing identifiers (introduction inbox per recipient + rotating session tokens per active MLS group).
- **Cannot:** decrypt content; determine real-world identity; identify the sender of bootstrap messages (sealed-sender envelope).
- **Can observe:** coarse activity on a per-inbox basis over time (see §5 below).
- **Defense:** E2E (MLS) + sealed-sender bootstrap + rotating routing tokens.

### A3. Hub server attacker (someone who roots the hub)
- **Same view as A2**, plus the ability to log future traffic.
- **Cannot:** decrypt past or future messages; recover content from disk because the hub stores only ciphertext.
- **Defense:** the hub never holds plaintext keys or messages; MLS forward secrecy.

### A4. Active network attacker
Can inject, modify, delay traffic.
- **Cannot:** read content (E2E); impersonate users (signatures); undetectably reorder messages within a session (sequence numbers + MLS epoch counter).
- **Can:** delay messages; perform denial of service.
- **Defense:** AEAD + signatures.

### A5. Local non-privileged adversary on the user's device
Other user accounts, processes without root.
- **Cannot:** read Onyx data — encrypted at rest with passphrase-derived key.
- **Cannot:** connect to a running Onyx daemon — local API authenticated with per-session token.
- **Defense:** at-rest encryption + local API auth.

### A6. Casual targeted attacker
Someone trying to deanonymize a specific Onyx user without nation-state resources.
- **Defense:** the combined stack above, assuming the user follows operational security guidance (§4).

---

## 3. Adversaries we do NOT defend against

We are honest about these. If any of these is in your model, Onyx is not enough on its own.

### N1. Global passive adversary
An entity that can observe most internet traffic simultaneously can perform traffic confirmation against Tor. Padding, cover traffic, and jitter raise the cost but do not eliminate the attack.

### N2. Endpoint compromise
If the user's device runs malware with sufficient privileges, no application-layer crypto saves them. Use Tails, Qubes, or equivalent for high-risk threat models.

### N3. Coercion of users
Legal compulsion, physical threat, or social engineering of a user to hand over their key or decrypted history is outside the technical threat model. Note: because Onyx messages are signed by long-term credentials (see §6), a recipient under coercion can produce cryptographic proof of what a sender said. Onyx v1 is not deniable.

### N4. Coercion of developers
A malicious or compelled update could backdoor users. Mitigations: reproducible builds, signed releases, public source, multiple maintainers, no auto-update. Users must verify what they install.

### N5. Cryptographic algorithm breaks
If Ed25519, X25519, ChaCha20-Poly1305, or MLS itself is broken in the future (including by quantum computers), past messages may become readable to anyone with archived ciphertext. Onyx does not currently use post-quantum primitives. This may change.

### N6. Onion web tier users
The onion-web tier explicitly does not provide full E2E. The hub-served web UI decrypts messages on the daemon side to render HTML. A daemon compromise while a user is in this mode exposes the decrypted content of their active session. Tier is gated by client-auth onion + an explicit configuration acknowledgement, but the underlying tradeoff stands.

### N7. User operational security failures
Typing a real name, photographing a screen, using Onyx on a compromised device, reusing identifiers across services — Onyx cannot prevent these. Documentation will guide users; the rest is on them.

---

## 4. Trust assumptions

The user must trust:

- The Rust standard library and toolchain
- The Tor network (specifically: at least one of their three relays is honest)
- The Arti, OpenMLS, and other audited dependencies
- Their own operating system kernel
- Their own hardware
- The Onyx maintainers (reduced via reproducible builds + signed releases + open source)
- The CPU's random number generator (mixed with other entropy sources)

This list is not optional. There is no software trust-free path.

---

## 5. Residual linkability (honest accounting)

Even with all of the above, the hub can still observe the following. None of these reveals content, but each is a metadata signal worth understanding.

| # | Signal                              | Visible to | Mitigation                                  | Defeats it? |
|---|-------------------------------------|------------|---------------------------------------------|-------------|
| 1 | Per-inbox activity rate              | Hub, anyone holding the recipient's fingerprint | Padding + cover traffic; do not publish per-inbox metrics | Partial — raises cost, does not eliminate |
| 2 | Token cluster registered in one SUBSCRIBE | Hub | Distribute SUBSCRIBE across distinct Tor circuits | Partial — costs latency + circuits |
| 3 | Epoch-boundary intersection (who was online for a commit) | Hub | None ideal in v1 | No — documented limit |
| 4 | Back-to-back bootstrap envelopes from one circuit | Hub | Rate-limit bootstraps per circuit; offer deferred-send | Partial |
| 5 | Frame timing on an active connection | Hub, network | Constant-rate cover traffic ("high" mode) | Yes against hub at "high" mode; no against N1 |
| 6 | Padding bucket distribution per connection | Hub | Chunking all >4 KB messages into LARGE frames | Partial — N consecutive LARGE frames is a "big message" signal |
| 7 | Hidden-service descriptor liveness | Tor HSDir relays | (Standard Tor property — out of scope here) | No — inherent to onion services |

---

## 6. Non-deniability

Onyx v1 is **not deniable**. Every message a user sends carries a signature from their long-term identity key:

- the MLS credential signature inside the ciphertext, and
- (for non-bootstrap envelopes) an outer Ed25519 signature over the routing fields.

Any recipient can produce cryptographic proof to a third party of what a sender wrote. This is contained to the recipient — the hub and network do not gain this proof — but it does mean that the property "the recipient can convince a third party of what I said" is *strengthened* compared to a casual chat.

Users in coercion scenarios (N3) should be aware that screenshots and recipient honesty are already not under their control; cryptographic non-repudiation marginally worsens an already-bad situation. A future revision may add a deniable-credentials mode; the wire format reserves space for it via the optional outer signature field.

---

## 7. What to do with this document

- If your threat model is contained within §2, Onyx is appropriate.
- If it overlaps §3, layer Onyx with the appropriate complementary tool (an amnesic OS, OPSEC discipline, etc.) or use a different system.
- If you find an adversary class that belongs in §2 but is not currently defended, that's a security report — please raise an issue.
- If you find a property claimed in §2 that does not hold in the implementation, that's a vulnerability — please coordinate disclosure per `SECURITY.md` (TODO: to be added in Phase 1).

---

*See `DESIGN.md` for the full system specification.*
