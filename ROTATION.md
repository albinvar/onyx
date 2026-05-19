# Why routing-id rotation doesn't close ANONYMITY.md §3.2 on its own

**Status**: design-doc. Captures the structural analysis behind the (small) concrete fix in `Config.subscribe_intro_inbox` and the reason a fuller solution requires more than "rotate the subscription routing id."

If you're reading this because you want to know "is alice's hub-connection identity hidden from the hub?" the short answer is: **no, and it can't be without changing the protocol's trust model.** This doc explains why.

## §0 The honest claim

A user who connects to an Onyx hub for first-contact reachability **is identifiable to that hub on every reconnect.** Multi-hub usage (T8.1) limits the leak to per-hub; cover traffic (T-cover) limits the timing signal; the new `--no-intro-inbox-subscribe` opt-out (T-rotation.a) removes one of three independent linkability vectors at the cost of first-contact reachability. None of these is "the hub doesn't know who you are." That property would require a fundamentally different relay design.

## §1 The three independent leaks

When alice's daemon connects to a hub, the hub learns alice's identity from each of three sources independently:

1. **Noise XK static key.** The handshake authenticates alice's long-term X25519 identity key to the hub. The hub knows it's alice the moment the handshake completes — before any subscription or publication frame.

2. **Subscription to `introduction_inbox(fingerprint)`.** The routing id is derived deterministically from alice's fingerprint. The hub seeing a subscriber for this id implies "alice is online." Anyone with alice's fingerprint (which is the user-facing identifier in invite URLs, `onyx identity`, etc.) can independently probe the hub by sending a DELIVER and observing whether it gets queued or routed live.

3. **KP publication (`FRAME_KP_PUBLISH`).** The KP carries alice's signing key + signature. The hub validates the signature against the KP's claimed fingerprint and stores under that routing id. Anyone fetching the directory entry for alice's fingerprint gets the KP, which links the publishing connection to alice.

**Each leak independently identifies alice to the hub.** Closing any one of them alone changes nothing; the other two still expose her identity.

## §2 What "subscription rotation" was proposed to do

The proposal in `ANONYMITY.md §3.2`'s "What would close it" was:

> Per-session subscription rotation. Subscribe via a fresh routing id derived from a session secret + epoch, so reconnects look like different users to the hub. Recipient still learns about traffic in their real inbox via a separate (less-frequent) probe.

Walking through it: alice subscribes to `session_id = HKDF(seed, epoch_counter)` instead of `introduction_inbox(fp)`. Hub sees a fresh subscription id on every reconnect. **But:**

- **Noise leaks alice's identity before the subscription frame.** Rotating the subscription id changes nothing about who the hub thinks is connecting.
- **Senders need to address messages somehow.** If senders use `introduction_inbox(fp)`, the hub has to map fp → current session_id locally (and the hub learns the mapping). If senders use the rotating id, they need a directory lookup keyed by fp (and the hub sees the lookup → can correlate the directory entry's fp with the rotating id it returns).
- Either way, the hub can correlate the rotation back to fp via the routing surface it has to provide for senders.

Rotation **alone** moves the leak from one observable to another. It does not close it.

## §3 What actually would close it (and why we don't do it today)

For the hub to not know who alice is, three things have to change together:

A. **Ephemeral Noise keys per session.** alice generates a fresh X25519 keypair for the hub handshake every reconnect. The hub authenticates "some X25519 peer," not "alice." Alice's long-term identity is bound only to the in-band frames (KP signatures, sealed-envelope signatures).

B. **Separate connections for publish and subscribe.** If alice publishes her KP and subscribes to her inbox on the same connection, the hub correlates the two and learns "this ephemeral peer == alice." Publishing on connection X and subscribing on connection Y (with different ephemeral keys) breaks the same-session correlation.

C. **A way for senders to route to alice without revealing alice's identity to the hub.** This is the deep problem. The hub MUST know which routing id a DELIVER targets in order to deliver it. If the routing id is derived from alice's fingerprint, the hub learns it. If it's not, the sender has to learn the current id somehow — which inevitably leaks back to alice's fingerprint through whatever lookup mechanism we provide.

Designs that solve (C) usually do one of:

- **Sealed-id mailboxes** — every published id is encrypted under a per-recipient key the hub can't decrypt. Hub stores ciphertexts indexed by hash-table buckets; senders probe buckets. Doable but expensive: lookups need to either reveal the recipient (back to square one) or do oblivious-RAM-style queries (slow + complex).
- **Mixnet-style routing** — multiple-hop relay where no single hub sees the full path. Materially changes the architecture; not what Onyx is.
- **Onion-service-only delivery** — every recipient publishes a long-term onion address; senders dial directly via Tor circuits; no hub relay for established peers. We already kind of have this via direct sessions; the hub is the offline-recipient fallback. To go further would mean dropping the offline-relay feature.

**None of these is a quick slice.** They each rewrite a sizable chunk of the protocol. Onyx v0 does not take any of them.

## §4 What Onyx v0 actually has (mitigations, in layers)

In order of contribution to "the hub knows less about alice":

1. **Multi-hub fan-out (T8.1).** alice's daemon connects to N hubs. No single hub sees her complete online pattern, room set, or peer interactions. The leak is per-hub. Operator picks how many trust roots to spread across.

2. **Cover traffic, bidirectional (T-cover + T-cover.hub).** When both alice and the hub opt in, the daemon↔hub channel becomes traffic-shape-uniform in both directions. The hub still knows alice is online but can't fingerprint when she's actively sending vs idle. See `ANONYMITY.md §3.1` for the full caveat table.

3. **Per-(room, epoch) session-token routing (T6.3.g).** In-room hub traffic routes via `session_token(group_secret, 0)` — derivable only by current room members. The hub sees "some room is active" but can't link two rooms together by their routing ids, and can't identify which members are subscribed (multiple subscribers fetch from the same room-token inbox). This closes §3.2 for **in-room traffic specifically**.

4. **`subscribe_intro_inbox = false` opt-out (T-rotation.a — this slice).** The daemon skips the fingerprint-derived intro_inbox subscription. **Catches leak #2 only**, not #1 or #3. Tradeoff: alice can't receive first-contact bootstraps via the hub (msg/v1, mls/v1 envelopes queue indefinitely until she switches back or runs another daemon process that does subscribe). Useful for users who've established all their peer relationships and prefer maximum unlinkability via this vector over reachability.

5. **Onion-service direct dials.** For established peers with onion-service publication, the hub is only an offline fallback. Live online → direct Tor circuit, hub sees nothing. The "hub knows alice is online" leak only fires when alice is on the hub at all.

## §5 What the operator can do today (practical guidance)

- **For maximum privacy** (no first-contact reachability): set `--no-intro-inbox-subscribe`. Combine with `--cover-traffic-mean-secs` on both daemon and hub. Run multiple hubs. The hub still knows alice's Noise identity but loses the live-subscription signal for her intro_inbox, and the timing leak is muted.

- **For maximum reachability** (default): leave both unset. The hub sees alice on every reconnect; multi-hub mitigates if you trust at least one hub in the set.

- **For paranoia at zero cost**: use onion-service direct dials when both parties are online. Bypass the hub entirely for already-established peers.

## §6 Items deferred to future design

- **Ephemeral Noise keys + KP-only identity binding** (§3.A above). Would close leak #1. Estimated effort: medium-large; touches every hub-client + hub-side handshake path.

- **Separate publish/subscribe connections** (§3.B above). Cheap on top of §3.A; useless without it.

- **Oblivious-recipient routing** for first-contact (§3.C above). Significant cryptographic design + UX consequences. Not currently planned for v0.

- **Lazy-poll mode**: persistent connection subscribes to NO fingerprint-derived ids; opens brief side connections on a Poisson schedule to drain the intro_inbox. Doesn't help while #1 is unfixed (the side connection still uses alice's static Noise key). Marked here as "interesting only after §3.A."

## §7 Related documents

- `ANONYMITY.md §3.1` — cover traffic (which addresses the **timing** observable independently of the **identity** observable analyzed here).
- `ANONYMITY.md §3.2` — the original "What we have today: nothing" entry. Rewritten alongside this doc to reference the structural analysis instead of implying rotation alone would close it.
- `FEDERATION.md` — multi-hub mode.
- `THREAT_MODEL.md §8.2` — full adversary catalog.

## §8 Decision log

- **2026-05-19**: shipped `Config.subscribe_intro_inbox` opt-out (T-rotation.a). Closes leak #2 in isolation. Documented the structural multi-leak situation here so future readers don't think "all that's missing is rotation."
- **Deferred**: ephemeral Noise keys, oblivious routing, lazy-poll. Each is its own slice with substantial design + protocol-level changes.
