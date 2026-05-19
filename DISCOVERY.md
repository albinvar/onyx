# Public Hub Discovery (T8.4) — Design Doc + Deferral Rationale

> **Status: deferred.** This doc exists to explain why Onyx does *not* yet have public hub discovery, what the realistic approaches are, and what we'd build if/when the deferral conditions are resolved. Like `FEDERATION.md` (T8.3.a), this is the design step that prefigures any code; unlike `FEDERATION.md`, the recommendation here is "don't build it yet." Last updated: 2026-05-19.

---

## 0. The honest framing (read this first)

A fresh-install Onyx daemon today has no way to discover *any* hub on its own — the operator has to pass `--hub onion:port,b32pubkey` or the daemon runs direct-peer-only (no offline/asynchronous messaging). For a user who knows nobody on Onyx, this is a bootstrapping problem: how do they find a hub to use?

The natural-feeling answer — "ship a list of public community hubs" — runs straight into a question we cannot answer technically: **who decides which hubs are on the list, and why should the user trust them?** Every approach to public discovery either centralises that decision (introducing a trust point Onyx's other architecture deliberately avoids) or pushes it back onto the user (which is what T8.2 invite URLs already do).

This is mostly a **governance** problem, not a technical one. The technical bits are easy. The hard question is: who curates? And without a community of operators willing to *run* public hubs in the first place, the question is academic.

**Recommendation: defer T8.4 until there is a real public-hub community to discover.** What we have today (T8.2 invite URLs with `--with-hubs`) is the correct shape for the current state — users discover hubs *through people*, not through directories. That aligns with Onyx's no-central-authority posture.

---

## 1. The bootstrapping problem

The actual user need is: "I just installed Onyx. I want to talk to someone. What do I do?"

There are two cases:

  * **Case A: you know someone on Onyx.** They send you an invite URL via Signal/in-person/whatever channel you already trust. T8.2's `--with-hubs` flag bundles the inviter's hub list into that URL; you paste it into `onyx accept` and your daemon learns where to publish + subscribe. **Solved today.** No discovery service needed.
  * **Case B: you don't know anyone on Onyx.** You need to find a hub the same way the first user did. This is the genuine bootstrapping problem. There is no clean technical answer.

For Case B, the realistic options are: (1) someone publishes a list and you trust the publisher, (2) you run your own hub, (3) you wait until someone you know joins Onyx and gives you an invite. Each of these has the same shape as Tor/Briar/Cwtch — those tools all have similar bootstrap properties, and all have chosen to ship a bundled list of one form or another *because* they have an established community to populate the list.

**Until Onyx has that community, public hub discovery is a feature looking for a use case.**

---

## 2. Four approaches, honestly compared

### (1) Bundled list in the binary

Ship a static `well_known_hubs.toml` (or equivalent) in the source tree. On startup, if `--hub` isn't passed, the daemon picks one from the list (random, or round-robin, or first-online).

  * **Pros**: simple, no startup network call (good for anonymity), auditable in source, no centralised online lookup.
  * **Cons**: stale on every release. Adding/removing a hub requires a software release. *Who decides which hubs go on the list?* — Onyx maintainers, who become a governance authority for hub legitimacy. That's a trust position Onyx's other architecture deliberately avoids.
  * **What Tor does**: ships its directory-authority list this way. The Tor Project curates it.
  * **Tech effort**: ~30 minutes — trivial.
  * **Governance effort**: large. Needs a written policy for hub inclusion/exclusion, contact procedures for removed operators, a security disclosure process when a listed hub is compromised, etc.

### (2) Online directory fetched from a well-known URL

On startup, fetch a JSON list from e.g. `https://onyx.org/hubs.json`. Daemon picks from the response.

  * **Pros**: dynamic (no software updates to refresh), centralised governance is at least transparent (it's a URL, not a bundled blob).
  * **Cons**: **introduces a fresh-client metadata-collection point**. Every Onyx daemon phones home to a single URL on startup. That URL operator sees:
    * Approximate fresh-install counts
    * IP address of every Onyx user (unless the daemon fetches over Tor — which has its own startup-bootstrap problem because the daemon needs Tor to fetch, but doesn't have Tor configured yet at that point)
    * Time-of-day usage patterns by region
  * Without significant care, this is a **major anonymity violation** for the population of users who never touch `--hub`. Even worse: a compromised directory could selectively serve different hub lists to different IPs, fragmenting the user population.
  * **Tech effort**: ~1 hour.
  * **Anonymity cost**: serious. Probably disqualifying without onion-routed fetching + careful caching, which itself adds complexity.

### (3) DHT (Kademlia, etc.) — distributed directory

Hubs gossip their existence to a DHT; new clients query any DHT node for the current hub population. Tor-style without directory authorities.

  * **Pros**: maximally decentralised, no governance point.
  * **Cons**: **massive engineering project**. Tor's distributed system took years and still uses directory authorities for the initial bootstrap. Building a robust DHT for this is multi-session real work, not a slice.
  * **Tech effort**: weeks of design + multiple sessions of implementation.
  * **Anonymity cost**: depends entirely on implementation quality. Easy to get wrong; hard to verify right.

### (4) Invite-based — peer tells you the hubs (T8.2 — already shipped)

A user who already runs Onyx generates an invite URL containing their identity AND the hub list their daemon uses. The new user pastes the URL into `onyx accept`; their daemon now knows which hubs the inviter publishes to and can be configured to use those.

  * **Pros**: **zero centralised governance**, zero startup metadata leak, perfectly aligned with Onyx's no-central-authority posture. Already implemented.
  * **Cons**: Case B users (no contacts on Onyx) can't bootstrap from scratch. They need to know one person first.
  * **What Briar does**: exactly this, plus QR codes. No central directory at all. Users must trust the in-person-or-out-of-band channel they used to share the invite.

---

## 3. Comparison with other tools

| Tool | Discovery approach | Has bundled list? | Has online directory? | Has DHT? |
|---|---|---|---|---|
| **Onyx** (today) | Invite-based (T8.2) | No | No | No |
| Tor | Bundled DA list + in-Tor consensus | Yes | Yes (via Tor) | No |
| Briar | Invite-based + QR codes | No | No | No |
| Matrix | Federation + homeserver lookup | Implicit (in client config) | Yes (federated DNS) | No |
| Cwtch | Invite-based | No | No | No |
| Session | Bundled service-node seeds | Yes | Optional | Yes (Loki) |

Note: every tool in the "anonymity-focused" subset (Briar, Cwtch) chose invite-based. Tools with central operators (Matrix homeservers, Session's project-controlled service nodes) use directories. **Onyx's invite-based shape is consistent with the anonymity-focused cluster, not the centralised-service cluster.**

---

## 4. Recommendation

**Don't implement T8.4 today.** Reasons:

  1. **No public-hub community exists** to populate any kind of discovery mechanism. Building infrastructure for zero users is theatre.
  2. **T8.2 invite URLs already solve the realistic use case** (you got told about Onyx by someone; they tell you their hubs). The remaining case (you found Onyx via Hacker News and don't know anyone using it) is the same case Briar/Cwtch users face; the answer is "run your own hub, or wait for someone you know to join."
  3. **The governance question dominates the technical question.** Adding a discovery mechanism without a written policy for who's on the list, why, how they're removed, and what happens when one of them is compromised would be irresponsible.
  4. **Approach (2) (online directory) is the most tempting and the most dangerous.** Without significant onion-routing + caching work, it introduces a fresh-install metadata-collection point that contradicts everything else about Onyx's design.

**Revisit T8.4 if any of the following become true:**

  * A community of 5+ public Onyx hubs emerges with stable operators willing to commit to a service-level baseline.
  * Onyx becomes commonly recommended in contexts where users don't already know existing users (e.g., listed on PrivacyTools.io with no clear bootstrap path).
  * The Onyx project formally adopts a maintainer body able to take on governance for a hub-listing policy.

None of these are true today. The doc exists so the next reader who asks "why don't we have public hub discovery?" has an answer that isn't "I forgot."

---

## 5. What we'd actually build if we did go ahead

For the record, if T8.4 lands later, the minimum viable shape is approach (1) — bundled list. Concretely:

  * New file `crates/onyx-daemon/well_known_hubs.toml` with a list of `[[hub]]` entries (each: `onion`, `pubkey`, `operator_label`, `notes`).
  * `Config` gains `use_well_known_hubs: bool` (default false). When true AND `--hub` not passed AND `--no-tor` not set, daemon loads the list at startup.
  * Selection strategy: try each in declared order; first that completes Noise XK + first SUBSCRIBE round-trip wins. Document the strategy in `SECURITY.md` (predictable selection = traffic analysis surface).
  * Loud `info!` log at startup naming which well-known hub was selected, so operators can audit.
  * **Strict opt-in**: the well-known list is OFF by default. Users who want it must explicitly enable.

That gets us approach (1) without any of the metadata-leak of approach (2). The technical work is ~half a session; the *governance* work (curating the list, drafting the inclusion policy, finding willing operators) is the real cost and is not yet a thing that needs to happen.

If approach (2) ever becomes necessary, the onion-routed fetch + aggressive caching + signed-list verification design would need its own dedicated doc and a serious review of the residual metadata leak.

---

## 6. Why this matters for the project posture

This doc is more about **what Onyx isn't** than what it is. Onyx is not trying to be a one-click anonymity tool that hides the hard parts; it's trying to be a discipline of "each implicit trust assumption gets removed deliberately, one slice at a time." A bundled-hub-list with no operators is the kind of feature that *looks* like progress in a README screenshot but introduces a trust assumption (the maintainer's hub-curation policy) that we don't yet have a credible answer for.

`ANONYMITY.md` §0 already says "no claim of 'perfect anonymity' appears anywhere in this repository." That posture extends here: no claim of "one-click hub discovery" should appear either, until the supporting community + policy exist.

---

## 7. Related documents

  * `FEDERATION.md` — hub-to-hub gossip (T8.3, done). The technical layer this doc builds *atop*.
  * `ANONYMITY.md` §3 — the anonymity gap list. T8.4 done badly would *add* to that list; done well would shrink #3.2 (online/offline linkability) by reducing the fraction of users on a single popular hub.
  * `ROADMAP.md` §5 "Long-term" — where T8.4 has been parked, with a pointer to this doc.
  * `THREAT_MODEL.md` §4 — trust assumptions. T8.4 via approach (1) would add "the bundled hub list's curator(s) act in good faith" as a new assumption.
  * `T8.2` invite-URL implementation (`crates/onyx-core/src/invite.rs` + `crates/onyx/src/main.rs` `Command::Invite`) — the existing alternative.

---

## 8. Decision log

  * **2026-05-19** — Drafted. T8.4 deferred pending (a) emergence of a public-hub community, or (b) formal governance body able to maintain a hub-listing policy. Re-evaluate when either condition holds.
