# Known attacks, and where Onyx stands on each

This is a catalogue of attacks that have actually been published or carried
out against secure messengers, Tor onion services, and software release
pipelines — and, for each, an honest statement of whether Onyx is exposed.

It exists for two reasons. Every one of these broke a system whose authors
believed it was sound, so each is a concrete question to ask of Onyx. And a
reader deciding whether to rely on Onyx deserves to see the answers,
including the unflattering ones.

**How to read the status column**

| Status | Meaning |
|---|---|
| **Addressed** | There is a specific mechanism against this attack, and a test or source reference for it. Not a claim of proof. |
| **Partial** | Some of the attack is blocked, or it is blocked only in a non-default configuration. The remaining exposure is stated. |
| **Open** | Onyx is exposed. A planned fix is named where one exists. |
| **By design** | The attack is outside what Onyx tries to defend (see `THREAT_MODEL.md` §3), or the exposure is a deliberate trade. |
| **N/A** | The feature the attack targets does not exist in Onyx. |

"Addressed" entries have not been checked by anyone outside the project.
Onyx has had no external audit. Identifiers like `E-1` refer to
`THREAT_MODEL.md` §8.6; `T-1`…`T-4` refer to `TRUST-ARCHITECTURE.md`.

References are given by author, title and year so they can be looked up;
descriptions are summaries, and the original papers are the authority.

---

## 1. Attacks on end-to-end messaging protocols

### 1.1 The server controls who is in a group

*Rösler, Mainka, Schwenk — "More is Less: On the End-to-End Security of Group
Communications in Signal, WhatsApp, and Threema" (2018).* In WhatsApp, group
membership was managed by server-relayed messages that were not
end-to-end authenticated, so whoever controlled the server could add a member
to a group and receive future messages.

*Albrecht, Celi, Dowling, Jones — "Practically-exploitable Cryptographic
Vulnerabilities in Matrix" (2022).* A malicious homeserver could add users or
devices to rooms, and several implementation bugs let it impersonate devices
or break confidentiality outright.

**Onyx: Addressed.** Membership is the MLS group state. A hub relays opaque
ciphertext and cannot produce a valid commit. Inside a room, every
non-self-update proposal must come from an admin, and the admin check is on
the MLS leaf signature key rather than a claimed name
(`credential_bound_to_key`, the admin gate in `onyx-daemon`). The 2026-11
audit found that this gate previously covered only some proposal types; that
is fixed and tested. *Residual:* the admin set itself is stored in the vault
unauthenticated (`V-3`), so someone who can edit the vault file can change
who the client believes is an admin.

### 1.2 A member impersonates another member

*Matrix (2022, above)* — a confusion between message types let an attacker be
treated as a trusted device. More generally, any group system that attributes
a message by a field inside the payload, rather than by the key that signed
it, lets one member speak as another.

**Onyx: Addressed (was exploitable until 2026-11).** The audit found exactly
this bug: room messages were attributed using a sender field the sender
controlled. Attribution now comes from the MLS leaf that signed the message,
and unsigned-framing `PublicMessage`s are refused for application data
(`private_protocol_message`). Regression tests cover both.

### 1.3 Protocol-level flaws in a home-grown transport

*Albrecht, Mareková, Paterson, Stepanovs — "Four Attacks and a Proof for
Telegram" (2022)*: message reordering, a timing side channel in decryption,
and a key-exchange weakness in MTProto. *Paterson, Scarlata, Truong — "Three
Lessons from Threema" (2023)*: no forward secrecy against a server
compromise, replay and reordering, and a cross-protocol interaction that let
one protocol's messages be used against another. *Garman et al. — "Dancing on
the Lip of the Volcano" (2016)*: malleable ciphertext in iMessage allowed
retrospective decryption.

The shared lesson is that custom compositions fail at the seams: unauthenticated
or malleable encryption, missing replay protection, and key reuse across
protocols.

**Onyx: Partial.** Onyx does not invent primitives or a ratchet: it uses MLS
(RFC 9420, `openmls`), Noise XK (`snow`) and AEAD throughout, so there is no
unauthenticated or malleable ciphertext. Domain-separated labels are used for
derived keys. There is a replay guard on relayed envelopes. **But the
composition itself — how the envelope, Noise, MLS and the hub protocol fit
together — is Onyx's own and has had only internal review.** That is
precisely the category in which the systems above failed, and it is the main
reason an external audit is the largest open item.

### 1.4 Message decryption via the content renderer

*Poddebniak et al. — "Efail" (2018).* Mail clients that rendered HTML could be
made to exfiltrate decrypted plaintext through a URL fetch.

**Onyx: Addressed.** There is no renderer. Message text is displayed as plain
text in a terminal; nothing is fetched, no links are previewed, no HTML or
images are interpreted. Control characters in received text are replaced
before printing in the CLI (`output::clean`, with a test using an
escape-sequence payload), and the terminal interface draws through a cell
buffer that drops control characters. *Residual:* a received **file** is
written to disk and opening it is the user's risk; Onyx sets no quarantine
attribute (`X-1`).

### 1.5 Replayed or stale key material

In Signal-style systems, a server that hands out the same prekey twice, or a
"last-resort" prekey indefinitely, weakens forward secrecy for the first
message. MLS has the same hazard with reused KeyPackages.

**Onyx: Open (`K-1`).** A hub can serve a stale KeyPackage from its
directory, or an old invite link carrying an embedded KeyPackage can be
reused. A Welcome that reuses an existing group id is rejected by `openmls`
(verified against the 0.8.1 source), and invite links carry an expiry, but
there is no tracking of consumed KeyPackages.

### 1.6 No forward secrecy for the first message

Systems that encrypt the first message to a static public key (PGP, early
Threema server-to-client) lose it on later key compromise.

**Onyx: Open (`E-1`, fix chosen: `T-2`).** A relayed envelope is sealed to
the recipient's long-lived hybrid KEM key. The sender's side is ephemeral, so
compromising the *sender* later reveals nothing; compromising the *recipient*
later, combined with a recording of hub traffic, reveals the sender identity
of every recorded envelope and the content of first-contact messages. Content
of established conversations is additionally MLS-encrypted and keeps MLS's
forward secrecy. The chosen fix is a rotating KEM key (7-day rotation,
14-day overlap).

### 1.7 Man-in-the-middle at first contact

Every system without a trusted directory has this: if the attacker controls
the channel over which keys are first exchanged, they can substitute their
own. Key-transparency logs (WhatsApp, iMessage, Signal's roadmap) exist to
make this detectable.

**Onyx: Partial.** Keys are pinned on first use and a later change is flagged
and blocks sending until re-verified (`pin_block`). Hub-routed invite links
are signed by the inviter. Safety numbers allow out-of-band comparison. But
the first exchange is only as trustworthy as the channel the connect code
travelled over, there is no transparency log, and nothing forces a user to
verify. A stranger can also still open an *unverified* direct conversation
(`W-1`).

### 1.8 Non-repudiation used against the sender

Signal's X3DH/Double Ratchet give deniability: a transcript does not prove to
a third party who wrote it. Systems that sign every message do not.

**Onyx: By design, and worth knowing.** MLS signs each message with the
sender's identity key. A recipient can prove to a third party what you wrote
(`THREAT_MODEL.md` §6). The hub and the network do not get this proof.

### 1.9 Harvest now, decrypt later

Recorded ciphertext may be decrypted once a large quantum computer exists.
Signal (PQXDH, 2023) and Apple (PQ3, 2024) added post-quantum key agreement
for this reason.

**Onyx: Partial.** The sealed envelope used for relayed traffic is hybrid
X25519 + ML-KEM-768. **The rest is classical:** the Noise XK link is X25519,
the MLS ciphersuite is `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`,
and Tor's own circuit handshake is classical. A direct session recorded today
is therefore protected by Tor + Noise + MLS, none of which is post-quantum.

---

## 2. Metadata attacks on messengers

### 2.1 Statistical disclosure against sealed sender

*Martiny et al. — "Improving Signal's Sealed Sender" (2021).* Even when the
server cannot see who sent a message, replies and delivery receipts arrive at
predictable times. Observing which recipients become active shortly after a
given user receives a message identifies conversation partners after a
modest number of messages.

**Onyx: Partial.** The attack needs a vantage point that sees both ends of an
exchange. For **direct** sessions there is no server: only the two parties'
Tor circuits carry the traffic. For **hub-relayed** traffic, the hub sees
opaque routing tokens and arrival times and could run this analysis across
tokens. Defences in place: per-recipient routing tokens, padded envelope
sizes, a private default in which the hub connection uses fresh keys and no
identity-linked inbox, and optional constant-rate cover traffic upstream.
Not in place: downstream cover from the hub, and any defence if a user enables
`--first-contact-reachable` on a single hub for a long time. See
`ANONYMITY.md` §3 and `OBLIVIOUS-ROUTING.md`.

### 2.2 Delivery receipts as a probe

*Schnitzler et al. — "Hope of Delivery" (2023)* inferred a recipient's
location class from receipt timing. *Gegenhuber et al. — "Careless Whisper"
(2024)* showed that receipts triggered silently let anyone who knows a phone
number track a target's online state, screen activity and device count, and
drain their battery.

**Onyx: Partial — this exposure was added deliberately in 2026-11.** Direct
messages are now acknowledged so that lost messages are retried. An
acknowledgement tells the sender that the recipient's daemon was running at
that moment. Limits on the damage: acknowledgements travel only inside an
established, mutually authenticated session, so the prober must already be a
contact; there are no read receipts and no typing indicators; and a contact
could already observe whether a session to you is up. It is still a signal a
contact can collect over time. It can be switched off (`/receipts off`,
`--no-delivery-receipts`, or `"delivery_receipts": false`); the cost is that
your contacts can no longer tell a delivered message from a lost one.

### 2.3 Presence from a permanent address

Any system where an identifier is also a reachable address lets its holders
check whether you are online. For onion services specifically, anyone with
the address can attempt a connection at any time, forever.

**Onyx: Open (`O-1`, fix chosen: `T-1`).** One onion address is shared with
all contacts and cannot be revoked per contact. A former contact, or anyone
they gave it to, can test whether your daemon is up. Chosen fix: Tor client
authorization, so that only holders of a per-contact key can even fetch the
service descriptor, with a move to a new address on migration.

### 2.4 Contact discovery and enumeration

*Hagen et al. — "All the Numbers are US" (2021)* enumerated a large share of
phone numbers registered on WhatsApp, Signal and Telegram through the
contact-discovery API.

**Onyx: N/A in the default configuration.** There are no phone numbers,
usernames or global directory. *Caveat:* a user who enables
`--first-contact-reachable` publishes a KeyPackage on a hub under their
fingerprint, and anyone who already knows that fingerprint can confirm it is
registered there.

### 2.5 Push-notification metadata

In 2023 it became public that governments had requested push-notification
records from Apple and Google, which can link an app account to a device.

**Onyx: N/A.** No push services. The cost is that Onyx must be running to
receive anything.

### 2.6 Message size and timing

Traffic analysis of encrypted messengers by packet size and burst pattern is
long-established (for example, identifying which of a set of known messages or
files was sent).

**Onyx: Partial.** Relayed envelopes are padded to size buckets
(`pad_len_for`). Direct-session frames inside Tor are subject to Tor's cell
padding only. Large file transfers are visible as volume on a circuit. Cover
traffic is opt-in.

### 2.7 Room membership visible to the relay

A relay that fans a group message out to N recipients learns N, and often who.

**Onyx: Partial.** Since 2026-11 each member has their own routing token, so a
single token no longer reveals a room. The sender still uploads N envelopes
in a burst, from which a hub can estimate room size. The legacy shared token
is still subscribed to for compatibility with older clients (`C-2`), and
subscriptions to routing tokens are not authenticated (`H-7`): anyone who
learns a token can subscribe to it and receive ciphertext they cannot read,
learning timing and volume.

---

## 3. Attacks on Tor and onion services

### 3.1 End-to-end traffic confirmation

The foundational limitation, documented since Tor's design paper: an adversary
who observes both ends of a circuit can correlate them. *Sun et al. — "RAPTOR"
(2015)* showed network-level adversaries can place themselves on both ends
through routing. In 2024, German reporting (NDR/Panorama) described law
enforcement deanonymising onion-service users by long-term timing analysis
combined with running relays; the affected chat application was an old
version without vanguards.

**Onyx: By design (`N1`), with mitigation.** Onyx cannot defeat this and says
so. It raises the cost: full vanguards are compiled in and pinned for
onion-service circuits, and optional cover traffic blurs timing. It does not
claim more than that.

### 3.2 Guard discovery against an onion service

*Øverlier and Syverson — "Locating Hidden Servers" (2006)*; *Biryukov,
Pustogarov, Weinmann — "Trawling for Tor Hidden Services" (2013).* By forcing
an onion service to build many circuits, an attacker running relays eventually
becomes adjacent to the service's guard, learns the guard, and can then
target it.

**Onyx: Partial.** Full vanguards (extra pinned layers behind the guard) are
enabled explicitly, because Arti does not enable them by default
(`tor.rs`, `effective_vanguard_mode`, logged at startup). Vanguards slow
guard discovery; they do not make it impossible. Onyx makes the attack
easier than it needs to be in one respect: any contact holds the address and
can trigger circuits at will (`O-1`). Inbound sessions are capped
(`MAX_INBOUND_SESSIONS`), and a contact that keeps failing resumption is
backed off.

### 3.3 Malicious relays and the relay-early attack

In 2014 attackers ran relays that used `RELAY_EARLY` cells to signal across a
circuit and confirm which users visited which onion services. Large groups of
malicious relays have been found and removed since (for example the "KAX17"
group, 2021).

**Onyx: By design / inherited.** This is Tor's to defend, and the specific
2014 technique was fixed in Tor. Onyx inherits whatever Arti and the network
provide. Circuits to different peers and hubs are isolated from each other so
that one malicious exit-side relay cannot link them (`isolated_client`).

### 3.4 Onion-service enumeration through directories

With v2 onion services, relays acting as hidden-service directories could
harvest addresses. v3 services use blinded keys so directories cannot learn
the address.

**Onyx: Addressed (inherited).** v3 only. An address is learned only from
someone who was given it.

### 3.5 Denial of service against onion services

Introduction-point flooding took major onion services offline through
2022–2023; Tor added a proof-of-work defence for onion services in 2023.

**Onyx: Partial.** Daemon and hub cap inbound sessions, bound per-connection
work, time out stalled handshakes and MLS exchanges, and the hub rate-limits
and bounds queues with own-queue-only eviction. The onion-service
proof-of-work defence is **not** enabled. Anyone holding your address can
make you hard to reach.

### 3.6 Circuit and website fingerprinting

*Kwon et al. — "Circuit Fingerprinting Attacks" (2015)* showed that onion-service
circuits were distinguishable from ordinary ones by a local observer; website
fingerprinting research shows traffic patterns can identify destinations.

**Onyx: Open / inherited.** A local network observer can likely tell that you
run an onion service, and with effort that it behaves like a messenger. Tor's
circuit padding reduces but does not remove this. An obfs4, webtunnel or
snowflake bridge hides that the traffic is Tor from a network that
fingerprints Tor itself; it does not stop this analysis of what the
traffic does.

### 3.7 Leaks outside Tor

DNS lookups, update checks, or a "fallback" path that bypasses the proxy have
deanonymised users of many Tor-wrapped applications.

**Onyx: Addressed, with a caveat.** Tor is embedded (Arti), not a SOCKS
proxy an application can miss. The daemon makes no clearnet connections;
dial targets are validated as onion addresses (`is_valid_onion_target`), and
connect codes naming anything else are refused. *Caveat (`D-5`):* plain-TCP
development modes are compiled into release binaries. They refuse to start
without `--allow-clearnet`, but they exist. The installer itself fetches
from GitHub over the clear internet.

---

## 4. Attacks on the device and local storage

### 4.1 Forensic extraction

Commercial forensic tools read messenger databases from seized, unlocked
devices. Signal Desktop for years stored its database key in a plaintext file
next to the database.

**Onyx: Partial (`V-3`, fix chosen: `T-3`).** Keys and message text are sealed
under a key derived from the passphrase with Argon2id; the passphrase is not
stored. But the vault is an ordinary SQLite file in which contact
fingerprints, timestamps, room membership and row counts are readable
without the passphrase. A weak passphrase is brute-forceable offline. A
seized device with the daemon running and the vault unlocked exposes
everything. There are no disappearing messages.

### 4.2 Tampering with local state

If trust decisions ("this key is verified", "this person is an admin") are
stored without integrity protection, someone with write access to the file
can change them without knowing any key.

**Onyx: Open (`V-3`).** Pins, the verified flag and admin sets are not
authenticated. Whole-database encryption with per-page integrity is the
chosen fix.

### 4.3 Secrets in logs, arguments and memory

Plaintext or identifiers leaking into logs is a recurring finding in
messenger audits.

**Onyx: Partial.** The 2026-11 audit found message plaintext being logged;
that is fixed and the logs were scrubbed of fingerprints, group ids and room
names, with a live-test scan for regressions. Files and directories are
created `0600`/`0700`. *Residual (`X-1`):* a passphrase passed with
`--passphrase` is visible in the process list; secrets are not consistently
zeroized in memory; the process does not lock memory against swap.

### 4.4 Zero-click exploitation through parsers

Pegasus-class attacks (for example FORCEDENTRY, 2021) compromise a device by
sending content that a messenger parses automatically — images, PDFs,
previews.

**Onyx: Partial.** The attack surface is small and in a memory-safe language:
no media decoding on receipt, no previews, no rendering. What is parsed
automatically from a stranger is the wire framing, Noise, and MLS messages,
with size limits and a decoder fuzz. Metadata stripping parses files on the
**sending** side only. The dependencies include C code (SQLite, parts of the
crypto stack), and none of this helps against an operating-system-level
compromise (`N2`).

### 4.5 Two processes, one state

Running two instances on one key store can reuse ratchet state and break
forward secrecy or desynchronise groups.

**Onyx: Addressed.** An exclusive vault lock refuses a second daemon and
refuses `vault rekey` while a daemon runs. Ratchet state is persisted per
message. Restoring an old backup still rolls MLS state back; that is inherent
and documented.

---

## 5. Attacks on relays (hubs)

### 5.1 A malicious or seized relay

The baseline assumption for any store-and-forward system. Lavabit (2013) is
the standard example of an operator being compelled.

**Onyx: Addressed for content, Partial for metadata.** A hub holds only
sealed, padded envelopes and opaque tokens; it has no keys that decrypt
anything, and its stored timestamps are coarsened to the hour. It can drop,
delay or reorder (`H-8`: delivery from a hub is at-most-once and there is no
cross-hub deduplication), and it can record arrival times and volumes per
token (§2.1).

### 5.2 Queue exhaustion and eviction of other users' mail

A relay with a shared, bounded queue lets an attacker push out other people's
messages by filling it.

**Onyx: Addressed (was exploitable until 2026-11).** Eviction is now limited
to the sender's own oldest entries, with caps on subscriptions and idle
connections. *Residual:* the hub serialises storage under one lock and is not
built for high load (`H-8`).

### 5.3 Relay impersonation

**Onyx: Addressed.** A hub is identified by a public key that the client pins
from `--hub`; the Noise XK handshake fails against anything else. A resumed
peer session is bound to the pinned identity.

---

## 6. Supply-chain attacks

### 6.1 Backdoored dependency or build input

*xz-utils (CVE-2024-3094, 2024):* a maintainer account inserted a backdoor
that lived only in release tarballs. *event-stream (2018)*, and a steady
stream of typosquatted packages on every registry including crates.io.

**Onyx: Partial.** `Cargo.lock` is committed and builds use `--locked`;
`cargo deny` checks advisories, licences and sources in CI; the toolchain
version is pinned. Dependencies are **not** individually audited or vendored
— there are several hundred transitive crates, including Arti's tree — and no
`cargo vet`-style review record exists. A malicious update to a dependency
that is accepted into the lockfile would ship.

### 6.2 Compromised CI action

*tj-actions/changed-files (CVE-2025-30066, 2025):* a widely used GitHub Action
was modified to dump secrets from every workflow that referenced it by tag.
*Codecov (2021)* was the same class.

**Onyx: Addressed (2026-11).** Actions in the release workflow are pinned by
commit hash, not tag; signing permissions are scoped to the one job that
signs; the build cache action was removed from the release path.

### 6.3 Tampered or substituted release

Replacing a binary on a download host, or serving an old vulnerable version.

**Onyx: Partial.** Releases are signed with sigstore; the installer requires
the signature to come from this repository's release workflow at the matching
tag, requires a signed checksum file, and refuses to install an older version
over a newer one. A script checks build reproducibility. *Residual:* the
installer is itself downloaded and piped to a shell — a user who does not
read it first is trusting GitHub and the account; the maintainer's GitHub
account is a single point of compromise; and reproducibility has not been
independently confirmed by a second party.

### 6.4 Coercion or compromise of the developer

**Onyx: By design (`N4`).** One maintainer. The defences are that everything
is open source, signed from a public workflow, and reproducible in principle.
There is no second signer.

---

## 7. What this adds up to

Counting honestly: Onyx's strongest position is against a **malicious relay
trying to read or forge messages**, and against the **group-membership and
impersonation bugs** that affected WhatsApp and Matrix — the second only
because an audit this month found and fixed them.

Its weakest positions are structural and known:

1. **Anyone you have ever added can watch your presence** (§2.3, §3.2).
2. **Relayed envelopes lack recipient-side forward secrecy** (§1.6).
3. **The vault leaks the social graph and its trust state can be edited**
   (§4.1, §4.2).
4. **Nothing here has been checked by an outside reviewer**, and the category
   of flaw that broke Telegram, Threema and Matrix — errors in composition —
   is exactly the category internal review is worst at finding (§1.3).

The planned fixes for 1–3 are in `TRUST-ARCHITECTURE.md`. There is no
substitute for 4.

If you know of a published attack that belongs here and is missing, or you
believe an "Addressed" entry is wrong, please open a security advisory
(`SECURITY.md`).
