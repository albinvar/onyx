//! Local API protocol between the `onyx` CLI and the `onyxd` daemon.
//!
//! ## Why a local socket
//!
//! `onyxd` holds the only copy of the unlocked vault, the long-term
//! identity keys, the MLS group state, and the Tor circuit. The
//! `onyx` CLI is intentionally stateless — it dials a Unix domain
//! socket, asks the daemon to do something on its behalf, and exits.
//! This keeps secrets in exactly one process and lets the daemon run
//! detached (tmux, systemd, login-item, whatever) without the user
//! having to keep a TUI open.
//!
//! ## Wire format: newline-delimited JSON
//!
//! One JSON object per line. Chosen over CBOR because the primary
//! debugger of this layer for the next few months is going to be the
//! shell — `nc -U ./onyxd.sock | jq` should "just work". The wire
//! format between *daemons* is still CBOR over Noise; this is only
//! the local control channel.
//!
//! Tags use `serde(tag = "kind")` so every line is self-describing:
//!
//! ```json
//! {"kind":"Status"}
//! ```
//!
//! responds with
//!
//! ```json
//! {"kind":"StatusOk","api_version":1,"daemon_version":"0.0.1",
//!  "identity_pub_b32":"...","fingerprint":"...","tor_state":"ready"}
//! ```
//!
//! ## v0 scope
//!
//! Every request gets exactly one response. No multiplexing, no
//! request IDs, no streaming, no event push. Those come later when
//! we add `send` / `tail` / `subscribe`. The current minimal set
//! exists to prove the plumbing and let `onyx status` work.
//!
//! Authentication is **file-permission-based**: `onyxd` chmods the
//! socket to `0600` after binding, so only the daemon's UID can
//! connect. No tokens, no challenge — and no SO_PEERCRED check yet
//! (we trust the kernel's permission enforcement). This matches the
//! threat model: an attacker who can read your socket can already
//! read your vault.

use serde::{Deserialize, Serialize};

/// API protocol version. Bumped whenever a request/response shape
/// changes incompatibly. The client compares this to the version it
/// was built with and refuses to talk to a daemon that returns a
/// different number.
pub const API_VERSION: u16 = 1;

/// Default Unix-domain socket path. Both daemon and CLI use this if
/// neither `--api-socket` nor `ONYX_API_SOCKET` is set.
///
/// Lives in the current working directory rather than `$XDG_RUNTIME_DIR`
/// or `$TMPDIR` to keep paths short (macOS's `sun_path` is capped at
/// 104 bytes and `/var/folders/...` already eats half of that) and
/// to make it obvious to the operator where the socket is.
pub const DEFAULT_SOCKET_PATH: &str = "./onyxd.sock";

/// One request line on the wire (client → daemon).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum ApiRequest {
    /// Liveness + identity + Tor state in one round-trip.
    Status,
    /// Just the local identity (pub key + fingerprint).
    Identity,
    /// Snapshot of currently-known conversations (live + recently
    /// disconnected). Returns [`ApiResponse::PeersOk`].
    Peers,
    /// Send `text` into the conversation identified by `peer_short`
    /// (the 8-char id from [`PeerInfo::short_id`]). The daemon will
    /// MLS-encrypt and frame it on the peer's Noise session.
    Send { peer_short: String, text: String },
    /// Subscribe to all conversation events. The server responds with
    /// [`ApiResponse::TailStarted`] and then keeps pushing
    /// `Event…` response lines until the client closes the socket.
    /// After issuing `Tail`, the client **must not** send further
    /// requests on the same connection — open another one for that.
    Tail,
    /// Fetch up to `limit` most recent messages from the per-peer
    /// ring buffer. Used by clients to backfill scrollback after a
    /// restart or after a tail subscription reconnects. Returns
    /// [`ApiResponse::HistoryOk`].
    History { peer_short: String, limit: u32 },
    /// First-contact send via the hub. Constructs a sealed-sender
    /// envelope (PQ-hybrid X25519 + ML-KEM-768) carrying a
    /// `BootstrapPayload::PlainMessage` and ships it to the
    /// recipient's introduction-inbox routing id over the active
    /// hub session. Requires the daemon to have been launched with
    /// `--hub-onion` + `--hub-pubkey`.
    ///
    /// **Security tier note.** Messages sent this way have **per-
    /// message forward secrecy only** (via the ephemeral hybrid
    /// encapsulation). They do **not** have MLS post-compromise
    /// security — a future variant (`v: mls/v1`) will carry an MLS
    /// Welcome to upgrade to a ratcheted group. Until that lands the
    /// TUI should render hub-relayed messages with explicit visual
    /// distinction from direct-MLS ones.
    ///
    /// `peer_fingerprint` is the base32-grouped form printed by
    /// `onyx identity`; `peer_kem_pub_b32` is the b32 of the peer's
    /// hybrid KEM public.
    SendBootstrap {
        peer_fingerprint: String,
        peer_kem_pub_b32: String,
        text: String,
    },
    /// **MLS-tier** first-contact send via the hub. Constructs a fresh
    /// 2-party MLS group with self + the named peer (using the peer's
    /// supplied KeyPackage), wraps the resulting Welcome in a
    /// `BootstrapPayload::MlsWelcome` (`v: mls/v1`) sealed-sender
    /// envelope, and ships it to the recipient's introduction-inbox
    /// routing id over the hub.
    ///
    /// After the recipient comes online and decodes the envelope,
    /// both sides share an MLS group with full post-compromise
    /// security on every subsequent application message exchanged in
    /// that group — a strict upgrade over [`Self::SendBootstrap`]'s
    /// `msg/v1` tier.
    ///
    /// **What the recipient needs out-of-band**: the sender's
    /// fingerprint (to authenticate the sealed envelope's outer
    /// signature). What the *sender* needs:
    ///   * `peer_fingerprint` — to compute the recipient's
    ///     introduction-inbox routing id.
    ///   * `peer_kem_pub_b32` — to seal under the recipient's hybrid
    ///     KEM public key.
    ///   * `peer_kp_b64` — the recipient's MLS KeyPackage bytes,
    ///     base64-encoded. The daemon validates the KP's embedded
    ///     Ed25519 signing key against `peer_fingerprint` before
    ///     inviting (defends against a hostile hub that swapped a
    ///     different KP into the directory).
    ///
    /// Requires `--hub-onion` + `--hub-pubkey`.
    SendBootstrapMls {
        peer_fingerprint: String,
        peer_kem_pub_b32: String,
        peer_kp_b64: String,
        /// Optional plaintext "introduction" message to ride along
        /// with the MLS Welcome (T7.2-mls-fu). When `Some`, the
        /// recipient renders it as the first message of the new
        /// conversation — same as if you'd immediately followed the
        /// Welcome with an app-level message — instead of a synthetic
        /// "joined MLS group X" placeholder. `None` keeps the original
        /// T6.x behaviour. `#[serde(default)]` so older API clients
        /// that don't know about the field still parse cleanly.
        #[serde(default)]
        initial_text: Option<String>,
    },
    /// Fetch the latest published MLS KeyPackage for the named peer
    /// from the hub's directory (T6.1) over the daemon's existing
    /// hub session. The daemon validates the returned KP's embedded
    /// Ed25519 signing key against `peer_fingerprint` before
    /// surfacing it (defends `THREAT_MODEL.md` §8.2 #15 attack
    /// where a hostile hub directory swaps an attacker's KP under
    /// the target's routing id).
    ///
    /// Returns [`ApiResponse::FetchPeerKeyPackageOk`] with the KP
    /// bytes in base64, or [`ApiResponse::Error`] with code:
    ///   * `Malformed` — fingerprint won't parse, or returned KP
    ///     doesn't validate against it.
    ///   * `NotReady` — no hub configured, or hub responded
    ///     "not found" (peer hasn't published yet).
    ///   * `Internal` — hub session ended before responding.
    ///
    /// Requires `--hub-onion` + `--hub-pubkey`.
    FetchPeerKeyPackage { peer_fingerprint: String },
    /// Export a freshly-minted MLS KeyPackage for *our own* identity,
    /// so the CLI can bundle it into an invite URL (T7.2-mls).
    ///
    /// Each call mints a *new* KP from the persistent `MlsParty`
    /// (`MlsParty::key_package_bytes()`). KPs are single-use in MLS —
    /// the recipient consumes it when they call `SendBootstrapMls`
    /// against it — so don't share the same exported KP with two peers
    /// expecting both to succeed.
    ///
    /// Returns [`ApiResponse::ExportKeyPackageOk`] with the KP bytes
    /// in standard base64 (same shape as [`Self::FetchPeerKeyPackage`]
    /// returns). Does **not** require a hub: this is a purely local
    /// operation against the daemon's own MLS state. Useful when you
    /// want to share an invite URL out-of-band (Signal, in person)
    /// without exposing your KP via the hub directory.
    ExportKeyPackage,
    /// Create a new multi-party room with just us as the sole member
    /// (T6.3.b). Subsequent `InviteToRoom` calls add members via the
    /// existing T7.2-mls hub path. `name` is a local-only display
    /// label; it does not propagate over the wire. Returns
    /// [`ApiResponse::CreateRoomOk`] with the new room's MLS
    /// `group_id` in base32 — the cryptographic identity of the
    /// room (the name is just a label).
    ///
    /// Two rooms can share a name locally — the daemon disambiguates
    /// by `group_id` everywhere; the name is for the TUI's benefit.
    CreateRoom { name: String },
    /// List every room this daemon participates in (T6.3.b). Returns
    /// [`ApiResponse::ListRoomsOk`] with one [`RoomInfo`] per room,
    /// ordered by `created_at_ms` ascending (older first).
    ListRooms,
    /// List every pinned contact (T-1 TOFU key pinning). Returns
    /// [`ApiResponse::ListContactsOk`] with one [`ContactInfo`] per
    /// peer whose identity key we've pinned, newest contact first.
    /// Powers `onyx contact list`.
    ListContacts,
    /// T-2: build a **signed** invite URL (`onyx://invite/v2?…`),
    /// minted by the daemon so the inviter's Ed25519 identity key
    /// signs the canonical invite bytes (fingerprint + KEM + optional
    /// KP + optional hub list + expiry + nonce). The signature lets
    /// the recipient detect partial tampering on the side-channel
    /// (swapped KEM, KP, or hubs); it does NOT defeat full-invite
    /// substitution by a first-contact MITM (mitigated by OOB
    /// fingerprint verification + T-1 pinning).
    ///
    /// `with_kp` includes a fresh MLS KeyPackage (MLS-tier accept).
    /// `with_hubs` includes the daemon's configured hub list (T8.2
    /// transparency). `ttl_secs` overrides the default invite TTL;
    /// `None` means the daemon's default (30 days).
    BuildInvite {
        with_kp: bool,
        with_hubs: bool,
        ttl_secs: Option<u64>,
    },
    /// T-2: send a first-contact message addressed by an invite URL,
    /// with **daemon-side** trust gates. The daemon parses the URL,
    /// verifies the v2 signature (or refuses unsigned v1 unless
    /// `insecure_accept_unsigned` is true), cross-checks the
    /// fingerprint against the TOFU pin store (T-1), and dispatches
    /// internally to either the MLS-tier (when the invite carries a
    /// KeyPackage) or the msg/v1 (PFS-only) path.
    ///
    /// **This is the trust-anchored entry point.** Direct callers of
    /// the lower-level `SendBootstrap` / `SendBootstrapMls` verbs
    /// pass individual fields and therefore bypass the signature +
    /// pin checks; new code MUST use `SendInvite` so a malicious
    /// local process speaking to the API socket cannot strip the
    /// signature by hand.
    SendInvite {
        url: String,
        text: String,
        /// **DANGEROUS, default off.** Accept an unsigned v1 invite;
        /// otherwise the daemon refuses (see CLI doc for the same
        /// flag on `onyx accept`).
        insecure_accept_unsigned: bool,
    },
    /// Invite `peer` into the existing room identified by
    /// `group_id_b32` (T6.3.c). The daemon loads the persisted MLS
    /// group, calls `MlsGroupState::invite` against the peer's
    /// validated KeyPackage, wraps the resulting Welcome in a
    /// `BootstrapPayload::MlsWelcome` (`v: mls/v1`) sealed-sender
    /// envelope **with `room_name = Some(name)` set so the recipient
    /// surfaces a room and not a DM**, and fans out across all
    /// configured hubs.
    ///
    /// SECURITY: same fingerprint↔KP-signing-key validation as
    /// [`Self::SendBootstrapMls`] applies — refuses to add a member
    /// whose KP signing key does not hash to the supplied
    /// `peer_fingerprint` (defends `THREAT_MODEL.md` §8.2 #15: a
    /// hostile hub directory could otherwise swap an attacker's KP
    /// under the target's routing id).
    ///
    /// Requires `--hub onion:port,b32pubkey`. After a successful
    /// commit, the room's cached `members_b32` is refreshed in the
    /// vault with the new member's fingerprint included.
    InviteToRoom {
        group_id_b32: String,
        peer_fingerprint: String,
        peer_kem_pub_b32: String,
        peer_kp_b64: String,
    },
    /// Forget a room locally (T-polish.1). Drops the `rooms` row,
    /// the `room_member_kems` rows for that room, and the underlying
    /// MLS group state. Does **not** notify other members — they
    /// keep their copy of the group with you as a still-listed
    /// member who will simply never decrypt anything you send. For
    /// a clean leave that informs the other members, use
    /// [`Self::LeaveRoom`] instead.
    ///
    /// Idempotent — `Ok` even if no row matched.
    DeleteRoom { group_id_b32: String },
    /// Rename a room locally (T-polish.1). Pure-metadata update on
    /// `rooms.name`. Doesn't propagate to other members — each
    /// member's local name is independent (`CHANNELS.md §2`).
    /// Idempotent (returns `Ok` even if the name was already that
    /// value).
    RenameRoom {
        group_id_b32: String,
        new_name: String,
    },
    /// Send a file to every member of a room (T-files.d). The
    /// daemon reads `path`, sanitizes it per `FILES.md §3`
    /// (strips metadata + computes content_hash), chunks the
    /// cleaned bytes (12 KB each by default), and fans out a
    /// `FileMeta` followed by N `FileChunk` MLS messages via
    /// the existing room channel.
    ///
    /// `keep_filename`: false (default) renames to a hash-prefixed
    /// sanitized name; true preserves the original name (sanitized).
    /// `keep_metadata`: false (default) refuses to send formats
    /// Onyx can't safely strip; true bypasses the strip and
    /// passes raw bytes through with the leak documented at
    /// `FILES.md §3.2`.
    ///
    /// Per-file size cap enforced from `FilesConfig.max_send_size_bytes`
    /// (default 50 MB). Exceeded → `ApiResponse::Error`.
    SendFileToRoom {
        group_id_b32: String,
        path: String,
        #[serde(default)]
        keep_filename: bool,
        #[serde(default)]
        keep_metadata: bool,
    },
    /// Send a file to a directly-connected DM peer (task 322). Same
    /// sanitize + chunk pipeline as `SendFileToRoom`, but the frames
    /// ride the peer's DM MLS group. Requires a live conversation with
    /// the peer (direct-only — no hub fallback for DM files in v1).
    SendFileToPeer {
        peer_short: String,
        path: String,
        #[serde(default)]
        keep_filename: bool,
        #[serde(default)]
        keep_metadata: bool,
    },
    /// List files received from peers / in rooms (T-files.d). Returns
    /// most-recent-first. `conversation` is `peer/<short>` for DMs
    /// or `room/<short_b32>` for rooms.
    ListReceivedFiles { conversation: String, limit: u32 },
    /// Fetch the persisted scrollback for a room (T-polish.3).
    /// Returns up to `limit` most recent messages oldest → newest
    /// — same shape as [`Self::History`] for DMs. Empty Vec when
    /// the room is unknown or has no messages yet.
    RoomHistory { group_id_b32: String, limit: u32 },
    /// Leave a room cleanly (T-polish.2). The daemon produces an
    /// MLS `Remove` commit removing ourselves, fans the commit out
    /// to every other current member, and then drops the local
    /// `rooms` row + `room_member_kems` + MLS group state. Other
    /// members will see their roster shrink and continue without
    /// us.
    ///
    /// Requires `--hub` (the Remove commit fans out the same way
    /// as an Add commit in [`Self::InviteToRoom`]).
    LeaveRoom { group_id_b32: String },
    /// Remove (kick) another member from a room (task 325). The
    /// daemon issues an MLS `Remove` commit evicting the member whose
    /// fingerprint is `peer_fingerprint`, fans the commit out to all
    /// current members (incl. the evicted one, so it learns), advances
    /// the epoch, and updates the local roster. Requires `--hub`.
    /// `peer_fingerprint` is the base32-grouped form shown in the
    /// Details roster / `room list`.
    RemoveFromRoom {
        group_id_b32: String,
        peer_fingerprint: String,
    },
    /// Send `text` to every current member of the room identified
    /// by `group_id_b32` (T6.3.d, direct path only). The daemon
    /// encrypts the plaintext **once** in the room's MLS group
    /// state, then pushes the resulting ciphertext into every room
    /// member's live direct Noise session.
    ///
    /// Members without a live direct session are skipped on this
    /// path — T6.3.e adds the hub-fallback path so offline / hub-
    /// only members still receive the message. The response
    /// reports how many members were reached vs total so the
    /// caller can warn that some members will only get the message
    /// via T6.3.e once it ships.
    ///
    /// Returns [`ApiResponse::SendRoomOk`] on success even when
    /// `delivered_to_direct == 0` — encrypting succeeded and the
    /// sender's own MLS ratchet has advanced; the message exists
    /// cryptographically even if nobody picked it up on the wire.
    /// (Re-sending wastes a ratchet step; caller is expected to
    /// surface the count and let the user decide.)
    SendRoom { group_id_b32: String, text: String },
}

/// One response line on the wire (daemon → client).
///
/// For every request kind other than [`ApiRequest::Tail`], the daemon
/// produces **exactly one** response line and then waits for the
/// next request. `Tail` is the lone streaming verb: after the
/// initial [`ApiResponse::TailStarted`] line, the daemon may emit
/// any number of `Event…` lines until the client closes the socket.
/// No request IDs / multiplexing — open more sockets if you want
/// concurrent reads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum ApiResponse {
    // ── one-shot responses ──────────────────────────────────────────
    /// Reply to [`ApiRequest::Status`].
    StatusOk {
        api_version: u16,
        daemon_version: String,
        identity_pub_b32: String,
        fingerprint: String,
        tor_state: TorState,
        /// Hybrid (X25519 ‖ ML-KEM-768) KEM public key, base32.
        ///
        /// **Length note**: the underlying bytes are
        /// `HYBRID_PUBLIC_LEN = 1216` bytes (32 + 1184); base32 with
        /// no padding encodes that to ~1948 characters. It looks
        /// alarming on stdout but it isn't a typo — that's the
        /// real on-the-wire size of an ML-KEM-768 encapsulation key.
        ///
        /// Used by senders to address sealed-sender envelopes to
        /// this identity. Safe to publish.
        identity_kem_pub_b32: String,
    },
    /// Reply to [`ApiRequest::Identity`].
    IdentityOk {
        identity_pub_b32: String,
        fingerprint: String,
        /// See [`Self::StatusOk::identity_kem_pub_b32`] for the
        /// length-and-encoding caveat.
        identity_kem_pub_b32: String,
        /// Hubs the daemon currently publishes to and subscribes
        /// on (T8.2+). Each entry is `onion:port,b32pubkey` — the
        /// same shape as the daemon's `--hub` flag. Empty when the
        /// daemon has no hubs configured. `#[serde(default)]` for
        /// wire back-compat with pre-T8.2 daemons.
        #[serde(default)]
        hubs: Vec<String>,
    },
    /// Reply to [`ApiRequest::Peers`].
    PeersOk { entries: Vec<PeerInfo> },
    /// Reply to [`ApiRequest::Send`].
    SendOk,
    /// Reply to [`ApiRequest::History`]. Messages are ordered oldest
    /// → newest. May be shorter than `limit` if fewer messages exist
    /// (or empty if the peer has no exchanged messages yet).
    HistoryOk {
        peer_short: String,
        messages: Vec<HistoryEntry>,
    },
    /// Reply to [`ApiRequest::SendBootstrap`]. The envelope was
    /// constructed and accepted into the hub's outbound queue;
    /// delivery confirmation arrives later (out-of-band) when the
    /// recipient comes online — there is no synchronous ack.
    SendBootstrapOk,
    /// Reply to [`ApiRequest::SendBootstrapMls`]. The new MLS group
    /// is fully established on our side; `group_id_b32` is the
    /// group's stable identifier (echo of `MlsGroupState::group_id_bytes`
    /// in base32). The Welcome envelope has been pushed to the hub;
    /// the recipient will join the group the moment they decode it.
    SendBootstrapMlsOk { group_id_b32: String },
    /// Reply to [`ApiRequest::FetchPeerKeyPackage`] on success.
    /// `kp_b64` is the standard-base64 encoding of the raw MLS
    /// KeyPackage bytes — the same shape `SendBootstrapMls` expects
    /// for its `peer_kp_b64` argument.
    FetchPeerKeyPackageOk { kp_b64: String },
    /// Reply to [`ApiRequest::ExportKeyPackage`]. `kp_b64` is the
    /// standard-base64 encoding of a freshly-minted KeyPackage for
    /// our own MLS party. Re-encode as base64url and put into an
    /// invite URL's `kp` query parameter to enable MLS-tier first
    /// contact.
    ExportKeyPackageOk { kp_b64: String },
    /// Reply to [`ApiRequest::CreateRoom`]. `group_id_b32` is the
    /// MLS group's stable identifier in base32 — this IS the
    /// room's cryptographic identity (the name is just a local
    /// label). `name` echoes back what the caller passed.
    CreateRoomOk { group_id_b32: String, name: String },
    /// Reply to [`ApiRequest::ListRooms`]. `rooms` is ordered by
    /// `created_at_ms` ascending (older first).
    ListRoomsOk { rooms: Vec<RoomInfo> },
    /// Reply to [`ApiRequest::ListContacts`]. `contacts` is ordered by
    /// most-recent contact first.
    ListContactsOk { contacts: Vec<ContactInfo> },
    /// Reply to [`ApiRequest::BuildInvite`]. `url` is the full
    /// `onyx://invite/v2?…` string. `exp_ms` echoes the expiry the
    /// daemon stamped into the signature so the caller can display
    /// "valid until …" without re-parsing the URL. `hubs_attached` is
    /// the number of hub entries embedded in the URL (`0` when
    /// `with_hubs` was false OR when the daemon has none configured —
    /// the CLI uses this to warn the operator).
    BuildInviteOk {
        url: String,
        exp_ms: u64,
        hubs_attached: usize,
    },
    /// Reply to [`ApiRequest::SendInvite`]. `tier` is `"mls/v1"` when
    /// the daemon used MLS-tier bootstrap (invite had a KP), or
    /// `"msg/v1"` for the PFS-only path. `was_signed` lets the CLI
    /// surface the trust-gate result without having to re-parse the
    /// URL (true = v2 signature verified; false = unsigned v1
    /// accepted under `insecure_accept_unsigned`).
    SendInviteOk { tier: String, was_signed: bool },
    /// Reply to [`ApiRequest::InviteToRoom`] on success. `group_id_b32`
    /// echoes the room's stable identifier; `members` is the room's
    /// refreshed member-fingerprint list AFTER the invite commit
    /// (one entry per current member, fingerprint in the same
    /// `onyx identity`-printed form). Delivery to the recipient is
    /// asynchronous — they join the moment they decode the Welcome.
    InviteToRoomOk {
        group_id_b32: String,
        members: Vec<String>,
    },
    /// Reply to [`ApiRequest::RemoveFromRoom`] (task 325). `members`
    /// is the roster AFTER the remove commit (the evicted member is
    /// gone).
    RemoveFromRoomOk {
        group_id_b32: String,
        members: Vec<String>,
    },
    /// Reply to [`ApiRequest::SendFileToRoom`] (T-files.d). The file
    /// was sanitized + chunked + fanned out. Per-call delivery stats
    /// mirror the [`Self::SendRoomOk`] shape; `file_id_b32` is the
    /// 16-byte random transfer id from the FileMeta (useful for
    /// correlating later events).
    SendFileToRoomOk {
        group_id_b32: String,
        file_id_b32: String,
        size: u64,
        mime: String,
        stripped_metadata: bool,
        chunks: u32,
        delivered_to_direct: u32,
        #[serde(default)]
        delivered_to_hub: u32,
        #[serde(default)]
        skipped_no_kem: u32,
        total_members: u32,
    },
    /// Reply to [`ApiRequest::SendFileToPeer`] (task 322). The file was
    /// sanitized + chunked + sent over the peer's DM MLS group.
    SendFileToPeerOk {
        peer_short: String,
        file_id_b32: String,
        size: u64,
        mime: String,
        stripped_metadata: bool,
        chunks: u32,
    },
    /// Reply to [`ApiRequest::ListReceivedFiles`] (T-files.d).
    ListReceivedFilesOk {
        conversation: String,
        files: Vec<ReceivedFileInfo>,
    },
    /// Reply to [`ApiRequest::RoomHistory`] (T-polish.3). Messages
    /// are oldest → newest. May be shorter than `limit` if fewer
    /// messages exist (or empty if the room has none).
    RoomHistoryOk {
        group_id_b32: String,
        messages: Vec<RoomHistoryEntry>,
    },
    /// Reply to [`ApiRequest::DeleteRoom`] and
    /// [`ApiRequest::RenameRoom`] (T-polish.1). Pure-local
    /// operations; no on-the-wire side effect.
    RoomOpOk,
    /// Reply to [`ApiRequest::LeaveRoom`] (T-polish.2). `members`
    /// is the pre-leave roster (the count of other members the
    /// Remove commit was fanned out to).
    LeaveRoomOk { group_id_b32: String, members: u32 },
    /// Reply to [`ApiRequest::SendRoom`]. Per-call delivery stats:
    ///
    ///   * `delivered_to_direct` — members reached over a live
    ///     direct Noise session (one-shot push of the same MLS
    ///     ciphertext).
    ///   * `delivered_to_hub` (T6.3.e) — members the daemon
    ///     hub-fanned-out a sealed `BootstrapPayload::MlsApp` to
    ///     because they had no live direct session.
    ///   * `skipped_no_kem` (T6.3.e) — members with no live
    ///     session AND no cached hybrid KEM pub (a structural gap
    ///     for non-inviters until KEM-pub exchange ships). These
    ///     won't receive the message via this call.
    ///   * `total_members` — the room's full member count, *after*
    ///     excluding ourselves.
    SendRoomOk {
        group_id_b32: String,
        delivered_to_direct: u32,
        #[serde(default)]
        delivered_to_hub: u32,
        #[serde(default)]
        skipped_no_kem: u32,
        total_members: u32,
    },

    // ── streaming-mode ack + events (Tail only) ─────────────────────
    /// Initial ack of [`ApiRequest::Tail`]. Tells the client the
    /// daemon will now push events on this connection.
    TailStarted,
    /// An application message decrypted from `peer_short`'s
    /// conversation. `direction` distinguishes incoming from
    /// echo-of-our-own-send. `ts_unix_ms` is the daemon's wall clock
    /// at the moment of processing — not the sender's clock.
    ///
    /// `via_hub` is `true` when the message arrived via the hub
    /// (sealed-sender envelope, `BootstrapPayload::PlainMessage`).
    /// Such messages have **per-message PFS only** — no MLS PCS —
    /// so the TUI should render them visibly differently
    /// (T5.2.f). Default `false` (older daemons + direct-MLS path)
    /// via `#[serde(default)]` for wire-format backwards-compat.
    EventMessage {
        peer_short: String,
        direction: MessageDirection,
        text: String,
        ts_unix_ms: u64,
        #[serde(default)]
        via_hub: bool,
    },
    /// A new conversation was registered with the daemon (a peer
    /// dialled in, or `onyxd --dial-*` finished its handshake).
    EventPeerConnected { peer: PeerInfo },
    /// A conversation was torn down (peer closed the stream, dial
    /// session ended, etc.). The conversation handle is gone from
    /// the registry; the client should mark the row stale.
    EventPeerDisconnected { peer_short: String },

    // ── error ───────────────────────────────────────────────────────
    /// Catch-all error. The client matches on `code` for programmatic
    /// handling and shows `message` to the user.
    Error { code: ApiErrorCode, message: String },
}

/// One row in `PeersOk`. Mirrors what the daemon's conversation
/// registry holds for each live or recently-active peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerInfo {
    /// 8-char base32 prefix of the peer's X25519 identity public key.
    /// Used as a stable user-facing handle in `Send { peer_short }`
    /// and in event lines.
    pub short_id: String,
    /// Full base32 of the peer's X25519 identity public key.
    pub pubkey_b32: String,
    /// Peer's identity fingerprint (Ed25519 signing key, base32-grouped).
    pub fingerprint: String,
    /// Whether the peer's Noise session is still open. `false` means
    /// the conversation row is just history; new `Send`s will fail.
    pub connected: bool,
    /// `Some(text_preview)` for the most recent message, `None` if
    /// nothing has been exchanged yet.
    pub last_message_preview: Option<String>,
    /// Daemon wall clock (ms since UNIX epoch) of the last activity.
    pub last_active_unix_ms: u64,
}

/// One past message in a [`ApiResponse::HistoryOk`] reply.
///
/// Shape matches the daemon's internal `ChatLine` exactly so the
/// `HistoryOk` builder can map the ring buffer 1:1.
///
/// `via_hub` mirrors [`ApiResponse::EventMessage::via_hub`] — `true`
/// if the message arrived via the hub (weaker forward-secrecy
/// properties; see `SECURITY.md` §6.1). `#[serde(default)]` so a
/// daemon that doesn't know about the field returns `false` and
/// the wire shape stays backwards-compatible.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryEntry {
    pub direction: MessageDirection,
    pub text: String,
    pub ts_unix_ms: u64,
    #[serde(default)]
    pub via_hub: bool,
}

/// One row in [`ApiResponse::ListRoomsOk`]. The daemon's
/// projection of its internal `Room` state into the API-level
/// shape clients consume (T6.3.b).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoomInfo {
    /// User-supplied display label. Local-only — each member can
    /// call the same MLS group whatever they like; the name does
    /// NOT propagate over the wire.
    pub name: String,
    /// Stable MLS GroupId, base32. This IS the room's
    /// cryptographic identity; the name is just a label.
    pub group_id_b32: String,
    /// Current members' fingerprints, base32-grouped (the same
    /// shape `onyx identity` prints). Includes us. Refreshed on
    /// every successful MLS commit (invite/remove).
    pub members: Vec<String>,
    /// Daemon wall-clock at room creation. Used by clients to
    /// sort the room list; not authoritative across members.
    pub created_at_ms: u64,
}

/// One row in [`ApiResponse::ListContactsOk`] (T-1 TOFU key pinning).
/// One per peer whose identity key we've pinned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactInfo {
    /// Peer Ed25519 fingerprint (the identity), base32-grouped.
    pub fingerprint: String,
    /// X25519 identity key pinned at first contact, base32.
    pub x25519_pub_b32: String,
    /// Wall-clock (ms) of first contact.
    pub first_seen_ms: u64,
    /// Wall-clock (ms) of most recent contact.
    pub last_seen_ms: u64,
    /// `true` if a key different from the pinned one was ever presented
    /// — a key rotation or a man-in-the-middle. The user should
    /// re-verify the fingerprint out of band.
    pub key_changed: bool,
}

/// One row in [`ApiResponse::RoomHistoryOk`] (T-polish.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoomHistoryEntry {
    pub direction: MessageDirection,
    /// Sender fingerprint as a string (base32-grouped). For
    /// outgoing messages this is the local identity's fingerprint;
    /// for incoming it's the decoded sender from MLS.
    pub sender_fp: String,
    pub text: String,
    pub ts_unix_ms: u64,
}

/// One row in [`ApiResponse::ListReceivedFilesOk`] (T-files.d).
/// Projection of the vault's `received_files` row to the API
/// surface; `path` is the absolute filesystem path the receiver
/// can shell-`cat` / `open`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceivedFileInfo {
    pub sender_fp: String,
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub content_hash_b32: String,
    pub path: String,
    pub received_at_ms: u64,
}

/// Direction of an [`ApiResponse::EventMessage`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageDirection {
    /// Decrypted from the peer — show as "them".
    Incoming,
    /// Echo of a message the local user just sent — show as "me".
    Outgoing,
}

/// Coarse-grained Tor lifecycle states reported via [`ApiResponse::StatusOk`].
///
/// v0 only distinguishes "running with Tor" from "running without
/// Tor". Granular bootstrap progress, retry-after-failure, etc. will
/// add variants here without (we hope) breaking existing clients.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TorState {
    /// `--no-tor` was passed; the daemon is online but not anonymising.
    Disabled,
    /// Arti is bootstrapped and the hidden service has been requested.
    Ready,
}

/// Programmatic error classes returned in [`ApiResponse::Error`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApiErrorCode {
    /// The request `kind` is unknown to this daemon — usually a
    /// CLI built against a newer API version than the running daemon.
    UnknownRequest,
    /// The request was understood but couldn't be served right now
    /// (e.g. Tor not yet bootstrapped). Retryable.
    NotReady,
    /// An internal daemon error. The `message` has the details. The
    /// CLI should generally surface the message verbatim.
    Internal,
    /// The request line was malformed JSON or otherwise unparseable.
    /// Always non-retryable.
    Malformed,
}

/// Encode a request as a single NDJSON line, including the trailing newline.
pub fn encode_request_line(req: &ApiRequest) -> Result<String, serde_json::Error> {
    let mut s = serde_json::to_string(req)?;
    s.push('\n');
    Ok(s)
}

/// Encode a response as a single NDJSON line, including the trailing newline.
pub fn encode_response_line(resp: &ApiResponse) -> Result<String, serde_json::Error> {
    let mut s = serde_json::to_string(resp)?;
    s.push('\n');
    Ok(s)
}

/// Parse one NDJSON request line (without the trailing newline).
pub fn decode_request(line: &str) -> Result<ApiRequest, serde_json::Error> {
    serde_json::from_str(line)
}

/// Parse one NDJSON response line (without the trailing newline).
pub fn decode_response(line: &str) -> Result<ApiResponse, serde_json::Error> {
    serde_json::from_str(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every request variant must round-trip through NDJSON exactly.
    #[test]
    fn request_round_trip_status() {
        let r = ApiRequest::Status;
        let line = encode_request_line(&r).unwrap();
        assert!(line.ends_with('\n'));
        let parsed = decode_request(line.trim_end_matches('\n')).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn request_round_trip_identity() {
        let r = ApiRequest::Identity;
        let line = encode_request_line(&r).unwrap();
        let parsed = decode_request(line.trim_end_matches('\n')).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn response_round_trip_status_ok() {
        let r = ApiResponse::StatusOk {
            api_version: API_VERSION,
            daemon_version: "0.0.1".into(),
            identity_pub_b32: "abcdef".into(),
            fingerprint: "deadbeef".into(),
            tor_state: TorState::Ready,
            identity_kem_pub_b32: "long-b32-string-stand-in".into(),
        };
        let line = encode_response_line(&r).unwrap();
        let parsed = decode_response(line.trim_end_matches('\n')).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn response_round_trip_identity_ok() {
        let r = ApiResponse::IdentityOk {
            identity_pub_b32: "abc".into(),
            fingerprint: "def".into(),
            identity_kem_pub_b32: "long-b32-stand-in".into(),
            hubs: vec!["h1.onion:1,K1".into(), "h2.onion:1,K2".into()],
        };
        let line = encode_response_line(&r).unwrap();
        let parsed = decode_response(line.trim_end_matches('\n')).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn identity_ok_hubs_back_compat() {
        // A pre-T8.2 daemon would not include the `hubs` field in
        // its IdentityOk JSON. New clients must decode that legacy
        // payload as `hubs: vec![]` via `#[serde(default)]`.
        let legacy_wire = "{\"kind\":\"IdentityOk\",\"identity_pub_b32\":\"abc\",\
                           \"fingerprint\":\"def\",\"identity_kem_pub_b32\":\"k\"}";
        let parsed = decode_response(legacy_wire).expect("legacy wire decodes");
        match parsed {
            ApiResponse::IdentityOk { hubs, .. } => {
                assert!(hubs.is_empty(), "missing field must default to empty Vec");
            }
            other => panic!("expected IdentityOk, got {other:?}"),
        }
    }

    // ── T6.3.b: rooms ─────────────────────────────────────────────

    #[test]
    fn request_round_trip_create_room() {
        let r = ApiRequest::CreateRoom {
            name: "my-room".into(),
        };
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn request_round_trip_list_rooms() {
        let r = ApiRequest::ListRooms;
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn response_round_trip_create_room_ok() {
        let r = ApiResponse::CreateRoomOk {
            group_id_b32: "abcd".into(),
            name: "my-room".into(),
        };
        let line = encode_response_line(&r).unwrap();
        assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn response_round_trip_list_rooms_ok() {
        let r = ApiResponse::ListRoomsOk {
            rooms: vec![
                RoomInfo {
                    name: "alpha".into(),
                    group_id_b32: "g1".into(),
                    members: vec!["fp_alice".into(), "fp_bob".into()],
                    created_at_ms: 1000,
                },
                RoomInfo {
                    name: "beta".into(),
                    group_id_b32: "g2".into(),
                    members: vec!["fp_alice".into()],
                    created_at_ms: 2000,
                },
            ],
        };
        let line = encode_response_line(&r).unwrap();
        assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn create_room_wire_shape() {
        let r = ApiRequest::CreateRoom { name: "x".into() };
        let line = encode_request_line(&r).unwrap();
        assert!(
            line.contains("\"kind\":\"CreateRoom\""),
            "wire must carry kind=CreateRoom; got {line:?}"
        );
    }

    // ── T6.3.c: invite-to-room ────────────────────────────────────

    #[test]
    fn request_round_trip_invite_to_room() {
        let r = ApiRequest::InviteToRoom {
            group_id_b32: "groupabc".into(),
            peer_fingerprint: "AAAA-BBBB-CCCC-DDDD-EEEE".into(),
            peer_kem_pub_b32: "kemkemkem".into(),
            peer_kp_b64: "a2V5LXBhY2thZ2U=".into(),
        };
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn response_round_trip_invite_to_room_ok() {
        let r = ApiResponse::InviteToRoomOk {
            group_id_b32: "groupabc".into(),
            members: vec!["fp_alice".into(), "fp_bob".into(), "fp_carol".into()],
        };
        let line = encode_response_line(&r).unwrap();
        assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn invite_to_room_wire_shape() {
        let r = ApiRequest::InviteToRoom {
            group_id_b32: "g".into(),
            peer_fingerprint: "fp".into(),
            peer_kem_pub_b32: "k".into(),
            peer_kp_b64: "p".into(),
        };
        let line = encode_request_line(&r).unwrap();
        assert!(
            line.contains("\"kind\":\"InviteToRoom\""),
            "wire must carry kind=InviteToRoom; got {line:?}"
        );
    }

    // ── T6.3.d: send-to-room (direct path) ────────────────────────

    #[test]
    fn request_round_trip_send_room() {
        let r = ApiRequest::SendRoom {
            group_id_b32: "groupabc".into(),
            text: "hello room".into(),
        };
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn response_round_trip_send_room_ok() {
        let r = ApiResponse::SendRoomOk {
            group_id_b32: "groupabc".into(),
            delivered_to_direct: 2,
            delivered_to_hub: 1,
            skipped_no_kem: 0,
            total_members: 3,
        };
        let line = encode_response_line(&r).unwrap();
        assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn response_send_room_ok_back_compat_pre_t6_3_e() {
        // Older daemons returning SendRoomOk without the new fields
        // (delivered_to_hub, skipped_no_kem) must still decode — both
        // fields default to 0.
        let line =
            r#"{"kind":"SendRoomOk","group_id_b32":"g","delivered_to_direct":2,"total_members":2}"#;
        let parsed = decode_response(line).unwrap();
        match parsed {
            ApiResponse::SendRoomOk {
                delivered_to_hub,
                skipped_no_kem,
                ..
            } => {
                assert_eq!(delivered_to_hub, 0);
                assert_eq!(skipped_no_kem, 0);
            }
            other => panic!("expected SendRoomOk, got {other:?}"),
        }
    }

    #[test]
    fn send_room_wire_shape() {
        let r = ApiRequest::SendRoom {
            group_id_b32: "g".into(),
            text: "t".into(),
        };
        let line = encode_request_line(&r).unwrap();
        assert!(
            line.contains("\"kind\":\"SendRoom\""),
            "wire must carry kind=SendRoom; got {line:?}"
        );
    }

    // ── T-polish.1 + T-polish.2: room CRUD verbs ──────────────────

    #[test]
    fn request_round_trip_delete_room() {
        let r = ApiRequest::DeleteRoom {
            group_id_b32: "groupabc".into(),
        };
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn request_round_trip_rename_room() {
        let r = ApiRequest::RenameRoom {
            group_id_b32: "groupabc".into(),
            new_name: "still-general".into(),
        };
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn request_round_trip_leave_room() {
        let r = ApiRequest::LeaveRoom {
            group_id_b32: "groupabc".into(),
        };
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn response_round_trip_room_op_ok() {
        let r = ApiResponse::RoomOpOk;
        let line = encode_response_line(&r).unwrap();
        assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn response_round_trip_leave_room_ok() {
        let r = ApiResponse::LeaveRoomOk {
            group_id_b32: "g".into(),
            members: 3,
        };
        let line = encode_response_line(&r).unwrap();
        assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
    }

    // ── T-polish.3: persistent room scrollback ────────────────────

    #[test]
    fn request_round_trip_room_history() {
        let r = ApiRequest::RoomHistory {
            group_id_b32: "g".into(),
            limit: 50,
        };
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn response_round_trip_room_history_ok() {
        let r = ApiResponse::RoomHistoryOk {
            group_id_b32: "g".into(),
            messages: vec![
                RoomHistoryEntry {
                    direction: MessageDirection::Incoming,
                    sender_fp: "(peer/abcd1234)".into(),
                    text: "hi room".into(),
                    ts_unix_ms: 1_000,
                },
                RoomHistoryEntry {
                    direction: MessageDirection::Outgoing,
                    sender_fp: "fp_alice".into(),
                    text: "hi back".into(),
                    ts_unix_ms: 1_500,
                },
            ],
        };
        let line = encode_response_line(&r).unwrap();
        assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn response_round_trip_error_each_code() {
        for code in [
            ApiErrorCode::UnknownRequest,
            ApiErrorCode::NotReady,
            ApiErrorCode::Internal,
            ApiErrorCode::Malformed,
        ] {
            let r = ApiResponse::Error {
                code,
                message: "test".into(),
            };
            let line = encode_response_line(&r).unwrap();
            let parsed = decode_response(line.trim_end_matches('\n')).unwrap();
            assert_eq!(parsed, r);
        }
    }

    /// The wire format must be stable and human-readable; assert the
    /// literal JSON for one variant so accidental tag-renames break
    /// loudly.
    #[test]
    fn status_request_wire_shape() {
        let line = encode_request_line(&ApiRequest::Status).unwrap();
        assert_eq!(line, "{\"kind\":\"Status\"}\n");
    }

    #[test]
    fn tor_state_wire_shape() {
        // Lowercase via `serde(rename_all="snake_case")`.
        let s = serde_json::to_string(&TorState::Disabled).unwrap();
        assert_eq!(s, "\"disabled\"");
        let s = serde_json::to_string(&TorState::Ready).unwrap();
        assert_eq!(s, "\"ready\"");
    }

    #[test]
    fn request_round_trip_peers() {
        let r = ApiRequest::Peers;
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn request_round_trip_send() {
        let r = ApiRequest::Send {
            peer_short: "u5lhmxps".into(),
            text: "hello bob".into(),
        };
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn request_round_trip_tail() {
        let r = ApiRequest::Tail;
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn response_round_trip_peers_ok() {
        let r = ApiResponse::PeersOk {
            entries: vec![PeerInfo {
                short_id: "u5lhmxps".into(),
                pubkey_b32: "u5lhmxpsxxxx".into(),
                fingerprint: "fpr".into(),
                connected: true,
                last_message_preview: Some("hi".into()),
                last_active_unix_ms: 1_700_000_000_000,
            }],
        };
        let line = encode_response_line(&r).unwrap();
        assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn response_round_trip_send_ok_and_tail_started() {
        for r in [ApiResponse::SendOk, ApiResponse::TailStarted] {
            let line = encode_response_line(&r).unwrap();
            assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
        }
    }

    #[test]
    fn response_round_trip_event_message_both_directions() {
        for direction in [MessageDirection::Incoming, MessageDirection::Outgoing] {
            for via_hub in [false, true] {
                let r = ApiResponse::EventMessage {
                    peer_short: "u5lhmxps".into(),
                    direction,
                    text: "x".into(),
                    ts_unix_ms: 1_700_000_000_001,
                    via_hub,
                };
                let line = encode_response_line(&r).unwrap();
                assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
            }
        }
    }

    /// Wire-format backwards compatibility: an older serializer that
    /// omits the new `via_hub` field still decodes as `via_hub:
    /// false`. Captures the `#[serde(default)]` semantics so a future
    /// PR can't accidentally remove the default and break older
    /// clients still on the wire.
    #[test]
    fn event_message_without_via_hub_defaults_false() {
        let legacy = "{\"kind\":\"EventMessage\",\"peer_short\":\"u5lhmxps\",\
                      \"direction\":\"incoming\",\"text\":\"x\",\"ts_unix_ms\":1}";
        let parsed = decode_response(legacy).expect("decode legacy line");
        match parsed {
            ApiResponse::EventMessage { via_hub, .. } => assert!(!via_hub),
            other => panic!("expected EventMessage, got {other:?}"),
        }
    }

    #[test]
    fn response_round_trip_event_peer_connect_and_disconnect() {
        let connected = ApiResponse::EventPeerConnected {
            peer: PeerInfo {
                short_id: "u5lhmxps".into(),
                pubkey_b32: "u5lhmxpsxxxxxxxxxxxxxxxx".into(),
                fingerprint: "fpr".into(),
                connected: true,
                last_message_preview: None,
                last_active_unix_ms: 1,
            },
        };
        let disconnected = ApiResponse::EventPeerDisconnected {
            peer_short: "u5lhmxps".into(),
        };
        for r in [connected, disconnected] {
            let line = encode_response_line(&r).unwrap();
            assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
        }
    }

    #[test]
    fn request_round_trip_send_bootstrap() {
        let r = ApiRequest::SendBootstrap {
            peer_fingerprint: "6dzx yrut hgez rucw js3g fpdu xggt jn7r ...".into(),
            peer_kem_pub_b32: "verylongbase32stringgoeshere…".into(),
            text: "first contact via hub".into(),
        };
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn response_round_trip_send_bootstrap_ok() {
        let r = ApiResponse::SendBootstrapOk;
        let line = encode_response_line(&r).unwrap();
        assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn request_round_trip_send_bootstrap_mls() {
        let r = ApiRequest::SendBootstrapMls {
            peer_fingerprint: "6dzx yrut hgez rucw ...".into(),
            peer_kem_pub_b32: "longb32stringhere".into(),
            peer_kp_b64: "base64-encoded-mls-key-package-bytes".into(),
            initial_text: None,
        };
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn request_round_trip_send_bootstrap_mls_with_initial_text() {
        let r = ApiRequest::SendBootstrapMls {
            peer_fingerprint: "f".into(),
            peer_kem_pub_b32: "k".into(),
            peer_kp_b64: "p".into(),
            initial_text: Some("hi from the invite URL".into()),
        };
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn send_bootstrap_mls_initial_text_back_compat() {
        // A wire payload from a client predating T7.2-mls-fu would
        // omit the `initial_text` field entirely. New daemons must
        // accept that payload and treat it as `initial_text: None`.
        let legacy_wire = "{\"kind\":\"SendBootstrapMls\",\"peer_fingerprint\":\"f\",\
                           \"peer_kem_pub_b32\":\"k\",\"peer_kp_b64\":\"p\"}";
        let parsed = decode_request(legacy_wire).expect("legacy wire decodes");
        match parsed {
            ApiRequest::SendBootstrapMls { initial_text, .. } => {
                assert!(
                    initial_text.is_none(),
                    "missing field must default to None for back-compat"
                );
            }
            other => panic!("expected SendBootstrapMls, got {other:?}"),
        }
    }

    #[test]
    fn response_round_trip_send_bootstrap_mls_ok() {
        let r = ApiResponse::SendBootstrapMlsOk {
            group_id_b32: "longb32groupid".into(),
        };
        let line = encode_response_line(&r).unwrap();
        assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn request_round_trip_fetch_peer_keypackage() {
        let r = ApiRequest::FetchPeerKeyPackage {
            peer_fingerprint: "6dzx ...".into(),
        };
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn response_round_trip_fetch_peer_keypackage_ok() {
        let r = ApiResponse::FetchPeerKeyPackageOk {
            kp_b64: "base64-encoded-keypackage".into(),
        };
        let line = encode_response_line(&r).unwrap();
        assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn fetch_peer_keypackage_wire_shape() {
        let r = ApiRequest::FetchPeerKeyPackage {
            peer_fingerprint: "f".into(),
        };
        let line = encode_request_line(&r).unwrap();
        assert!(
            line.contains("\"kind\":\"FetchPeerKeyPackage\""),
            "wire must carry kind=FetchPeerKeyPackage; got {line:?}"
        );
    }

    #[test]
    fn send_bootstrap_mls_request_wire_shape() {
        let r = ApiRequest::SendBootstrapMls {
            peer_fingerprint: "f".into(),
            peer_kem_pub_b32: "k".into(),
            peer_kp_b64: "p".into(),
            initial_text: None,
        };
        let line = encode_request_line(&r).unwrap();
        assert!(
            line.contains("\"kind\":\"SendBootstrapMls\""),
            "wire must carry kind=SendBootstrapMls; got {line:?}"
        );
    }

    #[test]
    fn send_bootstrap_request_wire_shape() {
        // Literal-shape assertion: the wire JSON must contain
        // exactly "SendBootstrap" as the kind. Guards against a
        // rename slipping through.
        let r = ApiRequest::SendBootstrap {
            peer_fingerprint: "f".into(),
            peer_kem_pub_b32: "k".into(),
            text: "t".into(),
        };
        let line = encode_request_line(&r).unwrap();
        assert!(
            line.contains("\"kind\":\"SendBootstrap\""),
            "wire format must carry kind=SendBootstrap; got {line:?}"
        );
    }

    #[test]
    fn request_round_trip_history() {
        let r = ApiRequest::History {
            peer_short: "u5lhmxps".into(),
            limit: 50,
        };
        let line = encode_request_line(&r).unwrap();
        assert_eq!(decode_request(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn response_round_trip_history_ok() {
        let r = ApiResponse::HistoryOk {
            peer_short: "u5lhmxps".into(),
            messages: vec![
                HistoryEntry {
                    direction: MessageDirection::Incoming,
                    text: "hi".into(),
                    ts_unix_ms: 1_700_000_000_000,
                    via_hub: false,
                },
                HistoryEntry {
                    direction: MessageDirection::Outgoing,
                    text: "hey".into(),
                    ts_unix_ms: 1_700_000_000_001,
                    via_hub: true,
                },
            ],
        };
        let line = encode_response_line(&r).unwrap();
        assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn response_round_trip_history_ok_empty() {
        let r = ApiResponse::HistoryOk {
            peer_short: "fresh".into(),
            messages: vec![],
        };
        let line = encode_response_line(&r).unwrap();
        assert_eq!(decode_response(line.trim_end_matches('\n')).unwrap(), r);
    }

    #[test]
    fn unknown_request_kind_parses_as_serde_error() {
        let err = decode_request("{\"kind\":\"NonexistentVariant\"}").expect_err("must reject");
        // Just check it failed — exact error message is serde_json's.
        assert!(!err.to_string().is_empty());
    }
}
