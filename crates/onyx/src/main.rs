//! `onyx` — Onyx CLI/TUI client.
//!
//! Stateless client. Connects to a running `onyxd` over the local
//! API socket and asks it to do things on the user's behalf. All
//! long-term secrets — vault, identity, MLS state, Tor circuit —
//! live in `onyxd`, never here.
//!
//! ## v0 subcommands
//!
//! * `onyx` — **(no subcommand)** launches the daemon AND the TUI in
//!   one process. The recommended way to use Onyx interactively. T7.1+
//! * `onyx daemon` — run the daemon work without the TUI (foreground).
//!   Useful for headless use, debug, or running under process supervisors.
//! * `onyx status` — daemon liveness + identity + Tor state.
//! * `onyx identity` — just the identity (public key + fingerprint).
//! * `onyx send-bootstrap` — first-contact send via hub (msg/v1, PFS only).
//! * `onyx send-bootstrap-mls` — first-contact send via hub (mls/v1, full MLS PCS).
//! * `onyx fetch-keypackage` — pull a peer's published KP from the hub directory.
//! * `onyx invite [--with-kp]` — print a shareable `onyx://invite/v1?…`
//!   URL bundling this identity's fingerprint + KEM pubkey. With
//!   `--with-kp`, also bundles a fresh MLS KeyPackage so the accepting
//!   peer gets full PCS on first contact (T7.2 + T7.2-mls).
//! * `onyx accept <url> --text "…"` — parse such a URL and send the
//!   bundled identity a first-contact via the hub. Tier auto-picked
//!   from the URL: MLS if `kp` present, else msg/v1 (T7.2+).
//! * `onyx tui` — open the multi-pane Ratatui interface against an
//!   already-running daemon (won't start one for you — use the
//!   no-subcommand form for that).
//! * `onyx room create --name X` — create a new multi-party room
//!   (T6.3.b). Prints `{ "group_id_b32": "..." }`. Pipe that into
//!   subsequent `room invite` / `room send` calls.
//! * `onyx room list` — list every room this daemon participates in.
//! * `onyx room invite --group-id … --peer-fingerprint … --peer-kem-pub-b32 …
//!   --peer-kp-b64 …` — invite a peer into a room (T6.3.c).
//! * `onyx room send --group-id … --text "…"` — send a plaintext
//!   message to every room member (T6.3.d direct + T6.3.e hub-fallback).
//!   Response reports `delivered_to_direct` / `delivered_to_hub` /
//!   `skipped_no_kem` / `total_members` so you see who got it.
//!
//! ## Planned subcommands (see DESIGN.md §4 + §5)
//!
//!   * `onyx dial <onion> <pubkey>` — start a direct conversation.
//!   * `onyx send <peer> <msg>`     — send into an existing direct conversation.
//!   * `onyx tail <peer>`           — stream messages as they arrive.
//!   * `onyx contact [add|verify|list]`
//!   * `onyx wipe` — zeroize and exit (DESIGN.md §4.2)
//!
//! ## Exit codes
//!
//!   * `0` — request succeeded.
//!   * `1` — usage error or daemon returned [`ApiResponse::Error`].
//!   * `2` — could not connect to the daemon.

mod client;
mod theme;
mod tui;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use onyx_core::api::{ApiRequest, ApiResponse};

#[derive(Parser, Debug)]
#[command(
    name = "onyx",
    version = onyx_core::VERSION,
    about = "Onyx — anonymous E2E-encrypted chat over Tor. Run with no \
             subcommand to launch the daemon + TUI in one process."
)]
struct Args {
    /// Path of the local API socket. Defaults to `~/.onyx/onyx.sock`
    /// (same default as `onyxd --api-socket`). Override here or via
    /// `ONYX_API_SOCKET`.
    #[arg(long, env = "ONYX_API_SOCKET", global = true)]
    socket: Option<PathBuf>,

    /// Path to the encrypted vault file. Only used when this `onyx`
    /// invocation *starts* a daemon (no-subcommand form, or
    /// `onyx daemon`). One-shot CLI commands that talk to an
    /// already-running daemon ignore this flag. Defaults to
    /// `~/.onyx/vault.db` (auto-created with mode 0700).
    #[arg(long, env = "ONYX_VAULT", global = true)]
    vault: Option<PathBuf>,

    /// Vault passphrase. Required when starting a daemon
    /// (no-subcommand form, or `onyx daemon`). Pass via env var
    /// rather than CLI flag so it doesn't show up in `ps`.
    #[arg(long, env = "ONYX_PASSPHRASE", hide_env_values = true, global = true)]
    passphrase: Option<String>,

    /// **TEST-ONLY** local-TCP listen mode for the embedded daemon.
    /// See `onyxd --help` for the full caveat.
    #[arg(long, env = "ONYX_LISTEN_TCP", global = true)]
    listen_tcp: Option<String>,

    /// **TEST-ONLY** local-TCP dial mode for the embedded daemon.
    /// Requires `--dial-pubkey`.
    #[arg(long, env = "ONYX_DIAL_TCP", global = true)]
    dial_tcp: Option<String>,

    /// Peer-to-peer: dial a peer's hidden service **directly** over Tor
    /// (no hub). Value is `<onion>` or `<onion>:<port>` (default port is
    /// the Onyx HS port). Requires `--dial-pubkey` (the peer's X25519
    /// identity key, base32). This is the hub-less direct path: the two
    /// daemons speak Noise XK end-to-end over a dedicated, circuit-
    /// isolated Tor stream. Both peers must be running; there is no
    /// store-and-forward, so the dialled peer has to be online.
    #[arg(long, env = "ONYX_DIAL_ONION", global = true)]
    dial_onion: Option<String>,

    /// X25519 identity public key of the peer to dial (base32).
    /// Required by `--dial-tcp` / `--dial-onion`.
    #[arg(long, global = true)]
    dial_pubkey: Option<String>,

    /// Repeatable: each `--hub onion:port,b32pubkey` adds one hub
    /// the embedded daemon should publish to and subscribe on.
    /// Multi-hub mode (T8.1+) gives N-fold redundancy — if any one
    /// hub goes down, deliveries continue via the others. The
    /// recipient's replay guard silently dedups duplicate envelopes
    /// arriving from multiple hubs.
    #[arg(long = "hub", action = clap::ArgAction::Append, global = true)]
    hubs: Vec<String>,

    /// **TEST-ONLY** local-TCP hub, mirroring `--hub` but over plain
    /// TCP instead of Tor (pairs with `onyx-hub --listen-tcp`). No
    /// Tor, no anonymity — for local rooms/files testing without
    /// standing up onion services. Format: `--hub-tcp 127.0.0.1:7100,b32pubkey`.
    /// Repeatable. Loudly warned by the daemon at startup.
    #[arg(long = "hub-tcp", action = clap::ArgAction::Append, global = true)]
    hub_tcp: Vec<String>,

    /// **Opt-in.** Mean interval (in seconds) between cover-traffic
    /// PAD frames on each configured hub. When set, the embedded
    /// daemon publishes a sealed-sender-indistinguishable FRAME_PAD
    /// at exponentially-distributed (Poisson-process) intervals so
    /// a hub watching frame timing can't easily fingerprint "alice
    /// is actively chatting vs idle." Set to 0 or omit to disable
    /// (the v0 default — cover traffic burns bandwidth and isn't
    /// yet verified in real-Tor smoke). See `ANONYMITY.md` §3.1
    /// for the full threat model.
    #[arg(long, env = "ONYX_COVER_TRAFFIC_MEAN_SECS", global = true)]
    cover_traffic_mean_secs: Option<u64>,

    /// **Opt-in, "high mode".** Slot interval (in milliseconds) for
    /// constant-rate client→hub cover traffic. When set, the daemon
    /// sends exactly one frame per slot to each hub — a queued real
    /// frame if ready, otherwise a FRAME_PAD — so the upstream cadence
    /// is invariant whether you are chatting or idle. Stronger than
    /// the Poisson `--cover-traffic-mean-secs` (which real bursts
    /// still ride above) but costs up to one slot of latency per real
    /// frame plus a steady PAD/slot of bandwidth. Covers the
    /// client→hub direction only; mutually exclusive with
    /// `--cover-traffic-mean-secs`. 200–2000 ms is a sane range. See
    /// `ANONYMITY.md` §3.1.
    #[arg(long, env = "ONYX_CONSTANT_RATE_MS", global = true)]
    constant_rate_ms: Option<u64>,

    /// **D-1 — opt IN to first-contact reachability via the hub
    /// (default OFF = private).** Single master switch for the
    /// hub-linkage trade. Off (default): fresh per-connection
    /// ephemeral Noise static + ephemeral SUBSCRIBE-signing key, no
    /// `introduction_inbox(fp)` subscription, no KeyPackage publish —
    /// the hub cannot link the connection to your long-term identity
    /// (existing rooms + direct onion dials still work; you are just
    /// not reachable for first contact via this hub). On: long-term
    /// keys + intro-inbox + KP publish, reachable but linkable. The
    /// long-term identity is always used by the end-to-end
    /// sealed-sender layer regardless. See `ANONYMITY.md` §3.2.
    #[arg(long, env = "ONYX_FIRST_CONTACT_REACHABLE", global = true)]
    first_contact_reachable: bool,

    /// A1.2: acknowledge clearnet (NO TOR, NO ANONYMITY). Required to
    /// use any plain-TCP transport (--no-tor / --listen-tcp /
    /// --dial-tcp / --hub-tcp); without it the daemon refuses those
    /// modes so a mistyped flag can't silently expose your IP.
    #[arg(long, env = "ONYX_ALLOW_CLEARNET", global = true)]
    allow_clearnet: bool,

    #[command(subcommand)]
    cmd: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print daemon liveness + identity + Tor state as JSON.
    Status,
    /// Print the daemon's identity public key + fingerprint as JSON.
    Identity,
    /// Open the interactive multi-pane TUI against a daemon that is
    /// ALREADY RUNNING (this subcommand does NOT start one).
    ///
    /// **Most users want `onyx` with no subcommand instead** — it
    /// launches the daemon + TUI together in one process. `onyx tui` is
    /// for advanced cases where you've already started `onyxd`
    /// separately (e.g. headless deployment under a process supervisor).
    Tui,
    /// Run the daemon without a TUI (foreground). Useful for headless
    /// deployments or running under a process supervisor. Same as the
    /// standalone `onyxd` binary.
    Daemon,
    /// First-contact send via the hub (msg/v1 sealed-sender envelope).
    ///
    /// Requires the daemon to have been launched with
    /// `--hub-onion` + `--hub-pubkey`. The recipient does **not**
    /// need to be online — when they come online and subscribe to
    /// their introduction inbox, their daemon will receive and
    /// decode the envelope.
    ///
    /// Security tier note: `msg/v1` envelopes have per-message PFS
    /// only — no MLS PCS. See `SECURITY.md` §6.1 for the full
    /// tradeoff. The recipient TUI will render the message with a
    /// yellow `[hub]` badge so they can tell which tier it is.
    SendBootstrap {
        /// Recipient's base32-grouped fingerprint (the value printed
        /// by `onyx identity` under `fingerprint`).
        #[arg(long)]
        peer_fingerprint: String,
        /// Recipient's hybrid KEM public key, base32 (the value
        /// printed by `onyx identity` under `identity_kem_pub_b32`).
        /// ~1948 chars long — expect it to wrap on your terminal.
        #[arg(long)]
        peer_kem_pub_b32: String,
        /// Plaintext message to send.
        #[arg(long)]
        text: String,
    },
    /// **MLS-tier** first-contact via the hub. Establishes a real
    /// 2-party MLS group with the named peer; every application
    /// message exchanged in that group has full MLS post-compromise
    /// security.
    ///
    /// You need three things about the peer:
    ///   * `--peer-fingerprint` and `--peer-kem-pub-b32` — out of
    ///     band, like for `send-bootstrap`.
    ///   * `--peer-kp-b64` — pull this with
    ///     `onyx fetch-keypackage --peer-fingerprint X` (which talks
    ///     to your daemon's hub session to query the directory).
    ///
    /// After this call, both you and the peer hold a persistent MLS
    /// group; subsequent direct dials between you will resume the
    /// group via the existing T2.x path. Ongoing MLS-over-hub
    /// (async chat without a direct circuit) is T6.x.
    SendBootstrapMls {
        #[arg(long)]
        peer_fingerprint: String,
        #[arg(long)]
        peer_kem_pub_b32: String,
        /// Recipient's MLS KeyPackage in base64. Get via
        /// `onyx fetch-keypackage`.
        #[arg(long)]
        peer_kp_b64: String,
        /// Optional intro text to ride along with the MLS Welcome
        /// (T7.2-mls-fu). Max 1024 bytes. When set, the recipient
        /// sees this as the first message of the new conversation
        /// instead of a synthetic "joined MLS group" placeholder.
        #[arg(long)]
        text: Option<String>,
    },
    /// Look up a peer's published KeyPackage in the hub directory.
    /// Prints the KP bytes as base64 on stdout — suitable for
    /// piping into `--peer-kp-b64` of `send-bootstrap-mls`.
    ///
    /// The daemon validates the returned KP against `peer_fingerprint`
    /// before surfacing it; a mismatched KP (potential hub-directory
    /// tampering) surfaces as an `Error { code: malformed }` response.
    FetchKeypackage {
        #[arg(long)]
        peer_fingerprint: String,
    },
    /// Print a shareable `onyx://invite/v1?…` URL bundling our
    /// fingerprint and KEM public key. Hand it to a peer (over Signal,
    /// in person, whatever channel you trust to authenticate them) and
    /// they run `onyx accept <url> --text "hi"` to introduce themselves
    /// via the hub. The URL carries no secrets — it's the same data
    /// `onyx identity` already prints, just bundled.
    ///
    /// With `--with-kp`, the URL *also* embeds a fresh MLS KeyPackage
    /// so the accepting peer's `onyx accept` automatically uses
    /// MLS-tier bootstrap (full PCS on every subsequent message).
    /// KPs are single-use in MLS — mint a fresh URL per recipient if
    /// you want both to succeed.
    ///
    /// With `--with-hubs` (T8.2+), the URL embeds the list of hubs
    /// this daemon is currently configured to publish to and
    /// subscribe on (`--hub` flags). The accepting peer's CLI shows
    /// that list on `onyx accept` so they know where their
    /// first-contact message will land — transparency over the
    /// multi-hub fan-out path.
    Invite {
        /// Embed a fresh MLS KeyPackage in the URL so the accepting
        /// peer uses `SendBootstrapMls` (full MLS PCS on first
        /// contact) instead of msg/v1 (PFS only).
        #[arg(long)]
        with_kp: bool,
        /// Embed the daemon's hub list in the URL so the accepting
        /// peer sees where messages will land. Transparency, not
        /// auto-config — the accepting peer still uses *their own*
        /// daemon's hub config for the actual fan-out.
        #[arg(long)]
        with_hubs: bool,
    },
    /// Accept an `onyx://invite/v1?…` URL by sending the named
    /// fingerprint a first-contact message via the hub. Equivalent to
    /// `onyx send-bootstrap --peer-fingerprint … --peer-kem-pub-b32 …
    /// --text …` but you don't have to copy two long base32 strings.
    ///
    /// Tier: msg/v1 (PFS only). MLS-tier bootstrap via invite URL is
    /// queued for a follow-up phase; for now use `fetch-keypackage` +
    /// `send-bootstrap-mls` if you need MLS PCS on first contact.
    Accept {
        /// The `onyx://invite/v2?…` URL (v1 unsigned URLs are refused
        /// by default — see `--insecure-accept-unsigned`).
        url: String,
        /// Plaintext message to deliver alongside the introduction.
        /// Required — a sealed-sender envelope always carries a
        /// payload, so an empty "just say hi" introduction doesn't
        /// exist at the protocol level.
        #[arg(long)]
        text: String,
        /// **DANGEROUS, default OFF.** Accept an unsigned (v1) invite.
        /// v1 URLs carry no signature, so a side-channel MITM could
        /// have substituted any field (KEM, KP, hubs) without
        /// detection. Default behaviour now is to **refuse** v1 — the
        /// caller must pass this flag to opt in. Even with v2, a full
        /// MITM minting their own fully-valid invite is undetectable
        /// without out-of-band fingerprint verification.
        #[arg(long, default_value_t = false)]
        insecure_accept_unsigned: bool,
    },
    /// Multi-party room (channel) operations (T6.3.b-e). One MLS
    /// group per room, owned end-to-end; the daemon persists the
    /// room + member list in the vault and routes outgoing messages
    /// to each member over either their direct Noise session
    /// (preferred) or the hub (fallback). The wire format and
    /// crypto are identical to existing 2-party MLS DMs — a "room"
    /// is just an MLS group with N members.
    ///
    /// **Honest scope**: this verb group exposes the daemon API
    /// surface end-to-end. The TUI room pane (a dedicated split
    /// alongside the existing DM pane) is queued for a follow-up.
    Room {
        #[command(subcommand)]
        cmd: RoomCommand,
    },
    /// File-management subcommands (T-files.d). `onyx files list
    /// --conversation room/<short>` enumerates received files in
    /// a room; sending uses `onyx room send-file`.
    Files {
        #[command(subcommand)]
        cmd: FilesCommand,
    },
    /// Contact / pinned-key subcommands (T-1). `onyx contact list`
    /// shows every peer whose identity key you've pinned on first
    /// contact, and flags any whose key has since changed (a key
    /// rotation or a man-in-the-middle — re-verify out of band).
    Contact {
        #[command(subcommand)]
        cmd: ContactCommand,
    },
}

/// Subcommands under `onyx contact`. Pure dispatch to `ApiRequest::*`.
#[derive(Subcommand, Debug)]
enum ContactCommand {
    /// List every pinned contact (newest contact first), with each
    /// one's fingerprint, pinned key, first/last-seen, and a
    /// `key_changed` flag.
    List,
}

/// Subcommands under `onyx room`. Each maps directly to one
/// `ApiRequest::*` variant; no daemon-side work — pure dispatch.
#[derive(Subcommand, Debug)]
enum RoomCommand {
    /// Create a new room with just yourself as the sole member.
    /// Prints `{ "group_id_b32": "...", "name": "..." }` on stdout
    /// so you can pipe the id into subsequent `invite` / `send` calls.
    /// `name` is a local-only display label — it does NOT propagate
    /// over the wire; the cryptographic identity of the room is the
    /// MLS `group_id`. Two rooms can share a name locally; the
    /// daemon disambiguates by `group_id` everywhere.
    Create {
        /// Local display name for the room.
        #[arg(long)]
        name: String,
    },
    /// List every room this daemon participates in.
    List,
    /// Invite a peer into an existing room. Requires `--hub` on the
    /// daemon side. Same fingerprint↔KP signing-key validation as
    /// `send-bootstrap-mls` — the daemon refuses to add a member
    /// whose KP signing key doesn't match the supplied fingerprint
    /// (defends THREAT_MODEL §8.2 #15: hostile hub directory could
    /// swap an attacker's KP under the target's routing id).
    ///
    /// After a successful invite, the room's cached member list is
    /// refreshed in the vault and the inviter persists the
    /// invitee's KEM pub so future `send` calls can hub-fall-back
    /// to them when they're offline.
    Invite {
        /// Room id (the `group_id_b32` returned by `create` or
        /// listed by `list`).
        #[arg(long)]
        group_id: String,
        /// Invitee's base32-grouped fingerprint.
        #[arg(long)]
        peer_fingerprint: String,
        /// Invitee's hybrid KEM public key, base32.
        #[arg(long)]
        peer_kem_pub_b32: String,
        /// Invitee's MLS KeyPackage in base64. Get via
        /// `onyx fetch-keypackage`.
        #[arg(long)]
        peer_kp_b64: String,
    },
    /// Send `text` to every current member of the room. The daemon
    /// encrypts the plaintext once in the room's MLS group and
    /// fans the resulting ciphertext to each member via their
    /// direct Noise session (preferred) or the hub (fallback,
    /// requires a cached KEM pub for that member — currently only
    /// the inviter has KEMs cached for everyone they invited).
    ///
    /// Response reports `delivered_to_direct`, `delivered_to_hub`,
    /// `skipped_no_kem`, `total_members` so you can see who
    /// actually got it.
    Send {
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        text: String,
    },
    /// Forget a room **locally** (T-polish.1). Drops the room row,
    /// the cached KEM list, and the MLS group state. Does NOT
    /// notify the other members — they keep their copy with you
    /// listed as a (now-ghost) member. For a clean leave that
    /// informs the others, use `leave` instead.
    ///
    /// Idempotent — succeeds even if no room with that id exists.
    Delete {
        #[arg(long)]
        group_id: String,
    },
    /// Rename a room **locally** (T-polish.1). Pure-metadata
    /// update; doesn't propagate to other members (each member's
    /// local name is independent per `CHANNELS.md §2`).
    Rename {
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        new_name: String,
    },
    /// Leave a room cleanly (T-polish.2). Sends an MLS Remove
    /// commit informing every other current member, then drops
    /// local state. Other members will see their roster shrink
    /// and continue without you. Requires `--hub` on the daemon.
    Leave {
        #[arg(long)]
        group_id: String,
    },
    /// Remove (kick) another member from a room (task 325). Issues an
    /// MLS Remove commit evicting `--peer-fingerprint`, fans it out to
    /// all members, and refreshes the roster. Requires `--hub` on the
    /// daemon. The fingerprint is the base32-grouped form shown in
    /// `room list` / the TUI Details roster.
    Remove {
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        peer_fingerprint: String,
    },
    /// Send a file to every member of a room (T-files.d). The
    /// daemon sanitizes metadata by default (raster images get
    /// decoded + re-encoded; PDF/Office/video/audio are refused
    /// unless `--keep-metadata` is set). Filename is replaced
    /// with a hash-prefixed sanitized name unless `--keep-filename`
    /// is set. See `FILES.md §3` for the per-format strategy.
    SendFile {
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        path: String,
        /// Preserve the original filename (still sanitized for
        /// safe disk storage). Default: replace with `file.<ext>`.
        #[arg(long)]
        keep_filename: bool,
        /// Bypass metadata stripping. Required for formats Onyx
        /// can't safely strip (PDF, DOCX, video, audio, archives,
        /// HEIC). Documented leak — see `FILES.md §3.2`.
        #[arg(long)]
        keep_metadata: bool,
    },
}

/// `onyx files …` subcommands (T-files.d).
#[derive(Subcommand, Debug)]
enum FilesCommand {
    /// List files received from peers / in rooms.
    /// `conversation` is `peer/<short>` for DMs or
    /// `room/<short_b32>` for rooms.
    List {
        #[arg(long)]
        conversation: String,
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Send a file to a directly-connected DM peer (task 322).
    /// Requires a live conversation with the peer (direct-only).
    /// Metadata is stripped by default; pass `--keep-metadata` for
    /// formats we can't strip (non-image), `--keep-filename` to keep
    /// the original name instead of a random one.
    Send {
        #[arg(long)]
        peer_short: String,
        #[arg(long)]
        path: String,
        #[arg(long)]
        keep_filename: bool,
        #[arg(long)]
        keep_metadata: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    // Initialise tracing for any mode that runs the daemon or the TUI;
    // pure one-shot CLI commands keep stdout clean so they pipe into `jq`.
    //
    // Critical: the TUI owns the terminal, so any mode that renders it
    // (`onyx` combined mode = `None`, and `onyx tui`) MUST send logs to
    // a FILE, not stderr — otherwise the daemon's tracing output writes
    // straight over the ratatui frame and shreds the display. Only the
    // headless `onyx daemon` keeps logging to stderr (no TUI there).
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    match args.cmd {
        Some(Command::Daemon) => {
            tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_writer(std::io::stderr)
                .init();
        }
        Some(Command::Tui) | None => {
            // Log to ~/.onyx/onyx.log (next to the vault). Falls back to
            // stderr only if the file can't be opened.
            let log_path = onyx_daemon::default_data_dir().join("onyx.log");
            if let Some(parent) = log_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
            {
                Ok(file) => {
                    eprintln!(
                        "onyx: logs → {} (TUI owns the terminal)",
                        log_path.display()
                    );
                    tracing_subscriber::fmt()
                        .with_env_filter(env_filter)
                        .with_ansi(false)
                        .with_writer(move || file.try_clone().expect("clone log file handle"))
                        .init();
                }
                Err(e) => {
                    eprintln!(
                        "onyx: could not open log file {} ({e}); logging to stderr",
                        log_path.display()
                    );
                    tracing_subscriber::fmt()
                        .with_env_filter(env_filter)
                        .with_writer(std::io::stderr)
                        .init();
                }
            }
        }
        // Pure one-shot CLI commands: no tracing init (keep stdout clean).
        _ => {}
    }

    match dispatch(args).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("onyx: {e:#}");
            ExitCode::from(2)
        }
    }
}

/// Build a daemon `Config` from the global `Args`. Used by both the
/// no-subcommand path (`onyx`) and the explicit `onyx daemon` form.
/// v0.1.12: persisted, TUI-managed settings. Lives at
/// `~/.onyx/config.json` (JSON so we reuse the `serde_json` we already
/// depend on — no new crate). Every field is optional/defaulted so an
/// older or hand-edited file never fails to load. CLI flags always win
/// over the file (the file is the *default*, the flag is the override),
/// so power users and scripts keep their behaviour.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
struct FileConfig {
    /// Each entry is `onion:port,b32pubkey` — same grammar as `--hub`.
    #[serde(default)]
    hubs: Vec<String>,
    /// P2P direct-dial target onion (`onion` or `onion:port`).
    #[serde(default)]
    dial_onion: Option<String>,
    /// Peer X25519 identity pubkey (base32) for the dial target.
    #[serde(default)]
    dial_pubkey: Option<String>,
    /// D-1 reachability switch (default off = private).
    #[serde(default)]
    first_contact_reachable: bool,
    /// Optional Poisson cover-traffic mean interval, seconds.
    #[serde(default)]
    cover_traffic_mean_secs: Option<u64>,
}

/// Path to the persisted config: `~/.onyx/config.json`.
fn config_file_path() -> std::path::PathBuf {
    onyx_daemon::default_data_dir().join("config.json")
}

/// Load `~/.onyx/config.json` if present. A missing file is `None`
/// (first run); a malformed file is a hard error so the operator finds
/// out instead of silently running with default (less-private) settings.
fn load_file_config() -> anyhow::Result<Option<FileConfig>> {
    let path = config_file_path();
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            let cfg: FileConfig = serde_json::from_str(&s)
                .map_err(|e| anyhow::anyhow!("malformed {}: {e}", path.display()))?;
            Ok(Some(cfg))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::anyhow!("reading {}: {e}", path.display())),
    }
}

/// Persist `cfg` to `~/.onyx/config.json` (pretty JSON, mode 0600 —
/// it can hold a dial target / hub list, low-sensitivity but still the
/// user's social graph). Creates `~/.onyx` if needed.
fn save_file_config(cfg: &FileConfig) -> anyhow::Result<()> {
    let dir = onyx_daemon::default_data_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| anyhow::anyhow!("creating {}: {e}", dir.display()))?;
    let path = config_file_path();
    let json = serde_json::to_string_pretty(cfg)?;
    std::fs::write(&path, json).map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn build_daemon_config(
    args: &Args,
    socket: &std::path::Path,
) -> anyhow::Result<onyx_daemon::Config> {
    let Some(passphrase) = args.passphrase.clone() else {
        anyhow::bail!(
            "starting the embedded daemon requires --passphrase (or the \
             ONYX_PASSPHRASE env var). Pass it via env so it doesn't \
             show up in `ps`."
        );
    };
    // v0.1.12: load persisted TUI-managed settings. CLI flags win, so
    // this only *fills in* what the flags didn't set.
    let file_cfg = load_file_config()?.unwrap_or_default();
    // Parse repeatable --hub "onion:port,b32pubkey" args into a
    // Vec<HubConfig>. Each --hub is one hub; the embedded daemon
    // publishes/subscribes to all of them in parallel (T8.1+).
    let mut hubs: Vec<onyx_daemon::HubConfig> = Vec::new();
    for raw in &args.hubs {
        let (onion, pubkey) = raw.split_once(',').ok_or_else(|| {
            anyhow::anyhow!("--hub value must be `onion:port,b32pubkey` (missing comma): {raw}")
        })?;
        if onion.is_empty() || pubkey.is_empty() {
            anyhow::bail!("--hub value has empty field: {raw}");
        }
        hubs.push(onyx_daemon::HubConfig {
            onion: onion.to_string(),
            pubkey: pubkey.to_string(),
        });
    }
    // v0.1.12: if no --hub was passed on the CLI, fall back to the
    // hubs persisted in ~/.onyx/config.json (TUI-managed). CLI wins:
    // passing even one --hub ignores the file list entirely, so a
    // script's explicit hub set is never silently merged with stale
    // persisted state.
    if hubs.is_empty() {
        for raw in &file_cfg.hubs {
            let (onion, pubkey) = raw.split_once(',').ok_or_else(|| {
                anyhow::anyhow!(
                    "config.json hub entry must be `onion:port,b32pubkey` (missing comma): {raw}"
                )
            })?;
            if onion.is_empty() || pubkey.is_empty() {
                anyhow::bail!("config.json hub entry has empty field: {raw}");
            }
            hubs.push(onyx_daemon::HubConfig {
                onion: onion.to_string(),
                pubkey: pubkey.to_string(),
            });
        }
    }
    // TEST-ONLY: parse repeatable --hub-tcp "addr,b32pubkey" the same
    // way, into hub_tcp_addrs. Mirrors --hub but the daemon dials it
    // over plain TCP (no Tor). Pairs with `onyx-hub --listen-tcp`.
    let mut hub_tcp_addrs: Vec<onyx_daemon::HubConfig> = Vec::new();
    for raw in &args.hub_tcp {
        let (addr, pubkey) = raw.split_once(',').ok_or_else(|| {
            anyhow::anyhow!("--hub-tcp value must be `addr,b32pubkey` (missing comma): {raw}")
        })?;
        if addr.is_empty() || pubkey.is_empty() {
            anyhow::bail!("--hub-tcp value has empty field: {raw}");
        }
        hub_tcp_addrs.push(onyx_daemon::HubConfig {
            onion: addr.to_string(),
            pubkey: pubkey.to_string(),
        });
    }
    // v0.1.12: resolve dial / reachability / cover-traffic with CLI
    // winning over the persisted file. Onion dial: a CLI flag overrides
    // the file outright; otherwise use the file's saved target.
    let dial_onion = args
        .dial_onion
        .clone()
        .or_else(|| file_cfg.dial_onion.clone());
    let dial_pubkey = args
        .dial_pubkey
        .clone()
        .or_else(|| file_cfg.dial_pubkey.clone());
    // Reachability is a privacy toggle — OR the two so "on" from either
    // source wins (you opted in somewhere). Cover-traffic: CLI value or
    // the file's.
    let first_contact_reachable = args.first_contact_reachable || file_cfg.first_contact_reachable;
    let cover_traffic_mean_secs = args
        .cover_traffic_mean_secs
        .or(file_cfg.cover_traffic_mean_secs);
    // A peer dial (Tor onion or test TCP) needs the peer's identity key,
    // or the daemon would silently fall back to accept mode (lib.rs:878).
    // Fail loudly so a half-typed P2P dial doesn't look like "nothing
    // happened." Checks the *resolved* dial target (CLI or file).
    if (dial_onion.is_some() || args.dial_tcp.is_some()) && dial_pubkey.is_none() {
        anyhow::bail!(
            "a dial target (--dial-onion / config.json / --dial-tcp) requires a peer \
             X25519 identity key (--dial-pubkey or config.json dial_pubkey)"
        );
    }
    Ok(onyx_daemon::Config {
        vault: args
            .vault
            .clone()
            .unwrap_or_else(onyx_daemon::default_vault_path),
        passphrase: zeroize::Zeroizing::new(passphrase),
        // TCP hub mode is also a no-Tor path: when only --hub-tcp is
        // given (no Tor dial/listen), skip the Tor bootstrap.
        no_tor: args.listen_tcp.is_some()
            || args.dial_tcp.is_some()
            || (!args.hub_tcp.is_empty() && args.hubs.is_empty()),
        tor_state_dir: None,
        // P2P: direct onion dial needs Tor (never a no-Tor path), so it
        // doesn't appear in the `no_tor` condition above — it just wires
        // the target through to `run_dial_mode`. Resolved CLI-over-file.
        dial_onion,
        dial_pubkey,
        api_socket: socket.to_string_lossy().into_owned(),
        hubs,
        hub_tcp_addrs,
        listen_tcp: args.listen_tcp.clone(),
        dial_tcp: args.dial_tcp.clone(),
        cover_traffic_mean_secs,
        constant_rate_ms: args.constant_rate_ms,
        // D-1: single master switch; default false = private.
        first_contact_reachable,
        // A1.2: must explicitly opt in to clearnet (no-Tor) transport.
        allow_clearnet: args.allow_clearnet,
    })
}

/// Task 323: interactive first-run / unlock wizard. Returns the vault
/// passphrase. A fresh vault (file missing) gets a create-and-confirm
/// flow with an explicit "no recovery" warning + an 8-char minimum; an
/// existing vault gets a single unlock prompt. Input is hidden (no
/// echo) via the crossterm dependency we already have — no new
/// password-input crate, no plaintext in scrollback.
fn first_run_wizard(vault_path: &std::path::Path) -> anyhow::Result<String> {
    let fresh = !vault_path.exists();
    if !fresh {
        print_brand_banner(false);
        // Verify the passphrase HERE, before the daemon spawns and the
        // TUI launches. Previously a wrong passphrase was returned
        // as-is: the background daemon then failed at vault-open, printed
        // a cryptic error, and the TUI launched anyway into a dead
        // "connecting to daemon…" state. Instead we open the vault to
        // check the passphrase and re-prompt on a mismatch — a wrong
        // unlock should ask again, not drop you into a broken UI.
        loop {
            let p = read_hidden_line(&paint("  Unlock your vault — passphrase: ", ANSI_GREEN))?;
            match onyx_core::storage::Vault::open(vault_path, p.as_bytes()) {
                Ok(_vault) => {
                    // Drop immediately — the daemon reopens it. We only
                    // needed to confirm the passphrase unlocks the vault.
                    return Ok(p);
                }
                Err(onyx_core::error::Error::VerificationFailed) => {
                    eprintln!(
                        "  {}",
                        paint("wrong passphrase — try again (Esc to cancel).", ANSI_RED)
                    );
                }
                Err(e) => {
                    // Not a wrong-passphrase case (corrupt vault, schema
                    // mismatch, I/O). Re-prompting won't help — surface it.
                    anyhow::bail!("could not open vault at {}: {e}", vault_path.display());
                }
            }
        }
    }
    print_brand_banner(true);
    eprintln!(
        "  {}",
        paint(
            &format!(
                "Setting up your encrypted vault at {}.",
                vault_path.display()
            ),
            ANSI_DIM
        )
    );
    eprintln!(
        "  {}",
        paint(
            "Choose a passphrase — it protects your identity keys at rest (Argon2id).",
            ANSI_DIM
        )
    );
    eprintln!(
        "  {}\n",
        paint(
            "There is NO recovery if you forget it. Store it in a password manager.",
            ANSI_AMBER
        )
    );
    loop {
        let p1 = read_hidden_line(&paint("  New passphrase (min 8 chars): ", ANSI_GREEN))?;
        if p1.chars().count() < 8 {
            eprintln!(
                "  {}",
                paint("too short (need 8+ chars) — try again.", ANSI_RED)
            );
            continue;
        }
        // A friendly, non-blocking strength hint. We never reject a
        // long-enough passphrase (the user owns the trade-off), we just
        // nudge — Argon2id does the real heavy lifting at rest.
        eprintln!("  {}", passphrase_strength_hint(&p1));
        let p2 = read_hidden_line(&paint("  Confirm passphrase: ", ANSI_GREEN))?;
        if p1 != p2 {
            eprintln!(
                "  {}",
                paint("passphrases didn't match — try again.", ANSI_RED)
            );
            continue;
        }
        eprintln!("  {}\n", paint("✓ vault passphrase set.", ANSI_GREEN));
        return Ok(p1);
    }
}

// ── First-run banner / ANSI helpers ──────────────────────────────────────
//
// The wizard runs on stderr BEFORE the ratatui TUI takes the terminal,
// so it can't use the `theme` module (that's ratatui `Color`). Plain
// ANSI SGR codes give the same phosphor-green vibe here. They degrade to
// nothing on a non-tty (the codes are only emitted when stderr is a tty).

const ANSI_GREEN: &str = "1;32";
// Tor-purple truecolor, matching theme::PURPLE = Rgb(0xa9,0x6c,0xe6).
const ANSI_PURPLE: &str = "1;38;2;169;108;230";
const ANSI_DIM: &str = "2";
const ANSI_AMBER: &str = "1;33";
const ANSI_RED: &str = "1;31";
const ANSI_CYAN: &str = "1;36";

/// Wrap `s` in an ANSI SGR colour, but only when stderr is a real
/// terminal (so piping / logging stays clean plain text).
fn paint(s: &str, sgr: &str) -> String {
    if std::io::IsTerminal::is_terminal(&std::io::stderr()) {
        format!("\x1b[{sgr}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

/// The onyx onion banner shown at the top of the first-run / unlock
/// wizard — a small branded welcome before the TUI takes over.
fn print_brand_banner(fresh: bool) {
    // Layered Tor *onion* (sprout + concentric layers + bulb), matching
    // the in-TUI `theme::ONION_ART`. NOT a face. Painted Tor-purple.
    let art = [
        "      \\|/      ",
        "    .-===-.    ",
        "   /(  (  )\\   ",
        "   \\ )  ) (/   ",
        "    '-===-'    ",
    ];
    eprintln!();
    for line in art {
        eprintln!("  {}", paint(line, ANSI_PURPLE));
    }
    eprintln!("       {}", paint("O N Y X", ANSI_PURPLE));
    eprintln!("   {}", paint("anonymous · e2e · tor", ANSI_DIM));
    eprintln!();
    if fresh {
        eprintln!(
            "  {}",
            paint("Welcome to Onyx — let's set up your vault.", ANSI_CYAN)
        );
    } else {
        eprintln!("  {}", paint("Welcome back.", ANSI_CYAN));
    }
}

/// A friendly, non-blocking strength read on a passphrase (length +
/// rough character-class variety). Returns a coloured one-liner; it
/// never rejects (the 8-char minimum is the only hard floor).
fn passphrase_strength_hint(p: &str) -> String {
    let len = p.chars().count();
    let lower = p.chars().any(|c| c.is_ascii_lowercase());
    let upper = p.chars().any(|c| c.is_ascii_uppercase());
    let digit = p.chars().any(|c| c.is_ascii_digit());
    let other = p.chars().any(|c| !c.is_ascii_alphanumeric());
    let classes = u8::from(lower) + u8::from(upper) + u8::from(digit) + u8::from(other);

    // Length dominates entropy for passphrases; classes are a secondary
    // nudge. These thresholds are a UX hint, not a security guarantee.
    let (label, sgr) = if len >= 20 || (len >= 14 && classes >= 3) {
        ("strong", ANSI_GREEN)
    } else if len >= 12 || classes >= 3 {
        ("ok", ANSI_AMBER)
    } else {
        ("weak — consider a longer phrase", ANSI_AMBER)
    };
    paint(&format!("strength: {label}"), sgr)
}

/// Read a line from the terminal without echoing it, using crossterm
/// raw mode. `Enter` submits, `Backspace` edits, `Esc`/`Ctrl-C`
/// cancels. Raw mode is always restored, even on error/cancel.
fn read_hidden_line(prompt: &str) -> anyhow::Result<String> {
    use crossterm::event::{Event, KeyCode, KeyModifiers, read};
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
    use std::io::Write as _;

    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    enable_raw_mode().map_err(|e| anyhow::anyhow!("raw mode: {e}"))?;
    let mut buf = String::new();
    let result = loop {
        match read() {
            Ok(Event::Key(k)) => match k.code {
                KeyCode::Enter => break Ok(std::mem::take(&mut buf)),
                KeyCode::Backspace => {
                    buf.pop();
                }
                KeyCode::Esc => break Err(anyhow::anyhow!("cancelled")),
                KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                    break Err(anyhow::anyhow!("cancelled"));
                }
                KeyCode::Char(c) => buf.push(c),
                _ => {}
            },
            Ok(_) => {}
            Err(e) => break Err(anyhow::anyhow!("read input: {e}")),
        }
    };
    disable_raw_mode().ok();
    eprintln!();
    result
}

// The top-level subcommand dispatcher: one arm per CLI verb. Long by
// nature (it's the command table), consistent with the other
// #[allow(too_many_lines)] functions in this crate.
#[allow(clippy::too_many_lines)]
async fn dispatch(mut args: Args) -> anyhow::Result<ExitCode> {
    // Resolve the optional --socket once so every arm sees the same
    // path. Defaulting to `~/.onyx/onyx.sock` matches the daemon's
    // default api_socket; the parent dir is auto-created by
    // `onyx_daemon::run` with mode 0700.
    let socket: PathBuf = args
        .socket
        .clone()
        .unwrap_or_else(|| PathBuf::from(onyx_daemon::default_api_socket_path()));
    match args.cmd {
        // ── No subcommand: launch daemon + TUI in one process ───────────
        None => {
            // Task 323: first-run wizard. When launched interactively
            // without a passphrase, prompt for it (hidden) instead of
            // erroring — fresh vault → "create + confirm", existing →
            // "unlock". A new user is no longer blocked by the
            // --passphrase wall. Non-interactive (piped) falls through
            // to build_daemon_config's helpful error.
            // The wizard verifies the passphrase against the vault as it
            // prompts, so we don't need to re-check that path. A
            // passphrase supplied via --passphrase / ONYX_PASSPHRASE
            // skips the wizard, so we pre-flight-verify it below.
            let mut passphrase_verified = false;
            if args.passphrase.is_none() && std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                let vault_path = args
                    .vault
                    .clone()
                    .unwrap_or_else(onyx_daemon::default_vault_path);
                match first_run_wizard(&vault_path) {
                    Ok(p) => {
                        args.passphrase = Some(p);
                        passphrase_verified = true;
                    }
                    Err(e) => {
                        eprintln!("onyx: {e:#}");
                        return Ok(ExitCode::from(2));
                    }
                }
            }
            let config = build_daemon_config(&args, &socket)?;
            // Fail fast on a wrong --passphrase / ONYX_PASSPHRASE for an
            // existing vault, instead of spawning a daemon that dies at
            // vault-open and a TUI that then hangs on "connecting…".
            if !passphrase_verified && config.vault.exists() {
                if let Err(onyx_core::error::Error::VerificationFailed) =
                    onyx_core::storage::Vault::open(&config.vault, config.passphrase.as_bytes())
                {
                    eprintln!(
                        "onyx: wrong passphrase for vault at {} — \
                         check --passphrase / ONYX_PASSPHRASE.",
                        config.vault.display()
                    );
                    return Ok(ExitCode::from(2));
                }
            }
            // Spawn the daemon work in a background task.
            let daemon_handle = tokio::spawn(async move {
                if let Err(e) = onyx_daemon::run(config).await {
                    eprintln!("onyx: daemon exited with error: {e:#}");
                }
            });
            // Give the daemon a moment to bind the API socket so the
            // TUI's first connect doesn't race. We don't poll because
            // the TUI's own 2-second tick will keep retrying on its own.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let tui_result = tui::run(socket).await;
            daemon_handle.abort();
            tui_result?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Daemon) => {
            let config = build_daemon_config(&args, &socket)?;
            onyx_daemon::run(config).await?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Status) => one_shot_print(&socket, ApiRequest::Status).await,
        Some(Command::Identity) => one_shot_print(&socket, ApiRequest::Identity).await,
        Some(Command::Tui) => {
            tui::run(socket).await?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::SendBootstrap {
            peer_fingerprint,
            peer_kem_pub_b32,
            text,
        }) => {
            one_shot_print(
                &socket,
                ApiRequest::SendBootstrap {
                    peer_fingerprint,
                    peer_kem_pub_b32,
                    text,
                },
            )
            .await
        }
        Some(Command::SendBootstrapMls {
            peer_fingerprint,
            peer_kem_pub_b32,
            peer_kp_b64,
            text,
        }) => {
            one_shot_print(
                &socket,
                ApiRequest::SendBootstrapMls {
                    peer_fingerprint,
                    peer_kem_pub_b32,
                    peer_kp_b64,
                    initial_text: text,
                },
            )
            .await
        }
        Some(Command::FetchKeypackage { peer_fingerprint }) => {
            one_shot_print(
                &socket,
                ApiRequest::FetchPeerKeyPackage { peer_fingerprint },
            )
            .await
        }
        Some(Command::Invite { with_kp, with_hubs }) => {
            run_invite(&socket, with_kp, with_hubs).await
        }
        Some(Command::Accept {
            url,
            text,
            insecure_accept_unsigned,
        }) => run_accept(&socket, &url, text, insecure_accept_unsigned).await,
        Some(Command::Room { cmd }) => dispatch_room(&socket, cmd).await,
        Some(Command::Files { cmd }) => dispatch_files(&socket, cmd).await,
        Some(Command::Contact { cmd }) => dispatch_contact(&socket, cmd).await,
    }
}

/// Dispatch the `onyx room *` subcommands. Extracted from
/// [`dispatch`] so the top-level match block stays under clippy's
/// `too_many_lines` budget. Each arm maps 1:1 to one
/// `ApiRequest::*` variant; the daemon does the actual work.
async fn dispatch_room(socket: &std::path::Path, cmd: RoomCommand) -> anyhow::Result<ExitCode> {
    match cmd {
        RoomCommand::Create { name } => {
            one_shot_print(socket, ApiRequest::CreateRoom { name }).await
        }
        RoomCommand::List => one_shot_print(socket, ApiRequest::ListRooms).await,
        RoomCommand::Invite {
            group_id,
            peer_fingerprint,
            peer_kem_pub_b32,
            peer_kp_b64,
        } => {
            one_shot_print(
                socket,
                ApiRequest::InviteToRoom {
                    group_id_b32: group_id,
                    peer_fingerprint,
                    peer_kem_pub_b32,
                    peer_kp_b64,
                },
            )
            .await
        }
        RoomCommand::Send { group_id, text } => {
            one_shot_print(
                socket,
                ApiRequest::SendRoom {
                    group_id_b32: group_id,
                    text,
                },
            )
            .await
        }
        RoomCommand::Delete { group_id } => {
            one_shot_print(
                socket,
                ApiRequest::DeleteRoom {
                    group_id_b32: group_id,
                },
            )
            .await
        }
        RoomCommand::Rename { group_id, new_name } => {
            one_shot_print(
                socket,
                ApiRequest::RenameRoom {
                    group_id_b32: group_id,
                    new_name,
                },
            )
            .await
        }
        RoomCommand::Leave { group_id } => {
            one_shot_print(
                socket,
                ApiRequest::LeaveRoom {
                    group_id_b32: group_id,
                },
            )
            .await
        }
        RoomCommand::Remove {
            group_id,
            peer_fingerprint,
        } => {
            one_shot_print(
                socket,
                ApiRequest::RemoveFromRoom {
                    group_id_b32: group_id,
                    peer_fingerprint,
                },
            )
            .await
        }
        RoomCommand::SendFile {
            group_id,
            path,
            keep_filename,
            keep_metadata,
        } => {
            one_shot_print(
                socket,
                ApiRequest::SendFileToRoom {
                    group_id_b32: group_id,
                    path,
                    keep_filename,
                    keep_metadata,
                },
            )
            .await
        }
    }
}

/// T-files.d: dispatch `onyx files …` subcommands. Each maps
/// 1:1 to an ApiRequest variant.
async fn dispatch_files(socket: &std::path::Path, cmd: FilesCommand) -> anyhow::Result<ExitCode> {
    match cmd {
        FilesCommand::List {
            conversation,
            limit,
        } => {
            one_shot_print(
                socket,
                ApiRequest::ListReceivedFiles {
                    conversation,
                    limit,
                },
            )
            .await
        }
        FilesCommand::Send {
            peer_short,
            path,
            keep_filename,
            keep_metadata,
        } => {
            one_shot_print(
                socket,
                ApiRequest::SendFileToPeer {
                    peer_short,
                    path,
                    keep_filename,
                    keep_metadata,
                },
            )
            .await
        }
    }
}

/// Dispatch `onyx contact …` subcommands (T-1).
async fn dispatch_contact(
    socket: &std::path::Path,
    cmd: ContactCommand,
) -> anyhow::Result<ExitCode> {
    match cmd {
        ContactCommand::List => one_shot_print(socket, ApiRequest::ListContacts).await,
    }
}

/// T-2: ask the daemon to build a **signed** invite URL
/// (`onyx://invite/v2?…`) — the signing key lives there, not in the
/// CLI. Plain string output on stdout (pipeable); the signed-invite
/// expiry + hub status go to stderr. With `with_kp` the daemon also
/// mints + bundles a fresh MLS KeyPackage so `onyx accept` on the
/// other side uses MLS-tier bootstrap (full PCS) instead of msg/v1.
async fn run_invite(
    socket: &std::path::Path,
    with_kp: bool,
    with_hubs: bool,
) -> anyhow::Result<ExitCode> {
    let resp = client::one_shot(
        socket,
        &ApiRequest::BuildInvite {
            with_kp,
            with_hubs,
            ttl_secs: None,
        },
    )
    .await?;
    match resp {
        ApiResponse::BuildInviteOk {
            url,
            exp_ms,
            hubs_attached,
        } => {
            if with_hubs && hubs_attached == 0 {
                eprintln!(
                    "onyx: warning — --with-hubs requested but daemon has no hubs \
                     configured; the URL will not carry a hub list. Pass `--hub \
                     onion:port,b32pubkey` (one or more times) to the daemon to populate it."
                );
            }
            eprintln!(
                "onyx: signed (v2) invite, expires at unix-ms {exp_ms} ({} from now)",
                humanize_remaining_ms(exp_ms),
            );
            println!("{url}");
            Ok(ExitCode::SUCCESS)
        }
        ApiResponse::Error { .. } => {
            println!("{}", serde_json::to_string_pretty(&resp)?);
            Ok(ExitCode::from(1))
        }
        other => anyhow::bail!("unexpected daemon response to BuildInvite: {other:?}"),
    }
}

/// Best-effort "in ~N days/hours" string from a Unix-ms timestamp,
/// for human-friendly invite-expiry messages on stderr.
fn humanize_remaining_ms(exp_ms: u64) -> String {
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0);
    if exp_ms <= now_ms {
        return "already expired".into();
    }
    let remaining_secs = (exp_ms - now_ms) / 1000;
    let days = remaining_secs / 86_400;
    if days > 0 {
        return format!("~{days} days");
    }
    let hours = remaining_secs / 3600;
    if hours > 0 {
        return format!("~{hours} hours");
    }
    let mins = remaining_secs / 60;
    format!("~{mins} min")
}

/// Parse an invite URL, then ship a sealed-sender bootstrap to the
/// recipient with `text` as the payload. Picks the tier from the URL:
/// MLS-tier (`SendBootstrapMls`, full PCS, text rides as
/// `initial_text` inside the same sealed envelope as the Welcome)
/// when the URL carries a `kp`, otherwise msg/v1 (`SendBootstrap`,
/// PFS only).
///
/// On the MLS-tier path, `--text` is capped at 1024 bytes daemon-side
/// to avoid bumping the sealed envelope from the MEDIUM wire-size
/// bucket into LARGE — a length-leak signal observable to anyone
/// watching the daemon↔hub Noise channel.
// Trust-gate, hub-intersection, daemon dispatch, error printing — all
// linear and read-top-to-bottom; splitting each gate into a helper
// would just rename the work.
#[allow(clippy::too_many_lines)]
async fn run_accept(
    socket: &std::path::Path,
    url: &str,
    text: String,
    insecure_accept_unsigned: bool,
) -> anyhow::Result<ExitCode> {
    let invite = onyx_core::invite::Invite::parse(url)
        .map_err(|e| anyhow::anyhow!("invalid invite URL: {e}"))?;

    // T-2 trust gates, in order of how badly they bite:
    //
    //   (a) v1 (unsigned) is refused outright unless the operator
    //       explicitly opts in with `--insecure-accept-unsigned`. The
    //       previous "warn + send anyway" turned the entire v2 work
    //       into a downgrade target — an attacker rewriting `/v2 → /v1`
    //       and stripping the sig fields would get a warning + a sent
    //       envelope. No more.
    //   (b) Wall-clock failure is a hard error, not a silent 0. With
    //       `unwrap_or(0)`, a broken / backward-skewed clock would
    //       silently bypass the expiry check (every signed invite
    //       would "not yet" be expired).
    //   (c) The v2 signature is verified. Honest framing: this proves
    //       the invite is *internally consistent* (nobody flipped
    //       individual fields between mint and accept). It does NOT
    //       prove the invite came from the human you think it did —
    //       it's self-signed by whoever holds the fingerprint *in*
    //       the invite. A full-invite MITM mints their own valid v2
    //       under their own keys and still passes here.
    //   (d) TOFU cross-check: if we've already pinned a DIFFERENT key
    //       for this fingerprint, refuse rather than silently
    //       overwriting the pin. The user has to investigate.
    //
    // The OOB-fingerprint compare against what your peer told you over
    // a trusted channel (voice / Signal / in person) remains the only
    // real anti-MITM defence at first contact. T-2 narrows the
    // attacker's options; it does not eliminate them.
    if invite.is_signed() {
        let now_ms: u64 = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| anyhow::anyhow!("system clock is set before unix epoch: {e}"))?
                .as_millis(),
        )
        .map_err(|_| anyhow::anyhow!("system clock value exceeds u64 ms — refusing to accept"))?;
        invite
            .verify_signature(now_ms)
            .map_err(|e| anyhow::anyhow!("invite signature did not verify: {e}"))?;
        eprintln!(
            "onyx: invite signature is internally consistent (self-signed by the fingerprint \
             inside the invite — this is NOT a check that the invite came from the human you \
             think it did; verify the fingerprint out of band before trusting)"
        );
    } else if insecure_accept_unsigned {
        eprintln!(
            "onyx: WARNING — accepting an unsigned (v1) invite because \
             --insecure-accept-unsigned was passed. The side-channel could have substituted \
             any field. Re-verify the fingerprint OOB and ask for a v2 URL."
        );
    } else {
        anyhow::bail!(
            "refusing to accept an unsigned (v1) invite. v1 invites carry no signature, so a \
             side-channel MITM could have substituted any field (KEM / KP / hubs) without \
             detection. Ask the inviter to re-issue with `onyx invite` from a current daemon \
             (produces a signed v2 URL), or pass `--insecure-accept-unsigned` to opt in to \
             the historical (unsafe) behaviour."
        );
    }

    // TOFU cross-check (pairs with T-1). If we already have a pinned
    // key for this fingerprint AND it differs from the one in the
    // invite, refuse — a key change at accept-time is exactly the
    // signal `onyx contact list` was built to surface, and silently
    // re-pinning here would defeat the whole point.
    {
        let contacts = client::one_shot(socket, &ApiRequest::ListContacts).await?;
        if let ApiResponse::ListContactsOk { contacts } = contacts {
            let invite_fp = invite.fingerprint.to_string();
            for c in &contacts {
                if c.fingerprint == invite_fp && c.key_changed {
                    anyhow::bail!(
                        "the fingerprint in this invite ({invite_fp}) is already pinned, \
                         AND its identity key has changed since first contact (T-1). Run \
                         `onyx contact list` and verify out of band before sending. Refusing \
                         to send."
                    );
                }
            }
        }
    }

    // T8.2 transparency + T8.2-check intersection: if the inviter
    // disclosed their hub list, surface it to stderr AND check it
    // against our own daemon's configured hub list. If the
    // intersection is empty, warn loudly — the delivery will go out
    // via our hubs and never reach a hub the recipient subscribes
    // to. If non-empty, confirm "via N matching hub(s)" so the
    // operator sees the path. All on stderr; stdout stays JSON for
    // pipe-friendliness.
    if !invite.hubs.is_empty() {
        eprintln!("onyx: recipient publishes to {} hub(s):", invite.hubs.len());
        for hub in &invite.hubs {
            eprintln!("  • {hub}");
        }

        // Query our own daemon's hub list. If the Identity call
        // fails or returns Error, fall back to "no intersection
        // check possible" — better than refusing to send.
        let our_hubs = match client::one_shot(socket, &ApiRequest::Identity).await {
            Ok(ApiResponse::IdentityOk { hubs, .. }) => Some(hubs),
            _ => None,
        };
        if let Some(our_hubs) = our_hubs {
            let matching: Vec<&String> = invite
                .hubs
                .iter()
                .filter(|h| our_hubs.contains(*h))
                .collect();
            if our_hubs.is_empty() {
                eprintln!(
                    "onyx: WARNING — your daemon has NO hubs configured. The send will \
                     fail with NotReady. Pass `--hub onion:port,b32pubkey` (one or more \
                     times) to the daemon."
                );
            } else if matching.is_empty() {
                eprintln!(
                    "onyx: WARNING — your daemon's hubs ({}) do NOT intersect any of \
                     the recipient's hubs above. The envelope will be delivered to YOUR \
                     hubs, none of which the recipient subscribes to — they will \
                     never see it. Add at least one of the recipient's hubs to your \
                     daemon's `--hub` list.",
                    our_hubs.len()
                );
            } else {
                eprintln!(
                    "onyx: sending via {} matching hub(s) (out of {} your daemon \
                     publishes to and {} the recipient subscribes on).",
                    matching.len(),
                    our_hubs.len(),
                    invite.hubs.len()
                );
            }
        } else {
            eprintln!("onyx: (couldn't query daemon's own hub list; skipping intersection check)");
        }
    }

    // T-2: dispatch through the trust-anchored `SendInvite` API verb.
    // The daemon re-parses + re-verifies the URL (so a malicious local
    // process bypassing this CLI can't strip the signature), cross-
    // checks the pin store, and picks the tier (msg/v1 vs mls/v1)
    // based on whether the invite carries a KP. We pass the URL
    // through verbatim — the CLI is intentionally a thin wrapper
    // here, no per-tier dispatch logic on this side.
    let resp = client::one_shot(
        socket,
        &ApiRequest::SendInvite {
            url: url.to_string(),
            text,
            insecure_accept_unsigned,
        },
    )
    .await?;
    match &resp {
        ApiResponse::SendInviteOk { tier, was_signed } => {
            eprintln!(
                "onyx: sent via {tier} ({})",
                if *was_signed {
                    "signed invite, sig verified daemon-side"
                } else {
                    "unsigned v1, accepted under --insecure-accept-unsigned"
                }
            );
        }
        ApiResponse::Error { .. } => {}
        other => eprintln!("onyx: unexpected response shape: {other:?}"),
    }
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(match resp {
        ApiResponse::Error { .. } => ExitCode::from(1),
        _ => ExitCode::SUCCESS,
    })
}

/// Send `req`, pretty-print the response as JSON on stdout, return
/// `1` if the daemon returned an `Error`, `0` otherwise.
async fn one_shot_print(socket: &std::path::Path, req: ApiRequest) -> anyhow::Result<ExitCode> {
    let resp = client::one_shot(socket, &req).await?;
    let json = serde_json::to_string_pretty(&resp)?;
    println!("{json}");
    Ok(match resp {
        ApiResponse::Error { .. } => ExitCode::from(1),
        _ => ExitCode::SUCCESS,
    })
}

#[cfg(test)]
mod tests {
    // UX phase 3: the passphrase strength hint is a pure function; its
    // thresholds are a UX nudge, so we just pin the buckets so a future
    // tweak is deliberate. In `cargo test` stderr isn't a tty, so
    // `paint` returns plain text → substring asserts are stable.
    #[test]
    fn passphrase_strength_buckets() {
        use super::passphrase_strength_hint as h;
        assert!(h("abcdefgh").contains("weak"), "short all-lower → weak");
        assert!(h("abcdefghijkl").contains("ok"), "12 lower → ok");
        assert!(h("Abcdef12!xyz").contains("ok"), "12 chars, 4 classes → ok");
        assert!(
            h("correct horse battery staple").contains("strong"),
            "long passphrase → strong"
        );
        assert!(
            h("Abcdefgh12!xyz").contains("strong"),
            "14 chars + 4 classes → strong"
        );
    }

    use super::*;
    use clap::Parser;

    /// Lock in the CLI shape so a future arg rename doesn't silently
    /// break shell scripts users have written against this command.
    #[test]
    fn send_bootstrap_parses_with_three_flags() {
        let args = Args::try_parse_from([
            "onyx",
            "send-bootstrap",
            "--peer-fingerprint",
            "abcd efgh",
            "--peer-kem-pub-b32",
            "longb32stringgoeshere",
            "--text",
            "hello via hub",
        ])
        .expect("parses");
        match args.cmd {
            Some(Command::SendBootstrap {
                peer_fingerprint,
                peer_kem_pub_b32,
                text,
            }) => {
                assert_eq!(peer_fingerprint, "abcd efgh");
                assert_eq!(peer_kem_pub_b32, "longb32stringgoeshere");
                assert_eq!(text, "hello via hub");
            }
            other => panic!("expected SendBootstrap, got {other:?}"),
        }
    }

    #[test]
    fn send_bootstrap_requires_all_three_flags() {
        // Omitting --text must surface as a clap parse error rather
        // than defaulting to empty (sending an empty message silently
        // would be a real footgun).
        assert!(
            Args::try_parse_from([
                "onyx",
                "send-bootstrap",
                "--peer-fingerprint",
                "x",
                "--peer-kem-pub-b32",
                "y",
            ])
            .is_err()
        );
    }

    #[test]
    fn send_bootstrap_mls_parses_with_three_flags() {
        let args = Args::try_parse_from([
            "onyx",
            "send-bootstrap-mls",
            "--peer-fingerprint",
            "abcd",
            "--peer-kem-pub-b32",
            "kem",
            "--peer-kp-b64",
            "kpbase64",
        ])
        .expect("parses");
        match args.cmd {
            Some(Command::SendBootstrapMls {
                peer_fingerprint,
                peer_kem_pub_b32,
                peer_kp_b64,
                text,
            }) => {
                assert_eq!(peer_fingerprint, "abcd");
                assert_eq!(peer_kem_pub_b32, "kem");
                assert_eq!(peer_kp_b64, "kpbase64");
                assert_eq!(text, None, "--text omitted defaults to None");
            }
            other => panic!("expected SendBootstrapMls, got {other:?}"),
        }
    }

    #[test]
    fn send_bootstrap_mls_accepts_optional_text() {
        let args = Args::try_parse_from([
            "onyx",
            "send-bootstrap-mls",
            "--peer-fingerprint",
            "abcd",
            "--peer-kem-pub-b32",
            "kem",
            "--peer-kp-b64",
            "kpbase64",
            "--text",
            "hi there",
        ])
        .expect("parses");
        match args.cmd {
            Some(Command::SendBootstrapMls { text, .. }) => {
                assert_eq!(text.as_deref(), Some("hi there"));
            }
            other => panic!("expected SendBootstrapMls, got {other:?}"),
        }
    }

    #[test]
    fn fetch_keypackage_parses() {
        let args = Args::try_parse_from(["onyx", "fetch-keypackage", "--peer-fingerprint", "abcd"])
            .expect("parses");
        match args.cmd {
            Some(Command::FetchKeypackage { peer_fingerprint }) => {
                assert_eq!(peer_fingerprint, "abcd");
            }
            other => panic!("expected FetchKeypackage, got {other:?}"),
        }
    }

    #[test]
    fn send_bootstrap_mls_requires_all_three_flags() {
        // Same anti-footgun discipline as send-bootstrap: omitting
        // --peer-kp-b64 must be a clap parse error, not a silent default.
        assert!(
            Args::try_parse_from([
                "onyx",
                "send-bootstrap-mls",
                "--peer-fingerprint",
                "x",
                "--peer-kem-pub-b32",
                "y",
            ])
            .is_err()
        );
    }

    #[test]
    fn invite_subcommand_parses_with_no_args() {
        let args = Args::try_parse_from(["onyx", "invite"]).expect("parses");
        assert!(matches!(
            args.cmd,
            Some(Command::Invite {
                with_kp: false,
                with_hubs: false,
            })
        ));
    }

    #[test]
    fn invite_subcommand_parses_with_kp_flag() {
        let args = Args::try_parse_from(["onyx", "invite", "--with-kp"]).expect("parses");
        assert!(matches!(
            args.cmd,
            Some(Command::Invite {
                with_kp: true,
                with_hubs: false,
            })
        ));
    }

    #[test]
    fn invite_subcommand_parses_with_hubs_flag() {
        let args = Args::try_parse_from(["onyx", "invite", "--with-hubs"]).expect("parses");
        assert!(matches!(
            args.cmd,
            Some(Command::Invite {
                with_kp: false,
                with_hubs: true,
            })
        ));
    }

    #[test]
    fn invite_subcommand_parses_with_kp_and_hubs() {
        let args =
            Args::try_parse_from(["onyx", "invite", "--with-kp", "--with-hubs"]).expect("parses");
        assert!(matches!(
            args.cmd,
            Some(Command::Invite {
                with_kp: true,
                with_hubs: true,
            })
        ));
    }

    #[test]
    fn accept_subcommand_parses_url_and_text() {
        let args = Args::try_parse_from([
            "onyx",
            "accept",
            "onyx://invite/v1?fp=abcd&kem=efgh",
            "--text",
            "hi from accept",
        ])
        .expect("parses");
        match args.cmd {
            Some(Command::Accept {
                url,
                text,
                insecure_accept_unsigned,
            }) => {
                assert_eq!(url, "onyx://invite/v1?fp=abcd&kem=efgh");
                assert_eq!(text, "hi from accept");
                assert!(
                    !insecure_accept_unsigned,
                    "default must be false — opting into unsigned v1 is dangerous"
                );
            }
            other => panic!("expected Accept, got {other:?}"),
        }
    }

    #[test]
    fn accept_requires_text_flag() {
        // Empty introduction would silently ship an empty plaintext —
        // surface it as a clap parse error instead, same discipline
        // as send-bootstrap.
        assert!(Args::try_parse_from(["onyx", "accept", "onyx://invite/v1?fp=x&kem=y"]).is_err());
    }

    #[test]
    fn no_hub_flag_parses_to_empty_vec() {
        let args = Args::try_parse_from(["onyx"]).expect("parses");
        assert!(args.hubs.is_empty(), "no --hub args → empty Vec");
    }

    #[test]
    fn single_hub_flag_parses() {
        let args = Args::try_parse_from(["onyx", "--hub", "abc.onion:1,KEYBYTES"]).expect("parses");
        assert_eq!(args.hubs, vec!["abc.onion:1,KEYBYTES".to_string()]);
    }

    #[test]
    fn multiple_hub_flags_accumulate() {
        let args = Args::try_parse_from([
            "onyx",
            "--hub",
            "a.onion:1,KEYA",
            "--hub",
            "b.onion:1,KEYB",
            "--hub",
            "c.onion:1,KEYC",
        ])
        .expect("parses");
        assert_eq!(
            args.hubs,
            vec![
                "a.onion:1,KEYA".to_string(),
                "b.onion:1,KEYB".to_string(),
                "c.onion:1,KEYC".to_string(),
            ]
        );
    }
}
