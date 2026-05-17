//! `onyxd` — the Onyx daemon process.
//!
//! Responsibilities (DESIGN.md §3.2):
//!
//!   * Own the user's [`onyx_core::identity::Identity`] for the
//!     lifetime of the process (vault is unlocked at startup with a
//!     passphrase from the environment).
//!   * Run an embedded Tor client and publish the user's v3 hidden
//!     service so peers can dial in.
//!   * Maintain outbound connections to peers and hubs via Tor.
//!   * Expose a local API socket for the CLI (`onyx`) to drive.
//!
//! ## What this revision does
//!
//! Phase T1.3 — "make two daemons talk." Beyond the vault + Tor +
//! HS-publish work already in place:
//!
//!   * On startup, logs both the **fingerprint** *and* the
//!     **X25519 identity public key** (base32) so the operator can
//!     hand both to the peer they want to dial.
//!   * **Default (accept) mode**: publishes the hidden service and
//!     runs a handler task per inbound stream — Noise XK handshake as
//!     responder, then read one [`onyx_core::wire::InnerFrame`], log
//!     it, write a reply, drop the connection.
//!   * **Dial mode** (`--dial-onion` + `--dial-pubkey`): skips HS
//!     publish, dials the peer over Tor, runs Noise XK as initiator,
//!     writes one greeting frame, reads the peer's reply, exits 0.
//!
//! ## What's not here yet
//!
//! - Local API socket for the CLI to drive (the `--dial` flag is the
//!   one-shot equivalent for now).
//! - Persistent connection management (each handler accepts one frame
//!   and exits).
//! - HS key bound to long-term `Identity` (Arti's keymgr generates a
//!   fresh HS key per nickname today).
//! - Contact verification on the dial path (initiator accepts any peer
//!   X25519 that decapsulates correctly).
//! - Sealed-sender bootstrap / MLS Welcome — the frame content here is
//!   just `b"hello from <fpr>"`, not a real protocol message.

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use futures::StreamExt;
use onyx_core::crypto::{Argon2Params, IdentityPublic};
use onyx_core::identity::Identity;
use onyx_core::storage::Vault;
use onyx_core::tor::{TorRuntime, TorStream};
use onyx_core::transport::{handshake_initiator, handshake_responder, read_frame, write_frame};
use onyx_core::wire::{FRAME_PING, InnerFrame};
use tokio::io::AsyncWriteExt;
use tracing::{Instrument, error, info, info_span, warn};

const DEFAULT_IDENTITY_NICKNAME: &str = "default";
const HS_NICKNAME: &str = "onyx";

/// Application port on the hidden service. v3 onions multiplex by
/// virtual port number; we'll pick `1` as Onyx's well-known port for
/// now. Real protocol would use something like 19940.
const ONYX_HS_PORT: u16 = 1;

#[derive(Parser, Debug)]
#[command(name = "onyxd", version, about = "Onyx daemon")]
struct Args {
    /// Path to the encrypted vault file. Created on first run, opened
    /// thereafter.
    #[arg(long, env = "ONYX_VAULT", default_value = "./onyx-state.db")]
    vault: PathBuf,

    /// Vault passphrase. **Strongly recommended** to pass via
    /// environment variable rather than command line.
    #[arg(long, env = "ONYX_PASSPHRASE", hide_env_values = true)]
    passphrase: String,

    /// Skip the Tor bootstrap entirely. Useful for vault/identity
    /// smoke tests without 30 s of waiting or outbound network.
    #[arg(long)]
    no_tor: bool,

    /// **Dial mode**: connect to a peer's onion instead of publishing
    /// our own hidden service. Pass the address as `<onion>:<port>`,
    /// e.g. `abc123…xyz.onion:1`.
    #[arg(long, requires = "dial_pubkey")]
    dial_onion: Option<String>,

    /// X25519 identity public key of the peer to dial. Base32 (RFC 4648
    /// lowercase, no padding) — the same format the daemon prints at
    /// startup for its own key.
    #[arg(long, requires = "dial_onion")]
    dial_pubkey: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    // ── Vault + identity ────────────────────────────────────────────────
    let mut vault =
        open_or_create_vault(&args.vault, args.passphrase.as_bytes()).context("opening vault")?;

    let identity = ensure_default_identity(&mut vault).context("ensuring default identity")?;

    let fingerprint = identity.fingerprint();
    let identity_pub_b32 = encode_b32(&identity.identity_key().public().to_bytes());
    info!(
        fingerprint = %fingerprint,
        identity_pub_b32 = %identity_pub_b32,
        "vault unlocked, identity loaded"
    );

    drop(args.passphrase);

    if args.no_tor {
        warn!("--no-tor set: skipping Tor; daemon will idle until Ctrl-C");
        wait_for_ctrl_c().await;
        return Ok(());
    }

    // ── Tor bootstrap ───────────────────────────────────────────────────
    info!("bootstrapping Tor (this may take 30-60s on a cold cache)…");
    let tor = TorRuntime::bootstrap()
        .await
        .map_err(|e| anyhow::anyhow!("tor bootstrap failed: {e}"))?;
    info!("Tor bootstrap complete");

    if let (Some(onion), Some(pubkey_b32)) = (&args.dial_onion, &args.dial_pubkey) {
        run_dial_mode(&tor, &identity, onion, pubkey_b32).await?;
    } else {
        run_accept_mode(&tor, identity).await?;
    }

    drop(tor);
    drop(vault);
    Ok(())
}

// ── Accept mode (default) ──────────────────────────────────────────────────

async fn run_accept_mode(tor: &TorRuntime, identity: Identity) -> anyhow::Result<()> {
    let mut hs = tor
        .publish_hidden_service(HS_NICKNAME)
        .map_err(|e| anyhow::anyhow!("hidden service publish failed: {e}"))?;

    if let Some(addr) = hs.onion_address() {
        info!(
            onion = %addr,
            port = ONYX_HS_PORT,
            "hidden service published — peer needs onion + port + identity_pub_b32"
        );
    } else {
        warn!("hidden service has no address yet — Arti will produce one shortly");
    }

    let mut accept = hs
        .take_accept_streams()
        .context("HS accept-stream already taken")?;

    // The Identity holds long-term secrets. Share via Arc<Identity>
    // across spawned handler tasks — Identity is not Clone.
    let identity = std::sync::Arc::new(identity);

    info!("onyxd running in accept mode. Ctrl-C to stop.");

    // Run an accept loop in parallel with Ctrl-C.
    let accept_loop = async {
        while let Some(stream) = accept.next().await {
            let identity = identity.clone();
            let our_fpr = identity.fingerprint();
            let span = info_span!("inbound", local_fpr = %our_fpr);
            tokio::spawn(
                async move {
                    if let Err(e) = handle_inbound(stream, &identity).await {
                        warn!(error = %e, "inbound handler failed");
                    }
                }
                .instrument(span),
            );
        }
        info!("accept stream ended");
    };

    tokio::select! {
        () = accept_loop => {},
        () = wait_for_ctrl_c() => info!("shutting down on Ctrl-C"),
    }

    drop(hs);
    Ok(())
}

async fn handle_inbound(mut stream: TorStream, identity: &Identity) -> anyhow::Result<()> {
    info!("accepted inbound stream; starting Noise XK handshake (responder)");
    let mut session = handshake_responder(&mut stream, identity.identity_key())
        .await
        .map_err(|e| anyhow::anyhow!("handshake failed: {e}"))?;

    let peer_pub_b32 = encode_b32(&session.peer_static_key());
    info!(peer_identity_pub_b32 = %peer_pub_b32, "handshake complete");

    let frame = read_frame(&mut stream, &mut session)
        .await
        .map_err(|e| anyhow::anyhow!("read frame failed: {e}"))?;
    let payload = String::from_utf8_lossy(&frame.payload).into_owned();
    info!(
        frame_type = format!("{:#06x}", frame.frame_type),
        payload, "received frame"
    );

    let reply_text = format!("hello from {} (responder)", identity.fingerprint());
    let reply = InnerFrame {
        frame_type: FRAME_PING,
        payload: reply_text.into_bytes(),
    };
    write_frame(&mut stream, &mut session, &reply)
        .await
        .map_err(|e| anyhow::anyhow!("write reply failed: {e}"))?;
    info!("reply written, closing stream");
    let _ = stream.shutdown().await;
    Ok(())
}

// ── Dial mode ──────────────────────────────────────────────────────────────

async fn run_dial_mode(
    tor: &TorRuntime,
    identity: &Identity,
    onion_target: &str,
    peer_pubkey_b32: &str,
) -> anyhow::Result<()> {
    // Split "abc.onion:N" into (host, port). Default to ONYX_HS_PORT
    // if the caller didn't supply one.
    let (host, port) = match onion_target.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .with_context(|| format!("bad port in --dial-onion: {p}"))?,
        ),
        None => (onion_target.to_string(), ONYX_HS_PORT),
    };

    let peer_pub_bytes: [u8; 32] =
        decode_b32_32(peer_pubkey_b32).context("--dial-pubkey must decode to 32 bytes")?;
    let peer_pub = IdentityPublic::from_bytes(peer_pub_bytes);

    info!(host = %host, port = port, "dialing peer onion…");
    let mut stream = tor
        .dial(&host, port)
        .await
        .map_err(|e| anyhow::anyhow!("dial failed: {e}"))?;
    info!("Tor circuit established; starting Noise XK handshake (initiator)");

    let mut session = handshake_initiator(&mut stream, identity.identity_key(), &peer_pub)
        .await
        .map_err(|e| anyhow::anyhow!("handshake failed: {e}"))?;

    let learned_peer = encode_b32(&session.peer_static_key());
    info!(peer_identity_pub_b32 = %learned_peer, "handshake complete");

    let greeting = format!("hello from {} (initiator)", identity.fingerprint());
    let frame = InnerFrame {
        frame_type: FRAME_PING,
        payload: greeting.into_bytes(),
    };
    write_frame(&mut stream, &mut session, &frame)
        .await
        .map_err(|e| anyhow::anyhow!("write failed: {e}"))?;
    info!("greeting sent; awaiting peer reply");

    let reply = read_frame(&mut stream, &mut session)
        .await
        .map_err(|e| anyhow::anyhow!("read failed: {e}"))?;
    let payload = String::from_utf8_lossy(&reply.payload).into_owned();
    info!(payload, "received reply — round-trip complete");

    let _ = stream.shutdown().await;
    Ok(())
}

// ── Vault helpers ──────────────────────────────────────────────────────────

fn open_or_create_vault(path: &std::path::Path, passphrase: &[u8]) -> anyhow::Result<Vault> {
    if path.exists() {
        info!(path = %path.display(), "opening existing vault");
        Vault::open(path, passphrase)
            .map_err(|e| anyhow::anyhow!("vault open failed (wrong passphrase?): {e}"))
    } else {
        info!(path = %path.display(), "creating new vault");
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating vault parent directory {}", parent.display()))?;
        }
        Vault::create(path, passphrase, &Argon2Params::FLOOR)
            .map_err(|e| anyhow::anyhow!("vault create failed: {e}"))
    }
}

fn ensure_default_identity(vault: &mut Vault) -> anyhow::Result<Identity> {
    let existing = vault
        .list_identities()
        .map_err(|e| anyhow::anyhow!("list identities: {e}"))?;
    if let Some(first) = existing.into_iter().next() {
        return vault
            .get_identity(first.id)
            .map_err(|e| anyhow::anyhow!("loading identity {}: {e}", first.id));
    }
    info!("no identity found; generating fresh \"{DEFAULT_IDENTITY_NICKNAME}\" identity");
    let (_id, identity) = vault
        .create_identity(DEFAULT_IDENTITY_NICKNAME)
        .map_err(|e| anyhow::anyhow!("create identity: {e}"))?;
    Ok(identity)
}

// ── Base32 helpers for 32-byte X25519 pub keys ────────────────────────────

/// Same base32 alphabet the fingerprint uses (RFC 4648 lowercase, no
/// padding). 32 bytes → 52 characters.
fn encode_b32(bytes: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, bytes)
}

fn decode_b32_32(s: &str) -> anyhow::Result<[u8; 32]> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    let bytes = base32::decode(base32::Alphabet::Rfc4648Lower { padding: false }, &cleaned)
        .ok_or_else(|| anyhow::anyhow!("not valid base32"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("expected 32 bytes, got {}", v.len()))?;
    Ok(arr)
}

async fn wait_for_ctrl_c() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => {}
        Err(e) => error!("failed to listen for Ctrl-C: {e}"),
    }
}
