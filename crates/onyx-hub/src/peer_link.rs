//! Outbound peer-hub Noise XK session (T8.3.b.2+).
//!
//! Each `--peer-hub` entry on the hub binary spawns one task that:
//!
//!   1. Dials the peer hub's onion via the shared `TorRuntime`.
//!   2. Runs Noise XK as initiator with our hub identity secret and
//!      the peer hub's authenticated static key.
//!   3. Drains an `mpsc::Receiver<Vec<u8>>` that the rest of the hub
//!      pushes pre-encoded `GossipFrame` payloads into.
//!   4. Wraps each payload in an `InnerFrame { frame_type:
//!      FRAME_GOSSIP_PUBLISH, payload }` and writes it on the wire.
//!   5. On any error (peer disconnect, write failure, handshake
//!      failure), logs at `warn!`, sleeps with exponential backoff,
//!      and reconnects. The outbound channel is preserved across
//!      reconnects so queued gossip survives the gap (within the
//!      channel's bounded capacity).
//!
//! ## What this task does NOT do (T8.3.b.4 will add it)
//!
//!   * **Read inbound gossip frames** from the peer. The current
//!     session is one-way: we push, they receive. The peer hub's
//!     *own* outbound link back to us is a separate session opened
//!     by the peer (one-direction-per-pair, per FEDERATION.md §2.1
//!     recommendation Q1).
//!   * **Handle `FRAME_GOSSIP_DELIVER`**. Reserved for T8.3.c (queue
//!     gossip). This task currently emits only `FRAME_GOSSIP_PUBLISH`.
//!
//! ## What this task does NOT yet do (T8.3.b.4 inbound side)
//!
//!   * **Validate inbound gossip**. The inbound path lives in
//!     `handler.rs::serve_frames` once T8.3.b.4 lands the peer-role
//!     detection. This module's responsibility ends at "successfully
//!     wrote bytes to the peer's accept stream."

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use onyx_core::crypto::{IdentityPublic, IdentitySecret};
use onyx_core::tor::TorRuntime;
use onyx_core::transport::{handshake_initiator, write_frame};
use onyx_core::wire::InnerFrame;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Reasonable starting backoff; doubles on each failure up to
/// [`BACKOFF_MAX`].
const BACKOFF_INITIAL: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Bounded mailbox per peer-hub outbound. A normal hub gossips
/// at most a few KP_PUBLISHes per second; this cap is generous.
/// When full, `HubState::fan_out_kp_to_peers` drops gossip for
/// that one peer (`try_send` → `TrySendError::Full`) and logs a
/// warning. Other peers + the local store are unaffected.
pub const PEER_OUTBOUND_CAPACITY: usize = 256;

/// Drive one outbound peer-hub session forever. Returns only if the
/// receiver closes (parent task aborted). Otherwise reconnects with
/// exponential backoff on any per-session error.
pub async fn run_peer_session(
    tor: Arc<TorRuntime>,
    host: String,
    port: u16,
    peer_pubkey: IdentityPublic,
    our_sk: Arc<IdentitySecret>,
    mut outbound_rx: mpsc::Receiver<InnerFrame>,
) -> anyhow::Result<()> {
    let mut backoff = BACKOFF_INITIAL;
    loop {
        match run_once(&tor, &host, port, &peer_pubkey, &our_sk, &mut outbound_rx).await {
            Ok(()) => {
                // Receiver closed (hub shutting down). Exit cleanly.
                info!(host = %host, port, "peer-hub: outbound channel closed, task exiting");
                return Ok(());
            }
            Err(e) => {
                warn!(host = %host, port, error = %e, "peer-hub: session ended with error");
            }
        }
        let backoff_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX);
        info!(
            host = %host,
            port,
            backoff_ms,
            "peer-hub: backing off before reconnect"
        );
        tokio::time::sleep(backoff).await;
        backoff = std::cmp::min(backoff * 2, BACKOFF_MAX);
    }
}

/// One attempt: dial, handshake, drain. Returns `Ok(())` only when
/// the outbound channel is closed (clean shutdown). Any I/O or
/// handshake error returns `Err`, which the outer loop logs and
/// retries after backoff.
async fn run_once(
    tor: &TorRuntime,
    host: &str,
    port: u16,
    peer_pubkey: &IdentityPublic,
    our_sk: &IdentitySecret,
    outbound_rx: &mut mpsc::Receiver<InnerFrame>,
) -> anyhow::Result<()> {
    info!(host, port, "peer-hub: dialing");
    let mut stream = tor
        .dial(host, port)
        .await
        .map_err(|e| anyhow::anyhow!("peer-hub dial failed: {e}"))?;
    info!(
        host,
        port, "peer-hub: Tor circuit established; starting Noise XK (initiator)"
    );
    let mut session = handshake_initiator(&mut stream, our_sk, peer_pubkey)
        .await
        .context("peer-hub: Noise XK handshake (initiator) failed")?;
    info!(
        host,
        port, "peer-hub: Noise XK complete; draining outbound gossip queue"
    );

    while let Some(frame) = outbound_rx.recv().await {
        write_frame(&mut stream, &mut session, &frame)
            .await
            .context("peer-hub: write_frame")?;
    }
    Ok(())
}
