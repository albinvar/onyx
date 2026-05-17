//! Wire transport — Noise XK handshake + framed AEAD channel.
//!
//! See DESIGN.md §5.1–§5.3. The handshake is
//! `Noise_XK_25519_ChaChaPoly_BLAKE2s`. After it completes both sides
//! hold a [`Session`] that encrypts and decrypts [`InnerFrame`]s under a
//! direction-specific transport key with monotonically-increasing
//! per-direction nonces (managed by `snow`).
//!
//! ## Layering
//!
//! This module owns the **state machine and codec** — it is synchronous,
//! has no I/O, and is testable without an async runtime. The actual
//! socket reads/writes belong to `onyxd`. Splitting concerns this way
//! makes the security-sensitive code (handshake, AEAD wrap/unwrap) easy
//! to unit-test and easy to drop into either a Tokio or a thread-per-peer
//! daemon later.
//!
//! ## Outer framing
//!
//! Every ciphertext sits inside an outer length prefix on the wire:
//!
//! ```text
//! 0       2                                          N
//! ┌───────┬──────────────────────────────────────────┐
//! │ len   │  Noise-encrypted bytes                   │
//! │ u16BE │  (always plaintext_bucket + 16-byte tag) │
//! └───────┴──────────────────────────────────────────┘
//! ```
//!
//! Helpers [`frame_with_length`] and [`split_length_prefix`] handle this
//! framing; they're decoupled from `Session` so the daemon can also use
//! them to chunk a stream into AEAD-sized frames before decryption.
//!
//! ## Note on key confirmation
//!
//! DESIGN.md v0.2 §5.2 mentioned an explicit key-confirmation message
//! after handshake. Noise XK already provides **explicit mutual
//! authentication** by the end of its third message — the initiator's
//! static key is authenticated via `se` in message 3, and the
//! responder's via the AEAD tag on message 2. There is no implicit-auth
//! gap to close, so we do not emit an extra round trip. The DESIGN doc
//! is being updated to match.

use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::crypto::{IdentityPublic, IdentitySecret};
use crate::error::{Error, Result};
use crate::wire::InnerFrame;

/// Noise pattern designator. The version label inside DESIGN.md is the
/// authoritative reference; if this string ever changes the protocol
/// version in [`crate::PROTOCOL_VERSION`] MUST change with it.
pub const NOISE_PATTERN: &str = "Noise_XK_25519_ChaChaPoly_BLAKE2s";

/// AEAD authentication-tag size for ChaCha20-Poly1305 frames.
pub const AEAD_TAG_LEN: usize = 16;

/// Upper bound on a single Noise handshake or transport message.
/// The Noise spec caps message size at 65 535; our padded buckets are at
/// most 4 KiB + 16 (`AEAD_TAG_LEN`), so 8 KiB is a comfortable working
/// buffer that avoids a fresh allocation per call.
const SCRATCH_BUF_LEN: usize = 8192;

fn map_noise_err(err: snow::Error) -> Error {
    match err {
        // A failed AEAD tag means tampering or wrong key — the only
        // outcome that must surface as a security signal rather than as
        // "internal bug." Everything else is a caller misuse or hostile
        // input that we treat opaquely. Binding the catch-all gives us
        // a spot to add `tracing::debug!` later without changing shape.
        snow::Error::Decrypt => Error::VerificationFailed,
        _other => Error::Internal("Noise transport error"),
    }
}

fn parse_params() -> Result<NoiseParams> {
    NOISE_PATTERN
        .parse()
        .map_err(|_| Error::Internal("Noise pattern failed to parse"))
}

// ── Initiator ──────────────────────────────────────────────────────────────

/// Initiator side of the Noise XK handshake.
///
/// Call sequence (XK is a 3-message pattern):
///
/// ```text
/// init.write_handshake()  →  send to peer        (message 1: `e`)
/// init.read_handshake(m)  ←  peer's message 2     (`e, ee`)
/// init.write_handshake()  →  send to peer        (message 3: `s, se`)
/// init.into_session()
/// ```
pub struct Initiator {
    state: HandshakeState,
}

impl Initiator {
    /// Build an initiator that will authenticate to `peer_static` using
    /// our `our_static` X25519 long-term key.
    pub fn new(our_static: &IdentitySecret, peer_static: &IdentityPublic) -> Result<Self> {
        let params = parse_params()?;
        let our_bytes = our_static.to_bytes();
        let peer_bytes = peer_static.to_bytes();
        let state = Builder::new(params)
            .local_private_key(&our_bytes[..])
            .remote_public_key(&peer_bytes[..])
            .build_initiator()
            .map_err(map_noise_err)?;
        Ok(Self { state })
    }

    /// Produce the next handshake message to send to the peer.
    pub fn write_handshake(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; SCRATCH_BUF_LEN];
        let n = self
            .state
            .write_message(&[], &mut buf)
            .map_err(map_noise_err)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Process an incoming handshake message from the peer.
    pub fn read_handshake(&mut self, msg: &[u8]) -> Result<()> {
        let mut scratch = vec![0u8; SCRATCH_BUF_LEN];
        self.state
            .read_message(msg, &mut scratch)
            .map_err(map_noise_err)?;
        Ok(())
    }

    #[must_use]
    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Promote the completed handshake to a transport [`Session`]. Errors
    /// if the handshake is not yet finished.
    pub fn into_session(self) -> Result<Session> {
        let ts = self.state.into_transport_mode().map_err(map_noise_err)?;
        Ok(Session { state: ts })
    }
}

impl std::fmt::Debug for Initiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Initiator")
            .field("handshake_finished", &self.state.is_handshake_finished())
            .finish_non_exhaustive()
    }
}

// ── Responder ──────────────────────────────────────────────────────────────

/// Responder side of the Noise XK handshake.
///
/// Call sequence:
///
/// ```text
/// resp.read_handshake(m1)  ←  initiator's message 1
/// resp.write_handshake()   →  send to initiator    (message 2)
/// resp.read_handshake(m3)  ←  initiator's message 3
/// resp.into_session()
/// ```
///
/// The initiator's static X25519 key is only authenticated after
/// message 3; callers MUST NOT trust [`Session::peer_static_key`] until
/// [`Self::into_session`] succeeds.
pub struct Responder {
    state: HandshakeState,
}

impl Responder {
    pub fn new(our_static: &IdentitySecret) -> Result<Self> {
        let params = parse_params()?;
        let our_bytes = our_static.to_bytes();
        let state = Builder::new(params)
            .local_private_key(&our_bytes[..])
            .build_responder()
            .map_err(map_noise_err)?;
        Ok(Self { state })
    }

    pub fn read_handshake(&mut self, msg: &[u8]) -> Result<()> {
        let mut scratch = vec![0u8; SCRATCH_BUF_LEN];
        self.state
            .read_message(msg, &mut scratch)
            .map_err(map_noise_err)?;
        Ok(())
    }

    pub fn write_handshake(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; SCRATCH_BUF_LEN];
        let n = self
            .state
            .write_message(&[], &mut buf)
            .map_err(map_noise_err)?;
        buf.truncate(n);
        Ok(buf)
    }

    #[must_use]
    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    pub fn into_session(self) -> Result<Session> {
        let ts = self.state.into_transport_mode().map_err(map_noise_err)?;
        Ok(Session { state: ts })
    }
}

impl std::fmt::Debug for Responder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Responder")
            .field("handshake_finished", &self.state.is_handshake_finished())
            .finish_non_exhaustive()
    }
}

// ── Session ────────────────────────────────────────────────────────────────

/// Established transport channel. Both sides hold one after a successful
/// handshake. AEAD nonces are managed internally by `snow` (monotonic
/// per-direction counters); the application never sees them.
pub struct Session {
    state: TransportState,
}

impl Session {
    /// Encrypt an [`InnerFrame`] under this session's send key.
    ///
    /// The returned bytes are the AEAD ciphertext (plaintext bucket + 16
    /// byte tag). To put them on the wire, add the outer length prefix
    /// with [`frame_with_length`].
    pub fn encrypt_frame(&mut self, frame: &InnerFrame) -> Result<Vec<u8>> {
        let plaintext = frame.encode_padded()?;
        let mut buf = vec![0u8; plaintext.len() + AEAD_TAG_LEN];
        let n = self
            .state
            .write_message(&plaintext, &mut buf)
            .map_err(map_noise_err)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Decrypt AEAD ciphertext into an [`InnerFrame`]. The outer length
    /// prefix MUST already be stripped (use [`split_length_prefix`]).
    ///
    /// Tampered ciphertext, wrong key, or replay (out-of-order frame)
    /// surface as [`Error::VerificationFailed`]; an opaque variant by
    /// design — never tell the caller why decryption failed.
    pub fn decrypt_frame(&mut self, ciphertext: &[u8]) -> Result<InnerFrame> {
        if ciphertext.len() < AEAD_TAG_LEN {
            return Err(Error::InvalidEncoding(
                "transport: ciphertext shorter than AEAD tag",
            ));
        }
        let mut buf = vec![0u8; ciphertext.len()];
        let n = self
            .state
            .read_message(ciphertext, &mut buf)
            .map_err(map_noise_err)?;
        buf.truncate(n);
        InnerFrame::decode(&buf)
    }

    /// Peer's X25519 long-term static key as authenticated by the
    /// handshake. For an [`Initiator`] this matches what was supplied at
    /// `new()`; for a [`Responder`] this is what was learned during the
    /// third handshake message.
    ///
    /// # Panics
    ///
    /// Will not panic — XK guarantees the remote static is known once
    /// the session exists.
    #[must_use]
    pub fn peer_static_key(&self) -> [u8; 32] {
        let raw = self
            .state
            .get_remote_static()
            .expect("XK guarantees remote static is known in transport mode");
        let mut out = [0u8; 32];
        out.copy_from_slice(raw);
        out
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").finish_non_exhaustive()
    }
}

// ── Outer length-prefix framing ────────────────────────────────────────────

/// Prepend a 2-byte big-endian length to `body` for stream framing.
///
/// Errors if `body` is larger than `u16::MAX` (65 535 bytes). The largest
/// frame Onyx produces is `bucket::LARGE + AEAD_TAG_LEN = 4112` bytes, so
/// this limit is not approached in practice.
pub fn frame_with_length(body: &[u8]) -> Result<Vec<u8>> {
    let len = u16::try_from(body.len())
        .map_err(|_| Error::InvalidEncoding("outer frame longer than u16::MAX"))?;
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// Read the 2-byte length prefix and return `(declared_len, body_slice)`.
///
/// Errors if the input is shorter than the prefix or shorter than the
/// declared body length.
pub fn split_length_prefix(data: &[u8]) -> Result<(usize, &[u8])> {
    if data.len() < 2 {
        return Err(Error::InvalidEncoding(
            "outer frame: too short for length prefix",
        ));
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + len {
        return Err(Error::InvalidEncoding(
            "outer frame: body shorter than declared length",
        ));
    }
    Ok((len, &data[2..2 + len]))
}

// ── Async I/O bridge ───────────────────────────────────────────────────────
//
// Everything above is sync state + codec — no I/O. The helpers below
// glue that machinery onto any `tokio::io::AsyncRead + AsyncWrite`
// stream (a Tor circuit, a TcpStream, an in-memory duplex pair, …)
// using the existing length-prefix framing on the wire.
//
// We deliberately keep these as free functions rather than methods on
// `Session` / `Initiator` / `Responder`. That way the sync types stay
// usable from non-async test paths (which is what every test in the
// rest of this file does), and the async surface is the thinnest
// possible adapter around them.

/// Largest single Noise message we'll accept from the wire.
///
/// During handshake the protocol-defined max is 65 535 bytes; in
/// practice XK messages are < 100 B (m1) and < 50 B (m2/m3) with our
/// empty payloads. During transport the max we'd ever send is
/// `bucket::LARGE + AEAD_TAG_LEN = 4 112` bytes. We cap at 65 535 — the
/// Noise spec ceiling — so a hostile peer can't make us allocate
/// arbitrarily.
const MAX_WIRE_MESSAGE: usize = u16::MAX as usize;

/// Read one length-prefixed message from the wire. Returns the body
/// (length prefix stripped); errors on EOF or if the declared length
/// exceeds [`MAX_WIRE_MESSAGE`].
async fn read_lp<R: AsyncReadExt + Unpin>(stream: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|_| Error::Internal("transport: read length prefix"))?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len > MAX_WIRE_MESSAGE {
        return Err(Error::InvalidEncoding(
            "transport: declared message length exceeds MAX_WIRE_MESSAGE",
        ));
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|_| Error::Internal("transport: read body"))?;
    Ok(body)
}

/// Write `body` as a length-prefixed message and flush.
async fn write_lp<W: AsyncWriteExt + Unpin>(stream: &mut W, body: &[u8]) -> Result<()> {
    let framed = frame_with_length(body)?;
    stream
        .write_all(&framed)
        .await
        .map_err(|_| Error::Internal("transport: write framed bytes"))?;
    stream
        .flush()
        .await
        .map_err(|_| Error::Internal("transport: flush"))?;
    Ok(())
}

/// Drive the Noise XK handshake to completion on the **initiator** side
/// over an async stream. Returns the established [`Session`].
///
/// Wire order: write m1 → read m2 → write m3 → done.
pub async fn handshake_initiator<S>(
    stream: &mut S,
    our_static: &IdentitySecret,
    peer_static: &IdentityPublic,
) -> Result<Session>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut init = Initiator::new(our_static, peer_static)?;
    let m1 = init.write_handshake()?;
    write_lp(stream, &m1).await?;
    let m2 = read_lp(stream).await?;
    init.read_handshake(&m2)?;
    let m3 = init.write_handshake()?;
    write_lp(stream, &m3).await?;
    init.into_session()
}

/// Drive the Noise XK handshake to completion on the **responder** side
/// over an async stream. Returns the established [`Session`].
///
/// Wire order: read m1 → write m2 → read m3 → done.
pub async fn handshake_responder<S>(stream: &mut S, our_static: &IdentitySecret) -> Result<Session>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut resp = Responder::new(our_static)?;
    let m1 = read_lp(stream).await?;
    resp.read_handshake(&m1)?;
    let m2 = resp.write_handshake()?;
    write_lp(stream, &m2).await?;
    let m3 = read_lp(stream).await?;
    resp.read_handshake(&m3)?;
    resp.into_session()
}

/// Encrypt and send one [`InnerFrame`].
///
/// Wire layout: `len(u16) ‖ ChaCha20-Poly1305(type ‖ payload ‖ padding)`.
pub async fn write_frame<W>(stream: &mut W, session: &mut Session, frame: &InnerFrame) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let ct = session.encrypt_frame(frame)?;
    write_lp(stream, &ct).await
}

/// Receive and decrypt one [`InnerFrame`].
pub async fn read_frame<R>(stream: &mut R, session: &mut Session) -> Result<InnerFrame>
where
    R: AsyncReadExt + Unpin,
{
    let ct = read_lp(stream).await?;
    session.decrypt_frame(&ct)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::IdentitySecret;
    use crate::wire::{FRAME_DELIVER, FRAME_PING, InnerFrame};
    use proptest::prelude::*;

    /// Run a complete XK handshake in memory and return both sessions,
    /// plus the initiator's public key for the responder-learns-it test.
    #[allow(clippy::similar_names)] // alice_sk / bob_sk / alice_pk / bob_pk are intentional
    fn handshake() -> (Session, Session, [u8; 32]) {
        let alice_sk = IdentitySecret::generate();
        let bob_sk = IdentitySecret::generate();
        let alice_pk = alice_sk.public().to_bytes();
        let bob_pk = bob_sk.public();

        let mut init = Initiator::new(&alice_sk, &bob_pk).unwrap();
        let mut resp = Responder::new(&bob_sk).unwrap();

        let m1 = init.write_handshake().unwrap();
        resp.read_handshake(&m1).unwrap();
        let m2 = resp.write_handshake().unwrap();
        init.read_handshake(&m2).unwrap();
        let m3 = init.write_handshake().unwrap();
        resp.read_handshake(&m3).unwrap();

        assert!(init.is_handshake_finished());
        assert!(resp.is_handshake_finished());

        (
            init.into_session().unwrap(),
            resp.into_session().unwrap(),
            alice_pk,
        )
    }

    #[test]
    fn handshake_completes() {
        let _ = handshake();
    }

    #[test]
    fn responder_learns_initiator_static() {
        let (_alice, bob, alice_pk) = handshake();
        assert_eq!(
            bob.peer_static_key(),
            alice_pk,
            "responder must learn the initiator's authenticated static key"
        );
    }

    #[test]
    fn round_trip_frame() {
        let (mut alice, mut bob, _) = handshake();
        let frame = InnerFrame {
            frame_type: FRAME_PING,
            payload: b"hello over noise".to_vec(),
        };
        let ct = alice.encrypt_frame(&frame).unwrap();
        let got = bob.decrypt_frame(&ct).unwrap();
        assert_eq!(got, frame);
    }

    #[test]
    fn multiple_frames_in_order() {
        let (mut alice, mut bob, _) = handshake();
        for i in 0..10u8 {
            let frame = InnerFrame {
                frame_type: FRAME_DELIVER,
                payload: vec![i; 100],
            };
            let ct = alice.encrypt_frame(&frame).unwrap();
            let got = bob.decrypt_frame(&ct).unwrap();
            assert_eq!(got, frame);
        }
    }

    #[test]
    fn bidirectional_traffic() {
        let (mut alice, mut bob, _) = handshake();
        let from_alice = InnerFrame {
            frame_type: FRAME_PING,
            payload: b"alice".to_vec(),
        };
        let from_bob = InnerFrame {
            frame_type: FRAME_PING,
            payload: b"bob".to_vec(),
        };

        let ct_a = alice.encrypt_frame(&from_alice).unwrap();
        let ct_b = bob.encrypt_frame(&from_bob).unwrap();

        assert_eq!(bob.decrypt_frame(&ct_a).unwrap(), from_alice);
        assert_eq!(alice.decrypt_frame(&ct_b).unwrap(), from_bob);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (mut alice, mut bob, _) = handshake();
        let frame = InnerFrame {
            frame_type: FRAME_PING,
            payload: b"do not modify".to_vec(),
        };
        let mut ct = alice.encrypt_frame(&frame).unwrap();
        ct[0] ^= 0x01;
        assert!(matches!(
            bob.decrypt_frame(&ct),
            Err(Error::VerificationFailed)
        ));
    }

    #[test]
    fn out_of_order_rejected() {
        let (mut alice, mut bob, _) = handshake();
        let f1 = InnerFrame {
            frame_type: FRAME_PING,
            payload: b"a".to_vec(),
        };
        let f2 = InnerFrame {
            frame_type: FRAME_PING,
            payload: b"b".to_vec(),
        };
        let _ct1 = alice.encrypt_frame(&f1).unwrap();
        let ct2 = alice.encrypt_frame(&f2).unwrap();
        // Bob has not consumed ct1 yet — its counter is 0 — so ct2
        // (counter 1) must fail the AEAD check.
        assert!(matches!(
            bob.decrypt_frame(&ct2),
            Err(Error::VerificationFailed)
        ));
    }

    #[test]
    #[allow(clippy::similar_names)] // alice/bob/mallory _sk pairs are intentional
    fn wrong_responder_key_breaks_handshake() {
        // Alice expects Mallory's static key; she actually talks to Bob.
        // In Noise XK, message 1 already carries an AEAD tag bound to
        // the responder's expected static via the `es` DH. Alice
        // computes `es` against Mallory's static, Bob computes `es`
        // against his own — the chain keys diverge at step 1, so Bob's
        // decryption of m1 fails. This is the strongest possible
        // outcome: the responder never even sees a valid first message
        // and cannot leak any payload back.
        let alice_sk = IdentitySecret::generate();
        let bob_sk = IdentitySecret::generate();
        let mallory_sk = IdentitySecret::generate();

        let mut init = Initiator::new(&alice_sk, &mallory_sk.public()).unwrap();
        let mut resp = Responder::new(&bob_sk).unwrap();

        let m1 = init.write_handshake().unwrap();
        assert!(matches!(
            resp.read_handshake(&m1),
            Err(Error::VerificationFailed)
        ));
    }

    #[test]
    fn decrypt_rejects_too_short() {
        let (_, mut bob, _) = handshake();
        // Anything shorter than the 16-byte AEAD tag is malformed before
        // we even attempt decryption.
        assert!(matches!(
            bob.decrypt_frame(&[0u8; 8]),
            Err(Error::InvalidEncoding(_))
        ));
    }

    #[test]
    fn length_prefix_round_trip() {
        let body = b"some bytes";
        let framed = frame_with_length(body).unwrap();
        let expected_len = u16::try_from(body.len()).unwrap();
        assert_eq!(&framed[..2], &expected_len.to_be_bytes());
        let (len, rest) = split_length_prefix(&framed).unwrap();
        assert_eq!(len, body.len());
        assert_eq!(rest, body);
    }

    #[test]
    fn length_prefix_rejects_short_input() {
        assert!(split_length_prefix(&[]).is_err());
        assert!(split_length_prefix(&[0x00]).is_err());
        // Claims 16-byte body, only one byte present.
        assert!(split_length_prefix(&[0x00, 0x10, 0xAA]).is_err());
    }

    #[test]
    fn length_prefix_rejects_oversized_body() {
        let too_long = vec![0u8; usize::from(u16::MAX) + 1];
        assert!(matches!(
            frame_with_length(&too_long),
            Err(Error::InvalidEncoding(_))
        ));
    }

    /// End-to-end exercise of the async path using a tokio in-memory
    /// duplex pair. Proves handshake_initiator + handshake_responder
    /// drive XK to completion over a real `AsyncRead+AsyncWrite`, and
    /// that read_frame + write_frame correctly bridge `Session` to
    /// async I/O.
    #[allow(clippy::similar_names)] // alice / bob _sk / _pk are intentional
    #[tokio::test]
    async fn async_handshake_and_frame_round_trip() {
        let alice_sk = IdentitySecret::generate();
        let bob_sk = IdentitySecret::generate();
        let bob_pk = bob_sk.public();

        // 64 KiB is comfortably larger than the biggest frame we'd send.
        let (mut alice_io, mut bob_io) = tokio::io::duplex(65_536);

        let alice_pk_for_assert = alice_sk.public().to_bytes();

        let alice_task = tokio::spawn(async move {
            let mut session = handshake_initiator(&mut alice_io, &alice_sk, &bob_pk)
                .await
                .expect("alice handshake");
            let frame = InnerFrame {
                frame_type: FRAME_PING,
                payload: b"hello bob".to_vec(),
            };
            write_frame(&mut alice_io, &mut session, &frame)
                .await
                .expect("alice write");
            let reply = read_frame(&mut alice_io, &mut session)
                .await
                .expect("alice read");
            (session.peer_static_key(), reply)
        });

        let bob_task = tokio::spawn(async move {
            let mut session = handshake_responder(&mut bob_io, &bob_sk)
                .await
                .expect("bob handshake");
            let got = read_frame(&mut bob_io, &mut session)
                .await
                .expect("bob read");
            let reply = InnerFrame {
                frame_type: FRAME_PING,
                payload: b"hello alice".to_vec(),
            };
            write_frame(&mut bob_io, &mut session, &reply)
                .await
                .expect("bob write");
            (session.peer_static_key(), got)
        });

        let (alice_result, bob_result) = tokio::join!(alice_task, bob_task);
        let (alice_peer_static, alice_reply) = alice_result.unwrap();
        let (bob_peer_static, bob_got) = bob_result.unwrap();

        // Each side learned the *other's* static key from the
        // authenticated handshake.
        assert_eq!(alice_peer_static, bob_pk.to_bytes());
        assert_eq!(bob_peer_static, alice_pk_for_assert);

        assert_eq!(bob_got.payload, b"hello bob");
        assert_eq!(alice_reply.payload, b"hello alice");
    }

    proptest! {
        /// Arbitrary bytes never panic the AEAD decoder. They almost
        /// always fail (correct), but we require they fail *safely*.
        #[test]
        fn prop_decrypt_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..8192)) {
            let (_, mut bob, _) = handshake();
            let _ = bob.decrypt_frame(&bytes);
        }

        /// Arbitrary bytes never panic the responder's handshake decoder.
        #[test]
        fn prop_handshake_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..8192)) {
            let bob_sk = IdentitySecret::generate();
            let mut resp = Responder::new(&bob_sk).unwrap();
            let _ = resp.read_handshake(&bytes);
        }

        /// Length-prefix round-trip for arbitrary bodies that fit u16.
        #[test]
        fn prop_length_prefix_round_trip(body in prop::collection::vec(any::<u8>(), 0..=8192)) {
            let framed = frame_with_length(&body).unwrap();
            let (len, rest) = split_length_prefix(&framed).unwrap();
            prop_assert_eq!(len, body.len());
            prop_assert_eq!(rest, body.as_slice());
        }
    }
}
