//! Wire envelope, frame types, and CBOR codec.
//!
//! See DESIGN.md §5.3 (frame types) and §5.4 (DELIVER envelope).
//!
//! Frame-type discriminators (kept here so transport-layer code and the
//! hub agree on the same numeric constants):

/// `HELLO` — client → server, initial protocol version negotiation.
pub const FRAME_HELLO: u16 = 0x01;
/// `HELLO_ACK` — server → client, accept and assign session id.
pub const FRAME_HELLO_ACK: u16 = 0x02;
/// `DELIVER` — either direction, MLS-encrypted application message.
pub const FRAME_DELIVER: u16 = 0x10;
/// `ACK` — either direction, acknowledges a DELIVER.
pub const FRAME_ACK: u16 = 0x11;
/// `FETCH` — client → hub, pull queued messages.
pub const FRAME_FETCH: u16 = 0x20;
/// `FETCH_RESPONSE` — hub → client, batch of queued messages.
pub const FRAME_FETCH_RESPONSE: u16 = 0x21;
/// `SUBSCRIBE` — client → hub, register routing tokens for live delivery.
pub const FRAME_SUBSCRIBE: u16 = 0x22;
/// `ROOM_OP` — client → hub, create/join/leave/admin a room.
pub const FRAME_ROOM_OP: u16 = 0x30;
/// `ROOM_OP_ACK` — hub → client, result of a room op.
pub const FRAME_ROOM_OP_ACK: u16 = 0x31;
/// `PING` — either direction, keepalive.
pub const FRAME_PING: u16 = 0x40;
/// `PONG` — either direction, keepalive response.
pub const FRAME_PONG: u16 = 0x41;
/// `PAD` — either direction, cover traffic. Discarded by receiver.
pub const FRAME_PAD: u16 = 0xF0;
/// `ERROR` — either direction, protocol error; receiver closes the connection.
pub const FRAME_ERROR: u16 = 0xFF;

/// Padding buckets in bytes (DESIGN.md §5.8). Plaintext is padded to the
/// next bucket before AEAD encryption. Messages larger than `LARGE` are
/// chunked into multiple LARGE frames.
pub mod bucket {
    pub const SMALL: usize = 256;
    pub const MEDIUM: usize = 1024;
    pub const LARGE: usize = 4096;
}
