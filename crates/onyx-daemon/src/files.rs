// File-transfer paths have several signatures with many fields
// (FileMeta has 7 wire fields + sender/conv context), and the
// chunking math uses u64/u32/usize boundaries that clippy
// pedantic catches as truncation. These are bounded by caps
// enforced upstream (accept_file_meta validates sizes fit u32)
// so the casts are sound.
#![allow(
    clippy::too_many_arguments,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

//! T-files.b: file-transfer reassembly + persistence.
//!
//! Receive flow:
//!
//!   1. `FileMeta` arrives → [`accept_file_meta`] runs the receive-
//!      side caps (size, quota, in-flight limit, executable refuse).
//!      On accept, allocates the in-flight buffer.
//!   2. `FileChunk` arrives → [`accept_file_chunk`] dedups by
//!      `(file_id, index)`, inserts into the sparse buffer. When all
//!      chunks present, [`finalize_file`] runs: assemble + verify
//!      hash + write to disk + record in vault.
//!   3. On verify failure: drop the in-flight state, log warn,
//!      delete partial bytes (never landed on disk to begin with —
//!      assembly happens in memory).
//!
//! Send flow: `chunk_file` walks the cleaned bytes and yields
//! `FileMeta` + `FileChunk` messages the caller fans out via the
//! existing room / DM channel.
//!
//! All ops are bounded: no caller can grow memory past the
//! `FilesConfig` caps (see `FILES.md §4` for the table).

use std::collections::HashMap;
use std::path::PathBuf;

use onyx_core::room::RoomAppMessage;
use serde_bytes::ByteBuf;
use tracing::{debug, info, warn};

use crate::{DaemonState, FILES_MAX_INFLIGHT_PER_PEER, InflightFile};

/// T-files.b cap-list §2.1: outcome of trying to accept a
/// `FileMeta`. Caller logs + bails on Reject.
#[derive(Debug, PartialEq, Eq)]
pub enum AcceptDecision {
    Accepted,
    /// Per-file size exceeds `max_recv_size_bytes`.
    RejectTooLarge,
    /// Per-peer per-day quota would be exceeded.
    RejectQuotaExceeded,
    /// Too many in-flight transfers from this peer already.
    RejectInflightCap,
    /// Sniffed MIME indicates an executable type; cap-list §2.11.
    RejectExecutable,
    /// FileMeta is internally inconsistent (e.g. chunks * chunk_size
    /// doesn't bracket size, or fields beyond u32 bounds). Drop.
    RejectMalformed,
}

/// T-files.b: 24h window for the per-peer per-day quota.
const QUOTA_WINDOW_MS: i64 = 24 * 60 * 60 * 1000;

/// T-files.b: enforce the receive-side caps + allocate in-flight
/// state for an incoming `FileMeta`. Returns the accept decision;
/// caller does the logging + tail-event emission.
pub async fn accept_file_meta(
    state: &DaemonState,
    sender_fp: &str,
    conversation: &str,
    meta_id: &[u8],
    name: &str,
    mime: &str,
    size: u64,
    chunks: u32,
    chunk_size: u32,
    content_hash: &[u8],
    now_ms: i64,
) -> AcceptDecision {
    let cfg = &state.files_config;

    // §2.1 cap: per-file size
    if size > cfg.max_recv_size_bytes {
        return AcceptDecision::RejectTooLarge;
    }

    // §2.6 cap: per-peer per-day quota
    let window_start = now_ms.saturating_sub(QUOTA_WINDOW_MS);
    let recent_bytes = {
        let vault = state.vault.lock().await;
        vault
            .received_bytes_since(state.identity_id, sender_fp, window_start)
            .unwrap_or(0)
    };
    if recent_bytes.saturating_add(size) > cfg.max_recv_per_day_bytes {
        return AcceptDecision::RejectQuotaExceeded;
    }

    // §2.11 cap: executable MIMEs refused by default
    if is_executable_mime(mime) {
        return AcceptDecision::RejectExecutable;
    }

    // Malformed check: chunks * chunk_size must bracket size, hash
    // length must be 32B (BLAKE2b-256), id must be 16B.
    if meta_id.len() != 16 || content_hash.len() != 32 || chunks == 0 || chunk_size == 0 {
        return AcceptDecision::RejectMalformed;
    }
    let expected_max = u64::from(chunks) * u64::from(chunk_size);
    let expected_min = expected_max.saturating_sub(u64::from(chunk_size));
    if size > expected_max || size <= expected_min {
        return AcceptDecision::RejectMalformed;
    }

    // §2.7 cap: max in-flight per peer
    let mut id_arr = [0u8; 16];
    id_arr.copy_from_slice(meta_id);
    {
        let mut inflight = state.inflight_files.lock().await;
        let per_peer = inflight.entry(sender_fp.to_string()).or_default();
        if per_peer.len() >= FILES_MAX_INFLIGHT_PER_PEER && !per_peer.contains_key(&id_arr) {
            return AcceptDecision::RejectInflightCap;
        }
        per_peer.insert(
            id_arr,
            InflightFile {
                conversation: conversation.to_string(),
                name: name.to_string(),
                mime: mime.to_string(),
                size,
                chunks,
                chunk_size,
                content_hash: content_hash.to_vec(),
                received: HashMap::new(),
                started_at_ms: now_ms,
            },
        );
    }
    AcceptDecision::Accepted
}

/// T-files.b: insert a `FileChunk` into the in-flight buffer.
/// Returns `Some(path)` when this chunk completed the transfer and
/// the file is on disk; `None` when waiting for more chunks or the
/// chunk was rejected (logged at debug). All-or-nothing: a verify
/// failure drops the in-flight state and returns None.
pub async fn accept_file_chunk(
    state: &DaemonState,
    sender_fp: &str,
    chunk_id: &[u8],
    index: u32,
    bytes: &[u8],
    now_ms: i64,
) -> Option<PathBuf> {
    if chunk_id.len() != 16 {
        debug!("file chunk: id is not 16 bytes; dropping");
        return None;
    }
    let mut id_arr = [0u8; 16];
    id_arr.copy_from_slice(chunk_id);

    // Insert into the in-flight buffer + check completeness.
    let (completed, snapshot) = {
        let mut inflight = state.inflight_files.lock().await;
        let Some(per_peer) = inflight.get_mut(sender_fp) else {
            debug!("file chunk: no FileMeta from this sender; dropping");
            return None;
        };
        let Some(entry) = per_peer.get_mut(&id_arr) else {
            debug!("file chunk: id has no FileMeta; dropping");
            return None;
        };
        if index >= entry.chunks {
            debug!(
                index,
                total = entry.chunks,
                "file chunk: index out of range"
            );
            return None;
        }
        // §2.12 dedup: duplicate (id, index) → silent drop.
        if entry.received.contains_key(&index) {
            debug!("file chunk: duplicate index; dropping");
            return None;
        }
        // Reject oversized chunk (defense: sender claimed
        // chunk_size = X but sent X+1; aborts the transfer).
        if bytes.len() > entry.chunk_size as usize {
            debug!(
                got = bytes.len(),
                claimed = entry.chunk_size,
                "file chunk: exceeds claimed chunk_size; aborting transfer"
            );
            per_peer.remove(&id_arr);
            return None;
        }
        // Last chunk may be smaller; non-last chunks must match.
        let is_last = index == entry.chunks - 1;
        if !is_last && bytes.len() != entry.chunk_size as usize {
            debug!(
                got = bytes.len(),
                claimed = entry.chunk_size,
                "file chunk: non-last chunk wrong size; aborting transfer"
            );
            per_peer.remove(&id_arr);
            return None;
        }
        entry.received.insert(index, bytes.to_vec());
        let done = entry.received.len() as u32 == entry.chunks;
        let snap = if done {
            Some((
                entry.conversation.clone(),
                entry.name.clone(),
                entry.mime.clone(),
                entry.size,
                entry.chunks,
                entry.content_hash.clone(),
                std::mem::take(&mut entry.received),
            ))
        } else {
            None
        };
        if done {
            per_peer.remove(&id_arr);
        }
        (done, snap)
    };

    if !completed {
        return None;
    }
    let (conversation, name, mime, size, chunks, content_hash, parts) = snapshot?;

    finalize_file(
        state,
        sender_fp,
        &conversation,
        &name,
        &mime,
        size,
        chunks,
        &content_hash,
        parts,
        now_ms,
    )
    .await
}

/// T-files.b: assemble chunks → verify hash → write to disk →
/// record in vault. Returns the path written, or None on any
/// failure (verify fail, disk write fail, vault record fail).
#[allow(clippy::too_many_arguments)]
async fn finalize_file(
    state: &DaemonState,
    sender_fp: &str,
    conversation: &str,
    name: &str,
    mime: &str,
    size: u64,
    chunks: u32,
    claimed_hash: &[u8],
    parts: HashMap<u32, Vec<u8>>,
    now_ms: i64,
) -> Option<PathBuf> {
    // Assemble in chunk-index order.
    let mut assembled: Vec<u8> = Vec::with_capacity(size as usize);
    for i in 0..chunks {
        let Some(part) = parts.get(&i) else {
            warn!("file finalize: chunk {i} missing; dropping");
            return None;
        };
        assembled.extend_from_slice(part);
    }
    if assembled.len() as u64 != size {
        warn!(
            actual = assembled.len(),
            claimed = size,
            "file finalize: assembled size mismatch; dropping"
        );
        return None;
    }

    // §2.8 cap-list: BLAKE2b-256 verify.
    let actual_hash = onyx_core::crypto::blake2b_256(&[&assembled]);
    if actual_hash.as_slice() != claimed_hash {
        warn!("file finalize: content hash mismatch; dropping (possible sender tampering)");
        return None;
    }

    // §2.11 cap-list (receive-side enforcement): re-sniff the
    // ASSEMBLED bytes and refuse executables regardless of the
    // sender-claimed MIME. The accept_file_meta check trusts the
    // sender's `mime` string, which a malicious sender can lie about
    // (label an ELF as image/png). Magic-byte sniffing here can't be
    // fooled that way. We refuse if either `infer`'s app/executable
    // classifier fires OR the sniffed MIME is in our auditable
    // refuse-list. (Sniffing can't catch shebang scripts reliably —
    // those have no magic bytes — so the cap remains best-effort, but
    // it's no longer pure sender-honor-system for compiled binaries.)
    if let Some(kind) = infer::get(&assembled) {
        let sniffed = kind.mime_type();
        if infer::is_app(&assembled) || is_executable_mime(sniffed) {
            warn!(
                claimed_mime = mime,
                sniffed_mime = sniffed,
                "file finalize: refused — assembled bytes sniff as executable (cap §2.11)"
            );
            return None;
        }
    }

    // §2.4 cap-list: validate the conversation key before using it as
    // a path segment. It is locally derived today (`room/<base32>` or
    // `peer/<base32>`), but validating here makes the path join
    // robust against any future caller that routes peer-influenced
    // input through — defense against a latent path-traversal.
    if !is_valid_conversation_key(conversation) {
        warn!(
            conversation,
            "file finalize: invalid conversation key; refusing to build storage path"
        );
        return None;
    }

    // Build storage path. §2.4 + §2.5 + §5 cap-list.
    let cfg = &state.files_config;
    let conv_dir = cfg.storage_dir.join(conversation);
    if let Err(e) = std::fs::create_dir_all(&conv_dir) {
        warn!(error = %e, dir = %conv_dir.display(), "file finalize: mkdir failed");
        return None;
    }
    let sanitized_name = sanitize_filename(name);
    let mut hash_prefix = String::with_capacity(16);
    for b in actual_hash.iter().take(8) {
        use std::fmt::Write;
        let _ = write!(hash_prefix, "{b:02x}");
    }
    let filename = format!("{hash_prefix}-{sanitized_name}");
    let path = conv_dir.join(&filename);

    if let Err(e) = std::fs::write(&path, &assembled) {
        warn!(error = %e, path = %path.display(), "file finalize: write failed");
        return None;
    }

    // Record manifest row.
    {
        let vault = state.vault.lock().await;
        if let Err(e) = vault.record_received_file(
            state.identity_id,
            conversation,
            sender_fp,
            &sanitized_name,
            mime,
            size,
            &actual_hash,
            &path.to_string_lossy(),
            now_ms,
        ) {
            warn!(error = %e, "file finalize: record_received_file failed");
            // Clean up the file we just wrote since the manifest
            // entry didn't land — orphan would leak to disk
            // without an index entry.
            let _ = std::fs::remove_file(&path);
            return None;
        }
    }

    info!(
        sender_fp,
        path = %path.display(),
        size,
        mime,
        "file finalize: received + verified + persisted"
    );
    Some(path)
}

/// T-files.b cap-list §2.5: sanitize a filename for safe on-disk
/// storage. Strip path separators, replace non-portable chars with
/// `_`, truncate to 64 chars. Empty result → `unnamed`.
#[must_use]
pub fn sanitize_filename(raw: &str) -> String {
    // Replace (not strip) path separators with `_` so traversal
    // payloads like `../../etc/passwd` become an unambiguous
    // single filename `______etc_passwd` rather than collapsing
    // to `....etcpasswd` (which is technically safe but reads
    // weirdly + risks fs-specific quirks on `..`-prefixed names).
    let mut out: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.len() > 64 {
        out.truncate(64);
    }
    if out.is_empty() || out.chars().all(|c| c == '.') {
        return "unnamed".to_string();
    }
    out
}

/// T-files.b cap-list §2.4: validate a conversation key before it is
/// used as a filesystem path segment. Accepts exactly the shape the
/// daemon produces locally — `room/<base32>` or `peer/<base32>` where
/// the base32 tail is 1..=16 lowercase RFC-4648 chars (`a-z`, `2-7`).
/// Anything else (path separators beyond the single `/`, `..`,
/// absolute paths, NUL, uppercase, over-length) is rejected. This is
/// the guard that keeps `storage_dir.join(conversation)` from ever
/// escaping `storage_dir`.
#[must_use]
pub fn is_valid_conversation_key(conversation: &str) -> bool {
    let Some((prefix, tail)) = conversation.split_once('/') else {
        return false;
    };
    if prefix != "room" && prefix != "peer" {
        return false;
    }
    if tail.is_empty() || tail.len() > 16 {
        return false;
    }
    // Lowercase base32 (RFC 4648) alphabet only — no second '/',
    // no '.', no path-traversal bytes can survive this.
    tail.bytes()
        .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

/// T-files.b cap-list §2.11: executable MIME types refused by
/// default. Hard-coded list of the obvious ones; sniff-based
/// (`infer` crate) would add more but we want this list to be
/// auditable.
#[must_use]
pub fn is_executable_mime(mime: &str) -> bool {
    matches!(
        mime,
        "application/x-msdownload"            // .exe
        | "application/x-msdos-program"
        | "application/x-executable"          // ELF
        | "application/x-mach-binary"         // macOS Mach-O
        | "application/x-apple-diskimage"     // .dmg
        | "application/x-newton-compatible-pkg"
        | "application/vnd.debian.binary-package" // .deb
        | "application/x-rpm"
        | "application/vnd.microsoft.portable-executable" // .exe (registered)
        | "application/x-bat"                 // .bat
        | "application/x-sh" // shell scripts
    )
}

/// T-files.c: result of [`sanitize_file`]. Carries the cleaned
/// bytes ready for chunking + the sanitized metadata to put on
/// `FileMeta`.
#[derive(Debug)]
pub struct CleanedFile {
    /// The bytes to chunk + send. For re-encoded raster images
    /// this is the post-encode output (metadata-free); for raw
    /// pass-through (with `--no-strip-metadata`) this is the
    /// original bytes.
    pub bytes: Vec<u8>,
    /// MIME sniffed from the cleaned bytes. May differ from the
    /// claimed MIME of the source if it had a misleading extension.
    pub mime: String,
    /// Whether metadata was actually stripped (for the operator's
    /// log line / TUI display).
    pub stripped: bool,
}

/// T-files.c: outcome when the requested format is one we refuse
/// to strip safely. Caller (CLI / TUI) decides whether to surface
/// as an error or to bypass with explicit `keep_metadata = true`.
#[derive(Debug, PartialEq, Eq)]
pub enum SanitizeError {
    /// MIME identifies a format with metadata we can't safely
    /// strip without shipping a format-specific parser (PDF,
    /// DOCX, video). Operator can bypass with
    /// `SanitizeOpts.keep_metadata = true`.
    UnsupportedFormat(&'static str),
    /// Bytes don't look like any format `infer` recognises.
    /// Strip can't run. Same bypass.
    UnknownFormat,
    /// Bytes failed to decode as the sniffed image format.
    /// Likely a corrupt or truncated file.
    DecodeFailed(String),
    /// Re-encode failed. Should never happen for a successfully-
    /// decoded image but we surface it rather than panic.
    EncodeFailed(String),
    /// I/O error reading the path.
    IoError(String),
}

impl std::fmt::Display for SanitizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedFormat(name) => write!(
                f,
                "format `{name}` has metadata Onyx can't safely strip; \
                 pass --no-strip-metadata to send anyway with the leak \
                 documented in FILES.md §3.2"
            ),
            Self::UnknownFormat => write!(
                f,
                "could not identify the file format from content; \
                 pass --no-strip-metadata to send as application/octet-stream"
            ),
            Self::DecodeFailed(detail) => write!(f, "image decode failed: {detail}"),
            Self::EncodeFailed(detail) => write!(f, "image re-encode failed: {detail}"),
            Self::IoError(detail) => write!(f, "I/O error: {detail}"),
        }
    }
}

impl std::error::Error for SanitizeError {}

/// T-files.c: caller options for [`sanitize_file`]. `keep_metadata`
/// defaults to `false` — strip aggressively per `FILES.md §3.1`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SanitizeOpts {
    /// `false` (default): strip metadata aggressively per
    /// `FILES.md §3.1`. `true`: pass through; refused-format
    /// errors don't fire.
    pub keep_metadata: bool,
}

/// T-files.c: read `path`, sniff the MIME, and either strip
/// metadata (raster formats) or refuse (formats we can't safely
/// strip). See `FILES.md §3` for the per-format strategy table.
///
/// Returns the cleaned bytes + sniffed MIME ready for
/// [`chunk_file_for_send`]. The caller computes
/// `blake2b_256(cleaned.bytes)` for the FileMeta content_hash.
pub fn sanitize_file(
    path: &std::path::Path,
    opts: SanitizeOpts,
) -> Result<CleanedFile, SanitizeError> {
    let raw = std::fs::read(path).map_err(|e| SanitizeError::IoError(format!("{e}")))?;
    sanitize_bytes(&raw, opts)
}

/// T-files.c: same as [`sanitize_file`] but operates on bytes
/// already loaded into memory. Used directly by tests + when the
/// caller (TUI) already has the bytes.
pub fn sanitize_bytes(raw: &[u8], opts: SanitizeOpts) -> Result<CleanedFile, SanitizeError> {
    let sniffed_mime = infer::get(raw).map_or_else(
        || "application/octet-stream".to_string(),
        |t| t.mime_type().to_string(),
    );

    // Pass-through path: operator opted out of stripping. Return
    // raw bytes + sniffed MIME (still better than the sender's
    // claim per FILES.md §3.3).
    if opts.keep_metadata {
        return Ok(CleanedFile {
            bytes: raw.to_vec(),
            mime: sniffed_mime,
            stripped: false,
        });
    }

    // Strip path. Branch on sniffed MIME.
    match sniffed_mime.as_str() {
        // Raster formats: decode + re-encode without metadata.
        "image/jpeg" => reencode_raster(raw, image::ImageFormat::Jpeg, "image/jpeg"),
        "image/png" => reencode_raster(raw, image::ImageFormat::Png, "image/png"),
        "image/webp" => reencode_raster(raw, image::ImageFormat::WebP, "image/webp"),
        "image/tiff" => {
            // TIFF → PNG (lossless, no TIFF EXIF carry-through).
            reencode_raster(raw, image::ImageFormat::Png, "image/png")
        }
        "image/bmp" => {
            // BMP has minimal metadata; still re-encode to PNG
            // for consistency + future-proofing if BMP gains
            // metadata extensions.
            reencode_raster(raw, image::ImageFormat::Png, "image/png")
        }
        "image/gif" => {
            // Animated GIFs lose frames in a naive decode-encode;
            // for a still GIF this is fine, but to be safe we
            // refuse (matches the "refuse what we can't safely
            // strip" policy).
            Err(SanitizeError::UnsupportedFormat("image/gif"))
        }
        // Formats with metadata we can't safely strip without
        // shipping a format-specific parser. FILES.md §3.2.
        "image/heic" | "image/heif" => Err(SanitizeError::UnsupportedFormat("image/heic")),
        "application/pdf" => Err(SanitizeError::UnsupportedFormat("application/pdf")),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        | "application/vnd.oasis.opendocument.text"
        | "application/msword" => Err(SanitizeError::UnsupportedFormat("office document")),
        m if m.starts_with("video/") => Err(SanitizeError::UnsupportedFormat("video")),
        m if m.starts_with("audio/") => Err(SanitizeError::UnsupportedFormat("audio")),
        m if m.starts_with("application/zip")
            || m.starts_with("application/x-tar")
            || m.starts_with("application/x-7z-compressed")
            || m.starts_with("application/x-rar") =>
        {
            Err(SanitizeError::UnsupportedFormat("archive"))
        }
        "application/octet-stream" => Err(SanitizeError::UnknownFormat),
        // Anything else: refuse. The operator either passes
        // --no-strip-metadata to accept the leak, or converts
        // first.
        other => Err(SanitizeError::UnsupportedFormat(match other {
            "text/plain" => "text/plain",
            _ => "unknown",
        })),
    }
}

/// T-files.c §3.1: decode raster bytes via `image` crate, then
/// re-encode in `target_format` with no metadata fields. The
/// `image` crate's encoders don't carry forward any source-format
/// metadata structures, so a successful round-trip strips everything.
fn reencode_raster(
    raw: &[u8],
    target_format: image::ImageFormat,
    target_mime: &str,
) -> Result<CleanedFile, SanitizeError> {
    let img =
        image::load_from_memory(raw).map_err(|e| SanitizeError::DecodeFailed(format!("{e}")))?;
    let mut out = Vec::with_capacity(raw.len());
    img.write_to(&mut std::io::Cursor::new(&mut out), target_format)
        .map_err(|e| SanitizeError::EncodeFailed(format!("{e}")))?;
    Ok(CleanedFile {
        bytes: out,
        mime: target_mime.to_string(),
        stripped: true,
    })
}

/// T-files.b: send-side chunking. Splits `bytes` into
/// `chunk_size`-byte pieces and yields the `FileMeta` + `FileChunk`
/// RoomAppMessage values the caller fans out via the existing
/// room channel. `id` is the random 16-byte transfer id.
///
/// Caller is responsible for: cleaning metadata BEFORE calling
/// (T-files.c `sanitize_file`), computing `content_hash` over the
/// cleaned bytes, enforcing `cfg.max_send_size_bytes`.
#[must_use]
pub fn chunk_file_for_send(
    id: [u8; 16],
    name: &str,
    mime: &str,
    bytes: &[u8],
    chunk_size: u32,
    content_hash: &[u8; 32],
) -> Vec<RoomAppMessage> {
    let size = bytes.len() as u64;
    let chunks = size.div_ceil(u64::from(chunk_size)).max(1) as u32;
    let mut out = Vec::with_capacity(chunks as usize + 1);
    out.push(RoomAppMessage::FileMeta {
        id: ByteBuf::from(id.to_vec()),
        name: name.to_string(),
        mime: mime.to_string(),
        size,
        chunks,
        chunk_size,
        content_hash: ByteBuf::from(content_hash.to_vec()),
    });
    for (i, slice) in bytes.chunks(chunk_size as usize).enumerate() {
        out.push(RoomAppMessage::FileChunk {
            id: ByteBuf::from(id.to_vec()),
            index: u32::try_from(i).unwrap_or(u32::MAX),
            bytes: ByteBuf::from(slice.to_vec()),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_path_separators() {
        // `/` and `\` become `_`. The `..` characters are preserved
        // (they're allowed in filenames; we don't try to canonicalize
        // dot-dot away — the actual safety guarantee is the
        // path-separator strip + sandbox dir join, not arithmetic
        // on dot patterns).
        assert_eq!(sanitize_filename("../../etc/passwd"), ".._.._etc_passwd");
        assert_eq!(sanitize_filename("a\\b\\c"), "a_b_c");
        // "漢字" is 2 chars → 2 underscores. Plus 3 spaces in
        // "with spaces and " → 3 more underscores. Total trailing
        // run is 3 (one per space + one per CJK char interspersed).
        assert_eq!(
            sanitize_filename("with spaces and 漢字"),
            "with_spaces_and___"
        );
    }

    #[test]
    fn valid_conversation_key_accepts_local_shapes_only() {
        // The shapes the daemon actually produces.
        assert!(is_valid_conversation_key("room/abcdefgh"));
        assert!(is_valid_conversation_key("peer/a2b3c4d5"));
        assert!(is_valid_conversation_key("room/a")); // 1 char ok
        assert!(is_valid_conversation_key("room/abcdefghijklmnop")); // 16 ok

        // Traversal / injection attempts must all be rejected.
        assert!(!is_valid_conversation_key("room/../../etc"));
        assert!(!is_valid_conversation_key("../secrets"));
        assert!(!is_valid_conversation_key("/abs/path"));
        assert!(!is_valid_conversation_key("room/with/slash"));
        assert!(!is_valid_conversation_key("room/")); // empty tail
        assert!(!is_valid_conversation_key("room/abcdefghijklmnopq")); // 17 > 16
        assert!(!is_valid_conversation_key("ROOM/abcdefgh")); // wrong prefix case
        assert!(!is_valid_conversation_key("group/abcdefgh")); // unknown prefix
        assert!(!is_valid_conversation_key("room/UPPER")); // uppercase tail
        assert!(!is_valid_conversation_key("room/has.dot")); // '.' not base32
        assert!(!is_valid_conversation_key("room/has-dash")); // '-' not base32
        assert!(!is_valid_conversation_key("room/01")); // 0,1 not in base32 alphabet
        assert!(!is_valid_conversation_key("noslash"));
        assert!(!is_valid_conversation_key(""));
    }

    #[test]
    fn sanitize_preserves_safe_chars() {
        assert_eq!(
            sanitize_filename("photo_2026-01-12.jpg"),
            "photo_2026-01-12.jpg"
        );
        assert_eq!(sanitize_filename("a.b.c"), "a.b.c");
    }

    #[test]
    fn sanitize_truncates_long_names() {
        let long: String = "a".repeat(200);
        let out = sanitize_filename(&long);
        assert_eq!(out.len(), 64);
    }

    #[test]
    fn sanitize_empty_yields_unnamed() {
        // Truly empty input → unnamed.
        assert_eq!(sanitize_filename(""), "unnamed");
        // All-dot input → unnamed (avoids leaving `...` which on
        // some filesystems normalises to the current directory).
        assert_eq!(sanitize_filename("..."), "unnamed");
        // `///` becomes `___` which is a valid (if ugly) filename;
        // we don't substitute "unnamed" for that — strip-and-replace
        // is the contract.
        assert_eq!(sanitize_filename("///"), "___");
    }

    #[test]
    fn executable_mimes_rejected() {
        assert!(is_executable_mime("application/x-msdownload"));
        assert!(is_executable_mime("application/x-mach-binary"));
        assert!(is_executable_mime("application/x-executable"));
        assert!(!is_executable_mime("image/jpeg"));
        assert!(!is_executable_mime("application/pdf"));
    }

    // ── T-files.c: sanitize_file ──────────────────────────────────

    /// Build a tiny JPEG with EXIF metadata embedded. We build the
    /// JPEG via `image` (no EXIF), then SPLICE in a synthetic EXIF
    /// APP1 segment so we have a known marker to grep for after
    /// stripping. This is hacky but deterministic + dep-free.
    fn jpeg_with_fake_exif() -> Vec<u8> {
        // Build a 4x4 red JPEG via image crate.
        let img = image::DynamicImage::new_rgb8(4, 4);
        let mut buf = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut buf),
            image::ImageFormat::Jpeg,
        )
        .unwrap();
        // Splice a synthetic EXIF APP1 segment right after the SOI
        // marker (FF D8). Segment shape: FF E1 [len_hi][len_lo]
        // "Exif\0\0" <tiff-style payload>. We use a recognisable
        // payload "ONYX-EXIF-CANARY-12345" so the test can verify
        // it's GONE after sanitize.
        let canary = b"ONYX-EXIF-CANARY-12345";
        let mut exif_segment: Vec<u8> = vec![
            0xFF, 0xE1, // APP1 marker
            0, 0, // length placeholder
            b'E', b'x', b'i', b'f', 0x00, 0x00, // EXIF header
        ];
        exif_segment.extend_from_slice(canary);
        // Length = bytes from the size field onward = exif_segment.len() - 2
        let len = (exif_segment.len() - 2) as u16;
        exif_segment[2] = (len >> 8) as u8;
        exif_segment[3] = len as u8;
        // Splice in after the SOI (bytes 0..2 = FF D8).
        let mut out = Vec::with_capacity(buf.len() + exif_segment.len());
        out.extend_from_slice(&buf[..2]);
        out.extend_from_slice(&exif_segment);
        out.extend_from_slice(&buf[2..]);
        out
    }

    #[test]
    fn sanitize_strips_jpeg_exif_canary() {
        let dirty = jpeg_with_fake_exif();
        // Sanity: dirty JPEG contains the canary.
        let canary = b"ONYX-EXIF-CANARY-12345";
        assert!(dirty.windows(canary.len()).any(|w| w == canary));
        let cleaned = sanitize_bytes(&dirty, SanitizeOpts::default()).unwrap();
        assert_eq!(cleaned.mime, "image/jpeg");
        assert!(cleaned.stripped);
        // Cleaned output must NOT contain the canary anymore.
        assert!(
            !cleaned.bytes.windows(canary.len()).any(|w| w == canary),
            "EXIF canary survived the strip — metadata leak"
        );
        // Result must still be a valid JPEG.
        let _re = image::load_from_memory(&cleaned.bytes).expect("cleaned output decodes");
    }

    #[test]
    fn sanitize_keep_metadata_passes_canary_through() {
        let dirty = jpeg_with_fake_exif();
        let canary = b"ONYX-EXIF-CANARY-12345";
        let cleaned = sanitize_bytes(
            &dirty,
            SanitizeOpts {
                keep_metadata: true,
            },
        )
        .unwrap();
        assert!(!cleaned.stripped);
        assert!(
            cleaned.bytes.windows(canary.len()).any(|w| w == canary),
            "keep_metadata=true should preserve metadata (it didn't)"
        );
    }

    #[test]
    fn sanitize_refuses_pdf() {
        // PDF magic: %PDF-1.x
        let fake_pdf = b"%PDF-1.4\n%fake content for sniff test\n%%EOF";
        let err = sanitize_bytes(fake_pdf, SanitizeOpts::default()).unwrap_err();
        assert!(matches!(err, SanitizeError::UnsupportedFormat(_)));
    }

    #[test]
    fn sanitize_refuses_zip() {
        // ZIP magic: PK\x03\x04
        let fake_zip = b"PK\x03\x04fake-zip-bytes";
        let err = sanitize_bytes(fake_zip, SanitizeOpts::default()).unwrap_err();
        assert!(matches!(err, SanitizeError::UnsupportedFormat(_)));
    }

    #[test]
    fn sanitize_unknown_format_errors() {
        let random = b"not any recognizable format magic bytes";
        let err = sanitize_bytes(random, SanitizeOpts::default()).unwrap_err();
        assert!(matches!(err, SanitizeError::UnknownFormat));
    }

    #[test]
    fn sanitize_keep_metadata_accepts_unknown_format() {
        let random = b"not any recognizable format magic bytes";
        let cleaned = sanitize_bytes(
            random,
            SanitizeOpts {
                keep_metadata: true,
            },
        )
        .unwrap();
        assert_eq!(cleaned.mime, "application/octet-stream");
        assert!(!cleaned.stripped);
        assert_eq!(cleaned.bytes, random);
    }

    #[test]
    fn chunk_file_roundtrip_shape() {
        // 30 KB file, 12 KB chunks → 3 chunks (last is 6 KB).
        let bytes = vec![0xABu8; 30 * 1024];
        let hash = onyx_core::crypto::blake2b_256(&[&bytes]);
        let id = [0x11u8; 16];
        let msgs = chunk_file_for_send(
            id,
            "test.bin",
            "application/octet-stream",
            &bytes,
            12 * 1024,
            &hash,
        );
        assert_eq!(msgs.len(), 4); // 1 FileMeta + 3 FileChunk
        match &msgs[0] {
            RoomAppMessage::FileMeta {
                chunks,
                chunk_size,
                size,
                ..
            } => {
                assert_eq!(*chunks, 3);
                assert_eq!(*chunk_size, 12 * 1024);
                assert_eq!(*size, 30 * 1024);
            }
            other => panic!("first message must be FileMeta; got {other:?}"),
        }
        // Last chunk size = 6 KB
        match &msgs[3] {
            RoomAppMessage::FileChunk { bytes, .. } => {
                assert_eq!(bytes.len(), 6 * 1024);
            }
            other => panic!("last message must be FileChunk; got {other:?}"),
        }
    }
}
