# File sharing in Onyx — design + threat model

**Status**: design + slice plan. v0 implementation lands as T-files.b through T-files.e following this doc.

If you're reading this because you want to know "is it safe to send a photo through Onyx?" — the short version is **yes, with the metadata strip on by default, and with the timing-leak caveat in §6 understood.** This doc explains exactly what the strip does, what's left exposed, and what the operator opts into for stronger guarantees.

## §0 The honest framing (read this first)

File sharing is the single most adversary-exposed feature in a messaging system. Every file you send has up to four ways to leak your identity:

1. **Embedded metadata** — EXIF GPS, document author, last-modified, embedded thumbnails. Onyx **strips this aggressively by default** for raster image formats by decode-and-re-encode (T-files.c §3.1). For formats Onyx can't safely strip (PDF, DOCX, video), the daemon **refuses to send** unless the operator explicitly opts in with `--no-strip-metadata` and accepts the documented leak.

2. **Filename** — `tax-return-john-smith-2026.pdf` is the leak. Onyx **renames to `<content_hash>.<ext>` by default**; the original name is replaced with a hex hash of the file's contents. Operator can opt in to preserve names with `--keep-filename` per call.

3. **Content itself** — a photo of you, your house, your screen. **Onyx can't sanitize this.** End-to-end encryption protects it from the network and the hub; recipient-device security is the recipient's problem (`ANONYMITY.md §3.0 honest framing`). If you don't trust the recipient, don't send them a file.

4. **Traffic shape** — file transfers leak file-size + duration even with encryption. A 10 MB photo over Tor produces a recognisable burst of ~670 chunked frames over ~10 seconds. The hub can't read the content but can fingerprint "alice sent a large file at 09:23." Onyx **does not solve this in v0** — see `§6` for the caveat and the `--constant-rate` opt-in for partial mitigation.

The rest of this doc walks through each layer in detail. If you only read one other section, read `§6`.

## §1 Adversary additions

`ANONYMITY.md` already covers A1 (hub-watching), A2 (compromised peer in a room), A3 (network), A4 (recipient device). File sharing adds:

### A5 — sender-device-via-metadata

The sender's own device has metadata embedded in every file it produces:

- **Phone photos**: EXIF carries GPS lat/long (down to 5m precision), camera model, exact timestamp with timezone, sometimes the user's name (iPhone "Apple Account" leakage).
- **Screenshots**: file modification timestamp, OS-specific metadata (macOS thumbnail), sometimes embedded XMP with the source app.
- **Office documents**: `docProps/core.xml` carries the system user's name, last-modified-by, template path, total editing time.
- **PDFs**: `/Author`, `/Title`, `/Producer` (e.g. "Microsoft® Word 2021"), `/CreationDate`, `/ModDate`.

A5's specific danger: alice sends bob a photo from a chat she's anonymous in. The photo's EXIF GPS reveals her home address. Bob is the adversary now.

**Mitigation in Onyx**: §3.1 metadata strip on by default for raster images; refuse-with-warning for documents/video (can't safely strip).

### A6 — malicious sender

Once file transfer is possible, a malicious participant in a room can:

- Send a 10 GB file to fill the recipient's disk (DoS by storage).
- Send 1000 files in a tight loop (DoS by file-descriptor / metadata churn).
- Send a file with name `../../etc/passwd` to write outside the receive directory (path traversal).
- Send an executable with `.jpg` extension hoping the recipient auto-opens it.
- Send a "file" whose claimed size and actual chunked content don't match (DoS by buffer growth).

**Mitigations in §4 (size caps), §5 (path sanitization), §3.3 (MIME sniff from content), §3.5 (executable types refused by default).**

## §2 The 12-item security cap-list

Every file-receive path in Onyx enforces these. Numbered for easy cross-reference from code comments:

1. **Metadata strip on by default** for raster images (JPEG, PNG, HEIC, WebP). Refuses other formats unless `--no-strip-metadata` opt-in.
2. **Filename hash by default**: rename to `<blake2b-128(content)>.<ext>`; original name kept only with `--keep-filename`.
3. **MIME sniff from content** (via `infer` crate), not trusted from sender's claimed `mime` field. If they don't match, sniffed wins.
4. **Path component strip always**: the receive-side filename has all path separators removed; the file always lands directly under `~/.onyx/files/<conversation>/`.
5. **Per-file size cap** (default 50 MB, configurable). Sender side checks before chunking; receiver side enforces independently.
6. **Per-peer per-day quota** (default 500 MB, configurable). Receiver tracks rolling 24h window per sender fingerprint; over-quota = refuse with warn.
7. **Per-in-flight transfer cap** (default 10). Receiver state holds at most 10 partial files per peer; the 11th gets refused.
8. **Content-hash verification** end-to-end: every `FileMeta` carries `content_hash = blake2b-256(cleaned_bytes)`. Receiver assembles chunks, hashes, and compares. Mismatch = drop + log.
9. **Sanitized storage path**: `~/.onyx/files/<conversation_id>/<content_hash>-<sanitized_name>`. The hash prefix prevents two senders from clobbering each other; conversation_id keeps DM and room files separated.
10. **No auto-execute / no auto-open**: the TUI shows `📎 photo.jpg · downloaded · /path/to/file`. The user opens the file from a shell. Onyx never invokes the OS file-open handler for received files.
11. **Refuse executable MIMEs by default**: `.exe`, `.dmg`, `.pkg`, `.deb`, `.msi`, `.app`, `.scr`, `.bat`, `.cmd`, `.com`, `.elf`. Receiver-side detection via sniff. Configurable: `--executable-action {quarantine|accept|reject}`, default `reject`.
12. **Chunk replay protection**: receiver tracks seen `(file_id, chunk_index)` pairs in the in-flight state. Duplicate chunks (legitimate multi-hub fan-out + receiver dedup) silently drop.

## §3 Metadata stripping

### 3.1 Image formats — re-encode strategy

For JPEG, PNG, HEIC, WebP, TIFF, BMP: **decode to raw RGB(A) via the `image` crate, then re-encode** with no metadata fields populated.

| Input        | Re-encode to              | Quality |
|--------------|---------------------------|---------|
| JPEG, JPG    | JPEG, q=95                | High; near-lossless |
| PNG          | PNG, no chunks            | Lossless |
| HEIC, HEIF   | JPEG, q=95                | Lossy (HEIC encode requires patent-encumbered libs) |
| WebP         | WebP, q=95                | High |
| TIFF, BMP    | PNG                       | Lossless |

The re-encode **guarantees** zero EXIF / XMP / IPTC / thumbnail / GPS / ICC profile leakage because we throw the source format's metadata structures away entirely.

**Quality caveat**: re-encoding JPEG → JPEG at q=95 is visually indistinguishable from the original but is not byte-identical. If the recipient compares to a reference copy they'll see the difference. For pixel-perfect transfer the operator can pass `--no-strip-metadata`; that path also preserves whatever metadata you had.

### 3.2 Formats Onyx refuses to strip

For these, the daemon **refuses to send** unless `--no-strip-metadata` is passed:

- **PDF**: `/Author`, `/Title`, `/Producer`, `/Keywords`, `/CreationDate`, `/ModDate`, embedded XMP, plus document-internal references that may reveal the source machine. Safe PDF metadata stripping requires a complete PDF parser; we don't ship one.
- **Office docs** (DOCX/XLSX/PPTX/ODT/...): zip-based formats with multi-file XML metadata in `docProps/`. Safe stripping requires walking the entire archive — out of scope for v0.
- **Audio/video** (MP3, MP4, MOV, M4A, AVI, MKV, FLAC): ID3v2 / `udta` atoms / VORBIS_COMMENT blocks. Format-specific stripping is plausible but each format is its own slice. v0 refuses.
- **Archives** (ZIP, TAR, 7z, RAR): may contain files with path metadata embedded. Recursive sanitization is out of scope.

When the operator passes `--no-strip-metadata` for a refused format, the daemon prints a one-line warning naming the leak surface and proceeds.

### 3.3 MIME sniffing

Receiver sniffs the MIME type from the file's **content**, not from the sender's `FileMeta.mime` claim. Uses the `infer` crate (magic-byte-based detection — small, well-audited).

If sniff disagrees with the claim: log a warn, use the sniffed value. The sender's claim is hint-only.

If sniff returns "unknown": the file lands with `application/octet-stream` MIME. Receiver storage uses sender-provided filename's extension (after sanitization) for the on-disk path; user gets `📎 unknown-binary (12.3 MB)` in the TUI.

## §4 Size + quota

| Setting                           | Default | Configurable via                  |
|-----------------------------------|---------|-----------------------------------|
| `max_file_send_size_bytes`        | 50 MB   | `Config.max_file_send_bytes`      |
| `max_file_recv_size_bytes`        | 50 MB   | `Config.max_file_recv_bytes`      |
| `max_file_recv_per_day_bytes`     | 500 MB  | `Config.max_file_recv_per_day`    |
| `max_inflight_files_per_peer`     | 10      | `Config.max_inflight_files`       |
| `file_chunk_size_bytes`           | 12 KB   | `Config.file_chunk_size_bytes`    |
| `file_storage_dir`                | `~/.onyx/files/` | `Config.file_storage_dir`  |

Why 12 KB for chunk size: wire bucket `XLARGE = 16384` bytes max payload after the inner header. CBOR-encoding a `RoomAppMessage::FileChunk { id, index, bytes }` adds ~30 bytes of overhead. Leaving headroom for MLS framing + future field additions: 12 KB chunks fit comfortably with margin.

Why these defaults: 50 MB per-file covers any reasonable photo/document; larger transfers should go through purpose-built tools (Magic Wormhole, OnionShare). 500 MB per-day per-peer is generous for legitimate chat use and tight enough to make file-flooding DoS unattractive.

The sender side ALSO enforces `max_file_send_size_bytes` so the local operator doesn't accidentally ship a 1 GB file across Tor.

## §5 Path + filename sanitization

Receive-side path construction:

```
~/.onyx/files/<conversation>/<content_hash_hex_first_16_chars>-<sanitized_name>
```

Where `<conversation>` is `peer-<short_id>` for DMs and `room-<short_b32_of_group_id>` for rooms.

`<sanitized_name>` is computed by:
1. Strip all path separators (`/`, `\`, `:`).
2. Replace any character not in `[A-Za-z0-9._-]` with `_`.
3. Truncate to 64 chars.
4. If the result is empty after sanitization, use `unnamed`.
5. Apply the sniffed extension if the original had none / had a misleading one.

With `--keep-filename`: the original sender-provided name is used (still sanitized as above).

The hash prefix (`<content_hash_hex_first_16_chars>-`) means two senders can't clobber each other's files even with identical names — the hash differentiates.

## §6 Anonymity caveat — traffic shape leaks file size + duration

**This is the biggest residual gap, and v0 does not solve it.**

File transfers, even when chunked and padded to the XLARGE bucket, produce a recognisable wire pattern:

- A burst of XLARGE-bucket frames (each `bucket::XLARGE = 16384` bytes on the wire).
- Duration proportional to file size and channel bandwidth.
- A long pause afterward.

A hub watching the daemon-hub channel can observe:
- "Alice sent a large file at 09:23" (from the burst onset).
- Approximate file size (from the burst duration × known bandwidth).
- "Bob received a large file at 09:23" (from the burst at his subscribed inbox).

What this leaks:
- **Existence of file transfer activity** (vs idle / typing).
- **Approximate file size** (small/medium/large bucketed).
- **Correlation between sender and receiver** if the hub sees both endpoints (timing).

What cover traffic (`T-cover`) does NOT solve here: cover frames are `bucket::SMALL` (256 bytes). A file chunk at `bucket::XLARGE` (16 KB) is 64× larger; the size signal alone distinguishes file chunks from cover frames.

### 6.1 Partial mitigation: `--constant-rate`

Operator can opt in to constant-rate file transfer. The sender throttles to `constant_rate_bytes_per_sec` (default 100 KB/s when enabled). Effect:

- A 10 MB photo takes ~100 seconds regardless of channel bandwidth.
- The traffic shape becomes uniform per second: ~8 XLARGE chunks per second every second the transfer is active.
- The hub still sees "alice transferred something for 100 seconds" — but cannot distinguish a 10 MB file from a 100 MB file with throttling that would (the longer one runs for ~1000 seconds; visibly different timing).
- A long enough file transfer eventually blends with normal chat; a short transfer (single chunk, < 12 KB) is indistinguishable from a single XLARGE chat message.

**Status**: opt-in via `--constant-rate` flag on send. Off by default because the speed penalty is significant; documented honestly so operators who need it can enable.

### 6.2 What would close it fully

Active mixnet-style routing through multiple intermediate hops with per-hop padding + delay. That's a fundamentally different architecture (closer to Mixmaster than Tor). Not planned for Onyx v0.

For now: **don't send sensitive files through Onyx if your adversary controls the hub AND is watching for file-shaped traffic patterns.** Use OnionShare or Magic Wormhole directly for that case.

## §7 Wire format

CBOR-encoded `RoomAppMessage` (existing T6.3.h plaintext layer) gains two variants:

```rust
RoomAppMessage::FileMeta {
    id:           [u8; 16],   // random; identifies this transfer
    name:         String,     // sanitized by sender per §5
    mime:         String,     // sender's claim (hint-only on receive; see §3.3)
    size:         u64,        // total bytes (after metadata strip)
    chunks:       u32,        // total chunk count
    chunk_size:   u32,        // chunk size in bytes (last chunk may be smaller)
    content_hash: ByteBuf,    // BLAKE2b-256 of the cleaned content
}

RoomAppMessage::FileChunk {
    id:    [u8; 16],          // matches FileMeta.id
    index: u32,               // 0-based
    bytes: ByteBuf,           // chunk_size bytes (or smaller for last chunk)
}
```

For DMs: same shape, transmitted as MLS application messages on the DM group (existing T2.x path). DMs don't go through the `RoomAppMessage` enum today; T-files.b adds a parallel `DmAppMessage` enum that wraps Text + FileMeta + FileChunk.

**Why CBOR + tagged enum**: same forward-compatibility rationale as T6.3.h (CHANNELS.md). Future content types (typing, reactions, etc.) compose as new variants without coordinated upgrades.

**Why a separate enum for DMs**: the existing DM path encrypts raw UTF-8 plaintext (`encrypt_application(text.as_bytes())`). To add file framing without breaking back-compat, the DM path migrates to a tagged enum the same way rooms did in T6.3.h. Brief installed-base disruption — same posture as T6.3.h's migration.

## §8 Slice plan

Five slices, each shippable + testable independently:

- **T-files.a** (this doc, design): threat model + 12-item cap-list + size table + slice plan.
- **T-files.b** (wire infrastructure): `FileMeta` + `FileChunk` variants on the room channel, parallel `DmAppMessage` for DMs, receiver reassembly + content-hash verify, vault `received_files` table, storage under `~/.onyx/files/`. End-to-end smoke test sending a real file through the existing TCP smoke harness.
- **T-files.c** (metadata stripping): `sanitize_file` via `image` crate for raster formats; refuse + warn for everything else. Filename hashing. MIME sniff via `infer`. Unit tests with known-metadata fixtures (a JPEG with embedded GPS).
- **T-files.d** (CLI): `onyx send-file`, `onyx room send-file`, `onyx files list`, `onyx files open`. Per-call flags. Daemon `Config` integration.
- **T-files.e** (TUI): `Ctrl-F` opens a file-picker modal (path input + size preview + strip preview). Attachment rendering in scrollback. Progress reporting.

## §9 Threat-model deltas

To add to `THREAT_MODEL.md §8.2` when T-files.b lands:

- **#NEW.f1 (A5 metadata leak)**: file metadata strip is on by default; the strip works by re-encoding raster images (drops all metadata structures). For non-raster formats the daemon refuses to send unless `--no-strip-metadata` is explicitly passed. The operator override is documented but defaults to safe.
- **#NEW.f2 (A6 DoS via large/many files)**: defended by per-file size cap, per-peer per-day quota, per-in-flight cap. All configurable; sane defaults documented in `FILES.md §4`.
- **#NEW.f3 (A6 path traversal)**: defended by §5 sanitization. Path separators stripped; output always lands directly under `~/.onyx/files/<conversation>/`.
- **#NEW.f4 (A6 execution)**: executable MIMEs refused by default. Sniffed from content; sender's claimed MIME is hint-only.
- **#NEW.f5 (A6 chunk replay)**: defended by per-`(file_id, index)` dedup in receiver in-flight state.
- **#NEW.f6 (traffic-shape leak)**: documented limit (`§6`). `--constant-rate` opt-in for partial mitigation.

## §10 Cross-references

- `ANONYMITY.md §3.1` (cover traffic — the timing leak this doc inherits)
- `ANONYMITY.md §3.8` (memory zeroization — applies to in-flight chunk buffers)
- `CHANNELS.md §0–§8` (the structured-plaintext pattern T-files copies)
- `THREAT_MODEL.md §8.2` (adversary catalog)
- `ROTATION.md` (the identity-leak structural analysis — not directly file-related but provides the multi-leak framing this doc reuses)

## §11 Decision log

- **2026-05-19** (this doc): chose aggressive raster re-encode over best-effort per-format strip. Rationale: re-encode is provably complete (drops the source format's metadata structures entirely); per-format strip is whack-a-mole.
- **2026-05-19**: chose `--constant-rate` opt-in over on-by-default. Rationale: 100 KB/s throttling is a significant UX hit; majority of users won't need it; operator who does need it opts in explicitly. Mirrors the cover-traffic posture (T-cover).
- **Deferred**: PDF/DOCX/video metadata stripping. Would require shipping format-specific parsers; each is a substantial slice and the user can use `exiftool -all=` + manual PDF cleanup before sending if they need to.
- **Deferred**: resumeable transfers. Failed transfer = retry from scratch. Simpler + more verifiable; resume adds partial-state management that's hard to integrity-check.
- **Deferred**: in-band thumbnails / inline previews. Out of scope for v0.
