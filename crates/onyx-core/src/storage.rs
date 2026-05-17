//! Encrypted local storage (SQLite + app-level AEAD).
//!
//! See DESIGN.md §7. Sensitive fields are AEAD-encrypted at the row level
//! under a key derived from the user's passphrase via Argon2id (default
//! 256 MiB / t=3 / p=4, floor 64 MiB / t=3 / p=2). Non-sensitive fields
//! remain in plaintext so SQLite can index them.
//!
//! Session-only mode (DESIGN.md §7.3) disables persistence entirely;
//! identity import from a disk backup is intentionally not supported in
//! that mode because the backup file would defeat the forensic goal.
