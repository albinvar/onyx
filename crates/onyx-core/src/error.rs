//! Cross-cutting error type for `onyx-core`.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// A byte slice or string could not be parsed into the expected type.
    #[error("invalid encoding: {0}")]
    InvalidEncoding(&'static str),

    /// Cryptographic verification failed (signature, AEAD tag, point on curve, …).
    /// Deliberately opaque so a probing attacker learns nothing from the variant.
    #[error("cryptographic verification failed")]
    VerificationFailed,

    /// Argon2 parameters supplied by the caller were below the workspace floor.
    /// The floor exists to prevent accidental weak vault keys; raising it requires
    /// a deliberate config change.
    #[error("Argon2 parameters below floor: {0}")]
    KdfParamsTooWeak(&'static str),

    /// A buffer the caller passed in was the wrong size for the operation.
    #[error("buffer size mismatch: expected {expected}, got {actual}")]
    BufferSize { expected: usize, actual: usize },

    /// Catch-all for a failure from a dependency. Carries a static label only —
    /// the underlying error is logged via `tracing` rather than returned, so the
    /// dependency's error type does not leak into our public API surface.
    #[error("internal: {0}")]
    Internal(&'static str),

    /// Placeholder used by scaffold modules that have no implementation yet.
    #[error("{0}: not yet implemented")]
    NotImplemented(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
