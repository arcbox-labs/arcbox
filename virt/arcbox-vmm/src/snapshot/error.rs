/// Snapshot errors.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// Snapshot not found.
    #[error("snapshot not found: {0}")]
    NotFound(String),
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Snapshot is corrupted.
    #[error("snapshot corrupted: {0}")]
    Corrupted(String),
    /// Snapshot is in invalid state.
    #[error("invalid state: {0}")]
    InvalidState(String),
    /// Snapshot is in use.
    #[error("snapshot in use: {0}")]
    InUse(String),
    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
    /// CRIU error.
    #[error("CRIU error: {0}")]
    CriuError(String),
    /// Compression error.
    #[error("compression error: {0}")]
    CompressionError(String),
}
