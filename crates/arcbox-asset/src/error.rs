//! Error types for asset operations.

/// Errors that can occur during asset download, verification, or caching.
#[derive(Debug, thiserror::Error)]
pub enum AssetError {
    /// SHA-256 checksum mismatch after download.
    #[error("sha256 mismatch for '{name}': expected {expected}, got {actual}")]
    ChecksumMismatch {
        name: String,
        expected: String,
        actual: String,
    },

    /// HTTP or network-level download failure.
    #[error("download failed: {0}")]
    Download(String),

    /// Filesystem I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, AssetError>;
