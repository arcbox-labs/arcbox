//! Error types for the filesystem service.

use thiserror::Error;

/// Result type alias for filesystem operations.
pub type Result<T> = std::result::Result<T, FsError>;

/// Errors that can occur during filesystem operations.
#[derive(Debug, Error)]
pub enum FsError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid path.
    #[error("invalid path: {0}")]
    InvalidPath(String),

    /// File not found.
    #[error("file not found: {0}")]
    NotFound(String),

    /// Permission denied.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Operation not supported.
    #[error("operation not supported: {0}")]
    NotSupported(String),

    /// FUSE protocol error.
    #[error("FUSE error: {0}")]
    Fuse(String),

    /// Cache error.
    #[error("cache error: {0}")]
    Cache(String),

    /// Invalid file handle.
    #[error("invalid file handle: {0}")]
    InvalidHandle(u64),
}

impl FsError {
    /// Converts the error to a POSIX errno.
    #[must_use]
    pub fn to_errno(&self) -> i32 {
        match self {
            Self::Io(e) => e.raw_os_error().unwrap_or(libc::EIO),
            Self::InvalidPath(_) => libc::EINVAL,
            Self::NotFound(_) => libc::ENOENT,
            Self::PermissionDenied(_) => libc::EACCES,
            Self::NotSupported(_) => libc::ENOSYS,
            Self::Fuse(_) | Self::Cache(_) => libc::EIO,
            Self::InvalidHandle(_) => libc::EBADF,
        }
    }
}
