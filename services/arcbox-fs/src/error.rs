//! Error types for the filesystem service.

use arcbox_error::CommonError;
use thiserror::Error;

/// Result type alias for filesystem operations.
pub type Result<T> = std::result::Result<T, FsError>;

/// Errors that can occur during filesystem operations.
#[derive(Debug, Error)]
pub enum FsError {
    /// Common errors shared across ArcBox crates.
    #[error(transparent)]
    Common(#[from] CommonError),

    /// Invalid path.
    #[error("invalid path: {0}")]
    InvalidPath(String),

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

impl From<std::io::Error> for FsError {
    fn from(err: std::io::Error) -> Self {
        Self::Common(CommonError::from(err))
    }
}

impl FsError {
    /// Creates an I/O error.
    #[must_use]
    pub fn io(err: std::io::Error) -> Self {
        Self::Common(CommonError::Io(err))
    }

    /// Creates a not found error.
    #[must_use]
    pub fn not_found(path: impl Into<String>) -> Self {
        Self::Common(CommonError::not_found(path))
    }

    /// Creates a permission denied error.
    #[must_use]
    pub fn permission_denied(path: impl Into<String>) -> Self {
        Self::Common(CommonError::permission_denied(path))
    }

    /// Returns true if this is a not found error.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Common(CommonError::NotFound(_)))
    }

    /// Converts the error to a POSIX errno.
    #[must_use]
    pub fn to_errno(&self) -> i32 {
        match self {
            Self::Common(e) => Self::common_to_errno(e),
            Self::InvalidPath(_) => libc::EINVAL,
            Self::NotSupported(_) => libc::ENOSYS,
            Self::Fuse(_) | Self::Cache(_) => libc::EIO,
            Self::InvalidHandle(_) => libc::EBADF,
        }
    }

    /// Converts a CommonError to a POSIX errno.
    fn common_to_errno(err: &CommonError) -> i32 {
        match err {
            CommonError::Io(e) => e.raw_os_error().unwrap_or(libc::EIO),
            CommonError::NotFound(_) => libc::ENOENT,
            CommonError::PermissionDenied(_) => libc::EACCES,
            CommonError::AlreadyExists(_) => libc::EEXIST,
            CommonError::Config(_)
            | CommonError::InvalidState(_)
            | CommonError::Timeout(_)
            | CommonError::Internal(_) => libc::EIO,
        }
    }
}
