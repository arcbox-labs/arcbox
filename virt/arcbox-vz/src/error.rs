//! Error types for arcbox-vz.

use std::fmt;

/// Error type for Virtualization.framework operations.
#[derive(Debug, Clone)]
pub enum VZError {
    /// Virtualization is not supported on this system.
    NotSupported,

    /// Invalid configuration parameters.
    InvalidConfiguration(String),

    /// A VM operation failed.
    OperationFailed(String),

    /// Invalid state transition attempted.
    InvalidState {
        /// Expected state(s).
        expected: String,
        /// Actual state.
        actual: String,
    },

    /// Connection to vsock port failed.
    ConnectionFailed(String),

    /// Operation timed out.
    Timeout(String),

    /// File or path not found.
    NotFound(String),

    /// Internal framework error.
    Internal {
        /// Error code from NSError.
        code: i32,
        /// Error message.
        message: String,
    },
}

impl fmt::Display for VZError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSupported => write!(f, "Virtualization not supported on this system"),
            Self::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {msg}"),
            Self::OperationFailed(msg) => write!(f, "VM operation failed: {msg}"),
            Self::InvalidState { expected, actual } => {
                write!(f, "Invalid state: expected {expected}, got {actual}")
            }
            Self::ConnectionFailed(msg) => write!(f, "Connection failed: {msg}"),
            Self::Timeout(msg) => write!(f, "Timeout: {msg}"),
            Self::NotFound(path) => write!(f, "Not found: {path}"),
            Self::Internal { code, message } => {
                write!(f, "Internal error (code={code}): {message}")
            }
        }
    }
}

impl std::error::Error for VZError {}

/// Result type alias for VZError.
pub type VZResult<T> = Result<T, VZError>;
