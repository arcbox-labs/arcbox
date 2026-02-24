//! Error types for transport operations.

use arcbox_error::CommonError;
use thiserror::Error;

/// Result type alias for transport operations.
pub type Result<T> = std::result::Result<T, TransportError>;

/// Errors that can occur during transport operations.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Common errors shared across ArcBox crates.
    #[error(transparent)]
    Common(#[from] CommonError),

    /// Not connected.
    #[error("not connected")]
    NotConnected,

    /// Already connected.
    #[error("already connected")]
    AlreadyConnected,

    /// Connection refused.
    #[error("connection refused: {0}")]
    ConnectionRefused(String),

    /// Connection reset.
    #[error("connection reset")]
    ConnectionReset,

    /// Invalid address.
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// Protocol error.
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl From<std::io::Error> for TransportError {
    fn from(err: std::io::Error) -> Self {
        Self::Common(CommonError::from(err))
    }
}

impl TransportError {
    /// Creates an I/O error from std::io::Error.
    #[must_use]
    pub fn io(err: std::io::Error) -> Self {
        Self::Common(CommonError::from(err))
    }
}
