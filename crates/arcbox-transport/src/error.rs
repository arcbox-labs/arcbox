//! Error types for transport operations.

use thiserror::Error;

/// Result type alias for transport operations.
pub type Result<T> = std::result::Result<T, TransportError>;

/// Errors that can occur during transport operations.
#[derive(Debug, Error)]
pub enum TransportError {
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

    /// Timeout.
    #[error("timeout")]
    Timeout,

    /// Invalid address.
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// Protocol error.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
