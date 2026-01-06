//! Error types for the API server.

use thiserror::Error;

/// Result type alias for API operations.
pub type Result<T> = std::result::Result<T, ApiError>;

/// Errors that can occur in API operations.
#[derive(Debug, Error)]
pub enum ApiError {
    /// Core error.
    #[error("core error: {0}")]
    Core(#[from] arcbox_core::CoreError),

    /// gRPC error.
    #[error("gRPC error: {0}")]
    Grpc(#[from] tonic::transport::Error),

    /// Server error.
    #[error("server error: {0}")]
    Server(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Transport error.
    #[error("transport error: {0}")]
    Transport(String),
}
