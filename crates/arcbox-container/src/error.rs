//! Error types for container operations.

use thiserror::Error;

/// Result type alias for container operations.
pub type Result<T> = std::result::Result<T, ContainerError>;

/// Errors that can occur during container operations.
#[derive(Debug, Error)]
pub enum ContainerError {
    /// Container not found.
    #[error("container not found: {0}")]
    NotFound(String),

    /// Container already exists.
    #[error("container already exists: {0}")]
    AlreadyExists(String),

    /// Invalid container state.
    #[error("invalid container state: {0}")]
    InvalidState(String),

    /// Image error.
    #[error("image error: {0}")]
    Image(String),

    /// Volume error.
    #[error("volume error: {0}")]
    Volume(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Runtime error.
    #[error("runtime error: {0}")]
    Runtime(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
