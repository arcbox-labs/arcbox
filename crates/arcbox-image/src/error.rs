//! Error types for image operations.

use thiserror::Error;

/// Result type alias for image operations.
pub type Result<T> = std::result::Result<T, ImageError>;

/// Errors that can occur during image operations.
#[derive(Debug, Error)]
pub enum ImageError {
    /// Image not found.
    #[error("image not found: {0}")]
    NotFound(String),

    /// Invalid image reference.
    #[error("invalid image reference: {0}")]
    InvalidReference(String),

    /// Registry error.
    #[error("registry error: {0}")]
    Registry(String),

    /// Authentication error.
    #[error("authentication error: {0}")]
    Auth(String),

    /// Manifest error.
    #[error("manifest error: {0}")]
    Manifest(String),

    /// Layer error.
    #[error("layer error: {0}")]
    Layer(String),

    /// Storage error.
    #[error("storage error: {0}")]
    Storage(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
