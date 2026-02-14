//! Error types for image operations.

use arcbox_error::CommonError;
use thiserror::Error;

/// Result type alias for image operations.
pub type Result<T> = std::result::Result<T, ImageError>;

/// Errors that can occur during image operations.
#[derive(Debug, Error)]
pub enum ImageError {
    /// Common errors shared across ArcBox crates.
    #[error(transparent)]
    Common(#[from] CommonError),

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

    /// JSON error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<std::io::Error> for ImageError {
    fn from(err: std::io::Error) -> Self {
        Self::Common(CommonError::from(err))
    }
}

impl ImageError {
    /// Creates a new not found error.
    #[must_use]
    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::Common(CommonError::not_found(resource))
    }

    /// Returns true if this is a not found error.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Common(CommonError::NotFound(_)))
    }
}
