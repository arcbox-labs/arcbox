//! Error types for the image layer.

use arcbox_error::CommonError;
use thiserror::Error;

/// Result type alias for image operations.
pub type Result<T> = std::result::Result<T, ImageError>;

/// Errors that can occur in boot-asset and machine-image operations.
#[derive(Debug, Error)]
pub enum ImageError {
    /// Common errors (I/O, config, not found, etc.).
    #[error(transparent)]
    Common(#[from] CommonError),

    /// Published-image registry error (index/manifest fetch, reference
    /// parsing, name validation).
    #[error("image error: {0}")]
    Image(String),
}

impl ImageError {
    /// Creates a new configuration error.
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Common(CommonError::config(msg))
    }

    /// Creates a new not found error.
    #[must_use]
    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::Common(CommonError::not_found(resource))
    }

    /// Creates a new published-image registry error.
    #[must_use]
    pub fn image(msg: impl Into<String>) -> Self {
        Self::Image(msg.into())
    }
}

// Allow automatic conversion from std::io::Error via CommonError, matching
// the CoreError convention in arcbox-core.
impl From<std::io::Error> for ImageError {
    fn from(err: std::io::Error) -> Self {
        Self::Common(CommonError::from(err))
    }
}
