//! Error types for container operations.

use arcbox_error::CommonError;
use thiserror::Error;

/// Result type alias for container operations.
pub type Result<T> = std::result::Result<T, ContainerError>;

/// Errors that can occur during container operations.
#[derive(Debug, Error)]
pub enum ContainerError {
    /// Common errors shared across ArcBox crates.
    #[error(transparent)]
    Common(#[from] CommonError),

    /// Image error.
    #[error("image error: {0}")]
    Image(String),

    /// Volume error.
    #[error("volume error: {0}")]
    Volume(String),

    /// Runtime error.
    #[error("runtime error: {0}")]
    Runtime(String),

    /// Internal lock poisoned.
    #[error("internal lock poisoned")]
    LockPoisoned,
}

impl From<std::io::Error> for ContainerError {
    fn from(err: std::io::Error) -> Self {
        Self::Common(CommonError::from(err))
    }
}

impl ContainerError {
    /// Creates a new not found error.
    #[must_use]
    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::Common(CommonError::not_found(resource))
    }

    /// Creates a new invalid state error.
    #[must_use]
    pub fn invalid_state(msg: impl Into<String>) -> Self {
        Self::Common(CommonError::invalid_state(msg))
    }

    /// Creates a new config error.
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Common(CommonError::config(msg))
    }

    /// Creates a new already exists error.
    #[must_use]
    pub fn already_exists(resource: impl Into<String>) -> Self {
        Self::Common(CommonError::already_exists(resource))
    }

    /// Returns true if this is a not found error.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Common(CommonError::NotFound(_)))
    }

    /// Returns true if this is an invalid state error.
    #[must_use]
    pub fn is_invalid_state(&self) -> bool {
        matches!(self, Self::Common(CommonError::InvalidState(_)))
    }
}
