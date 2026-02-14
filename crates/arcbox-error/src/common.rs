//! Common error types shared across `ArcBox` crates.

use thiserror::Error;

/// Common errors that occur across multiple `ArcBox` crates.
///
/// This enum provides a unified set of error variants for common scenarios
/// like I/O errors, configuration issues, and resource lookup failures.
/// Crate-specific errors should wrap this type using `#[from]` attribute.
#[derive(Debug, Error)]
pub enum CommonError {
    /// I/O error from the standard library.
    ///
    /// This is the most common error type, wrapping `std::io::Error` for
    /// filesystem operations, network I/O, and other system calls.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration error.
    ///
    /// Indicates invalid or missing configuration values, malformed config
    /// files, or configuration validation failures.
    #[error("configuration error: {0}")]
    Config(String),

    /// Resource not found.
    ///
    /// Used when a requested resource (container, image, volume, network, etc.)
    /// does not exist in the system.
    #[error("not found: {0}")]
    NotFound(String),

    /// Resource already exists.
    ///
    /// Used when attempting to create a resource that already exists.
    #[error("already exists: {0}")]
    AlreadyExists(String),

    /// Invalid state transition.
    ///
    /// Indicates that an operation was attempted on a resource that is not
    /// in a valid state for that operation (e.g., stopping an already stopped
    /// container).
    #[error("invalid state: {0}")]
    InvalidState(String),

    /// Operation timeout.
    ///
    /// Used when an operation exceeds its allowed time limit.
    #[error("timeout: {0}")]
    Timeout(String),

    /// Permission denied.
    ///
    /// Used when an operation fails due to insufficient permissions.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Internal error.
    ///
    /// A catch-all for unexpected internal errors. Should include enough
    /// context for debugging.
    #[error("internal error: {0}")]
    Internal(String),
}

impl CommonError {
    /// Creates a new configuration error.
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Creates a new not found error.
    #[must_use]
    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::NotFound(resource.into())
    }

    /// Creates a new already exists error.
    #[must_use]
    pub fn already_exists(resource: impl Into<String>) -> Self {
        Self::AlreadyExists(resource.into())
    }

    /// Creates a new invalid state error.
    #[must_use]
    pub fn invalid_state(msg: impl Into<String>) -> Self {
        Self::InvalidState(msg.into())
    }

    /// Creates a new timeout error.
    #[must_use]
    pub fn timeout(msg: impl Into<String>) -> Self {
        Self::Timeout(msg.into())
    }

    /// Creates a new permission denied error.
    #[must_use]
    pub fn permission_denied(resource: impl Into<String>) -> Self {
        Self::PermissionDenied(resource.into())
    }

    /// Creates a new internal error.
    #[must_use]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Returns true if this is an I/O error.
    #[must_use]
    pub const fn is_io(&self) -> bool {
        matches!(self, Self::Io(_))
    }

    /// Returns true if this is a not found error.
    #[must_use]
    pub const fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }

    /// Returns true if this is an already exists error.
    #[must_use]
    pub const fn is_already_exists(&self) -> bool {
        matches!(self, Self::AlreadyExists(_))
    }

    /// Returns true if this is a timeout error.
    #[must_use]
    pub const fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let common_err: CommonError = io_err.into();
        assert!(common_err.is_io());
        assert!(common_err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_not_found_error() {
        let err = CommonError::not_found("container abc123");
        assert!(err.is_not_found());
        assert_eq!(err.to_string(), "not found: container abc123");
    }

    #[test]
    fn test_already_exists_error() {
        let err = CommonError::already_exists("network bridge0");
        assert!(err.is_already_exists());
        assert_eq!(err.to_string(), "already exists: network bridge0");
    }

    #[test]
    fn test_config_error() {
        let err = CommonError::config("invalid port number");
        assert_eq!(err.to_string(), "configuration error: invalid port number");
    }

    #[test]
    fn test_invalid_state_error() {
        let err = CommonError::invalid_state("container is not running");
        assert_eq!(
            err.to_string(),
            "invalid state: container is not running"
        );
    }

    #[test]
    fn test_timeout_error() {
        let err = CommonError::timeout("connection timed out after 30s");
        assert!(err.is_timeout());
        assert_eq!(
            err.to_string(),
            "timeout: connection timed out after 30s"
        );
    }

    #[test]
    fn test_permission_denied_error() {
        let err = CommonError::permission_denied("/var/run/docker.sock");
        assert_eq!(
            err.to_string(),
            "permission denied: /var/run/docker.sock"
        );
    }

    #[test]
    fn test_internal_error() {
        let err = CommonError::internal("unexpected null pointer");
        assert_eq!(err.to_string(), "internal error: unexpected null pointer");
    }
}
