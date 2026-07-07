//! Error types for the API server.

use arcbox_error::CommonError;
use thiserror::Error;

/// Result type alias for API operations.
pub type Result<T> = std::result::Result<T, ApiError>;

/// Errors that can occur in API operations.
#[derive(Debug, Error)]
pub enum ApiError {
    /// Common errors (I/O, config, etc.).
    #[error(transparent)]
    Common(#[from] CommonError),

    /// Core error.
    #[error("core error: {0}")]
    Core(#[from] arcbox_core::CoreError),

    /// gRPC error.
    #[error("gRPC error: {0}")]
    Grpc(#[from] tonic::transport::Error),

    /// Server error.
    #[error("server error: {0}")]
    Server(String),

    /// Transport error.
    #[error("transport error: {0}")]
    Transport(String),
}

// Allow automatic conversion from std::io::Error to ApiError via CommonError.
impl From<std::io::Error> for ApiError {
    fn from(err: std::io::Error) -> Self {
        Self::Common(CommonError::from(err))
    }
}

impl From<ApiError> for tonic::Status {
    fn from(err: ApiError) -> Self {
        let message = err.to_string();
        match &err {
            ApiError::Common(common) => match common {
                CommonError::Config(_) => Self::invalid_argument(message),
                CommonError::NotFound(_) => Self::not_found(message),
                CommonError::AlreadyExists(_) => Self::already_exists(message),
                CommonError::InvalidState(_) => Self::failed_precondition(message),
                CommonError::Timeout(_) => Self::deadline_exceeded(message),
                CommonError::PermissionDenied(_) => Self::permission_denied(message),
                _ => Self::internal(message),
            },
            // Agent-reported errors carry an HTTP-style code over the wire.
            ApiError::Core(arcbox_core::CoreError::Agent { code, .. }) => match code {
                400 => Self::invalid_argument(message),
                404 => Self::not_found(message),
                409 => Self::already_exists(message),
                412 => Self::failed_precondition(message),
                503 => Self::unavailable(message),
                _ => Self::internal(message),
            },
            ApiError::Grpc(_) => Self::unavailable(message),
            _ => Self::internal(message),
        }
    }
}

impl ApiError {
    /// Creates a new configuration error.
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Common(CommonError::config(msg))
    }
}
