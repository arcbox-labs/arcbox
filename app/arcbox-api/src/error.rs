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
                // Stdin offset gap: the client resyncs via GetStdinStatus.
                416 => Self::out_of_range(message),
                503 => Self::unavailable(message),
                _ => Self::internal(message),
            },
            ApiError::Grpc(_) => Self::unavailable(message),
            _ => Self::internal(message),
        }
    }
}

/// The sandbox services answer over Connect, so their errors must land as
/// `ConnectError` rather than `Status`.
///
/// The gRPC status code is the shared vocabulary between the two, and
/// [`tonic::Status`] above already owns the one mapping table from
/// `ApiError` to a code. Routing through it keeps that table single-source:
/// a new `ApiError` variant is classified once and both surfaces follow.
impl From<ApiError> for connectrpc::ConnectError {
    fn from(err: ApiError) -> Self {
        use connectrpc::ErrorCode;
        use tonic::Code;

        let status = tonic::Status::from(err);
        let code = match status.code() {
            Code::Cancelled => ErrorCode::Canceled,
            Code::InvalidArgument => ErrorCode::InvalidArgument,
            Code::DeadlineExceeded => ErrorCode::DeadlineExceeded,
            Code::NotFound => ErrorCode::NotFound,
            Code::AlreadyExists => ErrorCode::AlreadyExists,
            Code::PermissionDenied => ErrorCode::PermissionDenied,
            Code::ResourceExhausted => ErrorCode::ResourceExhausted,
            Code::FailedPrecondition => ErrorCode::FailedPrecondition,
            Code::Aborted => ErrorCode::Aborted,
            Code::OutOfRange => ErrorCode::OutOfRange,
            Code::Unimplemented => ErrorCode::Unimplemented,
            Code::Unavailable => ErrorCode::Unavailable,
            Code::DataLoss => ErrorCode::DataLoss,
            Code::Unauthenticated => ErrorCode::Unauthenticated,
            // `Ok` never reaches here (an ApiError always maps to a
            // failure), and `Unknown`/`Internal` share one bucket.
            Code::Ok | Code::Unknown | Code::Internal => ErrorCode::Internal,
        };
        Self::new(code, status.message())
    }
}

impl ApiError {
    /// Creates a new configuration error.
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Common(CommonError::config(msg))
    }
}
