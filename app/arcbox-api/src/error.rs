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

/// Every service answers over Connect, so `ApiError` classifies straight
/// into a Connect error code. The assignments predate the tonic retirement
/// (CORE-68/73): clients see the same codes the gRPC services always
/// answered.
impl From<ApiError> for connectrpc::ConnectError {
    fn from(err: ApiError) -> Self {
        use connectrpc::ErrorCode;

        let message = err.to_string();
        let code = match &err {
            ApiError::Common(common) => match common {
                CommonError::Config(_) => ErrorCode::InvalidArgument,
                CommonError::NotFound(_) => ErrorCode::NotFound,
                CommonError::AlreadyExists(_) => ErrorCode::AlreadyExists,
                CommonError::InvalidState(_) => ErrorCode::FailedPrecondition,
                CommonError::Timeout(_) => ErrorCode::DeadlineExceeded,
                CommonError::PermissionDenied(_) => ErrorCode::PermissionDenied,
                _ => ErrorCode::Internal,
            },
            // Agent-reported errors carry an HTTP-style code over the wire.
            ApiError::Core(arcbox_core::CoreError::Agent { code, .. }) => match code {
                400 => ErrorCode::InvalidArgument,
                404 => ErrorCode::NotFound,
                409 => ErrorCode::AlreadyExists,
                412 => ErrorCode::FailedPrecondition,
                // Stdin offset gap: the client resyncs via GetStdinStatus.
                416 => ErrorCode::OutOfRange,
                // Paused sandbox surfaced without a transparent resume
                // (control-plane call, or the caller opted out): a
                // FAILED_PRECONDITION carrying the machine-readable
                // SANDBOX_PAUSED detail (CORE-21).
                423 => {
                    let mut error = Self::new(ErrorCode::FailedPrecondition, message);
                    error.details.push(sandbox_paused_detail());
                    return error;
                }
                503 => ErrorCode::Unavailable,
                _ => ErrorCode::Internal,
            },
            _ => ErrorCode::Internal,
        };
        Self::new(code, message)
    }
}

/// The `SANDBOX_PAUSED` `ErrorInfo` Connect error detail (`errors.proto`).
fn sandbox_paused_detail() -> connectrpc::ErrorDetail {
    use arcbox_connect::sandbox_v1 as pb;

    error_info(
        pb::ErrorCode::SandboxPaused,
        "resume the sandbox (`abctl sandbox resume <id>`), or retry \
         the data-plane call without `x-arcbox-no-auto-resume`",
        &[],
    )
}

/// Build the `arcbox.sandbox.v1.ErrorInfo` Connect error detail from a
/// registry code + actionable suggestion + structured context (CORE-58).
/// The single builder every attachment site uses, so the type URL and
/// shape SDKs parse stay in one place.
pub(crate) fn error_info(
    code: arcbox_connect::sandbox_v1::ErrorCode,
    suggestion: &str,
    context: &[(&str, &str)],
) -> connectrpc::ErrorDetail {
    let info = arcbox_connect::sandbox_v1::ErrorInfo {
        code: code.into(),
        suggestion: suggestion.to_owned(),
        context: context
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect(),
        ..Default::default()
    };
    connectrpc::ErrorDetail::from_message("arcbox.sandbox.v1.ErrorInfo", &info)
}

impl ApiError {
    /// Creates a new configuration error.
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Common(CommonError::config(msg))
    }
}
