//! Structured error types for the sandbox service.
//!
//! [`SandboxError`] carries an HTTP-style status code over the vsock wire so
//! the host can map agent failures onto the right gRPC status instead of a
//! blanket `INTERNAL` (see `CoreError::Agent` and the `ApiError → Status`
//! mapping in `arcbox-api`).

use std::fmt;

/// Error returned by [`SandboxService`](crate::sandbox::SandboxService) methods.
#[derive(Debug)]
pub enum SandboxError {
    /// The request payload could not be decoded (protobuf parse failure).
    Decode(String),
    /// The request is malformed or violates a constraint (e.g. an invalid
    /// sandbox id or an out-of-range field).
    InvalidArgument(String),
    /// The referenced sandbox / snapshot does not exist.
    NotFound(String),
    /// A sandbox with the requested ID already exists.
    AlreadyExists(String),
    /// The sandbox is not in a state that allows the operation.
    WrongState(String),
    /// The host / guest lacks a prerequisite (e.g. nested virtualization).
    Unsupported(String),
    /// A runtime or business-logic error.
    Internal(String),
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(msg) => write!(f, "decode error: {msg}"),
            Self::InvalidArgument(msg)
            | Self::NotFound(msg)
            | Self::AlreadyExists(msg)
            | Self::WrongState(msg)
            | Self::Unsupported(msg)
            | Self::Internal(msg) => f.write_str(msg),
        }
    }
}

impl SandboxError {
    /// HTTP-style status code carried in the wire `ErrorResponse`.
    ///
    /// The host maps these onto gRPC statuses: 400 → `INVALID_ARGUMENT`,
    /// 404 → `NOT_FOUND`, 409 → `ALREADY_EXISTS`, 412 → `FAILED_PRECONDITION`,
    /// 503 → `UNAVAILABLE`, anything else → `INTERNAL`.
    pub const fn status_code(&self) -> i32 {
        match self {
            Self::Decode(_) | Self::InvalidArgument(_) => 400,
            Self::NotFound(_) => 404,
            Self::AlreadyExists(_) => 409,
            Self::WrongState(_) | Self::Unsupported(_) => 412,
            Self::Internal(_) => 500,
        }
    }
}

impl From<arcbox_vm::VmmError> for SandboxError {
    fn from(e: arcbox_vm::VmmError) -> Self {
        use arcbox_vm::VmmError;
        match &e {
            VmmError::NotFound(_) => Self::NotFound(e.to_string()),
            VmmError::AlreadyExists(_) => Self::AlreadyExists(e.to_string()),
            VmmError::WrongState { .. } => Self::WrongState(e.to_string()),
            // Invalid caller input (e.g. a rejected sandbox id) is a 400, not a
            // 500 — otherwise a bad request surfaces as INTERNAL to the client.
            VmmError::Config(_) => Self::InvalidArgument(e.to_string()),
            _ => Self::Internal(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_config_maps_to_400_not_500() {
        let err = SandboxError::from(arcbox_vm::VmmError::Config("bad id".into()));
        assert!(matches!(err, SandboxError::InvalidArgument(_)));
        assert_eq!(err.status_code(), 400);
    }

    #[test]
    fn runtime_errors_stay_500() {
        let err = SandboxError::from(arcbox_vm::VmmError::Vsock("boom".into()));
        assert_eq!(err.status_code(), 500);
    }
}
