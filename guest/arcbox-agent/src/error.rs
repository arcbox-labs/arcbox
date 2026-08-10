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
    /// The referenced sandbox / snapshot / execution does not exist.
    NotFound(String),
    /// A sandbox or execution with the requested ID already exists.
    AlreadyExists(String),
    /// The sandbox is not in a state that allows the operation.
    WrongState(String),
    /// The sandbox is paused. Carried as its own wire code (423) so the
    /// daemon can recognise "paused" machine-readably and resume the
    /// sandbox transparently on data-plane calls (CORE-21).
    SandboxPaused(String),
    /// A stdin write's offset is past the accepted byte count; the client
    /// must resync via `GetStdinStatus` and resume from the reported offset.
    StdinGap(String),
    /// The host / guest lacks a prerequisite (e.g. nested virtualization).
    Unsupported(String),
    /// A bounded wait elapsed before the awaited condition held (e.g. a
    /// `WaitForPort` deadline). Carried as 504 so the daemon maps it onto
    /// `DEADLINE_EXCEEDED` instead of a blanket `INTERNAL`.
    Deadline(String),
    /// A retryable runtime condition, including an unconfirmed durable write.
    Unavailable(String),
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
            | Self::SandboxPaused(msg)
            | Self::StdinGap(msg)
            | Self::Unsupported(msg)
            | Self::Deadline(msg)
            | Self::Unavailable(msg)
            | Self::Internal(msg) => f.write_str(msg),
        }
    }
}

impl SandboxError {
    /// HTTP-style status code carried in the wire `ErrorResponse`.
    ///
    /// The host maps these onto gRPC statuses: 400 → `INVALID_ARGUMENT`,
    /// 404 → `NOT_FOUND`, 409 → `ALREADY_EXISTS`, 412 → `FAILED_PRECONDITION`,
    /// 416 → `OUT_OF_RANGE`, 423 → `FAILED_PRECONDITION` (after the daemon's
    /// transparent auto-resume declined — 423 is the machine-readable
    /// "paused" signal it keys on, CORE-21), 503 → `UNAVAILABLE`, anything
    /// else → `INTERNAL`.
    pub const fn status_code(&self) -> i32 {
        match self {
            Self::Decode(_) | Self::InvalidArgument(_) => 400,
            Self::NotFound(_) => 404,
            Self::AlreadyExists(_) => 409,
            Self::WrongState(_) | Self::Unsupported(_) => 412,
            Self::StdinGap(_) => 416,
            Self::SandboxPaused(_) => 423,
            Self::Unavailable(_) => 503,
            Self::Deadline(_) => 504,
            Self::Internal(_) => 500,
        }
    }
}

impl From<arcbox_vm::VmmError> for SandboxError {
    fn from(e: arcbox_vm::VmmError) -> Self {
        use arcbox_vm::VmmError;
        match &e {
            // A missing sandbox path keeps its typed "path not found:"
            // message: the daemon's classifier maps the 404 onto the
            // FILE_NOT_FOUND registry code by that prefix.
            // A missing template keeps its typed "template not found:"
            // message for the same reason (TEMPLATE_NOT_FOUND, CORE-107).
            VmmError::NotFound(_) | VmmError::PathNotFound(_) | VmmError::TemplateNotFound(_) => {
                Self::NotFound(e.to_string())
            }
            VmmError::AlreadyExists(_) | VmmError::TemplateVersionExists(_) => {
                Self::AlreadyExists(e.to_string())
            }
            // A non-empty directory is a precondition failure (412), like a
            // wrong sandbox state: retrying without `recursive` never helps.
            VmmError::WrongState { .. }
            | VmmError::DirectoryNotEmpty(_)
            | VmmError::FailedPrecondition(_) => Self::WrongState(e.to_string()),
            VmmError::Paused(_) => Self::SandboxPaused(e.to_string()),
            VmmError::StdinGap { .. } => Self::StdinGap(e.to_string()),
            VmmError::DeadlineExceeded(_) => Self::Deadline(e.to_string()),
            VmmError::Unavailable(_) | VmmError::AckUnconfirmed { .. } => {
                Self::Unavailable(e.to_string())
            }
            // Invalid caller input (e.g. a rejected sandbox id, or a
            // directory verb aimed at a non-directory) is a 400, not a
            // 500 — otherwise a bad request surfaces as INTERNAL.
            VmmError::Config(_) | VmmError::NotADirectory(_) => {
                Self::InvalidArgument(e.to_string())
            }
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

    #[test]
    fn stdin_gap_maps_to_416() {
        let err = SandboxError::from(arcbox_vm::VmmError::StdinGap {
            accepted: 7,
            offset: 9,
        });
        assert!(matches!(err, SandboxError::StdinGap(_)));
        assert_eq!(err.status_code(), 416);
    }

    #[test]
    fn paused_maps_to_423_for_the_daemon_auto_resume() {
        let err = SandboxError::from(arcbox_vm::VmmError::Paused("box".into()));
        assert!(matches!(err, SandboxError::SandboxPaused(_)));
        assert_eq!(err.status_code(), 423);
    }

    #[test]
    fn path_not_found_maps_to_404_with_the_classifier_prefix() {
        let err = SandboxError::from(arcbox_vm::VmmError::PathNotFound("/a/b".into()));
        assert!(matches!(err, SandboxError::NotFound(_)));
        assert_eq!(err.status_code(), 404);
        // The daemon classifier keys on this exact prefix (FILE_NOT_FOUND).
        assert_eq!(err.to_string(), "path not found: /a/b");
    }

    #[test]
    fn template_errors_keep_their_classifier_prefixes_and_codes() {
        let err = SandboxError::from(arcbox_vm::VmmError::TemplateNotFound("code:9.9".into()));
        assert!(matches!(err, SandboxError::NotFound(_)));
        assert_eq!(err.status_code(), 404);
        // The daemon classifier keys on this exact prefix (TEMPLATE_NOT_FOUND).
        assert_eq!(err.to_string(), "template not found: code:9.9");

        let err = SandboxError::from(arcbox_vm::VmmError::TemplateVersionExists("x".into()));
        assert_eq!(err.status_code(), 409);

        let err = SandboxError::from(arcbox_vm::VmmError::FailedPrecondition("no draft".into()));
        assert_eq!(err.status_code(), 412);
    }

    #[test]
    fn directory_not_empty_maps_to_412() {
        let err = SandboxError::from(arcbox_vm::VmmError::DirectoryNotEmpty("/full".into()));
        assert_eq!(err.status_code(), 412);
    }

    #[test]
    fn not_a_directory_maps_to_400() {
        let err = SandboxError::from(arcbox_vm::VmmError::NotADirectory("/a/file".into()));
        assert_eq!(err.status_code(), 400);
    }

    #[test]
    fn deadline_maps_to_504_for_the_daemon_deadline_code() {
        let err = SandboxError::from(arcbox_vm::VmmError::DeadlineExceeded(
            "no listener on port 8080".into(),
        ));
        assert!(matches!(err, SandboxError::Deadline(_)));
        assert_eq!(err.status_code(), 504);
    }

    #[test]
    fn durability_uncertainty_maps_to_503() {
        let err = SandboxError::from(arcbox_vm::VmmError::Unavailable(
            "record fsync failed".into(),
        ));
        assert!(matches!(err, SandboxError::Unavailable(_)));
        assert_eq!(err.status_code(), 503);
    }
}
