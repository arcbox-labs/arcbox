//! The SDK's error type, derived from the daemon's error registry.
//!
//! One boundary: every RPC failure is mapped through [`Error::from_connect`],
//! with the registry's `arcbox.sandbox.v1.ErrorInfo` detail (precise) taking
//! precedence over the coarse Connect code — the same precedence the
//! TypeScript and Python SDKs apply.

use std::collections::BTreeMap;
use std::fmt;

use arcbox_connect::sandbox_v1 as pb;
use base64::Engine as _;
use buffa::Message as _;
use connectrpc::{ConnectError, ErrorCode};

/// Convenience alias for SDK results.
pub type Result<T> = std::result::Result<T, Error>;

/// What went wrong, as a machine-usable class.
///
/// Mirrors the daemon's error registry (`errors.proto`): unknown future
/// registry codes fall back to the coarse class of their transport code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The addressed resource does not exist (coarse).
    NotFound,
    /// The addressed sandbox does not exist.
    SandboxNotFound,
    /// The addressed template does not exist or is malformed.
    TemplateNotFound,
    /// The addressed execution does not exist.
    ExecutionNotFound,
    /// The addressed path does not exist inside the sandbox.
    FileNotFound,
    /// A request argument was rejected.
    InvalidArgument,
    /// The sandbox exists but its state refuses this operation.
    SandboxState,
    /// A wait elapsed: a TTL, a command timeout, or a bounded SDK wait.
    Timeout,
    /// This host cannot run sandboxes (no nested virtualization).
    Capability,
    /// A file transfer exceeded the per-file size cap.
    FileTooLarge,
    /// Stdin was already closed for this execution.
    StdinClosed,
    /// The operation requires a TTY execution.
    TtyRequired,
    /// The requested host port is already bound.
    PortInUse,
    /// Authentication is required (reserved for the remote tier).
    Authentication,
    /// Client and daemon protocol levels are incompatible.
    ProtocolMismatch,
    /// The host is out of a resource (memory, disk, sandbox slots).
    ResourceExhausted,
    /// The daemon could not be reached.
    ConnectionFailed,
    /// A stream died after it had delivered data.
    ConnectionLost,
    /// The daemon is up but cannot serve this call right now.
    Unavailable,
    /// Anything the registry has no name for.
    Internal,
}

/// An SDK failure: a [`kind`](Error::kind) for matching, plus the
/// registry's actionable context.
///
/// Boxed internally so `Result<T>` stays one pointer wide.
#[derive(Debug)]
pub struct Error(Box<ErrorInner>);

#[derive(Debug)]
struct ErrorInner {
    kind: ErrorKind,
    message: String,
    operation: &'static str,
    code: Option<String>,
    suggestion: Option<String>,
    context: BTreeMap<String, String>,
    source: Option<ConnectError>,
}

impl Error {
    pub(crate) fn new(
        kind: ErrorKind,
        message: impl Into<String>,
        operation: &'static str,
    ) -> Self {
        Self(Box::new(ErrorInner {
            kind,
            message: message.into(),
            operation,
            code: None,
            suggestion: None,
            context: BTreeMap::new(),
            source: None,
        }))
    }

    pub(crate) fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.0.suggestion = Some(suggestion.into());
        self
    }

    pub(crate) fn with_context(mut self, key: &str, value: impl Into<String>) -> Self {
        self.0.context.insert(key.to_owned(), value.into());
        self
    }

    /// Map an RPC failure onto the SDK error, `ErrorInfo` detail first.
    pub(crate) fn from_connect(error: ConnectError, operation: &'static str) -> Self {
        let info = error.details.iter().find_map(decode_error_info);
        let kind = info
            .as_ref()
            .and_then(|info| registry_kind(info.code.as_known().unwrap_or_default()))
            .unwrap_or_else(|| coarse_kind(error.code));
        let message = error
            .message
            .clone()
            .unwrap_or_else(|| format!("{operation} failed"));
        let mut mapped = Self(Box::new(ErrorInner {
            kind,
            message,
            operation,
            code: info.as_ref().map(registry_code_name),
            suggestion: None,
            context: BTreeMap::new(),
            source: Some(error),
        }));
        if let Some(info) = info {
            if !info.suggestion.is_empty() {
                mapped.0.suggestion = Some(info.suggestion);
            }
            mapped.0.context = info.context.into_iter().collect();
        }
        mapped
    }

    /// The failure's class, for matching.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        self.0.kind
    }

    /// The registry code name (e.g. `SANDBOX_NOT_FOUND`), when the daemon
    /// attached one.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        self.0.code.as_deref()
    }

    /// An actionable fix, phrased for direct display.
    #[must_use]
    pub fn suggestion(&self) -> Option<&str> {
        self.0.suggestion.as_deref()
    }

    /// The SDK operation that failed (e.g. `sandbox.create`).
    #[must_use]
    pub fn operation(&self) -> &str {
        self.0.operation
    }

    /// Structured facts about the failure, from the registry.
    #[must_use]
    pub fn context(&self) -> &BTreeMap<String, String> {
        &self.0.context
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.0.operation, self.0.message)?;
        if let Some(suggestion) = &self.0.suggestion {
            write!(formatter, " ({suggestion})")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0
            .source
            .as_ref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

/// Decode one Connect error detail as the registry's `ErrorInfo`, if it
/// is one.
fn decode_error_info(detail: &connectrpc::ErrorDetail) -> Option<pb::ErrorInfo> {
    if detail.type_url != "arcbox.sandbox.v1.ErrorInfo" {
        return None;
    }
    let encoded = detail.value.as_deref()?.trim_end_matches('=');
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(encoded)
        .ok()?;
    pb::ErrorInfo::decode_from_slice(&bytes).ok()
}

/// Registry code → precise kind. `None` for codes this SDK predates, so
/// the coarse transport code decides instead.
fn registry_kind(code: pb::ErrorCode) -> Option<ErrorKind> {
    use pb::ErrorCode as Code;
    match code {
        Code::ERROR_CODE_SANDBOX_NOT_FOUND => Some(ErrorKind::SandboxNotFound),
        Code::ERROR_CODE_TEMPLATE_NOT_FOUND | Code::ERROR_CODE_TEMPLATE_INVALID => {
            Some(ErrorKind::TemplateNotFound)
        }
        Code::ERROR_CODE_EXECUTION_NOT_FOUND => Some(ErrorKind::ExecutionNotFound),
        Code::ERROR_CODE_FILE_NOT_FOUND => Some(ErrorKind::FileNotFound),
        Code::ERROR_CODE_SANDBOX_PAUSED
        | Code::ERROR_CODE_SANDBOX_NOT_READY
        | Code::ERROR_CODE_SANDBOX_FAILED => Some(ErrorKind::SandboxState),
        Code::ERROR_CODE_TTL_EXPIRED | Code::ERROR_CODE_COMMAND_TIMEOUT => Some(ErrorKind::Timeout),
        Code::ERROR_CODE_NESTED_VIRT_UNSUPPORTED => Some(ErrorKind::Capability),
        Code::ERROR_CODE_FILE_TOO_LARGE => Some(ErrorKind::FileTooLarge),
        Code::ERROR_CODE_STDIN_CLOSED => Some(ErrorKind::StdinClosed),
        Code::ERROR_CODE_TTY_REQUIRED => Some(ErrorKind::TtyRequired),
        Code::ERROR_CODE_PORT_IN_USE => Some(ErrorKind::PortInUse),
        Code::ERROR_CODE_AUTH_REQUIRED => Some(ErrorKind::Authentication),
        Code::ERROR_CODE_PROTOCOL_MISMATCH => Some(ErrorKind::ProtocolMismatch),
        Code::ERROR_CODE_RESOURCE_EXHAUSTED_HOST => Some(ErrorKind::ResourceExhausted),
        Code::ERROR_CODE_UNSPECIFIED => None,
    }
}

/// Coarse Connect code → kind, when no registry detail decided.
fn coarse_kind(code: ErrorCode) -> ErrorKind {
    match code {
        ErrorCode::NotFound => ErrorKind::NotFound,
        ErrorCode::InvalidArgument => ErrorKind::InvalidArgument,
        ErrorCode::FailedPrecondition => ErrorKind::SandboxState,
        ErrorCode::DeadlineExceeded => ErrorKind::Timeout,
        ErrorCode::Unauthenticated | ErrorCode::PermissionDenied => ErrorKind::Authentication,
        ErrorCode::ResourceExhausted => ErrorKind::ResourceExhausted,
        ErrorCode::Unavailable => ErrorKind::Unavailable,
        _ => ErrorKind::Internal,
    }
}

/// The registry code's stable SCREAMING_SNAKE name (`SANDBOX_NOT_FOUND`).
fn registry_code_name(info: &pb::ErrorInfo) -> String {
    match info.code.as_known() {
        Some(code) => {
            let name = format!("{code:?}");
            name.strip_prefix("ERROR_CODE_").unwrap_or(&name).to_owned()
        }
        None => format!("UNKNOWN_{}", info.code.to_i32()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coarse_codes_map_without_a_detail() {
        let error = Error::from_connect(ConnectError::not_found("gone"), "sandbox.info");
        assert_eq!(error.kind(), ErrorKind::NotFound);
        assert_eq!(error.code(), None);
        assert_eq!(error.operation(), "sandbox.info");
        assert_eq!(error.to_string(), "sandbox.info: gone");
    }

    #[test]
    fn registry_detail_beats_the_coarse_code() {
        let info = pb::ErrorInfo {
            code: pb::ErrorCode::SandboxNotFound.into(),
            suggestion: "list sandboxes with `abctl sandbox list`".into(),
            context: std::iter::once(("id".to_owned(), "sb-1".to_owned())).collect(),
            ..Default::default()
        };
        let detail = connectrpc::ErrorDetail::from_message("arcbox.sandbox.v1.ErrorInfo", &info);
        let mut wire = ConnectError::not_found("sandbox sb-1 not found");
        wire.details.push(detail);

        let error = Error::from_connect(wire, "sandbox.info");
        assert_eq!(error.kind(), ErrorKind::SandboxNotFound);
        assert_eq!(error.code(), Some("SANDBOX_NOT_FOUND"));
        assert_eq!(
            error.suggestion(),
            Some("list sandboxes with `abctl sandbox list`")
        );
        assert_eq!(error.context().get("id").map(String::as_str), Some("sb-1"));
    }

    #[test]
    fn unknown_registry_codes_fall_back_to_the_coarse_class() {
        let info = pb::ErrorInfo {
            code: pb::ErrorCode::Unspecified.into(),
            ..Default::default()
        };
        let detail = connectrpc::ErrorDetail::from_message("arcbox.sandbox.v1.ErrorInfo", &info);
        let mut wire = ConnectError::unavailable("starting up");
        wire.details.push(detail);

        let error = Error::from_connect(wire, "sandbox.create");
        assert_eq!(error.kind(), ErrorKind::Unavailable);
    }
}
