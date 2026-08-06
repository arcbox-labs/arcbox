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
            // Agent-reported errors carry an HTTP-style code over the wire;
            // the raw message classifies further into the error registry.
            ApiError::Core(arcbox_core::CoreError::Agent {
                code,
                message: agent_message,
            }) => {
                let connect_code = match code {
                    400 => ErrorCode::InvalidArgument,
                    404 => ErrorCode::NotFound,
                    409 => ErrorCode::AlreadyExists,
                    412 | 423 => ErrorCode::FailedPrecondition,
                    // Stdin offset gap: resync via GetStdinStatus.
                    416 => ErrorCode::OutOfRange,
                    503 => ErrorCode::Unavailable,
                    _ => ErrorCode::Internal,
                };
                let mut error = Self::new(connect_code, message);
                if let Some(detail) = classify_agent_error(*code, agent_message) {
                    error.details.push(detail);
                }
                return error;
            }
            _ => ErrorCode::Internal,
        };
        Self::new(code, message)
    }
}

/// Map a guest agent error onto the sandbox error registry (CORE-58).
///
/// The wire carries only an HTTP-style code + message, so registry
/// precision comes from the message shapes this same tree produces (the
/// daemon and agent ship from one master state, enforced by the protocol
/// handshake): `VmmError`'s `Display` impls and the guest `SandboxError`
/// constructors. The markers are pinned by the tests below — changing a
/// message shape must update both together.
fn classify_agent_error(code: i32, message: &str) -> Option<connectrpc::ErrorDetail> {
    use arcbox_connect::sandbox_v1 as pb;

    match code {
        // VmmError::NotFound → "VM not found: {id}"; the execution
        // registry names its resource explicitly.
        404 if message.starts_with("execution '") => Some(error_info(
            pb::ErrorCode::ExecutionNotFound,
            "list live executions with `abctl sandbox ps`, or start a new one",
            &[],
        )),
        404 if message.starts_with("VM not found:") => Some(error_info(
            pb::ErrorCode::SandboxNotFound,
            "list sandboxes with `abctl sandbox list`",
            &[],
        )),
        // Guest-side nested-virt probe failure (the daemon's own fail-fast
        // gate attaches this detail directly; this covers agent-originated
        // 412s, e.g. a stale capability view).
        412 if message.contains("nested virtualization") => Some(error_info(
            pb::ErrorCode::NestedVirtUnsupported,
            "check `SandboxService.GetCapabilities` for this host's sandbox support",
            &[],
        )),
        // VmmError::WrongState → "VM '{id}' is in wrong state: expected
        // {expected}, got {actual}". A FAILED sandbox is its own registry
        // code; anything else is "exists but not ready for this call"
        // (still STARTING, or busy RUNNING under the single-execution
        // model).
        412 if message.contains("is in wrong state") => {
            let observed = message.rsplit("got ").next().unwrap_or_default();
            match observed {
                "failed" => Some(error_info(
                    pb::ErrorCode::SandboxFailed,
                    "inspect the sandbox for the failure reason, then remove it",
                    &[("state", observed)],
                )),
                "starting" | "running" | "stopping" | "stopped" | "pausing" => Some(error_info(
                    pb::ErrorCode::SandboxNotReady,
                    "wait for the sandbox to reach READY (watch `Events` or poll `Inspect`)",
                    &[("state", observed)],
                )),
                // Other WrongState shapes (generation races, cleanup
                // tickets) are precondition failures without a precise
                // registry identity.
                _ => None,
            }
        }
        // Guest template parse/resolution rejections name the template.
        400 if message.contains("template") => Some(error_info(
            pb::ErrorCode::TemplateInvalid,
            "use \"\" (built-in), \"docker:<image>\", or a catalog template name",
            &[],
        )),
        // Paused sandbox surfaced without a transparent resume
        // (control-plane call, or the caller opted out), CORE-21.
        423 => Some(error_info(
            pb::ErrorCode::SandboxPaused,
            "resume the sandbox (`abctl sandbox resume <id>`), or retry \
             the data-plane call without `x-arcbox-no-auto-resume`",
            &[],
        )),
        _ => None,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use arcbox_connect::sandbox_v1 as pb;
    use buffa::Message as _;

    fn decode_info(detail: &connectrpc::ErrorDetail) -> pb::ErrorInfo {
        use base64::Engine as _;
        assert_eq!(detail.type_url, "arcbox.sandbox.v1.ErrorInfo");
        let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(detail.value.as_deref().expect("detail value"))
            .expect("base64 detail value");
        pb::ErrorInfo::decode_from_slice(&bytes).expect("valid ErrorInfo payload")
    }

    fn registry_code(detail: &connectrpc::ErrorDetail) -> pb::ErrorCode {
        decode_info(detail)
            .code
            .as_known()
            .expect("known registry code")
    }

    fn classified(code: i32, message: &str) -> Option<pb::ErrorCode> {
        classify_agent_error(code, message).map(|detail| registry_code(&detail))
    }

    /// Pins the guest message markers the classifier keys on. If one of
    /// these fails after a message change, update the marker AND this test
    /// together (`VmmError` Display impls / guest `SandboxError` sites).
    #[test]
    fn agent_errors_classify_into_the_registry() {
        assert_eq!(
            classified(404, "VM not found: box1"),
            Some(pb::ErrorCode::SandboxNotFound)
        );
        assert_eq!(
            classified(404, "execution 'e1' in sandbox 'box1'"),
            Some(pb::ErrorCode::ExecutionNotFound)
        );
        assert_eq!(
            classified(423, "sandbox 'box1' is paused"),
            Some(pb::ErrorCode::SandboxPaused)
        );
        assert_eq!(
            classified(
                412,
                "VM 'box1' is in wrong state: expected Ready, got running"
            ),
            Some(pb::ErrorCode::SandboxNotReady)
        );
        assert_eq!(
            classified(
                412,
                "VM 'box1' is in wrong state: expected Ready, got failed"
            ),
            Some(pb::ErrorCode::SandboxFailed)
        );
        assert_eq!(
            classified(
                412,
                "sandboxes require nested virtualization (/dev/kvm is missing in the guest)"
            ),
            Some(pb::ErrorCode::NestedVirtUnsupported)
        );
        assert_eq!(
            classified(
                400,
                "unknown template \"typo\"; expected \"\" or \"docker:<image>\""
            ),
            Some(pb::ErrorCode::TemplateInvalid)
        );
    }

    #[test]
    fn unmatched_agent_errors_carry_no_registry_detail() {
        assert_eq!(classified(500, "vsock error: boom"), None);
        assert_eq!(classified(404, "snapshot abc not found"), None);
        // Generation races are precondition failures without a precise
        // registry identity.
        assert_eq!(
            classified(
                412,
                "VM 'box1' is in wrong state: expected the sandbox generation selected by \
                 this operation, got a newer generation now owns this sandbox ID"
            ),
            None
        );
    }

    #[test]
    fn wrong_state_context_carries_the_observed_state() {
        let detail = classify_agent_error(
            412,
            "VM 'box1' is in wrong state: expected Ready, got running",
        )
        .expect("classified");
        let info = decode_info(&detail);
        assert_eq!(
            info.context.get("state").map(String::as_str),
            Some("running")
        );
    }

    #[test]
    fn paused_agent_error_maps_to_failed_precondition_with_detail() {
        let error = connectrpc::ConnectError::from(ApiError::Core(arcbox_core::CoreError::Agent {
            code: 423,
            message: "sandbox 'box1' is paused".into(),
        }));
        assert_eq!(error.code, connectrpc::ErrorCode::FailedPrecondition);
        assert_eq!(error.details.len(), 1);
        assert_eq!(
            registry_code(&error.details[0]),
            pb::ErrorCode::SandboxPaused
        );
    }
}
