//! Connect adapter for transparent sandbox resume (CORE-21).
//!
//! The resume protocol itself (retry budget, DNS re-registration, paused
//! detection) lives in `arcbox_computer::resume`; this module owns the
//! wire-side halves: the `x-arcbox-no-auto-resume` opt-out header and the
//! `EngineError` → `ConnectError` mapping.

use std::sync::Arc;

use arcbox_core::Runtime;
use arcbox_engine::EngineError;
use connectrpc::{ConnectError, RequestContext};

use crate::ApiError;
use arcbox_computer::locks::SandboxOperationLocks;

pub(super) use arcbox_computer::resume::{REASON_AUTO_RESUME, REASON_RESUME, is_sandbox_paused};

/// Reserved request header opting out of transparent resume.
pub(super) const NO_AUTO_RESUME_HEADER: &str = "x-arcbox-no-auto-resume";

/// True when the caller opted out of transparent resume.
///
/// The documented form is `x-arcbox-no-auto-resume: 1`; any value except an
/// explicit off ("", "0", "false") opts out, so a client that sets the
/// header at all gets the honest state machine.
pub(super) fn auto_resume_opted_out(ctx: &RequestContext) -> bool {
    ctx.header(NO_AUTO_RESUME_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !matches!(value, "" | "0" | "false"))
}

/// Resume `sandbox_id` on `machine`, mapping the protocol error onto the
/// wire. See [`arcbox_computer::resume::resume`].
pub(super) async fn resume(
    runtime: &Arc<Runtime>,
    operations: &SandboxOperationLocks,
    machine: &str,
    sandbox_id: &str,
    reason: &str,
) -> Result<(), ConnectError> {
    arcbox_computer::resume::resume(runtime, operations, machine, sandbox_id, reason)
        .await
        .map_err(|e| ConnectError::from(ApiError::from(e)))
}

/// Run a data-plane call, transparently resuming a paused sandbox once.
///
/// The call is optimistic: nothing is added to the hot path until the guest
/// answers SANDBOX_PAUSED, and then exactly one resume + one retry happen.
pub(super) async fn with_auto_resume<T, F, Fut>(
    runtime: &Arc<Runtime>,
    operations: &SandboxOperationLocks,
    ctx: &RequestContext,
    machine: &str,
    sandbox_id: &str,
    call: F,
) -> Result<T, ConnectError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, EngineError>>,
{
    match call().await {
        Ok(value) => Ok(value),
        Err(error) if is_sandbox_paused(&error) => {
            if auto_resume_opted_out(ctx) {
                return Err(ConnectError::from(ApiError::from(error)));
            }
            resume(runtime, operations, machine, sandbox_id, REASON_AUTO_RESUME).await?;
            call()
                .await
                .map_err(|e| ConnectError::from(ApiError::from(e)))
        }
        Err(error) => Err(ConnectError::from(ApiError::from(error))),
    }
}

/// Pre-flight for client-streaming writes; honors the opt-out header.
/// See [`arcbox_computer::resume::ensure_resumed_for_write`].
pub(super) async fn ensure_resumed_for_write(
    runtime: &Arc<Runtime>,
    operations: &SandboxOperationLocks,
    ctx: &RequestContext,
    machine: &str,
    sandbox_id: &str,
) -> Result<(), ConnectError> {
    arcbox_computer::resume::ensure_resumed_for_write(
        runtime,
        operations,
        machine,
        sandbox_id,
        !auto_resume_opted_out(ctx),
    )
    .await
    .map_err(|e| ConnectError::from(ApiError::from(e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with_header(value: Option<&str>) -> RequestContext {
        let mut headers = http::HeaderMap::new();
        if let Some(value) = value {
            headers.insert(NO_AUTO_RESUME_HEADER, value.parse().unwrap());
        }
        RequestContext::new(headers)
    }

    #[test]
    fn opt_out_header_is_presence_with_explicit_off_values() {
        assert!(!auto_resume_opted_out(&ctx_with_header(None)));
        assert!(!auto_resume_opted_out(&ctx_with_header(Some(""))));
        assert!(!auto_resume_opted_out(&ctx_with_header(Some("0"))));
        assert!(!auto_resume_opted_out(&ctx_with_header(Some("false"))));
        assert!(auto_resume_opted_out(&ctx_with_header(Some("1"))));
        assert!(auto_resume_opted_out(&ctx_with_header(Some("true"))));
    }
}
