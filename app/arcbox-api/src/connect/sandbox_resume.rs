//! Daemon-side transparent resume for paused sandboxes (CORE-21).
//!
//! Data-plane RPCs (executions, files) targeting a PAUSED sandbox resume it
//! before proceeding, so clients see a latency blip instead of an error.
//! The guest signals "paused" with the dedicated wire code 423
//! (`SandboxError::SandboxPaused`); callers opt out with the reserved
//! `x-arcbox-no-auto-resume` request header and receive the honest
//! `FAILED_PRECONDITION` carrying the `SANDBOX_PAUSED` `ErrorInfo` detail.
//! `Inspect`/`List` never resume.
//!
//! Concurrent auto-resumes share one resume by construction: the per-sandbox
//! operation lock serializes them and the guest's Resume is idempotent, so
//! every follower no-ops against the already-resumed sandbox.

use std::sync::Arc;

use arcbox_connect::v1::SandboxResumeCommand;
use arcbox_core::{CoreError, Runtime};
use connectrpc::{ConnectError, RequestContext};

use super::sandbox_cleanup;
use super::sandbox_locks::SandboxOperationLocks;
use crate::ApiError;

/// Reserved request header opting out of transparent resume.
pub(super) const NO_AUTO_RESUME_HEADER: &str = "x-arcbox-no-auto-resume";

/// Wire code the guest agent answers for a paused sandbox
/// (`SandboxError::SandboxPaused`; see `guest/arcbox-agent/src/error.rs`).
pub(super) const SANDBOX_PAUSED_WIRE_CODE: i32 = 423;

/// Resume reasons, surfaced verbatim as the RESUMED event's "reason"
/// attribute. The value vocabulary is defined on `SandboxResumeCommand`
/// (`agent.proto`).
pub(super) const REASON_RESUME: &str = "resume";
pub(super) const REASON_AUTO_RESUME: &str = "auto_resume";

/// True when this agent error means "the sandbox is paused".
pub(super) fn is_sandbox_paused(error: &CoreError) -> bool {
    matches!(
        error,
        CoreError::Agent {
            code: SANDBOX_PAUSED_WIRE_CODE,
            ..
        }
    )
}

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

/// Resume `sandbox_id` on `machine` and re-register its host DNS entry.
///
/// Shared by the explicit `SandboxService.Resume` handler and the
/// data-plane auto-resume; only `reason` differs. Mirrors Create's DNS
/// discipline: the fresh IP is registered only after confirming it still
/// names the live sandbox under the host-state lock.
pub(super) async fn resume(
    runtime: &Arc<Runtime>,
    operations: &SandboxOperationLocks,
    machine: &str,
    sandbox_id: &str,
    reason: &str,
) -> Result<(), ConnectError> {
    let _operation = operations.lock(machine, sandbox_id).await;
    let mut agent = runtime
        .get_agent(machine)
        .map_err(|e| ConnectError::from(ApiError::from(e)))?;
    // A resume can race the host finalization of the pause's network
    // quarantine (guest-initiated pauses — the idle detector — publish
    // their cleanup ticket through the async watch stream). The guest
    // answers 503 for that transient, so retry within a bounded budget
    // while the daemon's cleanup watcher completes the ticket; resume is
    // idempotent, and the guest lock is released between attempts.
    let resumed = {
        const RETRY_BUDGET: std::time::Duration = std::time::Duration::from_secs(8);
        const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(250);
        let deadline = tokio::time::Instant::now() + RETRY_BUDGET;
        loop {
            let attempt = agent
                .sandbox_resume(SandboxResumeCommand {
                    id: sandbox_id.to_owned(),
                    reason: reason.to_owned(),
                    ..Default::default()
                })
                .await;
            match attempt {
                Ok(resumed) => break resumed,
                Err(CoreError::Agent { code: 503, message })
                    if tokio::time::Instant::now() < deadline =>
                {
                    tracing::debug!(
                        sandbox_id,
                        message,
                        "sandbox resume hit a retryable condition; retrying"
                    );
                    tokio::time::sleep(RETRY_DELAY).await;
                }
                Err(error) => {
                    // Same reason as create/stop/remove/pause: a failed
                    // lifecycle mutation must reach the daemon log on its own
                    // (CORE-82). It matters more here — an auto-resume has no
                    // caller expecting a Resume RPC, so the failure would
                    // otherwise surface only as the data-plane error.
                    tracing::warn!(machine, sandbox_id, reason, %error, "sandbox resume failed");
                    return Err(ConnectError::from(ApiError::from(error)));
                }
            }
        }
    };

    let _host_state = runtime.lock_sandbox_host_state().await;
    if let Ok(ip) = resumed.ip_address.parse()
        && sandbox_cleanup::live_sandbox_matches(runtime, machine, sandbox_id, ip).await
    {
        runtime.register_sandbox_dns(sandbox_id, ip).await;
    }
    Ok(())
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
    Fut: Future<Output = Result<T, CoreError>>,
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

/// Pre-flight for client-streaming writes.
///
/// `WriteFile` consumes its input stream before the guest's verdict comes
/// back, so a paused sandbox cannot be handled by retrying the call — the
/// bytes are gone. Instead the sandbox's state is checked up front and a
/// paused one is resumed (or refused, honoring the opt-out header) before
/// any chunk is bridged.
pub(super) async fn ensure_resumed_for_write(
    runtime: &Arc<Runtime>,
    operations: &SandboxOperationLocks,
    ctx: &RequestContext,
    machine: &str,
    sandbox_id: &str,
) -> Result<(), ConnectError> {
    use arcbox_connect::sandbox_v1::{InspectSandboxRequest, SandboxState};

    let mut agent = runtime
        .get_agent(machine)
        .map_err(|e| ConnectError::from(ApiError::from(e)))?;
    let info = agent
        .sandbox_inspect(InspectSandboxRequest {
            id: sandbox_id.to_owned(),
            ..Default::default()
        })
        .await
        .map_err(|e| ConnectError::from(ApiError::from(e)))?;
    // Pausing counts too: the guest serializes on its per-sandbox operation
    // lock, so the resume below simply waits for the pause to finish.
    if matches!(
        info.state.as_known(),
        Some(SandboxState::Paused | SandboxState::Pausing)
    ) {
        if auto_resume_opted_out(ctx) {
            return Err(ConnectError::from(ApiError::from(CoreError::Agent {
                code: SANDBOX_PAUSED_WIRE_CODE,
                message: format!("sandbox '{sandbox_id}' is paused"),
            })));
        }
        resume(runtime, operations, machine, sandbox_id, REASON_AUTO_RESUME).await?;
    }
    Ok(())
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
    fn only_the_paused_wire_code_triggers_auto_resume() {
        assert!(is_sandbox_paused(&CoreError::Agent {
            code: 423,
            message: "sandbox 'box' is paused".into(),
        }));
        for code in [400, 404, 409, 412, 416, 500, 503] {
            assert!(!is_sandbox_paused(&CoreError::Agent {
                code,
                message: "other".into(),
            }));
        }
        assert!(!is_sandbox_paused(&CoreError::Machine("dead vsock".into())));
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
