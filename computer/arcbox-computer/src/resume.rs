//! Transparent resume for paused sandboxes (CORE-21), host half.
//!
//! Data-plane RPCs (executions, files) targeting a PAUSED sandbox resume
//! it before proceeding, so clients see a latency blip instead of an
//! error. The guest signals "paused" with the dedicated wire code 423
//! (`SandboxError::SandboxPaused`); `Inspect`/`List` never resume. The
//! caller-facing opt-out (a request header) lives in the transport
//! adapter — this module receives the already-made decision.
//!
//! Concurrent auto-resumes share one resume by construction: the
//! per-sandbox operation lock serializes them and the guest's Resume is
//! idempotent, so every follower no-ops against the already-resumed
//! sandbox.

use arcbox_connect::sandbox_v1::{InspectSandboxRequest, SandboxState};
use arcbox_connect::v1::SandboxResumeCommand;
use arcbox_engine::EngineError;

use crate::cleanup;
use crate::host::SandboxHost;
use crate::locks::SandboxOperationLocks;

/// Wire code the guest agent answers for a paused sandbox
/// (`SandboxError::SandboxPaused`; see `guest/arcbox-agent/src/error.rs`).
pub const SANDBOX_PAUSED_WIRE_CODE: i32 = 423;

/// Resume reason for an explicit `SandboxService.Resume` call, surfaced
/// verbatim as the RESUMED event's "reason" attribute. The value
/// vocabulary is defined on `SandboxResumeCommand` (`agent.proto`).
pub const REASON_RESUME: &str = "resume";

/// Resume reason for a data-plane transparent resume.
pub const REASON_AUTO_RESUME: &str = "auto_resume";

/// True when this agent error means "the sandbox is paused".
#[must_use]
pub fn is_sandbox_paused(error: &EngineError) -> bool {
    matches!(
        error,
        EngineError::Agent {
            code: SANDBOX_PAUSED_WIRE_CODE,
            ..
        }
    )
}

/// Resume `sandbox_id` on `machine` and re-register its host DNS entry.
///
/// Shared by the explicit `SandboxService.Resume` handler and the
/// data-plane auto-resume; only `reason` differs. Mirrors Create's DNS
/// discipline: the fresh IP is registered only after confirming it still
/// names the live sandbox under the host-state lock.
///
/// # Errors
///
/// Returns the agent's error when the resume fails (or keeps failing past
/// the transient-retry budget).
pub async fn resume<H: SandboxHost>(
    host: &H,
    operations: &SandboxOperationLocks,
    machine: &str,
    sandbox_id: &str,
    reason: &str,
) -> arcbox_engine::Result<()> {
    let _operation = operations.lock(machine, sandbox_id).await;
    let mut agent = host.agent(machine)?;
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
                Err(EngineError::Agent { code: 503, message })
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
                    return Err(error);
                }
            }
        }
    };

    let _host_state = host.lock_host_state().await;
    if let Ok(ip) = resumed.ip_address.parse()
        && cleanup::live_sandbox_matches(host, machine, sandbox_id, ip).await
    {
        host.register_dns(sandbox_id, ip).await;
    }
    Ok(())
}

/// Pre-flight for client-streaming writes.
///
/// `WriteFile` consumes its input stream before the guest's verdict comes
/// back, so a paused sandbox cannot be handled by retrying the call — the
/// bytes are gone. Instead the sandbox's state is checked up front and a
/// paused one is resumed before any chunk is bridged; with `auto_resume`
/// off (the caller opted out) a paused sandbox is refused with the
/// paused wire code instead.
///
/// # Errors
///
/// Returns the agent's error when the inspect or resume fails, or the
/// paused wire error when the sandbox is paused and `auto_resume` is off.
pub async fn ensure_resumed_for_write<H: SandboxHost>(
    host: &H,
    operations: &SandboxOperationLocks,
    machine: &str,
    sandbox_id: &str,
    auto_resume: bool,
) -> arcbox_engine::Result<()> {
    let mut agent = host.agent(machine)?;
    let info = agent
        .sandbox_inspect(InspectSandboxRequest {
            id: sandbox_id.to_owned(),
            ..Default::default()
        })
        .await?;
    // Pausing counts too: the guest serializes on its per-sandbox operation
    // lock, so the resume below simply waits for the pause to finish.
    if matches!(
        info.state.as_known(),
        Some(SandboxState::Paused | SandboxState::Pausing)
    ) {
        if !auto_resume {
            return Err(EngineError::Agent {
                code: SANDBOX_PAUSED_WIRE_CODE,
                message: format!("sandbox '{sandbox_id}' is paused"),
            });
        }
        resume(host, operations, machine, sandbox_id, REASON_AUTO_RESUME).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_paused_wire_code_triggers_auto_resume() {
        assert!(is_sandbox_paused(&EngineError::Agent {
            code: 423,
            message: "sandbox 'box' is paused".into(),
        }));
        for code in [400, 404, 409, 412, 416, 500, 503] {
            assert!(!is_sandbox_paused(&EngineError::Agent {
                code,
                message: "other".into(),
            }));
        }
        assert!(!is_sandbox_paused(&EngineError::Machine(
            "dead vsock".into()
        )));
    }
}
