//! Capturing a checkpoint, stopping a guest, and the three releases.

use std::time::Duration;

use tracing::info;

use super::ComputerFlows;
use crate::error::VmmError;
use crate::lifecycle::effect::ReleaseScope;
use crate::lifecycle::tasks::checkpoint::{CheckpointFailure, CheckpointRequest, checkpoint_impl};
use crate::lifecycle::tasks::pause::release_for_pause;
use crate::lifecycle::tasks::release::{release_everything, release_runtime_resources};
use crate::lifecycle::tasks::{CaptureSpec, TaskFailure, TaskResult};
use crate::sandbox::pause::PAUSE_SNAPSHOT_NAME;
use crate::sandbox::{CheckpointInfo, SandboxState};

/// How often a stop looks for the workload it is draining to finish.
const DRAIN_POLL: Duration = Duration::from_millis(100);

impl ComputerFlows {
    /// Capture a checkpoint into the catalog.
    ///
    /// `hold` is the pause path: the guest stays quiesced, because progress
    /// past the memory image would diverge from the retained disk overlay.
    /// It is also what names the capture — a pause writes the reserved
    /// internal name, and a user checkpoint brings its own.
    pub(super) async fn capture(
        &self,
        hold: bool,
        spec: Option<CaptureSpec>,
    ) -> TaskResult<CheckpointInfo> {
        let request = match spec {
            Some(spec) => CheckpointRequest {
                name: spec.name,
                labels: spec.labels,
                expected_state: SandboxState::Ready,
                resume_after: !hold,
            },
            None => CheckpointRequest {
                name: PAUSE_SNAPSHOT_NAME.to_owned(),
                labels: std::collections::HashMap::new(),
                expected_state: SandboxState::Pausing,
                resume_after: !hold,
            },
        };
        checkpoint_impl(&self.computer, &self.services.snapshots, &self.id, request)
            .await
            .map_err(|failure| match failure {
                // The port has no verb to thaw a held VM (pause is
                // hold-then-kill by design), so a frozen guest cannot go back
                // to `Ready`; the machine degrades it rather than reporting
                // `Ready` for a guest that answers nothing.
                CheckpointFailure::Frozen(error) => TaskFailure::frozen(error),
                CheckpointFailure::Recoverable(error) => TaskFailure::recoverable(error),
            })
    }

    /// Drain the workload, ask the guest to shut down, and release what it
    /// was running on.
    pub(super) async fn stop_vm(&self, budget: Duration, drain: bool) -> TaskResult {
        let deadline = tokio::time::Instant::now() + budget;
        let (handle, last_exited_at) = {
            let computer = self.computer.lock().unwrap();
            (computer.handle.clone(), computer.last_exited_at)
        };

        // Give an active workload the budget to finish. The exit watcher
        // records `last_exited_at` when the exit chunk arrives, so poll for
        // that signal.
        if drain {
            while tokio::time::Instant::now() < deadline {
                if self.computer.lock().unwrap().last_exited_at != last_exited_at {
                    break;
                }
                tokio::time::sleep(DRAIN_POLL).await;
            }
        }

        // Ask the guest to shut down (Ctrl+Alt+Del reboots it, which the VMM
        // turns into a VM exit) and wait for it within the remaining budget;
        // the driver kills the VMM at the deadline (and reports a reap that
        // timed out — the handle stays on the computer for a retry). A VM
        // that never came up has no handle to ask.
        if let Some(handle) = handle {
            let remaining = deadline
                .checked_duration_since(tokio::time::Instant::now())
                .unwrap_or(Duration::from_secs(1))
                .max(Duration::from_secs(1));
            handle
                .shutdown(arcbox_vm_driver::ShutdownMode::Graceful { timeout: remaining })
                .await
                .map_err(|error| {
                    TaskFailure::recoverable(VmmError::Process(format!(
                        "shut down computer {}: {error}",
                        self.id
                    )))
                })?;
        }

        // Release the VMM (already exited, or never booted), TAP/IP, CoW
        // device, and chroot; the record itself stays inspectable until
        // Remove.
        self.release_scope(ReleaseScope::Runtime).await?;
        info!(sandbox_id = %self.id, "computer stopped");
        Ok(())
    }

    pub(super) async fn release_scope(&self, scope: ReleaseScope) -> TaskResult {
        let services = &self.services;
        let outcome = match scope {
            ReleaseScope::Runtime => {
                release_runtime_resources(
                    &self.id,
                    &self.computer,
                    &services.network,
                    &services.config,
                    &services.cow_manager,
                )
                .await
            }
            ReleaseScope::KeepDisk => match services.config.firecracker.jailer.as_ref() {
                Some(jailer) => {
                    release_for_pause(
                        &self.id,
                        &self.computer,
                        jailer,
                        &services.config,
                        &services.cow_manager,
                        &*services.network,
                    )
                    .await
                }
                // Unreachable: `pause_sandbox` refuses direct mode before it
                // claims anything, because a direct-mode vmstate pins origin
                // paths and could never resume.
                None => Err(VmmError::Config(
                    "computer pause requires jailer isolation; direct mode cannot resume".into(),
                )),
            },
            ReleaseScope::Full => {
                release_everything(
                    &self.id,
                    &self.computer,
                    &services.network,
                    &services.config,
                    &services.cow_manager,
                    &services.snapshots,
                )
                .await
            }
        };
        outcome.map_err(TaskFailure::recoverable)
    }
}
