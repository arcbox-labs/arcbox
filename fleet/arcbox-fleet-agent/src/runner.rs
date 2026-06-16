//! Runner supervision: spawn the GitHub Actions runner per `ProvisionRunner`,
//! track in-flight jobs, and report terminal state back over the stream.
//!
//! v1 has no isolation: the job runs directly on the host. `ProvisionRunner`'s
//! `image`/`cpus`/`mem_mib` describe a sandbox that does not exist yet and are
//! intentionally ignored.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arcbox_fleet_proto::v1::{
    AttachRequest, ProvisionRunner, RunnerAccepted, RunnerFailed, RunnerFinished, RunnerStarted,
    attach_request,
};
use dashmap::{DashMap, DashSet};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tracing::{info, warn};

/// Spawns and tracks runner processes, emitting lifecycle events to the gateway.
#[derive(Clone)]
pub struct RunnerSupervisor {
    inner: Arc<Inner>,
}

struct Inner {
    /// Outbound channel to the gateway (runner lifecycle events).
    events: mpsc::Sender<AttachRequest>,
    /// Job ids currently in flight (drives local capacity).
    in_flight: DashSet<String>,
    /// Abort handles for in-flight jobs, for `CancelRunner`.
    cancels: DashMap<String, AbortHandle>,
    /// Directory holding the installed runner (`run.sh` / `run.cmd`).
    runner_dir: PathBuf,
    /// Local backpressure cap.
    max_concurrent: usize,
    /// Set once `Drain` is received; no new jobs are accepted.
    draining: std::sync::atomic::AtomicBool,
}

impl RunnerSupervisor {
    /// Create a supervisor that emits events on `events`.
    pub fn new(
        events: mpsc::Sender<AttachRequest>,
        runner_dir: PathBuf,
        max_concurrent: usize,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                events,
                in_flight: DashSet::new(),
                cancels: DashMap::new(),
                runner_dir,
                max_concurrent,
                draining: std::sync::atomic::AtomicBool::new(false),
            }),
        }
    }

    /// Start a runner for `order`, unless draining or at capacity.
    pub async fn handle_provision(&self, order: ProvisionRunner) {
        let job_id = order.job_id.clone();

        if self
            .inner
            .draining
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            self.fail(&job_id, "host is draining").await;
            return;
        }
        if self.inner.in_flight.len() >= self.inner.max_concurrent {
            self.fail(&job_id, "host at capacity").await;
            return;
        }

        // Reserve the slot synchronously so a follow-up dispatch sees it.
        self.inner.in_flight.insert(job_id.clone());

        let sup = self.clone();
        let handle = tokio::spawn(async move { sup.run_job(order).await });
        self.inner.cancels.insert(job_id, handle.abort_handle());
    }

    /// Cancel an in-flight job: aborting the task drops the child (kill-on-drop).
    pub fn handle_cancel(&self, job_id: &str) {
        if let Some((_, handle)) = self.inner.cancels.remove(job_id) {
            handle.abort();
            self.inner.in_flight.remove(job_id);
            warn!(job_id, "runner canceled");
        }
    }

    /// Stop accepting new work; in-flight jobs run to completion.
    pub fn handle_drain(&self) {
        self.inner
            .draining
            .store(true, std::sync::atomic::Ordering::Relaxed);
        info!("draining: no new runners will be accepted");
    }

    /// Drive one runner process end to end, emitting accept/start/terminal events.
    async fn run_job(&self, order: ProvisionRunner) {
        let job_id = order.job_id.clone();
        self.send(attach_request::Msg::RunnerAccepted(RunnerAccepted {
            job_id: job_id.clone(),
        }))
        .await;

        let mut command = runner_command(&self.inner.runner_dir, &order.encoded_jit_config);
        let mut child = match command.kill_on_drop(true).spawn() {
            Ok(child) => child,
            Err(e) => {
                self.fail(&job_id, &format!("failed to spawn runner: {e}"))
                    .await;
                return;
            }
        };

        self.send(attach_request::Msg::RunnerStarted(RunnerStarted {
            job_id: job_id.clone(),
        }))
        .await;
        info!(job_id, "runner started");

        match child.wait().await {
            Ok(status) => {
                self.send(attach_request::Msg::RunnerFinished(RunnerFinished {
                    job_id: job_id.clone(),
                    success: status.success(),
                    detail: format!("exit status: {status}"),
                }))
                .await;
                info!(job_id, success = status.success(), "runner finished");
                self.release(&job_id);
            }
            Err(e) => self.fail(&job_id, &format!("waiting on runner: {e}")).await,
        }
    }

    /// Drop bookkeeping for a job, releasing its capacity slot.
    fn release(&self, job_id: &str) {
        self.inner.in_flight.remove(job_id);
        self.inner.cancels.remove(job_id);
    }

    /// Emit a `RunnerFailed` and release the slot.
    async fn fail(&self, job_id: &str, reason: &str) {
        warn!(job_id, reason, "runner failed");
        self.send(attach_request::Msg::RunnerFailed(RunnerFailed {
            job_id: job_id.to_string(),
            reason: reason.to_string(),
        }))
        .await;
        self.release(job_id);
    }

    /// Send a runner event, awaiting channel capacity.
    async fn send(&self, msg: attach_request::Msg) {
        if self
            .inner
            .events
            .send(AttachRequest { msg: Some(msg) })
            .await
            .is_err()
        {
            warn!("event channel closed; gateway stream is reconnecting");
        }
    }
}

/// Build the platform-appropriate runner invocation.
fn runner_command(runner_dir: &Path, encoded_jit_config: &str) -> tokio::process::Command {
    #[cfg(windows)]
    {
        let script = runner_dir.join("run.cmd");
        let mut command = tokio::process::Command::new("cmd");
        command
            .arg("/C")
            .arg(script)
            .arg("--jitconfig")
            .arg(encoded_jit_config);
        command
    }
    #[cfg(not(windows))]
    {
        let script = runner_dir.join("run.sh");
        let mut command = tokio::process::Command::new(script);
        command.arg("--jitconfig").arg(encoded_jit_config);
        command
    }
}
