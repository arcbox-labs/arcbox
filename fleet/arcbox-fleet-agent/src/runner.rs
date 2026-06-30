//! Runner supervision: the agent is the admission authority. On each offer it
//! decides — against live host state — whether to run the job, starts the
//! runner, and answers the gateway with **accept** (the runner started) or
//! **reject** (try another host). It reports no terminal event; the GitHub
//! webhook is the authoritative outcome.
//!
//! Backend is chosen from the agent's own advertised capabilities: Linux jobs a
//! Docker capability serves run in a container (isolation); a `host_runner`
//! capability runs via the pre-installed runner. Capacity is never a number —
//! admission gates on live load and free memory, so a busy host simply rejects
//! and the platform re-offers elsewhere.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arcbox_fleet_proto::v1::{
    AttachRequest, Backend, Capability, HostTelemetry, ProvisionRunner, RunnerAccepted,
    RunnerRejected, attach_request,
};
use dashmap::DashMap;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tracing::{info, warn};

use crate::docker::{DockerRunner, RunSpec};
use crate::host;

/// Give up resending a verdict after this many attempts (~5 min at the
/// attach-loop resend interval), so a verdict whose awakeable no longer exists
/// (job long concluded, workflow retention expired) cannot resend forever.
const VERDICT_MAX_RESENDS: u32 = 30;

/// A verdict sent to the gateway but not yet acknowledged. Held until an
/// `OfferVerdictAck` arrives and resent meanwhile; `attempts` bounds the resends.
struct Outstanding {
    msg: attach_request::Msg,
    attempts: u32,
}

/// Outcome of the admission decision for an incoming offer.
#[derive(Debug, PartialEq, Eq)]
enum Admission {
    /// Run the job via this backend.
    Accept(Backend),
    /// The job is already running here; re-accept idempotently, don't restart.
    Duplicate,
    /// Decline the offer; `reason` is echoed back for debuggability.
    Reject(String),
}

/// Spawns and tracks runner processes, answering each offer with accept/reject.
#[derive(Clone)]
pub struct RunnerSupervisor {
    inner: Arc<Inner>,
}

struct Inner {
    /// Outbound channel to the gateway (offer verdicts).
    events: mpsc::Sender<AttachRequest>,
    /// Verdicts sent but not yet acknowledged by the gateway, keyed by
    /// `offer_token`. Resent until an `OfferVerdictAck` arrives so a gateway
    /// crash-after-read cannot lose the verdict; the gateway resolves the
    /// awakeable idempotently, so resends are safe.
    outstanding: DashMap<String, Outstanding>,
    /// Jobs currently running here — for duplicate detection and release.
    in_flight: DashMap<String, ()>,
    /// Abort handles for in-flight jobs, for `CancelRunner`.
    cancels: DashMap<String, AbortHandle>,
    /// Directory holding the installed runner (`run.sh` / `run.cmd`).
    /// `None` when only Docker-based execution is configured.
    runner_dir: Option<PathBuf>,
    /// Docker runtime for Linux jobs, if available.
    docker: Option<DockerRunner>,
    /// The backend serving each advertised `(os, arch)` — the routing table.
    backends: HashMap<(String, String), Backend>,
    /// Reject an offer when 1-minute load per core exceeds this.
    load_ceiling: f64,
    /// Reject an offer when available memory (MiB) is below this.
    mem_floor_mib: u64,
    /// Set once `Drain` is received; no new jobs are accepted.
    draining: std::sync::atomic::AtomicBool,
}

/// Clears a job's bookkeeping (`in_flight`, `cancels`) when dropped. Held by the
/// runner task so release happens on every exit — normal completion, early
/// return, abort, or panic. Without it a panicking task would leak the job ID in
/// `in_flight` forever, and re-offers would be mis-classified as duplicates and
/// re-accepted with no runner behind them.
struct ReleaseGuard {
    inner: Arc<Inner>,
    job_id: String,
}

impl Drop for ReleaseGuard {
    fn drop(&mut self) {
        self.inner.in_flight.remove(&self.job_id);
        self.inner.cancels.remove(&self.job_id);
    }
}

impl RunnerSupervisor {
    /// Create a supervisor that emits verdicts on `events`. `capabilities` is the
    /// same set advertised to the gateway, so routing and advertisement agree.
    pub fn new(
        events: mpsc::Sender<AttachRequest>,
        runner_dir: Option<PathBuf>,
        docker: Option<DockerRunner>,
        capabilities: Vec<Capability>,
        load_ceiling: f64,
        mem_floor_mib: u64,
    ) -> Self {
        let backends = capabilities
            .into_iter()
            .filter_map(|c| {
                Backend::try_from(c.backed_by)
                    .ok()
                    .map(|b| ((c.os, c.arch), b))
            })
            .collect();
        Self {
            inner: Arc::new(Inner {
                events,
                outstanding: DashMap::new(),
                in_flight: DashMap::new(),
                cancels: DashMap::new(),
                runner_dir,
                docker,
                backends,
                load_ceiling,
                mem_floor_mib,
                draining: std::sync::atomic::AtomicBool::new(false),
            }),
        }
    }

    /// Decide on an offer and answer it. A redelivered offer for a running job
    /// is re-accepted (idempotent, echoing the new token); otherwise it is
    /// accepted (and a runner started) or rejected.
    pub async fn handle_provision(&self, order: ProvisionRunner) {
        let job_id = order.job_id.clone();
        let token = order.offer_token.clone();
        match self.admit(&job_id, &order.os, &order.arch, &host::telemetry()) {
            Admission::Duplicate => {
                // At-least-once delivery: a re-offer of a running job must never
                // start a second runner, but must still resolve this offer.
                info!(job_id, "duplicate offer; re-accepting");
                self.accept(&job_id, &token).await;
            }
            Admission::Reject(reason) => self.reject(&job_id, &token, &reason).await,
            Admission::Accept(backend) => {
                // Reserve synchronously so a follow-up offer sees the job in
                // flight before the spawned task starts the runner.
                self.inner.in_flight.insert(job_id.clone(), ());
                let sup = self.clone();
                let handle = tokio::spawn(async move {
                    // The guard releases the job on any task exit, including a
                    // panic, so the ID never leaks in `in_flight`.
                    let _release = ReleaseGuard {
                        inner: sup.inner.clone(),
                        job_id: order.job_id.clone(),
                    };
                    sup.run_job(order, backend, token).await;
                });
                self.inner.cancels.insert(job_id, handle.abort_handle());
            }
        }
    }

    /// Decide whether to run `job_id`. `Duplicate` takes precedence so a
    /// redelivery is never a fresh runner. Then drain, then capability routing,
    /// then live headroom (load per core and free memory). The check/insert gap
    /// in [`Self::handle_provision`] is safe: the attach loop dispatches offers
    /// one at a time with no `.await` between this check and the reservation.
    fn admit(&self, job_id: &str, os: &str, arch: &str, telemetry: &HostTelemetry) -> Admission {
        if self.inner.in_flight.contains_key(job_id) {
            return Admission::Duplicate;
        }
        if self
            .inner
            .draining
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Admission::Reject("host is draining".to_owned());
        }
        let Some(&backend) = self.inner.backends.get(&(os.to_owned(), arch.to_owned())) else {
            return Admission::Reject(format!("no capability for {os}/{arch}"));
        };
        let load_per_core = if telemetry.cpu_count > 0 {
            telemetry.load_avg_1m / f64::from(telemetry.cpu_count)
        } else {
            telemetry.load_avg_1m
        };
        if load_per_core > self.inner.load_ceiling {
            return Admission::Reject(format!("load too high ({load_per_core:.2}/core)"));
        }
        if telemetry.mem_available_mib < self.inner.mem_floor_mib {
            return Admission::Reject(format!(
                "low memory ({} MiB free)",
                telemetry.mem_available_mib
            ));
        }
        Admission::Accept(backend)
    }

    /// Cancel an in-flight job: aborting the task drops the child (kill-on-drop)
    /// or the container (guard-on-drop).
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
        info!("draining: no new offers will be accepted");
    }

    /// Start the runner for an accepted offer, then accept once it is actually
    /// running. A failure to start rejects instead, so the platform re-offers.
    async fn run_job(&self, order: ProvisionRunner, backend: Backend, token: String) {
        let job_id = order.job_id.clone();
        match backend {
            Backend::Docker => self.run_docker_job(&job_id, &order, &token).await,
            Backend::HostRunner => self.run_host_job(&job_id, &order, &token).await,
            // We never advertise these, so admit() never routes to them; reject
            // defensively rather than panic if one ever slips through.
            Backend::Vm | Backend::Unspecified => {
                self.reject(&job_id, &token, "backend not supported by this agent")
                    .await;
            }
        }
    }

    /// Run a job directly on the host via the pre-installed runner.
    async fn run_host_job(&self, job_id: &str, order: &ProvisionRunner, token: &str) {
        let Some(runner_dir) = &self.inner.runner_dir else {
            self.reject(job_id, token, "no host runner directory configured")
                .await;
            return;
        };

        let mut command = runner_command(runner_dir, &order.encoded_jit_config);
        let mut child = match command.kill_on_drop(true).spawn() {
            Ok(child) => child,
            Err(e) => {
                self.reject(job_id, token, &format!("failed to spawn runner: {e}"))
                    .await;
                return;
            }
        };

        // The runner is running: accept the offer.
        self.accept(job_id, token).await;
        info!(job_id, "runner started (host)");

        match child.wait().await {
            Ok(status) => info!(job_id, success = status.success(), "runner exited"),
            Err(e) => warn!(job_id, error = %e, "waiting on runner failed"),
        }
    }

    /// Run a job inside a Docker container.
    async fn run_docker_job(&self, job_id: &str, order: &ProvisionRunner, token: &str) {
        // Invariant: a Docker-backed capability is only advertised when Docker
        // is present, so admit() routes here only with `docker` set.
        let docker = self
            .inner
            .docker
            .as_ref()
            .expect("docker backend implies a docker runtime");

        let running = match docker
            .start(RunSpec {
                job_id,
                encoded_jit_config: &order.encoded_jit_config,
                arch: &order.arch,
            })
            .await
        {
            Ok(running) => running,
            Err(e) => {
                self.reject(job_id, token, &format!("failed to start container: {e}"))
                    .await;
                return;
            }
        };

        // The container is running: accept the offer.
        self.accept(job_id, token).await;
        info!(job_id, arch = %order.arch, "runner started (docker)");

        match running.wait().await {
            Ok(outcome) => {
                info!(job_id, success = outcome.success, detail = %outcome.detail, "runner exited");
            }
            Err(e) => warn!(job_id, error = %e, "waiting on container failed"),
        }
    }

    /// Accept an offer (the runner has started).
    async fn accept(&self, job_id: &str, token: &str) {
        self.send_verdict(
            token,
            attach_request::Msg::RunnerAccepted(RunnerAccepted {
                job_id: job_id.to_owned(),
                offer_token: token.to_owned(),
            }),
        )
        .await;
    }

    /// Reject an offer with a reason.
    async fn reject(&self, job_id: &str, token: &str, reason: &str) {
        info!(job_id, reason, "offer rejected");
        self.send_verdict(
            token,
            attach_request::Msg::RunnerRejected(RunnerRejected {
                job_id: job_id.to_owned(),
                offer_token: token.to_owned(),
                reason: reason.to_owned(),
            }),
        )
        .await;
    }

    /// Record a verdict as outstanding (resent until acked) and send it once now.
    async fn send_verdict(&self, token: &str, msg: attach_request::Msg) {
        self.inner.outstanding.insert(
            token.to_owned(),
            Outstanding {
                msg: msg.clone(),
                attempts: 0,
            },
        );
        self.send(msg).await;
    }

    /// Stop resending the verdict the gateway just acknowledged.
    pub fn handle_ack(&self, offer_token: &str) {
        self.inner.outstanding.remove(offer_token);
    }

    /// Resend every still-unacked verdict onto the egress queue, bounded by
    /// [`VERDICT_MAX_RESENDS`]. Non-blocking (`try_send`): a full buffer or a
    /// momentarily detached stream just retries on the next tick. Driven by the
    /// attach loop's resend ticker and, implicitly, every reconnect.
    pub fn resend_outstanding(&self) {
        self.inner.outstanding.retain(|token, entry| {
            if entry.attempts >= VERDICT_MAX_RESENDS {
                warn!(offer_token = %token, "giving up on unacknowledged verdict");
                return false;
            }
            entry.attempts += 1;
            // Ignore send errors: outstanding stays, the next tick retries.
            let _ = self.inner.events.try_send(AttachRequest {
                msg: Some(entry.msg.clone()),
            });
            true
        });
    }

    /// Send a verdict, awaiting channel capacity.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn capability(os: &str, arch: &str, backend: Backend) -> Capability {
        Capability {
            os: os.to_owned(),
            arch: arch.to_owned(),
            backed_by: backend as i32,
        }
    }

    fn telemetry(load_avg_1m: f64, mem_available_mib: u64) -> HostTelemetry {
        HostTelemetry {
            load_avg_1m,
            cpu_count: 8,
            mem_total_mib: 16384,
            mem_available_mib,
        }
    }

    fn supervisor(capabilities: Vec<Capability>) -> RunnerSupervisor {
        let (events, _rx) = mpsc::channel(1);
        RunnerSupervisor::new(
            events,
            Some(PathBuf::from("/nonexistent")),
            None,
            capabilities,
            0.9,
            2048,
        )
    }

    // Idle host: plenty of headroom.
    fn idle() -> HostTelemetry {
        telemetry(0.5, 8192)
    }

    #[test]
    fn accepts_when_servable_with_headroom() {
        let sup = supervisor(vec![capability("darwin", "arm64", Backend::HostRunner)]);
        assert_eq!(
            sup.admit("rjob_a", "darwin", "arm64", &idle()),
            Admission::Accept(Backend::HostRunner)
        );
    }

    #[test]
    fn rejects_unservable_os_arch() {
        let sup = supervisor(vec![capability("darwin", "arm64", Backend::HostRunner)]);
        assert!(matches!(
            sup.admit("rjob_a", "linux", "amd64", &idle()),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn duplicate_takes_precedence_over_drain() {
        let sup = supervisor(vec![capability("darwin", "arm64", Backend::HostRunner)]);
        sup.inner.in_flight.insert("rjob_a".to_owned(), ());
        sup.inner
            .draining
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            sup.admit("rjob_a", "darwin", "arm64", &idle()),
            Admission::Duplicate
        );
        // A different job while draining is rejected.
        assert!(matches!(
            sup.admit("rjob_b", "darwin", "arm64", &idle()),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn rejects_when_load_or_memory_over_budget() {
        let sup = supervisor(vec![capability("linux", "amd64", Backend::Docker)]);
        // load 16 over 8 cores = 2.0/core > 0.9 ceiling.
        assert!(matches!(
            sup.admit("rjob_a", "linux", "amd64", &telemetry(16.0, 8192)),
            Admission::Reject(_)
        ));
        // 1 GiB free < 2 GiB floor.
        assert!(matches!(
            sup.admit("rjob_b", "linux", "amd64", &telemetry(0.1, 1024)),
            Admission::Reject(_)
        ));
        // Routes to the docker backend when healthy.
        assert_eq!(
            sup.admit("rjob_c", "linux", "amd64", &idle()),
            Admission::Accept(Backend::Docker)
        );
    }

    fn supervisor_with_rx(capacity: usize) -> (RunnerSupervisor, mpsc::Receiver<AttachRequest>) {
        let (events, rx) = mpsc::channel(capacity);
        let sup = RunnerSupervisor::new(
            events,
            Some(PathBuf::from("/nonexistent")),
            None,
            vec![capability("darwin", "arm64", Backend::HostRunner)],
            0.9,
            2048,
        );
        (sup, rx)
    }

    #[tokio::test]
    async fn verdict_tracked_and_acked() {
        let (sup, mut rx) = supervisor_with_rx(8);
        sup.accept("rjob_a", "tok1").await;
        assert!(sup.inner.outstanding.contains_key("tok1"));
        assert!(matches!(
            rx.try_recv().expect("verdict emitted").msg,
            Some(attach_request::Msg::RunnerAccepted(_))
        ));

        // The ack stops tracking, so a later resend emits nothing for it.
        sup.handle_ack("tok1");
        assert!(!sup.inner.outstanding.contains_key("tok1"));
        sup.resend_outstanding();
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn resend_reemits_unacked_verdict() {
        let (sup, mut rx) = supervisor_with_rx(8);
        sup.reject("rjob_b", "tok2", "busy").await;
        rx.try_recv().expect("initial verdict");

        sup.resend_outstanding();
        match rx.try_recv().expect("resend emitted").msg {
            Some(attach_request::Msg::RunnerRejected(r)) => assert_eq!(r.offer_token, "tok2"),
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[tokio::test]
    async fn resend_gives_up_after_cap() {
        let (sup, _rx) = supervisor_with_rx(256);
        sup.accept("rjob_c", "tok3").await;
        // One resend per attempt up to the cap, then the entry is dropped.
        for _ in 0..=VERDICT_MAX_RESENDS {
            sup.resend_outstanding();
        }
        assert!(!sup.inner.outstanding.contains_key("tok3"));
    }
}
