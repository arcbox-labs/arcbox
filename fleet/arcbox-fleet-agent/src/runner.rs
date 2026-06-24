//! Runner supervision: start a runner per `ProvisionRunner`, track in-flight
//! jobs per `(os, arch)` capacity pool, and report terminal state back over the
//! stream.
//!
//! Linux jobs run inside a Docker container for isolation (using
//! `ProvisionRunner.image`); all other jobs run directly on the host via the
//! pre-installed runner. Admission gates each pool against the cap the agent
//! advertised for it, so the gateway's per-pool reservations and the agent's
//! local capacity never disagree.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arcbox_fleet_proto::v1::{
    AttachRequest, ProvisionRunner, RunnerAccepted, RunnerFailed, RunnerFinished, RunnerStarted,
    RuntimeCapacity, attach_request,
};
use command_group::AsyncCommandGroup;
use dashmap::DashMap;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::docker::{DockerRunner, RunSpec};

/// An `(os, arch)` capacity pool, mirroring the gateway's reservation key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Pool {
    os: String,
    arch: String,
}

/// Outcome of the admission check for an incoming `ProvisionRunner`.
#[derive(Debug, PartialEq, Eq)]
enum Admission {
    /// Accept the job and start a runner.
    Accept,
    /// The job is already in flight; ignore the redelivered order.
    Duplicate,
    /// The host is draining and rejects new work.
    Draining,
    /// The job's `(os, arch)` pool is at its concurrency cap.
    AtCapacity,
    /// No advertised pool serves the job's `(os, arch)`.
    Unservable,
}

/// Spawns and tracks runner processes, emitting lifecycle events to the gateway.
#[derive(Clone)]
pub struct RunnerSupervisor {
    inner: Arc<Inner>,
}

struct Inner {
    /// Outbound channel to the gateway (runner lifecycle events).
    events: mpsc::Sender<AttachRequest>,
    /// In-flight jobs mapped to the pool each occupies; drives per-pool capacity.
    in_flight: DashMap<String, Pool>,
    /// Cancel signals for in-flight jobs. Firing one makes the job's `run_job`
    /// kill the runner's whole process group; see [`RunnerSupervisor::handle_cancel`].
    cancels: DashMap<String, oneshot::Sender<()>>,
    /// Directory holding the installed runner (`run.sh` / `run.cmd`).
    /// `None` when only Docker-based execution is configured.
    runner_dir: Option<PathBuf>,
    /// Docker runtime for Linux jobs, if available.
    docker: Option<DockerRunner>,
    /// Advertised capacity per `(os, arch)` pool. Admission gates each pool
    /// against its own cap, mirroring the gateway's per-pool reservation.
    pools: HashMap<Pool, i32>,
    /// Set once `Drain` is received; no new jobs are accepted.
    draining: std::sync::atomic::AtomicBool,
}

impl RunnerSupervisor {
    /// Create a supervisor that emits events on `events`. `pools` is the
    /// advertised capacity set — the same list reported to the gateway, so
    /// admission and advertisement can never disagree.
    pub fn new(
        events: mpsc::Sender<AttachRequest>,
        runner_dir: Option<PathBuf>,
        docker: Option<DockerRunner>,
        pools: Vec<RuntimeCapacity>,
    ) -> Self {
        let pools = pools
            .into_iter()
            .map(|c| {
                (
                    Pool {
                        os: c.os,
                        arch: c.arch,
                    },
                    c.max_concurrent,
                )
            })
            .collect();
        Self {
            inner: Arc::new(Inner {
                events,
                in_flight: DashMap::new(),
                cancels: DashMap::new(),
                runner_dir,
                docker,
                pools,
                draining: std::sync::atomic::AtomicBool::new(false),
            }),
        }
    }

    /// Start a runner for `order`. A redelivered order for a job already in
    /// flight is ignored; otherwise the job is rejected if draining or at
    /// capacity.
    pub async fn handle_provision(&self, order: ProvisionRunner) {
        let job_id = order.job_id.clone();
        let pool = Pool {
            os: order.os.clone(),
            arch: order.arch.clone(),
        };

        match self.admit(&job_id, &pool) {
            Admission::Duplicate => {
                // The gateway's dispatch is at-least-once, so a redelivered
                // order for a running job must be a no-op — never a second
                // runner process for the same job.
                info!(job_id, "duplicate provision ignored");
                return;
            }
            Admission::Draining => {
                self.fail(&job_id, "host is draining").await;
                return;
            }
            Admission::AtCapacity => {
                self.fail(&job_id, "host at capacity").await;
                return;
            }
            Admission::Unservable => {
                self.fail(
                    &job_id,
                    &format!("no capacity pool for {}/{}", order.os, order.arch),
                )
                .await;
                return;
            }
            Admission::Accept => {}
        }

        // Reserve the slot synchronously so a follow-up dispatch sees it.
        self.inner.in_flight.insert(job_id.clone(), pool);

        // Cancellation is cooperative: `run_job` owns the runner process group
        // and tears it down on this signal, so `CancelRunner` never orphans the
        // runner's child processes (a task abort would kill only the immediate
        // `run.sh`/`cmd` child, not the runner and job it spawns).
        let (cancel_tx, cancel_rx) = oneshot::channel();
        self.inner.cancels.insert(job_id, cancel_tx);
        let sup = self.clone();
        tokio::spawn(async move { sup.run_job(order, cancel_rx).await });
    }

    /// Decide whether to start a runner for `job_id` in `pool`. `Duplicate`
    /// takes precedence over the host-state checks: a redelivery of an
    /// already-running job is a no-op regardless. Capacity is gated per pool —
    /// each `(os, arch)` against its own advertised cap — so the agent admits
    /// exactly what the gateway reserves. The `contains`/`insert` gap back in
    /// [`Self::handle_provision`] is safe because the attach loop dispatches
    /// orders one at a time, with no `.await` between this check and the
    /// reservation.
    fn admit(&self, job_id: &str, pool: &Pool) -> Admission {
        if self.inner.in_flight.contains_key(job_id) {
            return Admission::Duplicate;
        }
        if self
            .inner
            .draining
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Admission::Draining;
        }
        let Some(&cap) = self.inner.pools.get(pool) else {
            return Admission::Unservable;
        };
        if self.active_in(pool) >= cap.max(0) as usize {
            return Admission::AtCapacity;
        }
        Admission::Accept
    }

    /// Count jobs currently occupying `pool`.
    fn active_in(&self, pool: &Pool) -> usize {
        self.inner
            .in_flight
            .iter()
            .filter(|entry| entry.value() == pool)
            .count()
    }

    /// Cancel an in-flight job. Signals `run_job`, which tears down the runner
    /// (process group for host jobs, container for Docker jobs) and releases the
    /// slot — the slot is dropped there, not here, so local capacity tracks the
    /// real process lifetime.
    pub fn handle_cancel(&self, job_id: &str) {
        if let Some((_, cancel)) = self.inner.cancels.remove(job_id) {
            let _ = cancel.send(());
            warn!(job_id, "runner cancel requested");
        }
    }

    /// Stop accepting new work; in-flight jobs run to completion.
    pub fn handle_drain(&self) {
        self.inner
            .draining
            .store(true, std::sync::atomic::Ordering::Relaxed);
        info!("draining: no new runners will be accepted");
    }

    /// Begin graceful shutdown: stop accepting offers, cancel every in-flight
    /// job (each `run_job` tears down its runner — process group for host jobs,
    /// container for Docker jobs), and wait — bounded by `grace` — for the jobs
    /// to release their slots.
    ///
    /// Terminal events are emitted best-effort: the attach stream may already be
    /// torn down, but the gateway reclaims capacity when it observes the dropped
    /// connection, so a runner that cannot flush its event is not stranded. The
    /// real guarantee here is that no runner process group or container is left
    /// orphaned.
    pub async fn shutdown(&self, grace: Duration) {
        self.handle_drain();
        // `cancels` is a subset of `in_flight`, so firing every cancel signals a
        // teardown for each running job; jobs already mid-cancel keep tearing
        // down and are covered by the wait below.
        let jobs: Vec<String> = self
            .inner
            .cancels
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        for job_id in &jobs {
            self.handle_cancel(job_id);
        }
        if self.inner.in_flight.is_empty() {
            return;
        }
        info!(jobs = jobs.len(), "shutdown: waiting for runners to stop");
        let drained = async {
            while !self.inner.in_flight.is_empty() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        if tokio::time::timeout(grace, drained).await.is_err() {
            warn!(
                remaining = self.inner.in_flight.len(),
                "shutdown grace elapsed; some runners may still be terminating"
            );
        }
    }

    /// Drive one runner job end to end, emitting accept/start/terminal events.
    ///
    /// Linux jobs are routed through Docker when available (for isolation);
    /// all other jobs run directly on the host via the pre-installed runner.
    async fn run_job(&self, order: ProvisionRunner, cancel_rx: oneshot::Receiver<()>) {
        let job_id = order.job_id.clone();
        self.send(attach_request::Msg::RunnerAccepted(RunnerAccepted {
            job_id: job_id.clone(),
        }))
        .await;

        let use_docker = order.os == "linux" && self.inner.docker.is_some();

        if use_docker {
            self.run_docker_job(&job_id, &order, cancel_rx).await;
        } else {
            self.run_host_job(&job_id, &order, cancel_rx).await;
        }
    }

    /// Run a job directly on the host via the pre-installed runner. The runner is
    /// spawned as a process group so cancellation can take down `run.sh` and
    /// every process it spawned, not just the immediate child.
    async fn run_host_job(
        &self,
        job_id: &str,
        order: &ProvisionRunner,
        mut cancel_rx: oneshot::Receiver<()>,
    ) {
        let runner_dir = match &self.inner.runner_dir {
            Some(dir) => dir,
            None => {
                self.fail(job_id, "no host runner directory configured")
                    .await;
                return;
            }
        };

        let mut command = runner_command(runner_dir, &order.encoded_jit_config);
        let mut child = match command.group_spawn() {
            Ok(child) => child,
            Err(e) => {
                self.fail(job_id, &format!("failed to spawn runner: {e}"))
                    .await;
                return;
            }
        };

        self.send(attach_request::Msg::RunnerStarted(RunnerStarted {
            job_id: job_id.to_owned(),
        }))
        .await;
        info!(job_id, "runner started (host)");

        tokio::select! {
            result = child.wait() => match result {
                Ok(status) => {
                    self.send(attach_request::Msg::RunnerFinished(RunnerFinished {
                        job_id: job_id.to_owned(),
                        success: status.success(),
                        detail: format!("exit status: {status}"),
                    }))
                    .await;
                    info!(job_id, success = status.success(), "runner finished");
                    self.release(job_id);
                }
                Err(e) => self.fail(job_id, &format!("waiting on runner: {e}")).await,
            },
            // CancelRunner: SIGKILL the whole process group (run.sh and the
            // runner/job processes it spawned) and reap it, then report terminal.
            _ = &mut cancel_rx => {
                if let Err(e) = child.kill().await {
                    warn!(job_id, error = %e, "killing runner process group failed");
                }
                self.fail(job_id, "canceled by gateway").await;
            }
        }
    }

    /// Run a job inside a Docker container. On cancellation the in-flight
    /// container future is dropped, and its `ContainerGuard` kills and removes
    /// the container.
    async fn run_docker_job(
        &self,
        job_id: &str,
        order: &ProvisionRunner,
        mut cancel_rx: oneshot::Receiver<()>,
    ) {
        let docker = self.inner.docker.as_ref().expect("checked by caller");
        let image = docker.resolve_image(&order.image);

        self.send(attach_request::Msg::RunnerStarted(RunnerStarted {
            job_id: job_id.to_owned(),
        }))
        .await;
        info!(job_id, image, arch = %order.arch, "runner started (docker)");

        let run = docker.run_job(RunSpec {
            job_id,
            image,
            encoded_jit_config: &order.encoded_jit_config,
            arch: &order.arch,
        });
        tokio::select! {
            result = run => match result {
                Ok(outcome) => {
                    self.send(attach_request::Msg::RunnerFinished(RunnerFinished {
                        job_id: job_id.to_owned(),
                        success: outcome.success,
                        detail: outcome.detail.clone(),
                    }))
                    .await;
                    info!(job_id, success = outcome.success, detail = %outcome.detail, "runner finished");
                    self.release(job_id);
                }
                Err(e) => self.fail(job_id, &format!("docker runner: {e}")).await,
            },
            // CancelRunner: dropping `run` drops the container guard, which kills
            // and removes the container.
            _ = &mut cancel_rx => {
                self.fail(job_id, "canceled by gateway").await;
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(os: &str, arch: &str, max: i32) -> RuntimeCapacity {
        RuntimeCapacity {
            os: os.to_owned(),
            arch: arch.to_owned(),
            max_concurrent: max,
        }
    }

    fn pool(os: &str, arch: &str) -> Pool {
        Pool {
            os: os.to_owned(),
            arch: arch.to_owned(),
        }
    }

    fn supervisor(pools: Vec<RuntimeCapacity>) -> RunnerSupervisor {
        let (events, _rx) = mpsc::channel(1);
        RunnerSupervisor::new(events, Some(PathBuf::from("/nonexistent")), None, pools)
    }

    #[test]
    fn admits_until_pool_capacity_then_rejects() {
        let sup = supervisor(vec![cap("darwin", "arm64", 2)]);
        let p = pool("darwin", "arm64");
        assert_eq!(sup.admit("rjob_a", &p), Admission::Accept);

        sup.inner.in_flight.insert("rjob_a".to_string(), p.clone());
        // A redelivery of a running job is a duplicate, never a fresh slot.
        assert_eq!(sup.admit("rjob_a", &p), Admission::Duplicate);
        assert_eq!(sup.admit("rjob_b", &p), Admission::Accept);

        sup.inner.in_flight.insert("rjob_b".to_string(), p.clone());
        assert_eq!(sup.admit("rjob_c", &p), Admission::AtCapacity);
    }

    #[test]
    fn pools_have_independent_capacity() {
        let sup = supervisor(vec![cap("darwin", "arm64", 1), cap("linux", "amd64", 1)]);
        let darwin = pool("darwin", "arm64");
        let linux = pool("linux", "amd64");

        sup.inner
            .in_flight
            .insert("rjob_a".to_string(), darwin.clone());
        // The darwin pool is full...
        assert_eq!(sup.admit("rjob_b", &darwin), Admission::AtCapacity);
        // ...but the linux pool is unaffected.
        assert_eq!(sup.admit("rjob_c", &linux), Admission::Accept);
    }

    #[test]
    fn unadvertised_pool_is_unservable() {
        let sup = supervisor(vec![cap("darwin", "arm64", 2)]);
        assert_eq!(
            sup.admit("rjob_a", &pool("linux", "amd64")),
            Admission::Unservable
        );
    }

    #[test]
    fn duplicate_takes_precedence_over_drain_and_capacity() {
        let sup = supervisor(vec![cap("darwin", "arm64", 1)]);
        let p = pool("darwin", "arm64");
        sup.inner.in_flight.insert("rjob_a".to_string(), p.clone());
        sup.inner
            .draining
            .store(true, std::sync::atomic::Ordering::Relaxed);

        // Already running, host draining and at capacity: still a duplicate.
        assert_eq!(sup.admit("rjob_a", &p), Admission::Duplicate);
        // A different job while draining is rejected for draining.
        assert_eq!(sup.admit("rjob_b", &p), Admission::Draining);
    }

    /// Register an in-flight job with a cancel signal, mirroring what
    /// `handle_provision` sets up before spawning `run_job`.
    fn register_in_flight(sup: &RunnerSupervisor, job_id: &str) -> oneshot::Receiver<()> {
        let (cancel_tx, cancel_rx) = oneshot::channel();
        sup.inner
            .in_flight
            .insert(job_id.to_string(), pool("darwin", "arm64"));
        sup.inner.cancels.insert(job_id.to_string(), cancel_tx);
        cancel_rx
    }

    #[tokio::test]
    async fn shutdown_drains_cancels_and_waits_for_release() {
        let sup = supervisor(vec![cap("darwin", "arm64", 4)]);
        let cancel_rx = register_in_flight(&sup, "rjob_a");

        // Stand in for `run_job`: release the slot once the cancel signal fires.
        let inner = sup.inner.clone();
        tokio::spawn(async move {
            let _ = cancel_rx.await;
            inner.in_flight.remove("rjob_a");
            inner.cancels.remove("rjob_a");
        });

        sup.shutdown(Duration::from_secs(5)).await;

        assert!(
            sup.inner
                .draining
                .load(std::sync::atomic::Ordering::Relaxed)
        );
        assert!(sup.inner.in_flight.is_empty());
    }

    #[tokio::test]
    async fn shutdown_returns_after_grace_when_a_job_will_not_release() {
        let sup = supervisor(vec![cap("darwin", "arm64", 4)]);
        // Hold the receiver so the cancel send succeeds, but never release the
        // slot — shutdown must give up after the grace rather than hang.
        let _cancel_rx = register_in_flight(&sup, "rjob_a");

        sup.shutdown(Duration::from_millis(250)).await;

        assert!(!sup.inner.in_flight.is_empty());
    }
}
