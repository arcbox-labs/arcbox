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
use std::time::Duration;

use arcbox_fleet_control_proto::v1 as control_proto;
use arcbox_fleet_proto::v1::{
    AttachRequest, Backend, Capability, HostTelemetry, ProvisionRunner, RunnerAccepted,
    RunnerRejected, attach_request,
};
use command_group::AsyncCommandGroup;
use dashmap::DashMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::docker::{DockerRunner, RunSpec};
use crate::host;
use crate::state::AgentState;

/// Convert a gateway-advertised capability into its control-plane
/// counterpart. A plain function, not `From`: both `Capability` types are
/// generated in other crates, so Rust's orphan rule blocks implementing a
/// foreign trait (`From`) for two foreign types here.
fn capability_to_control(c: &Capability) -> control_proto::Capability {
    let backed_by = match Backend::try_from(c.backed_by) {
        Ok(Backend::HostRunner) => control_proto::Backend::HostRunner,
        Ok(Backend::Docker) => control_proto::Backend::Docker,
        Ok(Backend::Vm) => control_proto::Backend::Vm,
        Ok(Backend::Unspecified) | Err(_) => control_proto::Backend::Unspecified,
    };
    control_proto::Capability {
        os: c.os.clone(),
        arch: c.arch.clone(),
        backed_by: backed_by as i32,
    }
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
    /// crash-after-read cannot lose the verdict. There is no local expiry: the
    /// gateway acks every settled verdict — durably handed off (resolution is
    /// idempotent, so resends are safe) or provably obsolete — so only a
    /// transiently unreachable gateway leaves an entry here, and resending
    /// through that is exactly the recovery we want. Growth is bounded because
    /// offers originate from the same parked workflows the acks come from.
    outstanding: DashMap<String, attach_request::Msg>,
    /// Jobs currently running here, each with its cancellation token — one map
    /// for duplicate detection, cancel delivery, and release. Cancelling a token
    /// makes the job's `run_job` tear down the runner — the whole process group
    /// (host) or the container (Docker) — awaited, before the entry is released.
    /// The token is level-triggered, so a cancel that lands while the runner is
    /// still starting is observed at the next cancellation point rather than
    /// lost; see [`RunnerSupervisor::handle_cancel`].
    in_flight: DashMap<String, CancellationToken>,
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
    /// Observable state mirrored to `FleetStateService.Watch` subscribers.
    state: AgentState,
}

/// Clears a job's `in_flight` entry when dropped. Held by the runner task so
/// release happens on every exit — normal completion, early return, awaited
/// teardown, or panic. Without it a panicking task would leak the job ID in
/// `in_flight` forever, and re-offers would be mis-classified as duplicates and
/// re-accepted with no runner behind them. Because teardown is awaited inside
/// the task, the entry disappears only once the runner is actually gone —
/// which is what lets [`RunnerSupervisor::shutdown`] poll `in_flight` as its
/// orphan-free condition.
struct ReleaseGuard {
    inner: Arc<Inner>,
    job_id: String,
}

impl Drop for ReleaseGuard {
    fn drop(&mut self) {
        self.inner.in_flight.remove(&self.job_id);
        self.inner.state.remove_in_flight(&self.job_id);
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
        state: AgentState,
    ) -> Self {
        // Static for the attachment's lifetime, so this is set once rather
        // than tracked incrementally alongside `backends` below.
        state.set_capabilities(capabilities.iter().map(capability_to_control).collect());
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
                runner_dir,
                docker,
                backends,
                load_ceiling,
                mem_floor_mib,
                draining: std::sync::atomic::AtomicBool::new(false),
                state,
            }),
        }
    }

    /// Decide on an offer and answer it. A redelivered offer for a job started
    /// here is re-accepted (idempotent, echoing the new token); otherwise it is
    /// accepted (and a runner started) or rejected.
    pub fn handle_provision(&self, order: ProvisionRunner) {
        let job_id = order.job_id.clone();
        let token = order.offer_token.clone();
        // The exact same offer redelivered (a gateway/worker replay before its
        // dispatch was journaled): the verdict is already recorded and the
        // resend loop is delivering it — answering again would only overwrite
        // that pending verdict.
        if self.inner.outstanding.contains_key(&token) {
            info!(job_id, "offer replayed; verdict already pending");
            return;
        }
        match self.admit(&job_id, &order.os, &order.arch, &host::telemetry()) {
            Admission::Duplicate => {
                // At-least-once delivery: a re-offer of a job started here must
                // never start a second runner, but must still resolve this
                // offer — with the new token, since each offer has its own
                // awakeable and the old one is dead.
                info!(job_id, "duplicate offer; re-accepting");
                self.accept(&job_id, &token);
            }
            Admission::Reject(reason) => self.reject(&job_id, &token, &reason),
            Admission::Accept(backend) => {
                // Reserve synchronously so a follow-up offer sees the job in
                // flight before the spawned task starts the runner. The token
                // travels with the entry: cancelling it makes `run_job` tear
                // down the runner — process group (host) or container (Docker),
                // awaited — so `CancelRunner` never orphans the runner's work.
                let cancel = CancellationToken::new();
                self.inner.in_flight.insert(job_id.clone(), cancel.clone());
                self.inner.state.add_in_flight(control_proto::InFlightJob {
                    job_id,
                    os: order.os.clone(),
                    arch: order.arch.clone(),
                });
                let sup = self.clone();
                tokio::spawn(async move {
                    // The guard releases the job on any task exit, including a
                    // panic, so the ID never leaks in `in_flight`.
                    let _release = ReleaseGuard {
                        inner: sup.inner.clone(),
                        job_id: order.job_id.clone(),
                    };
                    sup.run_job(order, backend, token, cancel).await;
                });
            }
        }
    }

    /// Decide whether to run `job_id`. `Duplicate` takes precedence so a
    /// redelivery is never a fresh runner. Then drain, then capability routing,
    /// then live headroom (load per core and free memory). The check/insert gap
    /// in [`Self::handle_provision`] is safe: dispatch is synchronous and the
    /// attach loop delivers offers one at a time.
    fn admit(&self, job_id: &str, os: &str, arch: &str, telemetry: &HostTelemetry) -> Admission {
        // Started here and still settling counts as a duplicate too: a runner
        // can finish (releasing `in_flight`) while its accept is still unacked,
        // and a re-offer of that job must replay "started here" — not admit a
        // fresh runner for a job whose single-use JIT config is already spent.
        if self.inner.in_flight.contains_key(job_id) || self.has_unacked_accept(job_id) {
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

    /// Whether an accepted verdict for `job_id` is still awaiting its ack — the
    /// window between the runner exiting and the gateway settling the accept.
    /// A linear scan: `outstanding` only holds verdicts the gateway hasn't
    /// settled yet, so it is empty in steady state.
    fn has_unacked_accept(&self, job_id: &str) -> bool {
        self.inner.outstanding.iter().any(|entry| {
            matches!(entry.value(), attach_request::Msg::RunnerAccepted(a) if a.job_id == job_id)
        })
    }

    /// Cancel an in-flight job. Signals `run_job`, which tears down the runner —
    /// the whole process group for a host job, or the container for a Docker job
    /// — awaited, then releases the slot via its `ReleaseGuard`, so local state
    /// tracks the real runner lifetime rather than a fire-and-forget abort. The
    /// entry stays until that release: cancellation is a state the job observes,
    /// not an event that can race past it.
    pub fn handle_cancel(&self, job_id: &str) {
        if let Some(entry) = self.inner.in_flight.get(job_id) {
            entry.value().cancel();
            warn!(job_id, "runner cancel requested");
        }
    }

    /// Stop accepting new work; in-flight jobs run to completion.
    pub fn handle_drain(&self) {
        self.inner
            .draining
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.inner.state.set_draining(true);
        info!("draining: no new offers will be accepted");
    }

    /// Resume accepting new work after a local [`Self::handle_drain`]. This
    /// is the local control-plane's `Resume`, distinct from the gateway's
    /// own `Drain` push (e.g. a machine being decommissioned), which this
    /// agent has no way to countermand.
    pub fn resume(&self) {
        self.inner
            .draining
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.inner.state.set_draining(false);
        info!("resumed: accepting new offers");
    }

    /// Begin graceful shutdown: stop accepting offers, cancel every in-flight
    /// job (each `run_job` tears down its runner — process group for host jobs,
    /// container for Docker jobs), and wait — bounded by `grace` — for the jobs
    /// to release their slots. The guarantee is that no runner process group or
    /// container is left orphaned when the agent exits.
    pub async fn shutdown(&self, grace: Duration) {
        self.handle_drain();
        // Cancelling is idempotent, so jobs already mid-cancel just keep
        // tearing down and are covered by the wait below.
        for entry in &self.inner.in_flight {
            entry.value().cancel();
        }
        if self.inner.in_flight.is_empty() {
            return;
        }
        info!(
            jobs = self.inner.in_flight.len(),
            "shutdown: waiting for runners to stop"
        );
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

    /// Start the runner for an accepted offer, then accept once it is actually
    /// running. A failure to start rejects instead, so the platform re-offers.
    async fn run_job(
        &self,
        order: ProvisionRunner,
        backend: Backend,
        token: String,
        cancel: CancellationToken,
    ) {
        let job_id = order.job_id.clone();
        match backend {
            Backend::Docker => self.run_docker_job(&job_id, &order, &token, cancel).await,
            Backend::HostRunner => self.run_host_job(&job_id, &order, &token, cancel).await,
            // We never advertise these, so admit() never routes to them; reject
            // defensively rather than panic if one ever slips through.
            Backend::Vm | Backend::Unspecified => {
                self.reject(&job_id, &token, "backend not supported by this agent");
            }
        }
    }

    /// Run a job directly on the host via the pre-installed runner. The runner is
    /// spawned as a process group so cancellation tears down `run.sh` and every
    /// process it spawned, not just the immediate child.
    async fn run_host_job(
        &self,
        job_id: &str,
        order: &ProvisionRunner,
        token: &str,
        cancel: CancellationToken,
    ) {
        let Some(runner_dir) = &self.inner.runner_dir else {
            self.reject(job_id, token, "no host runner directory configured");
            return;
        };

        let mut command = runner_command(runner_dir, &order.encoded_jit_config);
        let mut child = match command.group_spawn() {
            Ok(child) => child,
            Err(e) => {
                self.reject(job_id, token, &format!("failed to spawn runner: {e}"));
                return;
            }
        };

        // The runner is running: accept the offer.
        self.accept(job_id, token);
        info!(job_id, "runner started (host)");

        tokio::select! {
            result = child.wait() => match result {
                Ok(status) => info!(job_id, success = status.success(), "runner exited"),
                Err(e) => warn!(job_id, error = %e, "waiting on runner failed"),
            },
            // CancelRunner: SIGKILL the whole process group and reap it. The
            // token is level-triggered, so a cancel that fired while the runner
            // was being spawned is observed here immediately.
            () = cancel.cancelled() => {
                if let Err(e) = child.kill().await {
                    warn!(job_id, error = %e, "killing runner process group failed");
                }
                info!(job_id, "runner canceled");
            }
        }
    }

    /// Run a job inside a Docker container. Cancellation is observed at every
    /// stage — during startup (image pull / create / start) and while the
    /// container runs — and the teardown is awaited, so by the time this
    /// returns (releasing `in_flight`) no container is left behind.
    async fn run_docker_job(
        &self,
        job_id: &str,
        order: &ProvisionRunner,
        token: &str,
        cancel: CancellationToken,
    ) {
        // Invariant: a Docker-backed capability is only advertised when Docker
        // is present, so admit() routes here only with `docker` set.
        let docker = self
            .inner
            .docker
            .as_ref()
            .expect("docker backend implies a docker runtime");

        // Startup is cancellation-aware: a slow image pull must not make the
        // agent deaf to CancelRunner and then accept a job the platform has
        // already concluded.
        let started = {
            let start = std::pin::pin!(docker.start(RunSpec {
                job_id,
                encoded_jit_config: &order.encoded_jit_config,
                arch: &order.arch,
            }));
            tokio::select! {
                result = start => Some(result),
                () = cancel.cancelled() => None,
            }
        };
        let running = match started {
            Some(Ok(running)) => running,
            Some(Err(e)) => {
                self.reject(job_id, token, &format!("failed to start container: {e}"));
                return;
            }
            None => {
                // Canceled mid-startup. A cancel follows the job concluding on
                // the platform, so no verdict is owed — its awakeable is
                // abandoned. Dropping `start` stopped the startup; the awaited
                // remove reaches whatever it had created by then (the name is
                // deterministic), so nothing is orphaned.
                docker.remove_job_container(job_id).await;
                info!(job_id, "runner canceled during startup");
                return;
            }
        };

        // The container is running: accept the offer.
        self.accept(job_id, token);
        info!(job_id, arch = %order.arch, "runner started (docker)");

        let exited = {
            let wait = std::pin::pin!(running.wait());
            tokio::select! {
                result = wait => Some(result),
                () = cancel.cancelled() => None,
            }
        };
        match exited {
            Some(Ok(exit_code)) => {
                info!(job_id, exit_code, "runner exited");
                running.remove().await;
            }
            Some(Err(e)) => {
                warn!(job_id, error = %e, "waiting on container failed");
                running.remove().await;
            }
            // CancelRunner: kill and remove the container, awaited, so the
            // in-flight slot outlives the container — never the reverse.
            None => {
                running.cancel().await;
                info!(job_id, "runner canceled");
            }
        }
    }

    /// Accept an offer (the runner has started).
    fn accept(&self, job_id: &str, token: &str) {
        self.inner.state.push_verdict(control_proto::OfferVerdict {
            job_id: job_id.to_owned(),
            accepted: true,
            reason: String::new(),
        });
        self.send_verdict(
            token,
            attach_request::Msg::RunnerAccepted(RunnerAccepted {
                job_id: job_id.to_owned(),
                offer_token: token.to_owned(),
            }),
        );
    }

    /// Reject an offer with a reason.
    fn reject(&self, job_id: &str, token: &str, reason: &str) {
        info!(job_id, reason, "offer rejected");
        self.inner.state.push_verdict(control_proto::OfferVerdict {
            job_id: job_id.to_owned(),
            accepted: false,
            reason: reason.to_owned(),
        });
        self.send_verdict(
            token,
            attach_request::Msg::RunnerRejected(RunnerRejected {
                job_id: job_id.to_owned(),
                offer_token: token.to_owned(),
                reason: reason.to_owned(),
            }),
        );
    }

    /// Record a verdict as outstanding (resent until acked) and try to send it
    /// now. Never blocks: the `outstanding` entry is the source of truth for
    /// delivery, so a full egress buffer just means the resend tick delivers
    /// instead — runner supervision must not stall on verdict transport.
    fn send_verdict(&self, token: &str, msg: attach_request::Msg) {
        self.inner.outstanding.insert(token.to_owned(), msg.clone());
        let _ = self.inner.events.try_send(AttachRequest { msg: Some(msg) });
    }

    /// Stop resending the verdict the gateway just settled (delivered to the
    /// workflow, or found obsolete).
    pub fn handle_ack(&self, offer_token: &str) {
        self.inner.outstanding.remove(offer_token);
    }

    /// Resend every still-unacked verdict onto the egress queue. Non-blocking
    /// (`try_send`): a full buffer or a momentarily detached stream just retries
    /// on the next tick. Driven by the attach loop's resend ticker and,
    /// implicitly, every reconnect.
    pub fn resend_outstanding(&self) {
        for entry in &self.inner.outstanding {
            let _ = self.inner.events.try_send(AttachRequest {
                msg: Some(entry.value().clone()),
            });
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
            AgentState::new(),
        )
    }

    // Idle host: plenty of headroom.
    fn idle() -> HostTelemetry {
        telemetry(0.5, 8192)
    }

    #[test]
    fn constructor_mirrors_capabilities_into_state() {
        let sup = supervisor(vec![capability("darwin", "arm64", Backend::HostRunner)]);
        let caps = sup.inner.state.current().capabilities;
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].os, "darwin");
        assert_eq!(caps[0].arch, "arm64");
        assert_eq!(caps[0].backed_by, control_proto::Backend::HostRunner as i32);
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
        sup.inner
            .in_flight
            .insert("rjob_a".to_owned(), CancellationToken::new());
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
    fn resume_undoes_drain() {
        let sup = supervisor(vec![capability("darwin", "arm64", Backend::HostRunner)]);
        assert!(!sup.inner.state.current().draining);

        sup.handle_drain();
        assert!(sup.inner.state.current().draining);
        assert!(matches!(
            sup.admit("rjob_a", "darwin", "arm64", &idle()),
            Admission::Reject(_)
        ));

        sup.resume();
        assert!(!sup.inner.state.current().draining);
        assert_eq!(
            sup.admit("rjob_a", "darwin", "arm64", &idle()),
            Admission::Accept(Backend::HostRunner)
        );
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
            AgentState::new(),
        );
        (sup, rx)
    }

    #[tokio::test]
    async fn verdict_tracked_and_acked() {
        let (sup, mut rx) = supervisor_with_rx(8);
        sup.accept("rjob_a", "tok1");
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
    async fn accept_and_reject_push_verdicts_into_state() {
        let (sup, _rx) = supervisor_with_rx(8);
        sup.accept("rjob_a", "tok1");
        sup.reject("rjob_b", "tok2", "busy");

        let verdicts = sup.inner.state.current().recent_verdicts;
        assert_eq!(verdicts.len(), 2);
        assert!(verdicts[0].accepted);
        assert!(!verdicts[1].accepted);
        assert_eq!(verdicts[1].reason, "busy");
    }

    #[tokio::test]
    async fn accepted_offer_is_tracked_in_state_in_flight() {
        let (sup, _rx) = supervisor_with_rx(8);
        sup.handle_provision(ProvisionRunner {
            job_id: "rjob_a".to_owned(),
            os: "darwin".to_owned(),
            arch: "arm64".to_owned(),
            encoded_jit_config: String::new(),
            offer_token: "tok1".to_owned(),
        });

        let in_flight = sup.inner.state.current().in_flight;
        assert_eq!(in_flight.len(), 1);
        assert_eq!(in_flight[0].job_id, "rjob_a");
        assert_eq!(in_flight[0].os, "darwin");
        assert_eq!(in_flight[0].arch, "arm64");
    }

    #[test]
    fn release_guard_drop_removes_from_state_in_flight() {
        let sup = supervisor(vec![capability("darwin", "arm64", Backend::HostRunner)]);
        sup.inner.state.add_in_flight(control_proto::InFlightJob {
            job_id: "rjob_a".to_owned(),
            os: "darwin".to_owned(),
            arch: "arm64".to_owned(),
        });
        {
            let _guard = ReleaseGuard {
                inner: sup.inner.clone(),
                job_id: "rjob_a".to_owned(),
            };
        }
        assert!(sup.inner.state.current().in_flight.is_empty());
    }

    #[tokio::test]
    async fn resend_reemits_unacked_verdict_until_acked() {
        let (sup, mut rx) = supervisor_with_rx(8);
        sup.reject("rjob_b", "tok2", "busy");
        rx.try_recv().expect("initial verdict");

        // No local expiry: every tick re-emits until the gateway acks.
        for _ in 0..3 {
            sup.resend_outstanding();
            match rx.try_recv().expect("resend emitted").msg {
                Some(attach_request::Msg::RunnerRejected(r)) => assert_eq!(r.offer_token, "tok2"),
                other => panic!("unexpected message: {other:?}"),
            }
        }
        assert!(sup.inner.outstanding.contains_key("tok2"));
    }

    #[tokio::test]
    async fn replayed_offer_token_is_not_answered_twice() {
        let (sup, mut rx) = supervisor_with_rx(8);
        sup.reject("rjob_a", "tok1", "busy");
        rx.try_recv().expect("initial verdict");

        // The same offer redelivered verbatim: the pending verdict stands and
        // no fresh admission (which might now accept) overwrites it.
        sup.handle_provision(ProvisionRunner {
            job_id: "rjob_a".to_owned(),
            os: "darwin".to_owned(),
            arch: "arm64".to_owned(),
            encoded_jit_config: String::new(),
            offer_token: "tok1".to_owned(),
        });
        assert!(rx.try_recv().is_err());
        assert!(matches!(
            sup.inner.outstanding.get("tok1").map(|e| e.value().clone()),
            Some(attach_request::Msg::RunnerRejected(_))
        ));
        assert!(!sup.inner.in_flight.contains_key("rjob_a"));
    }

    #[tokio::test]
    async fn unacked_accept_makes_a_reoffer_duplicate() {
        let (sup, _rx) = supervisor_with_rx(8);
        // The runner started and exited (no longer in flight), but the accept
        // has not been acked: a re-offer must replay "started here" under its
        // new token, not admit a fresh runner.
        sup.accept("rjob_a", "tok1");
        assert_eq!(
            sup.admit("rjob_a", "darwin", "arm64", &idle()),
            Admission::Duplicate
        );

        // Once the gateway settles the accept, the job is genuinely done here.
        sup.handle_ack("tok1");
        assert_eq!(
            sup.admit("rjob_a", "darwin", "arm64", &idle()),
            Admission::Accept(Backend::HostRunner)
        );
    }

    #[tokio::test]
    async fn verdict_survives_full_egress_buffer() {
        // Capacity 1: the initial send fills the buffer, further sends drop.
        let (sup, mut rx) = supervisor_with_rx(1);
        sup.accept("rjob_a", "tok1");
        sup.accept("rjob_b", "tok2");

        // Both verdicts stay outstanding regardless of delivery; once the
        // buffer drains, the resend tick delivers the one that didn't fit.
        assert!(sup.inner.outstanding.contains_key("tok1"));
        assert!(sup.inner.outstanding.contains_key("tok2"));
        rx.try_recv().expect("first verdict delivered");
        sup.resend_outstanding();
        rx.try_recv().expect("second verdict delivered by resend");
    }

    /// Register an in-flight job with its cancel token, mirroring what
    /// `handle_provision` sets up before spawning `run_job`.
    fn register_in_flight(sup: &RunnerSupervisor, job_id: &str) -> CancellationToken {
        let cancel = CancellationToken::new();
        sup.inner
            .in_flight
            .insert(job_id.to_owned(), cancel.clone());
        cancel
    }

    #[tokio::test]
    async fn cancel_signals_token_and_keeps_entry_until_release() {
        let sup = supervisor(vec![capability("darwin", "arm64", Backend::HostRunner)]);
        let cancel = register_in_flight(&sup, "rjob_a");

        sup.handle_cancel("rjob_a");

        assert!(cancel.is_cancelled());
        // The entry stays until the runner task's ReleaseGuard drops it, so
        // shutdown keeps waiting for the awaited teardown to finish.
        assert!(sup.inner.in_flight.contains_key("rjob_a"));
    }

    #[tokio::test]
    async fn shutdown_drains_cancels_and_waits_for_release() {
        let sup = supervisor(vec![capability("darwin", "arm64", Backend::HostRunner)]);
        let cancel = register_in_flight(&sup, "rjob_a");

        // Stand in for `run_job`: release the slot once the cancel signal fires.
        let inner = sup.inner.clone();
        tokio::spawn(async move {
            cancel.cancelled().await;
            inner.in_flight.remove("rjob_a");
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
        let sup = supervisor(vec![capability("darwin", "arm64", Backend::HostRunner)]);
        // Cancel is signalled but the slot is never released — shutdown must
        // give up after the grace rather than hang.
        let _cancel = register_in_flight(&sup, "rjob_a");

        sup.shutdown(Duration::from_millis(250)).await;

        assert!(!sup.inner.in_flight.is_empty());
    }
}
