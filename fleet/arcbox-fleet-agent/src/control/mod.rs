//! Local control-plane API: a Unix-socket gRPC server
//! (`~/.arcbox/fleet/agent.sock`) that turns the agent's enrollment from a
//! fixed, credential-required-at-startup process into a state machine the
//! `arcbox-fleet-agent` CLI and the desktop app can drive — enroll, drain,
//! resume, disconnect — while it runs. See [`lifecycle`] for the tonic
//! service implementation.

pub mod client;
mod image;
mod lifecycle;
mod settings;
mod watch;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arcbox_fleet_control_proto::v1::fleet_image_service_server::FleetImageServiceServer;
use arcbox_fleet_control_proto::v1::fleet_lifecycle_service_server::FleetLifecycleServiceServer;
use arcbox_fleet_control_proto::v1::fleet_settings_service_server::FleetSettingsServiceServer;
use arcbox_fleet_control_proto::v1::fleet_state_service_server::FleetStateServiceServer;
use arcbox_fleet_control_proto::v1::{ConnectionState, Enrollment};
use arcbox_fleet_proto::v1::Capability;
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::Status;
use tonic::transport::Server;
use tracing::{info, warn};

use crate::config::AgentConfig;
use crate::credentials::{Credential, CredentialStore};
use crate::docker::DockerRunner;
use crate::runner::RunnerSupervisor;
use crate::settings::SettingsStore;
use crate::state::AgentState;
use crate::{attach, enroll};
use image::ImageService;
use lifecycle::LifecycleService;
use settings::SettingsService;
use watch::WatchService;

/// Wraps an unexpected internal failure (a disk write, a gateway round-trip,
/// a keychain clear) so `?` converts it to a tonic `Status` via the `From`
/// impl below — the repo's error-conversion convention, where a crate-local
/// type sidesteps the orphan rule that blocks `From<anyhow::Error> for
/// Status`. Everything wrapped here maps to `INTERNAL`; a site needing a
/// different code maps it itself.
struct Internal(anyhow::Error);

impl From<Internal> for Status {
    fn from(e: Internal) -> Self {
        Self::internal(e.0.to_string())
    }
}

/// Bind `agent.sock` and serve `FleetLifecycleService` until `shutdown`
/// fires. Mirrors `arcbox-daemon`'s `services::start_grpc` (remove-before-bind,
/// then `UnixListener`/`UnixListenerStream`), plus explicit owner-only
/// permissions: unlike the daemon's socket, this one can enroll/disconnect
/// the machine, so it must not rely on umask alone. The parent directory
/// (which also holds the credential file) is made `0700` *before* the bind,
/// so the socket is unreachable by other users even during the brief window
/// between `bind` and its own `0600` chmod.
pub async fn serve(
    socket_path: &Path,
    supervisor: Arc<AgentSupervisor>,
    state: AgentState,
    settings_store: SettingsStore,
    shutdown: CancellationToken,
) -> Result<()> {
    let _ = std::fs::remove_file(socket_path);
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        // Unconditional, not just on creation: an existing data dir from an
        // older or umask-lenient run gets the same traversal barrier.
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", parent.display()))?;
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("binding control socket at {}", socket_path.display()))?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", socket_path.display()))?;
    let incoming = UnixListenerStream::new(listener);

    info!(socket = %socket_path.display(), "control-plane server listening");

    let docker = supervisor.docker();
    Server::builder()
        .add_service(FleetLifecycleServiceServer::new(LifecycleService::new(
            supervisor,
        )))
        .add_service(FleetStateServiceServer::new(WatchService::new(
            state.clone(),
        )))
        .add_service(FleetSettingsServiceServer::new(SettingsService::new(
            state.clone(),
            settings_store,
        )))
        .add_service(FleetImageServiceServer::new(ImageService::new(
            state, docker,
        )))
        .serve_with_incoming_shutdown(incoming, shutdown.cancelled())
        .await
        .context("control-plane server error")
}

/// How long [`AgentSupervisor::disconnect`] waits for the attach task to
/// react to cancellation before clearing the credential anyway. The task's
/// own runner teardown is separately bounded by `attach::run`'s
/// `SHUTDOWN_GRACE`; this only needs to cover that plus scheduling overhead.
const DISCONNECT_GRACE: Duration = Duration::from_secs(20);

/// Wait up to `grace` for `task` to finish on its own; if it doesn't, abort
/// it and wait for that reap too, so `task` is guaranteed stopped by the
/// time this returns regardless of whether it ever observed its own
/// cancellation signal. Split out from [`AgentSupervisor::disconnect`] so
/// the abort-on-timeout behavior can be exercised directly with a short
/// `grace`, instead of the real [`DISCONNECT_GRACE`].
///
/// Polls `&mut task` rather than the owned handle so it survives a timeout:
/// `tokio::time::timeout` drops its future on `Elapsed`, and dropping a
/// `JoinHandle` does not abort the task — losing the handle here would leave
/// it running detached, still holding the old in-memory credential, with
/// nothing to stop a concurrent `Enroll` from starting a second live
/// attachment.
async fn join_or_abort(mut task: tokio::task::JoinHandle<Result<()>>, grace: Duration) {
    match tokio::time::timeout(grace, &mut task).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => warn!(error = %e, "attach task exited with an error on disconnect"),
        Ok(Err(e)) => warn!(error = %e, "attach task panicked on disconnect"),
        Err(_) => {
            warn!("disconnect grace elapsed; aborting attach task");
            task.abort();
            // Best-effort reap; a `Cancelled` JoinError here is expected.
            let _ = task.await;
        }
    }
}

/// A live attachment to the gateway: the admission authority in `admit()`
/// and the handle to stop it. The credential itself isn't retained here —
/// nothing reads it back once attaching starts; `machine_id` observability
/// goes through [`AgentState`] instead.
struct Attachment {
    supervisor: RunnerSupervisor,
    /// Child of [`AgentSupervisor::process_shutdown`]: cancelling it stops
    /// only this attachment (`Disconnect`); cancelling the parent (process
    /// shutdown) cascades to it too, so runners still drain on SIGTERM.
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<Result<()>>,
    /// The gateway this attachment's credential is persisted under (the
    /// keychain backend keys its entry by gateway URI). `disconnect` clears
    /// exactly this store: reading the live `gateway_target` there instead
    /// would clear the wrong entry if a settings update moved the target
    /// while attached, leaving this credential behind on disk.
    credential_gateway: String,
}

enum State {
    Unenrolled,
    Attached(Attachment),
}

/// Owns the agent's enrollment state machine.
///
/// `Run` no longer requires a credential up front: with none on disk the
/// agent starts `Unenrolled` and idles until `Enroll` delivers one — the
/// desktop-managed handoff (RUN-8) — while the CLI's one-shot `enroll`
/// subcommand still works entirely offline, before this process even starts.
pub struct AgentSupervisor {
    config: AgentConfig,
    docker: Option<DockerRunner>,
    capabilities: Vec<Capability>,
    /// Cancelled on process shutdown (SIGTERM/Ctrl-C); every attachment's
    /// `shutdown` is a child of this token.
    process_shutdown: CancellationToken,
    state: Mutex<State>,
    /// Observable state mirrored to `FleetStateService.Watch` subscribers —
    /// the single source of truth `status()` reads from below, so it never
    /// disagrees with what a `Watch` subscriber sees.
    agent_state: AgentState,
    /// Persists an `Enroll`-provided gateway override the same way
    /// `FleetSettingsService.UpdateSettings` persists any other setting.
    settings_store: SettingsStore,
}

impl AgentSupervisor {
    /// Build the supervisor, immediately attaching if a credential is
    /// already persisted — the existing headless/farm behavior.
    pub async fn new(
        config: AgentConfig,
        docker: Option<DockerRunner>,
        capabilities: Vec<Capability>,
        process_shutdown: CancellationToken,
        agent_state: AgentState,
        settings_store: SettingsStore,
    ) -> Result<Self> {
        let this = Self {
            config,
            docker,
            capabilities,
            process_shutdown,
            state: Mutex::new(State::Unenrolled),
            agent_state,
            settings_store,
        };
        let gateway = this.agent_state.gateway_target();
        let existing = this.credential_store_for(&gateway).load()?;
        if let Some(credential) = existing {
            info!(machine_id = %credential.machine_id, "starting fleet agent (credential on disk)");
            *this.state.lock().await = State::Attached(this.attach(credential, gateway));
        }
        Ok(this)
    }

    /// The credential store scoped to `gateway`. Built per operation rather
    /// than held: the keychain backend keys its entry by gateway URI, and the
    /// effective gateway can change over this supervisor's lifetime (an
    /// `Enroll` `control_plane` override, or a settings update), so a store
    /// captured at startup could read or clear the wrong entry.
    fn credential_store_for(&self, gateway: &str) -> CredentialStore {
        CredentialStore::new(
            self.config.credential_store,
            self.config.credentials_path(),
            gateway,
        )
    }

    /// A handle to the process-lifetime Docker runtime, if configured — read
    /// by [`serve`] and passed to `FleetImageService` to prepare a candidate
    /// `linux_runner_image` (see `control::image`). Fixed at construction
    /// and unaffected by the attach/detach cycle: `docker_mode` changes are
    /// restart-scoped, so this is never stale.
    fn docker(&self) -> Option<DockerRunner> {
        self.docker.clone()
    }

    /// Spawn the attach task for `credential` and build its [`Attachment`].
    /// `credential_gateway` is the store key the credential is persisted
    /// under (see [`Attachment::credential_gateway`]).
    fn attach(&self, credential: Credential, credential_gateway: String) -> Attachment {
        self.agent_state
            .set_enrollment(Enrollment::Attaching, &credential.machine_id);
        // A fresh attachment always starts accepting: `Drain` is runtime-only
        // (never persisted), and the previous attachment's teardown shares this
        // process-lifetime state, so clear any stale draining flag rather than
        // letting a re-enroll inherit it.
        self.agent_state.set_draining(false);
        let (supervisor, egress_rx) = attach::spawn_supervisor(
            &self.config,
            self.docker.clone(),
            self.capabilities.clone(),
            self.agent_state.clone(),
        );
        let shutdown = self.process_shutdown.child_token();
        let task = tokio::spawn(attach::run(
            self.config.clone(),
            credential,
            supervisor.clone(),
            egress_rx,
            self.capabilities.clone(),
            shutdown.clone(),
            self.agent_state.clone(),
        ));
        Attachment {
            supervisor,
            shutdown,
            task,
            credential_gateway,
        }
    }

    /// Exchange `token` for a machine credential and start attaching.
    /// `control_plane` overrides the configured gateway for this enrollment.
    pub async fn enroll(
        &self,
        token: String,
        control_plane: Option<&str>,
    ) -> Result<String, Status> {
        if matches!(*self.state.lock().await, State::Attached(_)) {
            return Err(Status::failed_precondition(
                "already enrolled — disconnect first",
            ));
        }

        // Resolve the gateway to dial without mutating shared state yet: a
        // concurrent Enroll may still win the race check below, and a losing
        // attempt must not leave its gateway override applied or persisted.
        let gateway =
            control_plane.map_or_else(|| self.agent_state.gateway_target(), str::to_owned);

        // The gateway round-trip must not hold `state` locked.
        let credential = enroll::enroll(&self.config, token, self.capabilities.clone(), &gateway)
            .await
            .map_err(Internal)?;

        let mut state = self.state.lock().await;
        if matches!(*state, State::Attached(_)) {
            // Lost a race with a concurrent Enroll. The credential just fetched
            // is dropped here without ever being persisted — only the winner,
            // below, writes to the credential store — so it cannot clobber the
            // winner's persisted credential.
            return Err(Status::failed_precondition(
                "already enrolled — disconnect first",
            ));
        }

        // Won the race. Persist the credential now, and only now: a losing
        // concurrent Enroll returned above without writing, so what lands on
        // disk always matches the attachment started just below — a later
        // restart reattaches as the same machine. Scoped to the gateway just
        // enrolled against, which the settings write below makes the target,
        // so the restart load finds it under the same key.
        self.credential_store_for(&gateway)
            .store(&credential)
            .map_err(Internal)?;

        // Persist an explicit gateway override the same way
        // `FleetSettingsService.UpdateSettings` persists any other setting.
        // `attach()` below dials `gateway_target`, so both `current` and
        // `target` already agree with what happens next.
        if let Some(control_plane) = control_plane {
            self.agent_state.set_gateway_target(control_plane);
            self.agent_state.set_gateway_current(control_plane);
            self.settings_store
                .store(&self.agent_state.persisted_settings())
                .map_err(Internal)?;
        }

        let machine_id = credential.machine_id.clone();
        *state = State::Attached(self.attach(credential, gateway));
        Ok(machine_id)
    }

    /// Stop attaching and remove the persisted credential. Returns to
    /// `Unenrolled` immediately (concurrent `GetStatus`/`Drain`/`Resume`
    /// observe that right away); the attach task's own teardown finishes in
    /// the background, bounded by [`DISCONNECT_GRACE`].
    pub async fn disconnect(&self) -> Result<(), Status> {
        let attachment = {
            let mut state = self.state.lock().await;
            if matches!(*state, State::Unenrolled) {
                return Err(Status::failed_precondition("not enrolled"));
            }
            let State::Attached(attachment) = std::mem::replace(&mut *state, State::Unenrolled)
            else {
                unreachable!("checked above");
            };
            attachment
        };
        // Immediate observability: `GetStatus`/`Watch` read only `agent_state`,
        // not the `Mutex<State>` swapped above, so without this a concurrent
        // caller would see stale state for the whole grace window below.
        // Re-asserted after the task is provably stopped, since a reconnect
        // attempt that straddles this cancel could otherwise briefly clobber
        // it (mitigated, not fully eliminated, by `connect_and_serve`'s own
        // cancellation race).
        self.agent_state.set_enrollment(Enrollment::Unenrolled, "");

        attachment.shutdown.cancel();
        join_or_abort(attachment.task, DISCONNECT_GRACE).await;
        // Authoritative: the task is now provably stopped (joined or
        // aborted), so this can no longer be raced.
        self.agent_state.set_enrollment(Enrollment::Unenrolled, "");

        // Keyed by the gateway this attachment enrolled against, not the
        // live `gateway_target`, which a settings update may have moved
        // while attached (see `Attachment::credential_gateway`).
        Ok(self
            .credential_store_for(&attachment.credential_gateway)
            .clear()
            .map_err(Internal)?)
    }

    /// Stop accepting new offers; in-flight jobs finish normally.
    pub async fn drain(&self) -> Result<(), Status> {
        match &*self.state.lock().await {
            State::Attached(a) => {
                a.supervisor.handle_drain();
                Ok(())
            }
            State::Unenrolled => Err(Status::failed_precondition("not enrolled")),
        }
    }

    /// Resume accepting new offers after [`Self::drain`].
    pub async fn resume(&self) -> Result<(), Status> {
        match &*self.state.lock().await {
            State::Attached(a) => {
                a.supervisor.resume();
                Ok(())
            }
            State::Unenrolled => Err(Status::failed_precondition("not enrolled")),
        }
    }

    /// Current lifecycle state and machine id (empty when unenrolled),
    /// derived from [`AgentState`] rather than the resource-holding
    /// `Mutex<State>` above — the two must agree, and `AgentState` is the
    /// one `FleetStateService.Watch` subscribers also read, so there is
    /// exactly one place this can disagree with itself.
    pub async fn status(&self) -> (ConnectionState, String) {
        let snapshot = self.agent_state.current();
        let enrollment =
            Enrollment::try_from(snapshot.enrollment).unwrap_or(Enrollment::Unenrolled);
        let state = match enrollment {
            Enrollment::Unspecified | Enrollment::Unenrolled => ConnectionState::Unenrolled,
            Enrollment::Attaching | Enrollment::Attached if snapshot.draining => {
                ConnectionState::Draining
            }
            Enrollment::Attaching | Enrollment::Attached => ConnectionState::Enrolled,
        };
        (state, snapshot.machine_id)
    }

    /// Await the current attach task's completion, if one is running.
    /// Called once, at process shutdown, after [`serve`] has itself stopped
    /// accepting connections — so the process doesn't exit before runners
    /// get their shutdown grace.
    pub async fn join(&self) {
        let attachment = {
            let mut state = self.state.lock().await;
            match std::mem::replace(&mut *state, State::Unenrolled) {
                State::Attached(a) => Some(a),
                State::Unenrolled => None,
            }
        };
        if let Some(a) = attachment {
            match a.task.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(error = %e, "attach task exited with an error"),
                Err(e) => warn!(error = %e, "attach task panicked"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A task that ignores `shutdown` entirely (never checks it) simulates
    /// the pathological case `join_or_abort`'s abort branch exists for — a
    /// reconnect attempt that never observes cancellation. Without the
    /// abort, this would still be running (and the sender below would
    /// eventually fire) long after `join_or_abort` returns.
    #[tokio::test]
    async fn join_or_abort_stops_a_task_that_ignores_cancellation() {
        let (never_aborted_tx, never_aborted_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let _ = never_aborted_tx.send(());
            Ok(())
        });

        let start = tokio::time::Instant::now();
        join_or_abort(task, Duration::from_millis(50)).await;
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "must abort rather than wait out the task's own 10s sleep"
        );

        // The task was aborted mid-sleep, so its sender was dropped without
        // ever sending — the receiver observes that as an error, not a value.
        assert!(never_aborted_rx.await.is_err());
    }

    /// A task that finishes well within `grace` is joined normally; no abort
    /// needed, and `join_or_abort` doesn't wait out the full grace either.
    #[tokio::test]
    async fn join_or_abort_returns_promptly_for_a_task_that_exits_quickly() {
        let task = tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            Ok(())
        });

        let start = tokio::time::Instant::now();
        join_or_abort(task, Duration::from_secs(20)).await;
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "must return once the task joins, not wait out the full grace"
        );
    }
}
