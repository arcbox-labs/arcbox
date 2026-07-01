//! Local control-plane API: a Unix-socket gRPC server
//! (`~/.arcbox/fleet/agent.sock`) that turns the agent's enrollment from a
//! fixed, credential-required-at-startup process into a state machine the
//! `arcbox-fleet-agent` CLI and the desktop app can drive — enroll, drain,
//! resume, disconnect — while it runs. See [`lifecycle`] for the tonic
//! service implementation.

pub mod client;
mod lifecycle;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arcbox_fleet_control_proto::v1::ConnectionState;
use arcbox_fleet_control_proto::v1::fleet_lifecycle_service_server::FleetLifecycleServiceServer;
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
use crate::{attach, enroll};
use lifecycle::LifecycleService;

/// Bind `agent.sock` and serve `FleetLifecycleService` until `shutdown`
/// fires. Mirrors `arcbox-daemon`'s `services::start_grpc` (remove-before-bind,
/// then `UnixListener`/`UnixListenerStream`), plus an explicit owner-only
/// permission: unlike the daemon's socket, this one can enroll/disconnect
/// the machine, so it must not rely on umask alone.
pub async fn serve(
    socket_path: &Path,
    supervisor: Arc<AgentSupervisor>,
    shutdown: CancellationToken,
) -> Result<()> {
    let _ = std::fs::remove_file(socket_path);
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("binding control socket at {}", socket_path.display()))?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", socket_path.display()))?;
    let incoming = UnixListenerStream::new(listener);

    info!(socket = %socket_path.display(), "control-plane server listening");

    Server::builder()
        .add_service(FleetLifecycleServiceServer::new(LifecycleService::new(
            supervisor,
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

/// A live attachment to the gateway: the credential it authenticated with,
/// the admission authority in `admit()`, and the handle to stop it.
struct Attachment {
    credential: Credential,
    supervisor: RunnerSupervisor,
    /// Child of [`AgentSupervisor::process_shutdown`]: cancelling it stops
    /// only this attachment (`Disconnect`); cancelling the parent (process
    /// shutdown) cascades to it too, so runners still drain on SIGTERM.
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<Result<()>>,
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
    credential_store: CredentialStore,
    /// Cancelled on process shutdown (SIGTERM/Ctrl-C); every attachment's
    /// `shutdown` is a child of this token.
    process_shutdown: CancellationToken,
    state: Mutex<State>,
}

impl AgentSupervisor {
    /// Build the supervisor, immediately attaching if a credential is
    /// already persisted — the existing headless/farm behavior.
    pub async fn new(
        config: AgentConfig,
        docker: Option<DockerRunner>,
        capabilities: Vec<Capability>,
        credential_store: CredentialStore,
        process_shutdown: CancellationToken,
    ) -> Result<Self> {
        let existing = credential_store.load()?;
        let this = Self {
            config,
            docker,
            capabilities,
            credential_store,
            process_shutdown,
            state: Mutex::new(State::Unenrolled),
        };
        if let Some(credential) = existing {
            info!(machine_id = %credential.machine_id, "starting fleet agent (credential on disk)");
            *this.state.lock().await = State::Attached(this.attach(credential));
        }
        Ok(this)
    }

    /// Spawn the attach task for `credential` and build its [`Attachment`].
    fn attach(&self, credential: Credential) -> Attachment {
        let (supervisor, egress_rx) =
            attach::spawn_supervisor(&self.config, self.docker.clone(), self.capabilities.clone());
        let shutdown = self.process_shutdown.child_token();
        let task = tokio::spawn(attach::run(
            self.config.clone(),
            credential.clone(),
            supervisor.clone(),
            egress_rx,
            self.capabilities.clone(),
            shutdown.clone(),
        ));
        Attachment {
            credential,
            supervisor,
            shutdown,
            task,
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
        // The gateway round-trip must not hold `state` locked.
        let credential = enroll::enroll(
            &self.config,
            token,
            self.capabilities.clone(),
            control_plane,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        let mut state = self.state.lock().await;
        if matches!(*state, State::Attached(_)) {
            // Lost a race with a concurrent Enroll; the credential just
            // fetched is simply discarded rather than clobbering the winner.
            return Err(Status::failed_precondition(
                "already enrolled — disconnect first",
            ));
        }
        let machine_id = credential.machine_id.clone();
        *state = State::Attached(self.attach(credential));
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

        attachment.shutdown.cancel();
        match tokio::time::timeout(DISCONNECT_GRACE, attachment.task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => warn!(error = %e, "attach task exited with an error on disconnect"),
            Ok(Err(e)) => warn!(error = %e, "attach task panicked on disconnect"),
            Err(_) => warn!("disconnect grace elapsed; clearing credential anyway"),
        }
        self.credential_store
            .clear()
            .map_err(|e| Status::internal(e.to_string()))
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

    /// Current lifecycle state and machine id (empty when unenrolled).
    pub async fn status(&self) -> (ConnectionState, String) {
        match &*self.state.lock().await {
            State::Unenrolled => (ConnectionState::Unenrolled, String::new()),
            State::Attached(a) if a.supervisor.is_draining() => {
                (ConnectionState::Draining, a.credential.machine_id.clone())
            }
            State::Attached(a) => (ConnectionState::Enrolled, a.credential.machine_id.clone()),
        }
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
