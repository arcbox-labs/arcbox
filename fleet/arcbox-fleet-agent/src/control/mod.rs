//! Local control-plane API: a Unix-socket gRPC server
//! (`~/.arcbox/fleet/agent.sock`) that turns the agent's enrollment from a
//! fixed, credential-required-at-startup process into a state machine the
//! `arcbox-fleet-agent` CLI and the desktop app can drive — enroll, drain,
//! resume, unenroll — while it runs. See [`lifecycle`] for the tonic
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
use crate::credentials::Credential;
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
/// permissions: unlike the daemon's socket, this one can enroll/unenroll
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

/// How long [`AgentSupervisor::unenroll`] waits for the attach task to
/// react to cancellation before clearing the credential anyway. The task's
/// own runner teardown is separately bounded by `attach::run`'s
/// `SHUTDOWN_GRACE`; this only needs to cover that plus scheduling overhead.
const TEARDOWN_GRACE: Duration = Duration::from_secs(20);

/// Wait up to `grace` for `task` to finish on its own; if it doesn't, abort
/// it and wait for that reap too, so `task` is guaranteed stopped by the
/// time this returns regardless of whether it ever observed its own
/// cancellation signal. Split out from [`AgentSupervisor::unenroll`] so
/// the abort-on-timeout behavior can be exercised directly with a short
/// `grace`, instead of the real [`TEARDOWN_GRACE`].
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
        Ok(Ok(Err(e))) => warn!(error = %e, "attach task exited with an error on unenroll"),
        Ok(Err(e)) => warn!(error = %e, "attach task panicked on unenroll"),
        Err(_) => {
            warn!("unenroll grace elapsed; aborting attach task");
            task.abort();
            // Best-effort reap; a `Cancelled` JoinError here is expected.
            let _ = task.await;
        }
    }
}

/// The `Enroll` admission check: only `Unenrolled` may proceed. Applied
/// once, at the start of [`AgentSupervisor::enroll`] — the transition into
/// [`State::Enrolling`] under the same lock then keeps every concurrent
/// admission out, including a straggling `Unenroll`.
///
/// Returns a plain message rather than `Status` — every failure here maps
/// to the same `FAILED_PRECONDITION` code, so the caller does that one
/// conversion (the same convention as `control::settings::validate`).
fn check_enrollable(state: &State) -> Result<(), &'static str> {
    match state {
        State::Unenrolled => Ok(()),
        State::Enrolling => Err("enroll in progress — retry shortly"),
        State::Unenrolling => Err("unenroll in progress — retry shortly"),
        State::Detaching => Err("detach in progress — retry shortly"),
        State::Detached { .. } => {
            Err("already enrolled — set participate=true to reattach, or unenroll first")
        }
        State::Attached(_) => Err("already enrolled — unenroll first"),
    }
}

/// A live attachment to the gateway: the admission authority in `admit()`
/// and the handle to stop it. Retains a copy of the credential for
/// `unenroll`'s server-side revocation call; `machine_id` observability
/// still goes through [`AgentState`].
struct Attachment {
    supervisor: RunnerSupervisor,
    /// Child of [`AgentSupervisor::process_shutdown`]: cancelling it stops
    /// only this attachment (`Unenroll`); cancelling the parent (process
    /// shutdown) cascades to it too, so runners still drain on SIGTERM.
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<Result<()>>,
    /// The credential this attachment runs with — what `unenroll` presents
    /// to the gateway to decommission the machine.
    credential: Credential,
    /// The gateway this attachment's credential is persisted under (the
    /// keychain backend keys its entry by gateway URI). `unenroll` calls
    /// and clears exactly this store: reading the live `gateway_target`
    /// there instead would clear the wrong entry if a settings update moved
    /// the target while attached, leaving this credential behind on disk.
    credential_gateway: String,
}

enum State {
    Unenrolled,
    /// An `Enroll` is between the initial admission check and either
    /// success (transition to [`State::Attached`]) or failure (rollback to
    /// [`State::Unenrolled`]). Held across the gateway round-trip so
    /// [`check_enrollable`] refuses a concurrent `Enroll`, and mirrored as
    /// observable [`Enrollment::Attaching`] on [`AgentState`] so
    /// `settings::validate` refuses a gateway change during the same
    /// window — without that mirror, a settings write could move the
    /// gateway target under our feet and leave the credential (persisted
    /// under the enrolling gateway's key) unreachable to the next startup.
    Enrolling,
    /// An `Unenroll` is tearing its attachment down (bounded by
    /// [`TEARDOWN_GRACE`]). `Enroll` is refused while here: an enrollment
    /// that raced into the teardown window would have its observable state
    /// stomped by the old task's late writes and by unenroll's own final
    /// `Unenrolled` re-assert, so the window is closed instead of fenced.
    Unenrolling,
    /// The participation reconciler is tearing its attachment down
    /// (`participate` moved to false). Same gating rationale as
    /// [`State::Unenrolling`].
    Detaching,
    /// Enrolled — the credential is kept for reattaching — but deliberately
    /// offline: `participate` is false. The machine shows Offline
    /// server-side.
    Detached {
        credential: Credential,
        /// See [`Attachment::credential_gateway`].
        credential_gateway: String,
    },
    Attached(Attachment),
}

/// Owns the agent's enrollment state machine.
///
/// The `serve` command does not require a credential up front: with none on disk the
/// agent starts `Unenrolled` and idles until `Enroll` delivers one — the
/// desktop-managed handoff (RUN-8) — while the CLI's `quick enroll`
/// subcommand works entirely offline, before this process even starts.
pub struct AgentSupervisor {
    config: AgentConfig,
    docker: Option<DockerRunner>,
    vm: Option<crate::vm::VmRunner>,
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
        vm: Option<crate::vm::VmRunner>,
        capabilities: Vec<Capability>,
        process_shutdown: CancellationToken,
        agent_state: AgentState,
        settings_store: SettingsStore,
    ) -> Result<Self> {
        let this = Self {
            config,
            docker,
            vm,
            capabilities,
            process_shutdown,
            state: Mutex::new(State::Unenrolled),
            agent_state,
            settings_store,
        };
        let gateway = this.agent_state.gateway_target();
        let existing = this.config.credential_store_for(&gateway).load()?;
        if let Some(credential) = existing {
            if this.agent_state.participate_target() {
                info!(machine_id = %credential.machine_id, "starting fleet agent (credential on disk)");
                *this.state.lock().await = State::Attached(this.attach(credential, gateway));
            } else {
                // An operator's detach must survive a launchd restart — a
                // silent reattach here would betray it.
                info!(machine_id = %credential.machine_id, "starting fleet agent detached (participate=false)");
                this.agent_state
                    .set_enrollment(Enrollment::Detached, &credential.machine_id);
                *this.state.lock().await = State::Detached {
                    credential,
                    credential_gateway: gateway,
                };
            }
        }
        Ok(this)
    }

    /// A handle to the process-lifetime Docker runtime, if configured — read
    /// by [`serve`] and passed to `FleetImageService` to prepare a candidate
    /// `linux_runner_image` (see `control::image`). Fixed at construction
    /// and unaffected by the attach/detach cycle: `docker_mode` changes are
    /// restart-scoped, so this is never stale.
    fn docker(&self) -> Option<DockerRunner> {
        self.docker.clone()
    }

    /// Whether the macOS VM backend is active — the daemon probe succeeded
    /// at startup. Reported as a `GetAgentInfo` feature so clients can
    /// discover it. Fixed at construction like [`Self::docker`]:
    /// `vm_mode` changes are restart-scoped.
    pub fn vm_active(&self) -> bool {
        self.vm.is_some()
    }

    /// Spawn the attach task for `credential` and build its [`Attachment`].
    /// `credential_gateway` is the store key the credential is persisted
    /// under (see [`Attachment::credential_gateway`]).
    fn attach(&self, credential: Credential, credential_gateway: String) -> Attachment {
        self.agent_state
            .set_enrollment(Enrollment::Attaching, &credential.machine_id);
        // Attaching realizes participation.
        self.agent_state.set_participate_current(true);
        // A fresh attachment always starts accepting: `Drain` is runtime-only
        // (never persisted), and the previous attachment's teardown shares this
        // process-lifetime state, so clear any stale draining flag rather than
        // letting a re-enroll inherit it.
        self.agent_state.set_draining(false);
        let (supervisor, egress_rx) = attach::spawn_supervisor(
            &self.config,
            self.docker.clone(),
            self.vm.clone(),
            self.capabilities.clone(),
            self.agent_state.clone(),
        );
        let shutdown = self.process_shutdown.child_token();
        let task = tokio::spawn(attach::run(
            self.config.clone(),
            credential.clone(),
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
            credential,
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
        // Enter `Enrolling` under the state lock so `check_enrollable`
        // refuses every concurrent admission for the whole round-trip, and
        // mirror the observable state as `Attaching` on `AgentState` so
        // `settings::validate` refuses a racing gateway change against the
        // same window. Without the observable write here, a settings-time
        // gateway move could land between our target read and the credential
        // persist, splitting the gateway keys of settings.json and the
        // credential store — the next startup would then miss the credential.
        {
            let mut state = self.state.lock().await;
            check_enrollable(&state).map_err(Status::failed_precondition)?;
            *state = State::Enrolling;
            self.agent_state.set_enrollment(Enrollment::Attaching, "");
        }

        // Any early return past this point must roll `Enrolling` back to
        // `Unenrolled` — otherwise the gate stays closed to future enrolls.
        let outcome = self.finish_enroll(token, control_plane).await;
        if outcome.is_err() {
            let mut state = self.state.lock().await;
            // Only roll back the state we own. `attach()` transitions to
            // `Attached` (with a real machine_id in `set_enrollment`), so
            // if we're still `Enrolling`, no one else has advanced the
            // observable state either.
            if matches!(*state, State::Enrolling) {
                *state = State::Unenrolled;
                self.agent_state.set_enrollment(Enrollment::Unenrolled, "");
            }
        }
        outcome
    }

    /// Body of [`Self::enroll`] between entering `State::Enrolling` and
    /// the `Attached` transition. Split out so the caller can roll the
    /// state back on any `?`-early return uniformly, without repeating the
    /// cleanup at every fallible site.
    async fn finish_enroll(
        &self,
        token: String,
        control_plane: Option<&str>,
    ) -> Result<String, Status> {
        // Resolve the gateway to dial. Because `Enrolling` is now held and
        // `settings::validate` refuses gateway changes while enrollment is
        // live, this value is stable across the round-trip below — the
        // credential and settings.json will end up under the same key.
        let gateway =
            control_plane.map_or_else(|| self.agent_state.gateway_target(), str::to_owned);

        // The gateway round-trip must not hold `state` locked.
        let credential = enroll::enroll(&self.config, token, self.capabilities.clone(), &gateway)
            .await
            .map_err(Internal)?;

        let mut state = self.state.lock().await;
        // `check_enrollable` refuses `Enrolling`, so nothing else can
        // transition it while we're away — assert defensively in case a
        // future path breaks that invariant.
        debug_assert!(
            matches!(*state, State::Enrolling),
            "state left Enrolling behind our back"
        );

        // Enrolling is an explicit act of participation: override a stale
        // participate=false so the reconciler doesn't immediately detach
        // the attachment started below. Persisted together with an explicit
        // gateway override, the same way `UpdateSettings` persists any
        // other setting; `attach()` below dials `gateway_target`, so both
        // `current` and `target` already agree with what happens next.
        self.agent_state.set_participate_target(true);
        if let Some(control_plane) = control_plane {
            self.agent_state.set_gateway_target(control_plane);
            self.agent_state.set_gateway_current(control_plane);
        }

        // Settings before the credential — order matters. On a crash or
        // failure between these two writes we prefer "settings on the new
        // gateway, no credential" (next startup loads the new gateway,
        // finds nothing under the same key, and starts cleanly Unenrolled)
        // over "credential under the new gateway, settings still on the
        // old" (next startup reads the old gateway, misses the entry keyed
        // by the new one on the macOS keychain backend, and the machine
        // token is orphaned — invisible to `Unenroll`, which also keys by
        // the settings gateway).
        self.settings_store
            .store(&self.agent_state.persisted_settings())
            .map_err(Internal)?;

        // Scoped to the gateway just persisted above, so the restart load
        // finds it under the same key.
        self.config
            .credential_store_for(&gateway)
            .store(&credential)
            .map_err(Internal)?;

        let machine_id = credential.machine_id.clone();
        *state = State::Attached(self.attach(credential, gateway));
        Ok(machine_id)
    }

    /// Leave the fleet — terminal. Stops attaching, decommissions the
    /// machine at the gateway (best-effort), and removes the persisted
    /// credential. Observably `Unenrolled` immediately (`GetStatus`/
    /// `Watch`); the attach task's own teardown finishes in the background,
    /// bounded by [`TEARDOWN_GRACE`], and `Enroll` is refused until it
    /// completes (see [`State::Unenrolling`]).
    pub async fn unenroll(&self) -> Result<(), Status> {
        // What we are leaving from: a live attachment (needs teardown) or a
        // detached-but-enrolled state (credential only).
        enum Leaving {
            Attached(Attachment),
            Detached {
                credential: Credential,
                credential_gateway: String,
            },
        }
        let leaving = {
            let mut state = self.state.lock().await;
            match &*state {
                State::Unenrolled => {
                    return Err(Status::failed_precondition("not enrolled"));
                }
                State::Enrolling => {
                    return Err(Status::failed_precondition(
                        "enroll in progress — retry shortly",
                    ));
                }
                State::Unenrolling => {
                    return Err(Status::failed_precondition("unenroll already in progress"));
                }
                State::Detaching => {
                    return Err(Status::failed_precondition(
                        "detach in progress — retry shortly",
                    ));
                }
                State::Attached(_) | State::Detached { .. } => {}
            }
            // Immediate observability: `GetStatus`/`Watch` read only
            // `agent_state`, not the `Mutex<State>`, so without this a
            // concurrent caller would see stale state for the whole grace
            // window below. Written while still holding the lock — every
            // other `agent_state` enrollment write happens under it too, so
            // none can interleave here.
            self.agent_state.set_enrollment(Enrollment::Unenrolled, "");
            match std::mem::replace(&mut *state, State::Unenrolling) {
                State::Attached(attachment) => Leaving::Attached(attachment),
                State::Detached {
                    credential,
                    credential_gateway,
                } => Leaving::Detached {
                    credential,
                    credential_gateway,
                },
                _ => unreachable!("checked above"),
            }
        };

        let (credential, credential_gateway) = match leaving {
            Leaving::Attached(attachment) => {
                attachment.shutdown.cancel();
                join_or_abort(attachment.task, TEARDOWN_GRACE).await;
                (attachment.credential, attachment.credential_gateway)
            }
            Leaving::Detached {
                credential,
                credential_gateway,
            } => (credential, credential_gateway),
        };

        // Authoritative: any attach task is provably stopped (joined or
        // aborted) and `Unenrolling` kept every `Enroll` out of the grace
        // window, so no live attachment's state can be stomped here and no
        // stale write from the old task survives it.
        {
            let mut state = self.state.lock().await;
            *state = State::Unenrolled;
            self.agent_state.set_enrollment(Enrollment::Unenrolled, "");
        }

        // Keyed by the gateway this attachment enrolled against, not the
        // live `gateway_target`, which a settings update may have moved
        // while attached (see `Attachment::credential_gateway`).
        Ok(
            enroll::unenroll_and_clear(&self.config, &credential_gateway, &credential)
                .await
                .map_err(Internal)?,
        )
    }

    /// Converge the attachment onto the `participate` target: detach (keep
    /// the credential) when it moves to false, reattach with the kept
    /// credential when it moves back to true. One pass; the reconciler task
    /// re-invokes it on every [`AgentState`] change — including this
    /// method's own writes, which is what re-checks a target that flipped
    /// mid-teardown.
    async fn reconcile_participation(&self) {
        let target = self.agent_state.participate_target();
        let mut state = self.state.lock().await;
        match &*state {
            State::Attached(_) if !target => {
                let State::Attached(attachment) = std::mem::replace(&mut *state, State::Detaching)
                else {
                    unreachable!("just matched");
                };
                let machine_id = attachment.credential.machine_id.clone();
                // Immediate observability, written under the lock (the same
                // discipline as `unenroll`).
                self.agent_state
                    .set_enrollment(Enrollment::Detached, &machine_id);
                drop(state);

                attachment.shutdown.cancel();
                join_or_abort(attachment.task, TEARDOWN_GRACE).await;

                let mut state = self.state.lock().await;
                *state = State::Detached {
                    credential: attachment.credential,
                    credential_gateway: attachment.credential_gateway,
                };
                // Authoritative re-assert + realized flag: the task is
                // provably stopped and `Detaching` kept `Enroll` out.
                self.agent_state
                    .set_enrollment(Enrollment::Detached, &machine_id);
                self.agent_state.set_participate_current(false);
                info!(machine_id = %machine_id, "detached from the fleet (participate=false)");
            }
            State::Detached { .. } if target => {
                let State::Detached {
                    credential,
                    credential_gateway,
                } = std::mem::replace(&mut *state, State::Unenrolled)
                else {
                    unreachable!("just matched");
                };
                info!(machine_id = %credential.machine_id, "reattaching (participate=true)");
                // `attach` is synchronous (it only spawns), so the
                // transitional `Unenrolled` above is never observable: the
                // lock is held across both writes.
                *state = State::Attached(self.attach(credential, credential_gateway));
            }
            // Nothing to attach or detach: the wish is trivially realized.
            State::Unenrolled => self.agent_state.set_participate_current(target),
            _ => {}
        }
    }

    /// Drive [`Self::reconcile_participation`] from the [`AgentState`]
    /// watch channel until `shutdown` fires. This is what lets
    /// `FleetSettingsService` stay free of any supervisor dependency:
    /// settings write the target, the supervisor observes and converges.
    pub fn spawn_participation_reconciler(
        self: &Arc<Self>,
        shutdown: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut rx = this.agent_state.subscribe();
            loop {
                this.reconcile_participation().await;
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    changed = rx.changed() => {
                        if changed.is_err() {
                            break;
                        }
                    }
                }
            }
        })
    }

    /// Stop accepting new offers; in-flight jobs finish normally.
    pub async fn drain(&self) -> Result<(), Status> {
        match &*self.state.lock().await {
            State::Attached(a) => {
                a.supervisor.handle_drain();
                Ok(())
            }
            State::Unenrolled | State::Enrolling | State::Unenrolling => {
                Err(Status::failed_precondition("not enrolled"))
            }
            State::Detaching | State::Detached { .. } => Err(Status::failed_precondition(
                "not attached (participate=false)",
            )),
        }
    }

    /// Resume accepting new offers after [`Self::drain`].
    pub async fn resume(&self) -> Result<(), Status> {
        match &*self.state.lock().await {
            State::Attached(a) => {
                a.supervisor.resume();
                Ok(())
            }
            State::Unenrolled | State::Enrolling | State::Unenrolling => {
                Err(Status::failed_precondition("not enrolled"))
            }
            State::Detaching | State::Detached { .. } => Err(Status::failed_precondition(
                "not attached (participate=false)",
            )),
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
            Enrollment::Detached => ConnectionState::Detached,
            Enrollment::CredentialRejected => ConnectionState::CredentialRejected,
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
                // During `Enrolling`/`Unenrolling`/`Detaching` the transition
                // owns any handle involved and awaits it itself; `Unenrolled`
                // and `Detached` have no task at all. Nothing to join.
                State::Unenrolled
                | State::Enrolling
                | State::Unenrolling
                | State::Detaching
                | State::Detached { .. } => None,
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
    use crate::config::{CredentialMode, DockerConfig, DockerMode};
    use crate::settings::PersistedSettings;

    fn seed() -> PersistedSettings {
        PersistedSettings {
            load_ceiling: 0.9,
            mem_floor_mib: 2048,
            linux_runner_image: "ghcr.io/actions/actions-runner:latest".to_owned(),
            gateway: "http://127.0.0.1:1".to_owned(),
            docker_mode: DockerMode::Disabled,
            runner_script: None,
            participate: true,
            vm_mode: crate::config::VmMode::Auto,
            macos_runner_image: "tahoe-base".to_owned(),
        }
    }

    fn test_config(data_dir: std::path::PathBuf) -> AgentConfig {
        AgentConfig {
            gateway: "http://127.0.0.1:1".to_owned(),
            runner_script: None,
            load_ceiling: 0.9,
            mem_floor_mib: 2048,
            data_dir,
            docker: DockerConfig {
                mode: DockerMode::Disabled,
                linux_runner_image: "ghcr.io/actions/actions-runner:latest".to_owned(),
            },
            vm: crate::config::VmConfig {
                mode: crate::config::VmMode::Disabled,
                macos_runner_image: "tahoe-base".to_owned(),
                daemon_socket: std::path::PathBuf::from("/nonexistent/arcbox.sock"),
            },
            credential_store: CredentialMode::File,
        }
    }

    /// Build an unenrolled supervisor over a scratch data dir.
    async fn test_supervisor(
        dir: &std::path::Path,
        agent_state: AgentState,
    ) -> Arc<AgentSupervisor> {
        Arc::new(
            AgentSupervisor::new(
                test_config(dir.to_path_buf()),
                None,
                None,
                Vec::new(),
                CancellationToken::new(),
                agent_state,
                SettingsStore::new(dir.join("settings.json")),
            )
            .await
            .expect("no credential on disk, so no attach on startup"),
        )
    }

    fn test_credential() -> Credential {
        Credential {
            machine_id: "fltm_test".to_owned(),
            machine_token: "flt_token_test".to_owned(),
        }
    }

    /// A local TCP endpoint that accepts a gateway connection and holds it
    /// open without ever speaking gRPC, so an enroll round-trip against it
    /// blocks in `State::Enrolling` rather than failing fast — which a refused
    /// port (`127.0.0.1:1`) does too quickly for the mid-round-trip state to
    /// be observed reliably. Aborting the returned task drops the held sockets,
    /// failing the in-flight round-trip so the enroll can then roll back.
    async fn stalling_gateway() -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind stalling gateway listener");
        let addr = listener.local_addr().expect("stalling gateway addr");
        let task = tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                // Hold the connection open without ever speaking gRPC; parking
                // here keeps the round-trip blocked, and dropping `sock` on
                // task abort closes it so the round-trip fails.
                let _sock = sock;
                std::future::pending::<()>().await;
            }
        });
        (format!("http://{addr}"), task)
    }

    /// Poll until the observable enrollment reaches `Attaching`, bounded so a
    /// stuck transition fails the test instead of hanging it.
    async fn wait_for_attaching(agent_state: &AgentState) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while agent_state.current().enrollment != Enrollment::Attaching as i32 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("enroll must flip observable state to Attaching");
    }

    /// The reconciler realizes `participate=false` by detaching — the
    /// credential is kept in the `Detached` state, the enrollment shows
    /// Detached, and `current` flips false — and realizes `true` again by
    /// reattaching with that same credential.
    #[tokio::test]
    async fn reconciler_detaches_and_reattaches_keeping_the_credential() {
        let dir = std::env::temp_dir().join(format!("fleet-participate-{}", std::process::id()));
        let agent_state = AgentState::new(&seed());
        let supervisor = test_supervisor(&dir, agent_state.clone()).await;

        // Inject a live attachment whose task observes its cancel promptly.
        let shutdown = supervisor.process_shutdown.child_token();
        let task_token = shutdown.clone();
        let task = tokio::spawn(async move {
            task_token.cancelled().await;
            Ok(())
        });
        let (events, _events_rx) = tokio::sync::mpsc::channel(1);
        let runner = crate::runner::RunnerSupervisor::new(
            events,
            None,
            None,
            None,
            Vec::new(),
            agent_state.clone(),
        );
        *supervisor.state.lock().await = State::Attached(Attachment {
            supervisor: runner,
            shutdown,
            task,
            credential: test_credential(),
            credential_gateway: "http://127.0.0.1:1".to_owned(),
        });

        agent_state.set_participate_target(false);
        supervisor.reconcile_participation().await;

        {
            let state = supervisor.state.lock().await;
            let State::Detached { credential, .. } = &*state else {
                panic!("expected Detached after reconciling participate=false");
            };
            assert_eq!(credential.machine_id, "fltm_test");
        }
        let snapshot = agent_state.current();
        assert_eq!(snapshot.enrollment, Enrollment::Detached as i32);
        assert_eq!(snapshot.machine_id, "fltm_test");
        assert!(!agent_state.settings().participate.unwrap().current);

        agent_state.set_participate_target(true);
        supervisor.reconcile_participation().await;

        assert!(matches!(
            &*supervisor.state.lock().await,
            State::Attached(_)
        ));
        assert!(agent_state.settings().participate.unwrap().current);
        // The fresh attachment starts dialing (the gateway is unreachable in
        // this test, so it stays Attaching — which is enough to prove the
        // kept credential was reused).
        assert_eq!(
            agent_state.current().enrollment,
            Enrollment::Attaching as i32
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Unenroll must also work from `Detached` (leave the fleet while
    /// offline): no task to tear down, straight to the credential clear.
    #[tokio::test]
    async fn unenroll_from_detached_clears_the_credential() {
        let dir = std::env::temp_dir().join(format!("fleet-det-unenroll-{}", std::process::id()));
        let agent_state = AgentState::new(&seed());
        let supervisor = test_supervisor(&dir, agent_state.clone()).await;

        let store = supervisor.config.credential_store_for("http://127.0.0.1:1");
        store
            .store(&test_credential())
            .expect("persist test credential");
        *supervisor.state.lock().await = State::Detached {
            credential: test_credential(),
            credential_gateway: "http://127.0.0.1:1".to_owned(),
        };
        agent_state.set_enrollment(Enrollment::Detached, "fltm_test");

        supervisor.unenroll().await.expect("unenroll from detached");

        assert!(matches!(*supervisor.state.lock().await, State::Unenrolled));
        assert_eq!(
            agent_state.current().enrollment,
            Enrollment::Unenrolled as i32
        );
        assert!(store.load().expect("store readable").is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    /// A persisted `participate=false` must survive a restart: the agent
    /// starts detached instead of silently reattaching.
    #[tokio::test]
    async fn startup_honors_persisted_participate_false() {
        let dir = std::env::temp_dir().join(format!("fleet-start-det-{}", std::process::id()));
        let config = test_config(dir.clone());
        config
            .credential_store_for("http://127.0.0.1:1")
            .store(&test_credential())
            .expect("persist test credential");

        let agent_state = AgentState::new(&PersistedSettings {
            participate: false,
            ..seed()
        });
        let supervisor = AgentSupervisor::new(
            config,
            None,
            None,
            Vec::new(),
            CancellationToken::new(),
            agent_state.clone(),
            SettingsStore::new(dir.join("settings.json")),
        )
        .await
        .expect("startup with credential");

        assert!(matches!(
            *supervisor.state.lock().await,
            State::Detached { .. }
        ));
        let snapshot = agent_state.current();
        assert_eq!(snapshot.enrollment, Enrollment::Detached as i32);
        assert_eq!(snapshot.machine_id, "fltm_test");
        assert!(!agent_state.settings().participate.unwrap().current);

        let _ = std::fs::remove_dir_all(dir);
    }

    /// While an unenroll is inside its teardown grace, a concurrent
    /// `Enroll` must be refused — not succeed and then have its observable
    /// state stomped by the unenroll's final `Unenrolled` re-assert (or
    /// by the old task's late writes). Once the unenroll completes, the
    /// gate opens again.
    #[tokio::test]
    async fn enroll_is_refused_during_unenroll_grace() {
        let dir = std::env::temp_dir().join(format!("fleet-disc-race-{}", std::process::id()));
        let agent_state = AgentState::new(&seed());
        let supervisor = Arc::new(
            AgentSupervisor::new(
                test_config(dir.clone()),
                None,
                None,
                Vec::new(),
                CancellationToken::new(),
                agent_state.clone(),
                SettingsStore::new(dir.join("settings.json")),
            )
            .await
            .expect("no credential on disk, so no attach on startup"),
        );

        // Inject a live attachment whose task takes a while to observe its
        // cancel — the teardown grace window the race lives in.
        let shutdown = supervisor.process_shutdown.child_token();
        let task_token = shutdown.clone();
        let task = tokio::spawn(async move {
            task_token.cancelled().await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            Ok(())
        });
        let (events, _events_rx) = tokio::sync::mpsc::channel(1);
        let runner =
            crate::runner::RunnerSupervisor::new(events, None, None, None, Vec::new(), agent_state);
        // A persisted credential, so the completed unenroll can prove the
        // local clear happens even though this gateway is unreachable (the
        // server-side call is best-effort).
        let credential = Credential {
            machine_id: "fltm_test".to_owned(),
            machine_token: "flt_token_test".to_owned(),
        };
        let store = supervisor.config.credential_store_for("http://127.0.0.1:1");
        store.store(&credential).expect("persist test credential");
        *supervisor.state.lock().await = State::Attached(Attachment {
            supervisor: runner,
            shutdown,
            task,
            credential,
            credential_gateway: "http://127.0.0.1:1".to_owned(),
        });

        let unenroll = {
            let supervisor = Arc::clone(&supervisor);
            tokio::spawn(async move { supervisor.unenroll().await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Mid-grace: the enrollment gate is closed.
        let err = supervisor
            .enroll("flt_join_test".to_owned(), None)
            .await
            .expect_err("enroll during unenroll grace must be refused");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("unenroll in progress"), "{err}");

        unenroll
            .await
            .expect("unenroll task")
            .expect("unenroll succeeds");
        assert!(matches!(*supervisor.state.lock().await, State::Unenrolled));
        // The unreachable gateway didn't block the terminal local outcome.
        assert!(store.load().expect("credential store readable").is_none());

        // Gate open again: enroll now passes the state check and fails
        // later, at the unreachable gateway — a different error.
        let err = supervisor
            .enroll("flt_join_test".to_owned(), None)
            .await
            .expect_err("gateway is unreachable");
        assert_ne!(err.code(), tonic::Code::FailedPrecondition, "{err}");

        let _ = std::fs::remove_dir_all(dir);
    }

    /// `enroll` must mirror its `State::Enrolling` transition onto
    /// `agent_state.enrollment = Attaching` before releasing the state
    /// lock — that mirror is what makes `settings::validate` refuse a
    /// gateway change while the gateway round-trip is in flight. If the
    /// round-trip then fails, both the supervisor state and the observable
    /// enrollment must roll back to `Unenrolled`, or the gate stays closed
    /// to every future enroll.
    #[tokio::test]
    async fn enroll_marks_state_attaching_across_the_gateway_round_trip() {
        let dir =
            std::env::temp_dir().join(format!("fleet-enroll-observability-{}", std::process::id()));
        let agent_state = AgentState::new(&seed());
        let supervisor = test_supervisor(&dir, agent_state.clone()).await;

        // A stalling gateway keeps the round-trip in flight so the transient
        // state below is observable; aborting it later fails the round-trip.
        let (gateway, gateway_task) = stalling_gateway().await;
        let enroll = {
            let supervisor = Arc::clone(&supervisor);
            tokio::spawn(async move {
                supervisor
                    .enroll("flt_join_test".to_owned(), Some(&gateway))
                    .await
            })
        };
        wait_for_attaching(&agent_state).await;

        assert_eq!(
            agent_state.current().enrollment,
            Enrollment::Attaching as i32,
            "observable state must flip to Attaching before the round-trip yields"
        );
        assert!(matches!(*supervisor.state.lock().await, State::Enrolling));

        // Release the stalled round-trip so it fails and the enroll rolls back.
        gateway_task.abort();
        let err = enroll
            .await
            .expect("enroll task")
            .expect_err("gateway round-trip fails once released");
        assert_ne!(err.code(), tonic::Code::FailedPrecondition, "{err}");

        // Rollback: both the supervisor state and observable enrollment
        // must return to Unenrolled so future enrolls can proceed.
        assert!(matches!(*supervisor.state.lock().await, State::Unenrolled));
        assert_eq!(
            agent_state.current().enrollment,
            Enrollment::Unenrolled as i32
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Two `enroll` RPCs racing against the same supervisor: the second
    /// must be refused by `State::Enrolling` (not by the round-trip
    /// re-check that came after it), so its token is never used and its
    /// credential is never persisted alongside the first one.
    #[tokio::test]
    async fn concurrent_enroll_is_refused_by_the_enrolling_gate() {
        let dir =
            std::env::temp_dir().join(format!("fleet-enroll-concurrent-{}", std::process::id()));
        let agent_state = AgentState::new(&seed());
        let supervisor = test_supervisor(&dir, agent_state.clone()).await;

        // The first enroll stalls at the gateway, holding the enrollment gate
        // closed for the whole window the second enroll races against.
        let (gateway, gateway_task) = stalling_gateway().await;
        let first = {
            let supervisor = Arc::clone(&supervisor);
            tokio::spawn(async move {
                supervisor
                    .enroll("flt_join_first".to_owned(), Some(&gateway))
                    .await
            })
        };
        wait_for_attaching(&agent_state).await;

        let err = supervisor
            .enroll("flt_join_second".to_owned(), None)
            .await
            .expect_err("concurrent enroll must be refused");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("enroll in progress"), "{err}");

        // Release the first enroll; the point is that the second one was gated
        // *before* even trying, not by the round-trip re-check that came after.
        gateway_task.abort();
        let _ = first.await.expect("enroll task");
        let _ = std::fs::remove_dir_all(dir);
    }

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
