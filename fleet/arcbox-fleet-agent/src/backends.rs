//! Live registry of the job-execution backends behind the agent's
//! advertised capabilities.
//!
//! One shared handle replaces the per-consumer `Option<DockerRunner>` /
//! `Option<VmRunner>` / `Option<InteropRunner>` copies that used to be
//! frozen at startup: offer routing (`RunnerSupervisor`), capability
//! advertisement (`attach`), image preparation (`FleetImageService`), and
//! `GetAgentInfo` all read the same slots, so what the agent advertises
//! and what it can actually serve cannot drift apart.
//!
//! On the wire, the capability set is per-attachment declarative state:
//! the gateway rewrites the machine's capability pools from each `Attach`
//! handshake, and a reconnect refreshes them. This registry is the client
//! half of that contract — the VM slot can activate after startup (an
//! arcbox-daemon that was not up yet when the agent started at login),
//! and the attach loop re-attaches with the fresh set when it does.
//!
//! Activation is one-way: a slot never empties once filled, so
//! "capability advertised ⇒ runner present" holds for the process
//! lifetime. A backend that dies later surfaces as per-job failures
//! (reject + platform re-offer), never as a capability retraction.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use arcbox_fleet_control_proto::v1 as control_proto;
use arcbox_fleet_proto::v1::{Backend, Capability};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::config::VmMode;
use crate::docker::DockerRunner;
use crate::host;
use crate::interop::InteropRunner;
use crate::state::AgentState;
use crate::vm::VmRunner;

/// How often to re-run the VM backend probe while it is inactive. The
/// probe is one unix-socket connect plus one `ImageList` RPC against the
/// local daemon — cheap enough to poll; the loop exits on activation.
const VM_REPROBE_INTERVAL: Duration = Duration::from_secs(30);

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

/// The agent's job-execution backends, shared by every consumer.
///
/// Slot lock discipline: the `RwLock` is held only to clone a handle in or
/// out (runners are cheap-clone channel wrappers) — never across an await.
pub struct Backends {
    /// Whether a host runner script is configured — the native-platform
    /// fallback capability when no isolating backend serves it.
    runner_script_present: bool,
    /// Docker runtime for Linux jobs. Probed at startup only (its `Auto`
    /// re-probe is a known follow-up); lives here so every consumer reads
    /// the same slot.
    docker: Option<DockerRunner>,
    /// macOS VM backend for darwin jobs. Live: empty while the daemon
    /// probe has not succeeded, one-way filled once it does.
    vm: RwLock<Option<VmRunner>>,
    /// WSL interop backend for windows jobs. Startup-probed only: it
    /// wraps host binaries, not a daemon that can come up later.
    interop: Option<InteropRunner>,
    /// Observable-state handle the advertised capability set is mirrored
    /// into on every change.
    state: AgentState,
    /// Nudged on every activation. Attach loops subscribe and treat a
    /// change as "the advertised capability set is stale — re-attach".
    changed: watch::Sender<()>,
    /// Test override for [`Self::capabilities`], so routing/advertisement
    /// logic can be exercised with synthetic sets independent of the host
    /// this test runs on.
    #[cfg(test)]
    fixed_capabilities: Option<Vec<Capability>>,
}

impl Backends {
    /// Build the registry from the startup probes' results and mirror the
    /// initial capability set into the observable state.
    pub fn new(
        runner_script_present: bool,
        docker: Option<DockerRunner>,
        vm: Option<VmRunner>,
        interop: Option<InteropRunner>,
        state: AgentState,
    ) -> Arc<Self> {
        let this = Arc::new(Self {
            runner_script_present,
            docker,
            vm: RwLock::new(vm),
            interop,
            state,
            changed: watch::channel(()).0,
            #[cfg(test)]
            fixed_capabilities: None,
        });
        this.mirror_capabilities();
        this
    }

    /// Activate the macOS VM backend. One-way: the first activation wins
    /// and later calls are ignored (the existing handle keeps serving).
    /// Mirrors the grown capability set into the observable state and
    /// nudges [`Self::subscribe`]rs so attach loops re-attach and the
    /// gateway learns the new set.
    pub fn activate_vm(&self, runner: VmRunner) {
        {
            let mut slot = self.vm.write().expect(LOCK_INVARIANT);
            if slot.is_some() {
                return;
            }
            *slot = Some(runner);
        }
        self.mirror_capabilities();
        self.changed.send_replace(());
    }

    /// Subscribe to activations. Receivers only learn "something changed"
    /// and re-derive the capability set from the registry.
    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.changed.subscribe()
    }

    /// The capability set this agent serves right now — what the `Attach`
    /// handshake declares and what offer routing agrees with.
    pub fn capabilities(&self) -> Vec<Capability> {
        #[cfg(test)]
        if let Some(capabilities) = &self.fixed_capabilities {
            return capabilities.clone();
        }
        let docker_arches = self
            .docker
            .as_ref()
            .map(DockerRunner::linux_arches)
            .unwrap_or_default();
        host::capabilities(
            self.runner_script_present,
            &docker_arches,
            self.vm_active(),
            self.interop.is_some(),
        )
    }

    /// The backend serving `(os, arch)` per the current capability set —
    /// the offer-routing table, derived live so routing and advertisement
    /// can never disagree.
    pub fn backend_for(&self, os: &str, arch: &str) -> Option<Backend> {
        self.capabilities()
            .into_iter()
            .find(|c| c.os == os && c.arch == arch)
            .and_then(|c| Backend::try_from(c.backed_by).ok())
    }

    /// A handle to the Docker runtime, if the startup probe passed.
    pub fn docker(&self) -> Option<DockerRunner> {
        self.docker.clone()
    }

    /// A handle to the macOS VM backend, if active.
    pub fn vm(&self) -> Option<VmRunner> {
        self.vm.read().expect(LOCK_INVARIANT).clone()
    }

    /// A handle to the WSL interop backend, if the startup probe passed.
    pub fn interop(&self) -> Option<InteropRunner> {
        self.interop.clone()
    }

    /// Whether the macOS VM backend is active (the daemon probe succeeded
    /// at startup or a later re-probe activated it).
    pub fn vm_active(&self) -> bool {
        self.vm.read().expect(LOCK_INVARIANT).is_some()
    }

    /// Whether the WSL interop backend is active.
    pub fn interop_active(&self) -> bool {
        self.interop.is_some()
    }

    /// Mirror the current capability set into the observable state.
    fn mirror_capabilities(&self) {
        let capabilities = self.capabilities();
        self.state
            .set_capabilities(capabilities.iter().map(capability_to_control).collect());
    }
}

/// The slot locks are held only for handle clones — no code path can panic
/// while holding one, so poisoning is unreachable.
const LOCK_INVARIANT: &str = "backend slot lock poisoned";

/// Spawn the VM backend re-probe when this host could ever activate it:
/// macOS, `vm_mode` Auto, and the startup probe having failed. `Enabled`
/// needs no re-probe (startup fails while the daemon is down, and launchd
/// respawns the agent until it comes up); `Disabled` means never. This
/// closes the login race where the LaunchAgent starts before arcbox-daemon
/// has bound its socket — without it the failed startup probe silently
/// benched darwin VM jobs for the whole process lifetime.
///
/// The task is detached: it exits on activation or when `shutdown` fires.
pub fn spawn_vm_reprobe(
    backends: &Arc<Backends>,
    state: AgentState,
    mode: VmMode,
    daemon_socket: PathBuf,
    shutdown: CancellationToken,
) {
    if std::env::consts::OS != "macos" || mode != VmMode::Auto || backends.vm_active() {
        return;
    }
    info!("macOS VM backend unavailable at startup; re-probing in the background");
    tokio::spawn(vm_reprobe_loop(
        Arc::clone(backends),
        state,
        daemon_socket,
        VM_REPROBE_INTERVAL,
        shutdown,
    ));
}

/// Re-run the startup probe every `interval` until it succeeds, then
/// activate the backend and exit. Probes against the *current*
/// `macos_runner_image` — the same image dispatch would boot — so a probe
/// can also start succeeding once the image gets installed (e.g. by
/// `abctl macos image pull`), not only once the daemon comes up.
async fn vm_reprobe_loop(
    backends: Arc<Backends>,
    state: AgentState,
    daemon_socket: PathBuf,
    interval: Duration,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            () = tokio::time::sleep(interval) => {}
        }
        let image = state.macos_runner_image_current();
        match VmRunner::new(&daemon_socket, &image).await {
            Ok(runner) => {
                info!("macOS VM backend became available; activating");
                backends.activate_vm(runner);
                return;
            }
            // The startup probe already warned once; steady-state misses
            // stay at debug so an offline daemon doesn't spam the log.
            Err(e) => debug!(
                error = format!("{e:#}"),
                "macOS VM backend still unavailable"
            ),
        }
    }
}

#[cfg(test)]
impl Backends {
    /// Registry whose [`Self::capabilities`] returns a fixed synthetic set,
    /// with no live runtimes behind it. For routing/advertisement tests
    /// that must not depend on the host the test runs on.
    pub(crate) fn fixed(capabilities: Vec<Capability>, state: AgentState) -> Arc<Self> {
        Self::fixed_with_interop(capabilities, None, state)
    }

    /// [`Self::fixed`] with a live interop backend, for windows-dispatch
    /// tests that exercise the real interop path behind a synthetic
    /// capability set.
    pub(crate) fn fixed_with_interop(
        capabilities: Vec<Capability>,
        interop: Option<InteropRunner>,
        state: AgentState,
    ) -> Arc<Self> {
        let this = Arc::new(Self {
            runner_script_present: false,
            docker: None,
            vm: RwLock::new(None),
            interop,
            state,
            changed: watch::channel(()).0,
            fixed_capabilities: Some(capabilities),
        });
        this.mirror_capabilities();
        this
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::PersistedSettings;

    fn seed() -> PersistedSettings {
        PersistedSettings {
            load_ceiling: 0.9,
            mem_floor_mib: 2048,
            linux_runner_image: "img".to_owned(),
            gateway: "https://fleet.arcbox.dev".to_owned(),
            docker_mode: crate::config::DockerMode::Disabled,
            runner_script: None,
            windows_runner_script: None,
            participate: true,
            vm_mode: crate::config::VmMode::Auto,
            macos_runner_image: "tahoe-base".to_owned(),
        }
    }

    fn capability(os: &str, arch: &str, backend: Backend) -> Capability {
        Capability {
            os: os.to_owned(),
            arch: arch.to_owned(),
            backed_by: backend as i32,
        }
    }

    #[test]
    fn construction_mirrors_capabilities_into_state() {
        let state = AgentState::new(&seed());
        let _backends = Backends::fixed(
            vec![capability("darwin", "arm64", Backend::HostRunner)],
            state.clone(),
        );
        let mirrored = state.current().capabilities;
        assert_eq!(mirrored.len(), 1);
        assert_eq!(mirrored[0].os, "darwin");
        assert_eq!(mirrored[0].arch, "arm64");
        assert_eq!(
            mirrored[0].backed_by,
            control_proto::Backend::HostRunner as i32
        );
    }

    #[test]
    fn backend_for_routes_by_os_arch() {
        let backends = Backends::fixed(
            vec![
                capability("linux", "amd64", Backend::Docker),
                capability("darwin", "arm64", Backend::Vm),
            ],
            AgentState::new(&seed()),
        );
        assert_eq!(
            backends.backend_for("linux", "amd64"),
            Some(Backend::Docker)
        );
        assert_eq!(backends.backend_for("darwin", "arm64"), Some(Backend::Vm));
        assert_eq!(backends.backend_for("windows", "amd64"), None);
    }

    #[test]
    fn empty_registry_serves_nothing() {
        let backends = Backends::new(false, None, None, None, AgentState::new(&seed()));
        assert!(!backends.vm_active());
        assert!(!backends.interop_active());
        assert!(backends.docker().is_none());
        assert!(backends.vm().is_none());
        assert!(backends.capabilities().is_empty());
    }

    /// Activation must grow the derived capability set (native platform,
    /// VM-backed), refresh the observable-state mirror, and nudge
    /// subscribers — the re-attach trigger.
    #[tokio::test]
    async fn activate_vm_grows_capabilities_and_notifies() {
        let daemon = crate::mock_daemon::MockDaemon::spawn(&["tahoe-base"]).await;
        let runner = VmRunner::new(&daemon.socket, "tahoe-base")
            .await
            .expect("probe against the mock daemon");

        let state = AgentState::new(&seed());
        let backends = Backends::new(false, None, None, None, state.clone());
        let mut rx = backends.subscribe();
        rx.mark_unchanged();

        backends.activate_vm(runner);

        assert!(backends.vm_active());
        assert!(backends.vm().is_some());
        assert!(rx.has_changed().expect("registry alive"));
        let capabilities = backends.capabilities();
        assert_eq!(capabilities.len(), 1);
        assert_eq!(capabilities[0].os, host::host_os());
        assert_eq!(capabilities[0].backed_by, Backend::Vm as i32);
        assert_eq!(
            backends.backend_for(&host::host_os(), &host::host_arch()),
            Some(Backend::Vm)
        );
        assert_eq!(state.current().capabilities.len(), 1);
    }

    /// While the probe keeps failing (daemon up, image missing) the loop
    /// stays inactive; once the probe starts succeeding it activates and
    /// exits. This is the image-appears flavor of the login race — the
    /// daemon-appears flavor differs only in which probe step fails.
    #[tokio::test]
    async fn vm_reprobe_loop_activates_when_the_probe_starts_succeeding() {
        let daemon = crate::mock_daemon::MockDaemon::spawn(&[]).await;
        let state = AgentState::new(&seed());
        let backends = Backends::new(false, None, None, None, state.clone());
        let loop_task = tokio::spawn(vm_reprobe_loop(
            Arc::clone(&backends),
            state,
            daemon.socket.clone(),
            Duration::from_millis(10),
            CancellationToken::new(),
        ));

        // Give a few ticks their chance to mis-activate on the missing image.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!backends.vm_active());

        daemon.install("tahoe-base");
        tokio::time::timeout(Duration::from_secs(5), loop_task)
            .await
            .expect("loop must exit once the probe succeeds")
            .expect("reprobe loop must not panic");
        assert!(backends.vm_active());
    }
}
