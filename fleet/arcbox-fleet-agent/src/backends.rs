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

use std::sync::{Arc, RwLock};

use arcbox_fleet_control_proto::v1 as control_proto;
use arcbox_fleet_proto::v1::{Backend, Capability};

use crate::docker::DockerRunner;
use crate::host;
use crate::interop::InteropRunner;
use crate::state::AgentState;
use crate::vm::VmRunner;

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
            #[cfg(test)]
            fixed_capabilities: None,
        });
        this.mirror_capabilities();
        this
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
}
