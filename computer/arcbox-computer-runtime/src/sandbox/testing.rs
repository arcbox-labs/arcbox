//! Test scaffolding shared by the sandbox flows: a manager over the port's
//! fake driver, and a live sandbox with every runtime resource a boot hands
//! over — so the failure paths can be driven on any host, no KVM or root.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use arcbox_vm_driver::testkit::{FakeDriver, FakeNetwork};
use arcbox_vm_driver::{
    BootSpec, Checkpoint, CheckpointImage, CheckpointOptions, ConsoleSpec, Error, ExitStatus,
    IsolationSpec, PreparedVm, ShutdownMode, VmDriver as _, VmEvent, VmHandle, VmId, VmRecord,
    VmSpec, VmState,
};
use async_trait::async_trait;
use tokio::sync::broadcast;

use super::reconcile::{JournaledLease, SandboxStateRecord, write_state_record};
use super::record::{ProvisionIntent, SandboxProvisionOutcome, SandboxTransition};
use super::{ComputerRuntime, Runtime, SandboxManager, SandboxSpec, SandboxState};
use crate::config::{JailerConfig, VmmConfig};
use crate::lifecycle::actor::{Command, Deadlines, Seeded};
use crate::lifecycle::flows::Launch;
use crate::sandbox::record::PersistPhase;
use crate::sandbox::workload::WorkloadClaim;
use crate::snapshot_cow::{CowManager, CowOptions, CowTestProbe};
use crate::testkit::agent::FakeAgentFactory;
use crate::{SandboxEnvironment, VmmError};

/// A manager over [`FakeDriver`] and [`FakeNetwork`] with a probed CoW
/// manager and jailer mode configured (checkpoints, pause and restore
/// require it), its startup cleanup finalized so leases can be reserved.
///
/// Both fakes are what make these tests platform-free: the TAP network
/// reserves and releases through netlink and iptables, which an
/// unprivileged unit test cannot drive on Linux, so the release paths used
/// to be exercised on macOS only.
pub(super) async fn fake_manager(
    data_dir: &Path,
) -> (SandboxManager, FakeDriver, Arc<CowTestProbe>) {
    let (manager, driver, probe, _agent) = fake_manager_with_agent(
        data_dir,
        Some(JailerConfig {
            binary: "/usr/bin/jailer".into(),
            uid: 0,
            gid: 0,
            chroot_base_dir: Some(data_dir.join("jailer").to_string_lossy().into_owned()),
            netns: None,
            new_pid_ns: false,
            cgroup_version: None,
            parent_cgroup: None,
            resource_limits: vec![],
        }),
    )
    .await;
    (manager, driver, probe)
}

/// [`fake_manager`] in direct mode, for the flows that do not need a
/// jailer.
///
/// A jailer chroot under a temp dir spends the whole AF_UNIX socket-path
/// budget, leaving `max_sandbox_id_len` at zero — so any test that calls
/// `create_sandbox` for real is refused at id validation before it reaches
/// anything it meant to exercise.
pub(super) async fn fake_manager_direct(
    data_dir: &Path,
) -> (SandboxManager, FakeDriver, Arc<CowTestProbe>) {
    let (manager, driver, probe, _agent) = fake_manager_with_agent(data_dir, None).await;
    (manager, driver, probe)
}

/// [`fake_manager_direct`] keeping the scripted agent, for the tests that
/// drive a real boot rather than planting an instance.
pub(super) async fn fake_manager_with_agent(
    data_dir: &Path,
    jailer: Option<JailerConfig>,
) -> (
    SandboxManager,
    FakeDriver,
    Arc<CowTestProbe>,
    FakeAgentFactory,
) {
    let mut config = VmmConfig::default();
    config.firecracker.data_dir = data_dir.to_string_lossy().into_owned();
    config.firecracker.jailer = jailer;
    let driver = FakeDriver::new();
    let agent = FakeAgentFactory::new();
    let probe = Arc::new(CowTestProbe::default());
    let manager = SandboxManager::with_environment(
        config,
        SandboxEnvironment {
            driver: Some(Arc::new(driver.clone())),
            network: Some(Arc::new(FakeNetwork::with_startup_cleanup("test-boot"))),
            agent: Some(Arc::new(agent.clone())),
            cow_manager: Some(Arc::new(
                CowManager::new_with_test_probe(CowOptions::new(data_dir), Arc::clone(&probe))
                    .unwrap(),
            )),
            ..SandboxEnvironment::default()
        },
    )
    .unwrap();
    manager.await_reconcile().await.unwrap();
    let token = manager.startup_cleanup_token().await.unwrap().unwrap();
    manager.finalize_startup_cleanup(&token).await.unwrap();
    (manager, driver, probe, agent)
}

/// A minimal spec the fake boots.
fn vm_spec(id: &VmId) -> VmSpec {
    VmSpec {
        id: id.clone(),
        cpus: 1,
        memory_mib: 128,
        boot: BootSpec::Kernel {
            image: "/vmlinux".into(),
            cmdline: String::new(),
            initrd: None,
        },
        disks: vec![],
        nics: vec![],
        vsock: None,
        shares: vec![],
        console: ConsoleSpec::Off,
        balloon: false,
        entropy: false,
        dirty_tracking: false,
        isolation: IsolationSpec::None,
    }
}

/// A VM whose checkpoint fails and leaves the guest frozen — the case where
/// the driver's own resume after the capture failed — over a live fake VM.
/// Everything else delegates, so killing the process the fake VM runs on
/// (through the prepared VMM's `discard`) still shows up as `Exited` here.
pub(super) struct FrozenOnCheckpoint {
    inner: Arc<dyn VmHandle>,
    frozen: AtomicBool,
}

impl FrozenOnCheckpoint {
    pub(super) fn over(inner: Arc<dyn VmHandle>) -> Arc<dyn VmHandle> {
        Arc::new(Self {
            inner,
            frozen: AtomicBool::new(false),
        })
    }
}

#[async_trait]
impl VmHandle for FrozenOnCheckpoint {
    fn id(&self) -> &VmId {
        self.inner.id()
    }

    fn record(&self) -> VmRecord {
        self.inner.record()
    }

    fn state(&self) -> VmState {
        match self.inner.state() {
            exited @ VmState::Exited(_) => exited,
            _ if self.frozen.load(Ordering::Acquire) => VmState::Quiesced,
            state => state,
        }
    }

    fn events(&self) -> broadcast::Receiver<VmEvent> {
        self.inner.events()
    }

    async fn shutdown(&self, mode: ShutdownMode) -> arcbox_vm_driver::Result<ExitStatus> {
        self.inner.shutdown(mode).await
    }

    fn checkpoint(&self) -> Option<&dyn Checkpoint> {
        Some(self)
    }
}

#[async_trait]
impl Checkpoint for FrozenOnCheckpoint {
    async fn checkpoint(
        &self,
        _dst: &Path,
        _opts: CheckpointOptions,
    ) -> arcbox_vm_driver::Result<CheckpointImage> {
        self.frozen.store(true, Ordering::Release);
        Err(Error::Driver {
            driver: "fake",
            message: "the guest stays quiesced: it could not be resumed after a failed checkpoint"
                .into(),
            source: None,
        })
    }
}

/// A handle that remembers how it was asked to shut down.
///
/// The fake VM reports the same exit status whether it was killed or merely
/// dropped, so a test that must prove a kill *was asked for* — rather than
/// that a handle went out of scope — reads it here.
pub(super) struct RecordsShutdown {
    inner: Arc<dyn VmHandle>,
    modes: Mutex<Vec<ShutdownMode>>,
}

impl RecordsShutdown {
    /// Wrap `inner`, handing back both the recorder and the handle to
    /// install — [`live_sandbox_with`] only returns the erased one.
    pub(super) fn wrap(inner: Arc<dyn VmHandle>) -> (Arc<Self>, Arc<dyn VmHandle>) {
        let recorder = Arc::new(Self {
            inner,
            modes: Mutex::new(Vec::new()),
        });
        (Arc::clone(&recorder), recorder)
    }

    /// How this handle was shut down, in order.
    pub(super) fn modes(&self) -> Vec<ShutdownMode> {
        self.modes.lock().unwrap().clone()
    }
}

#[async_trait]
impl VmHandle for RecordsShutdown {
    fn id(&self) -> &VmId {
        self.inner.id()
    }

    fn record(&self) -> VmRecord {
        self.inner.record()
    }

    fn state(&self) -> VmState {
        self.inner.state()
    }

    fn events(&self) -> broadcast::Receiver<VmEvent> {
        self.inner.events()
    }

    async fn shutdown(&self, mode: ShutdownMode) -> arcbox_vm_driver::Result<ExitStatus> {
        self.modes.lock().unwrap().push(mode);
        self.inner.shutdown(mode).await
    }
}

/// A computer in `state`, with a durable record to match and no runtime
/// resources — what the startup sweep reinstates, and what a test that only
/// needs a computer in a given state should plant.
///
/// Goes through the same claim-and-seed path the sweep does, so the actor
/// behind it is a real one: its mailbox answers, its snapshot reads, and its
/// deadlines fire.
pub(super) async fn plant_computer(
    manager: &SandboxManager,
    id: &str,
    state: SandboxState,
) -> Runtime {
    plant_computer_with(manager, id, state, |_| {}).await
}

/// [`plant_computer`], with the runtime dressed before its actor starts —
/// the only moment anything but the actor may write to it.
pub(super) async fn plant_computer_with(
    manager: &SandboxManager,
    id: &str,
    state: SandboxState,
    dress: impl FnOnce(&mut ComputerRuntime),
) -> Runtime {
    let vm_dir = PathBuf::from(&manager.config.firecracker.data_dir)
        .join("sandboxes")
        .join(id);
    let mut runtime = ComputerRuntime::new(
        id.to_owned(),
        SandboxSpec {
            id: Some(id.to_owned()),
            ..SandboxSpec::default()
        },
        None,
        vm_dir,
    );
    runtime.state = state;
    dress(&mut runtime);
    let reservation = super::reserve_actor(&manager.computers, &id.to_owned(), runtime).unwrap();
    let shared = Arc::clone(reservation.runtime());
    let (services, timers_enabled) = manager.spawn_context();
    let mailbox = reservation.spawn(super::ActorSpawn {
        services,
        timers_enabled,
        generation: None,
        deadlines: Deadlines::default(),
        launch: Launch::Reinstated,
        seeded: match state {
            // A computer this process took back: usable, never booted here.
            SandboxState::Ready | SandboxState::Running | SandboxState::Starting => Seeded::Adopted,
            SandboxState::Paused | SandboxState::Pausing => Seeded::Recovered(PersistPhase::Paused),
            SandboxState::Stopped | SandboxState::Stopping => {
                Seeded::Recovered(PersistPhase::Stopped)
            }
            SandboxState::Failed => Seeded::Recovered(PersistPhase::Failed),
        },
    });
    if state == SandboxState::Running {
        mailbox
            .ask(&id.to_owned(), |reply| Command::ClaimWorkload {
                claim: WorkloadClaim::Api,
                reply,
            })
            .await
            .expect("an adopted computer accepts a workload");
    }
    // The actor dispatches its seeding on its own task, so a read taken
    // before that lands would still see the claim's `Starting`.
    await_state(manager, id, state).await;
    shared
}

/// Wait until `id`'s read snapshot reports `state`.
pub(super) async fn await_state(manager: &SandboxManager, id: &str, state: SandboxState) {
    let mut snapshot = manager
        .computer(&id.to_owned())
        .expect("the computer is registered")
        .snapshot;
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        snapshot.wait_for(|snapshot| snapshot.state == state),
    )
    .await
    .unwrap_or_else(|_| panic!("{id} never reached {state}"))
    .expect("the actor keeps its snapshot open");
}

/// [`live_sandbox_with`] over the fake VM's own handle.
pub(super) async fn live_sandbox(
    manager: &SandboxManager,
    driver: &FakeDriver,
    id: &str,
) -> (Runtime, Arc<dyn VmHandle>) {
    live_sandbox_with(manager, driver, id, |handle| handle).await
}

/// A `Ready` sandbox holding everything a successful boot hands its instance:
/// the prepared VMM and the handle of the VM booted on it (as `wrap` dresses
/// it), a (probed) CoW overlay, a reserved network allocation, a durable
/// `Ready` record, and a crash journal naming them. Returns the instance and
/// the handle it holds.
pub(super) async fn live_sandbox_with(
    manager: &SandboxManager,
    driver: &FakeDriver,
    id: &str,
    wrap: impl FnOnce(Arc<dyn VmHandle>) -> Arc<dyn VmHandle>,
) -> (Runtime, Arc<dyn VmHandle>) {
    let vm_dir = PathBuf::from(&manager.config.firecracker.data_dir)
        .join("sandboxes")
        .join(id);
    std::fs::create_dir_all(&vm_dir).unwrap();
    let vm_id = VmId::new(id).unwrap();
    let prepared: Arc<dyn PreparedVm> = Arc::from(
        driver
            .prepare()
            .unwrap()
            .prepare(&vm_id, &IsolationSpec::None, &vm_dir)
            .await
            .unwrap(),
    );
    let handle = wrap(Arc::from(prepared.boot(vm_spec(&vm_id)).await.unwrap()));
    let cow_handle = manager.cow_manager.setup(id, "/rootfs.ext4").await.unwrap();
    let lease = manager
        .services
        .network
        .reserve(&vm_id, super::sandbox_network_policy())
        .await
        .unwrap();

    let spec = SandboxSpec {
        id: Some(id.to_owned()),
        ..SandboxSpec::default()
    };
    let record = match manager
        .records
        .provision_intent(id, "create-key", spec.clone())
        .unwrap()
    {
        ProvisionIntent::Created(record) => record,
        other => panic!("expected a new record, got {other:?}"),
    };
    let generation = record.generation;
    manager
        .records
        .transition(
            id,
            generation,
            SandboxTransition::Starting(SandboxProvisionOutcome {
                ip_address: lease.ip.to_string(),
            }),
        )
        .unwrap();
    manager
        .records
        .transition(id, generation, SandboxTransition::Ready)
        .unwrap();
    write_state_record(
        &vm_dir,
        &SandboxStateRecord::new(
            id,
            super::journaled_pid(&*prepared),
            // A cold boot with the invariant identity baked in, which is
            // what `live_sandbox` stands for and what the identity below
            // is read under.
            Some(JournaledLease::cold_boot(&lease, true)),
            Some(&cow_handle),
            &manager.config,
            None,
        )
        .unwrap(),
    )
    .unwrap();

    // A cold boot activates the interface invariant and hands the computer
    // that identity beside the handle, so a planted one must too: it is what
    // every agent built afterwards describes the guest with.
    let identity = manager
        .services
        .network
        .identity(&lease, super::attach_mode(true));
    let mut runtime =
        ComputerRuntime::new_with_generation(id.to_owned(), spec, Some(lease), vm_dir, generation);
    runtime.state = SandboxState::Ready;
    runtime.prepared = Some(prepared);
    runtime.handle = Some(Arc::clone(&handle));
    runtime.net_identity = Some(identity);
    runtime.cow_handle = Some(cow_handle);

    // Seeded the way the startup sweep seeds a computer whose VM it took
    // back: durably `Ready`, holding everything a boot hands over, and never
    // launched in this process.
    let reservation = super::reserve_actor(&manager.computers, &id.to_owned(), runtime).unwrap();
    let shared = Arc::clone(reservation.runtime());
    let (services, timers_enabled) = manager.spawn_context();
    reservation.spawn(super::ActorSpawn {
        services,
        timers_enabled,
        generation: Some(generation),
        deadlines: Deadlines::default(),
        launch: Launch::Reinstated,
        seeded: Seeded::Adopted,
    });
    await_state(manager, id, SandboxState::Ready).await;
    (shared, handle)
}

/// Every mark of a sandbox that failed the way a failed boot does: `Failed`
/// in memory and on the durable record, no VMM (the prepared process
/// discarded, the handle dropped), CoW overlay and network lease released,
/// crash journal cleared. Panics on the first mark that is missing.
pub(super) async fn assert_failed_and_released(
    manager: &SandboxManager,
    runtime: &Runtime,
    probe: &CowTestProbe,
    id: &str,
) {
    // The failure runs in the computer's actor and its release in a
    // sub-task, so wait for the last thing either does — the journal clear,
    // which is gated on both — rather than assuming the caller's error means
    // it has all landed.
    let vm_dir = runtime.lock().unwrap().vm_dir.clone();
    for _ in 0..500 {
        if runtime.lock().unwrap().state == SandboxState::Failed
            && !vm_dir.join("state.json").exists()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    {
        let inst = runtime.lock().unwrap();
        assert_eq!(inst.state, SandboxState::Failed);
        assert!(
            inst.error.is_some(),
            "the failure is recorded on the instance"
        );
        assert!(inst.prepared.is_none(), "the VMM process is discarded");
        assert!(inst.handle.is_none(), "the dead VM's handle is dropped");
        assert!(inst.cow_handle.is_none(), "the CoW overlay is released");
        assert!(inst.network.is_none(), "the network lease is released");
        assert_eq!(probe.teardown_count(), 1, "the CoW teardown ran once");
        assert_eq!(
            manager.records.load(id).unwrap().unwrap().phase,
            super::record::PersistPhase::Failed
        );
        assert!(
            !inst.vm_dir.join("state.json").exists(),
            "the crash journal is cleared once every resource is released"
        );
    }
    assert!(
        manager
            .reconcile_network()
            .pending_cleanups()
            .await
            .unwrap()
            .iter()
            .any(|(quarantined, _)| quarantined.as_str() == id),
        "the address is quarantined for host cleanup"
    );
}

/// The `Result` an assertion helper cannot express: surfaces a mismatch as
/// the test's own panic with the error attached.
pub(super) fn expect_err<T>(result: Result<T, VmmError>, what: &str) -> VmmError {
    match result {
        Ok(_) => panic!("{what} should have failed"),
        Err(error) => error,
    }
}
