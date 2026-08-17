//! Test scaffolding shared by the sandbox flows: a manager over the port's
//! fake driver, and a live sandbox with every runtime resource a boot hands
//! over — so the failure paths can be driven on any host, no KVM or root.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use arcbox_vm_driver::testkit::FakeDriver;
use arcbox_vm_driver::{
    BootSpec, Checkpoint, CheckpointImage, CheckpointOptions, ConsoleSpec, Error, ExitStatus,
    IsolationSpec, PreparedVm, ShutdownMode, VmDriver as _, VmEvent, VmHandle, VmId, VmRecord,
    VmSpec, VmState,
};
use async_trait::async_trait;
use tokio::sync::broadcast;

use super::reconcile::{SandboxStateRecord, write_state_record};
use super::record::{ProvisionIntent, SandboxProvisionOutcome, SandboxTransition};
use super::{SandboxInstance, SandboxManager, SandboxSpec, SandboxState};
use crate::config::{JailerConfig, VmmConfig};
use crate::snapshot_cow::{CowManager, CowOptions, CowTestProbe};
use crate::{SandboxEnvironment, VmmError};

/// Whether the live sandbox carries a network allocation. Releasing one on
/// Linux talks to netlink and iptables (root, and the System VM's binaries),
/// which an unprivileged unit test cannot — the tap-net crate skips those
/// paths without root for the same reason; the macOS build's no-op branch
/// is what lets these tests drive the release end to end.
pub(super) const RELEASES_NETWORK: bool = cfg!(not(target_os = "linux"));

/// A manager over [`FakeDriver`] with a probed CoW manager and jailer mode
/// configured (checkpoints, pause and restore require it), its startup
/// cleanup finalized so networks can be reserved.
pub(super) async fn fake_manager(
    data_dir: &Path,
) -> (SandboxManager, FakeDriver, Arc<CowTestProbe>) {
    let mut config = VmmConfig::default();
    config.firecracker.data_dir = data_dir.to_string_lossy().into_owned();
    config.firecracker.jailer = Some(JailerConfig {
        binary: "/usr/bin/jailer".into(),
        uid: 0,
        gid: 0,
        chroot_base_dir: Some(data_dir.join("jailer").to_string_lossy().into_owned()),
        netns: None,
        new_pid_ns: false,
        cgroup_version: None,
        parent_cgroup: None,
        resource_limits: vec![],
    });
    let driver = FakeDriver::new();
    let mut manager = SandboxManager::with_environment(
        config,
        SandboxEnvironment {
            driver: Some(Arc::new(driver.clone())),
            ..SandboxEnvironment::default()
        },
    )
    .unwrap();
    manager.await_reconcile().await.unwrap();
    let probe = Arc::new(CowTestProbe::default());
    manager.cow_manager = Arc::new(
        CowManager::new_with_test_probe(CowOptions::new(data_dir), Arc::clone(&probe)).unwrap(),
    );
    let token = manager.startup_cleanup_token().await.unwrap().unwrap();
    manager.finalize_startup_cleanup(&token).await.unwrap();
    (manager, driver, probe)
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

/// [`live_sandbox_with`] over the fake VM's own handle.
pub(super) async fn live_sandbox(
    manager: &SandboxManager,
    driver: &FakeDriver,
    id: &str,
) -> (Arc<Mutex<SandboxInstance>>, Arc<dyn VmHandle>) {
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
) -> (Arc<Mutex<SandboxInstance>>, Arc<dyn VmHandle>) {
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
    let network = RELEASES_NETWORK.then(|| manager.network.reserve(id).unwrap());

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
                ip_address: network
                    .as_ref()
                    .map(|network| network.ip_address.to_string())
                    .unwrap_or_default(),
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
            network.as_ref(),
            Some(&cow_handle),
            true,
            None,
        ),
    )
    .unwrap();

    let mut instance =
        SandboxInstance::new_with_generation(id.to_owned(), spec, network, vm_dir, generation);
    instance.state = SandboxState::Ready;
    instance.prepared = Some(prepared);
    instance.handle = Some(Arc::clone(&handle));
    instance.cow_handle = Some(cow_handle);
    let instance = Arc::new(Mutex::new(instance));
    manager
        .instances
        .write()
        .unwrap()
        .insert(id.to_owned(), Arc::clone(&instance));
    (instance, handle)
}

/// Every mark of a sandbox that failed the way a failed boot does: `Failed`
/// in memory and on the durable record, no VMM (the prepared process
/// discarded, the handle dropped), CoW overlay and network (where the test
/// carries one, [`RELEASES_NETWORK`]) released, crash journal cleared.
/// Panics on the first mark that is missing.
pub(super) fn assert_failed_and_released(
    manager: &SandboxManager,
    instance: &Arc<Mutex<SandboxInstance>>,
    probe: &CowTestProbe,
    id: &str,
) {
    let inst = instance.lock().unwrap();
    assert_eq!(inst.state, SandboxState::Failed);
    assert!(
        inst.error.is_some(),
        "the failure is recorded on the instance"
    );
    assert!(inst.prepared.is_none(), "the VMM process is discarded");
    assert!(inst.handle.is_none(), "the dead VM's handle is dropped");
    assert!(inst.cow_handle.is_none(), "the CoW overlay is released");
    assert!(inst.network.is_none(), "the network allocation is released");
    assert_eq!(probe.teardown_count(), 1, "the CoW teardown ran once");
    assert_eq!(
        manager
            .network
            .pending_quarantines()
            .iter()
            .any(|(quarantined, _)| quarantined == id),
        RELEASES_NETWORK,
        "the TAP + IP are quarantined for host cleanup"
    );
    assert_eq!(
        manager.records.load(id).unwrap().unwrap().phase,
        super::record::PersistPhase::Failed
    );
    assert!(
        !inst.vm_dir.join("state.json").exists(),
        "the crash journal is cleared once every resource is released"
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
