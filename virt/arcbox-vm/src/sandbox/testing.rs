//! Test scaffolding shared by the sandbox flows: a manager over the port's
//! fake driver, and a live sandbox with every runtime resource a boot hands
//! over — so the failure paths can be driven on any host, no KVM or root.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use arcbox_vm_driver::testkit::FakeDriver;
use arcbox_vm_driver::{
    BootSpec, ConsoleSpec, IsolationSpec, PreparedVm, VmDriver as _, VmHandle, VmId, VmSpec,
};

use super::persistence::{ProvisionIntent, SandboxProvisionOutcome, SandboxTransition};
use super::reconcile::{SandboxStateRecord, write_state_record};
use super::{SandboxInstance, SandboxManager, SandboxSpec, SandboxState};
use crate::config::{JailerConfig, VmmConfig};
use crate::snapshot_cow::{CowManager, CowOptions, CowTestProbe};
use crate::{SandboxEnvironment, VmmError};

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

/// A `Ready` sandbox holding everything a successful boot hands its instance:
/// the prepared VMM and the handle of the VM booted on it, a (probed) CoW
/// overlay, a reserved network allocation, a durable `Ready` record, and a
/// crash journal naming them. Returns the instance and the VM's handle.
pub(super) async fn live_sandbox(
    manager: &SandboxManager,
    driver: &FakeDriver,
    id: &str,
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
    let handle: Arc<dyn VmHandle> = Arc::from(prepared.boot(vm_spec(&vm_id)).await.unwrap());
    let cow_handle = manager.cow_manager.setup(id, "/rootfs.ext4").await.unwrap();
    let network = manager.network.reserve(id).unwrap();

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
                ip_address: network.ip_address.to_string(),
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
            Some(&network),
            Some(&cow_handle),
            true,
            None,
        ),
    )
    .unwrap();

    let mut instance = SandboxInstance::new_with_generation(
        id.to_owned(),
        spec,
        Some(network),
        vm_dir,
        generation,
    );
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
/// discarded, the handle dropped), CoW overlay and network released, crash
/// journal cleared. Panics on the first mark that is missing.
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
    assert!(
        manager
            .network
            .pending_quarantines()
            .iter()
            .any(|(quarantined, _)| quarantined == id),
        "the TAP + IP are quarantined for host cleanup"
    );
    assert_eq!(
        manager.records.load(id).unwrap().unwrap().phase,
        super::persistence::SandboxPhase::Failed
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
