//! The fake's `Prepare` capability: a "spawned" VMM waiting for a spec.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use super::fake_driver::{DriverInner, NAME};
use super::fake_vm::{CHECKPOINT_FORMAT, CheckpointFile, FakeVm, VmInner};
use super::fake_vsock::{FakeListener, Inbound};
use super::lock;
use crate::capability::{CheckpointImage, Prepare, PreparedVm, VsockListen, VsockListener};
use crate::driver::{ExitStatus, ProcessRecord, RestoreSpec, VmHandle, VmRecord, VmState};
use crate::error::{Error, Result};
use crate::spec::{IsolationSpec, VmId, VmSpec};

/// What `discard` reports for a process killed before or after its boot.
const SIGKILL: i32 = 9;

/// The `Prepare` capability, on its own type so its `prepare` method does
/// not shadow the driver's accessor of the same name.
#[derive(Clone)]
pub(super) struct Preparer(pub(super) Arc<DriverInner>);

impl Preparer {
    /// The synchronous heart of `prepare`, shared with the driver's plain
    /// `boot`/`restore` so those are exactly prepare-then-boot.
    pub(super) fn prepare_sync(
        &self,
        id: &VmId,
        isolation: &IsolationSpec,
        runtime_dir: &Path,
    ) -> PreparedFake {
        let record = VmRecord {
            id: id.clone(),
            driver: NAME.to_owned(),
            runtime_dir: runtime_dir.to_path_buf(),
            process: Some(ProcessRecord {
                pid: self.0.next_pid(),
                api_socket: Some(runtime_dir.join("api.sock")),
            }),
        };
        PreparedFake {
            driver: Arc::clone(&self.0),
            isolation: isolation.clone(),
            inbound: Inbound::new(id.clone()),
            record,
            phase: Mutex::new(Phase::Prepared),
        }
    }
}

#[async_trait]
impl Prepare for Preparer {
    async fn prepare(
        &self,
        id: &VmId,
        isolation: &IsolationSpec,
        runtime_dir: &Path,
    ) -> Result<Box<dyn PreparedVm>> {
        Ok(Box::new(self.prepare_sync(id, isolation, runtime_dir)))
    }
}

/// A prepared fake process: a record with a synthetic pid, listeners that
/// outlive the boot, and at most one VM booted on it.
pub(super) struct PreparedFake {
    driver: Arc<DriverInner>,
    isolation: IsolationSpec,
    inbound: Arc<Inbound>,
    record: VmRecord,
    /// One lock for the whole life of the process, so a `boot` racing a
    /// `discard` cannot both pass: whichever takes the lock first decides.
    phase: Mutex<Phase>,
}

/// Where a prepared process is in its life.
enum Phase {
    /// Spawned, no guest yet; `Drop` kills it.
    Prepared,
    /// A boot or restore succeeded; the VM's handle owns the process now.
    Booted(Arc<VmInner>),
    /// Killed before any boot.
    Discarded(ExitStatus),
}

impl PreparedFake {
    fn require_unused(&self, phase: &Phase) -> Result<()> {
        match phase {
            Phase::Prepared => Ok(()),
            Phase::Booted(vm) => Err(Error::WrongState {
                id: self.record.id.clone(),
                state: vm.state(),
                expected: "a prepared vm that was not booted yet",
            }),
            Phase::Discarded(status) => Err(Error::WrongState {
                id: self.record.id.clone(),
                state: VmState::Exited(*status),
                expected: "a prepared vm that was not discarded",
            }),
        }
    }

    fn require_same_identity(&self, id: &VmId, isolation: &IsolationSpec) -> Result<()> {
        if *id != self.record.id {
            return Err(Error::InvalidSpec(format!(
                "spec id {id} does not match the prepared vm {}",
                self.record.id
            )));
        }
        if *isolation != self.isolation {
            return Err(Error::InvalidSpec(format!(
                "spec isolation does not match what vm {} was prepared with",
                self.record.id
            )));
        }
        Ok(())
    }

    fn launch(&self, spec: VmSpec, balloon_target_bytes: u64) -> Result<Box<dyn VmHandle>> {
        self.require_same_identity(&spec.id, &spec.isolation)?;
        spec.validate()?;
        let mut phase = lock(&self.phase);
        self.require_unused(&phase)?;
        if self
            .driver
            .knobs
            .fail_boot_once
            .swap(false, Ordering::AcqRel)
        {
            return Err(Error::Driver {
                driver: NAME,
                message: "scripted boot failure".into(),
                source: None,
            });
        }
        let vm = self.driver.register(
            spec,
            self.record.clone(),
            balloon_target_bytes,
            Arc::clone(&self.inbound),
        )?;
        *phase = Phase::Booted(Arc::clone(&vm));
        Ok(Box::new(FakeVm::new(vm)))
    }

    /// Kills whatever `phase` says is running: the booted VM, or the bare
    /// process itself.
    fn kill(&self, phase: &mut Phase) -> ExitStatus {
        let status = match phase {
            Phase::Booted(vm) => vm.exit(ExitStatus::signaled(SIGKILL)),
            Phase::Discarded(status) => *status,
            Phase::Prepared => {
                let status = ExitStatus::signaled(SIGKILL);
                *phase = Phase::Discarded(status);
                status
            }
        };
        self.inbound.close(status);
        status
    }
}

impl Drop for PreparedFake {
    fn drop(&mut self) {
        let mut phase = lock(&self.phase);
        if matches!(*phase, Phase::Prepared) {
            self.kill(&mut phase);
        }
    }
}

#[async_trait]
impl PreparedVm for PreparedFake {
    fn id(&self) -> &VmId {
        &self.record.id
    }

    fn record(&self) -> VmRecord {
        self.record.clone()
    }

    fn alive(&self) -> bool {
        match &*lock(&self.phase) {
            Phase::Prepared => true,
            Phase::Booted(vm) => !matches!(vm.state(), VmState::Exited(_)),
            Phase::Discarded(_) => false,
        }
    }

    fn vsock_listener(&self) -> Option<&dyn VsockListen> {
        self.driver.caps.vsock_listen.then_some(self)
    }

    async fn boot(&self, spec: VmSpec) -> Result<Box<dyn VmHandle>> {
        let balloon_target_bytes = u64::from(spec.memory_mib) << 20;
        self.launch(spec, balloon_target_bytes)
    }

    async fn restore(
        &self,
        image: &CheckpointImage,
        spec: RestoreSpec,
    ) -> Result<Box<dyn VmHandle>> {
        if !self.driver.caps.checkpoint || image.format.as_str() != CHECKPOINT_FORMAT {
            return Err(Error::ForeignCheckpoint(image.format.clone()));
        }
        let bytes = tokio::fs::read(image.dir.join("checkpoint.json")).await?;
        let file: CheckpointFile = serde_json::from_slice(&bytes).map_err(std::io::Error::from)?;
        if file.format.as_str() != CHECKPOINT_FORMAT {
            return Err(Error::ForeignCheckpoint(file.format));
        }
        let image_disks: BTreeSet<&str> = file.spec.disks.iter().map(|d| d.id.as_str()).collect();
        let given_disks: BTreeSet<&str> = spec.disks.iter().map(|d| d.id.as_str()).collect();
        if image_disks != given_disks {
            return Err(Error::InvalidSpec(format!(
                "restore disks {given_disks:?} must name exactly the image's disks {image_disks:?}"
            )));
        }
        let mut vm_spec = file.spec;
        vm_spec.id = spec.id;
        vm_spec.nics = spec.nics;
        vm_spec.disks = spec.disks;
        vm_spec.isolation = spec.isolation;
        self.launch(vm_spec, file.balloon_target_bytes)
    }

    async fn discard(&self) -> Result<ExitStatus> {
        Ok(self.kill(&mut lock(&self.phase)))
    }
}

#[async_trait]
impl VsockListen for PreparedFake {
    async fn listen(&self, port: u32) -> Result<Box<dyn VsockListener>> {
        let exited = match &*lock(&self.phase) {
            Phase::Prepared => None,
            Phase::Booted(vm) => match vm.state() {
                VmState::Exited(status) => Some(status),
                VmState::Running | VmState::Quiesced => None,
            },
            Phase::Discarded(status) => Some(*status),
        };
        if let Some(status) = exited {
            return Err(Error::WrongState {
                id: self.record.id.clone(),
                state: VmState::Exited(status),
                expected: "a live prepared vm",
            });
        }
        Ok(Box::new(FakeListener {
            inbound: Arc::clone(&self.inbound),
            port,
        }))
    }
}
