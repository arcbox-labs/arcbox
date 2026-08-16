//! An in-memory [`VmDriver`] for tests that need a VM without a hypervisor.

use std::collections::{BTreeSet, HashMap};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use super::fake_vm::{CHECKPOINT_FORMAT, CheckpointFile, FakeVm, VmInner};
use super::fake_vsock::Inbound;
use super::lock;
use crate::capability::{Adopt, CheckpointImage};
use crate::driver::{
    DriverCapabilities, NestedVirt, RestoreSpec, VmDriver, VmHandle, VmRecord, VmState,
};
use crate::error::{Error, Result};
use crate::spec::{VmId, VmSpec};

/// Scripted failures, armed once and consumed by the next matching call.
#[derive(Debug, Default)]
pub(super) struct Knobs {
    pub(super) fail_boot_once: AtomicBool,
    pub(super) fail_checkpoint_once: AtomicBool,
}

/// An in-memory VM driver.
///
/// VMs are a real state machine (`Running` → `Quiesced` under
/// `HoldQuiesced` → `Exited` on shutdown, kill, or drop) with an events
/// broadcast, and every capability is implemented: `Vsock::dial` returns
/// one end of a socketpair whose other end echoes; `VsockListen` accepts
/// what [`FakeDriver::guest_dial`] pushes; `Checkpoint` writes a
/// `checkpoint.json` that `restore` reads back; `Adopt`/`Detach` go through
/// the driver's registry; `Console` returns what
/// [`FakeDriver::push_console`] pushed. [`FakeDriver::builder`] scripts
/// failures and narrows the claimed capabilities — the accessors follow
/// the claims, so the contract can be run against a reduced set.
///
/// The driver's name is `"fake"`; its checkpoint format is `"fake/v1"`.
#[derive(Clone)]
pub struct FakeDriver {
    inner: Arc<DriverInner>,
    adopter: Adopter,
}

/// The driver's name, as `VmDriver::name` reports it.
const NAME: &str = "fake";

struct DriverInner {
    caps: DriverCapabilities,
    knobs: Arc<Knobs>,
    /// Every VM booted or restored and not yet seen exited.
    vms: Mutex<HashMap<VmId, Arc<VmInner>>>,
}

/// Configures a [`FakeDriver`].
#[derive(Debug)]
pub struct FakeDriverBuilder {
    caps: DriverCapabilities,
    knobs: Knobs,
}

impl FakeDriverBuilder {
    /// Claims exactly `caps`; the handles' accessors follow the claims.
    pub fn capabilities(mut self, caps: DriverCapabilities) -> Self {
        self.caps = caps;
        self
    }

    /// The next `boot` fails with [`Error::Driver`].
    pub fn fail_boot_once(self) -> Self {
        self.knobs.fail_boot_once.store(true, Ordering::Release);
        self
    }

    /// The next `Checkpoint::checkpoint` on any VM fails with
    /// [`Error::Driver`].
    pub fn fail_checkpoint_once(self) -> Self {
        self.knobs
            .fail_checkpoint_once
            .store(true, Ordering::Release);
        self
    }

    /// Builds the driver.
    pub fn build(self) -> FakeDriver {
        let inner = Arc::new(DriverInner {
            caps: self.caps,
            knobs: Arc::new(self.knobs),
            vms: Mutex::new(HashMap::new()),
        });
        FakeDriver {
            adopter: Adopter(Arc::clone(&inner)),
            inner,
        }
    }
}

impl FakeDriver {
    /// A driver claiming every capability, with no scripted failures.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// A driver to configure; starts from every capability claimed.
    pub fn builder() -> FakeDriverBuilder {
        FakeDriverBuilder {
            caps: DriverCapabilities {
                vsock: true,
                vsock_listen: true,
                checkpoint: true,
                diff_checkpoint: true,
                adopt: true,
                prepare: false,
                balloon: true,
                console: true,
                debug: true,
                nested_virt: NestedVirt::unsupported("the fake driver runs no hypervisor"),
            },
            knobs: Knobs::default(),
        }
    }

    /// The guest side of a vsock connection to host-side `port` on `vm`.
    ///
    /// The returned stream is what the "guest" writes; the host end is
    /// queued for the VM's `VsockListener::accept` on that port (before or
    /// after `listen` — the queue is per port, not per listener).
    pub fn guest_dial(&self, vm: &VmId, port: u32) -> Result<UnixStream> {
        let vm = self.inner.live(vm)?;
        let (host, guest) = UnixStream::pair()?;
        vm.push_inbound(port, host);
        Ok(guest)
    }

    /// Appends `bytes` to what `Console::read_output` returns for `vm`.
    pub fn push_console(&self, vm: &VmId, bytes: &[u8]) -> Result<()> {
        self.inner.live(vm)?.push_console(bytes);
        Ok(())
    }

    fn register(
        &self,
        spec: VmSpec,
        runtime_dir: &Path,
        balloon_target_bytes: u64,
    ) -> Result<Box<dyn VmHandle>> {
        let mut vms = lock(&self.inner.vms);
        if let Some(existing) = vms.get(&spec.id) {
            match existing.state() {
                VmState::Exited(_) => {}
                state => {
                    return Err(Error::WrongState {
                        id: spec.id.clone(),
                        state,
                        expected: "no vm with this id",
                    });
                }
            }
        }
        let record = VmRecord {
            id: spec.id.clone(),
            driver: NAME.to_owned(),
            runtime_dir: runtime_dir.to_path_buf(),
            process: None,
        };
        let inbound = Inbound::new(spec.id.clone());
        let vm = VmInner::new(
            spec,
            record,
            self.inner.caps.clone(),
            Arc::clone(&self.inner.knobs),
            balloon_target_bytes,
            inbound,
        );
        vms.insert(vm.id().clone(), Arc::clone(&vm));
        Ok(Box::new(FakeVm::new(vm)))
    }
}

impl Default for FakeDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl DriverInner {
    /// The VM if it has not exited; an exited entry is forgotten here.
    fn live(&self, id: &VmId) -> Result<Arc<VmInner>> {
        let mut vms = lock(&self.vms);
        match vms.get(id) {
            Some(vm) if !matches!(vm.state(), VmState::Exited(_)) => Ok(Arc::clone(vm)),
            Some(_) => {
                vms.remove(id);
                Err(Error::NotFound(id.clone()))
            }
            None => Err(Error::NotFound(id.clone())),
        }
    }
}

#[async_trait]
impl VmDriver for FakeDriver {
    fn name(&self) -> &'static str {
        NAME
    }

    fn capabilities(&self) -> DriverCapabilities {
        self.inner.caps.clone()
    }

    async fn boot(&self, spec: VmSpec, runtime_dir: &Path) -> Result<Box<dyn VmHandle>> {
        spec.validate()?;
        if self
            .inner
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
        let balloon_target_bytes = u64::from(spec.memory_mib) << 20;
        self.register(spec, runtime_dir, balloon_target_bytes)
    }

    async fn restore(
        &self,
        image: &CheckpointImage,
        spec: RestoreSpec,
        runtime_dir: &Path,
    ) -> Result<Box<dyn VmHandle>> {
        if !self.inner.caps.checkpoint || image.format.as_str() != CHECKPOINT_FORMAT {
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
        vm_spec.validate()?;
        self.register(vm_spec, runtime_dir, file.balloon_target_bytes)
    }

    fn adopt(&self) -> Option<&dyn Adopt> {
        self.inner.caps.adopt.then_some(&self.adopter)
    }
}

/// The `Adopt` capability, on its own type so its `adopt` method does not
/// shadow the driver's accessor of the same name.
#[derive(Clone)]
struct Adopter(Arc<DriverInner>);

#[async_trait]
impl Adopt for Adopter {
    async fn adopt(&self, record: &VmRecord) -> Result<Option<Box<dyn VmHandle>>> {
        let vm = match self.0.live(&record.id) {
            Ok(vm) => vm,
            Err(Error::NotFound(_)) => return Ok(None),
            Err(other) => return Err(other),
        };
        if vm.is_owned() {
            return Err(Error::Driver {
                driver: NAME,
                message: format!("vm {} is still owned by a live handle", record.id),
                source: None,
            });
        }
        Ok(Some(Box::new(FakeVm::new(vm))))
    }
}

#[cfg(test)]
mod tests;
