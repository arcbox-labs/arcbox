//! An in-memory [`VmDriver`] for tests that need a VM without a hypervisor.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use super::fake_vm::{FakeVm, VmInner};
use super::lock;
use crate::capability::{Adopt, CheckpointImage};
use crate::driver::{
    DriverCapabilities, NestedVirt, RestoreSpec, VmDriver, VmHandle, VmRecord, VmState,
};
use crate::error::{Error, Result};
use crate::spec::{VmId, VmSpec};

/// An in-memory VM driver.
///
/// VMs are a real state machine (`Running` → `Exited` on shutdown, kill, or
/// drop) with an events broadcast; the capabilities land alongside.
///
/// The driver's name is `"fake"`.
#[derive(Clone)]
pub struct FakeDriver {
    inner: Arc<DriverInner>,
}

struct DriverInner {
    /// Every VM booted and not yet seen exited.
    vms: Mutex<HashMap<VmId, Arc<VmInner>>>,
}

impl FakeDriver {
    /// A driver with no scripted failures.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DriverInner {
                vms: Mutex::new(HashMap::new()),
            }),
        }
    }

    fn register(&self, spec: VmSpec, runtime_dir: &Path) -> Result<Box<dyn VmHandle>> {
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
            driver: self.name().to_owned(),
            runtime_dir: runtime_dir.to_path_buf(),
            process: None,
        };
        let vm = VmInner::new(spec, record);
        vms.insert(vm.id().clone(), Arc::clone(&vm));
        Ok(Box::new(FakeVm::new(vm)))
    }
}

impl Default for FakeDriver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl VmDriver for FakeDriver {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn capabilities(&self) -> DriverCapabilities {
        DriverCapabilities {
            nested_virt: NestedVirt::unsupported("the fake driver runs no hypervisor"),
            ..DriverCapabilities::default()
        }
    }

    async fn boot(&self, spec: VmSpec, runtime_dir: &Path) -> Result<Box<dyn VmHandle>> {
        spec.validate()?;
        self.register(spec, runtime_dir)
    }

    async fn restore(
        &self,
        image: &CheckpointImage,
        _spec: RestoreSpec,
        _runtime_dir: &Path,
    ) -> Result<Box<dyn VmHandle>> {
        Err(Error::ForeignCheckpoint(image.format.clone()))
    }

    fn adopt(&self) -> Option<&dyn Adopt> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::driver::{ExitStatus, ShutdownMode, VmEvent};
    use crate::spec::BootSpec;

    fn spec(id: &str) -> VmSpec {
        VmSpec {
            id: VmId::new(id).unwrap(),
            cpus: 1,
            memory_mib: 64,
            boot: BootSpec::Kernel {
                image: "/fake/vmlinux".into(),
                cmdline: String::new(),
                initrd: None,
            },
            disks: vec![],
            nics: vec![],
            vsock: None,
            shares: vec![],
            console: Default::default(),
            balloon: false,
            entropy: false,
            dirty_tracking: false,
            isolation: Default::default(),
        }
    }

    #[tokio::test]
    async fn shutdown_is_idempotent_and_reports_the_first_status() {
        let driver = FakeDriver::new();
        let vm = driver
            .boot(spec("vm-1"), Path::new("/run/vm-1"))
            .await
            .unwrap();
        let graceful = ShutdownMode::Graceful {
            timeout: Duration::from_secs(1),
        };
        assert_eq!(vm.shutdown(graceful).await.unwrap(), ExitStatus::exited(0));
        assert_eq!(
            vm.shutdown(ShutdownMode::Kill).await.unwrap(),
            ExitStatus::exited(0)
        );
        assert_eq!(vm.state(), VmState::Exited(ExitStatus::exited(0)));
    }

    #[tokio::test]
    async fn dropping_the_handle_kills_the_vm_and_frees_the_id() {
        let driver = FakeDriver::new();
        let vm = driver
            .boot(spec("vm-1"), Path::new("/run/vm-1"))
            .await
            .unwrap();
        let mut events = vm.events();
        drop(vm);
        assert_eq!(
            events.try_recv().unwrap(),
            VmEvent::Exited(ExitStatus::signaled(9))
        );
        // The id is free again: the exited entry is pruned on the way in.
        driver
            .boot(spec("vm-1"), Path::new("/run/vm-1"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_live_id_cannot_be_booted_twice() {
        let driver = FakeDriver::new();
        let _vm = driver
            .boot(spec("vm-1"), Path::new("/run/vm-1"))
            .await
            .unwrap();
        let Err(err) = driver.boot(spec("vm-1"), Path::new("/run/vm-1")).await else {
            panic!("second boot of a live id succeeded");
        };
        assert!(
            matches!(
                err,
                Error::WrongState {
                    state: VmState::Running,
                    ..
                }
            ),
            "{err}"
        );
    }
}
