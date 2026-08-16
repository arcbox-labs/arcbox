//! An in-memory [`VmDriver`] for tests that need a VM without a hypervisor.

use std::collections::HashMap;
use std::os::unix::net::UnixStream;
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
/// drop) with an events broadcast. `Vsock::dial` returns one end of a
/// socketpair whose other end echoes; `VsockListen` accepts what
/// [`FakeDriver::guest_dial`] pushes; `Console` returns what
/// [`FakeDriver::push_console`] pushed; `Balloon` and `DebugSnapshot` report
/// the VM's own state. [`FakeDriver::builder`] narrows the claimed
/// capabilities — the accessors follow the claims, so the contract can be
/// run against a reduced set.
///
/// The driver's name is `"fake"`.
#[derive(Clone)]
pub struct FakeDriver {
    inner: Arc<DriverInner>,
}

struct DriverInner {
    caps: DriverCapabilities,
    /// Every VM booted and not yet seen exited.
    vms: Mutex<HashMap<VmId, Arc<VmInner>>>,
}

/// Configures a [`FakeDriver`].
#[derive(Debug)]
pub struct FakeDriverBuilder {
    caps: DriverCapabilities,
}

impl FakeDriverBuilder {
    /// Claims exactly `caps`; the handles' accessors follow the claims.
    pub fn capabilities(mut self, caps: DriverCapabilities) -> Self {
        self.caps = caps;
        self
    }

    /// Builds the driver.
    pub fn build(self) -> FakeDriver {
        FakeDriver {
            inner: Arc::new(DriverInner {
                caps: self.caps,
                vms: Mutex::new(HashMap::new()),
            }),
        }
    }
}

impl FakeDriver {
    /// A driver claiming every capability it implements.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// A driver to configure; starts from every implemented capability
    /// claimed.
    pub fn builder() -> FakeDriverBuilder {
        FakeDriverBuilder {
            caps: DriverCapabilities {
                vsock: true,
                vsock_listen: true,
                balloon: true,
                console: true,
                debug: true,
                nested_virt: NestedVirt::unsupported("the fake driver runs no hypervisor"),
                ..DriverCapabilities::default()
            },
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
        let balloon_target_bytes = u64::from(spec.memory_mib) << 20;
        let vm = VmInner::new(spec, record, self.inner.caps.clone(), balloon_target_bytes);
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
        "fake"
    }

    fn capabilities(&self) -> DriverCapabilities {
        self.inner.caps.clone()
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

    use std::io::{Read as _, Write as _};

    use super::*;
    use crate::driver::{ExitStatus, IoMode, ShutdownMode, VmEvent};
    use crate::spec::{BootSpec, ConsoleSpec, VsockSpec};

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

    /// A spec asking for every device the fake implements.
    fn full_spec(id: &str) -> VmSpec {
        VmSpec {
            vsock: Some(VsockSpec { guest_cid: 3 }),
            console: ConsoleSpec::File("/fake/console.log".into()),
            balloon: true,
            ..spec(id)
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

    #[tokio::test]
    async fn accessors_follow_the_spec_and_the_claims() {
        let driver = FakeDriver::new();
        let bare = driver
            .boot(spec("bare"), Path::new("/run/bare"))
            .await
            .unwrap();
        assert!(bare.vsock().is_none() && bare.vsock_listener().is_none());
        assert!(bare.balloon().is_none() && bare.console().is_none());
        assert!(bare.debug().is_some());

        let full = driver
            .boot(full_spec("full"), Path::new("/run/full"))
            .await
            .unwrap();
        assert!(full.vsock().is_some() && full.vsock_listener().is_some());
        assert!(full.balloon().is_some() && full.console().is_some());

        let narrow = FakeDriver::builder()
            .capabilities(DriverCapabilities::default())
            .build();
        let vm = narrow
            .boot(full_spec("narrow"), Path::new("/run/narrow"))
            .await
            .unwrap();
        assert!(vm.vsock().is_none() && vm.debug().is_none() && vm.balloon().is_none());
    }

    #[tokio::test]
    async fn dial_reaches_an_echoing_guest() {
        let driver = FakeDriver::new();
        let vm = driver
            .boot(full_spec("vm-1"), Path::new("/run/vm-1"))
            .await
            .unwrap();
        let conn = vm.vsock().unwrap().dial(1024).await.unwrap();
        assert_eq!(conn.mode, IoMode::Async);
        let mut stream = UnixStream::from(conn.fd);
        stream.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");

        vm.shutdown(ShutdownMode::Kill).await.unwrap();
        assert!(matches!(
            vm.vsock().unwrap().dial(1024).await,
            Err(Error::WrongState { .. })
        ));
    }

    #[tokio::test]
    async fn guest_dial_is_accepted_by_the_listener_in_order() {
        let driver = FakeDriver::new();
        let vm = driver
            .boot(full_spec("vm-1"), Path::new("/run/vm-1"))
            .await
            .unwrap();
        // Pushed before `listen`: the queue is per port, not per listener.
        let mut early = driver.guest_dial(vm.id(), 7).unwrap();
        early.write_all(b"early").unwrap();
        let mut listener = vm.vsock_listener().unwrap().listen(7).await.unwrap();
        let mut first = UnixStream::from(listener.accept().await.unwrap().fd);
        let mut buf = [0u8; 5];
        first.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"early");

        let accept = tokio::spawn(async move { listener.accept().await.map(|c| c.mode) });
        tokio::task::yield_now().await;
        let _late = driver.guest_dial(vm.id(), 7).unwrap();
        assert_eq!(accept.await.unwrap().unwrap(), IoMode::Async);

        vm.shutdown(ShutdownMode::Kill).await.unwrap();
        assert!(matches!(
            driver.guest_dial(vm.id(), 7),
            Err(Error::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn console_hands_out_pushed_bytes_once() {
        let driver = FakeDriver::new();
        let vm = driver
            .boot(full_spec("vm-1"), Path::new("/run/vm-1"))
            .await
            .unwrap();
        driver.push_console(vm.id(), b"hello world").unwrap();
        let console = vm.console().unwrap();
        assert_eq!(console.read_output(5).await.unwrap(), b"hello");
        assert_eq!(console.read_output(64).await.unwrap(), b" world");
        assert!(console.read_output(64).await.unwrap().is_empty());
    }
}
