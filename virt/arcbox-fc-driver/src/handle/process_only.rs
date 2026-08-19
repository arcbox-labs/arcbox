//! [`FcProcessHandle`]: the port's [`VmHandle`] over a Firecracker process
//! whose API cannot be reached.
//!
//! An adopt verifies a VMM by its process — the pid, its `/proc` identity —
//! and only then reconnects the API. When the socket is missing, wedged, or
//! closes, the process is still a VM this driver owns and must be able to
//! stop: the sandbox manager's restart sweep adopts exactly in order to
//! `shutdown(Kill)`. This handle is that and no more: identify, observe,
//! kill, and detach, all served by the process guard. Nothing that needs
//! the API is offered — no vsock, no listener, no checkpoint — and a
//! `Graceful` shutdown, whose ctrl-alt-del is an API call, kills at once.
//!
//! Staging is offered, though: where a VM's files live is a property of
//! how its VMM was launched, which the adopt read off the process itself,
//! so an unreachable API costs this handle the VM's devices and never the
//! disks staged into its area.

use std::sync::Arc;

use arcbox_vm_driver::{
    Detach, ExitStatus, Result, ShutdownMode, Staging, VmEvent, VmHandle, VmId, VmRecord, VmState,
};
use async_trait::async_trait;
use tokio::sync::broadcast;

use crate::jail::Jail;
use crate::process::FcProcess;
use crate::render::VmLayout;
use crate::staging::JailStaging;

/// A VMM process this driver verified but cannot talk to.
///
/// Dropping the handle kills the process unless [`Detach`] released it,
/// as with [`FcHandle`](crate::FcHandle).
pub struct FcProcessHandle {
    process: Arc<FcProcess>,
    record: VmRecord,
    /// The area this VM runs in, and the layout that names paths in it.
    /// Reachable without the API: where the VMM was launched is a property
    /// of the launch, which the adopt read off the process itself.
    staging: JailStaging,
}

impl FcProcessHandle {
    /// A handle over `process`, reporting `record` and running in the area
    /// `layout` describes.
    pub fn new(process: Arc<FcProcess>, record: VmRecord, layout: VmLayout) -> Self {
        Self {
            process,
            record,
            staging: JailStaging::new(layout),
        }
    }

    /// The jail this VM runs in, when it has one.
    fn jail(&self) -> Option<&Jail> {
        self.staging.layout().jail()
    }
}

impl Drop for FcProcessHandle {
    fn drop(&mut self) {
        if !self.process.is_detached() {
            self.process.kill_now();
        }
    }
}

#[async_trait]
impl VmHandle for FcProcessHandle {
    fn id(&self) -> &VmId {
        &self.record.id
    }

    fn record(&self) -> VmRecord {
        self.record.clone()
    }

    /// `Running` until the process is seen gone: a guest Firecracker holds
    /// paused is indistinguishable from a running one without the API.
    fn state(&self) -> VmState {
        match self.process.exit_status() {
            Some(status) => VmState::Exited(status),
            None => VmState::Running,
        }
    }

    fn events(&self) -> broadcast::Receiver<VmEvent> {
        self.process.events()
    }

    /// `Kill` as for any VM. `Graceful` degrades to it — asking the guest
    /// (`SendCtrlAltDel`) needs the API this handle does not have, and
    /// waiting out the deadline without having asked would gain nothing.
    ///
    /// The jail goes with the kill, on the same rule as
    /// [`FcHandle::shutdown`](crate::FcHandle): every VM reaching this
    /// handle was adopted, so nothing else is left to remove the area it
    /// ran in — unless the VM was handed on instead.
    async fn shutdown(&self, mode: ShutdownMode) -> Result<ExitStatus> {
        if matches!(mode, ShutdownMode::Graceful { .. }) && self.process.alive() {
            tracing::warn!(vm = %self.record.id, pid = self.process.pid(),
                "the vmm's api is unreachable: a graceful shutdown cannot ask the guest and kills it");
        }
        let status = self.process.kill().await?;
        if let Some(jail) = self.jail()
            && !self.process.is_detached()
        {
            jail.remove().await?;
        }
        Ok(status)
    }

    /// Present as on every handle of this driver: releasing the process
    /// needs only the guard.
    fn detach(&self) -> Option<&dyn Detach> {
        Some(self)
    }

    /// Present as on every handle of this driver: bringing a file into the
    /// jail, or taking one back out, is a filesystem operation on a path
    /// the layout names, and asks the VMM nothing.
    fn staging(&self) -> Option<&dyn Staging> {
        Some(&self.staging)
    }
}

#[async_trait]
impl Detach for FcProcessHandle {
    async fn detach(&self) -> Result<VmRecord> {
        self.process.detach();
        Ok(self.record.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use arcbox_vm_driver::{IsolationSpec, ProcessRecord};

    use super::*;
    use crate::NAME;
    use crate::config::FcDriverConfig;
    use crate::process::UNKNOWN_EXIT;

    /// The Firecracker binary the layouts below are built from; only its
    /// file name matters, and it names the jail's middle component.
    const FC_BINARY: &str = "/nonexistent/arcbox-fc-driver/firecracker";

    /// A `sleep` child adopted as a VMM, and the child to reap it with.
    fn adopted() -> (FcProcessHandle, tokio::process::Child) {
        adopted_in(
            &IsolationSpec::None,
            Path::new("/nonexistent/arcbox-fc-driver"),
        )
    }

    /// [`adopted`], confined by `isolation` with `runtime_dir` as its
    /// scratch space — the layout an adopt reads off the process.
    fn adopted_in(
        isolation: &IsolationSpec,
        runtime_dir: &Path,
    ) -> (FcProcessHandle, tokio::process::Child) {
        let child = tokio::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn test child");
        let pid = child.id().unwrap();
        let socket = PathBuf::from("/nonexistent/arcbox-fc-driver/api.sock");
        let id = VmId::new("box").unwrap();
        let record = VmRecord {
            id: id.clone(),
            driver: NAME.to_owned(),
            runtime_dir: runtime_dir.to_path_buf(),
            process: Some(ProcessRecord {
                pid,
                api_socket: Some(socket.clone()),
            }),
        };
        let layout = VmLayout::new(&id, isolation, &FcDriverConfig::new(FC_BINARY), runtime_dir)
            .expect("a layout for the adopted vm");
        let process = Arc::new(FcProcess::adopt(pid, socket));
        (FcProcessHandle::new(process, record, layout), child)
    }

    /// The jail of a VM adopted into `base`.
    fn jailed(base: &Path) -> IsolationSpec {
        IsolationSpec::Jailer {
            uid: 0,
            gid: 0,
            chroot_base: base.to_path_buf(),
            netns: None,
            new_pid_ns: false,
            cgroup: None,
        }
    }

    /// An API this handle cannot reach costs it the VM's devices, never
    /// the area the VM runs in: every VM that reaches this handle was
    /// adopted, so nothing else is left to take the jail down with it.
    #[tokio::test]
    async fn the_jail_goes_with_the_kill_even_without_an_api() {
        let dir = tempfile::tempdir().unwrap();
        let area = dir.path().join("jail/firecracker/box");
        std::fs::create_dir_all(area.join("root")).unwrap();
        let (vm, mut child) = adopted_in(&jailed(&dir.path().join("jail")), dir.path());
        assert_eq!(
            vm.jail().map(|jail| jail.root.clone()),
            Some(area.join("root"))
        );
        let reaper = tokio::spawn(async move { child.wait().await.unwrap() });
        vm.shutdown(ShutdownMode::Kill).await.unwrap();
        assert!(!area.exists(), "the adopted vm's jail goes with the kill");
        reaper.await.unwrap();
    }

    /// The disks in that area are reachable too, which is what lets a
    /// computer running on a staged rootfs be paused after its agent
    /// restarted: taking the disk out needs the area, not the API.
    #[tokio::test]
    async fn a_staged_disk_comes_back_out_without_an_api() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("jail/firecracker/box/root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("rootfs.ext4"), b"the guest's disk").unwrap();
        let (vm, mut child) = adopted_in(&jailed(&dir.path().join("jail")), dir.path());

        let parked = dir.path().join("paused-rootfs.ext4");
        let staging = vm.staging().expect("an adopted vm reaches its own area");
        assert!(staging.unstage_disk("rootfs", &parked).await.unwrap());
        assert_eq!(std::fs::read(&parked).unwrap(), b"the guest's disk");
        assert!(
            !staging.unstage_disk("rootfs", &parked).await.unwrap(),
            "nothing is left to take out"
        );

        child.kill().await.unwrap();
        child.wait().await.unwrap();
    }

    fn signal_of(status: std::process::ExitStatus) -> Option<i32> {
        use std::os::unix::process::ExitStatusExt as _;
        status.signal()
    }

    #[tokio::test]
    async fn kill_reaps_the_process_and_the_state_follows() {
        let (vm, mut child) = adopted();
        assert_eq!(*vm.id(), VmId::new("box").unwrap());
        assert_eq!(vm.record().process.unwrap().pid, child.id().unwrap());
        assert_eq!(vm.state(), VmState::Running);
        // Nothing the API would serve; detach needs only the guard.
        assert!(vm.vsock().is_none() && vm.vsock_listener().is_none());
        assert!(VmHandle::checkpoint(&vm).is_none());
        assert!(vm.balloon().is_none() && vm.console().is_none() && vm.debug().is_none());
        assert!(VmHandle::detach(&vm).is_some());
        assert!(vm.staging().is_some());
        let mut events = vm.events();
        // The real parent reaps once the signal lands.
        let reaper = tokio::spawn(async move { child.wait().await.unwrap() });
        let status = vm.shutdown(ShutdownMode::Kill).await.unwrap();
        assert_eq!(status, UNKNOWN_EXIT);
        assert_eq!(vm.state(), VmState::Exited(status));
        assert_eq!(events.recv().await.unwrap(), VmEvent::Exited(status));
        assert!(events.try_recv().is_err(), "Exited is delivered once");
        assert_eq!(signal_of(reaper.await.unwrap()), Some(9));
        // Idempotent: an exited process just reports its status.
        assert_eq!(vm.shutdown(ShutdownMode::Kill).await.unwrap(), status);
    }

    #[tokio::test]
    async fn graceful_shutdown_kills_at_once_without_waiting_out_the_deadline() {
        let (vm, mut child) = adopted();
        let reaper = tokio::spawn(async move { child.wait().await.unwrap() });
        let started = tokio::time::Instant::now();
        let status = vm
            .shutdown(ShutdownMode::Graceful {
                timeout: Duration::from_secs(60),
            })
            .await
            .unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "killed without waiting for a guest nobody could ask"
        );
        assert_eq!(status, UNKNOWN_EXIT);
        assert_eq!(vm.state(), VmState::Exited(status));
        assert_eq!(signal_of(reaper.await.unwrap()), Some(9));
    }

    #[tokio::test]
    async fn drop_kills_unless_detached() {
        let (vm, mut child) = adopted();
        drop(vm);
        assert_eq!(signal_of(child.wait().await.unwrap()), Some(9));

        let (vm, mut child) = adopted();
        let record = VmHandle::detach(&vm).unwrap().detach().await.unwrap();
        assert_eq!(record, vm.record());
        drop(vm);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            child.try_wait().unwrap().is_none(),
            "a detached process keeps running"
        );
        child.kill().await.unwrap();
        child.wait().await.unwrap();
    }
}
