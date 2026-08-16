//! [`FcHandle`]: a running Firecracker VM behind the port's [`VmHandle`],
//! with the vsock, listen, checkpoint, and detach capabilities.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use arcbox_vm_driver::{
    AfterCheckpoint, Checkpoint, CheckpointFormat, CheckpointImage, CheckpointKind,
    CheckpointOptions, Detach, Error, ExitStatus, IoMode, Result, ShutdownMode, VmEvent, VmHandle,
    VmId, VmRecord, VmState, Vsock, VsockConn, VsockListen, VsockListener,
};
use async_trait::async_trait;
use fc_sdk::Client;
use nix::unistd::{Gid, Uid, chown};
use tokio::sync::broadcast;

use crate::error::FcError;
use crate::process::FcProcess;
use crate::render::VmLayout;
use crate::{CHECKPOINT_FORMAT, NAME, api, jail, listener, vsock};

/// How long a graceful shutdown gives the `SendCtrlAltDel` API call itself.
const CTRL_ALT_DEL_TIMEOUT: Duration = Duration::from_secs(5);

/// A running (or just-exited) Firecracker VM.
///
/// Shares its [`FcProcess`] with the prepared VM it was booted on; dropping
/// the handle kills the VM unless [`Detach`] released it.
pub struct FcHandle {
    process: Arc<FcProcess>,
    client: Client,
    layout: VmLayout,
    record: VmRecord,
    /// The vsock socket the host dials, when the VM has a vsock device.
    vsock_uds: Option<PathBuf>,
    /// Frozen after a checkpoint that asked to hold.
    quiesced: AtomicBool,
}

impl FcHandle {
    /// A handle over a VM that is already running on `process`: the API
    /// `client` to drive it, its `layout` (jail, sockets), the `record` it
    /// reports, the vsock socket if the VM has one, and whether the guest
    /// is currently held paused.
    pub fn new(
        process: Arc<FcProcess>,
        client: Client,
        layout: VmLayout,
        record: VmRecord,
        vsock_uds: Option<PathBuf>,
        quiesced: bool,
    ) -> Self {
        Self {
            process,
            client,
            layout,
            record,
            vsock_uds,
            quiesced: AtomicBool::new(quiesced),
        }
    }

    /// Firecracker leaves its vsock Unix socket behind; once the process is
    /// gone the file is ours to remove — a restore that re-binds the
    /// recorded path (direct mode) must find it free.
    fn unlink_vsock(&self) {
        if let Some(uds) = &self.vsock_uds {
            let _ = std::fs::remove_file(uds);
        }
    }

    fn require_state(&self, want: VmState, expected: &'static str) -> Result<()> {
        let state = self.state();
        if state == want {
            Ok(())
        } else {
            Err(Error::WrongState {
                id: self.record.id.clone(),
                state,
                expected,
            })
        }
    }

    fn require_alive(&self) -> Result<VmState> {
        match self.state() {
            state @ VmState::Exited(_) => Err(Error::WrongState {
                id: self.record.id.clone(),
                state,
                expected: "running or quiesced",
            }),
            state => Ok(state),
        }
    }
}

impl Drop for FcHandle {
    fn drop(&mut self) {
        if !self.process.is_detached() {
            self.process.kill_now();
            self.unlink_vsock();
        }
    }
}

#[async_trait]
impl VmHandle for FcHandle {
    fn id(&self) -> &VmId {
        &self.record.id
    }

    fn record(&self) -> VmRecord {
        self.record.clone()
    }

    fn state(&self) -> VmState {
        if let Some(status) = self.process.exit_status() {
            VmState::Exited(status)
        } else if self.quiesced.load(Ordering::Acquire) {
            VmState::Quiesced
        } else {
            VmState::Running
        }
    }

    fn events(&self) -> broadcast::Receiver<VmEvent> {
        self.process.events()
    }

    async fn shutdown(&self, mode: ShutdownMode) -> Result<ExitStatus> {
        let status = match mode {
            ShutdownMode::Kill => self.process.kill().await?,
            ShutdownMode::Graceful { timeout } => match self.process.exit_status() {
                Some(status) => status,
                None => {
                    let deadline = tokio::time::Instant::now() + timeout;
                    // Ask the guest to shut down; errors are ignored — the
                    // VM may already be gone.
                    let _ = tokio::time::timeout(
                        CTRL_ALT_DEL_TIMEOUT.min(timeout),
                        api::send_ctrl_alt_del(&self.client),
                    )
                    .await;
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    match self.process.wait(remaining).await {
                        Some(status) => status,
                        None => {
                            tracing::warn!(vm = %self.record.id, "guest did not shut down in time; killing firecracker");
                            self.process.kill().await?
                        }
                    }
                }
            },
        };
        self.unlink_vsock();
        Ok(status)
    }

    fn vsock(&self) -> Option<&dyn Vsock> {
        self.vsock_uds.is_some().then_some(self)
    }

    fn checkpoint(&self) -> Option<&dyn Checkpoint> {
        Some(self)
    }

    fn vsock_listener(&self) -> Option<&dyn VsockListen> {
        self.vsock_uds.is_some().then_some(self)
    }

    fn detach(&self) -> Option<&dyn Detach> {
        Some(self)
    }
}

#[async_trait]
impl Vsock for FcHandle {
    async fn dial(&self, port: u32) -> Result<VsockConn> {
        self.require_state(VmState::Running, "running")?;
        let uds = self.vsock_uds.as_deref().ok_or_else(|| Error::Driver {
            driver: NAME,
            message: "vm has no vsock device".into(),
            source: None,
        })?;
        let stream = vsock::dial_uds(uds, port).await?;
        Ok(VsockConn {
            fd: stream.into_std()?.into(),
            mode: IoMode::Async,
        })
    }
}

#[async_trait]
impl VsockListen for FcHandle {
    async fn listen(&self, port: u32) -> Result<Box<dyn VsockListener>> {
        listener::bind(&self.layout, &self.process, port)
    }
}

#[async_trait]
impl Detach for FcHandle {
    async fn detach(&self) -> Result<VmRecord> {
        self.process.detach();
        Ok(self.record.clone())
    }
}

/// Where a snapshot is written for Firecracker, and how it reaches `dst`.
enum SnapshotSite {
    /// Firecracker writes straight into `dst`.
    Direct { vmstate: String, mem: String },
    /// Firecracker writes into a jail-local directory, moved to `dst`
    /// afterwards.
    Staged {
        dir: PathBuf,
        vmstate: String,
        mem: String,
    },
}

static SNAPSHOT_SEQ: AtomicU64 = AtomicU64::new(0);

#[async_trait]
impl Checkpoint for FcHandle {
    async fn checkpoint(&self, dst: &Path, opts: CheckpointOptions) -> Result<CheckpointImage> {
        if opts.kind != CheckpointKind::Full {
            return Err(Error::InvalidSpec(format!(
                "{NAME}: diff checkpoints are not supported"
            )));
        }
        let was_quiesced = self.require_alive()? == VmState::Quiesced;
        tokio::fs::create_dir_all(dst).await?;
        let site = self.snapshot_site(dst).await?;

        if !was_quiesced {
            api::pause(&self.client).await?;
        }
        // Everything between pause and resume is fallible; its result is
        // handled only AFTER the guest's state is settled — a bare `?` here
        // would leave the guest paused forever.
        let (vmstate, mem) = match &site {
            SnapshotSite::Direct { vmstate, mem } | SnapshotSite::Staged { vmstate, mem, .. } => {
                (vmstate.as_str(), mem.as_str())
            }
        };
        let captured = api::create_snapshot(&self.client, vmstate, mem).await;
        let hold = captured.is_ok() && opts.after == AfterCheckpoint::HoldQuiesced;
        if hold {
            self.quiesced.store(true, Ordering::Release);
        } else if captured.is_ok() || !was_quiesced {
            // Resume after a successful capture that did not ask to hold,
            // and after any failure that found the guest running.
            api::resume(&self.client).await?;
            self.quiesced.store(false, Ordering::Release);
        }
        captured?;

        if let SnapshotSite::Staged { dir, .. } = &site {
            // The guest is either resumed (files complete, FC flushed them
            // before returning) or deliberately held, so nothing is still
            // writing to them.
            jail::move_file(&dir.join("vmstate"), &dst.join("vmstate")).await?;
            jail::move_file(&dir.join("mem"), &dst.join("mem")).await?;
            let _ = tokio::fs::remove_dir_all(dir).await;
        }
        Ok(CheckpointImage {
            dir: dst.to_path_buf(),
            format: CheckpointFormat::new(CHECKPOINT_FORMAT),
            kind: CheckpointKind::Full,
        })
    }
}

impl FcHandle {
    /// Where Firecracker writes the snapshot: `dst` itself without a jail
    /// or when `dst` is already inside it (chowned so the jailed VMM can
    /// write there), else a fresh `{jail}/snapshots/<n>` to move from.
    async fn snapshot_site(&self, dst: &Path) -> Result<SnapshotSite> {
        let Some(jail) = self.layout.jail() else {
            return Ok(SnapshotSite::Direct {
                vmstate: utf8(&dst.join("vmstate"))?,
                mem: utf8(&dst.join("mem"))?,
            });
        };
        let owned = |dir: &Path| {
            chown(
                dir,
                Some(Uid::from_raw(jail.uid)),
                Some(Gid::from_raw(jail.gid)),
            )
            .map_err(|source| FcError::Chown {
                path: dir.to_path_buf(),
                source,
            })
        };
        if let Some(view) = jail.view(dst) {
            owned(dst)?;
            return Ok(SnapshotSite::Direct {
                vmstate: format!("{view}/vmstate"),
                mem: format!("{view}/mem"),
            });
        }
        let name = format!("ckpt-{}", SNAPSHOT_SEQ.fetch_add(1, Ordering::Relaxed));
        let dir = jail.root.join("snapshots").join(&name);
        tokio::fs::create_dir_all(&dir).await?;
        owned(&dir)?;
        Ok(SnapshotSite::Staged {
            dir,
            vmstate: format!("/snapshots/{name}/vmstate"),
            mem: format!("/snapshots/{name}/mem"),
        })
    }
}

fn utf8(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::InvalidSpec(format!("{NAME}: path {} is not UTF-8", path.display())))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use arcbox_vm_driver::{IsolationSpec, ProcessRecord};

    use super::*;
    use crate::config::FcDriverConfig;
    use crate::process::testing::{pid_exists, spawn};

    /// A handle over a `sleep` child and an API socket nobody answers on.
    fn handle(dir: &Path, isolation: IsolationSpec, vsock: bool) -> FcHandle {
        let id = VmId::new("box").unwrap();
        let mut config = FcDriverConfig::new("/opt/fc/firecracker");
        config.jailer_binary = Some("/opt/fc/jailer".into());
        let layout = VmLayout::new(&id, &isolation, &config, dir).unwrap();
        let process = Arc::new(spawn("sleep", &["30"]));
        let record = VmRecord {
            id,
            driver: NAME.to_owned(),
            runtime_dir: dir.to_path_buf(),
            process: Some(ProcessRecord {
                pid: process.pid(),
                api_socket: Some(layout.api_socket()),
            }),
        };
        let vsock_uds = vsock.then(|| layout.vsock_host_uds());
        FcHandle::new(
            process,
            fc_sdk::connection::connect(dir.join("absent.sock")),
            layout,
            record,
            vsock_uds,
            false,
        )
    }

    fn jail(dir: &Path) -> IsolationSpec {
        IsolationSpec::Jailer {
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
            chroot_base: dir.join("jail"),
            netns: None,
            new_pid_ns: false,
            cgroup: None,
        }
    }

    #[tokio::test]
    async fn state_follows_the_process_and_kill_reports_the_signal() {
        let dir = tempfile::tempdir().unwrap();
        let vm = handle(dir.path(), IsolationSpec::None, true);
        assert_eq!(vm.state(), VmState::Running);
        assert!(vm.vsock().is_some() && vm.vsock_listener().is_some());
        assert!(VmHandle::checkpoint(&vm).is_some() && VmHandle::detach(&vm).is_some());
        let mut events = vm.events();
        let status = vm.shutdown(ShutdownMode::Kill).await.unwrap();
        assert_eq!(status, ExitStatus::signaled(9));
        assert_eq!(vm.state(), VmState::Exited(status));
        assert_eq!(events.recv().await.unwrap(), VmEvent::Exited(status));
        assert!(events.try_recv().is_err());
        // Nothing to dial, listen on, or checkpoint once exited.
        assert!(matches!(
            vm.vsock().unwrap().dial(52).await,
            Err(Error::WrongState { .. })
        ));
        assert!(matches!(
            vm.vsock_listener().unwrap().listen(51).await,
            Err(Error::WrongState { .. })
        ));
        assert!(matches!(
            VmHandle::checkpoint(&vm)
                .unwrap()
                .checkpoint(&dir.path().join("ckpt"), CheckpointOptions::default())
                .await,
            Err(Error::WrongState { .. })
        ));
    }

    #[tokio::test]
    async fn graceful_shutdown_kills_at_the_deadline_when_the_guest_ignores_it() {
        let dir = tempfile::tempdir().unwrap();
        let vm = handle(dir.path(), IsolationSpec::None, false);
        assert!(vm.vsock().is_none() && vm.vsock_listener().is_none());
        let status = vm
            .shutdown(ShutdownMode::Graceful {
                timeout: Duration::from_millis(300),
            })
            .await
            .unwrap();
        assert_eq!(status, ExitStatus::signaled(9));
        assert_eq!(vm.state(), VmState::Exited(status));
    }

    #[tokio::test]
    async fn drop_kills_unless_detached() {
        let dir = tempfile::tempdir().unwrap();
        let vm = handle(dir.path(), IsolationSpec::None, false);
        let pid = vm.record().process.unwrap().pid;
        drop(vm);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!pid_exists(pid), "a dropped handle kills the vm");

        let vm = handle(dir.path(), IsolationSpec::None, false);
        let pid = vm.record().process.unwrap().pid;
        let record = VmHandle::detach(&vm).unwrap().detach().await.unwrap();
        assert_eq!(record, vm.record());
        drop(vm);
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(pid_exists(pid), "a detached vm keeps running");
        #[allow(clippy::cast_possible_wrap, reason = "test pid")]
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn diff_checkpoints_are_refused_before_touching_the_guest() {
        let dir = tempfile::tempdir().unwrap();
        let vm = handle(dir.path(), IsolationSpec::None, false);
        let opts = CheckpointOptions {
            after: AfterCheckpoint::Resume,
            kind: CheckpointKind::Diff,
        };
        assert!(matches!(
            VmHandle::checkpoint(&vm)
                .unwrap()
                .checkpoint(&dir.path().join("ckpt"), opts)
                .await,
            Err(Error::InvalidSpec(_))
        ));
        assert_eq!(vm.state(), VmState::Running);
    }

    #[tokio::test]
    async fn snapshots_are_written_in_place_or_staged_in_the_jail() {
        let dir = tempfile::tempdir().unwrap();
        let vm = handle(dir.path(), IsolationSpec::None, false);
        let dst = dir.path().join("ckpt");
        match vm.snapshot_site(&dst).await.unwrap() {
            SnapshotSite::Direct { vmstate, mem } => {
                assert_eq!(vmstate, dst.join("vmstate").to_str().unwrap());
                assert_eq!(mem, dst.join("mem").to_str().unwrap());
            }
            SnapshotSite::Staged { .. } => panic!("no jail, no staging"),
        }

        let vm = handle(dir.path(), jail(dir.path()), false);
        let root = vm.layout.jail().unwrap().root.clone();
        let inside = root.join("snapshots/abc");
        tokio::fs::create_dir_all(&inside).await.unwrap();
        match vm.snapshot_site(&inside).await.unwrap() {
            SnapshotSite::Direct { vmstate, mem } => {
                assert_eq!(vmstate, "/snapshots/abc/vmstate");
                assert_eq!(mem, "/snapshots/abc/mem");
            }
            SnapshotSite::Staged { .. } => panic!("inside the jail is written in place"),
        }
        let outside = dir.path().join("catalog/ckpt");
        match vm.snapshot_site(&outside).await.unwrap() {
            SnapshotSite::Staged { dir, vmstate, mem } => {
                assert!(dir.starts_with(root.join("snapshots")), "{}", dir.display());
                assert!(dir.is_dir());
                let name = dir.file_name().unwrap().to_str().unwrap().to_owned();
                assert_eq!(vmstate, format!("/snapshots/{name}/vmstate"));
                assert_eq!(mem, format!("/snapshots/{name}/mem"));
            }
            SnapshotSite::Direct { .. } => panic!("outside the jail is staged"),
        }
    }

    #[tokio::test]
    async fn a_listener_fails_once_the_vm_exits() {
        let dir = tempfile::tempdir().unwrap();
        let vm = handle(dir.path(), IsolationSpec::None, true);
        let mut listener = vm.vsock_listener().unwrap().listen(51).await.unwrap();
        assert!(dir.path().join("firecracker.vsock_51").exists());
        let killer = {
            let pid = vm.record().process.unwrap().pid;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                #[allow(clippy::cast_possible_wrap, reason = "test pid")]
                nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                )
                .unwrap();
            })
        };
        let accepted = tokio::time::timeout(Duration::from_secs(10), listener.accept()).await;
        assert!(matches!(accepted, Ok(Err(Error::WrongState { .. }))));
        killer.await.unwrap();
        drop(listener);
        assert!(!dir.path().join("firecracker.vsock_51").exists());
        let _ = PathBuf::new();
    }
}
