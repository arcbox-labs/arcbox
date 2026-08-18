//! The fake driver's VM: an in-memory state machine behind a real
//! [`VmHandle`].

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use super::fake_driver::{Knobs, NAME};
use super::fake_vsock::{FakeListener, Inbound, echo_peer};
use super::lock;
use crate::capability::{
    AfterCheckpoint, Balloon, BalloonStats, Checkpoint, CheckpointFormat, CheckpointImage,
    CheckpointKind, CheckpointOptions, Console, DebugSnapshot, Detach, Vsock, VsockListen,
    VsockListener,
};
use crate::driver::{
    DriverCapabilities, ExitStatus, IoMode, ShutdownMode, VmEvent, VmHandle, VmRecord, VmState,
    VsockConn,
};
use crate::error::{Error, Result};
use crate::spec::{ConsoleSpec, VmId, VmSpec};

/// What `shutdown(Kill)` and a killing `Drop` report.
const SIGKILL: i32 = 9;

/// The on-disk format the fake writes and the only one it restores.
pub(super) const CHECKPOINT_FORMAT: &str = "fake/v1";

/// The machine-state file every checkpoint writes, and the one `restore`
/// reads back.
///
/// Named the way a real adapter names it because consumers stage a
/// checkpoint by moving *these two files* — a fake that invented its own
/// name would be restorable only in place, and nothing that stages a
/// checkpoint into a jail could be tested over it.
pub(super) const VMSTATE_FILE: &str = "vmstate";

/// The guest-memory file a full checkpoint writes beside the vmstate. A
/// diff checkpoint writes none, which is the difference a catalog records.
pub(super) const MEM_FILE: &str = "mem";

/// What the fake puts in [`MEM_FILE`]. Fixed and small: it stands for guest
/// memory without costing what guest memory costs, and nothing reads it —
/// a restore replays [`VMSTATE_FILE`].
const MEM_IMAGE: &[u8] = b"fake guest memory\n";

/// The contents of a fake checkpoint's [`VMSTATE_FILE`].
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct CheckpointFile {
    pub(super) format: CheckpointFormat,
    pub(super) kind: CheckpointKind,
    pub(super) spec: VmSpec,
    pub(super) balloon_target_bytes: u64,
}

/// The VM's shared state; the driver's registry and every handle to the VM
/// hold an `Arc` of it.
pub(super) struct VmInner {
    spec: VmSpec,
    record: VmRecord,
    caps: DriverCapabilities,
    knobs: Arc<Knobs>,
    state: Mutex<VmState>,
    /// A live, non-detached handle exists.
    owned: AtomicBool,
    /// This VM came up from a checkpoint rather than from a boot.
    restored: bool,
    events: broadcast::Sender<VmEvent>,
    /// Guest-initiated connections; shared with the prepared process the VM
    /// was booted on, so listeners bound before boot keep working.
    inbound: Arc<Inbound>,
    console: Mutex<Vec<u8>>,
    balloon_target_bytes: AtomicU64,
    /// Every `shutdown` this VM was asked for, in order.
    ///
    /// A killing `Drop` is deliberately not one of them: it goes through
    /// `exit`, so a test can tell a VM that was *asked* to die from one
    /// whose handle merely went out of scope — and the two are different
    /// bugs in a teardown path.
    shutdowns: Mutex<Vec<ShutdownMode>>,
}

impl VmInner {
    pub(super) fn new(
        spec: VmSpec,
        record: VmRecord,
        caps: DriverCapabilities,
        knobs: Arc<Knobs>,
        balloon_target_bytes: u64,
        inbound: Arc<Inbound>,
        restored: bool,
    ) -> Arc<Self> {
        let (events, _) = broadcast::channel(16);
        Arc::new(Self {
            spec,
            record,
            caps,
            knobs,
            state: Mutex::new(VmState::Running),
            owned: AtomicBool::new(false),
            restored,
            events,
            inbound,
            console: Mutex::new(Vec::new()),
            balloon_target_bytes: AtomicU64::new(balloon_target_bytes),
            shutdowns: Mutex::new(Vec::new()),
        })
    }

    pub(super) fn id(&self) -> &VmId {
        &self.spec.id
    }

    pub(super) fn state(&self) -> VmState {
        *lock(&self.state)
    }

    pub(super) fn is_owned(&self) -> bool {
        self.owned.load(Ordering::Acquire)
    }

    pub(super) const fn is_restored(&self) -> bool {
        self.restored
    }

    /// Moves to `Exited(status)` and returns the status the VM ended with:
    /// `status`, or the earlier one if it had already exited.
    pub(super) fn exit(&self, status: ExitStatus) -> ExitStatus {
        {
            let mut state = lock(&self.state);
            if let VmState::Exited(earlier) = *state {
                return earlier;
            }
            *state = VmState::Exited(status);
        }
        // A send error only means nobody is subscribed.
        let _ = self.events.send(VmEvent::Exited(status));
        self.inbound.close(status);
        status
    }

    fn require_running(&self) -> Result<()> {
        match self.state() {
            VmState::Running => Ok(()),
            state => Err(Error::WrongState {
                id: self.spec.id.clone(),
                state,
                expected: "running",
            }),
        }
    }

    fn require_alive(&self) -> Result<()> {
        match self.state() {
            state @ VmState::Exited(_) => Err(Error::WrongState {
                id: self.spec.id.clone(),
                state,
                expected: "running or quiesced",
            }),
            VmState::Running | VmState::Quiesced => Ok(()),
        }
    }

    /// A guest-side connection to host `port`; the host `accept`s it.
    pub(super) fn push_inbound(&self, port: u32, stream: UnixStream) {
        self.inbound.push(port, stream);
    }

    pub(super) fn push_console(&self, bytes: &[u8]) {
        lock(&self.console).extend_from_slice(bytes);
    }

    pub(super) fn shutdowns(&self) -> Vec<ShutdownMode> {
        lock(&self.shutdowns).clone()
    }
}

/// A [`VmHandle`] onto a fake VM.
///
/// Dropping it kills the VM unless it was detached; the driver's registry
/// forgets exited VMs on its next lookup.
pub struct FakeVm {
    vm: Arc<VmInner>,
    checkpointer: Checkpointer,
    ownership: Ownership,
}

impl FakeVm {
    pub(super) fn new(vm: Arc<VmInner>) -> Self {
        vm.owned.store(true, Ordering::Release);
        Self {
            checkpointer: Checkpointer(Arc::clone(&vm)),
            ownership: Ownership {
                vm: Arc::clone(&vm),
                detached: AtomicBool::new(false),
            },
            vm,
        }
    }

    fn has_vsock(&self) -> bool {
        self.vm.spec.vsock.is_some()
    }
}

impl Drop for FakeVm {
    fn drop(&mut self) {
        if !self.ownership.detached.load(Ordering::Acquire) {
            self.vm.exit(ExitStatus::signaled(SIGKILL));
        }
    }
}

#[async_trait]
impl VmHandle for FakeVm {
    fn id(&self) -> &VmId {
        self.vm.id()
    }

    fn record(&self) -> VmRecord {
        self.vm.record.clone()
    }

    fn state(&self) -> VmState {
        self.vm.state()
    }

    fn events(&self) -> broadcast::Receiver<VmEvent> {
        self.vm.events.subscribe()
    }

    async fn shutdown(&self, mode: ShutdownMode) -> Result<ExitStatus> {
        lock(&self.vm.shutdowns).push(mode);
        let status = match mode {
            ShutdownMode::Graceful { .. } => ExitStatus::exited(0),
            ShutdownMode::Kill => ExitStatus::signaled(SIGKILL),
        };
        Ok(self.vm.exit(status))
    }

    fn vsock(&self) -> Option<&dyn Vsock> {
        (self.vm.caps.vsock && self.has_vsock()).then_some(self)
    }

    fn checkpoint(&self) -> Option<&dyn Checkpoint> {
        self.vm.caps.checkpoint.then_some(&self.checkpointer)
    }

    fn vsock_listener(&self) -> Option<&dyn VsockListen> {
        (self.vm.caps.vsock_listen && self.has_vsock()).then_some(self)
    }

    fn detach(&self) -> Option<&dyn Detach> {
        self.vm.caps.adopt.then_some(&self.ownership)
    }

    fn balloon(&self) -> Option<&dyn Balloon> {
        (self.vm.caps.balloon && self.vm.spec.balloon).then_some(self)
    }

    fn console(&self) -> Option<&dyn Console> {
        (self.vm.caps.console && self.vm.spec.console != ConsoleSpec::Off).then_some(self)
    }

    fn debug(&self) -> Option<&dyn DebugSnapshot> {
        self.vm.caps.debug.then_some(self)
    }
}

#[async_trait]
impl Vsock for FakeVm {
    /// Any port answers: the guest side echoes every byte back.
    async fn dial(&self, _port: u32) -> Result<VsockConn> {
        self.vm.require_running()?;
        Ok(VsockConn {
            fd: echo_peer()?.into(),
            mode: IoMode::Async,
        })
    }
}

#[async_trait]
impl VsockListen for FakeVm {
    async fn listen(&self, port: u32) -> Result<Box<dyn VsockListener>> {
        self.vm.require_alive()?;
        Ok(Box::new(FakeListener {
            inbound: Arc::clone(&self.vm.inbound),
            port,
        }))
    }
}

/// The `Checkpoint` capability, on its own type so its `checkpoint` method
/// does not shadow the handle's accessor of the same name.
struct Checkpointer(Arc<VmInner>);

#[async_trait]
impl Checkpoint for Checkpointer {
    async fn checkpoint(&self, dst: &Path, opts: CheckpointOptions) -> Result<CheckpointImage> {
        let vm = &self.0;
        vm.require_alive()?;
        if opts.kind == CheckpointKind::Diff && !vm.caps.diff_checkpoint {
            return Err(Error::Driver {
                driver: NAME,
                message: "diff checkpoints are not enabled on this fake".into(),
                source: None,
            });
        }
        if vm.knobs.fail_checkpoint.swap(false, Ordering::AcqRel) {
            return Err(Error::Driver {
                driver: NAME,
                message: "scripted checkpoint failure".into(),
                source: None,
            });
        }
        // The one failure a caller cannot recover from: the capture is
        // written or not, but the guest is left quiesced where the request
        // asked for it back. Set before reporting, because that is the
        // order the state a caller reads has to be in.
        if vm.knobs.freeze_checkpoint.swap(false, Ordering::AcqRel) {
            {
                let mut state = lock(&vm.state);
                if !matches!(*state, VmState::Exited(_)) {
                    *state = VmState::Quiesced;
                }
            }
            return Err(Error::Driver {
                driver: NAME,
                message: "the guest stays quiesced: it could not be resumed after a failed \
                          checkpoint"
                    .into(),
                source: None,
            });
        }
        let file = CheckpointFile {
            format: CheckpointFormat::new(CHECKPOINT_FORMAT),
            kind: opts.kind,
            spec: vm.spec.clone(),
            balloon_target_bytes: vm.balloon_target_bytes.load(Ordering::Acquire),
        };
        let json = serde_json::to_vec_pretty(&file).map_err(std::io::Error::from)?;
        tokio::fs::create_dir_all(dst).await?;
        tokio::fs::write(dst.join(VMSTATE_FILE), json).await?;
        // A diff checkpoint has no memory image, and a destination that
        // held a full one must not keep it: what a consumer stages is
        // whatever is in the directory, so a stale `mem` would travel with
        // a diff image as if it belonged to it.
        if opts.kind == CheckpointKind::Full {
            tokio::fs::write(dst.join(MEM_FILE), MEM_IMAGE).await?;
        } else if let Err(error) = tokio::fs::remove_file(dst.join(MEM_FILE)).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(Error::Io(error));
        }
        {
            let mut state = lock(&vm.state);
            if !matches!(*state, VmState::Exited(_)) {
                *state = match opts.after {
                    AfterCheckpoint::Resume => VmState::Running,
                    AfterCheckpoint::HoldQuiesced => VmState::Quiesced,
                };
            }
        }
        Ok(CheckpointImage {
            dir: dst.to_path_buf(),
            format: file.format,
            kind: opts.kind,
        })
    }
}

/// The `Detach` capability, on its own type so its `detach` method does not
/// shadow the handle's accessor of the same name.
struct Ownership {
    vm: Arc<VmInner>,
    detached: AtomicBool,
}

#[async_trait]
impl Detach for Ownership {
    async fn detach(&self) -> Result<VmRecord> {
        self.vm.require_alive()?;
        self.detached.store(true, Ordering::Release);
        self.vm.owned.store(false, Ordering::Release);
        Ok(self.vm.record.clone())
    }
}

#[async_trait]
impl Balloon for FakeVm {
    async fn set_target(&self, bytes: u64) -> Result<()> {
        self.vm.require_alive()?;
        self.vm.balloon_target_bytes.store(bytes, Ordering::Release);
        Ok(())
    }

    async fn stats(&self) -> Result<BalloonStats> {
        let target_bytes = self.vm.balloon_target_bytes.load(Ordering::Acquire);
        Ok(BalloonStats {
            target_bytes,
            current_bytes: Some(target_bytes),
        })
    }
}

#[async_trait]
impl Console for FakeVm {
    async fn read_output(&self, max_bytes: usize) -> Result<Vec<u8>> {
        let mut console = lock(&self.vm.console);
        let n = max_bytes.min(console.len());
        Ok(console.drain(..n).collect())
    }
}

impl DebugSnapshot for FakeVm {
    fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "driver": NAME,
            "id": self.vm.id().as_str(),
            "state": self.vm.state().to_string(),
            "balloon_target_bytes": self.vm.balloon_target_bytes.load(Ordering::Acquire),
            "console_pending_bytes": lock(&self.vm.console).len(),
            "inbound_ports": self.vm.inbound.pending_ports(),
        })
    }
}
