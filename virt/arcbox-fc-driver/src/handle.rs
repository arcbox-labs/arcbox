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
        match mode {
            ShutdownMode::Kill => Ok(self.process.kill().await?),
            ShutdownMode::Graceful { timeout } => {
                if let Some(status) = self.process.exit_status() {
                    return Ok(status);
                }
                let deadline = tokio::time::Instant::now() + timeout;
                // Ask the guest to shut down; errors are ignored — the VM
                // may already be gone.
                let _ = tokio::time::timeout(
                    CTRL_ALT_DEL_TIMEOUT.min(timeout),
                    api::send_ctrl_alt_del(&self.client),
                )
                .await;
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if let Some(status) = self.process.wait(remaining).await {
                    return Ok(status);
                }
                tracing::warn!(vm = %self.record.id, "guest did not shut down in time; killing firecracker");
                Ok(self.process.kill().await?)
            }
        }
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
