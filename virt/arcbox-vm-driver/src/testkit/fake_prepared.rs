//! The fake's `Prepare` capability: a "spawned" VMM waiting for a spec.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use super::fake_driver::{DriverInner, NAME};
use super::fake_vm::{CHECKPOINT_FORMAT, CheckpointFile, FakeVm, VmInner};
use super::fake_vsock::{FakeListener, Inbound};
use super::lock;
use crate::capability::{
    CheckpointImage, DiskSource, Prepare, PreparedVm, Staging, VsockListen, VsockListener,
};
use crate::driver::{ExitStatus, ProcessRecord, RestoreSpec, VmHandle, VmRecord, VmState};
use crate::error::{Error, Result};
use crate::spec::{IsolationSpec, VmId, VmSpec};

/// What `discard` reports for a process killed before or after its boot.
const SIGKILL: i32 = 9;

/// `path` with its `.` and `..` components resolved as far as they can be
/// without touching the filesystem.
///
/// Enough for deciding whether a path lands inside a directory: a `..`
/// that walks out of one is what the check exists to catch, and symlinks
/// are beyond what a fake needs to model.
fn lexically_resolved(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !out.pop() {
                    out.push(component);
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// How a staged file gets into the staging area.
#[derive(Debug, Clone, Copy)]
enum Bring {
    /// A stand-in for a device node.
    Device,
    /// A private copy; the source stays.
    Copy,
    /// The source is consumed.
    Move,
}

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

    /// The VM's staging area: a directory of its own under the runtime
    /// dir, standing in for a jail's chroot.
    fn staging_root(&self) -> PathBuf {
        self.record.runtime_dir.join("staged")
    }

    /// Where the disk `id` sits in the staging area.
    ///
    /// Refuses an id that is not a plain name, exactly as a real adapter
    /// must: staging writes and replaces at this path and unstaging moves
    /// what it finds there, so a `..` would reach a file outside the area.
    /// The fake enforces it because it is the reference driver — a gap it
    /// shares with the adapters is a gap no contract check can see.
    fn staged_disk(&self, id: &str) -> Result<PathBuf> {
        let mut components = Path::new(id).components();
        if !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
        {
            return Err(Error::InvalidSpec(format!(
                "disk id `{id}` must be a plain name"
            )));
        }
        Ok(self.staging_root().join(format!("{id}.ext4")))
    }

    /// Brings `src` into the staging area at `dst`, and answers with where
    /// it landed. A source already inside the area is left where it is —
    /// the same short-circuit a real confinement makes.
    async fn bring_in(&self, src: &Path, dst: &Path, how: Bring) -> Result<PathBuf> {
        // Against the resolved path, not the written one: `starts_with`
        // compares components, so `{staged}/../elsewhere` would look like
        // it is already inside the area and be left where it is — and a
        // `Handover` would then report a move that never happened. The
        // answer names where the file is, not how it was spelled.
        let resolved = lexically_resolved(src);
        if resolved.starts_with(self.staging_root()) {
            return Ok(resolved);
        }
        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        match tokio::fs::remove_file(dst).await {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(Error::Io(e)),
            _ => {}
        }
        match how {
            // A device node is not something a fake can make; a symlink is
            // the stand-in, and it is visibly not a copy.
            Bring::Device => tokio::fs::symlink(src, dst).await?,
            Bring::Copy => {
                tokio::fs::copy(src, dst).await?;
            }
            Bring::Move => match tokio::fs::rename(src, dst).await {
                Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
                    tokio::fs::copy(src, dst).await?;
                    tokio::fs::remove_file(src).await?;
                }
                other => other?,
            },
        }
        Ok(dst.to_path_buf())
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

    fn staging(&self) -> Option<&dyn Staging> {
        self.driver.caps.staging.then_some(self)
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

/// Files land in `{runtime_dir}/staged`, under the names a jail would give
/// them: `vmlinux`, `{disk id}.ext4`, `snapshots/{image dir name}`.
#[async_trait]
impl Staging for PreparedFake {
    async fn stage_kernel(&self, src: &Path) -> Result<PathBuf> {
        self.bring_in(src, &self.staging_root().join("vmlinux"), Bring::Copy)
            .await
    }

    async fn stage_disk(&self, id: &str, source: DiskSource<'_>) -> Result<PathBuf> {
        let how = match source {
            DiskSource::Device(_) => Bring::Device,
            DiskSource::Image(_) => Bring::Copy,
            DiskSource::Handover(_) => Bring::Move,
        };
        let into = self.staged_disk(id)?;
        self.bring_in(source.path(), &into, how).await
    }

    async fn unstage_disk(&self, id: &str, dst: &Path) -> Result<bool> {
        let staged = self.staged_disk(id)?;
        if !tokio::fs::try_exists(&staged).await.unwrap_or(false) {
            return Ok(false);
        }
        match tokio::fs::rename(&staged, dst).await {
            Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
                tokio::fs::copy(&staged, dst).await?;
                tokio::fs::remove_file(&staged).await?;
            }
            other => other?,
        }
        Ok(true)
    }

    async fn stage_checkpoint(&self, image: &CheckpointImage) -> Result<CheckpointImage> {
        let root = self.staging_root();
        let resolved = lexically_resolved(&image.dir);
        if resolved.starts_with(&root) {
            return Ok(CheckpointImage {
                dir: resolved,
                ..image.clone()
            });
        }
        let name = image.dir.file_name().ok_or_else(|| {
            Error::InvalidSpec(format!(
                "checkpoint dir {} has no usable name",
                image.dir.display()
            ))
        })?;
        let dir = root.join("snapshots").join(name);
        tokio::fs::create_dir_all(&dir).await?;
        let mut entries = tokio::fs::read_dir(&image.dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_file() {
                tokio::fs::copy(entry.path(), dir.join(entry.file_name())).await?;
            }
        }
        Ok(CheckpointImage {
            dir,
            ..image.clone()
        })
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
