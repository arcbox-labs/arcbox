//! The checkpoint sub-task: freezing a computer's guest and committing the
//! image to the catalog.
//!
//! Moved here from `sandbox::checkpoint` by R3 PR-F1d, unchanged: this is the
//! body `Effect::SpawnCheckpoint` names, and that effect's `hold` is this
//! request's `resume_after`, inverted. Its three callers — the Checkpoint
//! RPC, the warm publish, and pause — still drive it directly until R3 PR-F2
//! flips the manager onto the actor.
//!
//! A failure says whether the guest is still usable, and every caller must
//! act on that: `Frozen` means the port has no verb left to thaw it, so the
//! computer fails rather than reporting `Ready` for a guest that answers
//! nothing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use arcbox_vm_driver::{AfterCheckpoint, CheckpointKind, CheckpointOptions, VmHandle};
use tracing::info;

use crate::error::{ComputerError, Result};
use crate::lifecycle::runtime::ComputerRuntime;
use crate::sandbox::policy::settle::{self, Capture, GuestHold, Settlement};
use crate::sandbox::{CheckpointInfo, ComputerId, ComputerState};
use crate::snapshot::{SnapshotCatalog, SnapshotDraft};

/// What a single [`checkpoint_impl`] call should capture, and how it should
/// leave the guest.
pub struct CheckpointRequest {
    /// Catalog name recorded on the committed snapshot.
    pub name: String,
    /// Catalog labels recorded on the committed snapshot.
    pub labels: HashMap<String, String>,
    /// State the instance must be in. The Checkpoint RPC and the warm-create
    /// publisher require `Ready`; pause has already claimed the instance and
    /// moved it to `Pausing` (CORE-21).
    pub expected_state: ComputerState,
    /// Resume the guest once the snapshot files are written.
    ///
    /// False only for pause, whose whole point is that the guest must never
    /// run past the memory image — any progress after it would diverge from
    /// the retained disk overlay; the driver then holds it quiesced.
    pub resume_after: bool,
}

/// Why a checkpoint failed, told by what it left behind — the sandbox's
/// fate depends on that, not on the error itself.
pub enum CheckpointFailure {
    /// The guest is running — the driver resumed it, or the failure came
    /// before the capture — and the sandbox is as usable as it was.
    Recoverable(ComputerError),
    /// The guest is frozen and nothing can thaw it: the driver's own resume
    /// after the capture failed (it settles the guest before reporting, and
    /// this is the case where that settling itself failed), or the capture
    /// held the guest on request and a later step failed. The port has no
    /// resume verb, so the sandbox is unusable and the caller must fail it —
    /// kill, release, durable `Failed` — rather than report it Ready.
    Frozen(ComputerError),
}

impl CheckpointFailure {
    /// The error, for a caller whose next step disposes of the sandbox
    /// either way.
    pub fn into_error(self) -> ComputerError {
        match self {
            Self::Recoverable(error) | Self::Frozen(error) => error,
        }
    }
}

/// What a checkpoint captures from: the VM handle, and what the catalog
/// entry records so a restore can re-stage — kernel/rootfs paths, the
/// guest's addressing mode, the geometry.
struct CheckpointSource {
    kernel_path: String,
    rootfs_path: String,
    net_invariant: bool,
    geometry: crate::snapshot::SnapshotGeometry,
    handle: Arc<dyn VmHandle>,
}

fn checkpoint_source(
    computer: &Arc<Mutex<ComputerRuntime>>,
    computer_id: &ComputerId,
    expected_state: ComputerState,
) -> Result<CheckpointSource> {
    let inst = computer.lock().unwrap();
    if inst.state != expected_state {
        return Err(ComputerError::WrongState {
            id: computer_id.clone(),
            expected: expected_state.to_string(),
            actual: inst.state.to_string(),
        });
    }
    let handle = inst
        .handle
        .clone()
        .ok_or_else(|| ComputerError::WrongState {
            id: computer_id.clone(),
            expected: format!("{expected_state} (VM handle available)"),
            actual: inst.state.to_string(),
        })?;
    Ok(CheckpointSource {
        kernel_path: inst.spec.kernel.clone(),
        rootfs_path: inst.spec.rootfs.clone(),
        net_invariant: inst.net_invariant,
        geometry: crate::snapshot::SnapshotGeometry {
            vcpus: inst.spec.vcpus,
            memory_mib: inst.spec.memory_mib,
        },
        handle,
    })
}

/// Capture a full snapshot of a sandbox into the catalog through the
/// driver's `Checkpoint` capability, which freezes the guest for the capture
/// and (unless the request opts out) resumes it.
///
/// Free-standing (rather than a method) so the boot task can publish warm
/// snapshots (CORE-77) through the exact code path the Checkpoint RPC uses,
/// and so pause (CORE-21) inherits the same addressing-mode handling instead
/// of re-deriving it. A failure says whether the guest is still usable
/// ([`CheckpointFailure`]): every caller must fail the sandbox on `Frozen`.
pub async fn checkpoint_impl(
    computer: &Arc<Mutex<ComputerRuntime>>,
    snapshots: &SnapshotCatalog,
    computer_id: &ComputerId,
    request: CheckpointRequest,
) -> std::result::Result<CheckpointInfo, CheckpointFailure> {
    let resume_after = request.resume_after;
    let source = checkpoint_source(computer, computer_id, request.expected_state)
        .map_err(CheckpointFailure::Recoverable)?;
    let handle = Arc::clone(&source.handle);
    let outcome = capture(snapshots, computer_id, source, request).await;
    let settlement = settle::settlement(
        handle.state(),
        if resume_after {
            GuestHold::Resume
        } else {
            GuestHold::Hold
        },
        if outcome.is_ok() {
            Capture::Succeeded
        } else {
            Capture::Failed
        },
    );
    match (outcome, settlement) {
        (Ok(info), Settlement::AsRequested) => Ok(info),
        (Ok(info), Settlement::Frozen) => {
            Err(CheckpointFailure::Frozen(ComputerError::Process(format!(
                "sandbox {computer_id} stayed frozen after checkpoint {}: the driver could not \
                 resume the guest",
                info.snapshot_id
            ))))
        }
        (Err(error), Settlement::Frozen) => Err(CheckpointFailure::Frozen(error)),
        (Err(error), Settlement::AsRequested) => Err(CheckpointFailure::Recoverable(error)),
    }
}

/// The capture proper: stage, freeze-capture-settle through the driver,
/// commit to the catalog.
async fn capture(
    snapshots: &SnapshotCatalog,
    computer_id: &ComputerId,
    source: CheckpointSource,
    request: CheckpointRequest,
) -> Result<CheckpointInfo> {
    let CheckpointRequest {
        name,
        labels,
        resume_after,
        ..
    } = request;
    // The capability is a property of how the VM was built: the driver
    // checkpoints only jailed VMs, because a restore reopens the disk paths
    // the checkpoint recorded and only a per-VM chroot makes those private.
    let checkpoint = source.handle.checkpoint().ok_or_else(|| {
        ComputerError::FailedPrecondition(format!(
            "sandbox {computer_id} cannot be checkpointed: checkpoints require jailer \
             isolation, and this VM runs without it"
        ))
    })?;

    // Staging directory outside the catalog: the snapshot becomes visible
    // only on commit, and dropping `pending` on any error below takes the
    // directory and whatever partial vmstate/mem it holds with it.
    let pending = snapshots.begin(computer_id)?;

    // The driver owns the freeze: it pauses the guest, writes the capture
    // (into the jail and out to the staging dir), and resumes — or, for
    // pause, holds the guest quiesced — settling the guest before it
    // reports any failure, so a failed capture never leaves the VM paused.
    let image = checkpoint
        .checkpoint(
            &pending.dir(),
            CheckpointOptions {
                after: if resume_after {
                    AfterCheckpoint::Resume
                } else {
                    AfterCheckpoint::HoldQuiesced
                },
                kind: CheckpointKind::Full,
            },
        )
        .await?;

    // Store kernel/rootfs template paths so restore can re-derive them.
    // Jailer mode needs them for chroot staging; direct mode needs the
    // rootfs path to set up a fresh dm-snapshot and retarget the
    // vmstate-recorded symlink.
    let meta = pending.commit(SnapshotDraft {
        name: Some(name),
        labels,
        snapshot_type: crate::config::SnapshotType::Full,
        parent_id: None,
        kernel_path: Some(source.kernel_path),
        rootfs_path: Some(source.rootfs_path),
        net_invariant: source.net_invariant,
        geometry: Some(source.geometry),
        format: image.format.as_str().to_owned(),
    })?;

    let snap_dir_path = meta
        .vmstate_path
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    info!(computer_id, snapshot_id = %meta.id, "sandbox checkpointed");
    Ok(CheckpointInfo {
        snapshot_id: meta.id,
        snapshot_dir: snap_dir_path,
        created_at: meta.created_at.to_rfc3339(),
    })
}
