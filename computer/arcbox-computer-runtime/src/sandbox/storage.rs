//! Storage accounting — the on-disk footprint a sandbox retains, in every
//! state (CORE-146).
//!
//! `storage_bytes` is what an embedder meters disk by, so it must report
//! the retained footprint whatever the sandbox is doing, not only while
//! paused. Its composition per state:
//!
//! - **Running / Ready / Starting**: the live dm-snapshot COW overlay —
//!   the one file a running sandbox's disk writes grow. The shared
//!   template is not counted; a copy-mode sandbox (no overlay) reports 0
//!   until paused, because its private rootfs copy lives inside the VM's
//!   area, which this layer cannot name.
//! - **Paused**: the retained overlay (or the copy-mode rootfs parked in
//!   `vm_dir`) plus the internal pause checkpoint (vmstate + mem).
//!
//! All sizes are allocated blocks, so a sparse overlay is counted at its
//! real cost, and a path that does not exist contributes 0 — sizing is a
//! read, never a failure.

use super::*;
use crate::lifecycle::actor::ComputerSnapshot;

/// Locate the artifacts a sandbox's `storage_bytes` is composed of.
///
/// Pure field reads — no filesystem access. The sizing itself
/// ([`RetainedArtifacts::storage_bytes`]) stats files and, for the
/// checkpoint, needs a catalog lookup, which is why the two halves are
/// separate: the read borrows the actor's `watch` and the sizing must not.
///
/// The overlay is the snapshot's live COW file when the computer holds one
/// (a slot-adopted computer's is slot-keyed, so the id cannot name it), and
/// the preserved sandbox-id path otherwise — after pause detached it, or
/// while nothing exists there yet, in which case it stats to 0.
pub(super) fn retained_artifacts(
    config: &RuntimeConfig,
    id: &SandboxId,
    snapshot: &ComputerSnapshot,
) -> RetainedArtifacts {
    RetainedArtifacts {
        pause_snapshot_id: snapshot.pause_snapshot_id.clone(),
        overlay: snapshot
            .cow_file
            .clone()
            .unwrap_or_else(|| super::preserved_cow_file(config, id)),
        parked_rootfs: snapshot.vm_dir.join(super::pause::PAUSED_ROOTFS_FILE),
    }
}

/// Where a sandbox's retained state lives on disk.
pub(super) struct RetainedArtifacts {
    /// Catalog id of the internal pause checkpoint (`Paused` only).
    pause_snapshot_id: Option<String>,
    /// The dm-snapshot overlay: live while the sandbox holds one, the
    /// preserved sandbox-id path otherwise (absent in copy mode).
    overlay: PathBuf,
    /// Copy-mode fallback: the staged rootfs parked in `vm_dir` by pause.
    parked_rootfs: PathBuf,
}

impl RetainedArtifacts {
    /// Whether sizing these artifacts needs the checkpoint catalog at all —
    /// what lets a listing with no paused row skip the catalog scan.
    pub(super) fn has_checkpoint(&self) -> bool {
        self.pause_snapshot_id.is_some()
    }

    /// On-disk footprint: the disk overlay (or parked copy-mode rootfs)
    /// plus, while paused, the checkpoint (vmstate + mem) — allocated
    /// blocks, so a sparse COW is counted at its real cost.
    ///
    /// `checkpoint_paths` resolves a pause-checkpoint id to its files. A
    /// caller sizing many sandboxes should close over one catalog listing
    /// rather than paying a catalog scan per sandbox.
    pub(super) fn storage_bytes(&self, checkpoint_paths: impl FnOnce(&str) -> Vec<PathBuf>) -> u64 {
        use std::os::unix::fs::MetadataExt as _;

        let allocated = |path: &Path| {
            std::fs::metadata(path).map_or(0, |metadata| metadata.blocks().saturating_mul(512))
        };
        let checkpoint = self
            .pause_snapshot_id
            .as_deref()
            .map(checkpoint_paths)
            .unwrap_or_default();
        checkpoint
            .iter()
            .chain([&self.overlay, &self.parked_rootfs])
            .fold(0u64, |total, path| total.saturating_add(allocated(path)))
    }
}
