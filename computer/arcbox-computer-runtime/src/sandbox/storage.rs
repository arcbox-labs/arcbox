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
/// The overlay is named by *both* candidate paths: the snapshot's live COW
/// file when the computer holds one (a slot-adopted computer's is
/// slot-keyed, so the id cannot name it), and the preserved sandbox-id
/// path. Pause atomically renames the former onto the latter, so at most
/// one exists at a time and sizing both never double-counts — while sizing
/// only whichever the snapshot implies would race that rename and read the
/// overlay as absent for the moment between the move and the actor's next
/// snapshot publish.
pub(super) fn retained_artifacts(
    config: &RuntimeConfig,
    id: &SandboxId,
    snapshot: &ComputerSnapshot,
) -> RetainedArtifacts {
    let preserved = super::preserved_cow_file(config, id);
    let live = snapshot
        .cow_file
        .clone()
        .filter(|cow_file| *cow_file != preserved);
    RetainedArtifacts {
        pause_snapshot_id: snapshot.pause_snapshot_id.clone(),
        live_overlay: live,
        preserved_overlay: preserved,
        parked_rootfs: snapshot.vm_dir.join(super::pause::PAUSED_ROOTFS_FILE),
    }
}

/// Where a sandbox's retained state lives on disk.
pub(super) struct RetainedArtifacts {
    /// Catalog id of the internal pause checkpoint (`Paused` only).
    pause_snapshot_id: Option<String>,
    /// The live dm-snapshot overlay, when it is not already the preserved
    /// path (a slot-adopted computer's, until pause renames it).
    live_overlay: Option<PathBuf>,
    /// The overlay's preserved sandbox-id path — the live path for a
    /// computer created under its own id, and where pause parks a
    /// slot-keyed one (absent in copy mode).
    preserved_overlay: PathBuf,
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
            .chain(&self.live_overlay)
            .chain([&self.preserved_overlay, &self.parked_rootfs])
            .fold(0u64, |total, path| total.saturating_add(allocated(path)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::actor::{ComputerSnapshot, Deadlines};

    fn snapshot(vm_dir: &Path, cow_file: Option<PathBuf>) -> ComputerSnapshot {
        ComputerSnapshot {
            state: SandboxState::Ready,
            agent: None,
            handle: None,
            error: None,
            labels: HashMap::new(),
            vcpus: 1,
            memory_mib: 128,
            lease: None,
            vm_dir: vm_dir.to_path_buf(),
            created_at: chrono::Utc::now(),
            ready_at: None,
            last_exited_at: None,
            last_exit_status: None,
            paused_at: None,
            pause_snapshot_id: None,
            cow_file,
            deadlines: Deadlines::default(),
        }
    }

    fn config_over(data_dir: &Path) -> RuntimeConfig {
        let mut config = RuntimeConfig::default();
        config.firecracker.data_dir = data_dir.to_string_lossy().into_owned();
        config
    }

    /// Sizing names *both* overlay candidates. Pause atomically renames a
    /// slot-keyed overlay onto the sandbox-id path before the actor
    /// republishes its snapshot, so a read racing that rename holds a
    /// snapshot whose live path is already empty — the preserved path is
    /// where the bytes are, and sizing only what the snapshot implies would
    /// read the overlay as absent for that moment.
    #[test]
    fn the_overlay_is_found_on_either_side_of_the_pause_rename() {
        let dir = tempfile::tempdir().unwrap();
        let cow_dir = dir.path().join("cow");
        std::fs::create_dir_all(&cow_dir).unwrap();
        let config = config_over(dir.path());
        let id = "napper".to_owned();
        let slot_keyed = cow_dir.join("arcbox-cow-pool-1234.img");

        // Post-rename: the stale snapshot still names the slot path, the
        // file sits at the preserved path.
        std::fs::write(super::super::preserved_cow_file(&config, &id), b"overlay").unwrap();
        let stale = snapshot(dir.path(), Some(slot_keyed.clone()));
        let sized = retained_artifacts(&config, &id, &stale).storage_bytes(|_| Vec::new());
        assert!(sized > 0, "the renamed overlay is still counted");

        // Pre-rename: the same total comes off the slot path.
        std::fs::rename(super::super::preserved_cow_file(&config, &id), &slot_keyed).unwrap();
        let pre = retained_artifacts(&config, &id, &stale).storage_bytes(|_| Vec::new());
        assert_eq!(
            pre, sized,
            "either side of the rename sizes the same overlay"
        );
    }

    /// A computer created under its own id has one overlay path, named by
    /// both candidates — deduplicated, not summed twice.
    #[test]
    fn an_id_keyed_overlay_is_counted_once() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("cow")).unwrap();
        let config = config_over(dir.path());
        let id = "solo".to_owned();
        let overlay = super::super::preserved_cow_file(&config, &id);
        std::fs::write(&overlay, b"overlay").unwrap();
        use std::os::unix::fs::MetadataExt as _;
        let allocated = std::fs::metadata(&overlay).unwrap().blocks() * 512;

        let live = snapshot(dir.path(), Some(overlay));
        let sized = retained_artifacts(&config, &id, &live).storage_bytes(|_| Vec::new());
        assert_eq!(sized, allocated, "the shared path is not double-counted");
    }
}
