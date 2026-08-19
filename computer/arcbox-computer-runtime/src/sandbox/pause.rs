//! Pause / Resume — checkpoint a sandbox and release its VM while keeping
//! the record, checkpoint, and disk overlay under the same id (CORE-21).
//!
//! Pause differs from Checkpoint+Stop in two load-bearing ways:
//!
//! - The VM is **not resumed** after the snapshot. Any guest progress after
//!   the memory image is written would diverge from the retained disk, so
//!   the snapshot is the sandbox's final state until Resume.
//! - The disk survives. The dm-snapshot overlay is detached but its
//!   persistent (`P`) COW file stays on disk (or, in copy-mode fallback,
//!   the staged rootfs copy is moved out of the chroot), and Resume
//!   re-assembles exactly the device the memory image expects. A plain
//!   Restore instead builds a fresh overlay from the template, discarding
//!   writes — which is why restoring *from* a pause checkpoint is refused.
//!
//! Resume mirrors the fresh-network restore path: a new TAP + IP is
//! allocated (`RestoreSandboxSpec::network_override` semantics) and the
//! sandbox returns to `Ready` under its original id. The old allocation was
//! quarantined at pause time and its host forwarding state cleaned via the
//! same durable ticket flow Stop uses. Whether the guest needs re-addressing
//! at all depends on the snapshot's addressing mode — an invariant-addressed
//! guest (CORE-81) already holds the fixed link-local identity and only the
//! host-side TAP changes.
//!
//! A sandbox that adopted a pre-warmed restore slot (CORE-78) lives in the
//! slot's chroot with slot-keyed dm/CoW names. Pause releases that chroot and
//! renames the retained overlay onto the sandbox-id path, so from `Paused`
//! onwards every resource is keyed by the sandbox id again and resume,
//! reconciliation, and `Remove` all see one naming scheme.

use super::*;
use crate::lifecycle::actor::{ComputerSnapshot, PauseReason};

/// Reserved catalog name for internal pause checkpoints.
///
/// Everything with this name is lifecycle state owned by the pause
/// machinery: hidden from ListSnapshots, refused by DeleteSnapshot and
/// Restore, rejected as a user checkpoint name, and deleted by Remove.
pub const PAUSE_SNAPSHOT_NAME: &str = "arcbox-pause";

/// Where a copy-mode rootfs is parked inside `vm_dir` while paused.
pub const PAUSED_ROOTFS_FILE: &str = "paused-rootfs.ext4";

/// Reason attribute values for pause/resume events.
pub mod reason {
    /// Client-driven `Pause`.
    pub const PAUSE: &str = "pause";
    /// Idle-detector pause (`on_idle: PAUSE`, CORE-21).
    pub const IDLE_TIMEOUT: &str = "idle_timeout";
    /// Client-driven `Resume`.
    pub const RESUME: &str = "resume";
    /// Daemon-side transparent resume on a data-plane call.
    pub const AUTO_RESUME: &str = "auto_resume";
}

/// Delete every internal pause checkpoint of `sandbox_id`.
///
/// Scans by the reserved name rather than the recorded snapshot id so a
/// checkpoint leaked by an interrupted pause (committed to the catalog but
/// never recorded durably) is cleaned up too.
pub fn delete_pause_snapshots(
    snapshots: &crate::snapshot::SnapshotCatalog,
    sandbox_id: &str,
) -> Result<()> {
    for info in snapshots.list(sandbox_id)? {
        if info.name.as_deref() == Some(PAUSE_SNAPSHOT_NAME) {
            snapshots.delete_by_id(&info.id)?;
        }
    }
    Ok(())
}

/// Runtime resources a successful in-place restore hands back to the
/// instance.
pub struct ResumedRuntime {
    pub prepared: Arc<dyn PreparedVm>,
    pub handle: Arc<dyn VmHandle>,
    pub network: Option<NetworkLease>,
    /// What the resumed guest holds on its interface — see
    /// [`ComputerRuntime::net_identity`].
    pub net_identity: Option<NetworkIdentity>,
    pub cow_handle: Option<CowHandle>,
}

/// How a failed resume left the sandbox.
pub struct ResumeFailure {
    pub error: VmmError,
    /// True when every re-created resource was released again and the
    /// retained pause state (checkpoint + disk) is intact — the sandbox can
    /// go back to `Paused` and a retry can succeed.
    pub unwound: bool,
}

impl SandboxManager {
    /// Pause a `Ready` sandbox: checkpoint it, then release its runtime
    /// resources while keeping the record, checkpoint, and disk overlay
    /// under the same id.
    ///
    /// Idempotent: pausing a `Paused` sandbox is a no-op. Any other state
    /// answers `WrongState` — an active execution must finish (or be
    /// stopped) first, matching the contract's "requires READY".
    pub async fn pause_sandbox(&self, id: &SandboxId) -> Result<()> {
        self.pause_sandbox_with_reason(id, PauseReason::Requested)
            .await
    }

    /// [`Self::pause_sandbox`] with an explicit PAUSING-event reason —
    /// the idle detector reports `idle_timeout` (see [`reason`]).
    pub(super) async fn pause_sandbox_with_reason(
        &self,
        id: &SandboxId,
        reason: PauseReason,
    ) -> Result<()> {
        self.await_reconcile().await?;
        let computer = self.computer(id)?;
        // Resume restores into a fresh jailer chroot; direct-mode vmstate
        // pins origin paths, so a direct-mode pause could never resume. Read
        // off the snapshot rather than left to the flow, because it is a
        // refusal the caller gets *instead* of the claim: only a computer
        // that would otherwise be paused hears it, exactly as today.
        if computer.snapshot.borrow().state == SandboxState::Ready
            && self.config.firecracker.jailer.is_none()
        {
            return Err(VmmError::Config(
                "sandbox pause requires jailer isolation; direct mode cannot resume".into(),
            ));
        }
        computer
            .mailbox
            .ask(id, |reply| Command::Pause { reason, reply })
            .await
    }

    /// Resume a `Paused` sandbox in place: restore from its internal pause
    /// checkpoint with a fresh network allocation, back to `Ready` under
    /// the same id.
    ///
    /// Idempotent: `Ready`/`Running` return the current IP without touching
    /// anything. `reason` is surfaced verbatim as the `RESUMED` event's
    /// "reason" attribute (see [`reason`]).
    ///
    /// Returns the sandbox's (fresh) IP address, empty without networking.
    pub async fn resume_sandbox(&self, id: &SandboxId, resume_reason: &str) -> Result<String> {
        self.await_reconcile().await?;
        let computer = self.computer(id)?;
        computer
            .mailbox
            .ask(id, |reply| Command::Resume {
                reason: resume_reason.to_owned(),
                reply,
            })
            .await?;
        // The lease the resume reserved, read back off the snapshot the
        // actor republished when the flow reported.
        Ok(computer
            .snapshot
            .borrow()
            .lease
            .as_ref()
            .map(|lease| lease.ip.to_string())
            .unwrap_or_default())
    }
}

/// Locate a paused computer's retained artifacts.
///
/// Pure field reads — no filesystem access. The sizing itself
/// ([`PausedArtifacts::storage_bytes`]) stats files and, for the checkpoint,
/// needs a catalog lookup, which is why the two halves are separate: the read
/// borrows the actor's `watch` and the sizing must not.
pub(super) fn paused_artifacts(
    config: &RuntimeConfig,
    id: &SandboxId,
    snapshot: &ComputerSnapshot,
) -> PausedArtifacts {
    PausedArtifacts {
        pause_snapshot_id: snapshot.pause_snapshot_id.clone(),
        preserved_cow: super::preserved_cow_file(config, id),
        parked_rootfs: snapshot.vm_dir.join(PAUSED_ROOTFS_FILE),
    }
}

/// Where a paused computer's retained state lives on disk.
pub(super) struct PausedArtifacts {
    /// Catalog id of the internal pause checkpoint.
    pause_snapshot_id: Option<String>,
    /// Retained dm-snapshot overlay (absent in copy-mode).
    preserved_cow: PathBuf,
    /// Copy-mode fallback: the staged rootfs parked in `vm_dir`.
    parked_rootfs: PathBuf,
}

impl PausedArtifacts {
    /// On-disk footprint: the checkpoint (vmstate + mem) plus the disk
    /// overlay — allocated blocks, so a sparse COW is counted at its real
    /// cost.
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
            .chain([&self.preserved_cow, &self.parked_rootfs])
            .fold(0u64, |total, path| total.saturating_add(allocated(path)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::snapshot::{SnapshotCatalog, SnapshotDraft};

    /// Commit a snapshot of `vm_id` under `name`.
    fn publish(catalog: &SnapshotCatalog, vm_id: &str, name: &str) -> String {
        let pending = catalog.begin(vm_id).unwrap();
        std::fs::write(pending.dir().join("vmstate"), b"vmstate").unwrap();
        pending
            .commit(SnapshotDraft {
                name: Some(name.to_owned()),
                labels: HashMap::new(),
                snapshot_type: crate::config::SnapshotType::Full,
                parent_id: None,
                kernel_path: None,
                rootfs_path: None,
                net_invariant: false,
                geometry: None,
                format: super::checkpoint::CHECKPOINT_FORMAT.to_owned(),
            })
            .unwrap()
            .id
    }

    /// The pause sweep goes by the reserved *name*, not by the id the
    /// record holds — which is the only thing that reaches a checkpoint an
    /// interrupted pause committed to the catalog but never recorded.
    ///
    /// Driven against the catalog directly because that leak has no flow
    /// that produces it: the manager-level half (a pause checkpoint stays
    /// out of `ListSnapshots`, and Remove takes it with the computer) is a
    /// real flow, and lives in `tests/manager_over_fakes.rs`.
    #[test]
    fn the_pause_sweep_deletes_every_reserved_checkpoint_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        let recorded = publish(&catalog, "box", PAUSE_SNAPSHOT_NAME);
        let leaked = publish(&catalog, "box", PAUSE_SNAPSHOT_NAME);
        let user = publish(&catalog, "box", "warm");
        let other = publish(&catalog, "elsewhere", PAUSE_SNAPSHOT_NAME);

        delete_pause_snapshots(&catalog, "box").unwrap();

        assert!(catalog.find_by_id(&recorded).is_err());
        assert!(catalog.find_by_id(&leaked).is_err());
        assert!(catalog.find_by_id(&user).is_ok(), "a user checkpoint stays");
        assert!(
            catalog.find_by_id(&other).is_ok(),
            "another computer's pause state is not this one's to delete"
        );
    }
}
