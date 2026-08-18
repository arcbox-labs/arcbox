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
    /// [`SandboxInstance::net_identity`].
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
    config: &VmmConfig,
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

    use crate::sandbox::types::action;
    use crate::snapshot::SnapshotDraft;

    #[tokio::test]
    async fn pause_is_idempotent_and_gates_on_state() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, _driver, _probe) =
            super::super::testing::fake_manager_direct(dir.path()).await;
        let plant = super::super::testing::plant_computer;

        assert!(matches!(
            manager.pause_sandbox(&"missing".to_owned()).await,
            Err(VmmError::NotFound(_))
        ));

        plant(&manager, "paused", SandboxState::Paused).await;
        manager.pause_sandbox(&"paused".to_owned()).await.unwrap();

        plant(&manager, "busy", SandboxState::Running).await;
        assert!(matches!(
            manager.pause_sandbox(&"busy".to_owned()).await,
            Err(VmmError::WrongState { .. })
        ));

        // Ready but no jailer configured: pause must fail fast before
        // touching anything — a direct-mode pause could never resume.
        plant(&manager, "ready", SandboxState::Ready).await;
        let error = manager
            .pause_sandbox(&"ready".to_owned())
            .await
            .unwrap_err();
        assert!(matches!(error, VmmError::Config(_)), "{error}");
        assert!(error.to_string().contains("jailer"), "{error}");
    }

    /// A pause whose capture succeeded and held the guest, but whose commit
    /// failed, cannot go back to Ready — the port has no thaw — so it fails
    /// the sandbox the way a failed boot does and releases everything it
    /// held: nothing may sit in `Failed` still owning a frozen VMM, its
    /// TAP + IP, its overlay and its chroot until an explicit Remove.
    ///
    /// The fake driver's capture writes `checkpoint.json`, not the vmstate
    /// and mem pair the catalog commits, so with it a `HoldQuiesced` capture
    /// succeeds and the commit that follows fails — exactly this case.
    #[tokio::test]
    async fn pause_that_leaves_the_guest_frozen_fails_and_releases_the_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, driver, probe) = super::super::testing::fake_manager(dir.path()).await;
        let (instance, handle) =
            super::super::testing::live_sandbox(&manager, &driver, "frozen").await;
        let mut events = manager.subscribe_events();

        let error = super::super::testing::expect_err(
            manager.pause_sandbox(&"frozen".to_owned()).await,
            "a pause whose commit fails",
        );
        assert!(
            !matches!(error, VmmError::WrongState { .. }),
            "the commit failure is the reported error: {error}"
        );

        super::super::testing::assert_failed_and_released(&manager, &instance, &probe, "frozen")
            .await;
        assert_eq!(
            handle.state(),
            arcbox_vm_driver::VmState::Exited(arcbox_vm_driver::ExitStatus::signaled(9)),
            "the frozen guest is killed"
        );
        let mut actions = Vec::new();
        while let Ok(event) = events.try_recv() {
            actions.push(event.action);
        }
        assert_eq!(actions, [action::PAUSING, action::FAILED]);
        // Nothing to resume: the sandbox is Failed, not Paused.
        assert!(matches!(
            manager
                .resume_sandbox(&"frozen".to_owned(), reason::RESUME)
                .await,
            Err(VmmError::WrongState { .. })
        ));
    }

    #[tokio::test]
    async fn resume_noops_on_live_states_and_rejects_others() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, _driver, _probe) =
            super::super::testing::fake_manager_direct(dir.path()).await;

        super::super::testing::plant_computer(&manager, "ready", SandboxState::Ready).await;
        assert_eq!(
            manager
                .resume_sandbox(&"ready".to_owned(), reason::RESUME)
                .await
                .unwrap(),
            ""
        );
        super::super::testing::plant_computer(&manager, "running", SandboxState::Running).await;
        manager
            .resume_sandbox(&"running".to_owned(), reason::RESUME)
            .await
            .unwrap();

        super::super::testing::plant_computer(&manager, "stopped", SandboxState::Stopped).await;
        assert!(matches!(
            manager
                .resume_sandbox(&"stopped".to_owned(), reason::RESUME)
                .await,
            Err(VmmError::WrongState { .. })
        ));

        // Paused with no recorded checkpoint is corrupt retained state.
        super::super::testing::plant_computer(&manager, "hollow", SandboxState::Paused).await;
        assert!(matches!(
            manager
                .resume_sandbox(&"hollow".to_owned(), reason::RESUME)
                .await,
            Err(VmmError::Snapshot(_))
        ));
    }

    #[tokio::test]
    async fn data_plane_gates_report_paused_machine_readably() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, _driver, _probe) =
            super::super::testing::fake_manager_direct(dir.path()).await;
        super::super::testing::plant_computer(&manager, "asleep", SandboxState::Paused).await;

        assert!(matches!(
            manager.require_ready_agent(&"asleep".to_owned()),
            Err(VmmError::Paused(id)) if id == "asleep"
        ));
        assert!(matches!(
            manager.require_alive_agent(&"asleep".to_owned()),
            Err(VmmError::Paused(id)) if id == "asleep"
        ));
    }

    #[tokio::test]
    async fn pause_snapshots_are_hidden_and_protected() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, _driver, _probe) =
            super::super::testing::fake_manager_direct(dir.path()).await;

        // Seed a committed pause snapshot plus a user checkpoint.
        let pending = manager.snapshots.begin("box").unwrap();
        std::fs::write(pending.dir().join("vmstate"), b"state").unwrap();
        let pause_meta = pending
            .commit(SnapshotDraft {
                name: Some(PAUSE_SNAPSHOT_NAME.to_owned()),
                labels: HashMap::new(),
                snapshot_type: crate::config::SnapshotType::Full,
                parent_id: None,
                kernel_path: None,
                rootfs_path: None,
                net_invariant: false,
                geometry: None,
                format: super::checkpoint::CHECKPOINT_FORMAT.to_owned(),
            })
            .unwrap();
        let pending = manager.snapshots.begin("box").unwrap();
        std::fs::write(pending.dir().join("vmstate"), b"state").unwrap();
        let user_meta = pending
            .commit(SnapshotDraft {
                name: Some("warm".to_owned()),
                labels: HashMap::new(),
                snapshot_type: crate::config::SnapshotType::Full,
                parent_id: None,
                kernel_path: None,
                rootfs_path: None,
                net_invariant: false,
                geometry: None,
                format: super::checkpoint::CHECKPOINT_FORMAT.to_owned(),
            })
            .unwrap();

        let listed = manager.list_checkpoints(Some("box")).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, user_meta.id);

        assert!(matches!(
            manager.delete_checkpoint(&pause_meta.id).await,
            Err(VmmError::WrongState { .. })
        ));

        delete_pause_snapshots(&manager.snapshots, "box").unwrap();
        assert!(manager.snapshots.find_by_id(&pause_meta.id).is_err());
        assert!(manager.snapshots.find_by_id(&user_meta.id).is_ok());
    }

    /// `List` and `Inspect` must agree on a paused sandbox's footprint.
    /// They resolve the checkpoint differently — `Inspect` by `find_by_id`,
    /// `List` by a linear scan of one `list_all()` so a multi-sandbox
    /// response pays a single catalog read — so a drift in either id match
    /// would silently report 0 on one surface while the other stayed right.
    #[tokio::test]
    async fn list_and_inspect_report_the_same_paused_storage() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, _driver, _probe) =
            super::super::testing::fake_manager_direct(dir.path()).await;

        let pending = manager.snapshots.begin("napper").unwrap();
        std::fs::write(pending.dir().join("vmstate"), vec![0u8; 128 * 1024]).unwrap();
        std::fs::write(pending.dir().join("mem"), vec![0u8; 256 * 1024]).unwrap();
        let meta = pending
            .commit(SnapshotDraft {
                name: Some(PAUSE_SNAPSHOT_NAME.to_owned()),
                labels: HashMap::new(),
                snapshot_type: crate::config::SnapshotType::Full,
                parent_id: None,
                kernel_path: None,
                rootfs_path: None,
                net_invariant: false,
                geometry: None,
                format: super::checkpoint::CHECKPOINT_FORMAT.to_owned(),
            })
            .unwrap();

        // The retained disk overlay, alongside the checkpoint.
        let cow_dir = dir.path().join("cow");
        std::fs::create_dir_all(&cow_dir).unwrap();
        std::fs::write(cow_dir.join("arcbox-cow-napper.img"), vec![0u8; 64 * 1024]).unwrap();

        super::super::testing::plant_computer_with(
            &manager,
            "napper",
            SandboxState::Paused,
            |runtime| runtime.pause_snapshot_id = Some(meta.id),
        )
        .await;
        // A live sandbox reports nothing: the field is retained-state only.
        super::super::testing::plant_computer(&manager, "awake", SandboxState::Ready).await;

        let inspected = manager.inspect_sandbox(&"napper".to_owned()).unwrap();
        let listed = manager.list_sandboxes(None, &HashMap::new()).unwrap();
        let paused = listed.iter().find(|s| s.id == "napper").unwrap();
        let awake = listed.iter().find(|s| s.id == "awake").unwrap();

        assert!(
            inspected.storage_bytes >= (128 + 256 + 64) * 1024,
            "inspect must count the checkpoint and the overlay, got {}",
            inspected.storage_bytes
        );
        assert_eq!(paused.storage_bytes, inspected.storage_bytes);
        assert_eq!(awake.storage_bytes, 0);
    }
}
