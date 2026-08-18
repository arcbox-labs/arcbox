//! Pre-warmed restore slots (CORE-78).
//!
//! The fixed host-side setup of a snapshot restore — jailer chroot, the
//! VMM spawn, kernel/vmstate/mem staging, dm-snapshot — costs
//! ~114 ms of the restore RPC. A [`PreparedSlot`] pre-executes exactly
//! that sequence, so a restore that claims one proceeds directly to
//! LoadSnapshot + guest reconfiguration.
//!
//! Slots are keyed by snapshot id and journaled under `pool-<uuid>` ids in
//! the same `sandboxes/` namespace as real sandboxes, so a crash leaves
//! nothing behind that the startup orphan sweep cannot reclaim. TAP and IP
//! allocation deliberately stay in the claim path: the network override at
//! LoadSnapshot time binds a claimed slot to its TAP, which keeps slots
//! network-agnostic (the seam CORE-81 builds on).

use super::boot::{StageError, stage_rootfs_cow_or_copy};
use super::reconcile::{self, POOL_SLOT_PREFIX, SandboxStateRecord};
use super::*;
use crate::config::JailerConfig;
use crate::snapshot::SnapshotMeta;

/// The slot policy — LRU, refill accounting, eviction — lives in
/// [`super::policy::pool`]; re-exported so callers keep naming one
/// `pool::SlotPool`.
pub use super::policy::pool::SlotPool;

/// A fully staged restore slot: the VMM spawned (API socket up, nothing
/// loaded yet), kernel + vmstate + mem staged into the area it reads from,
/// dm-snapshot of the rootfs created.
pub struct PreparedSlot {
    /// Slot id (`pool-<uuid>`): the VM, its dm/CoW names, and its crash
    /// journal are keyed by it.
    pub slot_id: String,
    /// The VMM the driver prepared, waiting for the snapshot load.
    pub prepared: Arc<dyn PreparedVm>,
    /// dm-snapshot of the snapshot's rootfs (`None` = copy fallback).
    pub cow_handle: Option<CowHandle>,
    /// The root disk as staging left it — the path the restore's spec must
    /// name, which is not the caller's to recompute.
    pub rootfs: PathBuf,
    /// The checkpoint as staged for this slot, ready for the driver to
    /// load.
    pub image: CheckpointImage,
    /// Slot runtime dir (`sandboxes/pool-<uuid>`) holding its crash journal.
    pub vm_dir: PathBuf,
}

/// Pre-execute the restore setup sequence for `snapshot`: journal, prepare
/// the jailed VMM through the driver, stage kernel + rootfs (dm-snapshot
/// with copy fallback) + vmstate/mem hard links. A failure unwinds every
/// partial resource before returning.
pub(super) async fn prepare_slot(
    driver: &dyn VmDriver,
    config: &VmmConfig,
    cow_manager: &CowManager,
    snapshot: &SnapshotMeta,
) -> Result<PreparedSlot> {
    let fc_cfg = &config.firecracker;
    let jc = fc_cfg
        .jailer
        .as_ref()
        .ok_or_else(|| VmmError::Config("restore slot pooling requires jailer isolation".into()))?;
    // Short suffix on purpose: the slot id becomes a jailer identity and
    // must fit the API-socket budget (`max_sandbox_id_len`) under any
    // configured chroot layout — internal mints bypass the ingress
    // validator, so they keep themselves comfortably inside it. 16 hex
    // chars keep collisions out of reach for a handful of pool slots;
    // reconcile parses slot ids by prefix, so pre-existing full-UUID
    // journals stay adoptable.
    let mut suffix = Uuid::new_v4().simple().to_string();
    suffix.truncate(16);
    let slot_id = format!("{POOL_SLOT_PREFIX}{suffix}");
    let vm_dir = PathBuf::from(&fc_cfg.data_dir)
        .join("sandboxes")
        .join(&slot_id);

    // Journal before the first external resource exists so a crash
    // mid-prepare is swept like any orphaned sandbox.
    reconcile::create_runtime_dir(&vm_dir)?;
    reconcile::write_state_record(
        &vm_dir,
        &SandboxStateRecord::new(&slot_id, None, None, None, config, None)?,
    )?;

    match stage_slot(driver, config, jc, cow_manager, snapshot, &slot_id, &vm_dir).await {
        Ok(staged) => Ok(PreparedSlot {
            slot_id,
            prepared: staged.prepared,
            cow_handle: staged.cow_handle,
            rootfs: staged.rootfs,
            image: staged.image,
            vm_dir,
        }),
        Err(mut failure) => {
            // Unwind whatever the failed stage acquired; on unwind failure
            // the journal stays for the startup sweep to retry.
            let fc_unwound = match failure.prepared.take() {
                Some(prepared) => match prepared.discard().await {
                    Ok(_) => true,
                    Err(error) => {
                        warn!(slot_id, error = %error, "failed slot prepare left its vmm behind");
                        false
                    }
                },
                None => true,
            };
            let cow_unwound = match failure.cow_handle.take() {
                Some(handle) => match cow_manager.teardown_checked(&handle).await {
                    Ok(()) => true,
                    Err(error) => {
                        warn!(slot_id, error = %error, "failed slot prepare left CoW resources behind");
                        false
                    }
                },
                None => true,
            };
            // The discard above took the area the slot's files were staged
            // into with it, so what is left to unwind is the journal.
            if fc_unwound && cow_unwound {
                if let Err(error) = reconcile::clear_state_record(&vm_dir) {
                    warn!(slot_id, error = %error, "failed slot prepare kept its journal");
                } else {
                    let _ = tokio::fs::remove_dir_all(&vm_dir).await;
                }
            }
            Err(failure.error)
        }
    }
}

struct SlotFailure {
    error: VmmError,
    prepared: Option<Arc<dyn PreparedVm>>,
    cow_handle: Option<CowHandle>,
}

impl From<VmmError> for SlotFailure {
    fn from(error: VmmError) -> Self {
        Self {
            error,
            prepared: None,
            cow_handle: None,
        }
    }
}

/// What [`stage_slot`] pre-executes, and [`PreparedSlot`] then carries.
struct StagedSlot {
    prepared: Arc<dyn PreparedVm>,
    cow_handle: Option<CowHandle>,
    rootfs: PathBuf,
    image: CheckpointImage,
}

async fn stage_slot(
    driver: &dyn VmDriver,
    config: &VmmConfig,
    jc: &JailerConfig,
    cow_manager: &CowManager,
    snapshot: &SnapshotMeta,
    slot_id: &str,
    vm_dir: &Path,
) -> std::result::Result<StagedSlot, SlotFailure> {
    let prepared: Arc<dyn PreparedVm> = Arc::from(
        super::prepare_capability(driver)
            .prepare(
                &VmId::new(slot_id).map_err(VmmError::from)?,
                &IsolationSpec::try_from(jc)?,
                vm_dir,
            )
            .await
            .map_err(VmmError::from)?,
    );
    let pid = super::journaled_pid(&*prepared);
    let journal = |cow: Option<&CowHandle>| {
        reconcile::write_state_record(
            vm_dir,
            &SandboxStateRecord::new(slot_id, pid, None, cow, config, None)?,
        )
    };
    let carry = |error: VmmError, prepared, cow_handle| SlotFailure {
        error,
        prepared,
        cow_handle,
    };
    if let Err(error) = journal(None) {
        return Err(carry(error, Some(prepared), None));
    }

    // Everything the restore would otherwise pay for on its critical path,
    // brought into the area this slot's VMM reads from — under the same
    // names a restore renders, so claiming the slot stages nothing twice.
    let staging = super::staging_capability(&*prepared);
    if let Some(kernel) = snapshot.kernel_path.as_deref() {
        if let Err(error) = staging.stage_kernel(Path::new(kernel)).await {
            return Err(carry(error.into(), Some(prepared), None));
        }
    }

    let Some(rootfs) = snapshot.rootfs_path.as_deref() else {
        return Err(carry(
            VmmError::Snapshot(format!(
                "checkpoint {} records no rootfs template; there is no disk to pre-warm a slot \
                 with",
                snapshot.id
            )),
            Some(prepared),
            None,
        ));
    };
    let staged =
        match stage_rootfs_cow_or_copy(cow_manager, staging, slot_id, rootfs, &journal).await {
            Ok(staged) => staged,
            Err(StageError {
                error,
                cow_handle: leaked,
            }) => return Err(carry(error, Some(prepared), leaked)),
        };

    let image = match super::catalogued_checkpoint(snapshot) {
        Ok(catalogued) => staging
            .stage_checkpoint(&catalogued)
            .await
            .map_err(Into::into),
        Err(error) => Err(error),
    };
    match image {
        Ok(image) => Ok(StagedSlot {
            prepared,
            cow_handle: staged.cow_handle,
            rootfs: staged.path,
            image,
        }),
        Err(error) => Err(carry(error, Some(prepared), staged.cow_handle)),
    }
}

/// Drain and tear down every ready slot staged from one snapshot (or from
/// all of them). Teardown failures are logged and left to the startup
/// sweep — the slots' crash journals keep them reclaimable.
pub(super) async fn drain_pool_slots(
    pool: &SlotPool,
    cow_manager: &CowManager,
    snapshot_id: Option<&str>,
) {
    for slot in pool.drain(snapshot_id) {
        let slot_id = slot.slot_id.clone();
        if let Err(error) = destroy_slot(cow_manager, slot).await {
            warn!(
                slot_id,
                error = %error,
                "pool slot teardown incomplete; the startup sweep will retry"
            );
        }
    }
}

/// Tear down a slot completely: process (and the area its files were
/// staged into, which the discard takes), CoW resources, journal.
///
/// On error the slot's crash journal is left in place so the startup
/// sweep retries; callers log and move on.
pub(super) async fn destroy_slot(cow_manager: &CowManager, mut slot: PreparedSlot) -> Result<()> {
    // The VMM must be dead before the dm teardown (`dmsetup remove` returns
    // EBUSY while the block device is open).
    slot.prepared.discard().await?;
    if let Some(handle) = slot.cow_handle.take() {
        cow_manager.teardown_checked(&handle).await?;
    }
    reconcile::clear_state_record(&slot.vm_dir)?;
    match tokio::fs::remove_dir_all(&slot.vm_dir).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(VmmError::Io(error)),
    }
}

/// Claim a live pre-warmed slot for `snapshot_id`. Slots whose VMM died in
/// the meantime are discarded and torn down in the background.
///
/// A free function, like [`spawn_pool_refill`] below: the restore flow that
/// calls both runs in the computer's actor, while the pool stays
/// manager-wide — it is keyed by *snapshot* and LRU across ids, so it cannot
/// be per-computer.
pub fn claim_restore_slot(
    pool: &SlotPool,
    cow_manager: &Arc<CowManager>,
    snapshot_id: &str,
) -> Option<PreparedSlot> {
    loop {
        let slot = pool.claim(snapshot_id)?;
        if slot.prepared.alive() {
            return Some(slot);
        }
        warn!(
            snapshot_id,
            slot_id = %slot.slot_id,
            "discarding pre-warmed slot whose vmm died"
        );
        spawn_slot_teardown(cow_manager, slot);
    }
}

fn spawn_slot_teardown(cow_manager: &Arc<CowManager>, slot: PreparedSlot) {
    {
        let cow_manager = Arc::clone(cow_manager);
        tokio::spawn(async move {
            let slot_id = slot.slot_id.clone();
            if let Err(error) = destroy_slot(&cow_manager, slot).await {
                warn!(
                    slot_id,
                    error = %error,
                    "pool slot teardown incomplete; the startup sweep will retry"
                );
            }
        });
    }
}

/// Refill the pool for `snapshot_id` up to `firecracker.pool_size` spare
/// slots, in the background. Fired after each successful restore — which is
/// exactly what makes a snapshot "restored at least once" and eligible for
/// pooling — so a failing restore never spawns warm processes in a loop.
pub fn spawn_pool_refill(
    pool: &Arc<SlotPool>,
    driver: &Arc<dyn VmDriver>,
    config: &Arc<VmmConfig>,
    cow_manager: &Arc<CowManager>,
    snapshots: &Arc<SnapshotCatalog>,
    snapshot_id: &str,
) {
    {
        let plan = pool.begin_fill(snapshot_id, config.firecracker.pool_size);
        for slot in plan.evicted {
            spawn_slot_teardown(cow_manager, slot);
        }
        for _ in 0..plan.spawn {
            let pool = Arc::clone(pool);
            let driver = Arc::clone(driver);
            let config = Arc::clone(config);
            let cow_manager = Arc::clone(cow_manager);
            let snapshots = Arc::clone(snapshots);
            let snapshot_id = snapshot_id.to_owned();
            tokio::spawn(async move {
                // Re-resolve the snapshot: it may have been deleted since.
                let staged = match snapshots.find_by_id(&snapshot_id) {
                    Ok(meta) => prepare_slot(driver.as_ref(), &config, &cow_manager, &meta).await,
                    Err(error) => Err(error.into()),
                };
                match staged {
                    Ok(slot) => match pool.offer(&snapshot_id, slot) {
                        None => debug!(snapshot_id, "restore slot pre-warmed"),
                        Some(rejected) => {
                            // Evicted or drained while the fill was in flight.
                            let slot_id = rejected.slot_id.clone();
                            if let Err(error) = destroy_slot(&cow_manager, rejected).await {
                                warn!(
                                    slot_id,
                                    error = %error,
                                    "pool slot teardown incomplete; the startup sweep will retry"
                                );
                            }
                        }
                    },
                    Err(error) => {
                        pool.abandon_fill(&snapshot_id);
                        warn!(snapshot_id, error = %error, "restore slot pre-warm failed");
                    }
                }
            });
        }
    }
}

impl SandboxManager {
    /// Tear down pooled slots: all of them, or those staged from one
    /// snapshot.
    pub(super) async fn drain_pool(&self, snapshot_id: Option<&str>) {
        drain_pool_slots(&self.pool, &self.cow_manager, snapshot_id).await;
    }

    /// Release manager-held background resources: tears down every
    /// pre-warmed restore slot. Live sandboxes are untouched. On a crash
    /// (no shutdown) the startup orphan sweep reclaims slots via their
    /// `pool-<uuid>` crash journals instead.
    pub async fn shutdown(&self) {
        self.drain_pool(None).await;
    }
}
