//! Pre-warmed restore slots (CORE-78).
//!
//! The fixed host-side setup of a snapshot restore — jailer chroot,
//! Firecracker spawn, kernel/vmstate/mem staging, dm-snapshot — costs
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

/// Most distinct snapshot ids pooled at once. The least recently restored
/// id is evicted — its slots torn down — when a third id starts filling.
const MAX_POOLED_SNAPSHOTS: usize = 2;

/// A fully staged restore slot: jailer chroot prepared, the VMM spawned
/// (API socket up, nothing loaded yet), kernel + vmstate + mem staged,
/// dm-snapshot of the rootfs created.
pub(super) struct PreparedSlot {
    /// Slot id (`pool-<uuid>`): the chroot, dm/CoW names, and crash
    /// journal are keyed by it.
    pub slot_id: String,
    /// The VMM the driver prepared, chrooted into the slot's jail and
    /// waiting for the snapshot load.
    pub prepared: Arc<dyn PreparedVm>,
    /// dm-snapshot of the snapshot's rootfs (`None` = copy fallback).
    pub cow_handle: Option<CowHandle>,
    /// Chroot-relative vmstate path for `SnapshotLoadParams`.
    pub vmstate_path: String,
    /// Chroot-relative mem path, when the snapshot has one.
    pub mem_path: Option<String>,
    /// Host-side vsock UDS path inside the slot's chroot.
    pub vsock_path: PathBuf,
    /// Slot runtime dir (`sandboxes/pool-<uuid>`) holding its crash journal.
    pub vm_dir: PathBuf,
}

/// Refill work computed under the pool lock: how many slot prepares to
/// spawn and which evicted slots to tear down.
pub(super) struct FillPlan<S> {
    pub spawn: usize,
    pub evicted: Vec<S>,
}

/// Slot storage and policy: keyed by snapshot id, capped to
/// [`MAX_POOLED_SNAPSHOTS`] distinct ids (LRU), with in-flight refill
/// accounting. Generic over the slot type so the policy is unit-testable
/// without spawning Firecracker; the lock is never held across an await.
pub(super) struct SlotPool<S = PreparedSlot> {
    inner: Mutex<PoolInner<S>>,
}

struct PoolInner<S> {
    /// Ready slots per snapshot id.
    ready: HashMap<String, Vec<S>>,
    /// In-flight prepare tasks per snapshot id.
    filling: HashMap<String, usize>,
    /// Pooled snapshot ids, least recently restored first. Membership is
    /// the pooling permission: an offer for an id not listed here (evicted
    /// or drained while its fill was in flight) is rejected.
    lru: Vec<String>,
}

impl<S> Default for SlotPool<S> {
    fn default() -> Self {
        Self {
            inner: Mutex::new(PoolInner {
                ready: HashMap::new(),
                filling: HashMap::new(),
                lru: Vec::new(),
            }),
        }
    }
}

impl<S> SlotPool<S> {
    /// Pop a ready slot for `snapshot_id`, refreshing its recency.
    pub fn claim(&self, snapshot_id: &str) -> Option<S> {
        let mut inner = self.inner.lock().unwrap();
        let slot = inner.ready.get_mut(snapshot_id)?.pop()?;
        inner.touch(snapshot_id);
        inner.prune(snapshot_id);
        Some(slot)
    }

    /// Plan a refill of `snapshot_id` up to `target` spare slots,
    /// refreshing its recency and evicting beyond the LRU cap. The caller
    /// must run one prepare per `spawn` (finishing each with [`Self::offer`]
    /// or [`Self::abandon_fill`]) and tear down every evicted slot.
    pub fn begin_fill(&self, snapshot_id: &str, target: usize) -> FillPlan<S> {
        if target == 0 {
            return FillPlan {
                spawn: 0,
                evicted: Vec::new(),
            };
        }
        let mut inner = self.inner.lock().unwrap();
        inner.touch(snapshot_id);
        let ready = inner.ready.get(snapshot_id).map_or(0, Vec::len);
        let filling = inner.filling.get(snapshot_id).copied().unwrap_or(0);
        let spawn = target.saturating_sub(ready + filling);
        if spawn > 0 {
            *inner.filling.entry(snapshot_id.to_owned()).or_default() += spawn;
        }
        let mut evicted = Vec::new();
        while inner.lru.len() > MAX_POOLED_SNAPSHOTS {
            let stale = inner.lru.remove(0);
            evicted.extend(inner.ready.remove(&stale).unwrap_or_default());
            // In-flight fills for the evicted id keep their accounting and
            // get rejected at offer time (the id is no longer listed).
        }
        FillPlan { spawn, evicted }
    }

    /// Deliver a prepared slot. Returns it back for teardown when its
    /// snapshot was evicted or drained while the fill was in flight.
    pub fn offer(&self, snapshot_id: &str, slot: S) -> Option<S> {
        let mut inner = self.inner.lock().unwrap();
        inner.finish_fill(snapshot_id);
        if inner.lru.iter().any(|id| id == snapshot_id) {
            inner
                .ready
                .entry(snapshot_id.to_owned())
                .or_default()
                .push(slot);
            None
        } else {
            Some(slot)
        }
    }

    /// Account a failed fill for `snapshot_id`.
    pub fn abandon_fill(&self, snapshot_id: &str) {
        let mut inner = self.inner.lock().unwrap();
        inner.finish_fill(snapshot_id);
        inner.prune(snapshot_id);
    }

    /// Remove every ready slot for `snapshot_id` (or for all snapshots)
    /// and stop pooling it until the next restore refills.
    pub fn drain(&self, snapshot_id: Option<&str>) -> Vec<S> {
        let mut inner = self.inner.lock().unwrap();
        match snapshot_id {
            Some(id) => {
                inner.lru.retain(|entry| entry != id);
                inner.ready.remove(id).unwrap_or_default()
            }
            None => {
                inner.lru.clear();
                inner.ready.drain().flat_map(|(_, slots)| slots).collect()
            }
        }
    }
}

impl<S> PoolInner<S> {
    /// Move `snapshot_id` to the most-recent end of the LRU list.
    fn touch(&mut self, snapshot_id: &str) {
        self.lru.retain(|id| id != snapshot_id);
        self.lru.push(snapshot_id.to_owned());
    }

    /// Drop the LRU entry when nothing is pooled or filling for the id.
    fn prune(&mut self, snapshot_id: &str) {
        let ready = self.ready.get(snapshot_id).is_some_and(|s| !s.is_empty());
        let filling = self.filling.get(snapshot_id).copied().unwrap_or(0) > 0;
        if !ready && !filling {
            self.ready.remove(snapshot_id);
            self.lru.retain(|id| id != snapshot_id);
        }
    }

    fn finish_fill(&mut self, snapshot_id: &str) {
        if let Some(count) = self.filling.get_mut(snapshot_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.filling.remove(snapshot_id);
            }
        }
    }
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
        &SandboxStateRecord::new(&slot_id, None, None, None, true, None),
    )?;

    match stage_slot(driver, fc_cfg, jc, cow_manager, snapshot, &slot_id, &vm_dir).await {
        Ok((prepared, cow_handle, vmstate_path, mem_path, vsock_path)) => Ok(PreparedSlot {
            slot_id,
            prepared,
            cow_handle,
            vmstate_path,
            mem_path,
            vsock_path,
            vm_dir,
        }),
        Err(mut failure) => {
            // Unwind whatever the failed stage acquired; on unwind failure
            // the journal stays for the startup sweep to retry.
            let fc_unwound = match failure.prepared.take() {
                Some(prepared) => match prepared.discard().await {
                    Ok(_) => true,
                    Err(error) => {
                        warn!(slot_id, error = %error, "failed slot prepare left its firecracker behind");
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
            if fc_unwound && cow_unwound {
                let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
                let chroot = chroot_root(&fc_cfg.binary, base, &slot_id);
                if let Some(parent) = chroot.parent() {
                    let _ = tokio::fs::remove_dir_all(parent).await;
                }
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

type StagedSlot = (
    Arc<dyn PreparedVm>,
    Option<CowHandle>,
    String,
    Option<String>,
    PathBuf,
);

async fn stage_slot(
    driver: &dyn VmDriver,
    fc_cfg: &crate::config::FirecrackerConfig,
    jc: &JailerConfig,
    cow_manager: &CowManager,
    snapshot: &SnapshotMeta,
    slot_id: &str,
    vm_dir: &Path,
) -> std::result::Result<StagedSlot, SlotFailure> {
    let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
    let cr = chroot_root(&fc_cfg.binary, base, slot_id);
    let vsock_path = cr.join("run/firecracker.vsock");

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
            &SandboxStateRecord::new(slot_id, pid, None, cow, true, None),
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

    if let Some(kernel) = snapshot.kernel_path.as_deref() {
        if let Err(error) = stage_kernel_for_jailer(&cr, kernel, jc.uid, jc.gid).await {
            return Err(carry(error.into(), Some(prepared), None));
        }
    }

    let mut cow_handle = None;
    if let Some(rootfs) = snapshot.rootfs_path.as_deref() {
        match stage_rootfs_cow_or_copy(cow_manager, &cr, slot_id, rootfs, jc.uid, jc.gid, &journal)
            .await
        {
            Ok(handle) => cow_handle = handle,
            Err(StageError {
                error,
                cow_handle: leaked,
            }) => return Err(carry(error, Some(prepared), leaked)),
        }
    }

    let files = SnapshotFiles {
        id: &snapshot.id,
        vmstate: &snapshot.vmstate_path,
        mem: snapshot.mem_path.as_deref(),
    };
    match stage_snapshot_files(&cr, &files, jc.uid, jc.gid).await {
        Ok((vmstate_path, mem_path)) => {
            Ok((prepared, cow_handle, vmstate_path, mem_path, vsock_path))
        }
        Err(error) => Err(carry(error.into(), Some(prepared), cow_handle)),
    }
}

/// Drain and tear down every ready slot staged from one snapshot (or from
/// all of them). Teardown failures are logged and left to the startup
/// sweep — the slots' crash journals keep them reclaimable.
pub(super) async fn drain_pool_slots(
    pool: &SlotPool,
    config: &VmmConfig,
    cow_manager: &CowManager,
    snapshot_id: Option<&str>,
) {
    for slot in pool.drain(snapshot_id) {
        let slot_id = slot.slot_id.clone();
        if let Err(error) = destroy_slot(config, cow_manager, slot).await {
            warn!(
                slot_id,
                error = %error,
                "pool slot teardown incomplete; the startup sweep will retry"
            );
        }
    }
}

/// Tear down a slot completely: process, CoW resources, chroot, journal.
///
/// On error the slot's crash journal is left in place so the startup
/// sweep retries; callers log and move on.
pub(super) async fn destroy_slot(
    config: &VmmConfig,
    cow_manager: &CowManager,
    mut slot: PreparedSlot,
) -> Result<()> {
    // The VMM must be dead before the dm teardown (`dmsetup remove` returns
    // EBUSY while the block device is open).
    slot.prepared.discard().await?;
    if let Some(handle) = slot.cow_handle.take() {
        cow_manager.teardown_checked(&handle).await?;
    }
    if let Some(ref jc) = config.firecracker.jailer {
        let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
        let chroot = chroot_root(&config.firecracker.binary, base, &slot.slot_id);
        if let Some(parent) = chroot.parent()
            && let Err(error) = tokio::fs::remove_dir_all(parent).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(VmmError::Io(error));
        }
    }
    reconcile::clear_state_record(&slot.vm_dir)?;
    match tokio::fs::remove_dir_all(&slot.vm_dir).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(VmmError::Io(error)),
    }
}

impl SandboxManager {
    /// Claim a live pre-warmed slot for `snapshot_id`. Slots whose VMM
    /// died in the meantime are discarded and torn down in the background.
    pub(super) fn claim_restore_slot(&self, snapshot_id: &str) -> Option<PreparedSlot> {
        loop {
            let slot = self.pool.claim(snapshot_id)?;
            if slot.prepared.alive() {
                return Some(slot);
            }
            warn!(
                snapshot_id,
                slot_id = %slot.slot_id,
                "discarding pre-warmed slot whose firecracker died"
            );
            self.spawn_slot_teardown(slot);
        }
    }

    fn spawn_slot_teardown(&self, slot: PreparedSlot) {
        let config = Arc::clone(&self.config);
        let cow_manager = Arc::clone(&self.cow_manager);
        tokio::spawn(async move {
            let slot_id = slot.slot_id.clone();
            if let Err(error) = destroy_slot(&config, &cow_manager, slot).await {
                warn!(
                    slot_id,
                    error = %error,
                    "pool slot teardown incomplete; the startup sweep will retry"
                );
            }
        });
    }

    /// Refill the pool for `snapshot_id` up to `firecracker.pool_size`
    /// spare slots, in the background. Fired after each successful
    /// restore — which is exactly what makes a snapshot "restored at
    /// least once" and eligible for pooling — so a failing restore never
    /// spawns warm processes in a loop.
    pub(super) fn spawn_pool_refill(&self, snapshot_id: &str) {
        let plan = self
            .pool
            .begin_fill(snapshot_id, self.config.firecracker.pool_size);
        for slot in plan.evicted {
            self.spawn_slot_teardown(slot);
        }
        for _ in 0..plan.spawn {
            let pool = Arc::clone(&self.pool);
            let driver = Arc::clone(&self.driver);
            let config = Arc::clone(&self.config);
            let cow_manager = Arc::clone(&self.cow_manager);
            let snapshots = Arc::clone(&self.snapshots);
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
                            if let Err(error) = destroy_slot(&config, &cow_manager, rejected).await
                            {
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

    /// Tear down pooled slots: all of them, or those staged from one
    /// snapshot.
    pub(super) async fn drain_pool(&self, snapshot_id: Option<&str>) {
        drain_pool_slots(&self.pool, &self.config, &self.cow_manager, snapshot_id).await;
    }

    /// Release manager-held background resources: tears down every
    /// pre-warmed restore slot. Live sandboxes are untouched. On a crash
    /// (no shutdown) the startup orphan sweep reclaims slots via their
    /// `pool-<uuid>` crash journals instead.
    pub async fn shutdown(&self) {
        self.drain_pool(None).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Policy tests run against `SlotPool<u32>` — the slot type is opaque
    // to the policy, so no Firecracker process is needed.

    /// Refill `snapshot` to `target` and deliver every planned slot as
    /// consecutive values starting at `base`.
    fn fill_and_offer(pool: &SlotPool<u32>, snapshot: &str, target: usize, base: u32) {
        let plan = pool.begin_fill(snapshot, target);
        assert!(plan.evicted.is_empty(), "unexpected eviction while filling");
        for offset in 0..plan.spawn {
            assert!(
                pool.offer(snapshot, base + u32::try_from(offset).unwrap())
                    .is_none()
            );
        }
    }

    #[test]
    fn claims_are_keyed_by_snapshot_id() {
        let pool = SlotPool::<u32>::default();
        fill_and_offer(&pool, "a", 1, 10);

        assert_eq!(pool.claim("other"), None);
        assert_eq!(pool.claim("a"), Some(10));
        assert_eq!(pool.claim("a"), None);
    }

    #[test]
    fn refill_accounts_for_ready_and_in_flight_slots() {
        let pool = SlotPool::<u32>::default();
        let plan = pool.begin_fill("a", 2);
        assert_eq!(plan.spawn, 2);

        // Nothing delivered yet: a concurrent refill must not over-spawn.
        assert_eq!(pool.begin_fill("a", 2).spawn, 0);
        assert!(pool.offer("a", 10).is_none());
        assert!(pool.offer("a", 11).is_none());
        assert_eq!(pool.begin_fill("a", 2).spawn, 0);

        // A claim frees one spare; the next refill replaces exactly it.
        assert_eq!(pool.claim("a"), Some(11));
        assert_eq!(pool.begin_fill("a", 2).spawn, 1);

        // A failed fill releases its accounting for the next refill.
        pool.abandon_fill("a");
        assert_eq!(pool.begin_fill("a", 2).spawn, 1);
    }

    #[test]
    fn pool_size_zero_disables_pooling() {
        let pool = SlotPool::<u32>::default();
        let plan = pool.begin_fill("a", 0);
        assert_eq!(plan.spawn, 0);
        assert!(plan.evicted.is_empty());
        assert_eq!(pool.claim("a"), None);
    }

    #[test]
    fn a_third_snapshot_evicts_the_least_recently_restored() {
        let pool = SlotPool::<u32>::default();
        fill_and_offer(&pool, "a", 1, 10);
        fill_and_offer(&pool, "b", 1, 20);

        let plan = pool.begin_fill("c", 1);
        assert_eq!(plan.spawn, 1);
        assert_eq!(plan.evicted, vec![10], "a's slot must be handed back");
        assert_eq!(pool.claim("a"), None);
        assert_eq!(pool.claim("b"), Some(20));
    }

    #[test]
    fn claiming_refreshes_recency() {
        let pool = SlotPool::<u32>::default();
        fill_and_offer(&pool, "a", 2, 10);
        fill_and_offer(&pool, "b", 1, 20);

        // Restoring from `a` again makes `b` the eviction candidate.
        assert_eq!(pool.claim("a"), Some(11));
        let plan = pool.begin_fill("c", 1);
        assert_eq!(plan.evicted, vec![20]);
        assert_eq!(pool.claim("b"), None);
        assert_eq!(pool.claim("a"), Some(10));
    }

    #[test]
    fn late_offers_for_an_evicted_snapshot_are_rejected() {
        let pool = SlotPool::<u32>::default();
        let plan = pool.begin_fill("a", 1);
        assert_eq!(plan.spawn, 1);
        fill_and_offer(&pool, "b", 1, 20);
        fill_and_offer(&pool, "c", 1, 30); // evicts "a" while its fill is in flight

        assert_eq!(pool.offer("a", 10), Some(10), "must come back for teardown");
        assert_eq!(pool.claim("a"), None);
    }

    #[test]
    fn drain_scopes_to_one_snapshot_or_all() {
        let pool = SlotPool::<u32>::default();
        fill_and_offer(&pool, "a", 2, 10);
        fill_and_offer(&pool, "b", 1, 20);

        let mut drained = pool.drain(Some("a"));
        drained.sort_unstable();
        assert_eq!(drained, vec![10, 11]);
        assert_eq!(pool.claim("a"), None);

        // A fill in flight across the drain is rejected on delivery.
        let plan = pool.begin_fill("a", 1);
        assert_eq!(plan.spawn, 1);
        assert!(pool.drain(Some("a")).is_empty());
        assert_eq!(pool.offer("a", 12), Some(12));

        assert_eq!(pool.drain(None), vec![20]);
        assert_eq!(pool.claim("b"), None);
    }
}
