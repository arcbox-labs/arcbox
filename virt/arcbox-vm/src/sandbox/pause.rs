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

use super::boot::{
    chroot_root, link_or_copy_for_jailer, stage_kernel_for_jailer, stage_rootfs_device_for_jailer,
};
use super::checkpoint::{CheckpointRequest, checkpoint_impl, move_file};
use super::persistence::SandboxTransition;
use super::types::action;
use super::*;

/// Reserved catalog name for internal pause checkpoints.
///
/// Everything with this name is lifecycle state owned by the pause
/// machinery: hidden from ListSnapshots, refused by DeleteSnapshot and
/// Restore, rejected as a user checkpoint name, and deleted by Remove.
pub(super) const PAUSE_SNAPSHOT_NAME: &str = "arcbox-pause";

/// Where a copy-mode rootfs is parked inside `vm_dir` while paused.
pub(super) const PAUSED_ROOTFS_FILE: &str = "paused-rootfs.ext4";

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
pub(super) fn delete_pause_snapshots(
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
struct ResumedRuntime {
    process: fc_sdk::FirecrackerProcess,
    vm: Arc<fc_sdk::Vm>,
    vsock_uds_path: PathBuf,
    network: Option<NetworkAllocation>,
    cow_handle: Option<CowHandle>,
    ip_address: String,
}

/// How a failed resume left the sandbox.
struct ResumeFailure {
    error: VmmError,
    /// True when every re-created resource was released again and the
    /// retained pause state (checkpoint + disk) is intact — the sandbox can
    /// go back to `Paused` and a retry can succeed.
    unwound: bool,
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
        self.pause_sandbox_with_reason(id, reason::PAUSE).await
    }

    /// [`Self::pause_sandbox`] with an explicit PAUSING-event reason —
    /// the idle detector reports `idle_timeout` (see [`reason`]).
    pub(super) async fn pause_sandbox_with_reason(
        &self,
        id: &SandboxId,
        pause_reason: &str,
    ) -> Result<()> {
        self.await_reconcile().await?;
        let instance = self.get_instance(id)?;
        let cleanup_lock = instance.lock().unwrap().cleanup_lock.clone();
        let _cleanup_guard = cleanup_lock.lock().await;
        super::ensure_current_instance(&self.instances, id, &instance)?;

        // Claim `Ready → Pausing` atomically: setting the state in the same
        // critical section as the check means a concurrent Run cannot slip
        // its `Ready → Running` claim in between and end up checkpointed
        // mid-execution.
        let (generation, vm) = {
            let mut inst = instance.lock().unwrap();
            match inst.state {
                SandboxState::Paused => return Ok(()),
                SandboxState::Ready => {}
                s => {
                    return Err(VmmError::WrongState {
                        id: id.clone(),
                        expected: "Ready".into(),
                        actual: s.to_string(),
                    });
                }
            }
            // Resume restores into a fresh jailer chroot; direct-mode
            // vmstate pins origin paths, so a direct-mode pause could never
            // resume. Fail fast before claiming anything.
            if self.config.firecracker.jailer.is_none() {
                return Err(VmmError::Config(
                    "sandbox pause requires jailer isolation; direct mode cannot resume".into(),
                ));
            }
            let vm = inst
                .vm
                .as_ref()
                .map(Arc::clone)
                .ok_or_else(|| VmmError::WrongState {
                    id: id.clone(),
                    expected: "a sandbox with a live VM handle".into(),
                    actual: "no VM handle".into(),
                })?;
            inst.state = SandboxState::Pausing;
            (inst.record_generation, vm)
        };
        let jailer = self
            .config
            .firecracker
            .jailer
            .as_ref()
            .expect("checked in the claim above");

        if let Some(generation) = generation
            && let Err(error) = (|| -> Result<()> {
                let commit = self
                    .records
                    .transition(id, generation, SandboxTransition::Pausing)?;
                if let Some(error) = commit.durability_error {
                    warn!(
                        sandbox_id = %id,
                        error,
                        "pausing transition is visible but durability is unconfirmed"
                    );
                }
                Ok(())
            })()
        {
            // The durable claim failed: release the in-memory claim so the
            // sandbox stays usable.
            instance.lock().unwrap().state = SandboxState::Ready;
            return Err(error);
        }
        let _ = self
            .events_tx
            .send(SandboxEvent::new(id, action::PAUSING).with_attr("reason", pause_reason));

        // Checkpoint through the shared implementation — it owns the
        // chroot-owner (pool slot) and addressing-mode bookkeeping — but with
        // the resume suppressed: guest progress past the memory image would
        // diverge from the retained disk overlay. On failure the VM is
        // resumed here and the sandbox reverts to Ready, because a failed
        // pause must leave a usable sandbox behind.
        let snapshot_id = match checkpoint_impl(
            &self.instances,
            &self.snapshots,
            &self.config,
            id,
            CheckpointRequest {
                name: PAUSE_SNAPSHOT_NAME.to_owned(),
                labels: HashMap::new(),
                expected_state: SandboxState::Pausing,
                resume_after: false,
            },
        )
        .await
        {
            Ok(info) => info.snapshot_id,
            Err(error) => {
                let _ = vm.resume().await;
                if let Some(generation) = generation
                    && let Err(revert) =
                        self.records
                            .transition(id, generation, SandboxTransition::Ready)
                {
                    warn!(sandbox_id = %id, error = %revert, "pause revert transition failed");
                }
                instance.lock().unwrap().state = SandboxState::Ready;
                let _ = self.events_tx.send(SandboxEvent::new(id, action::READY));
                return Err(error);
            }
        };
        // Deliberately no `vm.resume()` on success: guest progress after the
        // snapshot would diverge from the retained disk overlay.

        // Release the VM, TAP + IP (quarantined for host cleanup), and
        // chroot; keep the disk. A failure here is a half-released sandbox
        // whose VM state is already gone — degrade honestly to Failed.
        if let Err(error) = self.release_for_pause(id, &instance, jailer).await {
            if let Some(generation) = generation
                && let Err(mark) = self.records.transition(
                    id,
                    generation,
                    SandboxTransition::Failed(error.to_string()),
                )
            {
                warn!(sandbox_id = %id, error = %mark, "pause failure transition failed");
            }
            {
                let mut inst = instance.lock().unwrap();
                inst.state = SandboxState::Failed;
                inst.error = Some(error.to_string());
            }
            let _ = self
                .events_tx
                .send(SandboxEvent::new(id, action::FAILED).with_attr("error", &error.to_string()));
            return Err(error);
        }

        let paused_commit = generation
            .map(|generation| {
                self.records.transition(
                    id,
                    generation,
                    SandboxTransition::Paused {
                        snapshot_id: snapshot_id.clone(),
                    },
                )
            })
            .transpose()?;
        {
            let mut inst = instance.lock().unwrap();
            inst.state = SandboxState::Paused;
            inst.paused_at = Some(Utc::now());
            inst.pause_snapshot_id = Some(snapshot_id.clone());
            inst.vm = None;
            inst.vsock_uds_path = None;
            if paused_commit
                .as_ref()
                .is_none_or(|commit| commit.durability_error.is_none())
            {
                // Every runtime resource is released and Paused is durable;
                // what remains on disk is retained state, not orphans.
                super::reconcile::clear_state_record(&inst.vm_dir)?;
            }
        }
        let _ = self.events_tx.send(SandboxEvent::new(id, action::PAUSED));
        info!(sandbox_id = %id, snapshot_id = %snapshot_id, "sandbox paused");
        paused_commit
            .map(|commit| commit.confirmed("sandbox pause"))
            .transpose()?;
        Ok(())
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
        let instance = self.get_instance(id)?;
        let cleanup_lock = instance.lock().unwrap().cleanup_lock.clone();
        let _cleanup_guard = cleanup_lock.lock().await;
        super::ensure_current_instance(&self.instances, id, &instance)?;

        let (generation, snapshot_id, vm_dir, networked) = {
            let inst = instance.lock().unwrap();
            match inst.state {
                SandboxState::Ready | SandboxState::Running => {
                    return Ok(inst
                        .network
                        .as_ref()
                        .map(|n| n.ip_address.to_string())
                        .unwrap_or_default());
                }
                SandboxState::Paused => {}
                s => {
                    return Err(VmmError::WrongState {
                        id: id.clone(),
                        expected: "Paused".into(),
                        actual: s.to_string(),
                    });
                }
            }
            let snapshot_id = inst.pause_snapshot_id.clone().ok_or_else(|| {
                VmmError::Snapshot(format!(
                    "paused sandbox {id} has no pause checkpoint recorded"
                ))
            })?;
            (
                inst.record_generation,
                snapshot_id,
                inst.vm_dir.clone(),
                inst.spec.network.mode != "none",
            )
        };
        let jailer =
            self.config.firecracker.jailer.as_ref().ok_or_else(|| {
                VmmError::Config("sandbox resume requires jailer isolation".into())
            })?;
        let snap_meta = self.snapshots.find_by_id(&snapshot_id)?;

        if let Some(generation) = generation {
            let commit = self
                .records
                .transition(id, generation, SandboxTransition::Resuming)?;
            if let Some(error) = commit.durability_error {
                // The restart sweep trusts the durable phase: were Resuming to
                // stay unconfirmed on disk, a crash mid-restore would read as
                // cleanly Paused and the restore's journaled TAP/IP/chroot
                // would be dropped as a stale pause journal, never released.
                // Park back at Paused and fail before allocating anything —
                // the mirror of the pause path's durability-gated journal
                // clear.
                if let Err(revert) = self.records.transition(
                    id,
                    generation,
                    SandboxTransition::Paused {
                        snapshot_id: snapshot_id.clone(),
                    },
                ) {
                    warn!(sandbox_id = %id, error = %revert, "resume durability revert failed");
                }
                return Err(VmmError::Unavailable(format!(
                    "sandbox resume is visible but its durability is unconfirmed: {error}"
                )));
            }
        }
        instance.lock().unwrap().state = SandboxState::Starting;

        let restore_started = std::time::Instant::now();
        match self
            .restore_paused(id, jailer, &snap_meta, &vm_dir, networked)
            .await
        {
            Ok(resumed) => {
                let ready_commit = generation
                    .map(|generation| {
                        self.records
                            .transition(id, generation, SandboxTransition::Ready)
                    })
                    .transpose()?;
                let ip_address = resumed.ip_address.clone();
                {
                    let mut inst = instance.lock().unwrap();
                    inst.process = Some(resumed.process);
                    inst.vm = Some(resumed.vm);
                    inst.vsock_uds_path = Some(resumed.vsock_uds_path);
                    inst.network = resumed.network;
                    inst.cow_handle = resumed.cow_handle;
                    // Re-establish the guest's addressing mode from the
                    // checkpoint, exactly as Restore does: a paused sandbox
                    // rebuilt by the restart sweep has no live instance to
                    // inherit it from, and a later Checkpoint must record the
                    // guest's actual addressing (CORE-81).
                    inst.net_invariant = snap_meta.net_invariant;
                    inst.state = SandboxState::Ready;
                    inst.paused_at = None;
                    inst.pause_snapshot_id = None;
                }
                // The checkpoint matched the disk *at pause time*; the
                // sandbox will now diverge, so it must not be restorable
                // again. Deletion also frees the memory-sized image.
                if let Err(error) = self.snapshots.delete_by_id(&snapshot_id) {
                    warn!(
                        sandbox_id = %id,
                        snapshot_id = %snapshot_id,
                        error = %error,
                        "resumed, but deleting the pause checkpoint failed"
                    );
                }
                let _ = self.events_tx.send(
                    SandboxEvent::new(id, action::RESUMED).with_attr("reason", resume_reason),
                );
                info!(
                    sandbox_id = %id,
                    reason = resume_reason,
                    total_ms = u64::try_from(restore_started.elapsed().as_millis())
                        .unwrap_or(u64::MAX),
                    "sandbox resumed from pause checkpoint"
                );
                ready_commit
                    .map(|commit| commit.confirmed("sandbox resume"))
                    .transpose()?;
                Ok(ip_address)
            }
            Err(failure) => {
                if failure.unwound {
                    // Retained state is intact: park back at Paused so a
                    // retry (or Remove) still works.
                    if let Some(generation) = generation
                        && let Err(revert) = self.records.transition(
                            id,
                            generation,
                            SandboxTransition::Paused {
                                snapshot_id: snapshot_id.clone(),
                            },
                        )
                    {
                        warn!(sandbox_id = %id, error = %revert, "resume revert transition failed");
                    }
                    instance.lock().unwrap().state = SandboxState::Paused;
                    let _ = self.events_tx.send(SandboxEvent::new(id, action::PAUSED));
                } else {
                    if let Some(generation) = generation
                        && let Err(mark) = self.records.transition(
                            id,
                            generation,
                            SandboxTransition::Failed(failure.error.to_string()),
                        )
                    {
                        warn!(sandbox_id = %id, error = %mark, "resume failure transition failed");
                    }
                    {
                        let mut inst = instance.lock().unwrap();
                        inst.state = SandboxState::Failed;
                        inst.error = Some(failure.error.to_string());
                    }
                    let _ = self.events_tx.send(
                        SandboxEvent::new(id, action::FAILED)
                            .with_attr("error", &failure.error.to_string()),
                    );
                }
                Err(failure.error)
            }
        }
    }

    /// Free the VM, network, and chroot of a checkpointed sandbox while
    /// keeping its disk.
    ///
    /// Ordering is load-bearing, mirroring full release: Firecracker must be
    /// dead before the dm detach (EBUSY) and TAP destruction. The network
    /// allocation is quarantined — the daemon completes host-side forwarding
    /// cleanup through the same durable ticket flow Stop uses.
    ///
    /// A sandbox that adopted a pre-warmed slot (CORE-78) is released out of
    /// the *slot's* chroot and its slot-keyed overlay is renamed onto the
    /// sandbox-id path, so `Paused` is always reached with every retained
    /// resource keyed by the sandbox id.
    async fn release_for_pause(
        &self,
        id: &SandboxId,
        arc: &Arc<Mutex<SandboxInstance>>,
        jailer: &crate::config::JailerConfig,
    ) -> Result<()> {
        super::cleanup::kill_sandbox_process(id, arc).await?;
        let owner = super::cleanup::chroot_owner(id, arc);

        // Disk: detach the overlay but keep its COW file; the copy-mode
        // fallback parks the staged rootfs (the sandbox's actual disk) in
        // vm_dir before the chroot is removed.
        let cow_handle = arc.lock().unwrap().cow_handle.take();
        if let Some(handle) = cow_handle {
            if let Err(error) = self.cow_manager.detach_keep_cow(&handle).await {
                arc.lock().unwrap().cow_handle = Some(handle);
                return Err(error.into());
            }
            // A slot-keyed overlay must become sandbox-keyed: resume's
            // `reattach`, the restart sweep's keep-list, and `Remove` all
            // look the file up by sandbox id.
            let retained = self.preserved_cow_file(id);
            let detached = self.preserved_cow_file(&owner);
            if detached != retained && detached.exists() {
                tokio::fs::rename(&detached, &retained)
                    .await
                    .map_err(VmmError::Io)?;
            }
        } else {
            let base = jailer.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
            let staged =
                chroot_root(&self.config.firecracker.binary, base, &owner).join("rootfs.ext4");
            if staged.exists() {
                let vm_dir = arc.lock().unwrap().vm_dir.clone();
                move_file(&staged, &vm_dir.join(PAUSED_ROOTFS_FILE))
                    .await
                    .map_err(VmmError::Io)?;
            }
        }

        {
            let mut inst = arc.lock().unwrap();
            if let Some(net) = inst.network.take() {
                drop(inst);
                if let Err(error) = self.network.quarantine_checked(id, &net) {
                    arc.lock().unwrap().network = Some(net);
                    return Err(error);
                }
            }
        }

        super::cleanup::remove_jailer_chroot(id, arc, &self.config).await?;
        // Nothing slot-keyed survives this point.
        arc.lock().unwrap().pool_slot_id = None;
        Ok(())
    }

    /// Re-create the runtime of a paused sandbox from its checkpoint.
    ///
    /// On failure every re-created resource is unwound (Firecracker killed,
    /// overlay detached with its COW kept, copy-mode rootfs parked again,
    /// fresh network quarantined, chroot and journal removed) so the caller
    /// can park the sandbox back at `Paused`.
    async fn restore_paused(
        &self,
        id: &SandboxId,
        jailer: &crate::config::JailerConfig,
        snap_meta: &crate::snapshot::SnapshotMeta,
        vm_dir: &Path,
        networked: bool,
    ) -> std::result::Result<ResumedRuntime, ResumeFailure> {
        let fc_cfg = &self.config.firecracker;
        let base = jailer.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
        let cr = chroot_root(&fc_cfg.binary, base, id);
        let uid = jailer.uid;
        let gid = jailer.gid;

        // Incrementally-owned resources for the unwind.
        let mut net_alloc: Option<NetworkAllocation> = None;
        let mut process: Option<fc_sdk::FirecrackerProcess> = None;
        let mut cow_handle: Option<CowHandle> = None;

        let attempt: Result<ResumedRuntime> = async {
            // Reserve network metadata, journal it, then materialize the
            // TAP — the same order boot and restore use, so a crash never
            // leaves an unowned interface.
            if networked {
                net_alloc = Some(self.network.reserve(id)?);
            }
            let ip_address = net_alloc
                .as_ref()
                .map(|n| n.ip_address.to_string())
                .unwrap_or_default();
            let journal =
                |pid: Option<i32>, cow: Option<&CowHandle>, net: Option<&NetworkAllocation>| {
                    let record =
                        super::reconcile::SandboxStateRecord::new(id, pid, net, cow, true, None);
                    super::reconcile::write_state_record(vm_dir, &record)
                };
            journal(None, None, net_alloc.as_ref())?;
            if let Some(net) = &net_alloc {
                // The resumed guest keeps the addressing its pause checkpoint
                // baked, exactly as Restore does: an invariant guest pairs
                // with an invariant TAP (host-side NAT, no guest work), a
                // legacy one with the legacy TAP shape plus the reconfig RPC
                // below (CORE-81).
                let mode = if snap_meta.net_invariant {
                    crate::network::TapMode::Invariant
                } else {
                    crate::network::TapMode::LegacySnapshot
                };
                self.network.activate(net, mode)?;
            }

            // Fresh chroot + Firecracker process.
            let run_dir = cr.join("run");
            std::fs::create_dir_all(&run_dir).map_err(VmmError::Io)?;
            let vsock_path = cr.join("run/firecracker.vsock");
            let _ = std::fs::remove_file(&vsock_path);
            let spawned = spawn_jailer(
                &FcDriverConfig::from(fc_cfg),
                &IsolationSpec::try_from(jailer)?,
                id,
            )
            .await?;
            #[allow(
                clippy::cast_possible_wrap,
                reason = "Firecracker pid fits platform pid_t"
            )]
            let pid = spawned.pid().map(|pid| pid as i32);
            process = Some(spawned);
            journal(pid, None, net_alloc.as_ref())?;

            // Stage kernel + the retained disk + snapshot files.
            if let Some(kernel) = snap_meta.kernel_path.as_deref() {
                stage_kernel_for_jailer(&cr, kernel, uid, gid).await?;
            }
            let preserved_cow = self.preserved_cow_file(id);
            if preserved_cow.exists() {
                let rootfs = snap_meta.rootfs_path.as_deref().ok_or_else(|| {
                    VmmError::Snapshot(format!(
                        "pause checkpoint for {id} records no rootfs template"
                    ))
                })?;
                let handle = self.cow_manager.reattach(id, rootfs).await?;
                journal(pid, Some(&handle), net_alloc.as_ref())?;
                stage_rootfs_device_for_jailer(&cr, &handle.dm_device, uid, gid).await?;
                cow_handle = Some(handle);
            } else {
                let parked = vm_dir.join(PAUSED_ROOTFS_FILE);
                if !parked.exists() {
                    return Err(VmmError::Snapshot(format!(
                        "paused sandbox {id} has neither a preserved overlay nor a parked rootfs"
                    )));
                }
                let staged = cr.join("rootfs.ext4");
                move_file(&parked, &staged).await.map_err(VmmError::Io)?;
                nix::unistd::chown(
                    &staged,
                    Some(nix::unistd::Uid::from_raw(uid)),
                    Some(nix::unistd::Gid::from_raw(gid)),
                )
                .map_err(|e| VmmError::Process(format!("chown parked rootfs: {e}")))?;
            }

            let snap_in_chroot = cr.join("snapshots").join(&snap_meta.id);
            std::fs::create_dir_all(&snap_in_chroot).map_err(VmmError::Io)?;
            nix::unistd::chown(
                &snap_in_chroot,
                Some(nix::unistd::Uid::from_raw(uid)),
                Some(nix::unistd::Gid::from_raw(gid)),
            )
            .map_err(|e| VmmError::Process(format!("chown snap dir: {e}")))?;
            link_or_copy_for_jailer(
                &snap_meta.vmstate_path,
                &snap_in_chroot.join("vmstate"),
                uid,
                gid,
            )
            .await?;
            let effective_mem = if let Some(ref mem) = snap_meta.mem_path
                && mem.exists()
            {
                link_or_copy_for_jailer(mem, &snap_in_chroot.join("mem"), uid, gid).await?;
                Some(format!("/snapshots/{}/mem", snap_meta.id))
            } else {
                None
            };

            // Load the snapshot; retarget eth0 onto the fresh TAP.
            let mut load_params = fc_sdk::types::SnapshotLoadParams {
                snapshot_path: format!("/snapshots/{}/vmstate", snap_meta.id),
                mem_file_path: effective_mem,
                mem_backend: None,
                enable_diff_snapshots: None,
                track_dirty_pages: None,
                resume_vm: Some(true),
                network_overrides: vec![],
            };
            if let Some(ref net) = net_alloc {
                load_params.network_overrides = vec![fc_sdk::types::NetworkOverride {
                    iface_id: "eth0".into(),
                    host_dev_name: net.tap_name.clone(),
                }];
            }
            let socket = process
                .as_ref()
                .expect("process set above")
                .socket_path()
                .to_owned();
            let vm = Arc::new(
                fc_sdk::restore(
                    socket.to_str().ok_or_else(|| {
                        VmmError::Config("non-UTF-8 firecracker socket path".into())
                    })?,
                    load_params,
                )
                .await
                .map_err(VmmError::from)?,
            );
            let vsock: Arc<dyn arcbox_vm_driver::Vsock> =
                Arc::new(vsock::UdsVsock(vsock_path.clone()));

            // Clock sync is DETACHED, mirroring restore and cold boot
            // (CORE-80): the guest wall clock froze at pause time, but
            // vm-agent re-syncs itself from ptp_kvm on every accepted exec
            // connection, so correct time no longer depends on this RPC.
            // Awaiting it would put the post-resume vsock connect settle back
            // on the resume critical path.
            {
                let id = id.clone();
                let vsock = Arc::clone(&vsock);
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        vsock::sync_clock(vsock.as_ref()),
                    )
                    .await
                    {
                        Ok(Ok(vsock::ClockSync::Synced)) => {}
                        Ok(Ok(vsock::ClockSync::AgentError(code))) => {
                            warn!(sandbox_id = %id, code, "agent could not set the clock after resume");
                        }
                        Ok(Err(e)) => warn!(sandbox_id = %id, "clock sync after resume failed: {e}"),
                        Err(_) => warn!(sandbox_id = %id, "clock sync after resume timed out"),
                    }
                });
            }

            // Re-address the guest only when its snapshot is legacy-addressed.
            // An invariant guest (CORE-81) already holds the fixed link-local
            // identity and its resolv.conf already points at the fixed
            // gateway; the fresh TAP carries the new pool IP host-side, so
            // resume awaits nothing here.
            if let Some(ref net) = net_alloc
                && !snap_meta.net_invariant
            {
                let cmd = crate::boot_proto::NetReconfigCommand {
                    ip: net.ip_address,
                    netmask: net.netmask(),
                    gateway: net.gateway,
                };
                tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    vsock::reconfigure_network(vsock.as_ref(), &cmd),
                )
                .await
                .map_err(|_| VmmError::Vsock("net reconfig after resume timed out".into()))
                .and_then(|r| r)?;
            }

            journal(pid, cow_handle.as_ref(), net_alloc.as_ref())?;
            Ok(ResumedRuntime {
                process: process.take().expect("process set above"),
                vm,
                vsock_uds_path: vsock_path,
                network: net_alloc.take(),
                cow_handle: cow_handle.take(),
                ip_address,
            })
        }
        .await;

        match attempt {
            Ok(resumed) => Ok(resumed),
            Err(error) => {
                let unwound = self
                    .unwind_resume(id, vm_dir, jailer, process, cow_handle, net_alloc)
                    .await;
                Err(ResumeFailure { error, unwound })
            }
        }
    }

    /// Best-effort release of everything a failed resume re-created,
    /// restoring the on-disk shape of a cleanly paused sandbox.
    ///
    /// Returns true when the sandbox can safely go back to `Paused`.
    async fn unwind_resume(
        &self,
        id: &SandboxId,
        vm_dir: &Path,
        jailer: &crate::config::JailerConfig,
        process: Option<fc_sdk::FirecrackerProcess>,
        cow_handle: Option<CowHandle>,
        net_alloc: Option<NetworkAllocation>,
    ) -> bool {
        let mut clean = true;

        if let Some(mut proc) = process {
            if let Some(pid) = proc.pid()
                && pid > 0
            {
                #[allow(
                    clippy::cast_possible_wrap,
                    reason = "Firecracker pid fits platform pid_t"
                )]
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            if tokio::time::timeout(std::time::Duration::from_secs(5), proc.wait())
                .await
                .is_err()
            {
                warn!(sandbox_id = %id, "resume unwind: firecracker did not exit");
                clean = false;
            }
        }

        if let Some(handle) = cow_handle
            && let Err(error) = self.cow_manager.detach_keep_cow(&handle).await
        {
            warn!(sandbox_id = %id, error = %error, "resume unwind: overlay detach failed");
            clean = false;
        }

        // Copy-mode fallback: park the staged rootfs back in vm_dir so the
        // retained disk state survives the chroot removal below.
        let base = jailer.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
        let cr = chroot_root(&self.config.firecracker.binary, base, id);
        let staged = cr.join("rootfs.ext4");
        if !self.preserved_cow_file(id).exists() && staged.exists() {
            if let Err(error) = move_file(&staged, &vm_dir.join(PAUSED_ROOTFS_FILE)).await {
                warn!(sandbox_id = %id, error = %error, "resume unwind: parking rootfs failed");
                clean = false;
            }
        }

        if let Some(net) = net_alloc
            && let Err(error) = self.network.quarantine_checked(id, &net)
        {
            warn!(sandbox_id = %id, error = %error, "resume unwind: network quarantine failed");
            clean = false;
        }

        if let Some(parent) = cr.parent()
            && let Err(error) = tokio::fs::remove_dir_all(parent).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(sandbox_id = %id, error = %error, "resume unwind: chroot removal failed");
            clean = false;
        }

        if clean && let Err(error) = super::reconcile::clear_state_record(vm_dir) {
            warn!(sandbox_id = %id, error = %error, "resume unwind: journal removal failed");
            clean = false;
        }
        clean
    }

    fn preserved_cow_file(&self, id: &str) -> PathBuf {
        PathBuf::from(&self.config.firecracker.data_dir)
            .join("cow")
            .join(format!("arcbox-cow-{id}.img"))
    }

    /// Locate a paused sandbox's retained artifacts.
    ///
    /// Pure field reads — no filesystem access — so it is the only half of
    /// the storage accounting that may run under the instance lock. The
    /// sizing itself ([`PausedArtifacts::storage_bytes`]) stats files and,
    /// for the checkpoint, needs a catalog lookup; doing that under the
    /// lock would block every lifecycle transition on the sandbox behind
    /// blocking I/O on the async executor.
    pub(super) fn paused_artifacts(&self, inst: &SandboxInstance) -> PausedArtifacts {
        PausedArtifacts {
            pause_snapshot_id: inst.pause_snapshot_id.clone(),
            preserved_cow: self.preserved_cow_file(&inst.id),
            parked_rootfs: inst.vm_dir.join(PAUSED_ROOTFS_FILE),
        }
    }
}

/// Where a paused sandbox's retained state lives on disk.
///
/// Collected under the instance lock, sized outside it.
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

    async fn manager(data_dir: &Path) -> SandboxManager {
        let mut config = VmmConfig::default();
        config.firecracker.data_dir = data_dir.to_string_lossy().into_owned();
        let manager = SandboxManager::new(config).unwrap();
        manager.await_reconcile().await.unwrap();
        manager
    }

    fn insert_instance(
        manager: &SandboxManager,
        id: &str,
        state: SandboxState,
    ) -> Arc<Mutex<SandboxInstance>> {
        let vm_dir = PathBuf::from(&manager.config.firecracker.data_dir)
            .join("sandboxes")
            .join(id);
        let mut inst = SandboxInstance::new(
            id.to_owned(),
            SandboxSpec {
                id: Some(id.to_owned()),
                ..Default::default()
            },
            None,
            vm_dir,
        );
        inst.state = state;
        let arc = Arc::new(Mutex::new(inst));
        manager
            .instances
            .write()
            .unwrap()
            .insert(id.to_owned(), Arc::clone(&arc));
        arc
    }

    #[tokio::test]
    async fn pause_is_idempotent_and_gates_on_state() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;

        assert!(matches!(
            manager.pause_sandbox(&"missing".to_owned()).await,
            Err(VmmError::NotFound(_))
        ));

        insert_instance(&manager, "paused", SandboxState::Paused);
        manager.pause_sandbox(&"paused".to_owned()).await.unwrap();

        insert_instance(&manager, "busy", SandboxState::Running);
        assert!(matches!(
            manager.pause_sandbox(&"busy".to_owned()).await,
            Err(VmmError::WrongState { .. })
        ));

        // Ready but no jailer configured: pause must fail fast before
        // touching anything — a direct-mode pause could never resume.
        insert_instance(&manager, "ready", SandboxState::Ready);
        let error = manager
            .pause_sandbox(&"ready".to_owned())
            .await
            .unwrap_err();
        assert!(matches!(error, VmmError::Config(_)), "{error}");
        assert!(error.to_string().contains("jailer"), "{error}");
    }

    #[tokio::test]
    async fn resume_noops_on_live_states_and_rejects_others() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;

        insert_instance(&manager, "ready", SandboxState::Ready);
        assert_eq!(
            manager
                .resume_sandbox(&"ready".to_owned(), reason::RESUME)
                .await
                .unwrap(),
            ""
        );
        insert_instance(&manager, "running", SandboxState::Running);
        manager
            .resume_sandbox(&"running".to_owned(), reason::RESUME)
            .await
            .unwrap();

        insert_instance(&manager, "stopped", SandboxState::Stopped);
        assert!(matches!(
            manager
                .resume_sandbox(&"stopped".to_owned(), reason::RESUME)
                .await,
            Err(VmmError::WrongState { .. })
        ));

        // Paused with no recorded checkpoint is corrupt retained state.
        insert_instance(&manager, "hollow", SandboxState::Paused);
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
        let manager = manager(dir.path()).await;
        insert_instance(&manager, "asleep", SandboxState::Paused);

        assert!(matches!(
            manager.require_ready_vsock(&"asleep".to_owned()),
            Err(VmmError::Paused(id)) if id == "asleep"
        ));
        assert!(matches!(
            manager.require_alive_vsock(&"asleep".to_owned()),
            Err(VmmError::Paused(id)) if id == "asleep"
        ));
    }

    #[tokio::test]
    async fn pause_snapshots_are_hidden_and_protected() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;

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
        let manager = manager(dir.path()).await;

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

        let arc = insert_instance(&manager, "napper", SandboxState::Paused);
        arc.lock().unwrap().pause_snapshot_id = Some(meta.id);
        // A live sandbox reports nothing: the field is retained-state only.
        insert_instance(&manager, "awake", SandboxState::Ready);

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
