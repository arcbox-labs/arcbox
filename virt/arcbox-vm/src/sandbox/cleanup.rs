use super::boot::chroot_root;
use super::persistence::{SandboxRecordStore, SandboxTransition};
use super::types::{SandboxBootTask, action};
use super::*;

#[cfg(not(test))]
const BOOT_RESOURCE_HANDOFF_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const BOOT_RESOURCE_HANDOFF_TIMEOUT: Duration = Duration::from_millis(100);
#[cfg(not(test))]
const TTL_REMOVE_RETRY_INITIAL: Duration = Duration::from_millis(250);
#[cfg(test)]
const TTL_REMOVE_RETRY_INITIAL: Duration = Duration::from_millis(10);
const TTL_REMOVE_RETRY_MAX: Duration = Duration::from_secs(5);

#[allow(
    clippy::type_complexity,
    reason = "manager storage type is shared here"
)]
#[allow(
    clippy::too_many_arguments,
    reason = "cleanup receives the manager-owned resource set"
)]
pub(super) async fn remove_sandbox_impl(
    id: &str,
    force: bool,
    expected: &Arc<Mutex<SandboxInstance>>,
    instances: &Arc<RwLock<HashMap<SandboxId, Arc<Mutex<SandboxInstance>>>>>,
    network: &Arc<NetworkManager>,
    events_tx: &broadcast::Sender<SandboxEvent>,
    config: &Arc<VmmConfig>,
    cow_manager: &Arc<CowManager>,
    records: &Arc<SandboxRecordStore>,
    snapshots: &Arc<crate::snapshot::SnapshotCatalog>,
) -> Result<()> {
    let cleanup_lock = expected.lock().unwrap().cleanup_lock.clone();
    let _cleanup_guard = cleanup_lock.lock().await;
    super::ensure_current_instance(instances, id, expected)?;
    let (record_generation, boot_task) = begin_removal(id, force, expected, records)?;

    cancel_and_join_boot(id, expected, boot_task).await?;
    release_runtime_resources(id, expected, network, config, cow_manager).await?;

    // Pause artifacts survive Stop-style release by design (CORE-21); Remove
    // is where they die: the retained disk overlay and the internal pause
    // checkpoint(s), including any leaked by an interrupted pause.
    cow_manager.remove_preserved_cow(id).await?;
    super::pause::delete_pause_snapshots(snapshots, id)?;

    // Remove the sandbox working directory (sockets, logs, state journal).
    let vm_dir = PathBuf::from(&config.firecracker.data_dir)
        .join("sandboxes")
        .join(id);
    if let Err(e) = tokio::fs::remove_dir_all(&vm_dir).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(VmmError::Io(e));
    }

    // Release durable ownership before dropping the in-memory handle. If the
    // unlink fails, a retry can finish removal through the still-present entry.
    let durability_error = match record_generation {
        Some(generation) => records.finish_remove(id, generation)?.durability_error,
        None => None,
    };

    // Only drop the map entry if it is still the instance we tore down. A
    // concurrent re-create under the same id installs a different Arc that this
    // removal must not evict.
    let mut removed = false;
    {
        let mut map = instances.write().unwrap();
        if map.get(id).is_some_and(|cur| Arc::ptr_eq(cur, expected)) {
            map.remove(id);
            removed = true;
        }
    }
    if removed {
        let _ = events_tx.send(SandboxEvent::new(id, action::REMOVED));
    }
    if let Some(error) = durability_error {
        return Err(VmmError::Unavailable(format!(
            "sandbox {id} was removed, but record deletion durability is unconfirmed: {error}"
        )));
    }
    Ok(())
}

/// Claims an exact instance for removal before cleanup performs its first await.
fn begin_removal(
    id: &str,
    force: bool,
    expected: &Arc<Mutex<SandboxInstance>>,
    records: &SandboxRecordStore,
) -> Result<(Option<Uuid>, Option<SandboxBootTask>)> {
    let mut inst = expected.lock().unwrap();
    if !force && inst.state == SandboxState::Running {
        return Err(VmmError::WrongState {
            id: id.to_owned(),
            expected: "non-running (pass force=true to override)".into(),
            actual: inst.state.to_string(),
        });
    }
    if !force && inst.state == SandboxState::Starting {
        return Err(VmmError::WrongState {
            id: id.to_owned(),
            expected: "a sandbox whose boot attempt has completed".into(),
            actual: inst.state.to_string(),
        });
    }

    let generation = inst.record_generation;
    if let Some(generation) = generation {
        let commit = records.transition(id, generation, SandboxTransition::Removing)?;
        if let Some(error) = commit.durability_error {
            warn!(
                sandbox_id = id,
                error,
                "removal transition is visible but directory fsync failed; cleanup continues"
            );
        }
    }
    inst.state = SandboxState::Stopping;
    Ok((generation, inst.boot_task.take()))
}

/// Stop the producer of runtime resources before cleanup removes their journal.
async fn cancel_and_join_boot(
    id: &str,
    expected: &Arc<Mutex<SandboxInstance>>,
    mut task: Option<SandboxBootTask>,
) -> Result<()> {
    let Some(mut task) = task.take() else {
        return Ok(());
    };

    if let Some(mut resource_handoff) = task.resource_handoff.take() {
        match tokio::time::timeout(BOOT_RESOURCE_HANDOFF_TIMEOUT, &mut resource_handoff).await {
            Ok(Ok(())) => {
                // All resources created before the next cancellation point are
                // now instance-owned, so aborting cannot strand a local handle.
                task.handle.abort();
            }
            Ok(Err(_)) => {
                // The producer ended without declaring abort safety. Join it
                // without aborting so its outer failure cleanup can finish.
            }
            Err(_) => {
                task.resource_handoff = Some(resource_handoff);
                expected.lock().unwrap().boot_task = Some(task);
                return Err(VmmError::Unavailable(format!(
                    "timed out waiting for sandbox {id} boot resource handoff; durable state was retained"
                )));
            }
        }
    }

    let joined = tokio::time::timeout(BOOT_RESOURCE_HANDOFF_TIMEOUT, &mut task.handle).await;
    let Ok(joined) = joined else {
        expected.lock().unwrap().boot_task = Some(task);
        return Err(VmmError::Unavailable(format!(
            "timed out joining sandbox {id} boot task; durable state was retained"
        )));
    };
    match joined {
        Ok(()) => Ok(()),
        Err(error) if error.is_cancelled() => Ok(()),
        Err(error) => Err(VmmError::Process(format!(
            "join sandbox {id} boot task: {error}"
        ))),
    }
}

/// Returns the armed instance when it is still registered under the id.
fn armed_instance(
    generation: Option<Uuid>,
    armed_for: &std::sync::Weak<Mutex<SandboxInstance>>,
    current: Option<&Arc<Mutex<SandboxInstance>>>,
) -> Option<Arc<Mutex<SandboxInstance>>> {
    match (armed_for.upgrade(), current) {
        (Some(mine), Some(cur)) => (Arc::ptr_eq(&mine, cur)
            && mine.lock().unwrap().record_generation == generation)
            .then_some(mine),
        _ => None,
    }
}

/// TTL expiry: force-remove `id`, but only if the instance registered under it
/// is still the one this timer was armed for.
///
/// A sandbox that was removed and re-created under the same id (deterministic
/// caller-supplied ids make this common) installs a fresh `Arc`. The captured
/// `Weak` then points at a different — or dropped — instance, so the stale
/// timer becomes a no-op instead of force-removing the unrelated new sandbox.
#[allow(
    clippy::type_complexity,
    reason = "manager storage type is shared here"
)]
#[allow(
    clippy::too_many_arguments,
    reason = "detached TTL task captures the manager-owned resource set"
)]
pub(super) async fn expire_sandbox(
    id: &str,
    generation: Option<Uuid>,
    armed_for: &std::sync::Weak<Mutex<SandboxInstance>>,
    instances: &Arc<RwLock<HashMap<SandboxId, Arc<Mutex<SandboxInstance>>>>>,
    network: &Arc<NetworkManager>,
    events_tx: &broadcast::Sender<SandboxEvent>,
    config: &Arc<VmmConfig>,
    cow_manager: &Arc<CowManager>,
    records: &Arc<SandboxRecordStore>,
    snapshots: &Arc<crate::snapshot::SnapshotCatalog>,
) {
    let mut retry_delay = TTL_REMOVE_RETRY_INITIAL;
    loop {
        let current = instances.read().unwrap().get(id).cloned();
        let Some(expected) = armed_instance(generation, armed_for, current.as_ref()) else {
            return;
        };
        match remove_sandbox_impl(
            id,
            true,
            &expected,
            instances,
            network,
            events_tx,
            config,
            cow_manager,
            records,
            snapshots,
        )
        .await
        {
            Ok(()) => return,
            Err(VmmError::Unavailable(error)) => {
                warn!(
                    sandbox_id = %id,
                    error,
                    retry_millis = retry_delay.as_millis(),
                    "TTL sandbox removal is not yet confirmed; retrying"
                );
                tokio::time::sleep(retry_delay).await;
                retry_delay = retry_delay.saturating_mul(2).min(TTL_REMOVE_RETRY_MAX);
            }
            Err(error) => {
                error!(sandbox_id = %id, error = %error, "TTL sandbox removal failed");
                return;
            }
        }
    }
}

/// Free every runtime resource a sandbox holds: the Firecracker process
/// (SIGKILL + bounded reap), the dm-snapshot CoW device, the TAP + IP
/// allocation, and the jailer chroot. Idempotent — every resource is
/// `take()`n, so calling this from both Stop and Remove is safe.
///
/// The ordering is load-bearing: FC must be dead before the CoW teardown
/// (`dmsetup remove` returns EBUSY while the block device is open) and
/// before TAP destruction (the ioctl fails while the fd is held).
pub(super) async fn release_runtime_resources(
    id: &str,
    arc: &Arc<Mutex<SandboxInstance>>,
    network: &Arc<NetworkManager>,
    config: &Arc<VmmConfig>,
    cow_manager: &Arc<CowManager>,
) -> Result<()> {
    kill_sandbox_process(id, arc).await?;

    // Teardown dm-snapshot CoW device (must happen after FC process exits
    // because Firecracker holds the block device open).
    {
        let cow_handle = arc.lock().unwrap().cow_handle.take();
        if let Some(handle) = cow_handle
            && let Err(error) = cow_manager.teardown_checked(&handle).await
        {
            arc.lock().unwrap().cow_handle = Some(handle);
            return Err(error);
        }
    }
    cow_manager.cleanup_setup_orphan(id).await?;

    // Release network resources (destroys TAP via ioctl).
    {
        let mut inst = arc.lock().unwrap();
        if let Some(net) = inst.network.take() {
            drop(inst);
            if let Err(error) = network.quarantine_checked(id, &net) {
                arc.lock().unwrap().network = Some(net);
                return Err(error);
            }
        }
    }

    // Clean up the jailer chroot directory if applicable. A sandbox that
    // adopted a pre-warmed pool slot lives in the slot's chroot, so the
    // removal is keyed by the owning id, not the sandbox id.
    remove_jailer_chroot(id, arc, config).await
}

/// Remove the jailer chroot a sandbox actually lives in.
///
/// Keyed by the adopted pool slot id when the sandbox claimed a pre-warmed
/// slot (CORE-78), by the sandbox id otherwise. Shared with the pause path,
/// which releases the same chroot while keeping the disk.
pub(super) async fn remove_jailer_chroot(
    id: &str,
    arc: &Arc<Mutex<SandboxInstance>>,
    config: &Arc<VmmConfig>,
) -> Result<()> {
    let Some(ref jc) = config.firecracker.jailer else {
        return Ok(());
    };
    let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
    let chroot_owner = chroot_owner(id, arc);
    let chroot_dir = chroot_root(&config.firecracker.binary, base, &chroot_owner);
    // Remove {base}/{exec_name}/{id}/ (parent of "root/").
    if let Some(parent) = chroot_dir.parent()
        && let Err(e) = tokio::fs::remove_dir_all(parent).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(VmmError::Io(e));
    }
    Ok(())
}

/// Id the sandbox's jailer chroot and dm/CoW resources are named after.
pub(super) fn chroot_owner(id: &str, arc: &Arc<Mutex<SandboxInstance>>) -> String {
    arc.lock()
        .unwrap()
        .pool_slot_id
        .clone()
        .unwrap_or_else(|| id.to_owned())
}

/// SIGKILL the sandbox's Firecracker process and reap it with a bounded wait.
///
/// Extracted so the pause path (which keeps the disk overlay) shares the exact
/// kill/reap discipline with full release. A failed reap restores the handle
/// so a retry can finish the job. Idempotent — the process is `take()`n.
pub(super) async fn kill_sandbox_process(
    id: &str,
    arc: &Arc<Mutex<SandboxInstance>>,
) -> Result<()> {
    let mut fc_process = {
        let mut inst = arc.lock().unwrap();
        if let Some(ref mut proc) = inst.process
            && let Some(pid) = proc.pid()
            && pid > 0
        {
            match nix::sys::signal::kill(
                #[allow(
                    clippy::cast_possible_wrap,
                    reason = "Firecracker pid fits platform pid_t"
                )]
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGKILL,
            ) {
                Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
                Err(error) => {
                    return Err(VmmError::Process(format!(
                        "kill firecracker for sandbox {id}: {error}"
                    )));
                }
            }
        }
        inst.process.take()
    };
    // Await process exit outside the lock. Use a timeout so cleanup proceeds
    // even if the process is stuck in uninterruptible sleep after SIGKILL.
    if let Some(mut proc) = fc_process.take() {
        match tokio::time::timeout(std::time::Duration::from_secs(5), proc.wait()).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                arc.lock().unwrap().process = Some(proc);
                return Err(VmmError::Process(format!(
                    "reap firecracker for sandbox {id}: {error}"
                )));
            }
            Err(_) => {
                arc.lock().unwrap().process = Some(proc);
                return Err(VmmError::Process(format!(
                    "timed out reaping firecracker for sandbox {id}"
                )));
            }
        }
    }
    Ok(())
}

pub(super) fn inst_to_info(inst: &SandboxInstance) -> SandboxInfo {
    SandboxInfo {
        id: inst.id.clone(),
        state: inst.state,
        labels: inst.labels.clone(),
        vcpus: inst.spec.vcpus,
        memory_mib: inst.spec.memory_mib,
        network: inst.network.as_ref().map(|n| SandboxNetworkInfo {
            ip_address: n.ip_address.to_string(),
            gateway: n.gateway.to_string(),
            tap_name: n.tap_name.clone(),
        }),
        created_at: inst.created_at,
        ready_at: inst.ready_at,
        last_exited_at: inst.last_exited_at,
        last_exit_status: inst.last_exit_status,
        error: inst.error.clone(),
        paused_at: inst.paused_at,
        // Filled by the manager for paused sandboxes (it owns the paths).
        storage_bytes: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::persistence::{ProvisionIntent, SandboxPhase, SandboxProvisionOutcome};
    use crate::snapshot_cow::CowTestProbe;
    use std::os::unix::fs::PermissionsExt;

    fn instance(id: &str) -> Arc<Mutex<SandboxInstance>> {
        Arc::new(Mutex::new(SandboxInstance::new(
            id.to_owned(),
            SandboxSpec::default(),
            None,
            PathBuf::from("/tmp/x"),
        )))
    }

    #[test]
    fn ttl_applies_only_to_the_armed_generation() {
        let original = instance("job");
        let armed_for = Arc::downgrade(&original);

        // Same instance still registered → timer applies.
        assert!(armed_instance(None, &armed_for, Some(&original)).is_some());

        // Removed and re-created under the same id → a different Arc; the stale
        // timer must NOT match the new generation.
        let recreated = instance("job");
        assert!(armed_instance(None, &armed_for, Some(&recreated)).is_none());

        // Removed with nothing re-created → no match.
        assert!(armed_instance(None, &armed_for, None).is_none());

        // Original fully dropped → the Weak is dead, no match even if some
        // other instance is present.
        drop(original);
        assert!(armed_instance(None, &armed_for, Some(&recreated)).is_none());
    }

    #[test]
    fn ttl_generation_must_match_the_armed_instance() {
        let instance = instance("job");
        let armed_for = Arc::downgrade(&instance);

        assert!(armed_instance(Some(Uuid::new_v4()), &armed_for, Some(&instance)).is_none());
    }

    #[tokio::test]
    async fn force_and_ttl_remove_a_wedged_starting_sandbox() {
        for via_ttl in [false, true] {
            let data_dir = tempfile::tempdir().unwrap();
            let vm_dir = data_dir.path().join("sandboxes/job");
            std::fs::create_dir_all(&vm_dir).unwrap();
            let spec = SandboxSpec {
                id: Some("job".into()),
                ..Default::default()
            };
            let records = Arc::new(SandboxRecordStore::new(data_dir.path()).unwrap());
            let record = match records
                .provision_intent("job", "create-key", spec.clone())
                .unwrap()
            {
                ProvisionIntent::Created(record) => record,
                other => panic!("unexpected create intent: {other:?}"),
            };
            records
                .transition(
                    "job",
                    record.generation,
                    SandboxTransition::Starting(SandboxProvisionOutcome {
                        ip_address: String::new(),
                    }),
                )
                .unwrap();
            let expected = Arc::new(Mutex::new(SandboxInstance::new_with_generation(
                "job".into(),
                spec,
                None,
                vm_dir.clone(),
                record.generation,
            )));
            let instances: InstanceMap = Arc::new(RwLock::new(HashMap::from([(
                "job".into(),
                Arc::clone(&expected),
            )])));
            let mut config = VmmConfig::default();
            config.firecracker.data_dir = data_dir.path().to_string_lossy().into_owned();
            let config = Arc::new(config);
            let network = Arc::new(
                NetworkManager::new(
                    &config.network.cidr,
                    &config.network.gateway,
                    config.network.dns.clone(),
                )
                .unwrap(),
            );
            let cow_manager = Arc::new(CowManager::new(&config.firecracker.data_dir).unwrap());
            let snapshots = Arc::new(crate::snapshot::SnapshotCatalog::new(
                &config.firecracker.data_dir,
            ));
            let (events_tx, _) = broadcast::channel(1);
            let armed_for = Arc::downgrade(&expected);

            tokio::time::timeout(Duration::from_secs(1), async {
                if via_ttl {
                    expire_sandbox(
                        "job",
                        Some(record.generation),
                        &armed_for,
                        &instances,
                        &network,
                        &events_tx,
                        &config,
                        &cow_manager,
                        &records,
                        &snapshots,
                    )
                    .await;
                    Ok(())
                } else {
                    remove_sandbox_impl(
                        "job",
                        true,
                        &expected,
                        &instances,
                        &network,
                        &events_tx,
                        &config,
                        &cow_manager,
                        &records,
                        &snapshots,
                    )
                    .await
                }
            })
            .await
            .expect("forced removal must not wait for boot to finish")
            .unwrap();

            assert!(!instances.read().unwrap().contains_key("job"));
            assert!(records.load("job").unwrap().is_none());
            assert!(!vm_dir.exists());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn join_timeout_retry_does_not_repoll_a_consumed_handoff() {
        let expected = instance("job");
        let (resource_handoff_tx, resource_handoff) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            resource_handoff_tx.send(()).unwrap();
            tokio::task::block_in_place(|| {
                std::thread::sleep(BOOT_RESOURCE_HANDOFF_TIMEOUT.saturating_mul(3));
            });
        });

        let error = cancel_and_join_boot(
            "job",
            &expected,
            Some(SandboxBootTask {
                resource_handoff: Some(resource_handoff),
                handle,
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, VmmError::Unavailable(_)));

        tokio::time::sleep(BOOT_RESOURCE_HANDOFF_TIMEOUT.saturating_mul(3)).await;
        let task = expected.lock().unwrap().boot_task.take();
        cancel_and_join_boot("job", &expected, task).await.unwrap();
    }

    #[tokio::test]
    async fn ttl_retries_resource_handoff_timeout_for_the_same_generation() {
        let data_dir = tempfile::tempdir().unwrap();
        let vm_dir = data_dir.path().join("sandboxes/job");
        std::fs::create_dir_all(&vm_dir).unwrap();
        let spec = SandboxSpec {
            id: Some("job".into()),
            ..Default::default()
        };
        let records = Arc::new(SandboxRecordStore::new(data_dir.path()).unwrap());
        let record = match records
            .provision_intent("job", "create-key", spec.clone())
            .unwrap()
        {
            ProvisionIntent::Created(record) => record,
            other => panic!("unexpected create intent: {other:?}"),
        };
        records
            .transition(
                "job",
                record.generation,
                SandboxTransition::Starting(SandboxProvisionOutcome {
                    ip_address: String::new(),
                }),
            )
            .unwrap();
        let expected = Arc::new(Mutex::new(SandboxInstance::new_with_generation(
            "job".into(),
            spec,
            None,
            vm_dir.clone(),
            record.generation,
        )));
        let (resource_handoff_tx, resource_handoff) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(BOOT_RESOURCE_HANDOFF_TIMEOUT.saturating_mul(2)).await;
            resource_handoff_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        expected.lock().unwrap().boot_task = Some(SandboxBootTask {
            resource_handoff: Some(resource_handoff),
            handle,
        });
        let instances: InstanceMap = Arc::new(RwLock::new(HashMap::from([(
            "job".into(),
            Arc::clone(&expected),
        )])));
        let mut config = VmmConfig::default();
        config.firecracker.data_dir = data_dir.path().to_string_lossy().into_owned();
        let config = Arc::new(config);
        let network = Arc::new(
            NetworkManager::new(
                &config.network.cidr,
                &config.network.gateway,
                config.network.dns.clone(),
            )
            .unwrap(),
        );
        let cow_manager = Arc::new(CowManager::new(&config.firecracker.data_dir).unwrap());
        let snapshots = Arc::new(crate::snapshot::SnapshotCatalog::new(
            &config.firecracker.data_dir,
        ));
        let (events_tx, _) = broadcast::channel(1);
        let armed_for = Arc::downgrade(&expected);

        tokio::time::timeout(
            Duration::from_secs(1),
            expire_sandbox(
                "job",
                Some(record.generation),
                &armed_for,
                &instances,
                &network,
                &events_tx,
                &config,
                &cow_manager,
                &records,
                &snapshots,
            ),
        )
        .await
        .expect("TTL removal must retry a transient handoff timeout");

        assert!(!instances.read().unwrap().contains_key("job"));
        assert!(records.load("job").unwrap().is_none());
        assert!(!vm_dir.exists());
    }

    #[tokio::test]
    async fn force_remove_tears_down_cow_after_blocked_boot() {
        let data_dir = tempfile::tempdir().unwrap();

        let fake_firecracker = data_dir.path().join("fake-firecracker");
        std::fs::write(&fake_firecracker, b"#!/bin/sh\nexec /bin/sleep 3600\n").unwrap();
        std::fs::set_permissions(&fake_firecracker, std::fs::Permissions::from_mode(0o755))
            .unwrap();

        let mut config = VmmConfig::default();
        config.firecracker.binary = fake_firecracker.to_string_lossy().into_owned();
        config.firecracker.data_dir = data_dir.path().to_string_lossy().into_owned();
        config.firecracker.socket_timeout_secs = Some(5);
        config.defaults.kernel = data_dir
            .path()
            .join("kernel")
            .to_string_lossy()
            .into_owned();
        config.defaults.rootfs = data_dir
            .path()
            .join("rootfs")
            .to_string_lossy()
            .into_owned();
        let mut manager = SandboxManager::new(config).unwrap();
        manager.await_reconcile().await.unwrap();
        let cow_probe = Arc::new(CowTestProbe::default());
        manager.cow_manager = Arc::new(
            CowManager::new_with_test_probe(
                manager.config.firecracker.data_dir.as_str(),
                Arc::clone(&cow_probe),
            )
            .unwrap(),
        );

        // Reconciliation must finish before the test creates runtime state;
        // otherwise the startup sweep correctly classifies it as an orphan.
        let vm_dir = data_dir.path().join("sandboxes/job");
        std::fs::create_dir_all(&vm_dir).unwrap();

        // The SDK removes a stale socket before spawning. Seed one so this
        // task can bind only after spawn has crossed that exact boundary.
        let socket_path = vm_dir.join("firecracker.sock");
        std::fs::write(&socket_path, b"stale").unwrap();
        let socket_path_for_server = socket_path.clone();
        let (boot_blocked_tx, boot_blocked_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            while socket_path_for_server.exists() {
                tokio::task::yield_now().await;
            }
            let listener = loop {
                match tokio::net::UnixListener::bind(&socket_path_for_server) {
                    Ok(listener) => break listener,
                    Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("bind fake Firecracker socket: {error}"),
                }
            };

            // First connection is the SDK's spawn probe. Hold the first API
            // request open to wedge boot after the resource handoff.
            drop(listener.accept().await.unwrap());
            let _request = listener.accept().await.unwrap();
            boot_blocked_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });

        let (id, _) = manager
            .create_sandbox_keyed(
                SandboxSpec {
                    id: Some("job".into()),
                    network: SandboxNetworkSpec {
                        mode: "none".into(),
                    },
                    ..Default::default()
                },
                "create-key",
            )
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(5), boot_blocked_rx)
            .await
            .expect("boot must reach the blocked API request")
            .unwrap();
        assert_eq!(cow_probe.setup_count(), 1);
        let pid = manager
            .instances
            .read()
            .unwrap()
            .get(&id)
            .unwrap()
            .lock()
            .unwrap()
            .process
            .as_ref()
            .and_then(fc_sdk::FirecrackerProcess::pid)
            .expect("spawned process must be owned by the instance");
        assert!(
            manager
                .instances
                .read()
                .unwrap()
                .get(&id)
                .unwrap()
                .lock()
                .unwrap()
                .cow_handle
                .is_some(),
            "CoW ownership must be transferred before boot can be aborted"
        );
        let state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(vm_dir.join("state.json")).unwrap()).unwrap();
        assert_eq!(state["pid"].as_u64(), Some(u64::from(pid)));

        tokio::time::timeout(Duration::from_secs(5), manager.remove_sandbox(&id, true))
            .await
            .expect("force removal must cancel the blocked boot")
            .unwrap();

        #[allow(clippy::cast_possible_wrap, reason = "child pid fits platform pid_t")]
        let exited = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None);
        assert_eq!(exited, Err(nix::errno::Errno::ESRCH));
        assert_eq!(cow_probe.teardown_count(), 1);
        assert!(manager.records.load(&id).unwrap().is_none());
        assert!(!vm_dir.exists());

        server.abort();
    }

    #[tokio::test]
    async fn release_removes_the_chroot_of_an_adopted_pool_slot() {
        let data_dir = tempfile::tempdir().unwrap();
        let chroot_base = data_dir.path().join("jailer");
        let mut config = VmmConfig::default();
        config.firecracker.data_dir = data_dir.path().to_string_lossy().into_owned();
        config.firecracker.jailer = Some(crate::config::JailerConfig {
            binary: "/usr/bin/jailer".into(),
            uid: 0,
            gid: 0,
            chroot_base_dir: Some(chroot_base.to_string_lossy().into_owned()),
            netns: None,
            new_pid_ns: false,
            cgroup_version: None,
            parent_cgroup: None,
            resource_limits: vec![],
        });
        let slot_chroot = chroot_root(
            &config.firecracker.binary,
            &chroot_base.to_string_lossy(),
            "pool-slot",
        );
        let sandbox_chroot = chroot_root(
            &config.firecracker.binary,
            &chroot_base.to_string_lossy(),
            "job",
        );
        std::fs::create_dir_all(&slot_chroot).unwrap();
        std::fs::create_dir_all(&sandbox_chroot).unwrap();

        let arc = instance("job");
        arc.lock().unwrap().pool_slot_id = Some("pool-slot".into());
        let config = Arc::new(config);
        let network = Arc::new(
            NetworkManager::new(
                &config.network.cidr,
                &config.network.gateway,
                config.network.dns.clone(),
            )
            .unwrap(),
        );
        let cow_manager = Arc::new(CowManager::new(&config.firecracker.data_dir).unwrap());

        release_runtime_resources("job", &arc, &network, &config, &cow_manager)
            .await
            .unwrap();

        assert!(!slot_chroot.parent().unwrap().exists());
        assert!(
            sandbox_chroot.exists(),
            "the sandbox-id chroot belongs to nobody here and must not be touched"
        );
    }

    #[tokio::test]
    async fn stale_removal_does_not_touch_a_recreated_sandbox() {
        let data_dir = tempfile::tempdir().unwrap();
        let vm_dir = data_dir.path().join("sandboxes/job");
        std::fs::create_dir_all(&vm_dir).unwrap();
        let marker = vm_dir.join("new-generation");
        std::fs::write(&marker, b"keep").unwrap();

        let expected = Arc::new(Mutex::new(SandboxInstance::new(
            "job".into(),
            SandboxSpec::default(),
            None,
            vm_dir.clone(),
        )));
        let replacement = Arc::new(Mutex::new(SandboxInstance::new(
            "job".into(),
            SandboxSpec::default(),
            None,
            vm_dir,
        )));
        let instances: InstanceMap = Arc::new(RwLock::new(HashMap::from([(
            "job".into(),
            Arc::clone(&replacement),
        )])));
        let mut config = VmmConfig::default();
        config.firecracker.data_dir = data_dir.path().to_string_lossy().into_owned();
        let config = Arc::new(config);
        let network = Arc::new(
            NetworkManager::new(
                &config.network.cidr,
                &config.network.gateway,
                config.network.dns.clone(),
            )
            .unwrap(),
        );
        let cow_manager = Arc::new(CowManager::new(&config.firecracker.data_dir).unwrap());
        let records = Arc::new(SandboxRecordStore::new(data_dir.path()).unwrap());
        let snapshots = Arc::new(crate::snapshot::SnapshotCatalog::new(
            &config.firecracker.data_dir,
        ));
        let (events_tx, _) = broadcast::channel(1);

        assert!(matches!(
            remove_sandbox_impl(
                "job",
                true,
                &expected,
                &instances,
                &network,
                &events_tx,
                &config,
                &cow_manager,
                &records,
                &snapshots,
            )
            .await,
            Err(VmmError::WrongState { .. })
        ));
        assert!(marker.exists());
        assert!(Arc::ptr_eq(
            instances.read().unwrap().get("job").unwrap(),
            &replacement
        ));
    }

    #[test]
    fn removal_claims_one_generation_before_cleanup() {
        let data_dir = tempfile::tempdir().unwrap();
        let records = SandboxRecordStore::new(data_dir.path()).unwrap();
        let spec = SandboxSpec {
            id: Some("job".into()),
            ..Default::default()
        };
        let record = match records
            .provision_intent("job", "create-key", spec.clone())
            .unwrap()
        {
            ProvisionIntent::Created(record) => record,
            other => panic!("unexpected create intent: {other:?}"),
        };
        let expected = Arc::new(Mutex::new(SandboxInstance::new_with_generation(
            "job".into(),
            spec,
            None,
            PathBuf::from("/tmp/job"),
            record.generation,
        )));
        records
            .transition(
                "job",
                record.generation,
                SandboxTransition::Starting(SandboxProvisionOutcome {
                    ip_address: String::new(),
                }),
            )
            .unwrap();
        assert!(matches!(
            begin_removal("job", false, &expected, &records),
            Err(VmmError::WrongState { .. })
        ));
        records
            .transition("job", record.generation, SandboxTransition::Ready)
            .unwrap();
        expected.lock().unwrap().state = SandboxState::Running;

        assert!(matches!(
            begin_removal("job", false, &expected, &records),
            Err(VmmError::WrongState { .. })
        ));
        assert_eq!(expected.lock().unwrap().state, SandboxState::Running);

        assert_eq!(
            begin_removal("job", true, &expected, &records).unwrap().0,
            Some(record.generation)
        );
        assert_eq!(expected.lock().unwrap().state, SandboxState::Stopping);
        assert_eq!(
            records.load("job").unwrap().unwrap().phase,
            SandboxPhase::Removing
        );
    }
}
