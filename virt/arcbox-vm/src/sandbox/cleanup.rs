use super::boot::chroot_root;
use super::persistence::{SandboxRecordStore, SandboxTransition};
use super::types::action;
use super::*;

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
) -> Result<()> {
    let cleanup_lock = expected.lock().unwrap().cleanup_lock.clone();
    let _cleanup_guard = cleanup_lock.lock().await;
    super::ensure_current_instance(instances, id, expected)?;
    let record_generation = begin_removal(id, force, expected, records)?;

    release_runtime_resources(id, expected, network, config, cow_manager).await?;

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
) -> Result<Option<Uuid>> {
    let mut inst = expected.lock().unwrap();
    if !force && inst.state == SandboxState::Running {
        return Err(VmmError::WrongState {
            id: id.to_owned(),
            expected: "non-running (pass force=true to override)".into(),
            actual: inst.state.to_string(),
        });
    }
    if inst.state == SandboxState::Starting {
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
    Ok(generation)
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
) {
    let expected = loop {
        let current = instances.read().unwrap().get(id).cloned();
        let Some(expected) = armed_instance(generation, armed_for, current.as_ref()) else {
            return;
        };
        if expected.lock().unwrap().state != SandboxState::Starting {
            break expected;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    if let Err(error) = remove_sandbox_impl(
        id,
        true,
        &expected,
        instances,
        network,
        events_tx,
        config,
        cow_manager,
        records,
    )
    .await
    {
        error!(sandbox_id = %id, error = %error, "TTL sandbox removal failed");
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

    // Clean up the jailer chroot directory if applicable.
    if let Some(ref jc) = config.firecracker.jailer {
        let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
        let chroot_dir = chroot_root(&config.firecracker.binary, base, id);
        // Remove {base}/{exec_name}/{id}/ (parent of "root/").
        if let Some(parent) = chroot_dir.parent()
            && let Err(e) = tokio::fs::remove_dir_all(parent).await
            && e.kind() != std::io::ErrorKind::NotFound
        {
            return Err(VmmError::Io(e));
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::persistence::{ProvisionIntent, SandboxPhase, SandboxProvisionOutcome};

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
            begin_removal("job", true, &expected, &records),
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
            begin_removal("job", true, &expected, &records).unwrap(),
            Some(record.generation)
        );
        assert_eq!(expected.lock().unwrap().state, SandboxState::Stopping);
        assert_eq!(
            records.load("job").unwrap().unwrap().phase,
            SandboxPhase::Removing
        );
    }
}
