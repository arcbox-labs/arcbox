use super::boot::chroot_root;
use super::*;

#[allow(
    clippy::type_complexity,
    reason = "manager storage type is shared here"
)]
pub(super) async fn remove_sandbox_impl(
    id: &str,
    _force: bool,
    instances: &Arc<RwLock<HashMap<SandboxId, Arc<Mutex<SandboxInstance>>>>>,
    network: &Arc<NetworkManager>,
    events_tx: &broadcast::Sender<SandboxEvent>,
    config: &Arc<VmmConfig>,
    cow_manager: &Arc<CowManager>,
) {
    let entry = instances.read().unwrap().get(id).cloned();
    let Some(arc) = entry else {
        return;
    };

    release_runtime_resources(id, &arc, network, config, cow_manager).await;

    // Remove the sandbox working directory (sockets, logs, etc.).
    let vm_dir = PathBuf::from(&config.firecracker.data_dir)
        .join("sandboxes")
        .join(id);
    if let Err(e) = tokio::fs::remove_dir_all(&vm_dir).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        warn!(sandbox_id = %id, err = %e, "failed to remove sandbox dir");
    }

    // For restored sandboxes: also remove the original sandbox's vm_dir,
    // which we recreated during restore to host the vmstate-recorded
    // `rootfs.link` symlink and FC vsock socket.  Without this every
    // restore-and-remove cycle would leak one orphaned directory.
    let origin_dir = arc.lock().unwrap().restore_origin_dir.clone();
    if let Some(dir) = origin_dir
        && let Err(e) = tokio::fs::remove_dir_all(&dir).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        warn!(sandbox_id = %id, err = %e, "failed to remove restore origin dir");
    }

    // Only drop the map entry if it is still the instance we tore down. A
    // concurrent re-create under the same id installs a different Arc that this
    // removal must not evict.
    {
        let mut map = instances.write().unwrap();
        if map.get(id).is_some_and(|cur| Arc::ptr_eq(cur, &arc)) {
            map.remove(id);
        }
    }
    let _ = events_tx.send(SandboxEvent::new(id, "removed"));
}

/// True when `armed_for` still refers to the instance currently registered
/// under the id. Used to decide whether a fired TTL timer applies.
fn is_armed_instance(
    armed_for: &std::sync::Weak<Mutex<SandboxInstance>>,
    current: Option<&Arc<Mutex<SandboxInstance>>>,
) -> bool {
    match (armed_for.upgrade(), current) {
        (Some(mine), Some(cur)) => Arc::ptr_eq(&mine, cur),
        _ => false,
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
pub(super) async fn expire_sandbox(
    id: &str,
    armed_for: &std::sync::Weak<Mutex<SandboxInstance>>,
    instances: &Arc<RwLock<HashMap<SandboxId, Arc<Mutex<SandboxInstance>>>>>,
    network: &Arc<NetworkManager>,
    events_tx: &broadcast::Sender<SandboxEvent>,
    config: &Arc<VmmConfig>,
    cow_manager: &Arc<CowManager>,
) {
    let current = instances.read().unwrap().get(id).cloned();
    if !is_armed_instance(armed_for, current.as_ref()) {
        return;
    }
    remove_sandbox_impl(id, true, instances, network, events_tx, config, cow_manager).await;
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
) {
    let mut fc_process = {
        let mut inst = arc.lock().unwrap();
        if let Some(ref mut proc) = inst.process
            && let Some(pid) = proc.pid()
            && pid > 0
        {
            let _ = nix::sys::signal::kill(
                #[allow(
                    clippy::cast_possible_wrap,
                    reason = "Firecracker pid fits platform pid_t"
                )]
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        inst.process.take()
    };
    // Await process exit outside the lock. Use a timeout so cleanup proceeds
    // even if the process is stuck in uninterruptible sleep after SIGKILL.
    if let Some(ref mut proc) = fc_process {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), proc.wait()).await;
    }

    // Teardown dm-snapshot CoW device (must happen after FC process exits
    // because Firecracker holds the block device open).
    {
        let cow_handle = arc.lock().unwrap().cow_handle.take();
        if let Some(ref handle) = cow_handle {
            cow_manager.teardown(handle).await;
        }
    }

    // Release network resources (destroys TAP via ioctl).
    {
        let mut inst = arc.lock().unwrap();
        if let Some(net) = inst.network.take() {
            network.release(&net);
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
            warn!(sandbox_id = %id, err = %e, "failed to remove jailer chroot dir");
        }
    }
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
        assert!(is_armed_instance(&armed_for, Some(&original)));

        // Removed and re-created under the same id → a different Arc; the stale
        // timer must NOT match the new generation.
        let recreated = instance("job");
        assert!(!is_armed_instance(&armed_for, Some(&recreated)));

        // Removed with nothing re-created → no match.
        assert!(!is_armed_instance(&armed_for, None));

        // Original fully dropped → the Weak is dead, no match even if some
        // other instance is present.
        drop(original);
        assert!(!is_armed_instance(&armed_for, Some(&recreated)));
    }
}
