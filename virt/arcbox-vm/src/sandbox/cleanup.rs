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

    // Kill the Firecracker process and wait for it to exit before releasing
    // network resources. TAP destruction (ioctl TUNSETPERSIST clear / ip link
    // delete fallback) fails if the TAP fd is still held by a running process.
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
        let inst = arc.lock().unwrap();
        if let Some(ref net) = inst.network {
            network.release(net);
        }
    }

    // Clean up the jailer chroot directory if applicable.
    if let Some(ref jc) = config.firecracker.jailer {
        let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
        let chroot_dir = chroot_root(&config.firecracker.binary, base, id);
        // Remove {base}/{exec_name}/{id}/ (parent of "root/").
        if let Some(parent) = chroot_dir.parent()
            && let Err(e) = tokio::fs::remove_dir_all(parent).await
        {
            warn!(sandbox_id = %id, err = %e, "failed to remove jailer chroot dir");
        }
    }

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

    instances.write().unwrap().remove(id);
    let _ = events_tx.send(SandboxEvent::new(id, "removed"));
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
        last_exit_code: inst.last_exit_code,
        error: inst.error.clone(),
    }
}
