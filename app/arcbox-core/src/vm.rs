//! Virtual machine management.

mod types;

use crate::error::{CoreError, Result};
use crate::machine::MachineState;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Duration;

pub use types::{
    BlockDeviceConfig, SharedDirConfig, VmConfig, VmId, VmInfo, bridge_nic_mac_for_vm_id,
};

use arcbox_vmm::{
    SharedDirConfig as VmmSharedDirConfig, SnapshotCreateOptions, SnapshotInfo, SnapshotManager,
    SnapshotTargetType, Vmm, VmmConfig, VmmState,
};

/// Internal VM entry with info, config, and runtime state.
struct VmEntry {
    info: VmInfo,
    config: VmConfig,
    vmm: Option<Vmm>,
}

/// VM manager.
pub struct VmManager {
    vms: RwLock<HashMap<VmId, VmEntry>>,
    snapshot_manager: SnapshotManager,
}

impl VmManager {
    /// Creates a new VM manager.
    #[must_use]
    pub fn new(snapshot_dir: PathBuf) -> Self {
        Self {
            vms: RwLock::new(HashMap::new()),
            snapshot_manager: SnapshotManager::new(snapshot_dir),
        }
    }

    /// Creates a new VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be created.
    pub fn create(&self, config: VmConfig) -> Result<VmId> {
        let id = VmId::new();
        let info = VmInfo {
            id: id.clone(),
            state: MachineState::Created,
            cpus: config.cpus,
            memory_mb: config.memory_mb,
        };

        let entry = VmEntry {
            info,
            config,
            vmm: None,
        };

        self.vms
            .write()
            .map_err(|_| CoreError::LockPoisoned)?
            .insert(id.clone(), entry);

        tracing::info!("Created VM {}", id);
        Ok(id)
    }

    /// Sets the guest CID for an existing VM configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM is running or not found.
    pub fn set_guest_cid(&self, id: &VmId, guest_cid: u32) -> Result<()> {
        let mut vms = self.vms.write().map_err(|_| CoreError::LockPoisoned)?;

        let entry = vms
            .get_mut(id)
            .ok_or_else(|| CoreError::not_found(id.to_string()))?;

        if matches!(
            entry.info.state,
            MachineState::Running | MachineState::Starting
        ) {
            return Err(CoreError::invalid_state(format!(
                "cannot set guest_cid while VM is {:?}",
                entry.info.state
            )));
        }

        entry.config.guest_cid = Some(guest_cid);
        Ok(())
    }

    /// Updates the hypervisor backend for a stopped VM.
    ///
    /// The Vmm is built lazily from `VmConfig` at start, so changing the
    /// backend here and restarting boots the VM on the new backend with no
    /// teardown of the VM record or its disks.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM is running/starting or not found.
    pub fn set_backend(&self, id: &VmId, backend: arcbox_vmm::VmBackend) -> Result<()> {
        let mut vms = self.vms.write().map_err(|_| CoreError::LockPoisoned)?;

        let entry = vms
            .get_mut(id)
            .ok_or_else(|| CoreError::not_found(id.to_string()))?;

        if matches!(
            entry.info.state,
            MachineState::Running | MachineState::Starting
        ) {
            return Err(CoreError::invalid_state(format!(
                "cannot set backend while VM is {:?}",
                entry.info.state
            )));
        }

        entry.config.backend = backend;
        Ok(())
    }

    fn build_vmm_config(entry: &VmEntry) -> VmmConfig {
        let shared_dirs: Vec<VmmSharedDirConfig> = entry
            .config
            .shared_dirs
            .iter()
            .map(|sd| VmmSharedDirConfig {
                host_path: PathBuf::from(&sd.host_path),
                tag: sd.tag.clone(),
                read_only: sd.read_only,
            })
            .collect();

        // An `arcbox.debug_console=<path>` token on the kernel cmdline is the
        // single source of truth for the interactive debug console: the host
        // opens the Unix socket at `<path>`, and the guest rcS keys off the
        // same token to spawn a shell. Absent in normal boots.
        let debug_console_socket = entry.config.cmdline.as_deref().and_then(|c| {
            c.split_whitespace()
                .find_map(|t| t.strip_prefix(arcbox_constants::cmdline::DEBUG_CONSOLE_KEY))
                .map(PathBuf::from)
        });

        VmmConfig {
            vcpu_count: entry.config.cpus,
            memory_size: entry.config.memory_mb * 1024 * 1024,
            kernel_path: entry
                .config
                .kernel
                .as_ref()
                .map(PathBuf::from)
                .unwrap_or_default(),
            kernel_cmdline: entry.config.cmdline.clone().unwrap_or_default(),
            initrd_path: None,
            // The Rosetta share can only be hosted on VZ; `config.rosetta` is
            // the host capability. Gating here (rather than baking it into the
            // config) keeps it correct after `set_backend` switches HV<->VZ.
            enable_rosetta: entry.config.rosetta
                && matches!(entry.config.backend, arcbox_vmm::VmBackend::Vz),
            serial_console: true,
            virtio_console: true,
            shared_dirs,
            networking: entry.config.networking,
            vsock: entry.config.vsock,
            guest_cid: entry.config.guest_cid,
            balloon: entry.config.balloon,
            block_devices: entry
                .config
                .block_devices
                .iter()
                .map(|bd| arcbox_vmm::vmm::BlockDeviceConfig {
                    path: PathBuf::from(&bd.path),
                    read_only: bd.read_only,
                })
                .collect(),
            bridge_nic_mac: Some(bridge_nic_mac_for_vm_id(&entry.info.id)),
            // Backend is set per-machine on the `VmConfig`, read here at start.
            // `VmManager::set_backend` can change it on a stopped VM to switch
            // the System VM between HV and VZ.
            backend: entry.config.backend,
            debug_console_socket,
        }
    }

    /// Starts a VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be started.
    pub fn start(
        &self,
        id: &VmId,
        shared_dns_hosts: Option<std::sync::Arc<arcbox_dns::LocalHostsTable>>,
    ) -> Result<()> {
        let mut vms = self.vms.write().map_err(|_| CoreError::LockPoisoned)?;

        let entry = vms
            .get_mut(id)
            .ok_or_else(|| CoreError::not_found(id.to_string()))?;

        if entry.info.state != MachineState::Created && entry.info.state != MachineState::Stopped {
            return Err(CoreError::invalid_state(format!(
                "cannot start VM in state {:?}",
                entry.info.state
            )));
        }

        entry.info.state = MachineState::Starting;

        let vmm_config = Self::build_vmm_config(entry);

        // Create and start VMM. On failure, roll back state so retries can proceed.
        let mut vmm = match Vmm::new(vmm_config) {
            Ok(vmm) => vmm,
            Err(e) => {
                entry.info.state = MachineState::Created;
                return Err(e.into());
            }
        };

        // Share the host DNS hosts table with the VMM-side DnsForwarder.
        #[cfg(target_os = "macos")]
        if let Some(table) = shared_dns_hosts {
            vmm.set_shared_dns_hosts(table);
        }
        #[cfg(not(target_os = "macos"))]
        let _ = shared_dns_hosts;

        if let Err(e) = vmm.start() {
            entry.info.state = MachineState::Created;
            return Err(e.into());
        }

        entry.vmm = Some(vmm);
        entry.info.state = MachineState::Running;

        tracing::info!("Started VM {}", id);
        Ok(())
    }

    /// Stops a VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be stopped.
    pub fn stop(&self, id: &VmId) -> Result<()> {
        let mut vms = self.vms.write().map_err(|_| CoreError::LockPoisoned)?;

        let entry = vms
            .get_mut(id)
            .ok_or_else(|| CoreError::not_found(id.to_string()))?;

        if !matches!(
            entry.info.state,
            MachineState::Running | MachineState::Stopping
        ) {
            return Err(CoreError::invalid_state(format!(
                "cannot stop VM in state {:?}",
                entry.info.state
            )));
        }

        entry.info.state = MachineState::Stopping;

        // Stop the VMM
        if let Some(ref mut vmm) = entry.vmm {
            vmm.stop()?;
        }

        entry.vmm = None;
        entry.info.state = MachineState::Stopped;

        tracing::info!("Stopped VM {}", id);
        Ok(())
    }

    /// Reports whether a VM stopped on its own — i.e. its VMM is still owned by
    /// the entry (no `stop()` cleared it) but is no longer running.
    ///
    /// `None` = still running, or no VMM/entry. `Some(true)` = stopped via a
    /// guest PSCI SYSTEM_RESET (reboot request); `Some(false)` = stopped some
    /// other way (guest halt / crash).
    #[must_use]
    pub fn vm_self_stopped(&self, id: &VmId) -> Option<bool> {
        let vms = self.vms.read().ok()?;
        let vmm = vms.get(id)?.vmm.as_ref()?;
        if vmm.is_running() {
            None
        } else {
            Some(vmm.reset_requested())
        }
    }

    /// Reboots a VM in place: full teardown + fresh boot in the same process,
    /// keeping the entry (unlike `stop`, which drops the VMM). Used when the
    /// guest issued PSCI SYSTEM_RESET.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry is missing, has no VMM, or the reboot
    /// (teardown + re-initialization) fails.
    pub fn reboot(&self, id: &VmId) -> Result<()> {
        let mut vms = self.vms.write().map_err(|_| CoreError::LockPoisoned)?;
        let entry = vms
            .get_mut(id)
            .ok_or_else(|| CoreError::not_found(id.to_string()))?;
        let vmm = entry
            .vmm
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state(format!("VM {id} has no VMM to reboot")))?;
        vmm.reboot()?;
        entry.info.state = MachineState::Running;
        tracing::info!("Rebooted VM {}", id);
        Ok(())
    }

    /// Attempts graceful VM shutdown via vsock shutdown RPC.
    ///
    /// Sends a shutdown command to the guest agent, then waits for the VM to
    /// reach the Stopped state (triggered by PSCI SYSTEM_OFF after the guest
    /// completes its teardown).
    ///
    /// Returns `Ok(true)` if the VM stopped, `Ok(false)` if graceful shutdown
    /// timed out or the agent was unreachable.
    pub fn graceful_stop(&self, id: &VmId, timeout: Duration) -> Result<bool> {
        // Pre-check: determine whether to send the shutdown RPC based on
        // current state. Only Running VMs accept vsock connections.
        let should_send_rpc = {
            let vms = self.vms.read().map_err(|_| CoreError::LockPoisoned)?;
            let entry = vms
                .get(id)
                .ok_or_else(|| CoreError::not_found(id.to_string()))?;
            match entry.info.state {
                MachineState::Running => true,
                MachineState::Stopping => false,
                MachineState::Stopped => return Ok(true),
                other => {
                    return Err(CoreError::invalid_state(format!(
                        "cannot stop VM in state {:?}",
                        other
                    )));
                }
            }
        };

        // Phase 1: Send shutdown RPC while VM is still Running and VMM is in
        // the entry. connect_vsock requires Running state.
        if should_send_rpc {
            if let Err(e) =
                self.send_shutdown_rpc(id, arcbox_constants::timeouts::GUEST_SHUTDOWN_GRACE_SECS)
            {
                tracing::warn!("Shutdown RPC failed for VM {id}: {e}, cannot gracefully stop");
                return Ok(false);
            }
        }

        // Phase 2: Take VMM out under write lock so the blocking wait below
        // doesn't hold the lock for up to `timeout`.
        let vmm = {
            let mut vms = self.vms.write().map_err(|_| CoreError::LockPoisoned)?;

            let entry = vms
                .get_mut(id)
                .ok_or_else(|| CoreError::not_found(id.to_string()))?;

            if !matches!(
                entry.info.state,
                MachineState::Running | MachineState::Stopping
            ) {
                if entry.info.state == MachineState::Stopped {
                    return Ok(true);
                }
                return Err(CoreError::invalid_state(format!(
                    "cannot stop VM in state {:?}",
                    entry.info.state
                )));
            }

            entry.info.state = MachineState::Stopping;
            entry
                .vmm
                .take()
                .ok_or_else(|| CoreError::invalid_state("VMM not initialized"))?
        };

        // Phase 3: Wait for VM to reach Stopped state (PSCI will trigger this).
        let stop_result = vmm.wait_for_stopped(timeout).map_err(CoreError::from);

        // Re-acquire to update final state. The entry may have been removed
        // by a concurrent force_stop while the lock was released — if so,
        // safely drop the Vmm (skipping the macOS VF stop path) and return
        // Ok since the force path already handled teardown.
        let mut vms = self.vms.write().map_err(|_| CoreError::LockPoisoned)?;
        let Some(entry) = vms.get_mut(id) else {
            tracing::warn!("VM {id} removed during graceful stop (concurrent force stop)");
            // Force path already handled teardown. Skip the macOS VF stop
            // path (could crash) but still drop to release FDs/resources.
            #[allow(unused_mut)]
            let mut vmm = vmm;
            #[cfg(target_os = "macos")]
            vmm.set_skip_hypervisor_stop();
            drop(vmm);
            return Ok(stop_result.unwrap_or(false));
        };

        match stop_result {
            Ok(true) => {
                // On macOS the VF stop path can crash when the guest has
                // already halted via ACPI. Skip it but still drop normally
                // to close FDs and free resources. On Linux/KVM the normal
                // stop path is safe, so let Drop handle it.
                #[allow(unused_mut)]
                let mut vmm = vmm;
                #[cfg(target_os = "macos")]
                vmm.set_skip_hypervisor_stop();
                drop(vmm);
                entry.info.state = MachineState::Stopped;
                tracing::info!("Gracefully stopped VM {}", id);
                Ok(true)
            }
            Ok(false) | Err(_) => {
                // Only restore if no concurrent stop changed the state while
                // the lock was released. If state is no longer Stopping, a
                // concurrent stop() already handled teardown — drop the VMM
                // safely instead of resurrecting the VM.
                if entry.info.state == MachineState::Stopping {
                    entry.vmm = Some(vmm);
                    entry.info.state = MachineState::Running;
                } else {
                    tracing::warn!(
                        "VM {id} state changed to {:?} during graceful stop, not restoring",
                        entry.info.state
                    );
                    #[allow(unused_mut)]
                    let mut vmm = vmm;
                    #[cfg(target_os = "macos")]
                    vmm.set_skip_hypervisor_stop();
                    drop(vmm);
                }
                stop_result.map(|_| false)
            }
        }
    }

    /// Sends a shutdown RPC to the guest agent over vsock.
    ///
    /// Uses synchronous I/O on the raw vsock fd so this can be called from
    /// a non-async context. The response is read but its content is not
    /// checked — what matters is that the agent accepted the request and
    /// will power off the VM via PSCI.
    fn send_shutdown_rpc(&self, id: &VmId, timeout_seconds: u32) -> Result<()> {
        use arcbox_constants::ports::AGENT_PORT;
        use arcbox_constants::wire::MessageType;
        use prost::Message;

        let fd = self.connect_vsock(id, AGENT_PORT)?;

        // Build the shutdown request wire frame.
        let req = arcbox_protocol::ShutdownRequest { timeout_seconds };
        let payload = req.encode_to_vec();
        let frame = crate::AgentClient::build_message(MessageType::ShutdownRequest, "", &payload);

        // Send the request frame.
        let written = {
            let ptr = frame.as_ref().as_ptr().cast::<libc::c_void>();
            let len = frame.len();
            // SAFETY: fd is a valid connected vsock fd from connect_vsock.
            // ptr/len describe a valid byte slice.
            let n = unsafe { libc::write(fd, ptr, len) };
            if n < 0 {
                // SAFETY: closing a valid fd.
                unsafe { libc::close(fd) };
                return Err(CoreError::Vm(format!(
                    "vsock write failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            n as usize
        };
        if written != frame.len() {
            // SAFETY: closing a valid fd.
            unsafe { libc::close(fd) };
            return Err(CoreError::Vm("vsock short write".to_string()));
        }

        // Wait for the response with a 2s timeout.
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is a valid, initialized pollfd struct; fd is a valid connected fd.
        let poll_ret = unsafe { libc::poll(&raw mut pfd, 1, 2000) };
        if poll_ret <= 0 {
            // SAFETY: closing a valid fd.
            unsafe { libc::close(fd) };
            return if poll_ret == 0 {
                Err(CoreError::Vm("shutdown RPC response timed out".to_string()))
            } else {
                Err(CoreError::Vm(format!(
                    "vsock poll failed: {}",
                    std::io::Error::last_os_error()
                )))
            };
        }

        // Read the response — we only care that it arrived, not its content.
        let mut buf = [0u8; 256];
        // SAFETY: fd is a valid connected fd, buf is a valid mutable slice.
        let _ = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };

        // SAFETY: closing a valid fd.
        unsafe { libc::close(fd) };

        tracing::info!("Shutdown RPC sent to VM {id}");
        Ok(())
    }

    /// Marks a running VM as stopped without invoking hypervisor stop.
    ///
    /// This is a macOS fallback for environments where explicit VF stop can
    /// terminate the daemon process unexpectedly.
    #[cfg(target_os = "macos")]
    pub fn force_stop_without_hypervisor(&self, id: &VmId) -> Result<()> {
        let mut vms = self.vms.write().map_err(|_| CoreError::LockPoisoned)?;

        let entry = vms
            .get_mut(id)
            .ok_or_else(|| CoreError::not_found(id.to_string()))?;

        if entry.info.state != MachineState::Running {
            return Err(CoreError::invalid_state(format!(
                "cannot force stop VM in state {:?}",
                entry.info.state
            )));
        }

        entry.info.state = MachineState::Stopping;

        if let Some(mut vmm) = entry.vmm.take() {
            // On macOS the VF stop path can crash. Skip it but still drop
            // to close FDs and free resources. Linux/KVM is safe.
            #[cfg(target_os = "macos")]
            vmm.set_skip_hypervisor_stop();
            drop(vmm);
        }

        entry.info.state = MachineState::Stopped;
        tracing::warn!("Force-stopped VM {} without hypervisor stop", id);
        Ok(())
    }

    /// Pauses a VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be paused.
    pub fn pause(&self, id: &VmId) -> Result<()> {
        let mut vms = self.vms.write().map_err(|_| CoreError::LockPoisoned)?;

        let entry = vms
            .get_mut(id)
            .ok_or_else(|| CoreError::not_found(id.to_string()))?;

        if let Some(ref mut vmm) = entry.vmm {
            vmm.pause()?;
        }

        Ok(())
    }

    /// Resumes a paused VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be resumed.
    pub fn resume(&self, id: &VmId) -> Result<()> {
        let mut vms = self.vms.write().map_err(|_| CoreError::LockPoisoned)?;

        let entry = vms
            .get_mut(id)
            .ok_or_else(|| CoreError::not_found(id.to_string()))?;

        if let Some(ref mut vmm) = entry.vmm {
            vmm.resume()?;
        }

        Ok(())
    }

    /// Creates a VM snapshot for a running VM.
    ///
    /// # Errors
    ///
    /// Returns an error if VM is not running, snapshot capture fails,
    /// or snapshot data cannot be persisted.
    pub async fn create_vm_snapshot(
        &self,
        id: &VmId,
        options: SnapshotCreateOptions,
    ) -> Result<SnapshotInfo> {
        let pause_vm = options.pause_vm;
        let context = {
            let mut vms = self.vms.write().map_err(|_| CoreError::LockPoisoned)?;

            let entry = vms
                .get_mut(id)
                .ok_or_else(|| CoreError::not_found(id.to_string()))?;

            if entry.info.state != MachineState::Running {
                return Err(CoreError::invalid_state(format!(
                    "cannot snapshot VM in state {:?}",
                    entry.info.state
                )));
            }

            let vmm = entry
                .vmm
                .as_mut()
                .ok_or_else(|| CoreError::invalid_state("VMM not initialized"))?;

            let resume_after_capture = if pause_vm && vmm.state() == VmmState::Running {
                vmm.pause()?;
                true
            } else {
                false
            };

            let capture_result = vmm.capture_snapshot_context().map_err(CoreError::from);

            if resume_after_capture {
                vmm.resume()?;
            }

            capture_result?
        };

        self.snapshot_manager
            .create_vm_with_context(id.as_str(), options, context)
            .await
            .map_err(CoreError::from)
    }

    /// Lists snapshots for a VM, newest first.
    #[must_use]
    pub fn list_vm_snapshots(&self, id: &VmId) -> Vec<SnapshotInfo> {
        let mut snapshots = self.snapshot_manager.list(id.as_str());
        snapshots.sort_by_key(|s| std::cmp::Reverse(s.created));
        snapshots
    }

    /// Deletes a snapshot by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot does not exist or cannot be deleted.
    pub async fn delete_snapshot(&self, snapshot_id: &str) -> Result<()> {
        self.snapshot_manager
            .delete(snapshot_id)
            .await
            .map_err(CoreError::from)
    }

    /// Prunes old snapshots for a VM, keeping only `keep` most recent snapshots.
    ///
    /// # Returns
    ///
    /// Returns deleted snapshot IDs.
    ///
    /// # Errors
    ///
    /// Returns an error if snapshot deletion fails.
    pub async fn prune_vm_snapshots(&self, id: &VmId, keep: usize) -> Result<Vec<String>> {
        let mut snapshots = self.snapshot_manager.list(id.as_str());
        if snapshots.len() <= keep {
            return Ok(Vec::new());
        }

        snapshots.sort_by_key(|s| std::cmp::Reverse(s.created));

        let mut deleted = Vec::new();
        for snapshot in snapshots.into_iter().skip(keep) {
            self.snapshot_manager
                .delete(&snapshot.id)
                .await
                .map_err(CoreError::from)?;
            deleted.push(snapshot.id);
        }

        Ok(deleted)
    }

    /// Restores a VM from snapshot data.
    ///
    /// The VM is paused before applying snapshot state and resumed afterwards.
    ///
    /// # Errors
    ///
    /// Returns an error if snapshot loading fails or VM restore application fails.
    pub async fn restore_vm_snapshot(&self, id: &VmId, snapshot_id: &str) -> Result<()> {
        let info = self
            .snapshot_manager
            .get(snapshot_id)
            .ok_or_else(|| CoreError::not_found(format!("snapshot {snapshot_id}")))?;

        if info.target_type != SnapshotTargetType::Vm {
            return Err(CoreError::invalid_state(format!(
                "snapshot {snapshot_id} is not a VM snapshot"
            )));
        }

        if info.target_id != id.as_str() {
            return Err(CoreError::invalid_state(format!(
                "snapshot {snapshot_id} belongs to VM {}, not {}",
                info.target_id, id
            )));
        }

        self.snapshot_manager
            .restore(snapshot_id)
            .await
            .map_err(CoreError::from)?;

        let restore_data = self
            .snapshot_manager
            .take_restore_data(snapshot_id)
            .ok_or_else(|| {
                CoreError::invalid_state(format!(
                    "snapshot {snapshot_id} restore data unavailable after restore"
                ))
            })?;

        let mut vms = self.vms.write().map_err(|_| CoreError::LockPoisoned)?;

        let entry = vms
            .get_mut(id)
            .ok_or_else(|| CoreError::not_found(id.to_string()))?;

        if entry.info.state != MachineState::Running {
            return Err(CoreError::invalid_state(format!(
                "cannot restore VM in state {:?}",
                entry.info.state
            )));
        }

        let vmm = entry
            .vmm
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("VMM not initialized"))?;

        // Pause the VM before applying snapshot state so guest CPUs don't
        // execute while memory and device state are being overwritten.
        let was_running = vmm.state() == VmmState::Running;
        if was_running {
            vmm.pause()?;
        }

        let apply_result = vmm.restore_from_snapshot_data(&restore_data);

        if was_running {
            vmm.resume()?;
        }

        apply_result.map_err(CoreError::from)
    }

    /// Gets VM information.
    #[must_use]
    pub fn get(&self, id: &VmId) -> Option<VmInfo> {
        self.vms.read().ok()?.get(id).map(|e| e.info.clone())
    }

    /// Lists all VMs.
    #[must_use]
    pub fn list(&self) -> Vec<VmInfo> {
        self.vms
            .read()
            .map(|vms| vms.values().map(|e| e.info.clone()).collect())
            .unwrap_or_default()
    }

    /// Removes a VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be removed.
    pub fn remove(&self, id: &VmId) -> Result<()> {
        let mut vms = self.vms.write().map_err(|_| CoreError::LockPoisoned)?;

        let entry = vms
            .get(id)
            .ok_or_else(|| CoreError::not_found(id.to_string()))?;

        if entry.info.state == MachineState::Running {
            return Err(CoreError::invalid_state(
                "cannot remove running VM".to_string(),
            ));
        }

        vms.remove(id);
        tracing::info!("Removed VM {}", id);
        Ok(())
    }

    /// Connects to a vsock port on a running VM.
    ///
    /// This establishes a vsock connection to the specified port number
    /// on the guest VM. The VM must be running.
    ///
    /// # Arguments
    /// * `id` - The VM ID
    /// * `port` - The port number to connect to (e.g., 1024 for agent)
    ///
    /// # Returns
    /// A file descriptor for the connection that can be used for I/O.
    ///
    /// # Errors
    /// Returns an error if the VM is not found, not running, or connection fails.
    pub fn connect_vsock(&self, id: &VmId, port: u32) -> Result<std::os::unix::io::RawFd> {
        let vms = self.vms.read().map_err(|_| CoreError::LockPoisoned)?;

        let entry = vms
            .get(id)
            .ok_or_else(|| CoreError::not_found(id.to_string()))?;

        if entry.info.state != MachineState::Running {
            return Err(CoreError::invalid_state(format!(
                "cannot connect vsock: VM is {:?}",
                entry.info.state
            )));
        }

        let vmm = entry
            .vmm
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("VMM not initialized"))?;

        vmm.connect_vsock(port).map_err(CoreError::from)
    }

    /// Reads serial console output from a running VM (macOS only).
    #[cfg(target_os = "macos")]
    pub fn read_console_output(&self, id: &VmId) -> Result<String> {
        let vms = self.vms.read().map_err(|_| CoreError::LockPoisoned)?;

        let entry = vms
            .get(id)
            .ok_or_else(|| CoreError::not_found(id.to_string()))?;

        if entry.info.state != MachineState::Running {
            return Err(CoreError::invalid_state(format!(
                "cannot read console output: VM is {:?}",
                entry.info.state
            )));
        }

        let vmm = entry
            .vmm
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("VMM not initialized"))?;

        vmm.read_console_output().map_err(CoreError::from)
    }

    /// Reads agent log output (hvc1) from a running VM (macOS only).
    #[cfg(target_os = "macos")]
    pub fn read_agent_log_output(&self, id: &VmId) -> Result<String> {
        let vms = self.vms.read().map_err(|_| CoreError::LockPoisoned)?;

        let entry = vms
            .get(id)
            .ok_or_else(|| CoreError::not_found(id.to_string()))?;

        if entry.info.state != MachineState::Running {
            return Err(CoreError::invalid_state(format!(
                "cannot read agent log: VM is {:?}",
                entry.info.state
            )));
        }

        let vmm = entry
            .vmm
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("VMM not initialized"))?;

        vmm.read_agent_log_output().map_err(CoreError::from)
    }

    /// Sets the target memory size for the balloon device on a running VM.
    ///
    /// The balloon device will inflate or deflate to reach the target:
    /// - **Smaller target**: Balloon inflates, reclaiming memory from guest
    /// - **Larger target**: Balloon deflates, returning memory to guest
    ///
    /// # Arguments
    /// * `id` - The VM ID
    /// * `target_bytes` - Target memory size in bytes
    ///
    /// # Errors
    /// Returns an error if the VM is not found, not running, or balloon operation fails.
    #[cfg(target_os = "macos")]
    pub fn set_balloon_target(&self, id: &VmId, target_bytes: u64) -> Result<()> {
        let vms = self.vms.read().map_err(|_| CoreError::LockPoisoned)?;

        let entry = vms
            .get(id)
            .ok_or_else(|| CoreError::not_found(id.to_string()))?;

        if entry.info.state != MachineState::Running {
            return Err(CoreError::invalid_state(format!(
                "cannot set balloon target: VM is {:?}",
                entry.info.state
            )));
        }

        let vmm = entry
            .vmm
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("VMM not initialized"))?;

        vmm.set_balloon_target(target_bytes)
            .map_err(CoreError::from)
    }

    /// Gets the current target memory size from the balloon device.
    ///
    /// Returns the target memory size in bytes, or 0 if no balloon is configured
    /// or the VM is not running.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn get_balloon_target(&self, id: &VmId) -> u64 {
        let Ok(vms) = self.vms.read() else {
            return 0;
        };

        let Some(entry) = vms.get(id) else {
            return 0;
        };

        if entry.info.state != MachineState::Running {
            return 0;
        }

        entry.vmm.as_ref().map_or(0, Vmm::get_balloon_target)
    }

    /// Gets balloon statistics for a VM.
    ///
    /// Returns current balloon stats including target, current, and configured memory sizes.
    #[cfg(target_os = "macos")]
    pub fn get_balloon_stats(&self, id: &VmId) -> Result<arcbox_hypervisor::BalloonStats> {
        let vms = self.vms.read().map_err(|_| CoreError::LockPoisoned)?;

        let entry = vms
            .get(id)
            .ok_or_else(|| CoreError::not_found(id.to_string()))?;

        if entry.info.state != MachineState::Running {
            return Err(CoreError::invalid_state(format!(
                "cannot get balloon stats: VM is {:?}",
                entry.info.state
            )));
        }

        let vmm = entry
            .vmm
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("VMM not initialized"))?;

        Ok(vmm.get_balloon_stats())
    }

    /// Captures a debug snapshot (virtio queue state + vCPU exit
    /// counters) from a VM.
    ///
    /// Custom-VMM backends only — empty under VZ (see
    /// [`arcbox_vmm::Vmm::debug_snapshot`]).
    ///
    /// # Errors
    ///
    /// Returns an error if the VM is not found or its VMM has not been
    /// created.
    pub fn debug_snapshot(&self, id: &VmId) -> Result<arcbox_vmm::VmDebugSnapshot> {
        let vms = self.vms.read().map_err(|_| CoreError::LockPoisoned)?;

        let entry = vms
            .get(id)
            .ok_or_else(|| CoreError::not_found(id.to_string()))?;

        let vmm = entry
            .vmm
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("VMM not initialized"))?;

        Ok(vmm.debug_snapshot())
    }

    /// Takes the inbound listener manager from a running VM (Darwin only).
    ///
    /// The manager is created during VM start when the network device is set up.
    /// After this call the VMM no longer owns the manager; the caller must call
    /// `stop_all()` on shutdown.
    #[cfg(target_os = "macos")]
    pub fn take_inbound_listener_manager(
        &self,
        id: &VmId,
    ) -> Option<arcbox_net::darwin::inbound_relay::InboundListenerManager> {
        let mut vms = self.vms.write().ok()?;
        let entry = vms.get_mut(id)?;
        entry.vmm.as_mut()?.take_inbound_listener_manager()
    }

    /// Returns the vmnet bridge interface name for a running VM.
    ///
    /// After vmnet creates the shared interface, the system also creates a
    /// bridge with a vmnet member. We resolve it via the MAC that vmnet
    /// reported. Since vmnet has already started, the bridge is immediately
    /// present — no retry needed.
    #[cfg(all(target_os = "macos", feature = "vmnet"))]
    pub fn vmnet_bridge_name(&self, id: &VmId) -> Option<String> {
        let vms = self.vms.read().ok()?;
        let entry = vms.get(id)?;
        let vmm = entry.vmm.as_ref()?;
        let info = vmm.vmnet_interface_info()?;
        let mac_str = arcbox_net::darwin::format_mac(&info.mac);
        let bridge = crate::bridge_discovery::resolve_bridge_by_mac(&mac_str)?;
        Some(bridge.name)
    }

    #[cfg(test)]
    pub(crate) fn guest_cid_for_test(&self, id: &VmId) -> Option<u32> {
        self.vms
            .read()
            .ok()?
            .get(id)
            .and_then(|entry| entry.config.guest_cid)
    }

    #[cfg(test)]
    pub(crate) fn build_vmm_config_for_test(&self, id: &VmId) -> Result<VmmConfig> {
        let vms = self.vms.read().map_err(|_| CoreError::LockPoisoned)?;
        let entry = vms
            .get(id)
            .ok_or_else(|| CoreError::not_found(id.to_string()))?;
        Ok(Self::build_vmm_config(entry))
    }
}

#[cfg(test)]
mod tests;
