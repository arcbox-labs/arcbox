use std::sync::atomic::Ordering;
use std::time::Duration;

use arcbox_vz::{
    NetworkDeviceConfiguration, SharedDirectory, SingleDirectoryShare, SocketDeviceConfiguration,
    StorageDeviceConfiguration, VirtioFileSystemDeviceConfiguration, VirtualMachineState,
};

use crate::{
    error::HypervisorError,
    traits::VirtualMachine,
    types::{DeviceSnapshot, VirtioDeviceConfig, VirtioDeviceType},
};

use super::{DarwinMemory, DarwinVm, VmState};
use crate::darwin::vcpu::DarwinVcpu;

impl VirtualMachine for DarwinVm {
    type Vcpu = DarwinVcpu;
    type Memory = DarwinMemory;

    fn is_managed_execution(&self) -> bool {
        // Darwin Virtualization.framework manages vCPU execution internally
        true
    }

    fn memory(&self) -> &Self::Memory {
        &self.memory
    }

    fn create_vcpu(&mut self, id: u32) -> Result<Self::Vcpu, HypervisorError> {
        if id >= self.config.vcpu_count as u32 {
            return Err(HypervisorError::VcpuCreationFailed {
                id,
                reason: format!(
                    "vCPU ID {} exceeds configured count {}",
                    id, self.config.vcpu_count
                ),
            });
        }

        // Check if already created
        {
            let vcpus = self
                .vcpus
                .read()
                .map_err(|_| HypervisorError::VcpuCreationFailed {
                    id,
                    reason: "Lock poisoned".to_string(),
                })?;

            if vcpus.contains(&id) {
                return Err(HypervisorError::VcpuCreationFailed {
                    id,
                    reason: "vCPU already created".to_string(),
                });
            }
        }

        // Create vCPU for managed execution.
        // On Virtualization.framework, vCPU execution is managed internally by the framework.
        // The vCPU struct is a lightweight handle that tracks vCPU ID and state;
        // VM state is queried through the DarwinVm's state() method instead.
        let vcpu = DarwinVcpu::new(id);

        // Record creation
        {
            let mut vcpus =
                self.vcpus
                    .write()
                    .map_err(|_| HypervisorError::VcpuCreationFailed {
                        id,
                        reason: "Lock poisoned".to_string(),
                    })?;
            vcpus.push(id);
        }

        tracing::debug!("Created vCPU {} for VM {} (managed execution)", id, self.id);

        Ok(vcpu)
    }

    fn add_virtio_device(&mut self, device: VirtioDeviceConfig) -> Result<(), HypervisorError> {
        // Check state
        let state = self.state();
        if state != VmState::Created {
            return Err(HypervisorError::DeviceError(
                "Cannot add device: VM not in Created state".to_string(),
            ));
        }

        // Get mutable reference to config
        let vz_config = self.vz_config.as_mut().ok_or_else(|| {
            HypervisorError::DeviceError("VZ configuration not available".to_string())
        })?;

        match device.device_type {
            VirtioDeviceType::Block => {
                // Create block device using arcbox-vz API
                if let Some(ref path) = device.path {
                    let storage_device =
                        StorageDeviceConfiguration::disk_image(path, device.read_only)
                            .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
                    vz_config.add_storage_device(storage_device);
                    tracing::debug!("Added block device: {}", path);
                }
            }
            VirtioDeviceType::Net => {
                let network_device = if let Some(fd) = device.net_fd {
                    // File-handle attachment: host owns the full network stack.
                    match device.mac_address.as_deref() {
                        Some(mac) => NetworkDeviceConfiguration::file_handle_with_mac(fd, mac),
                        None => NetworkDeviceConfiguration::file_handle(fd),
                    }
                    .map_err(|e| HypervisorError::DeviceError(e.to_string()))?
                } else {
                    // Fallback to Apple's built-in NAT attachment.
                    match device.mac_address.as_deref() {
                        Some(mac_address) => NetworkDeviceConfiguration::nat_with_mac(mac_address)
                            .map_err(|e| HypervisorError::DeviceError(e.to_string()))?,
                        None => NetworkDeviceConfiguration::nat()
                            .map_err(|e| HypervisorError::DeviceError(e.to_string()))?,
                    }
                };
                vz_config.add_network_device(network_device);
                tracing::debug!(
                    mac_address = device.mac_address.as_deref().unwrap_or("random"),
                    "Added network device (file_handle={})",
                    device.net_fd.is_some()
                );
            }
            VirtioDeviceType::Console => {
                // Console is handled separately via setup_serial_console()
                tracing::debug!("Console device will be configured separately");
            }
            VirtioDeviceType::Fs => {
                // Create filesystem device using arcbox-vz API
                if let (Some(path), Some(tag)) = (&device.path, &device.tag) {
                    let directory = SharedDirectory::new(path, device.read_only)
                        .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
                    let share = SingleDirectoryShare::new(directory)
                        .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
                    let mut fs_device = VirtioFileSystemDeviceConfiguration::new(tag)
                        .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
                    fs_device.set_share(share);
                    vz_config.add_directory_share(fs_device);
                    tracing::debug!("Added filesystem device: {} -> {}", tag, path);
                }
            }
            VirtioDeviceType::Vsock => {
                // Create vsock device using arcbox-vz API
                let socket_device = SocketDeviceConfiguration::new()
                    .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
                vz_config.add_socket_device(socket_device);
                tracing::debug!("Added vsock device");
            }
            VirtioDeviceType::Rng => {
                // Entropy device is already added in new()
                tracing::debug!("Entropy device already configured");
            }
            VirtioDeviceType::Balloon => {
                // Mark balloon as configured
                // NOTE: arcbox-vz does not yet support balloon device configuration
                self.balloon_configured = true;
                tracing::debug!("Balloon device configured (pending arcbox-vz support)");
            }
            _ => {
                // Other device types (Gpu) not yet supported on Darwin
                tracing::warn!(
                    "Device type {:?} not supported on Darwin",
                    device.device_type
                );
            }
        }

        tracing::debug!("Added {:?} device to VM {}", device.device_type, self.id);

        // Store device configuration for snapshot/restore
        self.device_configs.push(device);

        Ok(())
    }

    fn start(&mut self) -> Result<(), HypervisorError> {
        let state = self.state();
        if state != VmState::Created && state != VmState::Stopped {
            return Err(HypervisorError::VmStateError {
                expected: "Created or Stopped".to_string(),
                actual: format!("{state:?}"),
            });
        }

        self.set_state(VmState::Starting);

        // Finalize configuration if VM hasn't been created yet
        if self.vz_vm.is_none() {
            // Enable serial console for boot diagnostics unless already configured.
            if self.console_fds.is_none() {
                if let Err(err) = self.setup_serial_console() {
                    tracing::warn!("Failed to set up serial console: {}", err);
                }
            }
            self.finalize_configuration()?;
        }

        // Start the VM using arcbox-vz's async API
        if let Some(ref vm) = self.vz_vm {
            tracing::debug!("Starting VM {} asynchronously...", self.id);

            // Get tokio runtime handle for async operations
            let rt = tokio::runtime::Handle::try_current().map_err(|_| {
                self.set_state(VmState::Error);
                HypervisorError::VmError("No tokio runtime available for VM start".to_string())
            })?;

            // Start the VM using arcbox-vz's async start
            // Use block_in_place to allow blocking in async context
            tokio::task::block_in_place(|| rt.block_on(vm.start())).map_err(|e| {
                self.set_state(VmState::Error);
                HypervisorError::VmError(format!("Failed to start VM: {e}"))
            })?;

            tracing::debug!("Waiting for VM {} to reach Running state...", self.id);

            // Wait for VM to reach Running state
            match self.wait_for_state(VirtualMachineState::Running, Duration::from_secs(30)) {
                Ok(()) => {
                    self.running.store(true, Ordering::SeqCst);
                    self.set_state(VmState::Running);
                    tracing::info!("Started VM {}", self.id);
                    if let Some(path) = self.console_path() {
                        tracing::info!("Serial console attached at {}", path);
                    }
                    Ok(())
                }
                Err(e) => {
                    // Check actual VM state for better error message
                    if let Some(ref vz) = self.vz_vm {
                        let state = vz.state();
                        tracing::error!(
                            "VM {} failed to start, current state: {:?}",
                            self.id,
                            state
                        );
                    }
                    self.set_state(VmState::Error);
                    Err(e)
                }
            }
        } else {
            self.set_state(VmState::Error);
            Err(HypervisorError::VmError("No VZ VM instance".to_string()))
        }
    }

    fn pause(&mut self) -> Result<(), HypervisorError> {
        let state = self.state();
        if state != VmState::Running {
            return Err(HypervisorError::VmStateError {
                expected: "Running".to_string(),
                actual: format!("{state:?}"),
            });
        }

        if let Some(ref vm) = self.vz_vm {
            // Get tokio runtime handle for async operations
            let rt = tokio::runtime::Handle::try_current().map_err(|_| {
                HypervisorError::VmError("No tokio runtime available for VM pause".to_string())
            })?;

            // Pause using arcbox-vz's async pause
            // Use block_in_place to allow blocking in async context
            tokio::task::block_in_place(|| rt.block_on(vm.pause()))
                .map_err(|e| HypervisorError::VmError(format!("Failed to pause VM: {e}")))?;

            self.wait_for_state(VirtualMachineState::Paused, Duration::from_secs(10))?;
        }

        self.set_state(VmState::Paused);
        tracing::info!("Paused VM {}", self.id);

        Ok(())
    }

    fn resume(&mut self) -> Result<(), HypervisorError> {
        let state = self.state();
        if state != VmState::Paused {
            return Err(HypervisorError::VmStateError {
                expected: "Paused".to_string(),
                actual: format!("{state:?}"),
            });
        }

        if let Some(ref vm) = self.vz_vm {
            // Get tokio runtime handle for async operations
            let rt = tokio::runtime::Handle::try_current().map_err(|_| {
                HypervisorError::VmError("No tokio runtime available for VM resume".to_string())
            })?;

            // Resume using arcbox-vz's async resume
            // Use block_in_place to allow blocking in async context
            tokio::task::block_in_place(|| rt.block_on(vm.resume()))
                .map_err(|e| HypervisorError::VmError(format!("Failed to resume VM: {e}")))?;

            self.wait_for_state(VirtualMachineState::Running, Duration::from_secs(10))?;
        }

        self.set_state(VmState::Running);
        tracing::info!("Resumed VM {}", self.id);

        Ok(())
    }

    fn stop(&mut self) -> Result<(), HypervisorError> {
        let state = self.state();
        if state != VmState::Running && state != VmState::Paused {
            return Err(HypervisorError::VmStateError {
                expected: "Running or Paused".to_string(),
                actual: format!("{state:?}"),
            });
        }

        self.set_state(VmState::Stopping);

        if let Some(ref vm) = self.vz_vm {
            // Check if VM can be stopped
            let can_stop = vm.can_stop();
            tracing::debug!("VM {} can_stop: {}", self.id, can_stop);

            if can_stop {
                // Get tokio runtime handle for async operations
                let rt = tokio::runtime::Handle::try_current().ok();

                if let Some(rt) = rt {
                    // Stop using arcbox-vz's async stop
                    // Use block_in_place to allow blocking in async context
                    match tokio::task::block_in_place(|| rt.block_on(vm.stop())) {
                        Ok(()) => {
                            tracing::debug!("VM {} stop completed", self.id);
                        }
                        Err(e) => {
                            tracing::warn!("VM {} stop failed: {}", self.id, e);
                            // Continue with cleanup even if stop fails
                        }
                    }
                } else {
                    // Guest shutdown is handled by the vsock shutdown RPC at
                    // the VmManager layer. Without a tokio runtime we cannot
                    // call the async VZ stop — the VM will be force-stopped
                    // by process exit.
                    tracing::debug!("VM {} no tokio runtime for async stop", self.id);
                }

                // Wait for VM to reach Stopped state
                match self.wait_for_state(VirtualMachineState::Stopped, Duration::from_secs(10)) {
                    Ok(()) => {
                        tracing::debug!("VM {} reached Stopped state", self.id);
                    }
                    Err(e) => {
                        tracing::warn!("VM {} stop wait failed: {}", self.id, e);
                        // Continue with cleanup even if wait fails
                    }
                }
            } else {
                tracing::warn!(
                    "VM {} cannot be stopped (canStop=false), forcing state change",
                    self.id
                );
            }
        }

        self.running.store(false, Ordering::SeqCst);
        self.set_state(VmState::Stopped);

        tracing::info!("Stopped VM {}", self.id);

        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn vcpu_count(&self) -> u32 {
        self.config.vcpu_count as u32
    }

    fn snapshot_devices(&self) -> Result<Vec<DeviceSnapshot>, HypervisorError> {
        // Darwin Virtualization.framework does not expose internal device state.
        // However, we store the device configuration metadata which allows:
        // 1. Verifying device configuration matches on restore
        // 2. Re-creating devices with the same configuration
        //
        // The `state` field contains serialized VirtioDeviceConfig.
        let mut snapshots = Vec::new();

        for (idx, config) in self.device_configs.iter().enumerate() {
            // Serialize the device configuration to JSON bytes
            let state = serde_json::to_vec(config).unwrap_or_default();

            let name = match config.device_type {
                VirtioDeviceType::Block => {
                    if let Some(ref path) = config.path {
                        format!(
                            "block-{}-{}",
                            idx,
                            path.rsplit('/').next().unwrap_or("disk")
                        )
                    } else {
                        format!("block-{idx}")
                    }
                }
                VirtioDeviceType::Net => format!("net-{idx}"),
                VirtioDeviceType::Console => "console-0".to_string(),
                VirtioDeviceType::Fs => {
                    if let Some(ref tag) = config.tag {
                        format!("fs-{tag}")
                    } else {
                        format!("fs-{idx}")
                    }
                }
                VirtioDeviceType::Vsock => "vsock-0".to_string(),
                _ => format!("device-{idx}"),
            };

            snapshots.push(DeviceSnapshot {
                device_type: config.device_type,
                name,
                state,
            });
        }

        // Record serial ports if configured (not in device_configs).
        if self.console_fds.is_some() {
            snapshots.push(DeviceSnapshot {
                device_type: VirtioDeviceType::Console,
                name: "serial-0".to_string(),
                state: Vec::new(),
            });
        }
        if self.agent_log_fds.is_some() {
            snapshots.push(DeviceSnapshot {
                device_type: VirtioDeviceType::Console,
                name: "serial-1".to_string(),
                state: Vec::new(),
            });
        }

        tracing::debug!(
            "snapshot_devices: captured {} device configurations for VM {}",
            snapshots.len(),
            self.id
        );

        Ok(snapshots)
    }

    fn restore_devices(&mut self, snapshots: &[DeviceSnapshot]) -> Result<(), HypervisorError> {
        // Darwin Virtualization.framework does not support live device state restore.
        // However, we can validate that the snapshot device configuration matches
        // the current VM configuration.
        //
        // For actual device restore, the VM should be recreated with the same
        // configuration from the snapshot metadata.
        tracing::info!(
            "restore_devices: validating {} devices for VM {}",
            snapshots.len(),
            self.id
        );

        // Deserialize and validate device configurations
        let mut mismatches = Vec::new();

        for snapshot in snapshots {
            // Try to deserialize the stored configuration
            if !snapshot.state.is_empty() {
                if let Ok(stored_config) =
                    serde_json::from_slice::<VirtioDeviceConfig>(&snapshot.state)
                {
                    // Find matching device in current configuration
                    let matches = self.device_configs.iter().any(|current| {
                        current.device_type == stored_config.device_type
                            && current.path == stored_config.path
                            && current.tag == stored_config.tag
                    });

                    if !matches {
                        mismatches.push(format!(
                            "{:?} device '{}' (path={:?}, tag={:?})",
                            stored_config.device_type,
                            snapshot.name,
                            stored_config.path,
                            stored_config.tag
                        ));
                    }
                }
            }
        }

        if !mismatches.is_empty() {
            tracing::warn!(
                "restore_devices: {} device(s) in snapshot don't match current configuration: {:?}",
                mismatches.len(),
                mismatches
            );
        }

        // Verify device count by type
        let snapshot_blocks = snapshots
            .iter()
            .filter(|s| s.device_type == VirtioDeviceType::Block)
            .count();
        let snapshot_nets = snapshots
            .iter()
            .filter(|s| s.device_type == VirtioDeviceType::Net)
            .count();
        let current_blocks = self
            .device_configs
            .iter()
            .filter(|c| c.device_type == VirtioDeviceType::Block)
            .count();
        let current_nets = self
            .device_configs
            .iter()
            .filter(|c| c.device_type == VirtioDeviceType::Net)
            .count();

        if snapshot_blocks != current_blocks {
            tracing::warn!(
                "Block device count mismatch: snapshot has {}, current VM has {}",
                snapshot_blocks,
                current_blocks
            );
        }

        if snapshot_nets != current_nets {
            tracing::warn!(
                "Network device count mismatch: snapshot has {}, current VM has {}",
                snapshot_nets,
                current_nets
            );
        }

        Ok(())
    }
}
