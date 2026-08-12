use std::sync::atomic::Ordering;

use crate::{
    error::HypervisorError,
    traits::VirtualMachine,
    types::{DeviceSnapshot, VirtioDeviceConfig},
};

use super::virtio::{VIRTIO_MMIO_SIZE, bincode_serialize_device_config};
use super::{KvmMemory, KvmVm, VirtioDeviceInfo, VmState};
use crate::linux::KvmVcpu;

impl VirtualMachine for KvmVm {
    type Vcpu = KvmVcpu;
    type Memory = KvmMemory;

    fn memory(&self) -> &Self::Memory {
        &self.memory
    }

    fn create_vcpu(&mut self, id: u32) -> Result<Self::Vcpu, HypervisorError> {
        if id >= self.config.vcpu_count {
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

        // Create vCPU via KVM
        let vcpu_fd = self
            .vm_fd
            .create_vcpu(id, self.vcpu_mmap_size)
            .map_err(|e| HypervisorError::VcpuCreationFailed {
                id,
                reason: format!("KVM error: {}", e),
            })?;

        // Create wrapper
        let vcpu = KvmVcpu::new(id, vcpu_fd)?;

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

        tracing::debug!("Created vCPU {} for VM {}", id, self.id);

        Ok(vcpu)
    }

    fn add_virtio_device(&mut self, device: VirtioDeviceConfig) -> Result<(), HypervisorError> {
        // 1. Check state - devices can only be added before VM starts.
        let state = self.state();
        if state != VmState::Created {
            return Err(HypervisorError::DeviceError(
                "Cannot add device: VM not in Created state".to_string(),
            ));
        }

        // 2. Allocate MMIO address space for the device.
        let mmio_base = self.allocate_mmio_region()?;

        // 3. Allocate an IRQ (GSI) for the device.
        let gsi = self.allocate_irq();

        // 4. Create eventfd for IRQ injection and register IRQFD.
        let irq_fd = Self::create_eventfd()?;

        if let Err(e) = self.register_irqfd(irq_fd, gsi, None) {
            // Clean up on failure.
            unsafe { libc::close(irq_fd) };
            return Err(e);
        }

        // 5. Set up IOEVENTFD for queue notification.
        let notify_fd = match self.setup_ioeventfd(mmio_base) {
            Ok(fd) => fd,
            Err(e) => {
                // Clean up on failure.
                let _ = self.unregister_irqfd(irq_fd, gsi);
                unsafe { libc::close(irq_fd) };
                return Err(e);
            }
        };

        // 6. Record the device information.
        let device_info = VirtioDeviceInfo {
            device_type: device.device_type.clone(),
            mmio_base,
            mmio_size: VIRTIO_MMIO_SIZE,
            irq: gsi,
            irq_fd,
            notify_fd,
        };

        {
            let mut devices = self.virtio_devices.write().map_err(|_| {
                // Clean up on failure.
                let _ = self.unregister_irqfd(irq_fd, gsi);
                unsafe {
                    libc::close(irq_fd);
                    libc::close(notify_fd);
                }
                HypervisorError::DeviceError("Lock poisoned".to_string())
            })?;

            devices.push(device_info);
        }

        tracing::info!(
            "Added {:?} device to VM {}: MMIO={:#x}-{:#x}, IRQ={}, irq_fd={}, notify_fd={}",
            device.device_type,
            self.id,
            mmio_base,
            mmio_base + VIRTIO_MMIO_SIZE,
            gsi,
            irq_fd,
            notify_fd
        );

        Ok(())
    }

    fn start(&mut self) -> Result<(), HypervisorError> {
        let state = self.state();
        if state != VmState::Created && state != VmState::Stopped {
            return Err(HypervisorError::VmStateError {
                expected: "Created or Stopped".to_string(),
                actual: format!("{:?}", state),
            });
        }

        self.set_state(VmState::Starting);

        // Mark as running
        self.running.store(true, Ordering::SeqCst);
        self.set_state(VmState::Running);

        tracing::info!("Started VM {}", self.id);

        Ok(())
    }

    fn pause(&mut self) -> Result<(), HypervisorError> {
        let state = self.state();
        if state != VmState::Running {
            return Err(HypervisorError::VmStateError {
                expected: "Running".to_string(),
                actual: format!("{:?}", state),
            });
        }

        // Signal all vCPUs to pause
        // In KVM, this is typically done by setting immediate_exit and signaling
        // the vCPU threads

        self.set_state(VmState::Paused);

        tracing::info!("Paused VM {}", self.id);

        Ok(())
    }

    fn resume(&mut self) -> Result<(), HypervisorError> {
        let state = self.state();
        if state != VmState::Paused {
            return Err(HypervisorError::VmStateError {
                expected: "Paused".to_string(),
                actual: format!("{:?}", state),
            });
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
                actual: format!("{:?}", state),
            });
        }

        self.set_state(VmState::Stopping);

        // Signal all vCPUs to stop
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
        self.config.vcpu_count
    }

    fn snapshot_devices(&self) -> Result<Vec<DeviceSnapshot>, HypervisorError> {
        let devices = self
            .virtio_devices
            .read()
            .map_err(|_| HypervisorError::SnapshotError("Lock poisoned".to_string()))?;

        let mut snapshots = Vec::with_capacity(devices.len());

        for device in devices.iter() {
            // KVM VirtIO devices don't have internal state accessible from host.
            // The actual device state is managed by the VMM layer (e.g., arcbox-virtio).
            // We record the device configuration here; the VMM would need to
            // serialize its own device state.
            let state_bytes = bincode_serialize_device_config(device);

            snapshots.push(DeviceSnapshot {
                device_type: device.device_type.clone(),
                name: format!("{:?}-{}", device.device_type, snapshots.len()),
                state: state_bytes,
            });
        }

        tracing::debug!(
            "snapshot_devices: captured {} device configurations",
            snapshots.len()
        );

        Ok(snapshots)
    }

    fn restore_devices(&mut self, snapshots: &[DeviceSnapshot]) -> Result<(), HypervisorError> {
        // KVM device restoration is complex:
        // 1. VirtIO MMIO regions must be at the same addresses
        // 2. IRQs must be assigned to the same GSIs
        // 3. The VMM layer must restore internal device state
        //
        // For now, we verify that the device configuration matches.
        let devices = self
            .virtio_devices
            .read()
            .map_err(|_| HypervisorError::SnapshotError("Lock poisoned".to_string()))?;

        if snapshots.len() != devices.len() {
            return Err(HypervisorError::SnapshotError(format!(
                "Device count mismatch: snapshot has {}, VM has {}",
                snapshots.len(),
                devices.len()
            )));
        }

        for (snapshot, device) in snapshots.iter().zip(devices.iter()) {
            if snapshot.device_type != device.device_type {
                return Err(HypervisorError::SnapshotError(format!(
                    "Device type mismatch: snapshot has {:?}, VM has {:?}",
                    snapshot.device_type, device.device_type
                )));
            }
        }

        tracing::debug!(
            "restore_devices: verified {} device configurations",
            snapshots.len()
        );

        Ok(())
    }
}
