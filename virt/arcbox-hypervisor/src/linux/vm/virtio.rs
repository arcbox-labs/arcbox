use std::os::unix::io::RawFd;
use std::sync::atomic::Ordering;

use crate::{error::HypervisorError, types::VirtioDeviceType};

use super::KvmVm;

/// Base address for VirtIO MMIO devices (ARM64).
/// This is placed at 160MB to avoid conflicts with RAM and other devices.
pub(super) const VIRTIO_MMIO_BASE: u64 = 0x0a00_0000;

/// Size of each VirtIO MMIO device region (512 bytes).
pub(super) const VIRTIO_MMIO_SIZE: u64 = 0x200;

/// Gap between VirtIO MMIO devices (for alignment).
pub(super) const VIRTIO_MMIO_GAP: u64 = 0x200;

/// VirtIO MMIO register offset for queue notify (used for IOEVENTFD).
pub(super) const VIRTIO_MMIO_QUEUE_NOTIFY: u64 = 0x50;

/// Base IRQ for VirtIO devices.
/// On ARM64 GIC, SPI interrupts start at 32.
/// On x86 IOAPIC, we use IRQs starting at 5 (avoiding legacy devices).
#[cfg(target_arch = "aarch64")]
const VIRTIO_IRQ_BASE: u32 = 32;

#[cfg(target_arch = "x86_64")]
const VIRTIO_IRQ_BASE: u32 = 5;

/// Maximum number of VirtIO devices.
const MAX_VIRTIO_DEVICES: usize = 32;

/// Information about an attached VirtIO device.
#[derive(Debug)]
pub struct VirtioDeviceInfo {
    /// Device type.
    pub device_type: VirtioDeviceType,
    /// MMIO base address.
    pub mmio_base: u64,
    /// MMIO region size.
    pub mmio_size: u64,
    /// Assigned IRQ (GSI).
    pub irq: u32,
    /// Eventfd for IRQ injection.
    pub irq_fd: RawFd,
    /// Eventfd for queue notification.
    pub notify_fd: RawFd,
}

impl KvmVm {
    /// Allocates an MMIO region for a VirtIO device.
    ///
    /// Returns the base address for the device.
    pub(super) fn allocate_mmio_region(&self) -> Result<u64, HypervisorError> {
        let devices = self
            .virtio_devices
            .read()
            .map_err(|_| HypervisorError::DeviceError("Lock poisoned".to_string()))?;

        if devices.len() >= MAX_VIRTIO_DEVICES {
            return Err(HypervisorError::DeviceError(
                "Maximum number of VirtIO devices reached".to_string(),
            ));
        }

        // Calculate next available address.
        let offset = devices.len() as u64 * (VIRTIO_MMIO_SIZE + VIRTIO_MMIO_GAP);
        Ok(VIRTIO_MMIO_BASE + offset)
    }

    /// Allocates an IRQ (GSI) for a VirtIO device.
    pub(super) fn allocate_irq(&self) -> u32 {
        let offset = self.next_virtio_irq.fetch_add(1, Ordering::SeqCst);
        VIRTIO_IRQ_BASE + offset
    }

    /// Creates an eventfd.
    pub(super) fn create_eventfd() -> Result<RawFd, HypervisorError> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if fd < 0 {
            return Err(HypervisorError::DeviceError(format!(
                "Failed to create eventfd: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(fd)
    }

    /// Sets up IOEVENTFD for VirtIO queue notification.
    ///
    /// This allows the guest to notify the host about queue updates by writing
    /// to a specific MMIO address, without causing a VM exit.
    pub(super) fn setup_ioeventfd(&self, mmio_base: u64) -> Result<RawFd, HypervisorError> {
        let notify_fd = Self::create_eventfd()?;

        // Register IOEVENTFD at the queue notify register address.
        // 4 bytes for 32-bit writes to VIRTIO_MMIO_QUEUE_NOTIFY.
        let notify_addr = mmio_base + VIRTIO_MMIO_QUEUE_NOTIFY;

        self.vm_fd
            .register_ioeventfd(notify_addr, 4, notify_fd, None)
            .map_err(|e| {
                // Clean up the eventfd on failure.
                unsafe { libc::close(notify_fd) };
                HypervisorError::DeviceError(format!("Failed to register IOEVENTFD: {}", e))
            })?;

        tracing::debug!(
            "Registered IOEVENTFD at {:#x} with fd={}",
            notify_addr,
            notify_fd
        );

        Ok(notify_fd)
    }

    /// Returns a copy of the attached VirtIO devices info.
    pub fn virtio_devices(&self) -> Result<Vec<VirtioDeviceInfo>, HypervisorError> {
        let devices = self
            .virtio_devices
            .read()
            .map_err(|_| HypervisorError::DeviceError("Lock poisoned".to_string()))?;

        Ok(devices
            .iter()
            .map(|d| VirtioDeviceInfo {
                device_type: d.device_type.clone(),
                mmio_base: d.mmio_base,
                mmio_size: d.mmio_size,
                irq: d.irq,
                irq_fd: d.irq_fd,
                notify_fd: d.notify_fd,
            })
            .collect())
    }
}

/// Serializes device configuration to bytes for snapshot storage.
pub(super) fn bincode_serialize_device_config(device: &VirtioDeviceInfo) -> Vec<u8> {
    // Simple serialization of device config for snapshot purposes.
    // A full implementation would use serde/bincode.
    let mut bytes = Vec::new();

    // Serialize device type as u8
    let type_byte = match device.device_type {
        VirtioDeviceType::Block => 0u8,
        VirtioDeviceType::Net => 1,
        VirtioDeviceType::Console => 2,
        VirtioDeviceType::Rng => 3,
        VirtioDeviceType::Balloon => 4,
        VirtioDeviceType::Fs => 5,
        VirtioDeviceType::Vsock => 6,
        VirtioDeviceType::Gpu => 7,
    };
    bytes.push(type_byte);

    // Serialize MMIO base and size
    bytes.extend_from_slice(&device.mmio_base.to_le_bytes());
    bytes.extend_from_slice(&device.mmio_size.to_le_bytes());

    // Serialize IRQ
    bytes.extend_from_slice(&device.irq.to_le_bytes());

    bytes
}
