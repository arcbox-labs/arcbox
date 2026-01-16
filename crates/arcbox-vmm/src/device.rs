//! Device management for VMM.
//!
//! This module provides device management including VirtIO MMIO transport.
//!
//! The device manager bridges between:
//! - MMIO transport layer (`VirtioMmioState`) that handles guest MMIO accesses
//! - VirtIO device implementations (`VirtioDevice`) from arcbox-virtio

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use arcbox_virtio::{DeviceStatus, VirtioDevice, VirtioDeviceId};

use crate::error::{Result, VmmError};
use crate::irq::{Irq, IrqChip};
use crate::memory::MemoryManager;

/// Device identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(u32);

impl DeviceId {
    /// Creates a new device ID.
    #[must_use]
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the raw ID value.
    #[must_use]
    pub const fn raw(&self) -> u32 {
        self.0
    }
}

/// Device type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// Serial port.
    Serial,
    /// VirtIO block device.
    VirtioBlock,
    /// VirtIO network device.
    VirtioNet,
    /// VirtIO console.
    VirtioConsole,
    /// VirtIO filesystem.
    VirtioFs,
    /// VirtIO vsock.
    VirtioVsock,
    /// Other device.
    Other,
}

/// Device information.
#[derive(Debug)]
pub struct DeviceInfo {
    /// Device ID.
    pub id: DeviceId,
    /// Device type.
    pub device_type: DeviceType,
    /// Device name.
    pub name: String,
    /// MMIO base address.
    pub mmio_base: Option<u64>,
    /// MMIO size.
    pub mmio_size: u64,
    /// Assigned IRQ.
    pub irq: Option<Irq>,
}

/// VirtIO MMIO transport registers.
///
/// Based on VirtIO 1.1 specification.
pub mod virtio_mmio {
    /// Magic value ("virt").
    pub const MAGIC_VALUE: u32 = 0x74726976;
    /// VirtIO version (legacy: 1, modern: 2).
    pub const VERSION: u32 = 2;
    /// Vendor ID.
    pub const VENDOR_ID: u32 = 0x554D4551; // "QEMU"

    /// Register offsets.
    pub mod regs {
        /// Magic value.
        pub const MAGIC: u64 = 0x000;
        /// Version.
        pub const VERSION: u64 = 0x004;
        /// Device type.
        pub const DEVICE_ID: u64 = 0x008;
        /// Vendor ID.
        pub const VENDOR_ID: u64 = 0x00c;
        /// Device features.
        pub const DEVICE_FEATURES: u64 = 0x010;
        /// Device features selector.
        pub const DEVICE_FEATURES_SEL: u64 = 0x014;
        /// Driver features.
        pub const DRIVER_FEATURES: u64 = 0x020;
        /// Driver features selector.
        pub const DRIVER_FEATURES_SEL: u64 = 0x024;
        /// Queue selector.
        pub const QUEUE_SEL: u64 = 0x030;
        /// Queue size (max).
        pub const QUEUE_NUM_MAX: u64 = 0x034;
        /// Queue size.
        pub const QUEUE_NUM: u64 = 0x038;
        /// Queue ready.
        pub const QUEUE_READY: u64 = 0x044;
        /// Queue notify.
        pub const QUEUE_NOTIFY: u64 = 0x050;
        /// Interrupt status.
        pub const INTERRUPT_STATUS: u64 = 0x060;
        /// Interrupt acknowledge.
        pub const INTERRUPT_ACK: u64 = 0x064;
        /// Device status.
        pub const STATUS: u64 = 0x070;
        /// Queue descriptor low.
        pub const QUEUE_DESC_LOW: u64 = 0x080;
        /// Queue descriptor high.
        pub const QUEUE_DESC_HIGH: u64 = 0x084;
        /// Queue driver low.
        pub const QUEUE_DRIVER_LOW: u64 = 0x090;
        /// Queue driver high.
        pub const QUEUE_DRIVER_HIGH: u64 = 0x094;
        /// Queue device low.
        pub const QUEUE_DEVICE_LOW: u64 = 0x0a0;
        /// Queue device high.
        pub const QUEUE_DEVICE_HIGH: u64 = 0x0a4;
        /// Config generation.
        pub const CONFIG_GENERATION: u64 = 0x0fc;
        /// Config space starts here.
        pub const CONFIG: u64 = 0x100;
    }

    /// MMIO region size.
    pub const MMIO_SIZE: u64 = 0x200;
}

/// VirtIO MMIO device state.
pub struct VirtioMmioState {
    /// Device type ID.
    pub device_id: u32,
    /// Device features.
    pub device_features: u64,
    /// Driver features.
    pub driver_features: u64,
    /// Device features selector.
    pub device_features_sel: u32,
    /// Driver features selector.
    pub driver_features_sel: u32,
    /// Queue selector.
    pub queue_sel: u32,
    /// Queue sizes.
    pub queue_num: [u16; 8],
    /// Queue ready flags.
    pub queue_ready: [bool; 8],
    /// Queue descriptor addresses.
    pub queue_desc: [u64; 8],
    /// Queue driver addresses.
    pub queue_driver: [u64; 8],
    /// Queue device addresses.
    pub queue_device: [u64; 8],
    /// Device status.
    pub status: u8,
    /// Interrupt status.
    pub interrupt_status: u32,
    /// Configuration generation.
    pub config_generation: u32,
}

impl VirtioMmioState {
    /// Creates a new VirtIO MMIO state.
    #[must_use]
    pub fn new(device_id: u32, features: u64) -> Self {
        Self {
            device_id,
            device_features: features,
            driver_features: 0,
            device_features_sel: 0,
            driver_features_sel: 0,
            queue_sel: 0,
            queue_num: [0; 8],
            queue_ready: [false; 8],
            queue_desc: [0; 8],
            queue_driver: [0; 8],
            queue_device: [0; 8],
            status: 0,
            interrupt_status: 0,
            config_generation: 0,
        }
    }

    /// Reads from MMIO register.
    #[must_use]
    pub fn read(&self, offset: u64) -> u32 {
        use virtio_mmio::regs;

        match offset {
            regs::MAGIC => virtio_mmio::MAGIC_VALUE,
            regs::VERSION => virtio_mmio::VERSION,
            regs::DEVICE_ID => self.device_id,
            regs::VENDOR_ID => virtio_mmio::VENDOR_ID,
            regs::DEVICE_FEATURES => {
                if self.device_features_sel == 0 {
                    self.device_features as u32
                } else {
                    (self.device_features >> 32) as u32
                }
            }
            regs::QUEUE_NUM_MAX => 256, // Max queue size
            regs::QUEUE_READY => {
                if (self.queue_sel as usize) < 8 {
                    u32::from(self.queue_ready[self.queue_sel as usize])
                } else {
                    0
                }
            }
            regs::INTERRUPT_STATUS => self.interrupt_status,
            regs::STATUS => self.status as u32,
            regs::CONFIG_GENERATION => self.config_generation,
            _ => {
                tracing::trace!("VirtIO MMIO read unknown offset: {:#x}", offset);
                0
            }
        }
    }

    /// Writes to MMIO register.
    pub fn write(&mut self, offset: u64, value: u32) {
        use virtio_mmio::regs;

        match offset {
            regs::DEVICE_FEATURES_SEL => self.device_features_sel = value,
            regs::DRIVER_FEATURES => {
                if self.driver_features_sel == 0 {
                    self.driver_features =
                        (self.driver_features & 0xFFFF_FFFF_0000_0000) | u64::from(value);
                } else {
                    self.driver_features =
                        (self.driver_features & 0x0000_0000_FFFF_FFFF) | (u64::from(value) << 32);
                }
            }
            regs::DRIVER_FEATURES_SEL => self.driver_features_sel = value,
            regs::QUEUE_SEL => self.queue_sel = value,
            regs::QUEUE_NUM => {
                if (self.queue_sel as usize) < 8 {
                    self.queue_num[self.queue_sel as usize] = value as u16;
                }
            }
            regs::QUEUE_READY => {
                if (self.queue_sel as usize) < 8 {
                    self.queue_ready[self.queue_sel as usize] = value != 0;
                }
            }
            regs::QUEUE_NOTIFY => {
                // Guest is notifying us about available buffers
                tracing::trace!("VirtIO queue {} notified", value);
            }
            regs::INTERRUPT_ACK => {
                self.interrupt_status &= !value;
            }
            regs::STATUS => {
                self.status = value as u8;
                if value == 0 {
                    // Device reset
                    self.driver_features = 0;
                    self.queue_sel = 0;
                    self.queue_num = [0; 8];
                    self.queue_ready = [false; 8];
                    self.interrupt_status = 0;
                }
            }
            regs::QUEUE_DESC_LOW => {
                if (self.queue_sel as usize) < 8 {
                    self.queue_desc[self.queue_sel as usize] =
                        (self.queue_desc[self.queue_sel as usize] & 0xFFFF_FFFF_0000_0000)
                            | u64::from(value);
                }
            }
            regs::QUEUE_DESC_HIGH => {
                if (self.queue_sel as usize) < 8 {
                    self.queue_desc[self.queue_sel as usize] =
                        (self.queue_desc[self.queue_sel as usize] & 0x0000_0000_FFFF_FFFF)
                            | (u64::from(value) << 32);
                }
            }
            regs::QUEUE_DRIVER_LOW => {
                if (self.queue_sel as usize) < 8 {
                    self.queue_driver[self.queue_sel as usize] =
                        (self.queue_driver[self.queue_sel as usize] & 0xFFFF_FFFF_0000_0000)
                            | u64::from(value);
                }
            }
            regs::QUEUE_DRIVER_HIGH => {
                if (self.queue_sel as usize) < 8 {
                    self.queue_driver[self.queue_sel as usize] =
                        (self.queue_driver[self.queue_sel as usize] & 0x0000_0000_FFFF_FFFF)
                            | (u64::from(value) << 32);
                }
            }
            regs::QUEUE_DEVICE_LOW => {
                if (self.queue_sel as usize) < 8 {
                    self.queue_device[self.queue_sel as usize] =
                        (self.queue_device[self.queue_sel as usize] & 0xFFFF_FFFF_0000_0000)
                            | u64::from(value);
                }
            }
            regs::QUEUE_DEVICE_HIGH => {
                if (self.queue_sel as usize) < 8 {
                    self.queue_device[self.queue_sel as usize] =
                        (self.queue_device[self.queue_sel as usize] & 0x0000_0000_FFFF_FFFF)
                            | (u64::from(value) << 32);
                }
            }
            _ => {
                tracing::trace!("VirtIO MMIO write unknown offset: {:#x}", offset);
            }
        }
    }

    /// Triggers an interrupt.
    pub fn trigger_interrupt(&mut self, reason: u32) {
        self.interrupt_status |= reason;
    }
}

/// Trait for devices that can handle MMIO operations.
pub trait MmioDevice: Send + Sync {
    /// Reads from the device MMIO region.
    fn mmio_read(&self, offset: u64, size: usize) -> u64;

    /// Writes to the device MMIO region.
    fn mmio_write(&mut self, offset: u64, size: usize, value: u64);
}

/// A registered device with MMIO state and VirtIO device implementation.
struct RegisteredDevice {
    info: DeviceInfo,
    mmio_state: Option<Arc<RwLock<VirtioMmioState>>>,
    /// The actual VirtIO device implementation.
    virtio_device: Option<Arc<Mutex<dyn VirtioDevice>>>,
}

/// Manages devices attached to the VM.
pub struct DeviceManager {
    devices: HashMap<DeviceId, RegisteredDevice>,
    next_id: u32,
    /// MMIO address to device mapping.
    mmio_map: HashMap<u64, DeviceId>,
}

impl DeviceManager {
    /// Creates a new device manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
            next_id: 0,
            mmio_map: HashMap::new(),
        }
    }

    /// Registers a new device.
    ///
    /// # Errors
    ///
    /// Returns an error if device registration fails.
    pub fn register(
        &mut self,
        device_type: DeviceType,
        name: impl Into<String>,
    ) -> Result<DeviceId> {
        let id = DeviceId::new(self.next_id);
        self.next_id += 1;

        let info = DeviceInfo {
            id,
            device_type,
            name: name.into(),
            mmio_base: None,
            mmio_size: 0,
            irq: None,
        };

        self.devices.insert(
            id,
            RegisteredDevice {
                info,
                mmio_state: None,
                virtio_device: None,
            },
        );

        Ok(id)
    }

    /// Registers a VirtIO device with MMIO transport (without actual device).
    ///
    /// Use `register_virtio_device` to register with an actual VirtIO device implementation.
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails.
    pub fn register_virtio(
        &mut self,
        device_type: DeviceType,
        name: impl Into<String>,
        virtio_device_id: u32,
        features: u64,
        memory_manager: &mut MemoryManager,
        irq_chip: &IrqChip,
    ) -> Result<DeviceId> {
        let id = DeviceId::new(self.next_id);
        self.next_id += 1;

        // Allocate MMIO region
        let mmio_base = memory_manager.allocate_mmio(virtio_mmio::MMIO_SIZE, &name.into())?;
        let irq = irq_chip.allocate_irq()?;

        let name_str = format!("{}", id.0);
        let info = DeviceInfo {
            id,
            device_type,
            name: name_str,
            mmio_base: Some(mmio_base),
            mmio_size: virtio_mmio::MMIO_SIZE,
            irq: Some(irq),
        };

        let mmio_state = Arc::new(RwLock::new(VirtioMmioState::new(
            virtio_device_id,
            features,
        )));

        self.mmio_map.insert(mmio_base, id);
        self.devices.insert(
            id,
            RegisteredDevice {
                info,
                mmio_state: Some(mmio_state),
                virtio_device: None,
            },
        );

        tracing::info!(
            "Registered VirtIO device {} at MMIO {:#x}, IRQ {}",
            id.0,
            mmio_base,
            irq
        );

        Ok(id)
    }

    /// Registers a VirtIO device with MMIO transport and device implementation.
    ///
    /// This is the preferred method for registering VirtIO devices as it connects
    /// the MMIO transport layer with the actual device logic.
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails.
    pub fn register_virtio_device<D: VirtioDevice + 'static>(
        &mut self,
        device_type: DeviceType,
        name: impl Into<String>,
        device: D,
        memory_manager: &mut MemoryManager,
        irq_chip: &IrqChip,
    ) -> Result<DeviceId> {
        let id = DeviceId::new(self.next_id);
        self.next_id += 1;

        let virtio_device_id = device.device_id() as u32;
        let features = device.features();
        let name_str = name.into();

        // Allocate MMIO region
        let mmio_base = memory_manager.allocate_mmio(virtio_mmio::MMIO_SIZE, &name_str)?;
        let irq = irq_chip.allocate_irq()?;

        let info = DeviceInfo {
            id,
            device_type,
            name: name_str.clone(),
            mmio_base: Some(mmio_base),
            mmio_size: virtio_mmio::MMIO_SIZE,
            irq: Some(irq),
        };

        let mmio_state = Arc::new(RwLock::new(VirtioMmioState::new(
            virtio_device_id,
            features,
        )));
        let virtio_device = Arc::new(Mutex::new(device));

        self.mmio_map.insert(mmio_base, id);
        self.devices.insert(
            id,
            RegisteredDevice {
                info,
                mmio_state: Some(mmio_state),
                virtio_device: Some(virtio_device),
            },
        );

        tracing::info!(
            "Registered VirtIO device '{}' (type {:?}) at MMIO {:#x}, IRQ {}",
            name_str,
            device_type,
            mmio_base,
            irq
        );

        Ok(id)
    }

    /// Gets device info by ID.
    #[must_use]
    pub fn get(&self, id: DeviceId) -> Option<&DeviceInfo> {
        self.devices.get(&id).map(|d| &d.info)
    }

    /// Gets the MMIO state for a device.
    #[must_use]
    pub fn get_mmio_state(&self, id: DeviceId) -> Option<Arc<RwLock<VirtioMmioState>>> {
        self.devices.get(&id).and_then(|d| d.mmio_state.clone())
    }

    /// Gets the VirtIO device for a device ID.
    #[must_use]
    pub fn get_virtio_device(&self, id: DeviceId) -> Option<Arc<Mutex<dyn VirtioDevice>>> {
        self.devices.get(&id).and_then(|d| d.virtio_device.clone())
    }

    /// Triggers an interrupt for a device.
    ///
    /// # Errors
    ///
    /// Returns an error if the device doesn't exist or interrupt fails.
    pub fn trigger_interrupt(&self, id: DeviceId, reason: u32) -> Result<()> {
        let device = self
            .devices
            .get(&id)
            .ok_or_else(|| VmmError::Device(format!("Device {} not found", id.0)))?;

        if let Some(state) = &device.mmio_state {
            let mut state = state
                .write()
                .map_err(|e| VmmError::Device(format!("Failed to lock device state: {}", e)))?;
            state.trigger_interrupt(reason);
        }

        Ok(())
    }

    /// Finds device by MMIO address.
    #[must_use]
    pub fn find_by_mmio(&self, addr: u64) -> Option<DeviceId> {
        for (base, id) in &self.mmio_map {
            if let Some(device) = self.devices.get(id) {
                if addr >= *base && addr < *base + device.info.mmio_size {
                    return Some(*id);
                }
            }
        }
        None
    }

    /// Handles MMIO read.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    pub fn handle_mmio_read(&self, addr: u64, size: usize) -> Result<u64> {
        let device_id = self
            .find_by_mmio(addr)
            .ok_or_else(|| VmmError::Device(format!("No device at MMIO address {:#x}", addr)))?;

        let device = self
            .devices
            .get(&device_id)
            .ok_or_else(|| VmmError::Device(format!("Device {} not found", device_id.0)))?;

        let base = device.info.mmio_base.unwrap_or(0);
        let offset = addr - base;

        if let Some(state) = &device.mmio_state {
            let state = state
                .read()
                .map_err(|e| VmmError::Device(format!("Failed to lock device state: {}", e)))?;

            // Handle config space reads - forward to actual device
            if offset >= virtio_mmio::regs::CONFIG {
                let config_offset = offset - virtio_mmio::regs::CONFIG;
                if let Some(virtio_dev) = &device.virtio_device {
                    let dev = virtio_dev.lock().map_err(|e| {
                        VmmError::Device(format!("Failed to lock virtio device: {}", e))
                    })?;
                    let mut data = vec![0u8; size];
                    dev.read_config(config_offset, &mut data);
                    return Ok(match size {
                        1 => u64::from(data[0]),
                        2 => u64::from(u16::from_le_bytes([data[0], data[1]])),
                        4 => u64::from(u32::from_le_bytes([data[0], data[1], data[2], data[3]])),
                        8 => u64::from_le_bytes([
                            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                        ]),
                        _ => 0,
                    });
                }
                return Ok(0);
            }

            let value = state.read(offset);
            let result = match size {
                1 => u64::from(value as u8),
                2 => u64::from(value as u16),
                4 => u64::from(value),
                _ => u64::from(value),
            };

            Ok(result)
        } else {
            Ok(0)
        }
    }

    /// Handles MMIO write.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    pub fn handle_mmio_write(&self, addr: u64, size: usize, value: u64) -> Result<()> {
        let device_id = self
            .find_by_mmio(addr)
            .ok_or_else(|| VmmError::Device(format!("No device at MMIO address {:#x}", addr)))?;

        let device = self
            .devices
            .get(&device_id)
            .ok_or_else(|| VmmError::Device(format!("Device {} not found", device_id.0)))?;

        let base = device.info.mmio_base.unwrap_or(0);
        let offset = addr - base;

        if let Some(state) = &device.mmio_state {
            let old_status = {
                let s = state
                    .read()
                    .map_err(|e| VmmError::Device(format!("Failed to lock device state: {}", e)))?;
                s.status
            };

            // Handle config space writes - forward to actual device
            if offset >= virtio_mmio::regs::CONFIG {
                let config_offset = offset - virtio_mmio::regs::CONFIG;
                if let Some(virtio_dev) = &device.virtio_device {
                    let mut dev = virtio_dev.lock().map_err(|e| {
                        VmmError::Device(format!("Failed to lock virtio device: {}", e))
                    })?;
                    let data: Vec<u8> = match size {
                        1 => vec![value as u8],
                        2 => (value as u16).to_le_bytes().to_vec(),
                        4 => (value as u32).to_le_bytes().to_vec(),
                        8 => value.to_le_bytes().to_vec(),
                        _ => return Ok(()),
                    };
                    dev.write_config(config_offset, &data);
                }
                return Ok(());
            }

            let value32 = match size {
                1 => value as u32 & 0xFF,
                2 => value as u32 & 0xFFFF,
                4 | 8 => value as u32,
                _ => value as u32,
            };

            // Write to MMIO state
            {
                let mut state = state
                    .write()
                    .map_err(|e| VmmError::Device(format!("Failed to lock device state: {}", e)))?;
                state.write(offset, value32);
            }

            // Handle special cases after write
            match offset {
                virtio_mmio::regs::STATUS => {
                    let new_status = value32 as u8;

                    // Handle feature acknowledgment
                    if new_status & DeviceStatus::FEATURES_OK != 0
                        && old_status & DeviceStatus::FEATURES_OK == 0
                    {
                        if let Some(virtio_dev) = &device.virtio_device {
                            let mmio_state = state.read().map_err(|e| {
                                VmmError::Device(format!("Failed to lock device state: {}", e))
                            })?;
                            let mut dev = virtio_dev.lock().map_err(|e| {
                                VmmError::Device(format!("Failed to lock virtio device: {}", e))
                            })?;
                            dev.ack_features(mmio_state.driver_features);
                            tracing::debug!(
                                "Device {} acknowledged features: {:#x}",
                                device_id.0,
                                mmio_state.driver_features
                            );
                        }
                    }

                    // Handle device activation
                    if new_status & DeviceStatus::DRIVER_OK != 0
                        && old_status & DeviceStatus::DRIVER_OK == 0
                    {
                        if let Some(virtio_dev) = &device.virtio_device {
                            let mut dev = virtio_dev.lock().map_err(|e| {
                                VmmError::Device(format!("Failed to lock virtio device: {}", e))
                            })?;
                            dev.activate().map_err(|e| {
                                VmmError::Device(format!("Failed to activate device: {}", e))
                            })?;
                            tracing::info!("Device {} activated", device_id.0);
                        }
                    }

                    // Handle device reset
                    if new_status == 0 {
                        if let Some(virtio_dev) = &device.virtio_device {
                            let mut dev = virtio_dev.lock().map_err(|e| {
                                VmmError::Device(format!("Failed to lock virtio device: {}", e))
                            })?;
                            dev.reset();
                            tracing::info!("Device {} reset", device_id.0);
                        }
                    }
                }
                virtio_mmio::regs::QUEUE_NOTIFY => {
                    // Guest notified a queue - this would trigger async processing
                    tracing::trace!("Device {} queue {} notified", device_id.0, value32);
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Returns an iterator over all devices.
    pub fn iter(&self) -> impl Iterator<Item = &DeviceInfo> {
        self.devices.values().map(|d| &d.info)
    }

    /// Returns device tree entries for all VirtIO devices.
    #[must_use]
    pub fn device_tree_entries(&self) -> Vec<DeviceTreeEntry> {
        self.devices
            .values()
            .filter_map(|d| {
                if let (Some(base), Some(irq)) = (d.info.mmio_base, d.info.irq) {
                    Some(DeviceTreeEntry {
                        compatible: "virtio,mmio".to_string(),
                        reg_base: base,
                        reg_size: d.info.mmio_size,
                        irq,
                    })
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Device tree entry for FDT generation.
#[derive(Debug, Clone)]
pub struct DeviceTreeEntry {
    /// Compatible string.
    pub compatible: String,
    /// Register base address.
    pub reg_base: u64,
    /// Register region size.
    pub reg_size: u64,
    /// IRQ number.
    pub irq: Irq,
}

impl Default for DeviceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_registration() {
        let mut manager = DeviceManager::new();
        let id = manager.register(DeviceType::Serial, "serial0").unwrap();

        let info = manager.get(id);
        assert!(info.is_some());
        assert_eq!(info.unwrap().name, "serial0");
    }

    #[test]
    fn test_virtio_mmio_state() {
        let state = VirtioMmioState::new(2, 0x1234_5678);

        assert_eq!(
            state.read(virtio_mmio::regs::MAGIC),
            virtio_mmio::MAGIC_VALUE
        );
        assert_eq!(state.read(virtio_mmio::regs::VERSION), virtio_mmio::VERSION);
        assert_eq!(state.read(virtio_mmio::regs::DEVICE_ID), 2);
    }

    #[test]
    fn test_virtio_mmio_features() {
        let mut state = VirtioMmioState::new(2, 0xDEAD_BEEF_CAFE_BABE);

        // Read low 32 bits
        assert_eq!(state.read(virtio_mmio::regs::DEVICE_FEATURES), 0xCAFE_BABE);

        // Select high 32 bits
        state.write(virtio_mmio::regs::DEVICE_FEATURES_SEL, 1);
        assert_eq!(state.read(virtio_mmio::regs::DEVICE_FEATURES), 0xDEAD_BEEF);
    }
}
