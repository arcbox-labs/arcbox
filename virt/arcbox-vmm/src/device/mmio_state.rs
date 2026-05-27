//! VirtIO MMIO transport register layout and per-device state.
//!
//! Implements the virtio-mmio 1.1 modern transport: register offsets,
//! magic/version constants, and the in-memory mirror of the guest-visible
//! register file. `VirtioMmioState::read`/`write` dispatch guest MMIO
//! accesses to the appropriate field.

/// `VirtIO` MMIO transport registers.
///
/// Based on `VirtIO` 1.1 specification. Register offsets are sourced from
/// `virtio_bindings::virtio_mmio`.
pub mod virtio_mmio {
    use arcbox_virtio::virtio_bindings::virtio_mmio as vmmio;

    /// Magic value ("virt"). Not a register offset -- this is the *value*
    /// returned when the guest reads the MagicValue register.
    pub const MAGIC_VALUE: u32 = 0x74726976;
    /// `VirtIO` version (legacy: 1, modern: 2). Runtime value, not an offset.
    pub const VERSION: u32 = 2;
    /// Vendor ID. Runtime value, not an offset.
    pub const VENDOR_ID: u32 = 0x554D4551; // "QEMU"

    /// Interrupt reason: used buffer notification.
    pub const INT_VRING: u32 = vmmio::VIRTIO_MMIO_INT_VRING;
    /// Interrupt reason: configuration change.
    pub const INT_CONFIG: u32 = vmmio::VIRTIO_MMIO_INT_CONFIG;

    /// Register offsets sourced from `virtio_bindings::virtio_mmio`.
    pub mod regs {
        use super::vmmio;

        /// Magic value.
        pub const MAGIC: u64 = vmmio::VIRTIO_MMIO_MAGIC_VALUE as u64;
        /// Version.
        pub const VERSION: u64 = vmmio::VIRTIO_MMIO_VERSION as u64;
        /// Device type.
        pub const DEVICE_ID: u64 = vmmio::VIRTIO_MMIO_DEVICE_ID as u64;
        /// Vendor ID.
        pub const VENDOR_ID: u64 = vmmio::VIRTIO_MMIO_VENDOR_ID as u64;
        /// Device features.
        pub const DEVICE_FEATURES: u64 = vmmio::VIRTIO_MMIO_DEVICE_FEATURES as u64;
        /// Device features selector.
        pub const DEVICE_FEATURES_SEL: u64 = vmmio::VIRTIO_MMIO_DEVICE_FEATURES_SEL as u64;
        /// Driver features.
        pub const DRIVER_FEATURES: u64 = vmmio::VIRTIO_MMIO_DRIVER_FEATURES as u64;
        /// Driver features selector.
        pub const DRIVER_FEATURES_SEL: u64 = vmmio::VIRTIO_MMIO_DRIVER_FEATURES_SEL as u64;
        /// Queue selector.
        pub const QUEUE_SEL: u64 = vmmio::VIRTIO_MMIO_QUEUE_SEL as u64;
        /// Queue size (max).
        pub const QUEUE_NUM_MAX: u64 = vmmio::VIRTIO_MMIO_QUEUE_NUM_MAX as u64;
        /// Queue size.
        pub const QUEUE_NUM: u64 = vmmio::VIRTIO_MMIO_QUEUE_NUM as u64;
        /// Queue ready.
        pub const QUEUE_READY: u64 = vmmio::VIRTIO_MMIO_QUEUE_READY as u64;
        /// Queue notify.
        pub const QUEUE_NOTIFY: u64 = vmmio::VIRTIO_MMIO_QUEUE_NOTIFY as u64;
        /// Interrupt status.
        pub const INTERRUPT_STATUS: u64 = vmmio::VIRTIO_MMIO_INTERRUPT_STATUS as u64;
        /// Interrupt acknowledge.
        pub const INTERRUPT_ACK: u64 = vmmio::VIRTIO_MMIO_INTERRUPT_ACK as u64;
        /// Device status.
        pub const STATUS: u64 = vmmio::VIRTIO_MMIO_STATUS as u64;
        /// Queue descriptor low.
        pub const QUEUE_DESC_LOW: u64 = vmmio::VIRTIO_MMIO_QUEUE_DESC_LOW as u64;
        /// Queue descriptor high.
        pub const QUEUE_DESC_HIGH: u64 = vmmio::VIRTIO_MMIO_QUEUE_DESC_HIGH as u64;
        /// Queue driver low.
        pub const QUEUE_DRIVER_LOW: u64 = vmmio::VIRTIO_MMIO_QUEUE_AVAIL_LOW as u64;
        /// Queue driver high.
        pub const QUEUE_DRIVER_HIGH: u64 = vmmio::VIRTIO_MMIO_QUEUE_AVAIL_HIGH as u64;
        /// Queue device low.
        pub const QUEUE_DEVICE_LOW: u64 = vmmio::VIRTIO_MMIO_QUEUE_USED_LOW as u64;
        /// Queue device high.
        pub const QUEUE_DEVICE_HIGH: u64 = vmmio::VIRTIO_MMIO_QUEUE_USED_HIGH as u64;
        /// Config generation.
        pub const CONFIG_GENERATION: u64 = vmmio::VIRTIO_MMIO_CONFIG_GENERATION as u64;
        /// Config space starts here.
        pub const CONFIG: u64 = vmmio::VIRTIO_MMIO_CONFIG as u64;
    }

    /// MMIO region size.
    pub const MMIO_SIZE: u64 = 0x200;
}

/// `VirtIO` MMIO device state.
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
    /// SHM region selector (for DAX window discovery).
    pub shm_sel: u32,
    /// SHM regions: (base_ipa, length). Index = region ID.
    pub shm_regions: Vec<(u64, u64)>,
}

impl VirtioMmioState {
    /// Creates a new `VirtIO` MMIO state.
    #[must_use]
    pub const fn new(device_id: u32, features: u64) -> Self {
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
            shm_sel: 0,
            shm_regions: Vec::new(),
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
            regs::QUEUE_NUM_MAX => 1024, // Max queue size (increased from 256 for throughput)
            regs::QUEUE_READY => {
                if (self.queue_sel as usize) < 8 {
                    u32::from(self.queue_ready[self.queue_sel as usize])
                } else {
                    0
                }
            }
            regs::INTERRUPT_STATUS => self.interrupt_status,
            regs::STATUS => u32::from(self.status),
            regs::CONFIG_GENERATION => self.config_generation,
            // SHM registers for DAX window discovery (VirtIO 1.2+).
            0x0ac => self.shm_sel,
            0x0b0 => {
                // SHMLenLow
                self.shm_regions
                    .get(self.shm_sel as usize)
                    .map_or(0, |r| r.1 as u32)
            }
            0x0b4 => {
                // SHMLenHigh
                self.shm_regions
                    .get(self.shm_sel as usize)
                    .map_or(0, |r| (r.1 >> 32) as u32)
            }
            0x0b8 => {
                // SHMBaseLow
                self.shm_regions
                    .get(self.shm_sel as usize)
                    .map_or(0, |r| r.0 as u32)
            }
            0x0bc => {
                // SHMBaseHigh
                self.shm_regions
                    .get(self.shm_sel as usize)
                    .map_or(0, |r| (r.0 >> 32) as u32)
            }
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
            0x0ac => self.shm_sel = value, // SHMSel write
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
    pub const fn trigger_interrupt(&mut self, reason: u32) {
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
