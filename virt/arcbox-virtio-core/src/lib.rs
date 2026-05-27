//! # arcbox-virtio-core
//!
//! Foundational types and traits shared by every ArcBox VirtIO device
//! crate. Lives at the bottom of the dependency graph so each
//! per-device crate (`arcbox-virtio-net`, `arcbox-virtio-block`, …)
//! and the umbrella `arcbox-virtio` crate can pull from one place
//! without circular references.
//!
//! Contents:
//! - [`VirtioDevice`]: the device-implementation trait.
//! - [`DeviceCtx`]: shared guest-memory + IRQ-trigger context that
//!   each device holds at runtime.
//! - [`QueueConfig`]: per-virtqueue configuration snapshot built by
//!   the VMM from MMIO state and handed to a device for processing.
//! - [`VirtioDeviceId`] / [`DeviceStatus`]: device-type IDs and
//!   transport status flags.
//! - [`GuestMemWriter`]: GPA-keyed accessor over guest RAM.
//! - [`Result`] / [`VirtioError`]: error types shared by all devices.

#![allow(clippy::ptr_as_ptr)]
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::useless_vec)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::missing_fields_in_debug)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::needless_collect)]
#![allow(mismatched_lifetime_syntaxes)]

pub mod error;
pub mod guest_mem;
pub mod queue;
pub mod queue_guest;

pub use error::{Result, VirtioError};
pub use guest_mem::GuestMemWriter;
pub use queue::{AvailRing, Descriptor, UsedRing, VirtQueue};

// Re-export commonly used virtio constants from virtio-bindings so
// downstream crates can reach them without an extra direct dependency.
pub use virtio_bindings;

/// Per-device context shared between the VMM and each `VirtioDevice` for
/// accessing guest physical memory and injecting interrupts.
///
/// Every device that needs to read descriptors, write completions to
/// device-owned buffers, or raise a VirtIO used-ring / config-change
/// interrupt holds a `DeviceCtx`. Construction happens inside the VMM
/// at device-registration time, so by the time guest I/O begins both
/// fields are populated — devices store this by value (no `Option`).
///
/// `mem` is a shared-lifetime accessor over the single guest RAM mmap.
/// `raise_irq` is pre-bound to the device's GSI and MMIO state; the
/// only argument is the interrupt reason (`INT_VRING` = 1 for used-ring
/// notifications, `INT_CONFIG` = 2 for config-space changes).
#[derive(Clone)]
pub struct DeviceCtx {
    /// Guest physical memory accessor.
    pub mem: std::sync::Arc<GuestMemWriter>,
    /// Pre-bound interrupt trigger: updates the device's MMIO
    /// `interrupt_status` register and then asserts the device's GSI
    /// on the platform IRQ chip.
    pub raise_irq: std::sync::Arc<dyn Fn(u32) + Send + Sync>,
}

impl std::fmt::Debug for DeviceCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCtx")
            .field("mem_len", &self.mem.len())
            .field("mem_gpa_base", &self.mem.gpa_base())
            .field("raise_irq", &"<fn>")
            .finish()
    }
}

/// `VirtIO` device type IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VirtioDeviceId {
    /// Network device.
    Net = 1,
    /// Block device.
    Block = 2,
    /// Console device.
    Console = 3,
    /// Entropy source.
    Rng = 4,
    /// Balloon device.
    Balloon = 5,
    /// SCSI host.
    Scsi = 8,
    /// Filesystem device.
    Fs = 26,
    /// Socket device.
    Vsock = 19,
}

/// `VirtIO` device status flags.
///
/// Values sourced from `virtio_bindings::virtio_config`.
#[derive(Debug, Clone, Copy)]
pub struct DeviceStatus(u8);

impl DeviceStatus {
    /// Device acknowledged.
    pub const ACKNOWLEDGE: u8 = virtio_bindings::virtio_config::VIRTIO_CONFIG_S_ACKNOWLEDGE as u8;
    /// Driver loaded.
    pub const DRIVER: u8 = virtio_bindings::virtio_config::VIRTIO_CONFIG_S_DRIVER as u8;
    /// Driver is ready.
    pub const DRIVER_OK: u8 = virtio_bindings::virtio_config::VIRTIO_CONFIG_S_DRIVER_OK as u8;
    /// Feature negotiation complete.
    pub const FEATURES_OK: u8 = virtio_bindings::virtio_config::VIRTIO_CONFIG_S_FEATURES_OK as u8;
    /// Device needs reset.
    pub const DEVICE_NEEDS_RESET: u8 =
        virtio_bindings::virtio_config::VIRTIO_CONFIG_S_NEEDS_RESET as u8;
    /// Driver failed.
    pub const FAILED: u8 = virtio_bindings::virtio_config::VIRTIO_CONFIG_S_FAILED as u8;

    /// Creates a new device status.
    #[must_use]
    pub const fn new(status: u8) -> Self {
        Self(status)
    }

    /// Returns the raw status value.
    #[must_use]
    pub const fn raw(&self) -> u8 {
        self.0
    }

    /// Checks if a flag is set.
    #[must_use]
    pub const fn has(&self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    /// Sets a flag.
    pub const fn set(&mut self, flag: u8) {
        self.0 |= flag;
    }

    /// Clears a flag.
    pub const fn clear(&mut self, flag: u8) {
        self.0 &= !flag;
    }
}

/// Trait for `VirtIO` devices.
pub trait VirtioDevice: Send + Sync {
    /// Returns the device type ID.
    fn device_id(&self) -> VirtioDeviceId;

    /// Returns the device features.
    fn features(&self) -> u64;

    /// Acknowledges features from the driver.
    fn ack_features(&mut self, features: u64);

    /// Reads from the device configuration space.
    fn read_config(&self, offset: u64, data: &mut [u8]);

    /// Writes to the device configuration space.
    fn write_config(&mut self, offset: u64, data: &[u8]);

    /// Activates the device.
    fn activate(&mut self) -> Result<()>;

    /// Resets the device.
    fn reset(&mut self);

    /// Processes pending buffers in the specified queue.
    ///
    /// `memory` is the entire guest physical memory as a mutable byte slice.
    /// `queue_config` provides the guest physical addresses of the virtqueue
    /// rings so the device can read descriptors directly from guest memory.
    ///
    /// Returns a list of `(descriptor_head_index, bytes_written)` completions,
    /// or an empty vec if no processing occurred.
    ///
    /// The default implementation does nothing. Devices that support
    /// queue-based processing (blk, fs, net, vsock) should override this.
    fn process_queue(
        &mut self,
        queue_idx: u16,
        memory: &mut [u8],
        queue_config: &QueueConfig,
    ) -> Result<Vec<(u16, u32)>> {
        let _ = (queue_idx, memory, queue_config);
        Ok(Vec::new())
    }
}

/// Configuration for a single virtqueue, as set by the guest driver via
/// MMIO transport writes.
///
/// All addresses are guest physical addresses (GPAs). The `memory` slice
/// passed to [`VirtioDevice::process_queue`] starts at `gpa_base`, so
/// devices must subtract `gpa_base` to convert a GPA to a slice index.
///
/// Device-specific state (e.g. the vsock host connection manager) is
/// not plumbed through this struct — devices that need such state hold
/// it directly via their own `bind_*` setters.
#[derive(Debug, Default)]
pub struct QueueConfig {
    /// Guest physical address of the descriptor table.
    pub desc_addr: u64,
    /// Guest physical address of the available (driver) ring.
    pub avail_addr: u64,
    /// Guest physical address of the used (device) ring.
    pub used_addr: u64,
    /// Queue size (number of descriptors).
    pub size: u16,
    /// Whether the queue is ready.
    pub ready: bool,
    /// GPA of the start of the guest memory slice. Devices must subtract
    /// this from descriptor addresses to get slice offsets.
    pub gpa_base: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use virtio_bindings::virtio_config;
    use virtio_bindings::virtio_ids;

    /// Verify that our `VirtioDeviceId` enum values match the canonical
    /// constants from the `virtio-bindings` crate (linux kernel headers).
    #[test]
    fn device_id_values_match_virtio_bindings() {
        assert_eq!(VirtioDeviceId::Net as u32, virtio_ids::VIRTIO_ID_NET);
        assert_eq!(VirtioDeviceId::Block as u32, virtio_ids::VIRTIO_ID_BLOCK);
        assert_eq!(
            VirtioDeviceId::Console as u32,
            virtio_ids::VIRTIO_ID_CONSOLE
        );
        assert_eq!(VirtioDeviceId::Rng as u32, virtio_ids::VIRTIO_ID_RNG);
        assert_eq!(
            VirtioDeviceId::Balloon as u32,
            virtio_ids::VIRTIO_ID_BALLOON
        );
        assert_eq!(VirtioDeviceId::Scsi as u32, virtio_ids::VIRTIO_ID_SCSI);
        assert_eq!(VirtioDeviceId::Fs as u32, virtio_ids::VIRTIO_ID_FS);
        assert_eq!(VirtioDeviceId::Vsock as u32, virtio_ids::VIRTIO_ID_VSOCK);
    }

    /// Verify that our `DeviceStatus` constants match the canonical values.
    #[test]
    fn device_status_values_match_virtio_bindings() {
        assert_eq!(
            DeviceStatus::ACKNOWLEDGE as u32,
            virtio_config::VIRTIO_CONFIG_S_ACKNOWLEDGE
        );
        assert_eq!(
            DeviceStatus::DRIVER as u32,
            virtio_config::VIRTIO_CONFIG_S_DRIVER
        );
        assert_eq!(
            DeviceStatus::DRIVER_OK as u32,
            virtio_config::VIRTIO_CONFIG_S_DRIVER_OK
        );
        assert_eq!(
            DeviceStatus::FEATURES_OK as u32,
            virtio_config::VIRTIO_CONFIG_S_FEATURES_OK
        );
        assert_eq!(
            DeviceStatus::DEVICE_NEEDS_RESET as u32,
            virtio_config::VIRTIO_CONFIG_S_NEEDS_RESET
        );
        assert_eq!(
            DeviceStatus::FAILED as u32,
            virtio_config::VIRTIO_CONFIG_S_FAILED
        );
    }
}
