//! # arcbox-virtio
//!
//! VirtIO device implementations for ArcBox.
//!
//! This crate provides VirtIO device emulation including:
//!
//! - [`blk`]: Block device (virtio-blk)
//! - [`net`]: Network device (virtio-net)
//! - [`console`]: Console device (virtio-console)
//! - [`fs`]: Filesystem device (virtio-fs)
//! - [`vsock`]: Socket device (virtio-vsock)
//!
//! ## VirtIO Queue
//!
//! All devices use the standard VirtIO queue (virtqueue) mechanism for
//! communication with the guest. The [`queue`] module provides the core
//! queue implementation.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │            arcbox-virtio                │
//! │  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌────┐│
//! │  │ blk │ │ net │ │cons │ │ fs  │ │vsock││
//! │  └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬─┘│
//! │     └───────┴───────┴───────┴───────┘  │
//! │                   │                     │
//! │              VirtQueue                  │
//! └─────────────────────────────────────────┘
//! ```

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

pub mod blk;
pub mod console;
pub mod error;
pub mod fs;
pub mod net;
pub mod queue;
pub mod vsock;

pub use error::{VirtioError, Result};
pub use queue::{VirtQueue, Descriptor, AvailRing, UsedRing};

/// VirtIO device type IDs.
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

/// VirtIO device status flags.
#[derive(Debug, Clone, Copy)]
pub struct DeviceStatus(u8);

impl DeviceStatus {
    /// Device acknowledged.
    pub const ACKNOWLEDGE: u8 = 1;
    /// Driver loaded.
    pub const DRIVER: u8 = 2;
    /// Driver is ready.
    pub const DRIVER_OK: u8 = 4;
    /// Feature negotiation complete.
    pub const FEATURES_OK: u8 = 8;
    /// Device needs reset.
    pub const DEVICE_NEEDS_RESET: u8 = 64;
    /// Driver failed.
    pub const FAILED: u8 = 128;

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
    pub fn set(&mut self, flag: u8) {
        self.0 |= flag;
    }

    /// Clears a flag.
    pub fn clear(&mut self, flag: u8) {
        self.0 &= !flag;
    }
}

/// Trait for VirtIO devices.
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
}
