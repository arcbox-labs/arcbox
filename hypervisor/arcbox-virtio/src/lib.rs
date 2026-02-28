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
// VirtIO code involves many unsafe operations and bit manipulations.
#![allow(dead_code)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::ptr_as_ptr)]
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::redundant_else)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::similar_names)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::if_not_else)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::single_match_else)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::useless_vec)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::missing_fields_in_debug)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::needless_collect)]
#![allow(mismatched_lifetime_syntaxes)]

pub mod blk;
pub mod console;
pub mod error;
pub mod fs;
pub mod net;
pub mod queue;
pub mod vsock;

pub use error::{Result, VirtioError};
pub use queue::{AvailRing, Descriptor, UsedRing, VirtQueue};

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
