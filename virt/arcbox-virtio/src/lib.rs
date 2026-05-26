//! # arcbox-virtio
//!
//! `VirtIO` device implementations for `ArcBox`.
//!
//! This crate provides `VirtIO` device emulation including:
//!
//! - [`blk`]: Block device (virtio-blk)
//! - [`net`]: Network device (virtio-net)
//! - [`console`]: Console device (virtio-console)
//! - [`fs`]: Filesystem device (virtio-fs)
//! - [`vsock`]: Socket device (virtio-vsock)
//!
//! ## `VirtIO` Queue
//!
//! All devices use the standard `VirtIO` queue (virtqueue) mechanism for
//! communication with the guest. The [`queue`] module provides the core
//! queue implementation.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │            arcbox-virtio                │
//! │  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐│
//! │  │ blk │ │ net │ │cons │ │ fs  │ │vsock││
//! │  └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘│
//! │     └───────┴───────┴───────┴───────┘   │
//! │                   │                     │
//! │              VirtQueue                  │
//! └─────────────────────────────────────────┘
//! ```

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

/// Back-compat re-export of `arcbox-virtio-blk`.
pub mod blk {
    pub use arcbox_virtio_blk::*;
}

/// Back-compat re-export of `arcbox-virtio-console`.
pub mod console {
    pub use arcbox_virtio_console::*;
}

/// Back-compat re-export of `arcbox-virtio-fs`.
pub mod fs {
    pub use arcbox_virtio_fs::*;
}

/// Back-compat re-export of `arcbox-virtio-net`.
pub mod net {
    pub use arcbox_virtio_net::*;
}

/// Back-compat re-export of `arcbox-virtio-rng`.
pub mod rng {
    pub use arcbox_virtio_rng::*;
}

/// Back-compat re-export of `arcbox-virtio-vsock`.
pub mod vsock {
    pub use arcbox_virtio_vsock::*;
}

/// Back-compat re-export of `arcbox-virtio-balloon`.
pub mod balloon {
    pub use arcbox_virtio_balloon::*;
}

/// Back-compat re-export of the vsock connection manager. The actual
/// `RxOps` / `VsockConnectionManager` / `VsockConnection` definitions
/// live in `arcbox-virtio-vsock::manager` after the per-device split.
pub mod vsock_manager {
    pub use arcbox_virtio_vsock::manager::*;
}

// Back-compat re-export of `queue` / `queue_guest` modules (moved to
// `arcbox-virtio-core`). Existing `arcbox_virtio::queue::VirtQueue`
// paths keep working.
pub use arcbox_virtio_core::queue;
pub use arcbox_virtio_core::queue_guest;

// Re-export the foundational types from arcbox-virtio-core so existing
// `arcbox_virtio::{VirtioDevice, DeviceCtx, ...}` imports keep working
// without changes. The types' actual definitions live in
// `arcbox-virtio-core` so per-device crates (rng, console, blk, ...)
// can depend on the smaller foundation crate without pulling in every
// device implementation.
pub use arcbox_virtio_core::{
    DeviceCtx, DeviceStatus, GuestMemWriter, QueueConfig, Result, VirtioDevice, VirtioDeviceId,
    VirtioError, virtio_bindings,
};
pub use queue::{AvailRing, Descriptor, UsedRing, VirtQueue};

// Back-compat re-export of the foundational `error` and `guest_mem`
// modules — code that did `arcbox_virtio::error::VirtioError` or
// `arcbox_virtio::guest_mem::GuestMemWriter` keeps compiling.
pub use arcbox_virtio_core::error;
pub use arcbox_virtio_core::guest_mem;
