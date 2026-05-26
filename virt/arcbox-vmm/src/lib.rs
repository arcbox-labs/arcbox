//! # arcbox-vmm
//!
//! Host-side Virtual Machine Monitor (VMM) for `ArcBox`.
//!
//! This is the **primary** VM stack, used by `arcbox-core` to boot and manage
//! the Linux guest.  Platform-specific backends live in submodules:
//!
//! - **macOS**: Virtualization.framework (managed execution)
//! - **Linux**: KVM (manual vCPU execution)
//!
//! For the guest-side Firecracker sandbox stack, see `arcbox-vm`.
//!
//! # Key types
//!
//! - [`Vmm`]: VM lifecycle/state and device orchestration
//! - [`VmBuilder`]: Fluent API for VM configuration
//! - [`VcpuManager`]: Manages vCPU threads and execution
//! - [`MemoryManager`]: Memory allocation and mapping
//! - [`DeviceManager`]: Device registration and I/O handling
//! - [`KernelLoader`] and [`FdtBuilder`]: Boot image and device-tree setup
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │                    VMM                           │
//! │  ┌────────────┐ ┌────────────┐ ┌────────────┐  │
//! │  │VcpuManager │ │MemoryManager│ │DeviceManager│ │
//! │  └────────────┘ └────────────┘ └────────────┘  │
//! │  ┌────────────┐ ┌────────────┐ ┌────────────┐  │
//! │  │    Boot    │ │    FDT     │ │    IRQ     │  │
//! │  └────────────┘ └────────────┘ └────────────┘  │
//! └─────────────────────────────────────────────────┘
//!                      │
//!                      ▼
//!        ┌─────────────────────────┐
//!        │   arcbox-hypervisor     │
//!        └─────────────────────────┘
//!                      │
//!                      ▼
//!        ┌─────────────────────────┐
//!        │    arcbox-virtio        │
//!        └─────────────────────────┘
//! ```
//!
//! ## Example
//!
//! ```ignore
//! use arcbox_vmm::builder::VmBuilder;
//!
//! let vm = VmBuilder::new()
//!     .name("my-vm")
//!     .cpus(4)
//!     .memory_gb(2)
//!     .kernel("/path/to/vmlinux")
//!     .cmdline("console=hvc0 root=/dev/vda")
//!     .block_device("/path/to/disk.img", false)
//!     .network_device(None, None)
//!     .build()?;
//!
//! vm.run().await?;
//! ```
pub mod blk_worker;
pub mod boot;
pub mod builder;
pub mod dax;
pub mod device;
// Intentionally not `pub` — only used by darwin_hv to spawn the worker.
pub mod error;
pub mod event;
pub mod fdt;
pub mod irq;
pub mod memory;
#[cfg(target_os = "macos")]
pub(crate) mod net_rx_worker;
pub mod snapshot;
pub mod vcpu;
pub(crate) mod virtqueue_util;
pub mod vmm;
/// Back-compat re-export of `arcbox_virtio::vsock_manager`.
///
/// The module moved to `arcbox-virtio` so that
/// `VirtioVsock::poll_rx_injection` can reach `RxOps` /
/// `VsockConnection` internals without `arcbox-virtio` depending on
/// `arcbox-vmm`. Existing `crate::vsock_manager::*` imports continue
/// to work via this shim.
pub mod vsock_manager {
    pub use arcbox_virtio::vsock_manager::*;
}

pub use boot::{BootParams, KernelLoader, KernelType};
pub use builder::{VmBuilder, VmInstance};
pub use device::{DeviceId, DeviceInfo, DeviceManager, DeviceTreeEntry, DeviceType};
pub use error::{Result, VmmError};
pub use fdt::{FdtBuilder, FdtConfig};
pub use snapshot::{
    SnapshotCreateOptions, SnapshotError, SnapshotInfo, SnapshotManager, SnapshotState,
    SnapshotTargetType, VmRestoreData, VmSnapshotContext,
};
pub use vcpu::{DeviceManagerExitHandler, ExitHandler, VcpuManager};
pub use vmm::{
    BlockDeviceConfig, ResolvedBackend, SharedDirConfig, VmBackend, Vmm, VmmConfig, VmmState,
};
