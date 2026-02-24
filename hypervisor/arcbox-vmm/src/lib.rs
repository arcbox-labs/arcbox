//! # arcbox-vmm
//!
//! Virtual Machine Monitor (VMM) for ArcBox.
//!
//! This crate provides high-level VM management on top of the hypervisor
//! abstraction layer:
//!
//! - [`VmBuilder`]: Fluent API for VM configuration
//! - [`VcpuManager`]: Manages vCPU threads and execution
//! - [`MemoryManager`]: Memory allocation and mapping
//! - [`DeviceManager`]: Device registration and I/O handling
//! - [`EventLoop`]: Main VMM event loop
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │                    VMM                           │
//! │  ┌────────────┐ ┌────────────┐ ┌────────────┐  │
//! │  │VcpuManager │ │MemoryManager│ │DeviceManager│  │
//! │  └────────────┘ └────────────┘ └────────────┘  │
//! │  ┌────────────┐ ┌────────────┐ ┌────────────┐  │
//! │  │ EventLoop  │ │  IrqChip   │ │   Boot     │  │
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

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
// VMM code involves many low-level operations.
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(clippy::nursery)]

pub mod boot;
pub mod builder;
pub mod device;
pub mod error;
pub mod event;
pub mod fdt;
pub mod irq;
pub mod memory;
pub mod vcpu;
pub mod vmm;

pub use boot::{BootParams, KernelLoader, KernelType};
pub use builder::{VmBuilder, VmInstance};
pub use device::{DeviceId, DeviceInfo, DeviceManager, DeviceTreeEntry, DeviceType};
pub use error::{Result, VmmError};
pub use fdt::{FdtBuilder, FdtConfig};
pub use vcpu::{DeviceManagerExitHandler, ExitHandler, VcpuManager};
pub use vmm::{SharedDirConfig, Vmm, VmmConfig, VmmState};
