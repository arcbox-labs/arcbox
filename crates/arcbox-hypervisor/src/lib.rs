//! # arcbox-hypervisor
//!
//! Cross-platform hypervisor abstraction layer for ArcBox.
//!
//! This crate provides platform-agnostic traits for virtualization:
//! - [`Hypervisor`]: Main entry point for creating VMs
//! - [`VirtualMachine`]: VM lifecycle management
//! - [`Vcpu`]: Virtual CPU execution
//! - [`GuestMemory`]: Guest memory access
//!
//! ## Platform Backends
//!
//! - **macOS**: Uses `Virtualization.framework`
//! - **Linux**: Uses KVM (`/dev/kvm`)
//!
//! ## Example
//!
//! ```ignore
//! use arcbox_hypervisor::{create_hypervisor, VmConfig};
//!
//! let hypervisor = create_hypervisor()?;
//! let config = VmConfig::builder()
//!     .vcpu_count(4)
//!     .memory_size(4 * 1024 * 1024 * 1024) // 4GB
//!     .build();
//! let vm = hypervisor.create_vm(config)?;
//! ```

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

pub mod config;
pub mod error;
pub mod memory;
pub mod traits;
pub mod types;

#[cfg(target_os = "macos")]
pub mod darwin;

#[cfg(target_os = "linux")]
pub mod linux;

pub use config::{VmConfig, VmConfigBuilder};
pub use error::{HypervisorError, Result};
pub use memory::{GuestAddress, MemoryRegion};
pub use traits::{GuestMemory, Hypervisor, Vcpu, VirtualMachine};
pub use types::{CpuArch, PlatformCapabilities, Registers, VcpuExit, VirtioDeviceConfig};

/// Creates the appropriate hypervisor for the current platform.
///
/// # Errors
///
/// Returns an error if the hypervisor cannot be initialized.
pub fn create_hypervisor() -> Result<impl Hypervisor> {
    #[cfg(target_os = "macos")]
    {
        darwin::DarwinHypervisor::new()
    }

    #[cfg(target_os = "linux")]
    {
        linux::KvmHypervisor::new()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        compile_error!("Unsupported platform: only macOS and Linux are supported")
    }
}
