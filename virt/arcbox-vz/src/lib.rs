//! Safe Rust bindings for Apple's Virtualization.framework.
//!
//! This crate provides ergonomic, async-first bindings to Apple's Virtualization.framework,
//! allowing you to create and manage virtual machines on macOS. All framework
//! interaction happens in the bundled ArcBoxVZShim Swift static library
//! (`shim/`), reached through the hand-written C ABI in `shim_ffi.rs` — see
//! that file's header for the boundary conventions.
//!
//! # Features
//!
//! - **Safe API**: Minimize unsafe code exposure with safe Rust abstractions
//! - **Async-first**: Native async/await support for all asynchronous operations
//!
//! # Example
//!
//! ```rust,no_run
//! use arcbox_vz::{
//!     VirtualMachineConfiguration, LinuxBootLoader, GenericPlatform,
//!     SocketDeviceConfiguration, VZError,
//! };
//!
//! #[tokio::main]
//! async fn main() -> Result<(), VZError> {
//!     let mut config = VirtualMachineConfiguration::new()?;
//!     config
//!         .set_cpu_count(2)
//!         .set_memory_size(512 * 1024 * 1024);
//!
//!     let boot_loader = LinuxBootLoader::new("/path/to/kernel")?;
//!     config.set_boot_loader(boot_loader);
//!
//!     let vm = config.build()?;
//!     vm.start().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Platform Support
//!
//! This crate only supports macOS 11.0 (Big Sur) and later. Attempting to compile
//! on other platforms will result in a compilation error.
//!
//! # Entitlements
//!
//! Your application must have the `com.apple.security.virtualization` entitlement
//! to use this framework. See Apple's documentation for details.

#![cfg(target_os = "macos")]
#![warn(missing_docs)]

pub mod error;
mod shim_ffi;

pub mod configuration;
pub mod device;
pub mod restore;
pub mod socket;
pub mod vm;

// Re-exports for convenience
pub use error::VZError;

pub use configuration::{
    GenericPlatform, LinuxBootLoader, MacAuxiliaryStorage, MacHardwareModel, MacMachineIdentifier,
    MacOSBootLoader, MacPlatform, Platform, VirtualMachineConfiguration,
};

pub use device::{
    DirectoryShare, EntropyDeviceConfiguration, LinuxRosettaDirectoryShare,
    MacGraphicsDeviceConfiguration, MemoryBalloonDevice, MemoryBalloonDeviceConfiguration,
    NetworkDeviceConfiguration, RosettaAvailability, SerialPortConfiguration, SharedDirectory,
    SingleDirectoryShare, SocketDeviceConfiguration, StorageDeviceConfiguration,
    VirtioFileSystemDeviceConfiguration, desired_network_mtu,
};

pub use socket::{VirtioSocketConnection, VirtioSocketDevice};

pub use restore::{MacOSConfigurationRequirements, MacOSInstaller, MacOSRestoreImage};

pub use vm::{VirtualMachine, VirtualMachineState};

/// Check if virtualization is supported on this system.
///
/// Returns `true` if the Virtualization.framework is available and the
/// hardware supports virtualization.
#[must_use]
pub fn is_supported() -> bool {
    // SAFETY: shim reads a class property; no preconditions.
    unsafe { shim_ffi::abx_vz_supported() }
}

/// Get the minimum allowed CPU count for a virtual machine.
#[must_use]
pub fn min_cpu_count() -> u64 {
    // SAFETY: shim reads a class property; no preconditions.
    unsafe { shim_ffi::abx_vz_min_cpu_count() }
}

/// Get the maximum allowed CPU count for a virtual machine.
#[must_use]
pub fn max_cpu_count() -> u64 {
    // SAFETY: shim reads a class property; no preconditions.
    unsafe { shim_ffi::abx_vz_max_cpu_count() }
}

/// Get the minimum allowed memory size for a virtual machine (in bytes).
#[must_use]
pub fn min_memory_size() -> u64 {
    // SAFETY: shim reads a class property; no preconditions.
    unsafe { shim_ffi::abx_vz_min_memory_size() }
}

/// Get the maximum allowed memory size for a virtual machine (in bytes).
#[must_use]
pub fn max_memory_size() -> u64 {
    // SAFETY: shim reads a class property; no preconditions.
    unsafe { shim_ffi::abx_vz_max_memory_size() }
}
