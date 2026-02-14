//! Safe Rust bindings for Apple's Virtualization.framework.
//!
//! This crate provides ergonomic, async-first bindings to Apple's Virtualization.framework,
//! allowing you to create and manage virtual machines on macOS.
//!
//! # Features
//!
//! - **Safe API**: Minimize unsafe code exposure with safe Rust abstractions
//! - **Async-first**: Native async/await support for all asynchronous operations
//! - **Complete Coverage**: Support all Virtualization.framework features (macOS 11+)
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
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
// FFI bindings require extensive pointer casts - these are intentional and safe.
#![allow(clippy::ptr_as_ptr)]
#![allow(clippy::ptr_cast_constness)]
#![allow(clippy::ref_as_ptr)]
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::unnecessary_cast)]
// Documentation lints - acceptable for FFI code.
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
// Code style lints - acceptable for FFI patterns.
#![allow(clippy::items_after_statements)]
#![allow(clippy::redundant_else)]
#![allow(clippy::if_not_else)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::type_complexity)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::cast_possible_truncation)]

pub mod error;
pub mod ffi;

pub mod configuration;
pub(crate) mod delegate;
pub mod device;
pub mod socket;
pub mod vm;

// Re-exports for convenience
pub use error::VZError;

pub use configuration::{GenericPlatform, LinuxBootLoader, Platform, VirtualMachineConfiguration};

pub use device::{
    DirectoryShare, EntropyDeviceConfiguration, LinuxRosettaDirectoryShare,
    MemoryBalloonDevice, MemoryBalloonDeviceConfiguration, MultipleDirectoryShare,
    NetworkDeviceConfiguration, RosettaAvailability, SerialPortConfiguration, SharedDirectory,
    SingleDirectoryShare, SocketDeviceConfiguration, StorageDeviceConfiguration,
    VirtioFileSystemDeviceConfiguration,
};

pub use socket::{VirtioSocketConnection, VirtioSocketDevice, VirtioSocketListener};

pub use vm::{VirtualMachine, VirtualMachineState};

/// Check if virtualization is supported on this system.
///
/// Returns `true` if the Virtualization.framework is available and the
/// hardware supports virtualization.
#[must_use]
pub fn is_supported() -> bool {
    ffi::is_supported()
}

/// Get the minimum allowed CPU count for a virtual machine.
#[must_use]
pub fn min_cpu_count() -> u64 {
    ffi::min_cpu_count()
}

/// Get the maximum allowed CPU count for a virtual machine.
#[must_use]
pub fn max_cpu_count() -> u64 {
    ffi::max_cpu_count()
}

/// Get the minimum allowed memory size for a virtual machine (in bytes).
#[must_use]
pub fn min_memory_size() -> u64 {
    ffi::min_memory_size()
}

/// Get the maximum allowed memory size for a virtual machine (in bytes).
#[must_use]
pub fn max_memory_size() -> u64 {
    ffi::max_memory_size()
}
