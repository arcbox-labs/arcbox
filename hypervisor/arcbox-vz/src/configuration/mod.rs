//! VM configuration types.
//!
//! This module provides types for configuring virtual machines,
//! including boot loaders, platform configurations, and device settings.

mod boot_loader;
mod platform;
mod vm_config;

pub use boot_loader::{BootLoader, LinuxBootLoader};
pub use platform::{GenericPlatform, Platform};
pub use vm_config::VirtualMachineConfiguration;
