//! VM configuration types.
//!
//! This module provides types for configuring virtual machines,
//! including boot loaders, platform configurations, and device settings.

mod boot_loader;
mod mac;
mod platform;
mod vm_config;

pub use boot_loader::{BootLoader, LinuxBootLoader, MacOSBootLoader};
pub use mac::{MacAuxiliaryStorage, MacHardwareModel, MacMachineIdentifier};
pub use platform::{GenericPlatform, MacPlatform, Platform};
pub use vm_config::VirtualMachineConfiguration;
