//! macOS Virtualization.framework backend.
//!
//! This module provides the macOS implementation of the hypervisor traits
//! using Apple's Virtualization.framework.
//!
//! # Requirements
//!
//! - macOS 11.0 or later
//! - Apple Silicon (ARM64) or Intel x86_64
//! - Entitlements for virtualization (com.apple.security.virtualization)

pub(crate) mod ffi;
mod hypervisor;
mod memory;
mod vcpu;
mod vm;

pub use hypervisor::DarwinHypervisor;
pub use memory::DarwinMemory;
pub use vcpu::DarwinVcpu;
pub use vm::DarwinVm;

/// Checks if virtualization is supported on this system.
#[must_use]
pub fn is_supported() -> bool {
    ffi::is_supported()
}
