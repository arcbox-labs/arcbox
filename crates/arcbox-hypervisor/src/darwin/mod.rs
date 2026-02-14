//! macOS Virtualization.framework backend.
//!
//! This module provides the macOS implementation of the hypervisor traits
//! using Apple's Virtualization.framework via `arcbox-vz`.
//!
//! # Requirements
//!
//! - macOS 11.0 or later
//! - Apple Silicon (ARM64) or Intel x86_64
//! - Entitlements for virtualization (com.apple.security.virtualization)
//!
//! # Architecture
//!
//! - `DarwinHypervisor`: Uses `arcbox-vz` for capability detection and VM creation
//! - `DarwinVm`: Uses `arcbox-vz` for VM lifecycle management
//! - `DarwinMemory`: Internal memory management with software dirty tracking
//! - `DarwinVcpu`: Placeholder vCPU for managed execution model

mod hypervisor;
mod memory;
mod vcpu;
mod vm;

pub use hypervisor::DarwinHypervisor;
pub use memory::DarwinMemory;
pub use vcpu::DarwinVcpu;
pub use vm::DarwinVm;

/// Checks if virtualization is supported on this system.
///
/// Uses `arcbox-vz` to query the Virtualization.framework.
#[must_use]
pub fn is_supported() -> bool {
    arcbox_vz::is_supported()
}
