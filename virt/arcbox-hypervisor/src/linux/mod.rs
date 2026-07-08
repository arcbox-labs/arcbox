//! Linux KVM hypervisor backend.
//!
//! This module provides the Linux implementation of the hypervisor traits
//! using the KVM API (`/dev/kvm`).
//!
//! # Requirements
//!
//! - Linux kernel with KVM support enabled
//! - `/dev/kvm` device accessible
//! - x86_64 or aarch64 architecture
//!
//! # Architecture Support
//!
//! - **x86_64**: Full support with VMX/SVM
//! - **aarch64**: Full support with VHE/nVHE

mod ffi;
mod hypervisor;
mod memory;
mod vcpu;
mod vm;

pub use hypervisor::KvmHypervisor;
pub use memory::KvmMemory;
pub use vcpu::KvmVcpu;
pub use vm::{KvmVm, VirtioDeviceInfo};

/// Whether the Linux host has nested virtualization enabled for KVM.
///
/// Reads the `nested` module parameter of the Intel/AMD KVM drivers. x86-only;
/// other architectures always report `false`.
#[must_use]
pub(crate) fn host_supports_nested_virt() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        // Intel VMX and AMD SVM expose nesting via a module parameter that
        // reads "Y"/"1" when enabled.
        for path in [
            "/sys/module/kvm_intel/parameters/nested",
            "/sys/module/kvm_amd/parameters/nested",
        ] {
            if let Ok(content) = std::fs::read_to_string(path) {
                let value = content.trim();
                if value == "Y" || value == "1" {
                    return true;
                }
            }
        }
        false
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}
