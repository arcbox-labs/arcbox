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
pub use vm::KvmVm;
