//! ArcBox - High-performance container and VM runtime.
//!
//! This crate provides a unified API for the ArcBox runtime, re-exporting
//! functionality from the core crates.
//!
//! # Architecture
//!
//! This crate currently re-exports selected ArcBox foundational crates:
//!
//! - **Hypervisor**: Platform abstraction for virtualization (macOS/Linux)
//! - **VirtIO**: Virtual device implementations (block, net, fs, console)
//! - **Protocol**: Protobuf message and service definitions
//!
//! # Example
//!
//! ```ignore
//! use arcbox::{protocol, version};
//!
//! let _ = protocol::v1::Empty {};
//! println!("arcbox facade version: {}", version());
//! ```

// Re-export core crates (available in this version)
pub use arcbox_hypervisor as hypervisor;
pub use arcbox_protocol as protocol;
pub use arcbox_virtio as virtio;

// TODO: uncomment after publishing these crates
// pub use arcbox_container as container;
// pub use arcbox_core as core;
// pub use arcbox_fs as fs;
// pub use arcbox_net as net;
// pub use arcbox_vmm as vmm;

/// Prelude module for common imports.
pub mod prelude {
    // Hypervisor traits
    pub use crate::hypervisor::{GuestMemory, Hypervisor, Vcpu, VirtualMachine};

    // Common types
    pub use crate::hypervisor::{GuestAddress, HypervisorError, VcpuExit, VmConfig};

    // TODO: uncomment after publishing vmm
    // pub use crate::vmm::{Vmm, VmmConfig};
}

/// Returns the version of ArcBox.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!version().is_empty());
    }
}
