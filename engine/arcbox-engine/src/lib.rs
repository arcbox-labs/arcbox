//! # arcbox-engine
//!
//! The embeddable, daemon-free VM engine for `ArcBox`: guest-agent RPC
//! client, VM and machine management, and the VM lifecycle actor.
//!
//! This is an engine-layer crate: it must stay daemon-free and
//! platform-neutral (no dependency on the daemon, CLI, or any
//! macOS-only crate; macOS behavior is reached through `arcbox-vmm`'s
//! backend abstraction or injected by the composing layer).

pub mod agent_client;
pub mod error;
pub mod event;
pub mod machine;
pub mod persistence;
pub mod trace;
pub mod vm;
pub mod vm_lifecycle;

pub use error::{EngineError, Result};

// The platform vocabulary the layers above compose with. They reach the
// hypervisor through here, which is what keeps `arcbox-vmm` and
// `arcbox-hypervisor` off their dependency lists (charter D4).
pub use arcbox_hypervisor::{NestedVirtSupport, host_nested_virt};
pub use arcbox_vmm::VmBackend;
