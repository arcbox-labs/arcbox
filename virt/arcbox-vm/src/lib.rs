//! `arcbox-vm` — guest-side Firecracker sandbox orchestration.
//!
//! # Scope
//!
//! This crate runs **inside** the Linux guest VM, managing nested Firecracker
//! microVMs for workload isolation (sandboxes).  It is consumed exclusively by
//! `arcbox-agent`.
//!
//! The **host-side** VMM that boots the guest is [`arcbox-vmm`], which sits on
//! top of `arcbox-hypervisor` (Virtualization.framework on macOS, KVM on
//! Linux).  These two crates serve fundamentally different layers and should
//! not be confused:
//!
//! | Crate | Runs on | Purpose | Backend |
//! |-------|---------|---------|---------|
//! | `arcbox-vmm` | host | boot + manage the guest VM | Virtualization.framework / KVM |
//! | `arcbox-vm` | guest | nested sandbox microVMs | Firecracker (`fc-sdk`) |
//!
//! # Status: **frozen**
//!
//! New features should go into `arcbox-vmm` / `arcbox-hypervisor`.  This
//! crate receives bug-fixes and sandbox-specific work only.
//!
//! # Public API
//!
//! - [`SandboxManager`] — top-level sandbox orchestrator
//! - [`SandboxInstance`] / [`SandboxState`] — per-sandbox runtime state
//! - [`NetworkManager`] — TAP lifecycle & IP allocation
//! - [`SnapshotCatalog`] — checkpoint tracking
//! - [`VmmConfig`] / [`SandboxSpec`] — configuration types

pub mod boot_proto;
pub mod config;
pub mod error;
pub mod file_io;
pub mod network;
pub mod sandbox;
pub mod snapshot;
pub mod snapshot_cow;
pub mod spawn;
pub mod store;
pub mod vsock;

// Keep the general VM manager available for internal tooling.
pub mod instance;
pub mod manager;

pub use config::{DefaultVmConfig, FirecrackerConfig, GrpcConfig, NetworkConfig, VmmConfig};
pub use error::{Result, VmmError};
pub use network::{NetworkAllocation, NetworkManager};
pub use sandbox::{
    CheckpointInfo, CheckpointSummary, RestoreSandboxSpec, SandboxEvent, SandboxId, SandboxInfo,
    SandboxManager, SandboxMountSpec, SandboxNetworkInfo, SandboxNetworkSpec, SandboxSpec,
    SandboxState, SandboxSummary,
};
pub use snapshot::{SnapshotCatalog, SnapshotInfo};
pub use vsock::{ExecInputMsg, OutputChunk, StartCommand};

// Re-export VmState for system_svc compatibility (internal use only).
pub use instance::VmState;
