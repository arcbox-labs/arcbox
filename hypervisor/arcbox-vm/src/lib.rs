//! `arcbox-vm` — sandbox orchestration, state, networking, and checkpoints.
//!
//! This crate is the heart of the Firecracker VMM daemon.  It exposes:
//!
//! - [`SandboxManager`] — top-level sandbox orchestrator
//! - [`SandboxInstance`] / [`SandboxState`] — per-sandbox runtime state
//! - [`NetworkManager`] — TAP lifecycle & IP allocation
//! - [`SnapshotCatalog`] — checkpoint tracking
//! - [`VmmConfig`] / [`SandboxSpec`] — configuration types

pub mod config;
pub mod error;
pub mod network;
pub mod sandbox;
pub mod snapshot;
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
