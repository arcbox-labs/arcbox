//! `vmm-core` — multi-VM orchestration, state, networking, and snapshots.
//!
//! This crate is the heart of the Firecracker VMM daemon. It exposes:
//!
//! - [`VmmManager`] — top-level orchestrator
//! - [`VmInstance`] / [`VmState`] — per-VM runtime state
//! - [`VmStore`] — disk persistence
//! - [`NetworkManager`] — TAP lifecycle & IP allocation
//! - [`SnapshotCatalog`] — snapshot tracking
//! - [`VmmConfig`] / [`VmSpec`] — configuration types

pub mod config;
pub mod error;
pub mod instance;
pub mod manager;
pub mod network;
pub mod snapshot;
pub mod store;

pub use config::{
    DefaultVmConfig, FirecrackerConfig, GrpcConfig, NetworkConfig, RestoreSpec, SnapshotRequest,
    SnapshotType, VmSpec, VmmConfig,
};
pub use error::{Result, VmmError};
pub use instance::{VmId, VmInfo, VmInstance, VmMetrics, VmState, VmSummary};
pub use manager::VmmManager;
pub use network::{NetworkAllocation, NetworkManager};
pub use snapshot::{SnapshotCatalog, SnapshotInfo};
pub use store::VmStore;
