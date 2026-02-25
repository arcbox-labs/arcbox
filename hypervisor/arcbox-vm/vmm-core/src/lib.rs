//! `vmm-core` — multi-VM orchestration, state, networking, and snapshots.
// fc_sdk::Error is 144 bytes due to external library constraints; boxing every call
// site would add noise without runtime benefit since these are never in hot paths.
#![allow(clippy::result_large_err)]
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
    BalloonSpec, CacheType, CpuTemplateSpec, DefaultVmConfig, DriveSpec, FirecrackerConfig,
    GrpcConfig, HugePagesSpec, IoEngine, JailerConfig, MemoryHotplugSpec, MmdsSpec,
    MmdsVersionSpec, NetworkConfig, RateLimitSpec, RestoreSpec, SnapshotRequest, SnapshotType,
    TokenBucketSpec, VmSpec, VmmConfig, VsockSpec,
};
pub use error::{Result, VmmError};
pub use instance::{VmId, VmInfo, VmInstance, VmMetrics, VmState, VmSummary};
pub use manager::VmmManager;
pub use network::{NetworkAllocation, NetworkManager};
pub use snapshot::{SnapshotCatalog, SnapshotInfo};
pub use store::VmStore;
