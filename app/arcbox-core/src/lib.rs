//! # arcbox-core
//!
//! Core orchestration layer for `ArcBox`.
//!
//! This crate provides high-level management of:
//!
//! - [`VmManager`]: Virtual machine lifecycle
//! - [`MachineManager`]: Linux machine management
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │                  arcbox-core                    │
//! │  ┌─────────────┐ ┌─────────────┐              │
//! │  │  VmManager  │ │MachineManager│              │
//! │  │             │ │             │              │
//! │  └──────┬──────┘ └──────┬──────┘              │
//! │         │               │                      │
//! │         └───────────────┘                      │
//! │                         ▼                      │
//! │              ┌─────────────────┐              │
//! │              │    EventBus     │              │
//! │              └─────────────────┘              │
//! └─────────────────────────────────────────────────┘
//!                        │
//!           ┌────────────┼────────────┐
//!           ▼            ▼
//!      arcbox-vmm   arcbox-fs
//! ```
pub mod agent_client;
pub mod boot_assets;
pub mod config;
pub mod container_backend;
pub mod error;
pub mod event;
pub mod machine;
pub mod persistence;
pub mod runtime;
pub mod trace;
pub mod vm;
pub mod vm_lifecycle;

pub use agent_client::AgentClient;
pub use boot_assets::{
    BootAssetConfig, BootAssetManifest, BootAssetProvider, BootAssets, DownloadProgress,
    PreparePhase, boot_asset_version,
};
pub use config::{Config, ContainerRuntimeConfig};
pub use error::{CoreError, Result};
pub use machine::MachineManager;
pub use runtime::Runtime;
pub use vm::{SharedDirConfig, VmConfig, VmManager};
pub use vm_lifecycle::{
    DEFAULT_MACHINE_NAME, DefaultVmConfig, HealthMonitor, VmLifecycleConfig, VmLifecycleManager,
    VmLifecycleState,
};
