//! # arcbox-core
//!
//! Core orchestration layer for ArcBox.
//!
//! This crate provides high-level management of:
//!
//! - [`VmManager`]: Virtual machine lifecycle
//! - [`MachineManager`]: Linux machine management
//! - [`ContainerManager`]: Container orchestration
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │                  arcbox-core                    │
//! │  ┌─────────────┐ ┌─────────────┐ ┌───────────┐│
//! │  │  VmManager  │ │MachineManager│ │Container  ││
//! │  │             │ │             │ │ Manager   ││
//! │  └──────┬──────┘ └──────┬──────┘ └─────┬─────┘│
//! │         │               │               │      │
//! │         └───────────────┼───────────────┘      │
//! │                         ▼                      │
//! │              ┌─────────────────┐              │
//! │              │    EventBus     │              │
//! │              └─────────────────┘              │
//! └─────────────────────────────────────────────────┘
//!                        │
//!           ┌────────────┼────────────┐
//!           ▼            ▼            ▼
//!      arcbox-vmm   arcbox-fs   arcbox-container
//! ```

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

pub mod agent_client;
pub mod boot_assets;
pub mod config;
pub mod error;
pub mod event;
pub mod machine;
pub mod persistence;
pub mod runtime;
pub mod vm;
pub mod vm_lifecycle;

pub use agent_client::{AgentClient, AgentClientWrapper, AgentPool};
pub use boot_assets::{BootAssetConfig, BootAssetProvider, BootAssets, DownloadProgress};
pub use config::Config;
pub use error::{CoreError, Result};
pub use machine::MachineManager;
pub use runtime::Runtime;
pub use vm::{SharedDirConfig, VmConfig, VmManager};
pub use vm_lifecycle::{
    DEFAULT_MACHINE_NAME, DefaultVmConfig, HealthMonitor, VmLifecycleConfig, VmLifecycleManager,
    VmLifecycleState,
};
