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
#[cfg(target_os = "macos")]
pub mod bridge_discovery;
pub mod config;
pub mod container_backend;
pub mod error;
pub mod event;
pub mod machine;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod migration;
pub mod persistence;
#[cfg(target_os = "macos")]
pub mod route_reconciler;
pub mod runtime;
pub mod trace;
pub mod vm;
pub mod vm_lifecycle;

pub use agent_client::{AgentClient, ExecSessionInput, WriteFileChunk};
pub use arcbox_vmm::{DeviceDebug, QueueDebug, VmBackend};
pub use boot_assets::{
    BootAssetConfig, BootAssetManifest, BootAssetProvider, BootAssets, DownloadProgress,
    PreparePhase, boot_asset_version,
};
pub use config::{Config, ContainerRuntimeConfig};
pub use error::{CoreError, Result};
pub use machine::MachineManager;
#[cfg(target_os = "macos")]
pub use macos::{
    MacImage, MacImageManager, MacImageMeta, MacInstanceDisks, MacMachineConfig, MacMachineInfo,
    MacMachineManager, MacVm, PullPhase, PullSource,
};
pub use migration::MigrationManager;
pub use runtime::{Runtime, SandboxPortExposure};
pub use vm::{SharedDirConfig, VmConfig, VmManager};
pub use vm_lifecycle::{
    DEFAULT_MACHINE_NAME, DefaultVmConfig, HealthMonitor, VmLifecycleConfig, VmLifecycleManager,
    VmLifecycleState,
};
