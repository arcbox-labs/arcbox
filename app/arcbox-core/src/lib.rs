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
pub mod sandbox_capability;
pub mod stats_hub;
pub mod trace;
pub mod vm;
pub mod vm_lifecycle;

// Image management moved to the engine layer (arcbox-image); the module
// paths and crate-root items below are compatibility re-exports.
pub use arcbox_image::{boot_assets, machine_image, remote_image};

pub use agent_client::{AgentClient, ExecSessionInput, WriteFileChunk};
pub use arcbox_image::boot_assets::{
    BootAssetConfig, BootAssetManifest, BootAssetProvider, BootAssets, DownloadProgress,
    PreparePhase, boot_asset_version,
};
pub use arcbox_vmm::{DeviceDebug, QueueDebug, VmBackend};
pub use config::{Config, ContainerRuntimeConfig};
pub use error::{CoreError, Result};
pub use machine::MachineManager;
#[cfg(target_os = "macos")]
pub use macos::{
    ImageReference, MacImage, MacImageManager, MacImageMeta, MacInstanceDisks, MacMachineConfig,
    MacMachineInfo, MacMachineManager, MacVm, PullStage, RemoteLocation, RemoteSource,
    ResolvedImage,
};
#[cfg(feature = "macos-ipsw-install")]
pub use macos::{PullPhase, PullSource};
pub use migration::MigrationManager;
pub use runtime::{
    InitProgress, Runtime, SandboxPortExposure, SandboxPortMapping, SandboxPortProtocol,
};
pub use sandbox_capability::NestedVirtCapability;
pub use vm::{SharedDirConfig, VmConfig, VmManager};
pub use vm_lifecycle::{
    ActivityScope, DEFAULT_MACHINE_NAME, DefaultVmConfig, HealthMonitor, VmLifecycleConfig,
    VmLifecycleManager, VmLifecycleState,
};
