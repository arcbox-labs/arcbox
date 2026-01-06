//! # arcbox-container
//!
//! Container runtime for ArcBox.
//!
//! This crate provides Docker/OCI-compatible container management:
//!
//! - Container lifecycle (create, start, stop, remove)
//! - Container configuration
//! - Resource limits (CPU, memory)
//! - Volume management
//! - Environment and networking
//!
//! ## Architecture
//!
//! Containers run inside the ArcBox VM with a Linux kernel. The container
//! runtime communicates with the arcbox-agent inside the VM to manage
//! container processes.
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │               arcbox-container               │
//! │  ┌─────────────────────────────────────┐   │
//! │  │          ContainerManager           │   │
//! │  │  - Container lifecycle              │   │
//! │  │  - State management                 │   │
//! │  └─────────────────────────────────────┘   │
//! │                    │                        │
//! │                    ▼                        │
//! │  ┌─────────────────────────────────────┐   │
//! │  │           arcbox-agent              │   │
//! │  │         (inside guest VM)           │   │
//! │  └─────────────────────────────────────┘   │
//! └─────────────────────────────────────────────┘
//! ```

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

pub mod config;
pub mod error;
pub mod exec;
pub mod manager;
pub mod state;
pub mod volume;

pub use config::ContainerConfig;
pub use error::{ContainerError, Result};
pub use exec::{ExecConfig, ExecId, ExecInstance, ExecManager};
pub use manager::ContainerManager;
pub use state::{Container, ContainerId, ContainerState};
pub use volume::{Volume, VolumeManager};
