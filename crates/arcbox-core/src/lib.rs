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
pub mod config;
pub mod error;
pub mod event;
pub mod machine;
pub mod persistence;
pub mod runtime;
pub mod vm;

pub use agent_client::{AgentClient, AgentPool};
pub use config::Config;
pub use error::{CoreError, Result};
pub use machine::MachineManager;
pub use runtime::Runtime;
pub use vm::{SharedDirConfig, VmConfig, VmManager};
