//! # arcbox-container
//!
//! Container runtime for `ArcBox`.
//!
//! This crate provides shared container domain types and exec orchestration
//! primitives used by `ArcBox` services.

#![allow(clippy::needless_continue)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::struct_field_names)]

pub mod config;
pub mod error;
pub mod exec;
pub mod state;

pub use config::ContainerConfig;
pub use error::{ContainerError, Result};
pub use exec::{
    ExecAgentConnection, ExecConfig, ExecId, ExecInstance, ExecManager, ExecStartParams,
    ExecStartResult,
};
pub use state::{Container, ContainerId, ContainerState};
