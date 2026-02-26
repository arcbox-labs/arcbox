//! # arcbox-container
//!
//! Container runtime for ArcBox.
//!
//! This crate provides shared container domain types and exec orchestration
//! primitives used by ArcBox services.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
// Documentation and style lints.
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::redundant_else)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::derive_partial_eq_without_eq)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::if_not_else)]
#![allow(clippy::single_match_else)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::needless_continue)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::unused_async)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::struct_excessive_bools)]
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
