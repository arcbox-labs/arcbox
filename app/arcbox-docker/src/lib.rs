//! # arcbox-docker
//!
//! Docker REST API compatibility layer for ArcBox.
//!
//! This crate provides a Docker-compatible API server that allows existing
//! Docker CLI tools to work with ArcBox seamlessly.
//!
//! ## Compatibility
//!
//! Implements Docker Engine API v1.43, supporting:
//!
//! - Container operations (create, start, stop, remove, logs, exec)
//! - Image operations (pull, push, list, remove)
//! - Volume operations
//! - Network operations (basic)
//!
//! ## Architecture
//!
//! ```text
//! docker CLI ──► Unix Socket ──► arcbox-docker ──► arcbox-core
//!                                     │
//!                                     ▼
//!                              HTTP REST API
//!                             (Axum server)
//! ```
//!
//! ## Usage
//!
//! The server listens on a Unix socket that can be configured as the
//! Docker context, allowing transparent use of Docker CLI:
//!
//! ```bash
//! docker context create arcbox --docker "host=unix:///home/you/.arcbox/docker.sock"
//! docker context use arcbox
//! docker ps  # Now uses ArcBox!
//! ```

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
// Docker API compatibility layer has many fields matching Docker spec.
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(clippy::nursery)]

pub mod api;
pub mod context;
pub mod error;
pub mod handlers;
pub mod server;
pub mod trace;
pub mod types;

pub use context::{ContextStatus, DockerContextManager};
pub use error::{DockerError, Result};
pub use server::{DockerApiServer, ServerConfig};

/// Docker API version.
pub const API_VERSION: &str = "1.43";

/// Minimum supported API version.
pub const MIN_API_VERSION: &str = "1.24";
