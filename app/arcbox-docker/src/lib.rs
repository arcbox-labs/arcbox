//! # arcbox-docker
//!
//! Docker REST API compatibility layer for `ArcBox`.
//!
//! This crate provides a Docker-compatible API server that allows existing
//! Docker CLI tools to work with `ArcBox` seamlessly.
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

pub mod api;
pub mod context;
pub mod error;
pub mod handlers;
pub mod proxy;
pub mod server;
pub mod trace;
// Docker API compatibility layer contains many spec fields only serialized/deserialized.
#[allow(dead_code)]
pub mod types;

pub use context::{ContextStatus, DockerContextManager};
pub use error::{DockerError, Result};
pub use server::{DockerApiServer, ServerConfig};
