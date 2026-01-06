//! # arcbox-api
//!
//! API server for ArcBox.
//!
//! Provides multiple API interfaces:
//!
//! - **gRPC API**: High-performance native API (tonic)
//! - **Docker API**: Docker CLI compatibility (arcbox-docker)
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │                   arcbox-api                    │
//! │                                                 │
//! │  ┌─────────────┐         ┌─────────────────┐  │
//! │  │   gRPC      │         │   Docker API    │  │
//! │  │   Server    │         │   (arcbox-docker)│  │
//! │  └──────┬──────┘         └────────┬────────┘  │
//! │         │                         │           │
//! │         └────────────┬────────────┘           │
//! │                      ▼                        │
//! │              ┌─────────────┐                  │
//! │              │ arcbox-core │                  │
//! │              └─────────────┘                  │
//! └─────────────────────────────────────────────────┘
//! ```

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

pub mod error;
pub mod grpc;
pub mod server;

pub use error::{ApiError, Result};
pub use server::{ApiServer, ApiServerConfig};
