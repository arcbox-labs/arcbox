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
// API layer is under development.
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(clippy::nursery)]

pub mod error;
pub mod grpc;
pub mod server;

// Re-export gRPC service types from arcbox-grpc for convenience.
pub use arcbox_grpc::v1::{machine_service_client, machine_service_server};

pub use error::{ApiError, Result};
pub use grpc::MachineServiceImpl;
pub use server::{ApiServer, ApiServerConfig};
