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
pub mod generated;
pub mod grpc;
pub mod server;

// Re-export generated types for convenience.
pub use generated::{
    container_service_client, container_service_server,
    image_service_client, image_service_server,
    machine_service_client, machine_service_server,
    network_service_client, network_service_server,
    system_service_client, system_service_server,
};

pub use error::{ApiError, Result};
pub use grpc::{ContainerServiceImpl, ImageServiceImpl, MachineServiceImpl, NetworkServiceImpl, SystemServiceImpl};
pub use server::{ApiServer, ApiServerConfig};
