//! # arcbox-api
//!
//! gRPC service implementations for `ArcBox`.
//!
//! This crate hosts service implementations consumed by the `arcbox-daemon`
//! binary. It provides machine and sandbox gRPC services.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

pub mod error;
pub mod grpc;

// Re-export gRPC service types from arcbox-grpc for convenience.
pub use arcbox_grpc::v1::{machine_service_client, machine_service_server};
pub use arcbox_grpc::{
    SandboxService, SandboxServiceServer, SandboxSnapshotService, SandboxSnapshotServiceServer,
};

pub use error::{ApiError, Result};
pub use grpc::{MachineServiceImpl, SandboxServiceImpl, SandboxSnapshotServiceImpl};
