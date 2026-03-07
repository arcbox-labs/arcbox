//! # arcbox-api
//!
//! gRPC and REST service implementations for `ArcBox`.
//!
//! This crate hosts service implementations consumed by the `arcbox-daemon`
//! binary. It provides:
//! - Machine and sandbox gRPC services
//! - REST/HTTP+JSON API for external SDKs and the Swift desktop app
//!
//! On Linux the sandbox services call `arcbox-vm::SandboxManager` directly.
//! On macOS they proxy through the guest agent running inside the VM.

pub mod error;
pub mod grpc;
pub mod rest;

// Sandbox service: platform-split implementations.
#[cfg(target_os = "linux")]
mod sandbox_conv;
#[cfg(target_os = "linux")]
mod sandbox_linux;

// Re-export gRPC service types from arcbox-grpc for convenience.
pub use arcbox_grpc::v1::{machine_service_client, machine_service_server};
pub use arcbox_grpc::{
    SandboxService, SandboxServiceServer, SandboxSnapshotService, SandboxSnapshotServiceServer,
};

pub use error::{ApiError, Result};
pub use grpc::MachineServiceImpl;

// Re-export the platform-appropriate sandbox service implementations.
#[cfg(not(target_os = "linux"))]
pub use grpc::{SandboxServiceImpl, SandboxSnapshotServiceImpl};
#[cfg(target_os = "linux")]
pub use sandbox_linux::{SandboxServiceImpl, SandboxSnapshotServiceImpl};
