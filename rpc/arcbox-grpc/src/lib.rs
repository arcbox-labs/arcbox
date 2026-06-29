//! gRPC service clients and servers for ArcBox.
//!
//! This crate provides tonic-generated gRPC client and server implementations
//! for all ArcBox services. Message types are imported from `arcbox-protocol`.
//!
//! # Services
//!
//! - `MachineService` - Linux virtual machine management
//! - `MacosService` - macOS guest VM + base image management (Apple Silicon)
//! - `AgentService` - Guest agent communication
//! - `MigrationService` - Host-side runtime migration planning and execution
//! - `VolumeService` - Volume management (from api.proto)
//! - `SandboxService` - Sandbox lifecycle (create / run / exec / stop / remove)
//! - `SandboxSnapshotService` - Sandbox checkpoint and restore
//!
//! # Usage
//!
//! ```ignore
//! use arcbox_grpc::MachineServiceClient;
//! use arcbox_protocol::v1::ListMachinesRequest;
//! use tonic::transport::Channel;
//!
//! // Connect to daemon via Unix socket
//! let channel = tonic::transport::Endpoint::from_static("http://[::]:50051")
//!     .connect_with_connector(tower::service_fn(|_| async {
//!         tokio::net::UnixStream::connect("/var/run/arcbox.sock").await
//!     }))
//!     .await?;
//!
//! let mut client = MachineServiceClient::new(channel);
//!
//! // Make RPC calls
//! let request = tonic::Request::new(ListMachinesRequest { all: true });
//! let response = client.list(request).await?;
//! ```

// Re-export dependencies for convenience
pub use arcbox_protocol;
pub use tonic;

/// Compiled file descriptor set of every ArcBox proto, for gRPC server
/// reflection (`tonic-reflection`). Covers `arcbox.v1` and `sandbox.v1`.
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/arcbox_descriptor.bin"));

/// All gRPC services from the unified arcbox.v1 package.
///
/// This module contains tonic-generated client and server code for:
/// - MachineService - VM management
/// - AgentService - Guest agent communication
/// - MigrationService - Host-side migration planning and execution
/// - VolumeService - Volume management
pub mod v1 {
    tonic::include_proto!("arcbox.v1");
}

/// gRPC services from the sandbox.v1 package.
///
/// This module contains tonic-generated client and server code for:
/// - SandboxService - Sandbox lifecycle (create / run / exec / stop / remove)
/// - SandboxSnapshotService - Checkpoint and restore
///
/// Message types are imported from `arcbox_protocol::sandbox_v1`.
pub mod sandbox_v1 {
    #![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
    tonic::include_proto!("sandbox.v1");
}

pub use sandbox_v1::sandbox_service_client::SandboxServiceClient;
pub use sandbox_v1::sandbox_snapshot_service_client::SandboxSnapshotServiceClient;
pub use v1::agent_service_client::AgentServiceClient;
pub use v1::icon_service_client::IconServiceClient;
pub use v1::machine_service_client::MachineServiceClient;
pub use v1::macos_service_client::MacosServiceClient;
pub use v1::migration_service_client::MigrationServiceClient;
pub use v1::system_service_client::SystemServiceClient;
pub use v1::volume_service_client::VolumeServiceClient;

pub use sandbox_v1::sandbox_service_server::{SandboxService, SandboxServiceServer};
pub use sandbox_v1::sandbox_snapshot_service_server::{
    SandboxSnapshotService, SandboxSnapshotServiceServer,
};
pub use v1::agent_service_server::{AgentService, AgentServiceServer};
pub use v1::icon_service_server::{IconService, IconServiceServer};
pub use v1::machine_service_server::{MachineService, MachineServiceServer};
pub use v1::macos_service_server::{MacosService, MacosServiceServer};
pub use v1::migration_service_server::{MigrationService, MigrationServiceServer};
pub use v1::system_service_server::{SystemService, SystemServiceServer};
pub use v1::volume_service_server::{VolumeService, VolumeServiceServer};
