//! gRPC service clients and servers for ArcBox.
//!
//! This crate provides tonic-generated gRPC client and server implementations
//! for all ArcBox services. Message types are imported from `arcbox-protocol`.
//!
//! # Services
//!
//! - `MachineService` - Virtual machine management
//! - `AgentService` - Guest agent communication
//! - `VolumeService` - Volume management (from api.proto)
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

/// All gRPC services from the unified arcbox.v1 package.
///
/// This module contains tonic-generated client and server code for:
/// - MachineService - VM management
/// - AgentService - Guest agent communication
/// - VolumeService - Volume management
pub mod v1 {
    tonic::include_proto!("arcbox.v1");
}

// =============================================================================
// Client re-exports
// =============================================================================

pub use v1::agent_service_client::AgentServiceClient;
pub use v1::machine_service_client::MachineServiceClient;
pub use v1::volume_service_client::VolumeServiceClient;

// =============================================================================
// Server re-exports
// =============================================================================

pub use v1::agent_service_server::{AgentService, AgentServiceServer};
pub use v1::machine_service_server::{MachineService, MachineServiceServer};
pub use v1::volume_service_server::{VolumeService, VolumeServiceServer};
