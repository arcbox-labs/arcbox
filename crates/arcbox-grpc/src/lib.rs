//! gRPC service clients and servers for ArcBox.
//!
//! This crate provides tonic-generated gRPC client and server implementations
//! for all ArcBox services. Message types are imported from `arcbox-protocol`.
//!
//! # Services
//!
//! - `MachineService` - Virtual machine management
//! - `ContainerService` - Container lifecycle management
//! - `ImageService` - Container image management
//! - `AgentService` - Guest agent communication
//!
//! # Usage
//!
//! ```ignore
//! use arcbox_grpc::MachineServiceClient;
//! use arcbox_protocol::machine::ListMachinesRequest;
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

/// Machine service (VM management)
pub mod machine {
    tonic::include_proto!("arcbox.machine");
}

/// Container service (container lifecycle)
pub mod container {
    tonic::include_proto!("arcbox.container");
}

/// Image service (container images)
pub mod image {
    tonic::include_proto!("arcbox.image");
}

/// Agent service (guest agent)
pub mod agent {
    tonic::include_proto!("arcbox.agent");
}

// Convenience re-exports for clients
pub use machine::machine_service_client::MachineServiceClient;
pub use container::container_service_client::ContainerServiceClient;
pub use image::image_service_client::ImageServiceClient;
pub use agent::agent_service_client::AgentServiceClient;

// Convenience re-exports for servers
pub use machine::machine_service_server::{MachineService, MachineServiceServer};
pub use container::container_service_server::{ContainerService, ContainerServiceServer};
pub use image::image_service_server::{ImageService, ImageServiceServer};
pub use agent::agent_service_server::{AgentService, AgentServiceServer};
