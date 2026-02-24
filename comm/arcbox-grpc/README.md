# arcbox-grpc

gRPC service clients and servers for ArcBox.

## Overview

This crate provides tonic-generated gRPC client and server implementations for all ArcBox services. Message types are imported from `arcbox-protocol`.

## Services

| Service | Purpose | Key RPCs |
|---------|---------|----------|
| `MachineService` | VM management | Create, Start, Stop, List, Exec |
| `ContainerService` | Container lifecycle | Create, Start, Stop, List, Logs |
| `ImageService` | Image management | Pull, List, Remove, Import |
| `AgentService` | Guest agent communication | Exec, FileOps, Health |

## Features

- Tonic-based gRPC client and server implementations
- Async/await support with tokio
- Unix socket connectivity for daemon communication
- Re-exports `tonic` and `arcbox_protocol` for convenience

## Usage

### Client

```rust
use arcbox_grpc::MachineServiceClient;
use arcbox_protocol::machine::ListMachinesRequest;
use tonic::transport::Channel;

// Connect to daemon via Unix socket
let channel = tonic::transport::Endpoint::from_static("http://[::]:50051")
    .connect_with_connector(tower::service_fn(|_| async {
        tokio::net::UnixStream::connect("/var/run/arcbox.sock").await
    }))
    .await?;

let mut client = MachineServiceClient::new(channel);

// Make RPC calls
let request = tonic::Request::new(ListMachinesRequest { all: true });
let response = client.list(request).await?;
```

### Server

```rust
use arcbox_grpc::{MachineService, MachineServiceServer};
use tonic::{Request, Response, Status};

struct MyMachineService;

#[tonic::async_trait]
impl MachineService for MyMachineService {
    async fn list(
        &self,
        request: Request<ListMachinesRequest>,
    ) -> Result<Response<ListMachinesResponse>, Status> {
        // Implementation
    }
}

let server = MachineServiceServer::new(MyMachineService);
```

## Exported Types

- **Clients**: `MachineServiceClient`, `ContainerServiceClient`, `ImageServiceClient`, `AgentServiceClient`
- **Servers**: `MachineService` (trait), `MachineServiceServer`, `ContainerService`, `ContainerServiceServer`, etc.

## License

MIT OR Apache-2.0
