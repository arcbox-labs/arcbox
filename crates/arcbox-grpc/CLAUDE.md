# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox-grpc crate.

## Overview

`arcbox-grpc` provides tonic-generated gRPC client and server implementations for all ArcBox services. It defines the RPC interfaces for host-side communication, while message types are imported from `arcbox-protocol`.

## Architecture

```
arcbox-grpc/
├── src/lib.rs          # Re-exports clients/servers, includes tonic proto modules
└── build.rs            # tonic-build configuration for proto compilation
                        # (uses proto files from arcbox-protocol)
```

Proto files are sourced from `../arcbox-protocol/proto/`:
- `common.proto` - Shared types (Empty, Timestamp)
- `machine.proto` - VM management service
- `container.proto` - Container lifecycle service
- `image.proto` - Image management service
- `agent.proto` - Guest agent service
- `api.proto` - Network, System, Volume services

### Service Definitions

| Service | Purpose | Key RPCs |
|---------|---------|----------|
| `MachineService` | VM management | Create, Start, Stop, List, Exec |
| `ContainerService` | Container lifecycle | Create, Start, Stop, List, Logs |
| `ImageService` | Image management | Pull, List, Remove, Import |
| `AgentService` | Guest agent communication | Exec, FileOps, Health |

### Relationship with arcbox-protocol

- `arcbox-protocol`: Generates message types using `prost` from the unified `arcbox.v1` package
- `arcbox-grpc`: Generates service clients/servers using `tonic-build`
- The `extern_path` directive in build.rs maps `.arcbox.v1` to `::arcbox_protocol::v1` types
- Both crates share the same proto files located in `arcbox-protocol/proto/`

## Key Types

```rust
// Client usage
use arcbox_grpc::MachineServiceClient;
use arcbox_protocol::v1::ListMachinesRequest;
use tonic::transport::Channel;

let channel = /* connect to Unix socket */;
let mut client = MachineServiceClient::new(channel);
let response = client.list(tonic::Request::new(ListMachinesRequest { all: true })).await?;

// Server implementation
use arcbox_grpc::{MachineService, MachineServiceServer};

struct MyMachineService;
#[tonic::async_trait]
impl MachineService for MyMachineService {
    async fn list(&self, request: Request<ListMachinesRequest>) -> Result<Response<ListMachinesResponse>, Status> {
        // ...
    }
}

let server = MachineServiceServer::new(MyMachineService);
```

### Exported Types

- **Clients**: `MachineServiceClient`, `ContainerServiceClient`, `ImageServiceClient`, `AgentServiceClient`
- **Servers**: `MachineService` (trait), `MachineServiceServer`, etc.

## Common Commands

```bash
# Build (runs proto compilation)
cargo build -p arcbox-grpc

# Test
cargo test -p arcbox-grpc

# Regenerate protos after changes
cargo clean -p arcbox-grpc && cargo build -p arcbox-grpc
```

## Notes

- Proto files use the unified `package arcbox.v1` namespace
- Service methods follow REST-like naming (Create, List, Get, Update, Delete)
- Streaming RPCs are used for long-running operations (Exec, Logs)
- The crate re-exports `tonic` and `arcbox_protocol` for convenience
