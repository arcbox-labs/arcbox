# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox-api crate.

## Overview

`arcbox-api` is the API server layer for ArcBox, providing multiple interfaces for client communication:

- **gRPC API**: High-performance native API using tonic for the ArcBox CLI and desktop client
- **Docker API**: Docker CLI compatibility layer (via arcbox-docker crate)

The crate bridges external clients to the `arcbox-core` runtime, implementing service handlers for containers, machines, images, networks, and system operations.

## Architecture

```
crates/arcbox-api/src/
├── lib.rs              # Module exports and re-exports
├── error.rs            # ApiError and Result types
├── server.rs           # ApiServer and ApiServerConfig
├── grpc.rs             # gRPC service implementations
└── generated/          # prost-generated protobuf types
    ├── mod.rs
    └── arcbox.api.rs   # Generated service definitions
```

### Request Flow

```
Docker CLI ──HTTP/REST──► arcbox-docker ──────┐
                                              ├──► arcbox-core (Runtime)
arcbox CLI ──gRPC───────► arcbox-api ─────────┘
```

## Key Types

### ApiServer

Main server that runs both gRPC and Docker API simultaneously:

```rust
use arcbox_api::{ApiServer, ApiServerConfig};
use arcbox_core::Config;

let config = ApiServerConfig {
    grpc_addr: "[::1]:50051".to_string(),
    docker_socket: PathBuf::from("/var/run/arcbox-docker.sock"),
};

let server = ApiServer::new(config, Config::load()?)?;
server.run().await?;
```

### Service Implementations

Each service wraps `Arc<Runtime>` and implements tonic async traits:

```rust
// Container service example
pub struct ContainerServiceImpl {
    runtime: Arc<Runtime>,
}

#[tonic::async_trait]
impl container_service_server::ContainerService for ContainerServiceImpl {
    async fn create_container(&self, request: Request<CreateContainerRequest>)
        -> Result<Response<CreateContainerResponse>, Status>;
    async fn start_container(&self, request: Request<StartContainerRequest>)
        -> Result<Response<StartContainerResponse>, Status>;
    // ... other methods
}
```

### Available Services

| Service | Description |
|---------|-------------|
| `ContainerServiceImpl` | Container lifecycle (create, start, stop, exec, logs) |
| `MachineServiceImpl` | VM management (create, start, stop, shell) |
| `ImageServiceImpl` | Image operations (pull, list, remove, tag) |
| `NetworkServiceImpl` | Network management (create, remove, list) |
| `SystemServiceImpl` | System info, version, ping |

### Streaming Responses

Image pull and container logs use gRPC streaming:

```rust
type PullImageStream = Pin<Box<dyn Stream<Item = Result<PullProgress, Status>> + Send + 'static>>;

async fn pull_image(&self, request: Request<PullImageRequest>)
    -> Result<Response<Self::PullImageStream>, Status>;
```

## Common Commands

```bash
# Build
cargo build -p arcbox-api

# Test
cargo test -p arcbox-api

# Run with debug logging
RUST_LOG=arcbox_api=debug cargo run --bin arcbox -- daemon
```

## Dependencies

- `arcbox-core`: Runtime and manager access
- `arcbox-container`: Container types and state
- `arcbox-image`: Image pulling and registry client
- `arcbox-docker`: Docker API compatibility server
- `arcbox-protocol`: Agent communication types
- `tonic`: gRPC framework
- `prost`: Protocol buffer code generation
