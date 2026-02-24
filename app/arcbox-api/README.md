# arcbox-api

API server for ArcBox.

## Overview

This crate provides the API server layer for ArcBox, offering multiple interfaces for client communication. It bridges external clients to the arcbox-core runtime, implementing service handlers for containers, machines, images, networks, and system operations.

## Features

- **gRPC API**: High-performance native API using tonic for ArcBox CLI and desktop client
- **Docker API**: Docker CLI compatibility via arcbox-docker integration
- **Service Implementations**:
  - ContainerService: Container lifecycle management
  - MachineService: VM management
  - ImageService: Image operations with streaming pull
  - NetworkService: Network management
  - SystemService: System info and health checks

## Usage

```rust
use arcbox_api::{ApiServer, ApiServerConfig};
use arcbox_core::Config;
use std::path::PathBuf;

let config = ApiServerConfig {
    grpc_addr: "[::1]:50051".to_string(),
    docker_socket: PathBuf::from("/var/run/arcbox-docker.sock"),
};

let server = ApiServer::new(config, Config::default())?;
server.run().await?;
```

## Architecture

```text
┌─────────────────────────────────────────────────┐
│                   arcbox-api                    │
│                                                 │
│  ┌─────────────┐         ┌─────────────────┐   │
│  │   gRPC      │         │   Docker API    │   │
│  │   Server    │         │  (arcbox-docker)│   │
│  └──────┬──────┘         └────────┬────────┘   │
│         │                         │            │
│         └────────────┬────────────┘            │
│                      ▼                         │
│              ┌─────────────┐                   │
│              │ arcbox-core │                   │
│              └─────────────┘                   │
└─────────────────────────────────────────────────┘
```

## License

MIT OR Apache-2.0
