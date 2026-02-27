# arcbox-api

API server layer for ArcBox.

## Overview

This crate wires two host-facing APIs to `arcbox-core` runtime state:

- gRPC server (`MachineService` implementation)
- Docker-compatible HTTP API server (via `arcbox-docker`)

Current gRPC implementation in this crate is machine-focused (`MachineServiceImpl`).
Other service definitions may exist in shared protocol crates but are not all
implemented here.

## Features

- `ApiServer` wrapper that initializes runtime and serves APIs
- gRPC `MachineService` with machine lifecycle + guest-agent pass-through calls
- Docker API integration through embedded `arcbox-docker` server

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

## License

MIT OR Apache-2.0
