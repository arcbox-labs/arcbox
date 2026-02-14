# arcbox-protocol

Protocol definitions for ArcBox communication using Protocol Buffers.

## Overview

This crate defines the message types and service interfaces used for communication between:

- CLI <-> Daemon (ttrpc over Unix socket)
- Host <-> Guest (ttrpc over vsock)
- Docker CLI <-> Daemon (REST API, handled by arcbox-docker)

Message types are generated at build time from `.proto` files using prost.

## Features

- Protocol Buffer message definitions for all ArcBox services
- Efficient binary serialization for high-performance IPC
- Type-safe Rust structs generated from `.proto` files

## Modules

| Module | Description |
|--------|-------------|
| `common` | Shared types (Timestamp, Mount, PortBinding, etc.) |
| `container` | Container lifecycle operations |
| `image` | Image management |
| `machine` | Virtual machine management |
| `agent` | Guest agent operations |

## Usage

```rust
use arcbox_protocol::{
    CreateContainerRequest, ContainerConfig,
    PullImageRequest, ListMachinesRequest,
};

// Create a container request
let request = CreateContainerRequest {
    id: "my-container".to_string(),
    config: Some(ContainerConfig {
        image: "alpine:latest".to_string(),
        cmd: vec!["echo".to_string(), "hello".to_string()],
        ..Default::default()
    }),
    ..Default::default()
};

// Image pull request
let pull_request = PullImageRequest {
    reference: "nginx:latest".to_string(),
    ..Default::default()
};
```

## License

MIT OR Apache-2.0
