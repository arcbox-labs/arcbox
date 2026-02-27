# arcbox-protocol

Protocol Buffer message and service definitions for ArcBox.

## Overview

This crate provides generated Rust types for `arcbox.v1` protobuf schemas,
re-exported through:

- `arcbox_protocol::v1::*` (canonical)
- compatibility modules (`arcbox_protocol::machine`, `::container`, `::agent`, etc.)
- selected crate-root re-exports for convenience

## Modules

| Module | Source proto | Description |
|--------|--------------|-------------|
| `common` | `common.proto` | Shared types (`Empty`, `Mount`, `PortBinding`, ...) |
| `machine` | `machine.proto` | Machine lifecycle + agent passthrough requests |
| `container` | `container.proto` | Container lifecycle and exec messages |
| `image` | `image.proto` | Image pull/list/inspect/remove messages |
| `agent` | `agent.proto` | Guest agent health/runtime messages |
| `api` | `api.proto` | Network/system/volume API messages |

## Usage

```rust
use arcbox_protocol::{CreateContainerRequest, PullImageRequest};

let create = CreateContainerRequest {
    name: "demo".to_string(),
    image: "alpine:latest".to_string(),
    cmd: vec!["echo".to_string(), "hello".to_string()],
    tty: false,
    stdin_open: false,
    ..Default::default()
};

let pull = PullImageRequest {
    reference: "nginx:latest".to_string(),
    ..Default::default()
};

assert_eq!(create.image, "alpine:latest");
assert_eq!(pull.reference, "nginx:latest");
```

## License

MIT OR Apache-2.0
