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
| `api` | `api.proto` | Network/system/volume/migration API messages |

## Generated code

`build.rs` writes prost output into `src/generated/` (not `OUT_DIR`) and
runs rustfmt on it; the result is committed. After any `.proto` edit,
rebuild (`cargo build -p arcbox-protocol`) and commit the regenerated
files in the same change. A new `.proto` file must be registered in both
`arcbox-protocol/build.rs` and `arcbox-grpc/build.rs`.

## Protocol evolution

The daemon and the in-VM `arcbox-agent` are distributed separately, so a
running guest may speak an older schema than the host. Two mechanisms keep
skew safe:

- **Additive-only schemas.** CI runs `buf breaking` against `master`
  (`.github/workflows/ci.yml`): never remove or renumber fields; use
  `reserved` when retiring them.
- **Boot handshake.** The agent reports
  `AgentPingResponse.protocol_version`
  (`arcbox_constants::wire::AGENT_PROTOCOL_VERSION`); the host rejects
  agents below `MIN_AGENT_PROTOCOL_VERSION` before watching readiness.
  Bump the protocol version when a change alters the *meaning* of
  existing messages; purely additive, ignorable fields don't need one.

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
