# arcbox-grpc

gRPC client/server bindings for ArcBox services.

## Overview

This crate contains tonic-generated service modules for the `arcbox.v1` package,
with protobuf messages sourced from `arcbox-protocol`.

All generated services are available under `arcbox_grpc::v1::*`.

## Crate-Root Re-exports

For convenience, crate root currently re-exports:

- Clients: `MachineServiceClient`, `AgentServiceClient`, `VolumeServiceClient`
- Servers: `MachineService`, `MachineServiceServer`, `AgentService`,
  `AgentServiceServer`, `VolumeService`, `VolumeServiceServer`

Other generated clients/servers (for example container/image/network/system)
are available via `arcbox_grpc::v1::<service_module>::...`.

## Usage

```rust
use arcbox_grpc::MachineServiceClient;
use arcbox_protocol::v1::ListMachinesRequest;

let request = tonic::Request::new(ListMachinesRequest { all: true });
// client.list(request).await?;
# let _ = request;
```

## License

MIT OR Apache-2.0
