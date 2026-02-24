# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox-protocol crate.

## Overview

Protobuf definitions for host-guest communication via ttrpc. Defines the RPC interface between arcbox-core (host) and arcbox-agent (guest).

## Architecture

```
arcbox-protocol/
├── src/lib.rs          # Re-exports generated code
├── proto/
│   ├── agent.proto     # Agent service definition
│   ├── container.proto # Container messages
│   ├── image.proto     # Image messages
│   ├── machine.proto   # Machine messages
│   └── common.proto    # Shared types
└── build.rs            # prost code generation
```

## Generated Modules

```rust
pub mod agent;      // AgentService trait, request/response types
pub mod container;  // ContainerConfig, ContainerState, etc.
pub mod image;      // ImageInfo, LayerInfo
pub mod machine;    // MachineInfo, MachineState
pub mod common;     // Timestamp, PortBinding, etc.
```

## Agent Service (proto/agent.proto)

```protobuf
service Agent {
    // Container operations
    rpc CreateContainer(CreateContainerRequest) returns (CreateContainerResponse);
    rpc StartContainer(StartContainerRequest) returns (StartContainerResponse);
    rpc StopContainer(StopContainerRequest) returns (StopContainerResponse);
    rpc KillContainer(KillContainerRequest) returns (KillContainerResponse);

    // Exec operations
    rpc ExecStart(ExecStartRequest) returns (stream ExecOutput);
    rpc ExecResize(ExecResizeRequest) returns (ExecResizeResponse);

    // Streaming
    rpc ContainerLogs(ContainerLogsRequest) returns (stream LogEntry);
    rpc ContainerAttach(stream AttachInput) returns (stream AttachOutput);
}
```

## Usage

```rust
use arcbox_protocol::agent::{CreateContainerRequest, CreateContainerResponse};
use arcbox_protocol::container::ContainerConfig;

let request = CreateContainerRequest {
    id: "abc123".to_string(),
    config: Some(ContainerConfig { ... }),
};
```

## Code Generation

Build.rs uses prost-build:
```rust
prost_build::Config::new()
    .out_dir("src/")
    .compile_protos(&["proto/agent.proto", ...], &["proto/"])?;
```

## Common Commands

```bash
cargo build -p arcbox-protocol  # Regenerates if .proto changed
cargo test -p arcbox-protocol
```
