# arcbox-container

Container domain types and exec orchestration primitives for ArcBox.

## Overview

This crate does not expose a monolithic container manager. Instead, it provides
shared data models and exec coordination utilities used by higher-level
services:

- `ContainerConfig` for container creation parameters
- `Container` / `ContainerState` for container identity and lifecycle state
- `ExecManager` and related exec types for `docker exec`-style workflows

## Features

- Container metadata and state models (`Container`, `ContainerId`, `ContainerState`)
- Container configuration model (`ContainerConfig`)
- Exec lifecycle model (`ExecInstance`, `ExecConfig`, `ExecId`)
- Optional agent-backed exec operations via `ExecAgentConnection`

## Usage

```rust
use arcbox_container::{Container, ContainerConfig, ContainerState};

let config = ContainerConfig {
    image: "alpine:latest".to_string(),
    cmd: vec!["sh".to_string()],
    ..Default::default()
};

let container = Container::with_config("demo", config);
assert_eq!(container.state, ContainerState::Created);
```

## License

MIT OR Apache-2.0
