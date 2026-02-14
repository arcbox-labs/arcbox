# arcbox-container

Container runtime for ArcBox.

## Overview

This crate provides Docker/OCI-compatible container state management. It handles container lifecycle, configuration, exec instances, and volume management. Containers run inside the ArcBox VM with a Linux kernel, and this crate communicates with the arcbox-agent inside the VM to manage container processes.

## Features

- **Container Lifecycle**: Create, start, stop, pause, unpause, and remove containers
- **ContainerManager**: Centralized container state management
- **ExecManager**: Manage `docker exec` instances
- **VolumeManager**: Named volume creation and management
- **Resource Limits**: CPU and memory constraints
- **Environment and Networking**: Container configuration

## Usage

```rust
use arcbox_container::{ContainerManager, ContainerConfig, ContainerState};

// Create a container manager
let manager = ContainerManager::new(data_dir);

// Create a container
let config = ContainerConfig {
    image: "alpine:latest".to_string(),
    cmd: vec!["sh".to_string()],
    ..Default::default()
};
let container = manager.create(config)?;

// List containers
let containers = manager.list();
for c in containers {
    println!("{}: {:?}", c.name, c.state);
}
```

## Architecture

```text
┌─────────────────────────────────────────────┐
│               arcbox-container              │
│  ┌─────────────────────────────────────┐   │
│  │          ContainerManager           │   │
│  │  - Container lifecycle              │   │
│  │  - State management                 │   │
│  └─────────────────────────────────────┘   │
│                    │                        │
│                    ▼                        │
│  ┌─────────────────────────────────────┐   │
│  │           arcbox-agent              │   │
│  │         (inside guest VM)           │   │
│  └─────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

## License

MIT OR Apache-2.0
