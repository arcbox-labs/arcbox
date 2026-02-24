# arcbox-core

Core orchestration layer for ArcBox.

## Overview

This crate provides the central orchestration layer that manages all high-level operations in ArcBox. It coordinates virtual machines, Linux machines, containers, images, and volumes through a unified `Runtime` struct.

## Features

- **VmManager**: Virtual machine lifecycle management
- **MachineManager**: Named Linux machine management
- **VmLifecycleManager**: Automatic VM start/stop based on container activity
- **AgentClient**: Guest agent RPC communication via vsock
- **BootAssetProvider**: Kernel and initramfs management
- **EventBus**: System-wide event coordination

## Usage

```rust
use arcbox_core::{Runtime, Config, VmConfig};

// Create runtime with default configuration
let config = Config::default();
let runtime = Runtime::new(config).await?;

// Create and start a container (auto-starts VM if needed)
let container = runtime.create_container(container_config).await?;
runtime.start_container(&container.id).await?;
```

## Architecture

```text
┌─────────────────────────────────────────────────┐
│                  arcbox-core                    │
│  ┌─────────────┐ ┌─────────────┐ ┌───────────┐ │
│  │  VmManager  │ │MachineManager│ │Container  │ │
│  │             │ │             │ │ Manager   │ │
│  └──────┬──────┘ └──────┬──────┘ └─────┬─────┘ │
│         │               │               │       │
│         └───────────────┼───────────────┘       │
│                         ▼                       │
│              ┌─────────────────┐               │
│              │    EventBus     │               │
│              └─────────────────┘               │
└─────────────────────────────────────────────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
     arcbox-vmm   arcbox-fs   arcbox-container
```

## License

MIT OR Apache-2.0
