# arcbox

High-performance container and VM runtime library.

## Overview

This crate provides a unified API for the ArcBox runtime, re-exporting functionality from the core crates. It serves as the main library entry point for users who want to use ArcBox programmatically.

## Architecture

ArcBox is organized into several layers:

- **Hypervisor**: Platform abstraction for virtualization (macOS/Linux)
- **VMM**: Virtual machine monitor managing VM lifecycle
- **VirtIO**: Virtual device implementations (block, net, fs, console)
- **Container**: OCI-compatible container runtime
- **Core**: High-level orchestration and management

## Features

- Unified API for container and VM management
- Cross-platform support (macOS primary, Linux secondary)
- Re-exports core functionality from individual crates
- Convenient prelude module for common imports

## Re-exported Modules

| Module | Source Crate | Description |
|--------|--------------|-------------|
| `hypervisor` | arcbox-hypervisor | Virtualization abstraction |
| `virtio` | arcbox-virtio | VirtIO device implementations |
| `protocol` | arcbox-protocol | Protobuf message types |

## Usage

```rust
use arcbox::prelude::*;

// Access hypervisor traits
// - Hypervisor: Platform entry point, creates VMs
// - VirtualMachine: VM lifecycle management
// - Vcpu: vCPU execution and register access
// - GuestMemory: Guest physical memory read/write

// Common types
// - GuestAddress: Physical address in guest memory
// - VcpuExit: Reason for vCPU exit
// - VmConfig: VM configuration
// - HypervisorError: Error type

// Get version
let version = arcbox::version();
```

## Cargo Features

| Feature | Description |
|---------|-------------|
| `default` | Core functionality only |
| `pro` | Pro layer features (BSL-1.1 licensed) |
| `full` | All features including pro |

## Related Crates

- `arcbox-cli`: Command-line interface
- `arcbox-docker`: Docker API compatibility layer
- `arcbox-core`: Daemon and orchestration

## License

MIT OR Apache-2.0
