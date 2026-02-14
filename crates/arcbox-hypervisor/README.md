# arcbox-hypervisor

Cross-platform hypervisor abstraction layer for ArcBox.

## Overview

This crate provides platform-agnostic traits for virtualization, allowing the same VM management code to work across different operating systems. It abstracts away the differences between macOS Virtualization.framework and Linux KVM.

## Features

- **Cross-platform abstraction**: Unified API for VM creation and management
- **macOS support**: Native Virtualization.framework backend (Apple Silicon and Intel)
- **Linux support**: KVM backend for x86_64 and ARM64
- **Type-safe configuration**: Builder pattern for VM configuration
- **Memory management**: Guest physical address space abstraction

## Core Traits

- `Hypervisor` - Main entry point for creating VMs
- `VirtualMachine` - VM lifecycle management (start, stop, memory mapping)
- `Vcpu` - Virtual CPU execution and register access
- `GuestMemory` - Guest physical memory read/write operations

## Usage

```rust
use arcbox_hypervisor::{create_hypervisor, VmConfig};

// Create platform-appropriate hypervisor
let hypervisor = create_hypervisor()?;

// Configure VM
let config = VmConfig::builder()
    .vcpu_count(4)
    .memory_size(4 * 1024 * 1024 * 1024) // 4GB
    .build();

// Create and start VM
let vm = hypervisor.create_vm(config)?;
```

## Platform Backends

| Platform | Backend | Status |
|----------|---------|--------|
| macOS (Apple Silicon) | Virtualization.framework | Primary |
| macOS (Intel) | Virtualization.framework | Supported |
| Linux (x86_64) | KVM | Supported |
| Linux (ARM64) | KVM | Supported |

## License

MIT OR Apache-2.0
