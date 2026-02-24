# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox crate.

## Overview

`arcbox` is the main library crate that provides a unified API for the ArcBox runtime. It re-exports functionality from core crates, offering a single entry point for users who want to use ArcBox as a library.

## Architecture

```
arcbox/
├── src/
│   └── lib.rs          # Re-exports and prelude module
└── Cargo.toml          # Dependencies on core crates
```

### Re-exported Crates

| Module | Source Crate | Description |
|--------|--------------|-------------|
| `hypervisor` | arcbox-hypervisor | Virtualization abstraction (macOS/Linux) |
| `virtio` | arcbox-virtio | VirtIO device implementations |
| `image` | arcbox-image | Container image management |
| `protocol` | arcbox-protocol | Protobuf message types |

**Planned** (currently commented out):
- `vmm` - Virtual machine monitor
- `container` - Container management
- `fs` - Filesystem (VirtioFS)
- `net` - Network stack
- `core` - High-level orchestration

## Key Types

```rust
use arcbox::prelude::*;

// Hypervisor traits
// - Hypervisor: Platform entry point, creates VMs
// - VirtualMachine: VM lifecycle management
// - Vcpu: vCPU execution and register access
// - GuestMemory: Guest physical memory read/write

// Common types
// - GuestAddress: Physical address in guest memory
// - VcpuExit: Reason for vCPU exit
// - VmConfig: VM configuration
// - HypervisorError: Error type

// Version info
let version = arcbox::version();  // Returns crate version
```

### Prelude Module

The `prelude` module provides convenient imports for common use cases:

```rust
use arcbox::prelude::*;

// Now you have access to:
// - Hypervisor, VirtualMachine, Vcpu, GuestMemory (traits)
// - GuestAddress, HypervisorError, VcpuExit, VmConfig (types)
```

## Common Commands

```bash
# Build
cargo build -p arcbox

# Test
cargo test -p arcbox

# Build with Pro features
cargo build -p arcbox --features pro

# Build with all features
cargo build -p arcbox --features full
```

## Features

| Feature | Description |
|---------|-------------|
| `default` | Core functionality only |
| `pro` | Pro layer features (BSL-1.1 licensed) |
| `full` | All features including pro |

## Notes

- This crate serves as a facade/umbrella crate for the ArcBox ecosystem
- For CLI usage, see `arcbox-cli` crate
- For Docker API compatibility, see `arcbox-docker` crate
- The crate is designed for library consumers; daemon functionality lives in other crates
