# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox-vz crate.

## Overview

`arcbox-vz` provides safe, async-first Rust bindings to Apple's Virtualization.framework. It abstracts low-level Objective-C FFI into ergonomic Rust APIs for creating and managing virtual machines on macOS.

## Architecture

```
arcbox-vz/
├── src/
│   ├── lib.rs              # Public API re-exports, system queries
│   ├── error.rs            # VZError type definitions
│   ├── vm.rs               # VirtualMachine runtime control
│   ├── socket.rs           # VirtioSocketDevice, vsock communication
│   ├── delegate.rs         # VM delegate callbacks (internal)
│   ├── configuration/
│   │   ├── mod.rs          # Module re-exports
│   │   ├── vm_config.rs    # VirtualMachineConfiguration builder
│   │   ├── boot_loader.rs  # LinuxBootLoader
│   │   └── platform.rs     # GenericPlatform
│   ├── device/
│   │   ├── mod.rs          # Device re-exports
│   │   ├── storage.rs      # Block devices
│   │   ├── network.rs      # Network devices
│   │   ├── filesystem.rs   # VirtioFS directory shares
│   │   ├── serial.rs       # Serial port
│   │   ├── socket.rs       # Virtio socket device config
│   │   └── entropy.rs      # Entropy device
│   └── ffi/
│       ├── mod.rs          # FFI module, framework loading
│       ├── runtime.rs      # objc_msgSend wrappers
│       ├── foundation.rs   # NSString, NSArray helpers
│       ├── dispatch.rs     # DispatchQueue wrapper
│       └── block.rs        # Objective-C block ABI
└── examples/
    └── simple_vm.rs        # Basic VM example
```

### Layered Design

1. **ffi/**: Raw Objective-C bindings, msg_send macros, memory management
2. **configuration/**: VM configuration builders (CPU, memory, boot loader, devices)
3. **device/**: Individual device configurations (storage, network, filesystem)
4. **vm.rs + socket.rs**: Runtime VM control and vsock communication

## Key Types

```rust
use arcbox_vz::{
    VirtualMachineConfiguration, LinuxBootLoader, GenericPlatform,
    VirtualMachine, VirtualMachineState, VZError,
};

// Configure a VM
let mut config = VirtualMachineConfiguration::new()?;
config
    .set_cpu_count(2)
    .set_memory_size(512 * 1024 * 1024);

// Set boot loader
let boot_loader = LinuxBootLoader::new("/path/to/vmlinux")?;
config.set_boot_loader(boot_loader);

// Build and run
let vm = config.build()?;
vm.start().await?;

// Check state
match vm.state() {
    VirtualMachineState::Running => { /* ... */ }
    VirtualMachineState::Stopped => { /* ... */ }
    _ => {}
}

// Graceful shutdown
vm.request_stop()?;
```

### VirtualMachine Lifecycle

| Method | Description |
|--------|-------------|
| `start()` | Async start, waits for Running state |
| `stop()` | Force stop (destructive) |
| `pause()` | Pause execution |
| `resume()` | Resume from paused state |
| `request_stop()` | Send graceful shutdown request to guest |
| `state()` | Query current VirtualMachineState |

### Device Configuration

```rust
// VirtioFS directory share
use arcbox_vz::{SharedDirectory, SingleDirectoryShare, VirtioFileSystemDeviceConfiguration};

let share = SharedDirectory::new("/host/path", false)?; // readonly=false
let dir_share = SingleDirectoryShare::new(share);
let fs_device = VirtioFileSystemDeviceConfiguration::new("myshare", dir_share);
config.set_directory_sharing_devices(vec![fs_device]);
```

## Common Commands

```bash
# Build (macOS only)
cargo build -p arcbox-vz

# Test (requires entitlements for VM tests)
cargo test -p arcbox-vz

# Run example (requires signing)
cargo build --example simple_vm -p arcbox-vz
codesign --entitlements tests/resources/entitlements.plist --force -s - target/debug/examples/simple_vm
./target/debug/examples/simple_vm
```

## Notes

- **macOS only**: Compilation fails on other platforms (`#![cfg(target_os = "macos")]`)
- **Requires entitlements**: Applications must have `com.apple.security.virtualization` entitlement
- **macOS 11+ required**: Virtualization.framework was introduced in Big Sur
- **Async-first**: All long-running operations use async/await with tokio
- **Thread safety**: `VirtualMachine` is `Send + Sync` via dispatch queue synchronization
- **Memory management**: Uses ARC-style retain/release via `msg_send!` macros
