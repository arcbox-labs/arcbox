# arcbox-vz

Safe Rust bindings for Apple's Virtualization.framework.

## Overview

This crate provides ergonomic, async-first bindings to Apple's Virtualization.framework, allowing you to create and manage virtual machines on macOS.

## Features

- **Safe API**: Minimize unsafe code exposure with safe Rust abstractions
- **Async-first**: Native async/await support for all asynchronous operations
- **Complete Coverage**: Support all Virtualization.framework features (macOS 11+)

## Platform Support

This crate only supports macOS 11.0 (Big Sur) and later. Attempting to compile on other platforms will result in a compilation error.

## Entitlements

Your application must have the `com.apple.security.virtualization` entitlement to use this framework.

## Usage

```rust
use arcbox_vz::{
    VirtualMachineConfiguration, LinuxBootLoader, GenericPlatform,
    SocketDeviceConfiguration, VZError,
};

#[tokio::main]
async fn main() -> Result<(), VZError> {
    // Check if virtualization is supported
    if !arcbox_vz::is_supported() {
        return Err(VZError::NotSupported);
    }

    // Configure VM
    let mut config = VirtualMachineConfiguration::new()?;
    config
        .set_cpu_count(2)
        .set_memory_size(512 * 1024 * 1024);

    // Set boot loader
    let boot_loader = LinuxBootLoader::new("/path/to/kernel")?;
    config.set_boot_loader(boot_loader);

    // Build and start VM
    let vm = config.build()?;
    vm.start().await?;

    // Graceful shutdown
    vm.request_stop()?;

    Ok(())
}
```

### Device Configuration

```rust
use arcbox_vz::{SharedDirectory, SingleDirectoryShare, VirtioFileSystemDeviceConfiguration};

// VirtioFS directory share
let share = SharedDirectory::new("/host/path", false)?; // readonly=false
let dir_share = SingleDirectoryShare::new(share);
let fs_device = VirtioFileSystemDeviceConfiguration::new("myshare", dir_share);
config.set_directory_sharing_devices(vec![fs_device]);
```

## VM Lifecycle

| Method | Description |
|--------|-------------|
| `start()` | Async start, waits for Running state |
| `stop()` | Force stop (destructive) |
| `pause()` | Pause execution |
| `resume()` | Resume from paused state |
| `request_stop()` | Send graceful shutdown request to guest |
| `state()` | Query current VirtualMachineState |

## License

MIT OR Apache-2.0
