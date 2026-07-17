# arcbox-vz

Safe Rust bindings for Apple's Virtualization.framework, implemented on a
bundled Swift shim.

## Overview

This crate provides ergonomic, async-first bindings to Apple's
Virtualization.framework for creating and managing virtual machines on macOS.
All framework interaction lives in **ArcBoxVZShim**, a SwiftPM static library
under `shim/` that `build.rs` compiles and links into the crate. Rust and
Swift meet at a hand-written C ABI: `shim/Sources/ArcBoxVZShim/Exports.swift`
(`@_cdecl` exports) and `src/shim_ffi.rs` (extern declarations) mirror each
other in a normative symbol order — review them side by side, and bump the
ABI version in both on any signature change.

## Requirements

- macOS 13+ (the shim's deployment target)
- Xcode Command Line Tools (`xcode-select --install`) — `build.rs` invokes
  `swift build`
- The `com.apple.security.virtualization` entitlement on any binary that
  creates VMs (configuration objects and capability queries work unsigned)

## Usage

```rust
use arcbox_vz::{LinuxBootLoader, VirtualMachineConfiguration, VZError};

#[tokio::main]
async fn main() -> Result<(), VZError> {
    if !arcbox_vz::is_supported() {
        return Err(VZError::OperationFailed("virtualization unsupported".into()));
    }

    let mut config = VirtualMachineConfiguration::new()?;
    config
        .set_cpu_count(2)
        .set_memory_size(512 * 1024 * 1024);
    config.set_boot_loader(LinuxBootLoader::new("/path/to/kernel")?);

    let vm = config.build()?;
    vm.start().await?;

    vm.request_stop()?;
    Ok(())
}
```

## VM Lifecycle

| Method | Description |
|--------|-------------|
| `start()` | Async start; resolves on the framework's completion |
| `stop()` | Force stop (destructive); resolves on completion |
| `pause()` / `resume()` | Pause / resume; resolve on completion |
| `request_stop()` | Send a graceful shutdown request to the guest |
| `state()` | Query the current `VirtualMachineState` |

## License

MIT OR Apache-2.0
