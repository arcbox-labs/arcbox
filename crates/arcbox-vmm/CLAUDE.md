# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox-vmm crate.

## Overview

Virtual Machine Monitor - orchestrates VM lifecycle, vCPU management, memory layout, and device emulation. Sits between `arcbox-hypervisor` (platform abstraction) and `arcbox-virtio` (device implementations).

## Architecture

```
arcbox-vmm/src/
├── lib.rs          # Crate entry
├── vmm.rs          # Vmm struct - main orchestrator
├── builder.rs      # VmmBuilder for VM construction
├── vcpu.rs         # VcpuManager - vCPU lifecycle
├── memory.rs       # MemoryManager - guest memory layout
├── device.rs       # DeviceManager - virtio device registration
├── fdt.rs          # Flattened Device Tree generation (ARM64)
└── event.rs        # Event loop for device I/O
```

## Key Types

```rust
/// Main VMM orchestrator
pub struct Vmm {
    vm: Box<dyn VirtualMachine>,
    vcpu_manager: VcpuManager,
    memory_manager: MemoryManager,
    device_manager: DeviceManager,
}

/// VM configuration
pub struct VmmConfig {
    pub vcpu_count: u32,
    pub memory_size: u64,
    pub kernel_path: PathBuf,
    pub initrd_path: Option<PathBuf>,
    pub cmdline: String,
    pub vsock_cid: Option<u32>,
    pub balloon: bool,
}
```

## Memory Layout (ARM64)

```
0x0000_0000 - 0x3FFF_FFFF  : RAM (up to 1GB low memory)
0x4000_0000 - 0x4000_FFFF  : GIC distributor
0x4001_0000 - 0x4001_FFFF  : GIC redistributor
0x4002_0000 - 0x4002_FFFF  : UART (PL011)
0x4003_0000 - ...          : VirtIO MMIO devices
0x8000_0000 - ...          : RAM (high memory, if >1GB)
```

## FDT Generation

ARM64 VMs require a Flattened Device Tree describing hardware:
- CPU nodes with enable-method
- Memory nodes
- GIC (interrupt controller)
- Timer
- VirtIO MMIO devices
- Chosen node (kernel cmdline, initrd)

## Common Commands

```bash
cargo build -p arcbox-vmm
cargo test -p arcbox-vmm

# Run example (requires kernel + initramfs)
cargo build --example vmm_boot -p arcbox-vmm
codesign --entitlements tests/resources/entitlements.plist -s - target/debug/examples/vmm_boot
```

## Integration

- **arcbox-hypervisor**: Provides `VirtualMachine`, `Vcpu`, `GuestMemory` traits
- **arcbox-virtio**: Provides device implementations (blk, net, console, fs, vsock)
- **arcbox-core**: Uses Vmm for VM lifecycle management
