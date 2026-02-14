# CLAUDE.md - arcbox-hypervisor

This file provides guidance to Claude Code when working with the arcbox-hypervisor crate.

## Overview

`arcbox-hypervisor` provides a cross-platform virtualization abstraction layer, with Darwin (macOS Virtualization.framework) as the primary target and Linux (KVM) as secondary.

## Architecture

```
arcbox-hypervisor/src/
├── lib.rs              # Crate entry, re-exports
├── traits.rs           # Core traits (Hypervisor, VirtualMachine, Vcpu, GuestMemory)
├── types.rs            # Common types (VmExit, CpuArch, etc.)
├── error.rs            # HypervisorError
├── config.rs           # VmConfig, VmConfigBuilder
├── memory.rs           # Memory region management
│
├── darwin/             # macOS Virtualization.framework
│   ├── mod.rs          # Module entry
│   ├── ffi.rs          # Objective-C FFI bindings
│   ├── hypervisor.rs   # DarwinHypervisor
│   ├── vm.rs           # DarwinVm
│   ├── vcpu.rs         # DarwinVcpu
│   └── memory.rs       # DarwinMemory
│
└── linux/              # Linux KVM
    ├── mod.rs          # Module entry
    ├── ffi.rs          # KVM ioctl bindings
    ├── hypervisor.rs   # KvmHypervisor
    ├── vm.rs           # KvmVm
    ├── vcpu.rs         # KvmVcpu
    └── memory.rs       # KvmMemory
```

## Core Traits (`traits.rs`)

```rust
trait Hypervisor {
    fn create_vm(&self, config: &VmConfig) -> Result<Box<dyn VirtualMachine>>;
}

trait VirtualMachine {
    fn create_vcpu(&mut self, id: u32) -> Result<Box<dyn Vcpu>>;
    fn map_memory(&mut self, region: MemoryRegion) -> Result<()>;
    fn start(&mut self) -> Result<()>;
    fn stop(&mut self) -> Result<()>;
}

trait Vcpu {
    fn run(&mut self) -> Result<VmExit>;
    fn get_regs(&self) -> Result<Registers>;
    fn set_regs(&mut self, regs: &Registers) -> Result<()>;
}

trait GuestMemory {
    fn read(&self, gpa: u64, buf: &mut [u8]) -> Result<()>;
    fn write(&self, gpa: u64, buf: &[u8]) -> Result<()>;
}
```

## Platform Implementations

### Darwin (`darwin/`)

Uses Apple's Virtualization.framework via Objective-C FFI:

- `VZVirtualMachine` for VM lifecycle
- `VZVirtualMachineConfiguration` for VM config
- Native ARM64 support on Apple Silicon
- Rosetta 2 for x86_64 guests (limited)

**FFI Pattern** (`darwin/ffi.rs`):
```rust
// Uses objc2 crate for Objective-C interop
extern_class!(
    pub struct VZVirtualMachineConfiguration;
    unsafe impl ClassType for VZVirtualMachineConfiguration {
        type Super = NSObject;
    }
);
```

### Linux (`linux/`)

Uses KVM via ioctl:

- `/dev/kvm` device
- `KVM_CREATE_VM`, `KVM_CREATE_VCPU` ioctls
- Memory slots for guest physical memory
- Supports both x86_64 and ARM64

## Common Commands

```bash
# Build
cargo build -p arcbox-hypervisor

# Test (requires hypervisor access)
cargo test -p arcbox-hypervisor

# macOS: Requires entitlements for Virtualization.framework
codesign --entitlements entitlements.plist -s - target/debug/deps/arcbox_hypervisor-*
```

## Platform Support

| Platform | Backend | Status |
|----------|---------|--------|
| macOS (Apple Silicon) | Virtualization.framework | Primary |
| macOS (Intel) | Virtualization.framework | Supported |
| Linux (x86_64) | KVM | Secondary |
| Linux (ARM64) | KVM | Secondary |

## Safety Notes

### Darwin FFI

- Objective-C objects are reference-counted (ARC)
- Raw pointers must be properly retained/released
- `objc2` crate handles most safety automatically

### Linux KVM

- File descriptors must be properly closed
- Memory mappings must be unmapped before VM destruction
- ioctl calls require proper error handling

## Integration Points

- **arcbox-vmm**: Uses hypervisor traits for VM management
- **arcbox-virtio**: Maps guest memory for device emulation
- **arcbox-net**: Uses guest memory for zero-copy networking

## Performance Targets (vs OrbStack)

Based on competitor analysis (see `internal-docs/04-competitor-analysis.md`):

| Metric | OrbStack | ArcBox Target |
|--------|----------|---------------|
| Cold boot | ~2s | **<1.5s** |
| Machine creation | ~1s | **<500ms** |
| Idle CPU | <0.1% | **<0.05%** |
| Idle memory | ~200MB | **<150MB** |

### Key Optimizations from OrbStack

1. **Shared Kernel Architecture**: Multiple machines share one optimized kernel
2. **Event-driven**: Avoid polling, use events for state changes
3. **Rosetta Integration**: Leverage Apple's Rosetta for x86 on ARM (much faster than QEMU)
4. **Dynamic Memory**: Memory allocation on-demand, balloon device for reclaim

## TODO

- [x] Complete Linux KVM implementation
- [ ] Add vCPU hot-plug support
- [ ] Memory ballooning (critical for idle memory target)
- [ ] Nested virtualization detection
- [ ] Rosetta availability detection and integration
- [ ] Shared kernel support in VMM layer
- [ ] Event-driven VM state monitoring
