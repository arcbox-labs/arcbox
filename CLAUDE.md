# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Note**: This repository is the main repository of the arcboxd organization, containing Core and Pro layers.
> See organization-level guidance at: `../CLAUDE.md`
> See internal development docs at: `../internal-docs/`

## Crate-Level Documentation

Each crate has its own `CLAUDE.md` with detailed guidance:

| Layer | Crates |
|-------|--------|
| **Core** | `crates/arcbox-hypervisor`, `arcbox-vmm`, `arcbox-virtio`, `arcbox-fs`, `arcbox-net`, `arcbox-core`, `arcbox-container`, `arcbox-image`, `arcbox-docker`, `arcbox-api`, `arcbox-cli`, `arcbox-protocol`, `arcbox-transport`, `arcbox-oci`, `arcbox-grpc`, `arcbox-vz` |
| **Pro** | `pro/arcbox-fs-enhanced`, `arcbox-net-advanced`, `arcbox-snapshot`, `arcbox-perf` |
| **Guest** | `guest/arcbox-agent` |

When working on a specific crate, read its `CLAUDE.md` for crate-specific patterns and types.

## Project Overview

ArcBox is a high-performance container and virtual machine runtime implemented purely in Rust, aiming to surpass OrbStack. Supports macOS (primary) and Linux platforms.

**Internal Development Docs** (not committed to git):
- `../internal-docs/00-vision.md` - Project vision and performance goals
- `../internal-docs/02-architecture.md` - System architecture design
- `../internal-docs/03-licensing.md` - License structure
- `../internal-docs/development/setup.md` - Development environment setup

## Repository Structure

```
arcbox/                          # This repository
├── crates/                      # Core layer (MIT OR Apache-2.0)
│   ├── arcbox-hypervisor/       # Virtualization abstraction
│   ├── arcbox-vmm/              # Virtual machine monitor
│   ├── arcbox-virtio/           # VirtIO devices
│   ├── arcbox-fs/               # Base filesystem
│   ├── arcbox-net/              # Base network stack
│   ├── arcbox-container/        # Container management
│   ├── arcbox-image/            # Image management
│   ├── arcbox-oci/              # OCI spec implementation
│   ├── arcbox-protocol/         # ttrpc protocol
│   ├── arcbox-transport/        # Transport layer
│   ├── arcbox-docker/           # Docker REST API
│   ├── arcbox-core/             # Core coordination
│   ├── arcbox-api/              # gRPC API
│   └── arcbox-cli/              # Command-line tool
│
├── guest/                       # Guest components (MIT OR Apache-2.0)
│   └── arcbox-agent/            # In-VM agent (requires cross-compilation)
│
├── pro/                         # Pro layer (BSL-1.1)
│   ├── arcbox-fs-enhanced/      # Smart caching/prefetch
│   ├── arcbox-net-advanced/     # VPN-aware/advanced DNS
│   ├── arcbox-snapshot/         # Snapshot/restore
│   └── arcbox-perf/             # Performance monitoring
│
└── tests/resources/             # Test resources
    ├── entitlements.plist       # macOS signing entitlements
    ├── download-kernel.sh       # Download test kernel
    └── build-initramfs.sh       # Build initramfs
```

## Design Goals and Requirements

### Performance Goals

| Metric | ArcBox Target | vs OrbStack |
|--------|---------------|-------------|
| Cold boot time | **<1.5s** | ~2s |
| Warm boot time | **<500ms** | <1s |
| Idle memory usage | **<150MB** | ~200MB |
| Idle CPU | **<0.05%** | <0.1% |
| File I/O (vs native) | **>90%** | 75-95% |
| Network throughput | **>50 Gbps** | ~45 Gbps |

### Architecture Principles

1. **Clear layering** - Single responsibility per layer, well-defined interfaces
2. **Platform abstraction** - Core logic separated from platform implementation
3. **Zero-cost abstraction** - Abstractions incur no runtime overhead
4. **Dependency inversion** - High-level modules don't depend on low-level implementation details
5. **Testability** - Each component can be tested independently

### Technical Philosophy

- **Build over reuse**: Performance-critical paths are all custom-built (VirtioFS, network stack, caching system)
- **Zero-compromise performance**: Zero-copy, lock-free, batch operations, smart caching, minimal syscalls
- **Type safety**: Leverage Rust's type system for compile-time error detection, memory safety, no data races

### Platform Priority

1. **P0**: macOS (Apple Silicon) - Core target
2. **P1**: macOS (Intel) - Full support
3. **P2**: Linux (x86_64/ARM64) - Secondary target

## Common Commands

```bash
# Build
cargo build                           # Development build
cargo build --release                 # Release build
cargo build -p arcbox-hypervisor      # Build specific crate

# Test
cargo test                            # Run all tests
cargo test -p arcbox-hypervisor       # Test specific crate
cargo test test_vm_creation           # Run specific test
cargo test -- --nocapture             # Show test output
cargo test -- --ignored               # Run tests requiring special privileges

# Lint and format
cargo fmt                             # Format code
cargo clippy -- -D warnings           # Lint check

# Benchmarks
cargo bench                           # Run all benchmarks
cargo bench --bench fs_bench          # Run specific benchmark

# Run
cargo run --bin arcbox -- --help
RUST_LOG=debug cargo run --bin arcbox -- boot --kernel /path/to/vmlinux
```

### Guest Component Cross-Compilation (arcbox-agent)

```bash
# Install cross-compilation toolchain
brew install FiloSottile/musl-cross/musl-cross

# Add Rust target
rustup target add aarch64-unknown-linux-musl

# Build agent (runs inside Guest VM)
cargo build -p arcbox-agent --target aarch64-unknown-linux-musl --release
```

### Running VM Example

```bash
# 1. Prepare test kernel and initramfs
cd tests/resources
./download-kernel.sh                  # Download Alpine Linux kernel
./build-initramfs.sh                  # Build initramfs with agent

# 2. Build and sign example
cargo build --example boot_vm -p arcbox-hypervisor
codesign --entitlements tests/resources/entitlements.plist --force -s - \
    target/debug/examples/boot_vm

# 3. Run VM
./target/debug/examples/boot_vm tests/resources/Image-arm64 \
    tests/resources/initramfs-arcbox --vsock --net
```

## Architecture

### Layered Design (bottom-up)

1. **Layer 0: Platform APIs** - macOS Virtualization.framework / Linux KVM
2. **Layer 1: arcbox-hypervisor** - Cross-platform virtualization abstraction, defines core traits (Hypervisor, VirtualMachine, Vcpu, GuestMemory)
3. **Layer 2: arcbox-vmm** - Virtual machine monitor (VcpuManager, MemoryManager, DeviceManager, EventLoop)
4. **Layer 3: arcbox-virtio** - VirtIO device implementations (blk, console, net, fs, vsock)
5. **Layer 4: Services** - arcbox-fs (VirtioFS), arcbox-net (network stack), arcbox-container, arcbox-image
6. **Layer 5: arcbox-core** - Core coordination layer (VmManager, MachineManager, ContainerManager)
7. **Layer 6: arcbox-api** - gRPC/REST API layer, Docker API compatible
8. **Layer 7: arcbox-cli** - Command-line interface (arcbox-desktop is in separate Enterprise repository)

### Crate Dependency Chain

```
arcbox-cli → arcbox-api → arcbox-core
                            ↓
              arcbox-fs / arcbox-net / arcbox-container
                            ↓
                      arcbox-virtio
                            ↓
                       arcbox-vmm
                            ↓
                    arcbox-hypervisor
```

### Platform Backends

- **macOS**: Uses Virtualization.framework via FFI bindings
- **Linux**: Uses KVM (/dev/kvm)
- Switched via `#[cfg(target_os = "...")]` conditional compilation

## Technical Details

- **Rust Edition**: 2024
- **Async runtime**: tokio
- **gRPC**: tonic + prost
- **Error handling**: thiserror + anyhow
- **CLI**: clap
- **Logging**: tracing

### Performance-Critical Paths

- VirtioFS filesystem (performance-critical, custom-built)
- Network stack (performance-critical, custom-built)
- Zero-copy data transfer
- Lock-free data structures
- Smart caching and prefetching

### Code Standards

- Use clippy pedantic + nursery
- `unsafe` code requires careful use and auditing
- All platform-specific code abstracted via traits
- **Code comments**: Detailed comments required, all comments must be in English
- **Git Commit**: Do not add Co-Authored-By lines
- **Error handling**: Use `thiserror` for crate-specific errors, `anyhow` for CLI/API layers
- **Async**: Tokio runtime everywhere, performance-critical paths use async I/O

### Platform-Specific Notes

- **libc type differences**: On macOS `mode_t` (S_IFMT, S_IFDIR, etc.) is `u16`, on Linux it's `u32`. Use `u32::from(libc::S_IFMT)` for cross-platform compatibility
- **Extended attributes**: xattr API parameter order differs between macOS and Linux, use `#[cfg(target_os = "...")]` to implement separately
- **fallocate**: macOS doesn't support fallocate, use ftruncate as fallback

## Environment Variables

```bash
RUST_LOG=debug                        # Log level
RUST_LOG=arcbox_hypervisor=trace      # Module-level logging
RUST_BACKTRACE=1                      # Enable backtrace
ARCBOX_TEST_KERNEL=/path/to/vmlinux   # Test kernel path
```

## macOS Development Notes

- Requires Xcode Command Line Tools
- Virtualization.framework requires entitlement signing to run
- Signing command: `codesign --entitlements tests/resources/entitlements.plist --force -s - <binary>`
- Signing required for: Running VM-related examples and tests

## Dual-Channel Communication Architecture

```
Docker CLI ──HTTP/REST──► arcbox-docker ──────┐
                                              ├──► arcbox-core ──vsock+ttrpc──► Guest VM (arcbox-agent)
arcbox CLI ──ttrpc───────► arcbox-protocol ───┘
```

- **arcbox-docker**: Docker Engine API v1.43 compatibility layer, listens on Unix socket
- **arcbox-protocol**: Protobuf types generated by prost, ttrpc for high-performance Host-Guest communication
- **arcbox-transport**: vsock (Linux) / Virtualization.framework vsock (macOS) transport abstraction

## Core Trait System (arcbox-hypervisor)

```rust
trait Hypervisor       // Platform entry point, creates VM
  └── trait VirtualMachine  // VM lifecycle management
        ├── trait Vcpu      // vCPU execution and register access
        └── trait GuestMemory // Guest physical memory read/write
```

Platform implementations:
- **darwin/**: `DarwinHypervisor` → `DarwinVm` → `DarwinVcpu` + `DarwinMemory`
- **linux.rs**: KVM implementation (to be completed)

## arcbox-fs Architecture

```
FuseDispatcher (dispatcher.rs)
    ↓ Parse FUSE requests
PassthroughFs (passthrough.rs)
    ↓ Execute filesystem operations
NegativeCache (cache.rs)
    ↓ Cache non-existent paths
Host Filesystem
```

- **FuseDispatcher**: Parses FUSE protocol requests, routes to PassthroughFs methods
- **PassthroughFs**: Maps Guest filesystem operations directly to Host filesystem
- **NegativeCache**: Caches "file not found" results to avoid repeated syscalls (especially effective for node_modules/.git directories)

## arcbox-net Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       NAT Engine                            │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ ConnTracker │  │ 256-entry    │  │ Incremental       │  │
│  │             │  │ Fast Cache   │  │ Checksum (RFC1624)│  │
│  └─────────────┘  └──────────────┘  └───────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                    Zero-Copy Datapath                       │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ PacketPool  │  │ LockFreeRing │  │ ZeroCopyPacket    │  │
│  │             │  │ (SPSC queue) │  │ (raw guest mem)   │  │
│  └─────────────┘  └──────────────┘  └───────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

- **LockFreeRing**: Single-producer single-consumer queue for hot path
- **PacketPool**: Pre-allocated packet buffers for zero-allocation I/O
- **NAT Engine**: Connection tracking with fast-path cache, in-place packet modification

## VirtIO Device Pattern

```rust
// Standard VirtIO device processing loop:
loop {
    // 1. Pop available descriptor chains from guest
    while let Some(chain) = virtqueue.pop_avail() {
        // 2. Process I/O (zero-copy where possible)
        let result = process_request(&chain);

        // 3. Push completed descriptors back
        virtqueue.push_used(chain.head, result.len);
    }
    // 4. Signal guest if needed
    virtqueue.notify_guest();
}
```

## Common Pitfalls

1. **Forgetting to codesign** → "Virtualization not available" errors on macOS
2. **Using `libc::S_IFMT` directly** → Works on Linux, fails on macOS (cast to `u32` first)
3. **Not batching virtqueue operations** → Excessive VM exits hurt performance
4. **Ignoring cache alignment** → False sharing between CPU cores (use `#[repr(C, align(64))]`)
5. **Using `Arc<Mutex<T>>` in hot paths** → Prefer lock-free or `Arc<RwLock<T>>`
6. **Missing SAFETY comments** → All `unsafe` blocks require safety justification
