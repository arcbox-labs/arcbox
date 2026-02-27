# ArcBox AI Agent Instructions

ArcBox is a pure-Rust, high-performance container and VM runtime targeting macOS (primary) and Linux, aiming to surpass OrbStack's performance metrics.

## Architecture Overview

**Three-tier structure:**

- **Core layer** (`crates/`): MIT/Apache-2.0 licensed foundation
- **Pro layer** (`pro/`): BSL-1.1 licensed enhanced features (smart caching, snapshots, advanced networking)
- **Guest components** (`guest/arcbox-agent`): Runs inside VMs, cross-compiled to Linux ARM64/x86_64

**Key layers (bottom-up):**

```
arcbox-cli / arcbox-docker API → arcbox-core (Runtime singleton)
    ↓
arcbox-fs / arcbox-net / arcbox-container
    ↓
arcbox-virtio (VirtIO devices) → arcbox-vmm (VM Monitor)
    ↓
arcbox-hypervisor (platform abstraction: macOS Virtualization.framework / Linux KVM)
```

**Communication:** Host ↔ Guest via vsock + ttrpc (`arcbox-protocol`). Docker API compatibility via `arcbox-docker` (Axum REST server).

## Critical Platform Differences

**macOS specifics:**

- Uses Virtualization.framework via Objective-C FFI (`objc2` crate in `crates/arcbox-hypervisor/src/darwin/ffi.rs`)
- **All VM-related binaries require code signing:**
  ```bash
  codesign --entitlements tests/resources/entitlements.plist --force -s - <binary>
  ```
  Required for: examples, tests touching hypervisor. See [entitlements.plist](tests/resources/entitlements.plist)
- `mode_t` types (e.g., `libc::S_IFMT`) are `u16` (Linux: `u32`). Use `u32::from()` for cross-platform compatibility
- No `fallocate` - use `ftruncate` instead
- xattr APIs have different argument order than Linux

## Development Workflows

**Building:**

```bash
cargo build -p <crate>           # Dev build specific crate
cargo build --release            # Full optimized build (uses LTO)
```

**Testing:**

```bash
cargo test -p <crate>
cargo test -- --nocapture        # Show test output
cargo test -- --ignored          # Run privileged tests (require VM access)
```

**Guest agent cross-compilation:**

```bash
# Required once:
brew install FiloSottile/musl-cross/musl-cross
rustup target add aarch64-unknown-linux-musl

# Build agent:
cargo build -p arcbox-agent --target aarch64-unknown-linux-musl --release
```

**Running VM examples:**

```bash
cd tests/resources
./download-kernel.sh              # Get test kernel
./build-initramfs.sh              # Build initramfs with agent

# Build and sign example:
cargo build --example boot_vm -p arcbox-hypervisor
codesign --entitlements tests/resources/entitlements.plist --force -s - \
    target/debug/examples/boot_vm

# Run:
./target/debug/examples/boot_vm tests/resources/Image-arm64 \
    tests/resources/initramfs-arcbox --vsock --net
```

## Project Conventions

**Comments and commits:**

- All code comments MUST be in English
- NO `Co-Authored-By` lines in commits
- Detailed inline comments expected for complex logic

**Error handling:**

- Use `thiserror` for crate-specific errors (`FsError`, `NetError`, etc.)
- Use `anyhow` for application-level error propagation in CLI/API layers

**Async:**

- Tokio runtime everywhere (`tokio::main`, `tokio::spawn`)
- Performance-critical paths use async I/O

**Unsafe usage:**

- Justified only for FFI (Darwin Virtualization), zero-copy networking, lock-free structures
- Every `unsafe` block requires a safety comment explaining invariants

## Performance Philosophy

**Targets (vs OrbStack baselines):**
| Metric | ArcBox Goal | OrbStack |
|--------|-------------|----------|
| Cold boot | <1.5s | ~2s |
| Hot boot | <500ms | <1s |
| Idle memory | <150MB | ~200MB |
| File I/O | >90% native | 75-95% |

**Implementation patterns:**

1. **Zero-copy everywhere:** `arcbox-net` uses `ZeroCopyPacket` with raw guest memory pointers
2. **Lock-free:** `LockFreeRing<T>` SPSC queue in `arcbox-net/src/datapath/ring.rs`
3. **Cache-aligned:** Hot structures use `#[repr(C, align(64))]` + `CachePadded<T>` wrapper
4. **Batch operations:** Process multiple virtqueue descriptors per iteration
5. **Negative caching:** `arcbox-fs` caches "file not found" results (see `crates/arcbox-fs/src/cache.rs`)

**NAT Engine** (`arcbox-net/src/nat_engine/`):

- Connection tracking with 256-entry fast-path cache
- Incremental checksum updates (RFC 1624) - no full recalculations
- In-place packet modification for SNAT/DNAT

## Key Files & Patterns

**Runtime singleton** (`crates/arcbox-core/src/runtime.rs`):

- Central orchestrator holding `VmManager`, `MachineManager`, `ContainerManager`, `ImageStore`, etc.
- All managers are `Arc<>`-wrapped for sharing across async tasks

**VirtIO device pattern** (`crates/arcbox-virtio/src/*.rs`):

- `pop_avail()` to get descriptor chains from guest
- Process I/O (zero-copy where possible)
- `push_used()` to return completed descriptors

**Filesystem passthrough** (`crates/arcbox-fs/src/passthrough.rs`):

- Maps guest paths → host paths via `InodeData` table
- Platform-specific syscalls (`#[cfg(target_os = "...")]` branches common)
- Uses `NegativeCache` to avoid repeated stat calls on missing paths

**Hypervisor abstraction** (`crates/arcbox-hypervisor/src/traits.rs`):

- Core traits: `Hypervisor`, `VirtualMachine`, `Vcpu`, `GuestMemory`
- Platform impls in `darwin/` (Virtualization.framework) and `linux/` (KVM)

## Common Pitfalls

1. **Forgetting to codesign** → "Virtualization not available" errors on macOS
2. **Using `libc::S_IFMT` directly** → Works on Linux, fails on macOS (cast to `u32` first)
3. **Not batching virtqueue operations** → Excessive VM exits hurt performance
4. **Ignoring cache alignment** → False sharing between CPU cores
5. **Using `Arc<Mutex<T>>` in hot paths** → Prefer lock-free or `Arc<RwLock<T>>`

## Debugging & Logging

**Tracing levels:**

```bash
RUST_LOG=debug cargo run ...          # All modules
RUST_LOG=arcbox_hypervisor=trace      # Module-specific
RUST_BACKTRACE=1                      # Enable backtraces
```

**Test resources:**

- Kernel images: `tests/resources/Image-arm64`, `Image-microvm`
- Build scripts: `download-kernel.sh`, `build-initramfs.sh`
- Initramfs contains `arcbox-agent` + busybox

## Documentation References

- Main CLAUDE.md: Project overview, architecture, commands
- `crates/arcbox-hypervisor/CLAUDE.md`: FFI patterns, platform backends
- `crates/arcbox-net/CLAUDE.md`: Zero-copy datapath, NAT engine details
- `crates/arcbox-virtio/CLAUDE.md`: VirtIO device implementations
- `internal-docs/parallel-development-plan.md`: Development streams (VM lifecycle, image pull, guest agent, integration)

## Licensing & Structure

- Core (`crates/`) + Guest: **MIT OR Apache-2.0** - permissive
- Pro (`pro/`): **BSL-1.1** - production use requires license after 4 years
- Enterprise (separate repos): Proprietary (desktop app, SSO, K8s integration)
- When adding files to `crates/` or `guest/`, include dual-license header
