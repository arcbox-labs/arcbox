# ArcBox AI Agent Instructions

ArcBox is a pure-Rust, high-performance container and VM runtime targeting macOS (primary) and Linux, aiming to surpass OrbStack's performance metrics.

## Architecture Overview

**Three-tier structure:**

- **Core layer** (`common/`, `hypervisor/`, `services/`, `comm/`, `app/`): MIT/Apache-2.0 licensed foundation
- **Pro layer** (`pro/`): BSL-1.1 licensed enhanced features (smart caching, snapshots, advanced networking)
- **Guest components** (`guest/arcbox-agent`): Runs inside VMs, cross-compiled to Linux ARM64/x86_64

**Key layers (bottom-up):**

```text
arcbox-cli / arcbox-docker API -> arcbox-core (Runtime)
    ↓
arcbox-fs / arcbox-net / arcbox-container
    ↓
arcbox-virtio (VirtIO devices) -> arcbox-vmm (VM monitor)
    ↓
arcbox-hypervisor / arcbox-vz (platform virtualization)
```

**Communication:** Host <-> Guest via vsock and ArcBox protocol crates (`arcbox-protocol`, `arcbox-grpc`, `arcbox-transport`). Docker API compatibility is provided by `arcbox-docker` (Axum REST server + guest dockerd proxy).

## Critical Platform Differences

**macOS specifics:**

- Uses Apple's Virtualization.framework (not KVM)
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
cargo build --release            # Full optimized build
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
- Performance-critical paths use async I/O where appropriate

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

1. **Zero-copy datapath:** `arcbox-net` packet-path code avoids unnecessary copies
2. **Lock-free where it matters:** SPSC queue in `services/arcbox-net/src/datapath/ring.rs`
3. **Cache alignment:** use `#[repr(C, align(64))]` for hot structures
4. **Batch operations:** avoid per-descriptor overhead in VirtIO queues
5. **Negative caching:** `arcbox-fs` caches missing lookups (see `services/arcbox-fs/src/cache.rs`)

## Key Files & Patterns

**Runtime singleton** (`app/arcbox-core/src/runtime.rs`):

- Central orchestrator wiring `MachineManager`, `VmLifecycleManager`, container backend, networking, and port-forward state
- Shared managers/state are held behind `Arc` for async task coordination

**VirtIO device pattern** (`hypervisor/arcbox-virtio/src/*.rs`):

- `pop_avail()` to get descriptor chains from guest
- Process I/O (zero-copy where possible)
- `push_used()` to return completed descriptors

**Filesystem passthrough** (`services/arcbox-fs/src/passthrough.rs`):

- Maps guest paths -> host paths via inode/path tables
- Uses platform-specific syscall branches (`#[cfg(target_os = "...")]`)
- Uses negative caching to avoid repeated misses

**Hypervisor abstraction** (`hypervisor/arcbox-hypervisor/src/traits.rs`):

- Core traits: `Hypervisor`, `VirtualMachine`, `Vcpu`, `GuestMemory`
- Platform implementations in `darwin/` (Virtualization.framework) and `linux/` (KVM)

## Common Pitfalls

1. **Forgetting to codesign** -> "Virtualization not available" errors on macOS
2. **Using `libc::S_IFMT` directly** -> Works on Linux, fails on macOS (cast to `u32` first)
3. **Not batching virtqueue operations** -> Excessive VM exits hurt performance
4. **Ignoring cache alignment** -> False sharing between CPU cores
5. **Using `Arc<Mutex<T>>` in hot paths** -> Prefer lock-free or `Arc<RwLock<T>>`

## Debugging & Logging

**Tracing levels:**

```bash
RUST_LOG=debug cargo run ...          # All modules
RUST_LOG=arcbox_hypervisor=trace      # Module-specific
RUST_BACKTRACE=1                      # Enable backtraces
```

**Test resources:**

- Kernel images and initramfs live under `tests/resources/`
- Build scripts for assets are in `tests/resources/` and `scripts/`

## Documentation References

- Main [CLAUDE.md](../CLAUDE.md): project overview, architecture, commands
- Crate-level READMEs in `app/`, `hypervisor/`, `services/`, `comm/`
- Boot assets ownership and boundaries: [docs/boot-assets.md](../docs/boot-assets.md)

## Licensing & Structure

- Core (`common/`, `hypervisor/`, `services/`, `comm/`, `app/`) + Guest: **MIT OR Apache-2.0**
- Pro (`pro/`): **BSL-1.1** - production use requires license after 4 years
- Enterprise (separate repos): Proprietary (desktop app, SSO, K8s integration)
- When adding files to core directories or `guest/`, include dual-license headers
