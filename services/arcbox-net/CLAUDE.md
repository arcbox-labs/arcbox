# CLAUDE.md - arcbox-net

This file provides guidance to Claude Code when working with the arcbox-net crate.

## Overview

`arcbox-net` provides high-performance networking infrastructure for ArcBox VMs, with Darwin (macOS) as the primary target platform.

## Architecture

```
arcbox-net/src/
├── lib.rs              # Crate entry point
├── error.rs            # Error types (NetError)
├── nat.rs              # Basic NAT configuration and IP allocation
├── backend.rs          # Network backend trait
├── dhcp.rs             # DHCP server
├── dns.rs              # DNS server/forwarder
│
├── datapath/           # High-performance data path
│   ├── mod.rs          # CachePadded, prefetch, utilities
│   ├── packet.rs       # Zero-copy packet (ZeroCopyPacket)
│   ├── pool.rs         # Pre-allocated buffer pool (PacketPool)
│   ├── ring.rs         # Lock-free SPSC ring buffer (LockFreeRing)
│   └── stats.rs        # Performance statistics (DatapathStats)
│
├── nat_engine/         # High-performance NAT engine
│   ├── mod.rs          # NatEngine, NatEngineConfig
│   ├── checksum.rs     # Incremental checksum (RFC 1624)
│   ├── conntrack.rs    # Connection tracking table
│   └── translate.rs    # SNAT/DNAT translation
│
├── darwin/             # macOS-specific implementation
│   ├── mod.rs          # DarwinNetConfig, MAC utilities
│   └── nat.rs          # DarwinNatNetwork, DatapathPoller
│
└── linux/              # Linux-specific implementation
    ├── mod.rs          # Module entry
    ├── netlink.rs      # Netlink socket operations
    ├── bridge.rs       # Bridge device management
    ├── tap.rs          # TAP device management
    ├── firewall.rs     # iptables/nftables
    ├── nat.rs          # Linux NAT network
    ├── dhcp.rs         # Linux DHCP integration
    └── dns.rs          # Linux DNS integration
```

## Key Design Decisions

### Zero-Copy Data Path

- `ZeroCopyPacket` directly references guest memory via raw pointers
- No `memcpy` in the hot path
- Pre-parsed packet metadata for fast protocol handling

### Lock-Free Design

- `LockFreeRing<T>`: SPSC (Single-Producer Single-Consumer) ring buffer using atomic operations
- `PacketPool`: Lock-free allocation using atomic CAS on free list
- Uses `UnsafeCell` for interior mutability (required for `&self` methods returning `&mut`)

### Cache Optimization

- All hot structures are 64-byte aligned (`#[repr(C, align(64))]`)
- `CachePadded<T>` wrapper prevents false sharing between CPU cores
- Software prefetch hints for ARM64 and x86_64

### NAT Engine

- Connection tracking with Swiss Table (hashbrown) for O(1) lookups
- 256-entry fast-path cache for recent connections
- Incremental checksum updates (RFC 1624) - no full packet recalculation
- In-place packet modification for SNAT/DNAT

## Performance Targets

| Metric | Target |
|--------|--------|
| Host-Guest throughput | >60 Gbps |
| Guest-Guest throughput | >130 Gbps |
| Single packet latency | <5 μs |
| NAT throughput | >30 Mpps |

## Common Commands

```bash
# Build
cargo build -p arcbox-net

# Test
cargo test -p arcbox-net

# Test specific module
cargo test -p arcbox-net datapath::
cargo test -p arcbox-net nat_engine::
cargo test -p arcbox-net darwin::

# Clippy
cargo clippy -p arcbox-net
```

## Platform Support

- **Darwin (macOS)**: Primary target, uses Virtualization.framework
- **Linux**: Secondary target, uses TAP/bridge/netlink

Darwin-specific code is gated with `#[cfg(target_os = "macos")]`.

## Safety Notes

### Unsafe Code Patterns

1. **PacketPool**: Uses `UnsafeCell<PacketBuffer>` for interior mutability
   - Safe because: Atomic CAS ensures exclusive access during allocation
   - `Send + Sync` implemented manually with safety justification

2. **ZeroCopyPacket**: Holds raw pointer to guest memory
   - Safe because: Caller must ensure memory validity (documented in `# Safety`)
   - Reference counting prevents premature release

3. **LockFreeRing**: Uses `UnsafeCell<MaybeUninit<T>>`
   - Safe because: SPSC protocol ensures no concurrent access to same slot

### Rust 2024 Edition

All unsafe function bodies require explicit `unsafe {}` blocks for unsafe operations:

```rust
pub unsafe fn example(&self) {
    // Must wrap unsafe calls in explicit block
    unsafe { self.unsafe_operation() };
}
```

## Dependencies

- `hashbrown`: Swiss Table hash map for fast connection tracking
- `crossbeam-utils`: `CachePadded` for cache-line alignment
- `ipnetwork`: IP network/subnet utilities

## TODO

- [ ] Proper SIMD checksum optimization (ARM64 NEON with correct big-endian handling)
- [ ] Integration with arcbox-virtio VirtIO queues
- [ ] Benchmarks for real network traffic
- [ ] vmnet.framework support for advanced macOS scenarios
