# CLAUDE.md - arcbox-virtio

This file provides guidance to Claude Code when working with the arcbox-virtio crate.

## Overview

`arcbox-virtio` implements VirtIO device emulation for ArcBox VMs, providing high-performance paravirtualized I/O.

## Architecture

```
arcbox-virtio/src/
├── lib.rs          # Crate entry, device traits
├── error.rs        # VirtIO error types
├── queue.rs        # VirtQueue implementation (descriptor chains, avail/used rings)
├── blk.rs          # VirtIO block device (virtio-blk)
├── net.rs          # VirtIO network device (virtio-net)
├── console.rs      # VirtIO console (virtio-console)
├── fs.rs           # VirtIO filesystem (virtio-fs/9p)
└── vsock.rs        # VirtIO socket (virtio-vsock)
```

## Key Components

### VirtQueue (`queue.rs`)

Core virtio queue implementation:
- Descriptor table, available ring, used ring
- `pop_avail()` - Get next available descriptor chain from guest
- `push_used()` - Return completed descriptor to guest
- Batch operations for performance

### Device Implementations

| Device | File | Description |
|--------|------|-------------|
| virtio-blk | `blk.rs` | Block device with async file backend |
| virtio-net | `net.rs` | Network device for VM networking |
| virtio-console | `console.rs` | Serial console I/O |
| virtio-fs | `fs.rs` | Shared filesystem (FUSE protocol) |
| virtio-vsock | `vsock.rs` | Host-guest socket communication |

## Common Commands

```bash
# Build
cargo build -p arcbox-virtio

# Test
cargo test -p arcbox-virtio

# Test specific device
cargo test -p arcbox-virtio blk::
cargo test -p arcbox-virtio net::
```

## Integration with arcbox-net

The `VirtioNet` device in `net.rs` integrates with `arcbox-net` for network I/O:

1. Guest writes packets to TX virtqueue
2. VirtioNet processes TX descriptors
3. Packets forwarded to arcbox-net datapath
4. arcbox-net performs NAT translation
5. RX packets queued back to guest via RX virtqueue

## Performance Considerations

- **Batch processing**: Process multiple descriptors per iteration
- **Zero-copy**: Use guest memory directly where possible
- **Interrupt coalescing**: Reduce VM exits with batched notifications

## TODO

- [ ] Batch pop/push operations in VirtQueue
- [ ] Integration with arcbox-net LockFreeRing
- [ ] Interrupt coalescing for high throughput
