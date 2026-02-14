# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox-snapshot crate.

## Overview

Snapshot and restore functionality for ArcBox Pro. Features:

- **VM snapshots**: Full VM state capture (vCPU, devices, memory)
- **Container checkpoints**: CRIU-based container snapshots (Linux)
- **Incremental snapshots**: Efficient storage via parent references
- **Scheduled backups**: Automatic snapshot creation
- **Compression**: LZ4 compression for memory dumps

## License

BSL-1.1 (converts to MIT after 4 years)

## Architecture

```
arcbox-snapshot/src/
└── lib.rs      # SnapshotManager, SnapshotInfo, VmRestoreData, compression utils
```

### Dependencies

Integrates with arcbox-hypervisor for VM state types:
```
arcbox-snapshot → arcbox-hypervisor (VmSnapshot, VcpuSnapshot, DeviceSnapshot)
```

### Storage Layout

```
<base_dir>/
└── <snapshot_id>/
    ├── snapshot.json           # SnapshotInfo metadata
    ├── vm_state.json           # VmSnapshot (vCPU/device state)
    ├── memory.bin              # Raw memory dump
    ├── memory.bin.lz4          # Compressed memory dump (if compress=true)
    └── container_checkpoint.json  # Container checkpoint (for containers)
    └── criu/                   # CRIU checkpoint files (Linux only)
```

## Key Types

| Type | Description |
|------|-------------|
| `SnapshotManager` | Main API for create/restore/delete/prune operations |
| `SnapshotInfo` | Snapshot metadata (id, name, target, size, state) |
| `SnapshotCreateOptions` | Options for snapshot creation |
| `SnapshotTargetType` | `Vm` or `Container` |
| `SnapshotState` | `Creating`, `Ready`, or `Invalid` |
| `VmSnapshotContext` | Caller-provided VM state for capture |
| `VmRestoreData` | Restored VM state (vCPUs, devices, memory) |
| `SnapshotError` | Error types (NotFound, Io, Corrupted, etc.) |

## Key Operations

```rust
// Create snapshot
let info = manager.create(target_id, SnapshotTargetType::Vm, options).await?;

// Capture with full context (production use)
manager.capture_vm_snapshot_with_context(dir, id, options, context).await?;

// Restore
manager.restore(snapshot_id).await?;
let restore_data = manager.take_restore_data(snapshot_id);

// List/prune
let snapshots = manager.list(target_id);
let deleted = manager.prune(keep_count).await?;
```

## Status

Pro layer is substantially implemented:
- Full SnapshotManager with create/restore/delete/prune
- VM snapshot capture with vCPU/device/memory state
- LZ4 compression for memory dumps
- Incremental snapshot support (parent references)
- CRIU integration for container checkpoints (Linux, feature-gated)

TODO:
- Scheduled backup automation
- Deduplication between incremental snapshots
- Remote snapshot storage

## Common Commands

```bash
# Build
cargo build -p arcbox-snapshot

# Test
cargo test -p arcbox-snapshot

# Build with CRIU support (Linux only)
cargo build -p arcbox-snapshot --features criu

# Build with release optimizations
cargo build -p arcbox-snapshot --release
```
