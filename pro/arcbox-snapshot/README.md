# arcbox-snapshot

Snapshot and restore functionality for ArcBox Pro.

## Overview

This crate provides full VM and container snapshot capabilities for ArcBox. It supports capturing complete VM state (vCPU registers, device state, memory), container checkpoints via CRIU, incremental snapshots, and LZ4 compression for efficient storage.

## Features

- **VM snapshots**: Full VM state capture (vCPU, devices, memory)
- **Container checkpoints**: CRIU-based container snapshots (Linux)
- **Incremental snapshots**: Efficient storage via parent references
- **Compression**: LZ4 compression for memory dumps
- **Scheduled backups**: Automatic snapshot creation

## Usage

```rust
use arcbox_snapshot::{SnapshotManager, SnapshotCreateOptions, SnapshotTargetType};
use std::path::PathBuf;

// Create snapshot manager
let manager = SnapshotManager::new(PathBuf::from("/var/lib/arcbox/snapshots"));

// Create a VM snapshot
let info = manager.create(
    "my-vm",
    SnapshotTargetType::Vm,
    SnapshotCreateOptions {
        name: Some("before-upgrade".to_string()),
        compress: true,
        ..Default::default()
    },
).await?;

// Restore from snapshot
manager.restore(&info.id).await?;
let restore_data = manager.take_restore_data(&info.id);

// List and prune snapshots
let snapshots = manager.list("my-vm");
let deleted = manager.prune(5).await?; // Keep last 5 per target
```

## License

BSL-1.1 (converts to MIT after 4 years)
