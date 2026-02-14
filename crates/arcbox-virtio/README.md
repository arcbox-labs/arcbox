# arcbox-virtio

VirtIO device implementations for ArcBox.

## Overview

This crate provides VirtIO paravirtualized device emulation, enabling high-performance I/O between guest VMs and the host. It implements the standard VirtIO specification for various device types.

## Features

- **virtio-blk**: Block device with async file backend
- **virtio-net**: Network device for VM networking
- **virtio-console**: Serial console I/O
- **virtio-fs**: Shared filesystem using FUSE protocol
- **virtio-vsock**: Host-guest socket communication
- **VirtQueue**: Standard virtqueue implementation with descriptor chains

## Architecture

```
+------------------------------------------+
|             arcbox-virtio                |
|  +-----+ +-----+ +-----+ +-----+ +-----+ |
|  | blk | | net | |cons | | fs  | |vsock| |
|  +--+--+ +--+--+ +--+--+ +--+--+ +--+--+ |
|     +-------+-------+-------+-------+    |
|                     |                    |
|                VirtQueue                 |
+------------------------------------------+
```

## Usage

```rust
use arcbox_virtio::{VirtioDevice, VirtioDeviceId, VirtQueue};

// VirtIO devices implement the VirtioDevice trait
pub trait VirtioDevice: Send + Sync {
    fn device_id(&self) -> VirtioDeviceId;
    fn features(&self) -> u64;
    fn ack_features(&mut self, features: u64);
    fn read_config(&self, offset: u64, data: &mut [u8]);
    fn write_config(&mut self, offset: u64, data: &[u8]);
    fn activate(&mut self) -> Result<()>;
    fn reset(&mut self);
}
```

## VirtQueue Processing Pattern

```rust
loop {
    // 1. Pop available descriptor chains from guest
    while let Some(chain) = virtqueue.pop_avail() {
        // 2. Process I/O request
        let result = process_request(&chain);

        // 3. Push completed descriptors back
        virtqueue.push_used(chain.head, result.len);
    }
    // 4. Signal guest if needed
    virtqueue.notify_guest();
}
```

## License

MIT OR Apache-2.0
