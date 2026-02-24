# arcbox-transport

Transport layer abstractions for ArcBox host-guest communication.

## Overview

This crate provides transport implementations for communication between the ArcBox host daemon and guest VMs:

- **UnixTransport**: Unix domain sockets for CLI <-> Daemon and Docker compatibility
- **VsockTransport**: Virtio socket for high-performance Host <-> Guest communication

## Architecture

```text
+---------------------------------------------------+
|               arcbox-transport                     |
|                                                   |
|  +--------------+          +-----------------+    |
|  |    Unix      |          |     Vsock       |    |
|  |  Transport   |          |   Transport     |    |
|  +------+-------+          +--------+--------+    |
|         |                           |             |
|         v                           v             |
|  +--------------+          +-----------------+    |
|  | /var/run/    |          |    vsock CID    |    |
|  | arcbox.sock  |          |    + port       |    |
|  +--------------+          +-----------------+    |
+---------------------------------------------------+
```

## Features

- Async-first design with tokio
- Cross-platform vsock support (macOS Virtualization.framework / Linux)
- Unified `Transport` trait for transport-agnostic code

## Usage

```rust
use arcbox_transport::{Transport, VsockTransport, UnixTransport};
use bytes::Bytes;

// Unix socket transport
let mut unix = UnixTransport::new("/var/run/arcbox.sock");
unix.connect().await?;
unix.send(Bytes::from("hello")).await?;
let response = unix.recv().await?;

// Vsock transport (Host <-> Guest)
let mut vsock = VsockTransport::new(3, 1024); // CID 3, port 1024
vsock.connect().await?;
vsock.send(Bytes::from("ping")).await?;
```

## Port Convention

| Port | Service |
|------|---------|
| 1024 | Agent main service |
| 1025 | Agent streaming (logs, attach) |

## License

MIT OR Apache-2.0
