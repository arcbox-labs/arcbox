# arcbox-transport

Transport abstractions for ArcBox host/guest communication.

## Overview

This crate provides:

- `UnixTransport` for Unix domain sockets
- `VsockTransport` for virtio-vsock endpoints (`VsockAddr`)
- `Transport` / `TransportListener` traits for transport-agnostic code

## Usage

```rust
use arcbox_transport::{Transport, UnixTransport, VsockTransport};
use arcbox_transport::vsock::VsockAddr;
use bytes::Bytes;

let mut unix = UnixTransport::new("/var/run/arcbox.sock");
unix.connect().await?;
unix.send(Bytes::from("hello")).await?;

let mut vsock = VsockTransport::new(VsockAddr::new(3, 1024));
vsock.connect().await?;
vsock.send(Bytes::from("ping")).await?;
```

## Port Notes

- `1024` is the guest agent RPC port used by `arcbox-agent`.
- Additional ports are protocol-specific (for example guest Docker API proxying)
  and are configured by higher-level runtime components.

## License

MIT OR Apache-2.0
