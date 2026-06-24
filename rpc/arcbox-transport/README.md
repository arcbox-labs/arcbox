# arcbox-transport

Transport abstractions for ArcBox host/guest communication.

## Overview

This crate provides:

- `UnixTransport` for Unix domain sockets
- `VsockTransport` for virtio-vsock endpoints (`VsockAddr`)
- `VsockStream` for raw async byte streams backed by connected vsock fds
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

## Raw Vsock Streams

Use `VsockTransport` for framed ArcBox RPC traffic. Use `VsockStream` when a
caller already owns a connected fd and needs a transparent `AsyncRead +
AsyncWrite` byte stream, such as HTTP proxying or bidirectional tunnels.

```rust
use arcbox_transport::vsock::{VsockShutdown, VsockStream};
use std::os::fd::OwnedFd;

fn wrap_connected_fd(fd: OwnedFd) -> std::io::Result<VsockStream> {
    VsockStream::from_fd_with_shutdown(fd, VsockShutdown::CloseOnDropOnly)
}
```

`VsockShutdown` controls what happens when Tokio asks to shut down the write
half:

- `HalfClose` calls `shutdown(SHUT_WR)` and is the default for normal streams.
- `CloseOnDropOnly` treats shutdown as a no-op and closes only on drop. Use this
  for macOS vsock tunnels where half-close tears down the full connection.

## Port Notes

- `1024` is the guest agent RPC port used by `arcbox-agent`.
- Additional ports are protocol-specific (for example guest Docker API proxying)
  and are configured by higher-level runtime components.

## License

MIT OR Apache-2.0
