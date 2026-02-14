# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox-transport crate.

## Overview

Transport layer abstraction for host-guest communication. Provides vsock transport for both macOS (Virtualization.framework) and Linux.

## Architecture

```
arcbox-transport/src/
├── lib.rs          # Crate entry, Transport trait
├── vsock.rs        # VsockTransport implementation
└── error.rs        # TransportError
```

## Transport Trait

```rust
#[async_trait]
pub trait Transport: Send + Sync {
    async fn connect(&self, cid: u32, port: u32) -> Result<Box<dyn Connection>>;
    async fn listen(&self, port: u32) -> Result<Box<dyn Listener>>;
}

#[async_trait]
pub trait Connection: AsyncRead + AsyncWrite + Send + Sync {
    fn peer_cid(&self) -> u32;
}
```

## VsockTransport

```rust
pub struct VsockTransport {
    // Platform-specific implementation
    #[cfg(target_os = "macos")]
    vm_handle: VzVmHandle,  // From Virtualization.framework

    #[cfg(target_os = "linux")]
    // Uses /dev/vsock
}
```

## CID Allocation

- CID 0: Reserved (hypervisor)
- CID 1: Reserved (local)
- CID 2: Host
- CID 3+: Guest VMs

## Port Convention

| Port | Service |
|------|---------|
| 1024 | Agent main service |
| 1025 | Agent streaming (logs, attach) |

## Common Commands

```bash
cargo build -p arcbox-transport
cargo test -p arcbox-transport
```

## Platform Notes

### macOS
Uses `VZVirtioSocketDevice` from Virtualization.framework. Connection established via Objective-C FFI.

### Linux
Uses standard vsock (`AF_VSOCK` socket family). Requires `/dev/vsock` device.
