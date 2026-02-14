# arcbox-agent

Guest-side runtime agent for ArcBox VMs.

## Overview

The arcbox-agent runs inside ArcBox guest VMs and handles RPC requests from the host over vsock (port 1024). It manages container lifecycle, executes commands, handles PTY sessions for interactive containers, and streams logs to attached clients.

## Features

- **Container management**: Create, start, stop, remove containers
- **Command execution**: Run commands inside containers with PTY support
- **Log streaming**: Real-time log capture and broadcast to attach clients
- **VirtioFS mounts**: Mount host directories into containers
- **Process isolation**: Namespace and chroot isolation for containers

## Architecture

```
Host (arcbox-core)                    Guest VM (arcbox-agent)
       |                                      |
       +---- vsock (port 1024) -----> Agent (RPC server)
                                              |
                                    +---------+---------+
                                    |         |         |
                              Container    Exec     Log
                               Runtime   Sessions  Watcher
```

## Cross-Compilation

The agent must be cross-compiled for Linux since it runs inside guest VMs.

```bash
# Install cross-compilation toolchain (macOS)
brew install FiloSottile/musl-cross/musl-cross

# Add Rust target
rustup target add aarch64-unknown-linux-musl

# Build agent
cargo build -p arcbox-agent --target aarch64-unknown-linux-musl --release

# Output binary location
# target/aarch64-unknown-linux-musl/release/arcbox-agent
```

## Packaging

- Place binary at `/sbin/arcbox-agent` inside initramfs
- Init script must load vsock modules before starting agent:
  - `vsock`
  - `vmw_vsock_virtio_transport_common`
  - `vmw_vsock_virtio_transport`
- Agent listens on vsock port 1024

## License

MIT OR Apache-2.0
