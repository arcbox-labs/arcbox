# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox-agent crate.

## Overview

The arcbox-agent is the in-VM agent that runs inside ArcBox guest VMs. It listens on vsock port 1024 and handles RPC requests from the host, managing container lifecycle and executing commands within the guest VM.

**Note**: This crate requires cross-compilation for Linux targets since it runs inside Linux VMs.

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

### Key Files

| File | Description |
|------|-------------|
| `main.rs` | Entry point, initializes tracing and runs agent |
| `agent.rs` | Main RPC server, handles vsock connections and request dispatch |
| `container.rs` | Container lifecycle management (create/start/stop/remove) |
| `rpc.rs` | RPC protocol implementation (length-prefixed protobuf over vsock) |
| `shim.rs` | Process I/O shim, log capture, and broadcast to attach clients |
| `pty.rs` | PTY (pseudo-terminal) support for interactive sessions |
| `exec.rs` | Simple command execution helper |
| `log_watcher.rs` | Log file watching for `docker logs --follow` |
| `mount.rs` | Linux-specific mount operations (VirtioFS shares) |

## Key Types

### Core Types

- **`Agent`** - Main agent struct, listens on vsock and spawns connection handlers
- **`AgentState`** - Shared state across connections (runtime, exec processes)
- **`ContainerRuntime`** - Manages container metadata and process handles
- **`ContainerHandle`** - Container metadata (id, name, image, state, pid, etc.)
- **`ProcessHandle`** - Running process state (child, stdin, pty, broadcaster)

### RPC Types

- **`MessageType`** - RPC message type identifiers (request/response types)
- **`RpcRequest`** / **`RpcResponse`** - Request/response envelopes
- **`ErrorResponse`** - Error response with code and message

### I/O Types

- **`ProcessShim`** - Manages container I/O copying to log files and broadcast
- **`BroadcastWriter`** - Tee writer for attach clients (real-time log streaming)
- **`PtyHandle`** - PTY session management for interactive containers
- **`ExecSession`** - Exec session with optional PTY

## Wire Protocol

```
+----------------+----------------+----------------+
| Length (4B BE) | Type (4B BE)   | Payload        |
+----------------+----------------+----------------+
```

- Length: Total size of Type + Payload (big-endian)
- Type: Message type identifier (see `MessageType` enum)
- Payload: Protobuf-encoded message (`arcbox_protocol`)

## Container Isolation

When a rootfs is provided, containers are isolated using:
- Mount namespace (`CLONE_NEWNS`) for filesystem isolation
- Chroot to restrict filesystem access
- Special mounts (`/proc`, `/sys`, `/dev`) for proper Linux operation

## Cross-Compilation

The agent must be cross-compiled for Linux since it runs inside guest VMs.

```bash
# Install cross-compilation toolchain (macOS)
brew install FiloSottile/musl-cross/musl-cross

# Add Rust target
rustup target add aarch64-unknown-linux-musl

# Build agent
cargo build -p arcbox-agent --target aarch64-unknown-linux-musl --release

# Output binary
# target/aarch64-unknown-linux-musl/release/arcbox-agent
```

## Common Commands

```bash
# Build (native - for development/testing only)
cargo build -p arcbox-agent

# Build for Linux VM (release)
cargo build -p arcbox-agent --target aarch64-unknown-linux-musl --release

# Run tests (native)
cargo test -p arcbox-agent

# Run specific test
cargo test -p arcbox-agent test_container_lifecycle

# Lint
cargo clippy -p arcbox-agent -- -D warnings
```

## Platform Notes

- **Linux runtime only**: The full agent implementation is behind `#[cfg(target_os = "linux")]`
- **macOS stub**: A stub implementation exists for development/testing on macOS
- **vsock**: Uses `tokio-vsock` for host-guest communication
- **PTY**: Uses `nix` crate for PTY operations (differs between Linux/macOS)

## Dependencies

Key external dependencies:
- `tokio` + `tokio-vsock` - Async runtime and vsock support
- `prost` - Protobuf encoding/decoding
- `nix` - Unix system calls (PTY, signals, etc.)
- `arcbox_protocol` - Shared protobuf types with host
