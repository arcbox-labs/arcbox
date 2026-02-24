# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox-cli crate.

## Overview

`arcbox-cli` is the command-line interface for ArcBox, providing Docker-compatible commands for container and VM management. It communicates with the ArcBox daemon via Unix socket using the Docker-compatible REST API.

## Architecture

```
crates/arcbox-cli/src/
├── lib.rs              # Library exports (client, terminal)
├── main.rs             # CLI entry point and command routing
├── client.rs           # DaemonClient for HTTP/Unix socket communication
├── terminal.rs         # Terminal utilities
└── commands/           # Command implementations
    ├── mod.rs          # Command enum definitions
    ├── run.rs          # arcbox run
    ├── start.rs        # arcbox start
    ├── stop.rs         # arcbox stop
    ├── ps.rs           # arcbox ps
    ├── rm.rs           # arcbox rm
    ├── logs.rs         # arcbox logs
    ├── exec.rs         # arcbox exec
    ├── images.rs       # arcbox images / rmi
    ├── pull.rs         # arcbox pull
    ├── machine.rs      # arcbox machine (create/start/stop/list)
    ├── boot.rs         # arcbox boot (low-level VM boot)
    ├── daemon.rs       # arcbox daemon
    ├── docker.rs       # arcbox docker (context management)
    └── version.rs      # arcbox version
```

## Key Types

### DaemonClient

HTTP client for Unix socket communication with the daemon:

```rust
use arcbox_cli::client::{DaemonClient, get_client};

// Create client (auto-resolves socket path)
let client = DaemonClient::new();

// Or with custom socket
let client = DaemonClient::with_socket("/path/to/socket");

// Check daemon status
if client.is_running().await {
    // Make requests
    let containers: Vec<ContainerSummary> = client
        .get("/v1.43/containers/json?all=true")
        .await?;
}
```

### Socket Path Resolution

Socket path is resolved in order:
1. `ARCBOX_SOCKET` environment variable
2. `DOCKER_HOST` (with `unix://` prefix stripped)
3. Default: `~/.arcbox/docker.sock`

### Request Methods

```rust
// GET request with JSON response
let containers: Vec<ContainerSummary> = client.get("/path").await?;

// POST with JSON body
let response: CreateContainerResponse = client.post("/path", Some(body)).await?;

// POST without response body
client.post_empty("/path", Some(body)).await?;

// DELETE
client.delete("/path").await?;

// Streaming logs with callback
client.stream_logs("/containers/{id}/logs?follow=true", |data| {
    print!("{}", String::from_utf8_lossy(data));
}).await?;

// Connection upgrade for exec/attach
let stream = client.upgrade_exec(exec_id, Some(body)).await?;
```

### Command Structure

Commands use clap for argument parsing:

```rust
#[derive(Parser)]
struct Cli {
    #[arg(short, long)]
    debug: bool,

    #[arg(short, long)]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run(RunArgs),
    Start(StartArgs),
    Stop(StopArgs),
    // ...
}
```

## Common Commands

```bash
# Build CLI
cargo build -p arcbox-cli

# Run CLI commands
cargo run --bin arcbox -- ps
cargo run --bin arcbox -- run alpine echo hello
cargo run --bin arcbox -- logs -f <container>

# Run with debug logging
cargo run --bin arcbox -- --debug ps

# Specify custom socket
cargo run --bin arcbox -- --socket /tmp/arcbox.sock ps
```

## CLI Usage Examples

```bash
# Container operations
arcbox run -it alpine sh
arcbox run -d nginx
arcbox ps -a
arcbox logs -f <container>
arcbox exec -it <container> sh
arcbox stop <container>
arcbox rm <container>

# Image operations
arcbox pull nginx:latest
arcbox images
arcbox rmi nginx:latest

# Machine (VM) operations
arcbox machine create myvm
arcbox machine start myvm
arcbox machine list
arcbox machine stop myvm

# Daemon
arcbox daemon                    # Start daemon
arcbox info                      # System info
arcbox version                   # Version info

# Docker context integration
arcbox docker use                # Set ArcBox as Docker context
arcbox docker reset              # Reset to default context
```

## Dependencies

- `arcbox-core`: Runtime and configuration
- `clap`: Command-line argument parsing
- `hyper`: HTTP client for Unix socket
- `tokio`: Async runtime
- `serde`/`serde_json`: JSON serialization
