# arcbox-cli

Command-line interface for ArcBox.

## Overview

This crate provides a thin command-line interface for ArcBox machine management and local integration helpers. Runtime and Docker API serving are handled by the separate `arcbox-daemon` binary.

## Features

- **Machine Management**: Create and manage Linux VMs
- **Daemon Lifecycle**: Start/stop daemon process
- **Docker Context Integration**: Seamless switching between Docker and ArcBox
- **Boot Asset & DNS Helpers**: Manage boot cache and resolver setup

## Usage

```bash
# Machine (VM) operations
arcbox machine create myvm
arcbox machine start myvm
arcbox machine list
arcbox machine stop myvm

# Daemon management
arcbox daemon start              # Start daemon in background
arcbox daemon stop               # Stop daemon
arcbox info                      # System info
arcbox version                   # Version info

# Docker context integration
arcbox docker enable             # Set ArcBox as Docker context
arcbox docker disable            # Reset to default context

# Run containers through Docker CLI
docker run hello-world
```

## Configuration

Socket path resolution order:
1. `ARCBOX_SOCKET` environment variable
2. `DOCKER_HOST` (with `unix://` prefix stripped)
3. Default: `~/.arcbox/docker.sock`

## License

MIT OR Apache-2.0
