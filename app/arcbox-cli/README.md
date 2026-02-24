# arcbox-cli

Command-line interface for ArcBox.

## Overview

This crate provides a Docker-compatible command-line interface for container and VM management. It communicates with the ArcBox daemon via Unix socket using the Docker-compatible REST API.

## Features

- **Docker-Compatible Commands**: Familiar syntax for Docker users
- **Container Management**: run, start, stop, rm, ps, logs, exec
- **Image Operations**: pull, images, rmi
- **Machine Management**: Create and manage Linux VMs
- **Docker Context Integration**: Seamless switching between Docker and ArcBox

## Usage

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

# Daemon management
arcbox daemon                    # Start daemon
arcbox info                      # System info
arcbox version                   # Version info

# Docker context integration
arcbox docker use                # Set ArcBox as Docker context
arcbox docker reset              # Reset to default context
```

## Configuration

Socket path resolution order:
1. `ARCBOX_SOCKET` environment variable
2. `DOCKER_HOST` (with `unix://` prefix stripped)
3. Default: `~/.arcbox/docker.sock`

## License

MIT OR Apache-2.0
