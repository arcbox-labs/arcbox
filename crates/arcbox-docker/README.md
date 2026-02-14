# arcbox-docker

Docker REST API compatibility layer for ArcBox.

## Overview

This crate provides a Docker-compatible API server that allows existing Docker CLI tools to work with ArcBox seamlessly. It implements Docker Engine API v1.43, enabling transparent use of Docker commands with ArcBox as the backend.

## Features

- **Container Operations**: create, start, stop, kill, rm, ps, inspect, logs, exec, attach, wait, pause, unpause, top, stats
- **Image Operations**: pull, push, list, remove, tag, prune
- **Volume Operations**: create, list, inspect, remove, prune
- **Network Operations**: list, inspect, create, remove (basic)
- **System Operations**: info, version, ping, events, df

## Usage

The server listens on a Unix socket that can be configured as a Docker context:

```bash
# Create and use ArcBox Docker context
docker context create arcbox --docker "host=unix://$HOME/.arcbox/docker.sock"
docker context use arcbox

# Now Docker CLI uses ArcBox
docker ps
docker run alpine echo hello
docker images
```

## Architecture

```text
docker CLI ──► Unix Socket ──► arcbox-docker ──► arcbox-core
                                     │
                                     ▼
                              HTTP REST API
                             (Axum server)
```

## API Version

- **Current**: Docker Engine API v1.43 (Docker 24.0)
- **Minimum Supported**: v1.24

## License

MIT OR Apache-2.0
