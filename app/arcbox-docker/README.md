# arcbox-docker

Docker REST API compatibility layer for ArcBox.

## Overview

This crate provides a Docker-compatible API server that allows existing Docker CLI tools to work with ArcBox seamlessly. It acts as a host-side compatibility and proxy layer: some endpoints are handled by ArcBox handlers while pass-through requests are forwarded to guest `dockerd`.

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

- **Host route compatibility:** `/v1.24` through `/v1.43` plus unversioned routes
- **Version payload source:** `/version` and related system metadata are reported by guest `dockerd`

## License

MIT OR Apache-2.0
