# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox-docker crate.

## Overview

Docker Engine API v1.43 compatibility layer. Provides REST API endpoints that allow standard Docker CLI to work with ArcBox.

## Architecture

```
arcbox-docker/src/
├── lib.rs          # Crate entry
├── server.rs       # Axum HTTP server setup
├── api.rs          # AppState, router configuration
├── handlers.rs     # Request handlers (40+ endpoints)
├── types.rs        # Docker API request/response types
└── error.rs        # DockerError → HTTP response
```

## Server Setup

```rust
// Listens on Unix socket: ~/.arcbox/docker.sock
pub async fn run_server(runtime: Arc<Runtime>, socket_path: &Path) -> Result<()> {
    let app = Router::new()
        .route("/containers/json", get(list_containers))
        .route("/containers/create", post(create_container))
        // ... 40+ more routes
        .with_state(AppState { runtime });

    let listener = UnixListener::bind(socket_path)?;
    axum::serve(listener, app).await?;
}
```

## Implemented Endpoints

| Category | Endpoints |
|----------|-----------|
| Containers | create, start, stop, kill, rm, ps, inspect, logs, exec, attach, wait, pause, unpause, top, stats, diff, prune |
| Images | list, pull, inspect, rm, tag, prune |
| Volumes | create, list, inspect, rm, prune |
| Networks | list, inspect, create, rm (basic) |
| System | info, version, ping, events, df |

## Request Flow

```
Docker CLI
    ↓ HTTP request
Unix Socket (~/.arcbox/docker.sock)
    ↓
Axum Router
    ↓
Handler (handlers.rs)
    ↓
Runtime (arcbox-core)
    ↓
Guest Agent (vsock)
```

## Error Handling

```rust
pub enum DockerError {
    ContainerNotFound(String),  // 404
    ImageNotFound(String),      // 404
    InvalidParameter(String),   // 400
    Conflict(String),           // 409
    Server(String),             // 500
    NotImplemented(String),     // 501
}
```

## Common Commands

```bash
cargo build -p arcbox-docker
cargo test -p arcbox-docker

# Test with Docker CLI
export DOCKER_HOST=unix://$HOME/.arcbox/docker.sock
docker ps
docker run alpine echo hello
```

## Compatibility Notes

- API version: 1.43 (Docker 24.0)
- Streaming logs via HTTP chunked transfer
- Exec attach via HTTP upgrade to raw TCP
- Events via Server-Sent Events (SSE)
