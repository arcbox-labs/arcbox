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
docker CLI ──► Unix socket ──► Axum router ──► local handlers
                                      │
                                      └──────► proxy ──► vsock ──► guest dockerd
```

The router strips Docker API version prefixes before route matching and stores
the original URI for proxy forwarding. A request-context middleware derives the
target utility VM role once from the URI and stores it in request extensions.
Requests then take one of three paths:

- **Local handlers** implement ArcBox-owned behavior such as host path
  normalization, workload role tracking, and lifecycle orchestration. The route
  table intentionally contains only these endpoints.
- **Ordinary pass-through** uses the Axum fallback for endpoints that do not
  need ArcBox-specific behavior, then relays non-upgrade HTTP/1.1 requests to
  guest `dockerd` through a pooled hyper client.
- **Special proxy forwarding** handles streaming uploads and HTTP upgrades with
  dedicated connection lifecycles instead of the ordinary pool.

## Proxy Design

The proxy is split by protocol behavior rather than Docker endpoint category:

| Module | Responsibility |
| --- | --- |
| `connector.rs` | Production vsock connection establishment via `arcbox-core` runtime |
| `forward.rs` | Ordinary HTTP/1.1 request/response forwarding |
| `upload.rs` | Large streamed upload requests, including build contexts and image loads |
| `upgrade.rs` | HTTP upgrade tunnels for attach, exec, and BuildKit-style streams |
| `fallback.rs` | Catch-all forwarding for routes not explicitly handled by Axum |
| `headers.rs` | End-to-end header filtering and forwarding rules |
| `session.rs` | Guest HTTP client/session setup and pooled client adapter |
| `uri.rs` | Guest path/query normalization |

### Ordinary HTTP forwarding

Ordinary non-upgrade requests use `GuestHttpClient`, which wraps
`hyper-util::client::legacy::Client` with HTTP/1.1 connection pooling:

- up to 8 idle guest connections per internal authority;
- 30 second idle timeout;
- response bodies stream back to the Docker CLI without full buffering;
- hyper-util returns a connection to the pool only after the response body is
  fully consumed, and discards it if the body is dropped early or errors.

The pool key is the request URI authority, so ArcBox uses internal authorities
to separate utility VM roles:

```text
http://native.arcbox.internal/...   ──► UtilityVmRole::Native
http://rosetta.arcbox.internal/...  ──► UtilityVmRole::Rosetta
```

The internal authority is only for hyper-util pooling and role selection. The
guest request still carries `Host: localhost` and is sent over the selected
vsock connection.

### Upload and upgrade paths

Streaming uploads and HTTP upgrades intentionally do not use the ordinary
pooled client:

- upload forwarding can return the guest response while the client request body
  is still draining in the background;
- upgrade forwarding takes ownership of the raw HTTP/1.1 connection and then
  tunnels bytes after the `101 Switching Protocols` response.

Keeping these paths on dedicated connections avoids corrupting pooled HTTP/1.1
state with partially-drained request bodies or upgraded protocols.

### Guest transport

Production proxy connections are opened through `VsockConnector`, which asks
`arcbox-core` for the selected utility VM's dockerd vsock port. The underlying
file descriptor is wrapped by `arcbox_transport::vsock::VsockStream`, giving
the proxy one async stream abstraction for both production vsock and Unix-socket
integration tests.

## API Version

- **Host route compatibility:** `/v1.24` through `/v1.43` plus unversioned routes
- **Version payload source:** `/version` and related system metadata are reported by guest `dockerd`

## Testing

Focused proxy checks:

```bash
cargo test -p arcbox-docker proxy::
cargo test -p arcbox-docker --test proxy_integration
```

The integration tests run against a mock guest `dockerd` over a Unix socket, so
they do not require a VM. They cover ordinary forwarding, pooled session reuse,
early body-drop discard behavior, streaming forwarding, and HTTP upgrade
handling.

## License

MIT OR Apache-2.0
