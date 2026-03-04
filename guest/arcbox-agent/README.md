# arcbox-agent

Guest-side agent for ArcBox VMs.

## Overview

`arcbox-agent` runs inside the Linux guest and serves host requests over vsock
(port `1024`). Its active RPC surface focuses on host/guest liveness and runtime
readiness, not full container lifecycle RPCs.

Current request surface includes:

- Ping
- System information
- Ensure guest runtime stack (`containerd`/`dockerd`/`runc`) is ready
- Runtime status

When running as PID 1, the agent also performs basic system initialisation
(mount filesystems, set hostname, spawn a child reaper).

## Runtime Bootstrap Role

At startup, the agent detects and launches the bundled runtime stack
(`containerd` / `dockerd` / `runc`) so the host-side Docker API proxy can
target a healthy guest `dockerd` endpoint.

## Cross-Compilation

```bash
brew install FiloSottile/musl-cross/musl-cross
rustup target add aarch64-unknown-linux-musl
cargo build -p arcbox-agent --target aarch64-unknown-linux-musl --release
```

## License

MIT OR Apache-2.0
