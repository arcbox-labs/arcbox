# arcbox-agent

Guest-side agent for ArcBox VMs.

## Overview

`arcbox-agent` runs inside the Linux guest and serves host requests over vsock
(port `1024`). Its active RPC surface focuses on host/guest liveness and runtime
readiness, not full container lifecycle RPCs.

Current request surface includes:

- Ping
- System information
- Ensure guest runtime stack (`containerd`/`dockerd`/`youki`) is ready
- Runtime status

The agent also handles machine bootstrap responsibilities when running in
initramfs/PID1 mode.

## Runtime Bootstrap Role

At startup, the agent can provision and verify guest runtime prerequisites so
host-side Docker API proxying can target a healthy guest `dockerd` endpoint.

## Cross-Compilation

```bash
brew install FiloSottile/musl-cross/musl-cross
rustup target add aarch64-unknown-linux-musl
cargo build -p arcbox-agent --target aarch64-unknown-linux-musl --release
```

## License

MIT OR Apache-2.0
