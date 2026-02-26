# firecracker-vmm

A production-grade sandbox manager built on top of
[`fc-sdk`](../firecracker-client) that orchestrates multiple
[Firecracker](https://firecracker-microvm.github.io/) microVMs and exposes
a self-contained [gRPC](https://grpc.io/) interface (`sandbox.v1`).

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                        vmm-daemon                              │
│   (CLI args · config · signal handling · tokio runtime)        │
└───────────────────────────┬────────────────────────────────────┘
                            │
            ┌───────────────▼──────────────┐
            │         vmm-grpc             │
            │  tonic gRPC server           │
            │  ┌──────────────────────┐    │
            │  │  SandboxService      │    │  ◄── sandbox.v1 proto
            │  │  SandboxSnapshot     │    │
            │  │  Service             │    │
            │  └──────────┬───────────┘    │
            └─────────────┼────────────────┘
                          │
            ┌─────────────▼────────────────┐
            │         vmm-core             │
            │  SandboxManager              │
            │  ┌────────────────────────┐  │
            │  │  SandboxInstance       │  │
            │  │  registry              │  │
            │  │  (Arc<RwLock<...>>)    │  │
            │  └────────────────────────┘  │
            │  NetworkManager (TAP / IP)   │
            │  SnapshotCatalog             │
            └─────────────┬────────────────┘
                          │
            ┌─────────────▼────────────────┐
            │           fc-sdk             │
            │  VmBuilder / VmProcess / Vm  │
            └─────────────┬────────────────┘
                          │
            ┌─────────────▼────────────────┐
            │  Firecracker process (unix   │
            │  socket per VM)              │
            └──────────────────────────────┘
```

### Crates

| Crate | Type | Purpose |
|-------|------|---------|
| `vmm-core` | lib | Sandbox orchestration, state, networking, snapshots |
| `vmm-grpc` | lib | gRPC server + service implementations |
| `vmm-daemon` | bin | Daemon entrypoint |
| `vmm-cli` | bin | Management CLI (gRPC client) |

---

## Features

### Sandbox Lifecycle
- **Create** — provision kernel + rootfs, allocate TAP, configure and boot Firecracker; returns immediately (async boot)
- **Stop** — graceful halt with configurable timeout, then force-kill
- **Remove** — stop, release TAP, clean up all resources
- **List / Inspect** — live in-memory registry with full hardware/network detail
- **Events** — streaming sandbox lifecycle events (filtered by ID or action)

### Checkpoint / Restore
- **Checkpoint** — pause VM, write vmstate + memory snapshot, resume
- **Restore** — boot a new sandbox from an existing checkpoint
- **List / Delete** — manage checkpoints on disk

### Process Options
- Direct Firecracker mode or Jailer sandbox
- Configurable per-sandbox resources (vCPUs, memory)
- Auto-destroy TTL per sandbox

### gRPC Interface
- Unix socket transport (default: `/run/firecracker-vmm/vmm.sock`)
- Optional TCP transport (e.g. `127.0.0.1:9090`)
- Self-contained `sandbox.v1` proto — no external proto dependencies

---

## gRPC Services

### `sandbox.v1.SandboxService`

| RPC | Description |
|-----|-------------|
| `Create` | Boot a new sandbox (returns immediately; VM boots async) |
| `Run` | Execute a workload in a sandbox *(future: vsock guest agent)* |
| `Exec` | Attach to a running workload *(future: vsock guest agent)* |
| `Stop` | Stop a running sandbox gracefully |
| `Remove` | Delete sandbox and release all resources |
| `Inspect` | Full sandbox detail (hardware, network, state) |
| `List` | List sandboxes with optional state filter |
| `Events` | Stream sandbox lifecycle events |

### `sandbox.v1.SandboxSnapshotService`

| RPC | Description |
|-----|-------------|
| `Checkpoint` | Pause, snapshot, and resume a sandbox |
| `Restore` | Boot a new sandbox from a checkpoint |
| `ListSnapshots` | List checkpoints (optionally filtered by sandbox ID) |
| `DeleteSnapshot` | Remove a checkpoint and its on-disk data |

---

## Sandbox State Machine

```
            create()
               │
               ▼
          ┌─────────┐
          │ starting│ (VM booting in background)
          └────┬────┘
               │  boot success
               ▼
          ┌─────────┐
          │  ready  │ (VM running, awaiting workload)
          └────┬────┘
               │  run()
               ▼
          ┌─────────┐
          │ running │ (workload executing)
          └────┬────┘
               │  workload exits
               ▼
          ┌─────────┐ ◄── workload exits (returns to ready)
          │  ready  │
          └────┬────┘
               │  stop()
               ▼
         ┌──────────┐
         │ stopping │
         └────┬─────┘
              │
              ▼
         ┌─────────┐
         │ stopped │
         └─────────┘

  boot failure → failed
```

---

## Data Layout

```
/var/lib/firecracker-vmm/
├── kernels/
│   └── vmlinux               # default kernel
├── images/
│   └── ubuntu-22.04.ext4     # default rootfs
├── sandboxes/
│   └── {sandbox-id}/
│       ├── firecracker.sock  # Firecracker API socket (while running)
│       ├── firecracker.log
│       └── firecracker.metrics
└── snapshots/
    └── {sandbox-id}/
        └── {snapshot-id}/
            ├── vmstate       # Firecracker VM state file
            ├── mem           # memory file (full snapshots)
            └── meta.json     # snapshot metadata
```

---

## Configuration

Default location: `/etc/firecracker-vmm/config.toml`

```toml
[firecracker]
binary   = "/usr/bin/firecracker"
data_dir = "/var/lib/firecracker-vmm"

# Process-level options (all optional)
log_level                 = "Warning"   # Error | Warning | Info | Debug | Trace
no_seccomp                = false
# seccomp_filter          = "/etc/fc-seccomp.bpf"
# http_api_max_payload_size = 51200
# mmds_size_limit           = 51200
# socket_timeout_secs       = 5

# Jailer sandbox (omit this section to run without jailer)
# [firecracker.jailer]
# binary          = "/usr/bin/jailer"
# uid             = 1000
# gid             = 1000
# chroot_base_dir = "/srv/jailer"
# netns           = "/var/run/netns/myns"
# new_pid_ns      = false
# cgroup_version  = "2"
# parent_cgroup   = "firecracker"
# resource_limits = ["fsize=2048"]

[network]
bridge   = "fcvmm0"
cidr     = "172.20.0.0/16"
gateway  = "172.20.0.1"
dns      = ["1.1.1.1", "8.8.8.8"]

[grpc]
unix_socket = "/run/firecracker-vmm/vmm.sock"
tcp_addr    = ""                        # empty = disabled

[defaults]
vcpus      = 1
memory_mib = 512
kernel     = "/var/lib/firecracker-vmm/kernels/vmlinux"
rootfs     = "/var/lib/firecracker-vmm/images/ubuntu-22.04.ext4"
boot_args  = "console=ttyS0 reboot=k panic=1 pci=off"
```

---

## Quick Start

```bash
# Start daemon
vmm-daemon --config /etc/firecracker-vmm/config.toml

# Create a sandbox (returns immediately; VM boots async)
vmm create --vcpus 2 --memory 1024

# Create with explicit kernel/rootfs
vmm create --kernel /path/to/vmlinux --rootfs /path/to/root.ext4

# Create with labels and 5-minute auto-destroy TTL
vmm create --label env=dev --label owner=alice --ttl 300

# List sandboxes
vmm list

# Filter by state
vmm list --state ready

# Inspect a sandbox
vmm inspect <sandbox-id>

# Watch live events
vmm events

# Watch events for a specific sandbox
vmm events --id <sandbox-id>

# Stop and remove
vmm stop <sandbox-id>
vmm remove <sandbox-id>
vmm remove --force <sandbox-id>

# Checkpoint management
vmm snapshot create <sandbox-id> --name my-checkpoint
vmm snapshot list
vmm snapshot list --sandbox-id <sandbox-id>
vmm snapshot restore <snapshot-id> --ttl 600
vmm snapshot delete <snapshot-id>
```

---

## Development

### Prerequisites

- Rust 1.82+ (edition 2024)
- `firecracker` binary (set `[firecracker].binary` in config or add to PATH)
- Linux with `CAP_NET_ADMIN` for TAP interface creation
- `protoc` for proto codegen

### Build

```bash
cargo build --workspace
```

### Test

```bash
# Unit + integration (no Firecracker required)
cargo test --workspace

# e2e (requires firecracker binary + CAP_NET_ADMIN)
cargo test --test e2e -- --ignored
```

### Lint

```bash
cargo clippy --workspace -- -D warnings
cargo fmt --check
```

---

## License

MIT OR Apache-2.0
