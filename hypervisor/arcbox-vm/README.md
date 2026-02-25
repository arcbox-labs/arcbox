# firecracker-vmm

A production-grade VM Manager built on top of
[`fc-sdk`](../firecracker-client) that orchestrates multiple
[Firecracker](https://firecracker-microvm.github.io/) microVMs and exposes
a [gRPC](https://grpc.io/) interface compatible with the
[arcbox-protocol](../arcbox/comm/arcbox-protocol/proto).

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
            │  │  MachineService      │    │  ◄── arcbox.v1 proto
            │  │  SystemService       │    │
            │  │  VmmService          │    │  ◄── vmm.v1 proto (extensions)
            │  └──────────┬───────────┘    │
            └─────────────┼────────────────┘
                          │
            ┌─────────────▼────────────────┐
            │         vmm-core             │
            │  VmmManager                  │
            │  ┌────────────────────────┐  │
            │  │  VmInstance registry   │  │
            │  │  (Arc<RwLock<...>>)    │  │
            │  └────────────────────────┘  │
            │  VmStore  (disk persistence) │
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
| `vmm-core` | lib | Multi-VM orchestration, state, networking, snapshots |
| `vmm-grpc` | lib | gRPC server + service implementations |
| `vmm-daemon` | bin | Daemon entrypoint |
| `vmm-cli` | bin | Management CLI (gRPC client) |

---

## Features

### VM Lifecycle
- **Create** — provision kernel + rootfs, allocate TAP, configure and boot Firecracker
- **Start / Stop** — resume or gracefully halt (Ctrl+Alt+Del) or force-kill
- **Remove** — stop, release TAP, clean up socket and store entry
- **List / Inspect** — live registry with full hardware/network/OS detail

### Snapshots
- Full snapshots (memory + VM state)
- Diff snapshots (dirty pages only, requires `track_dirty_pages`)
- Snapshot catalog per VM with metadata
- Restore from any catalog entry

### Live Updates (post-boot)
- Balloon memory adjustment
- Memory hotplug size update
- Network interface rate limiter update
- Drive hot-swap

### gRPC Interface
- Unix socket transport (default: `/run/firecracker-vmm/vmm.sock`)
- Optional TCP transport
- Protocol-compatible with `arcbox.v1.MachineService`
- VMM-specific extensions via `vmm.v1.VmmService`

---

## gRPC Services

### `arcbox.v1.MachineService` (arcbox-protocol compatible)

```
Create       → boot a new VM
Start        → start a stopped VM
Stop         → stop a running VM
Remove       → delete a VM
List         → list all VMs
Inspect      → full VM detail
Ping         → guest agent health check (future: vsock)
GetSystemInfo→ guest OS info (future: vsock)
Exec         → run command in guest (future: vsock)
SSHInfo      → SSH connection details
```

### `arcbox.v1.SystemService`

```
GetInfo      → daemon stats (VM counts, host info)
GetVersion   → daemon version
Ping         → liveness probe
Events       → stream VM lifecycle events
```

### `vmm.v1.VmmService` (VMM-specific extensions)

```
Pause            → pause a running VM
Resume           → resume a paused VM
CreateSnapshot   → create full or diff snapshot
ListSnapshots    → list snapshot catalog for a VM
RestoreSnapshot  → restore VM from snapshot
DeleteSnapshot   → remove snapshot from catalog
GetMetrics       → balloon stats + instance info
UpdateBalloon    → adjust memory balloon target
UpdateMemory     → hotplug memory size change
```

---

## Data Layout

```
/var/lib/firecracker-vmm/
├── kernels/
│   └── vmlinux               # default kernel
├── images/
│   └── ubuntu-22.04.ext4     # default rootfs
├── vms/
│   └── {vm-id}/
│       ├── meta.json         # VmSpec + state + timestamps
│       ├── firecracker.sock  # API socket (while running)
│       ├── firecracker.log
│       └── firecracker.metrics
└── snapshots/
    └── {vm-id}/
        └── {snapshot-id}/
            ├── vmstate
            ├── mem           # full snapshots only
            └── meta.json
```

---

## Configuration

Default location: `/etc/firecracker-vmm/config.toml`

```toml
[firecracker]
binary   = "/usr/bin/firecracker"
jailer   = ""
data_dir = "/var/lib/firecracker-vmm"

[network]
bridge   = "fcvmm0"
cidr     = "172.20.0.0/16"
gateway  = "172.20.0.1"
dns      = ["1.1.1.1", "8.8.8.8"]

[grpc]
unix_socket = "/run/firecracker-vmm/vmm.sock"
tcp_addr    = ""

[defaults]
vcpus      = 1
memory_mib = 512
kernel     = "/var/lib/firecracker-vmm/kernels/vmlinux"
rootfs     = "/var/lib/firecracker-vmm/images/ubuntu-22.04.ext4"
boot_args  = "console=ttyS0 reboot=k panic=1 pci=off"
```

---

## Quick Start (planned CLI)

```bash
# Start daemon
vmm-daemon --config /etc/firecracker-vmm/config.toml

# Create a VM
vmm create --name my-vm --cpus 2 --memory 1024

# List VMs
vmm list

# Inspect a VM
vmm inspect my-vm

# Snapshot
vmm snapshot create my-vm --name before-upgrade

# Stop and remove
vmm stop my-vm
vmm remove my-vm
```

---

## Development

### Prerequisites

- Rust 1.82+ (edition 2024)
- `firecracker` binary in PATH (or set `[firecracker].binary` in config)
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

## Relation to ArcBox

`firecracker-vmm` is designed to be the Linux/x86_64 VM backend for ArcBox,
providing the same `MachineService` gRPC interface that ArcBox's orchestration
layer consumes — the same interface currently implemented against
Virtualization.framework on macOS.

On Linux, `arcbox-daemon` can connect to `firecracker-vmm` via the Unix socket
and route all `MachineService` RPCs through it without changes to the upper
layers.

---

## License

MIT OR Apache-2.0
