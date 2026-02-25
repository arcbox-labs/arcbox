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

### Full Device Support (via `VmmService.CreateVm`)
- Machine: vCPU, memory, SMT, huge pages, CPU templates, dirty-page tracking
- Root drive: read-only, IO engine (sync/async), cache mode, rate limiter, partuuid
- Extra drives: multiple additional block devices with per-drive settings
- Network: per-interface TX/RX rate limiters
- Balloon: amount, deflate-on-OOM, stats interval, free-page hinting/reporting
- Vsock: host↔guest virtio-vsock (guest CID configurable)
- Entropy: virtio-rng device
- Serial: redirect console output to host file
- Memory hotplug: virtio-mem with configurable total/slot/block sizes
- MMDS: metadata service with V1/V2 API, custom IP, IMDS compat mode

### Snapshots
- Full snapshots (memory + VM state)
- Diff snapshots (dirty pages only, requires `track_dirty_pages`)
- Snapshot catalog per VM with metadata
- Restore from any catalog entry

### Live Updates (post-boot)
- Balloon target size adjustment
- Balloon statistics polling interval
- Memory hotplug size update
- Drive hot-swap (path + rate limiter)
- Network interface rate limiter update
- Metrics flush to disk

### Process Options (daemon-level)
- Direct mode or Jailer sandbox
- Configurable log level, seccomp filter, API payload limits
- Custom socket timeout

### gRPC Interface
- Unix socket transport (default: `/run/firecracker-vmm/vmm.sock`)
- Optional TCP transport
- Protocol-compatible with `arcbox.v1.MachineService`
- VMM-specific extensions via `vmm.v1.VmmService`

---

## gRPC Services

### `arcbox.v1.MachineService` (arcbox-protocol compatible)

```
Create       → boot a new VM (basic params; uses daemon defaults)
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

> For full parameter control use `VmmService.CreateVm` instead.

### `arcbox.v1.SystemService`

```
GetInfo      → daemon stats (VM counts, host info)
GetVersion   → daemon version
Ping         → liveness probe
Events       → stream VM lifecycle events
```

### `vmm.v1.VmmService` (VMM-specific extensions)

```
CreateVm                 → create VM with full Firecracker parameter set
Pause                    → pause a running VM
Resume                   → resume a paused VM
CreateSnapshot           → create full or diff snapshot
ListSnapshots            → list snapshot catalog for a VM
RestoreSnapshot          → restore VM from snapshot
DeleteSnapshot           → remove snapshot from catalog
GetMetrics               → balloon stats
UpdateBalloon            → adjust memory balloon target
UpdateBalloonStatsInterval → update balloon statistics polling interval
UpdateMemory             → hotplug memory size change
UpdateDrive              → hot-swap drive path / update rate limiter
UpdateNetworkInterface   → update NIC TX/RX rate limiters
FlushMetrics             → flush metrics to disk immediately
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
│       ├── vsock.sock        # vsock UDS (if vsock enabled)
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
data_dir = "/var/lib/firecracker-vmm"

# Process-level options (all optional)
log_level                 = "Warning"   # Error | Warning | Info | Debug | Trace
no_seccomp                = false
# seccomp_filter          = "/etc/fc-seccomp.bpf"
# http_api_max_payload_size = 51200
# mmds_size_limit           = 51200
# socket_timeout_secs       = 5

# Jailer sandbox (remove this section to run without jailer)
# [firecracker.jailer]
# binary          = "/usr/bin/jailer"
# uid             = 1000
# gid             = 1000
# chroot_base_dir = "/srv/jailer"       # default: /srv/jailer
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
tcp_addr    = ""

[defaults]
vcpus      = 1
memory_mib = 512
kernel     = "/var/lib/firecracker-vmm/kernels/vmlinux"
rootfs     = "/var/lib/firecracker-vmm/images/ubuntu-22.04.ext4"
boot_args  = "console=ttyS0 reboot=k panic=1 pci=off"
```

> **Breaking change from earlier versions:** The `jailer` field under
> `[firecracker]` was previously a plain string (`jailer = ""`). It is now
> an optional TOML table (`[firecracker.jailer]`). Remove the old
> `jailer = ""` line from existing configs; the jailer is disabled by default
> when the section is absent.

---

## Quick Start (planned CLI)

```bash
# Start daemon
vmm-daemon --config /etc/firecracker-vmm/config.toml

# Create a VM (basic — uses daemon defaults)
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
layers. For Firecracker-specific features (snapshots, balloon, hotplug), use
the `vmm.v1.VmmService` extensions directly.

---

## License

MIT OR Apache-2.0
