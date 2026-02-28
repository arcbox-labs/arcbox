# arcbox-vm

A production-grade sandbox management library built on top of
[`fc-sdk`](https://crates.io/crates/fc-sdk) that orchestrates multiple
[Firecracker](https://firecracker-microvm.github.io/) microVMs.

Exposes a `SandboxManager` API and optional gRPC service implementations
(`sandbox.v1`) for embedding into a larger daemon.

---

## Architecture

```
            ┌─────────────────────────────┐
            │  your daemon / arcbox-vmm   │
            │  (owns runtime + transport) │
            └──────────────┬──────────────┘
                           │
            ┌──────────────▼──────────────┐
            │          arcbox-vm          │
            │  SandboxServiceImpl         │  ◄── sandbox.v1 proto (arcbox-protocol)
            │  SandboxSnapshotServiceImpl │
            │  ──────────────────────     │
            │  SandboxManager             │
            │  ┌─────────────────────┐   │
            │  │  SandboxInstance    │   │
            │  │  registry           │   │
            │  │  (Arc<RwLock<...>>) │   │
            │  └─────────────────────┘   │
            │  NetworkManager (TAP / IP) │
            │  SnapshotCatalog           │
            └──────────────┬──────────────┘
                           │
            ┌──────────────▼──────────────┐
            │           fc-sdk            │
            │  VmBuilder / VmProcess / Vm │
            └──────────────┬──────────────┘
                           │
            ┌──────────────▼──────────────┐
            │  Firecracker process        │
            │  (unix socket per VM)       │
            └─────────────────────────────┘
```

### Crates

| Crate | Type | Purpose |
|-------|------|---------|
| `arcbox-vm` | lib + bin | Sandbox orchestration, state, networking, snapshots; gRPC service implementations; ships the `vmm-guest-agent` binary |

There is no standalone daemon or CLI binary. The gRPC server and direct API usage are demonstrated via the examples described below.

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

### Workload Execution (via vsock guest agent)
- **Run** — execute a command and stream stdout/stderr; sandbox returns to `Ready` on exit
- **Exec** — interactive session with stdin, stdout/stderr, and TTY resize support
- Both use the vsock binary frame protocol; the in-guest `vmm-guest-agent` binary (built from `arcbox-vm`) must be present inside the rootfs

### Process Options
- **Direct mode** — Firecracker runs as a normal process; socket and files live under `data_dir/sandboxes/{id}/`
- **Jailer mode** — Firecracker runs under the Firecracker jailer (`pivot_root` + uid/gid drop + seccomp); kernel and rootfs are staged into the chroot at boot and cleaned up on removal; snapshot and restore also stage files through the chroot (see [Jailer Mode Internals](#jailer-mode-internals))
- Configurable per-sandbox resources (vCPUs, memory)
- Auto-destroy TTL per sandbox

---

## gRPC Services

### `sandbox.v1.SandboxService`

| RPC | Description |
|-----|-------------|
| `Create` | Boot a new sandbox (returns immediately; VM boots async) |
| `Run` | Execute a command and stream output (requires `vmm-guest-agent` in rootfs) |
| `Exec` | Interactive session with stdin/stdout/stderr and TTY support |
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

## Usage

`arcbox-vm` is designed to be embedded — there is no standalone daemon or CLI
binary. The examples below show the two main integration patterns.

### Direct API

```rust
use std::sync::Arc;
use arcbox_vm::{SandboxManager, SandboxSpec, VmmConfig};

let manager = Arc::new(SandboxManager::new(VmmConfig::default())?);

let (id, ip) = manager.create_sandbox(SandboxSpec {
    vcpus: 1,
    memory_mib: 512,
    ..Default::default()
}).await?;
```

### Embedding the gRPC services

```rust
use std::sync::Arc;
use arcbox_vm::{SandboxManager, VmmConfig, SandboxServiceImpl, SandboxSnapshotServiceImpl};
use arcbox_vm::proto::sandbox::{
    sandbox_service_server::SandboxServiceServer,
    sandbox_snapshot_service_server::SandboxSnapshotServiceServer,
};
use tonic::transport::Server;

let manager = Arc::new(SandboxManager::new(VmmConfig::default())?);

Server::builder()
    .add_service(SandboxServiceServer::new(
        SandboxServiceImpl::new(Arc::clone(&manager))
    ))
    .add_service(SandboxSnapshotServiceServer::new(
        SandboxSnapshotServiceImpl::new(Arc::clone(&manager))
    ))
    // add your own services here
    .serve_with_incoming(incoming)
    .await?;
```

---

## Examples

### `sandbox_lifecycle` — Direct API walkthrough

[`examples/sandbox_lifecycle.rs`](examples/sandbox_lifecycle.rs)

Demonstrates the full `SandboxManager` API without the gRPC layer:

1. **Create** a sandbox (1 vCPU, 512 MiB)
2. **Poll** until state transitions to `Ready`
3. **Inspect** hardware and network details
4. **List** all live sandboxes
5. **Checkpoint** (pause → snapshot → resume)
6. **Remove** the original sandbox
7. **Restore** a new sandbox from the checkpoint
8. **Cleanup** the restored sandbox

```bash
# from arcbox workspace root
cargo run -p arcbox-vm --example sandbox_lifecycle
```

### `serve` — Embedded gRPC server

[`examples/serve.rs`](examples/serve.rs)

Shows how to wire `SandboxServiceImpl` and `SandboxSnapshotServiceImpl` into a
tonic server listening on a Unix socket. This is the reference for embedding
the sandbox services into a larger daemon (e.g. arcbox-vmm).

```bash
# from arcbox workspace root
cargo run -p arcbox-vm --example serve -- --unix-socket /tmp/vmm-test.sock
```

---

## Data Layout

### Direct mode

```
/var/lib/firecracker-vmm/
├── kernels/
│   └── vmlinux               # default kernel
├── images/
│   └── ubuntu-22.04.ext4     # default rootfs
├── sandboxes/
│   └── {sandbox-id}/
│       ├── firecracker.sock  # Firecracker API socket (while running)
│       ├── firecracker.vsock # vsock UDS (while running)
│       ├── firecracker.log
│       └── firecracker.metrics
└── snapshots/
    └── {sandbox-id}/
        └── {snapshot-id}/
            ├── vmstate       # Firecracker VM state file
            ├── mem           # memory file (full snapshots)
            └── meta.json     # snapshot metadata
```

### Jailer mode

Firecracker runs inside a chroot created by the jailer. Files are staged
into the chroot before boot and removed on sandbox removal.

```
{chroot_base_dir}/             # default: /srv/jailer
└── firecracker/               # fc binary filename
    └── {sandbox-id}/
        └── root/              # chroot root (pivot_root target)
            ├── vmlinux        # staged kernel (copied from spec path)
            ├── rootfs.ext4    # staged rootfs (copied from spec path)
            ├── snapshots/     # temp dir used during checkpoint (moved out after)
            └── run/
                ├── firecracker.socket  # Firecracker API socket
                └── firecracker.vsock   # vsock UDS
```

---

## Jailer Mode Internals

### Create flow

```
SandboxManager::create_sandbox()
    │
    ├─ 1. NetworkManager.allocate()
    │      create TAP, assign IP, attach to bridge
    │
    ├─ 2. JailerProcessBuilder.spawn()
    │      jailer forks, sets up cgroups, calls pivot_root
    │      waits until Firecracker API socket is ready
    │
    ├─ 3. stage_files_for_jailer()
    │      copy kernel  →  {chroot}/vmlinux        (chown uid:gid)
    │      copy rootfs  →  {chroot}/rootfs.ext4    (chown uid:gid)
    │
    ├─ 4. fc-sdk VmBuilder (via Firecracker API)
    │      PUT /boot-source   path="/vmlinux"      (chroot-relative)
    │      PUT /drives/rootfs path="/rootfs.ext4"  (chroot-relative)
    │      PUT /network-interfaces/eth0  tap=vmtapXX
    │      PUT /vsock          uds_path="/run/firecracker.vsock"
    │      PUT /actions        {"action_type":"InstanceStart"}
    │
    └─ 5. background task polls boot; sets state=Ready
          on failure → remove_sandbox_impl() cleans chroot + TAP
```

### Checkpoint flow

```
SandboxManager::checkpoint_sandbox()
    │
    ├─ 1. fc-sdk Vm.pause()
    │
    ├─ 2. mkdir {chroot}/snapshots/{snapshot-id}/   (chown uid:gid)
    │
    ├─ 3. PUT /snapshot/create
    │      snapshot_path="/snapshots/{snapshot-id}/vmstate"  (chroot-relative)
    │      mem_file_path="/snapshots/{snapshot-id}/mem"
    │
    ├─ 4. fc-sdk Vm.resume()
    │
    ├─ 5. Move files out of chroot to catalog:
    │      {chroot}/snapshots/{snapshot-id}/vmstate  →  {data_dir}/snapshots/{sandbox-id}/{snapshot-id}/vmstate
    │      {chroot}/snapshots/{snapshot-id}/mem      →  {data_dir}/snapshots/{sandbox-id}/{snapshot-id}/mem
    │
    └─ 6. SnapshotCatalog.register()
           writes meta.json including kernel_path + rootfs_path
           (required for re-staging on restore)
```

### Restore flow

```
SandboxManager::restore_sandbox()
    │
    ├─ 1. NetworkManager.allocate()  (new TAP + IP for restored sandbox)
    │
    ├─ 2. JailerProcessBuilder.spawn()  (new sandbox-id, own chroot)
    │      mkdir {new-chroot}/run/   (for vsock bind)
    │
    ├─ 3. stage_files_for_jailer()
    │      re-copy kernel + rootfs from snapshot metadata paths
    │      {new-chroot}/vmlinux / {new-chroot}/rootfs.ext4
    │
    ├─ 4. Copy snapshot files into new chroot:
    │      {data_dir}/snapshots/.../vmstate  →  {new-chroot}/snapshots/{snapshot-id}/vmstate
    │      {data_dir}/snapshots/.../mem      →  {new-chroot}/snapshots/{snapshot-id}/mem
    │      (chown uid:gid)
    │
    ├─ 5. PUT /snapshot/load
    │      snapshot_path="/snapshots/{snapshot-id}/vmstate"  (chroot-relative)
    │      mem_file_path="/snapshots/{snapshot-id}/mem"
    │      network_overrides=[{iface_id:"eth0", host_dev_name:"vmtapXX"}]
    │      resume_vm=true
    │
    └─ 6. Register sandbox as state=Ready immediately
```

> **Why files must be inside the chroot:** Firecracker executes `pivot_root`
> before processing any API requests, so all paths passed to the FC API are
> resolved relative to the chroot root. Host-absolute paths (e.g.
> `/var/lib/firecracker-vmm/...`) do not exist inside the chroot and will
> return `ENOENT`.

> **vsock on restore:** The vmstate stores the vsock UDS path as seen by FC
> (`/run/firecracker.vsock`, chroot-relative). Each restored sandbox gets its
> own jailer chroot, so this path maps to a unique host path
> `{new-chroot}/run/firecracker.vsock` — no cross-sandbox socket conflicts.

---

## Configuration

`VmmConfig` can be loaded from a TOML file or constructed programmatically.

```toml
[firecracker]
binary   = "/usr/bin/firecracker"
data_dir = "/var/lib/firecracker-vmm"

# Process-level options (all optional)
log_level                 = "Warning"   # Error | Warning | Info | Debug | Trace
no_seccomp                = false
# seccomp_filter          = "/etc/fc-seccomp.bpf"

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

[defaults]
vcpus      = 1
memory_mib = 512
kernel     = "/var/lib/firecracker-vmm/kernels/vmlinux"
rootfs     = "/var/lib/firecracker-vmm/images/ubuntu-22.04.ext4"
boot_args  = "console=ttyS0 reboot=k panic=1 pci=off"
```

---

## Development

### Prerequisites

- Rust 1.85+ (edition 2024)
- `firecracker` binary (set `[firecracker].binary` in config or add to PATH)
- Linux with `CAP_NET_ADMIN` for TAP interface creation
- `protoc` for proto codegen
- `sandbox.proto` lives in `comm/arcbox-protocol/proto/sandbox.proto` (shared with the arcbox workspace)
- Jailer mode additionally requires: `jailer` binary, and running as root (or with `CAP_SYS_ADMIN`) to `pivot_root`

### Build

```bash
# from arcbox workspace root
cargo build -p arcbox-vm
```

### Cross-compile `vmm-guest-agent` to Linux (static)

`vmm-guest-agent` targets x86_64 Linux only — Firecracker requires KVM, which
is not available on ARM64 guests.

The workspace `.cargo/config.toml` sets the musl linker. Install the target
and toolchain, then build:

```bash
rustup target add x86_64-unknown-linux-musl
brew install FiloSottile/musl-cross/musl-cross   # macOS

cargo build -p arcbox-vm --bin vmm-guest-agent --target x86_64-unknown-linux-musl --release
# output: target/x86_64-unknown-linux-musl/release/vmm-guest-agent
```

### Test

```bash
# Unit + integration (no Firecracker required)
cargo test -p arcbox-vm

# Run examples (requires firecracker binary + CAP_NET_ADMIN)
cargo run -p arcbox-vm --example sandbox_lifecycle
cargo run -p arcbox-vm --example serve
```

### Lint

```bash
cargo clippy -p arcbox-vm -- -D warnings
cargo fmt --check
```

---

## License

MIT OR Apache-2.0

License files are inherited from the root arcbox repository.
