# Sandbox gRPC API

ArcBox sandboxes are short-lived, strongly-isolated Firecracker microVMs
running nested inside the guest VM, aimed at E2B-style local workloads:
create in milliseconds-to-seconds, run commands, transfer files, expose
ports, checkpoint and restore. This document is the integration reference
for SDK authors and frontend clients.

Proto source of truth: `rpc/arcbox-protocol/proto/sandbox.proto`
(package `sandbox.v1`). Server implementation:
`app/arcbox-api/src/grpc/{sandbox,snapshot}.rs`.

## Requirements

Sandboxes need **nested virtualization**: the VZ backend on Apple Silicon
M3 or newer with macOS 15+. On the HV backend or Intel/M1/M2 hosts every
sandbox RPC fails fast with `FAILED_PRECONDITION` and an explanatory
message (`/dev/kvm` is absent in the guest).

## Connection

- Socket: `~/.arcbox/run/arcbox.sock` (Unix domain socket, HTTP/2).
- Every request must carry the `x-machine` metadata header naming the
  target machine (`default` unless you manage extra machines). Missing
  header → `INVALID_ARGUMENT`.
- **Transport & auth posture (V1)**: UDS only — there is no TCP listener,
  and no authentication beyond the socket's file permissions. This is a
  single-user local API; remote access requires your own proxy in front of
  the socket.
- **Discovery**: the daemon serves gRPC server reflection (v1 and
  v1alpha), so `grpcurl` and reflection-aware SDKs work without vendoring
  protos:

  ```console
  $ grpcurl -unix -plaintext ~/.arcbox/run/arcbox.sock list
  $ grpcurl -unix -plaintext -H 'x-machine: default' \
        -d '{}' ~/.arcbox/run/arcbox.sock sandbox.v1.SandboxService/List
  ```

## Proto stability

`sandbox.v1` evolves additively: fields and RPCs are added, never removed
or renumbered (CI enforces `buf breaking`). Fields documented as "NOT
supported in Sandbox V1" (`image`, `mounts`, `ssh_public_key`) are
rejected with `FAILED_PRECONDITION` rather than silently ignored, and
will gain behavior in later releases without a wire break.

## Sandbox state machine

```
starting ──► ready ──► running ──► ready   (workload exited; "idle" event)
               │          │
               └──────────┴──► stopping ──► stopped
                                    │
                                 failed
```

- A sandbox is **not destroyed** when its workload exits — it returns to
  `ready` and accepts further `Run`/`Exec` calls.
- Destruction happens via `Stop`/`Remove` or `ttl_seconds` expiry.
- `stopped` sandboxes have released their TAP/IP, CoW device, and chroot;
  only the inspectable record and logs remain until `Remove`.

## SandboxService

### Create

`rpc Create(CreateSandboxRequest) returns (CreateSandboxResponse)`

Returns immediately with `state: "starting"`; wait for readiness via
`Events(action="ready")` or by polling `Inspect`.

Key fields:

| Field | Semantics |
|---|---|
| `id` | caller-supplied for idempotency; empty → UUID |
| `limits.vcpus` / `limits.memory_mib` | 0 → daemon defaults (1 vCPU, 512 MiB) |
| `rootfs` | ext4 image path (guest view), an overlay2 layer directory (auto-converted), or empty for the **default busybox rootfs** (auto-built with the vm-agent init) |
| `cmd`, `env`, `working_dir`, `user` | initial workload launched automatically once ready; exit returns the sandbox to `ready` with an `idle` event |
| `network.mode` | `"tap"` (default, IP from 172.20.0.0/16) or `"none"` |
| `ttl_seconds` | auto-destroy timer from creation (not reset by activity) |
| `image`, `mounts`, `ssh_public_key` | **rejected in V1** with `FAILED_PRECONDITION` (see Proto stability) |

### Run

`rpc Run(RunRequest) returns (stream RunOutput)`

One-shot command with streamed output; no stdin. Requires state
`ready`; a `running` sandbox answers `FAILED_PRECONDITION`. The final
message has `done == true` and the exit code. `user` accepts Docker-style
specs (`uid`, `uid:gid`, `name`, `name:group`) resolved against the
sandbox rootfs.

### Exec

`rpc Exec(stream ExecInput) returns (stream ExecOutput)`

Bidirectional interactive session:

1. First message: `ExecInput{init: ExecRequest{...}}` (set `tty` and
   `tty_size` for PTY sessions).
2. Then `ExecInput{stdin: bytes}` for input — an **empty** `stdin`
   payload signals EOF — and `ExecInput{resize: TerminalSize}` for live
   TTY resizes (forwarded end-to-end to the PTY).

Output mirrors `RunOutput`. A failed spawn or user resolution reports a
`stderr` chunk plus exit code 126/127 instead of a bare stream end.

### ReadFile / WriteFile

```
rpc ReadFile(ReadFileRequest) returns (stream FileChunk)
rpc WriteFile(stream WriteFileRequest) returns (Empty)
```

File transfer with a 256 MiB per-file cap, usable while the sandbox is
`ready` **or** `running`:

- `ReadFile{id, path}` streams chunks; the last has `done == true`.
- `WriteFile` starts with `WriteFileRequest{open: {id, path, mode}}`
  (mode 0 → 0644), followed by `chunk` payloads, last one `done == true`.

CLI: `abctl sandbox cp ./local <id>:/path` and
`abctl sandbox cp <id>:/path ./local`.

### ExposePort / UnexposePort

```
rpc ExposePort(ExposePortRequest) returns (ExposePortResponse)
rpc UnexposePort(UnexposePortRequest) returns (Empty)
```

Makes a sandbox port reachable from the host via loopback:

```
host listener :H → inbound relay → guest :G (reserved 40000-49999)
    → iptables DNAT → sandbox_ip:P
```

`host_port: 0` reuses the allocated guest relay port for a stable
mapping. Mappings are removed automatically on Stop/Remove/TTL. CLI:
`abctl sandbox expose <id> <port>` / `unexpose`.

### Stop / Remove

- `Stop{id, timeout_seconds}` (default 30 s): drains an active workload
  up to the budget, asks the guest to shut down, and force-kills only on
  timeout. Releases network/CoW/chroot resources.
- `Remove{id, force}`: destroys the sandbox and every remaining resource.
  `force: true` removes even a `running` sandbox.

### Inspect / List / Events

- `Inspect` → full `SandboxInfo` (state, limits, network incl. IP,
  timestamps, `last_exit_code`, `error`).
- `List{state, labels}` → `SandboxSummary` per sandbox.
- `Events{id, action}` → server stream of lifecycle events:
  `created`, `ready`, `running`, `idle` (with `exit_code` attribute),
  `stopping`, `stopped`, `failed` (with `error`), `removed`.

## SandboxSnapshotService

| RPC | Behavior |
|---|---|
| `Checkpoint{sandbox_id, name}` | pause → snapshot (vmstate + mem) → resume; requires state `ready` |
| `Restore{snapshot_id, id, network_override, ttl_seconds}` | new sandbox in `ready` state with near-zero boot; set `network_override` for a fresh TAP/IP when restoring concurrently |
| `ListSnapshots` / `DeleteSnapshot` | catalog management |

Direct-mode (non-jailer) restores of the same snapshot cannot run
concurrently with each other or the origin sandbox (the vmstate pins the
origin vsock path); jailer-mode restores have no such constraint.

`network_override` (a fresh TAP/IP for the restored sandbox) uses
Firecracker's `network_overrides` snapshot-load field (Firecracker ≥ 1.12;
the bundle ships 1.16.1). With it, a clone restores and runs while the
origin keeps its NIC. Restore without `network_override` reuses the
recorded NIC, so the origin must be stopped first.

## Error model

Agent-reported failures carry HTTP-style codes over the internal wire and
map onto gRPC statuses:

| Condition | Status |
|---|---|
| malformed request / oversized file | `INVALID_ARGUMENT` |
| unknown sandbox / snapshot | `NOT_FOUND` |
| duplicate sandbox ID | `ALREADY_EXISTS` |
| wrong state, missing nested virt, V1-unsupported field | `FAILED_PRECONDITION` |
| sandbox service initialisation failure | `UNAVAILABLE` |
| daemon still starting (runtime not ready) | `UNAVAILABLE` |
| everything else | `INTERNAL` |

## Typical client flow

1. `Create({id, limits, cmd})` → `starting`
2. `Events({id, action: "ready"})` → wait for readiness
3. `WriteFile` project files in, `Run`/`Exec` workloads,
   `ExposePort` for services, `ReadFile` results out
4. `Checkpoint` a warmed-up sandbox; `Restore` clones later
5. `Stop`/`Remove`, or let `ttl_seconds` reap it
