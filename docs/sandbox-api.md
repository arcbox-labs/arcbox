# Sandbox gRPC API

ArcBox sandboxes are short-lived, strongly-isolated Firecracker microVMs
running nested inside the guest VM, aimed at E2B-style local workloads:
create in milliseconds-to-seconds, run commands, transfer files, expose
ports, checkpoint and restore. This document is the integration reference
for SDK authors and frontend clients. Executions are addressable and
resumable: a process's identity, output offsets, and stdin offsets all
outlive any single connection (CORE-55).

Proto source of truth: `rpc/arcbox-protocol/proto/arcbox/sandbox/v1/`
(package `arcbox.sandbox.v1`), split along the control-plane / data-plane
seam (CORE-57):

| File | Service | Plane |
|---|---|---|
| `sandbox.proto` | `SandboxService` | control — lifecycle, events, published ports |
| `process.proto` | `SandboxProcessService` | data — executions |
| `filesystem.proto` | `SandboxFilesystemService` | data — file transfer |
| `snapshot.proto` | `SandboxSnapshotService` | checkpoint / restore |

The split is what lets a deployment put the two planes in different places:
control-plane calls address a fleet and can be served by a multi-tenant
front door, while data-plane calls carry a specific sandbox's stdio and
file bytes and are served by whatever is co-located with it. Locally the
daemon serves all four on the same socket, so a client may hold one
channel and four stubs.

Server implementation: `app/arcbox-api/src/grpc/sandbox/` (one module per
service) and `.../grpc/snapshot.rs`.

For the end-user CLI feature built on this API — running a coding agent in a
sandbox — see [agent-sandbox.md](agent-sandbox.md).

## Requirements

Sandboxes need **nested virtualization**: the VZ backend on Apple Silicon
M3 or newer with macOS 15+. On the HV backend or Intel/M1/M2 hosts every
sandbox RPC fails fast with `FAILED_PRECONDITION` and an explanatory
message (`/dev/kvm` is absent in the guest).

## Connection

- Socket: `~/.arcbox/run/arcbox.sock` (Unix domain socket, HTTP/2).
- Sandbox V1 runs only in the System VM. An absent, empty, or explicit
  `x-machine: default` header targets it; every other value returns
  `INVALID_ARGUMENT`. Supporting sandboxes in multiple VMs later requires
  extending host listener and DNS ownership with a machine identity first.
  The header remains local transport metadata, not part of the product
  contract — a cloud client never sends one.
- **Transport & auth posture (V1)**: UDS only — there is no TCP listener,
  and no authentication beyond the socket's file permissions. This is a
  single-user local API; remote access requires your own proxy in front of
  the socket.
- **Discovery**: the daemon serves gRPC server reflection (v1 and
  v1alpha), so `grpcurl` and reflection-aware SDKs work without vendoring
  protos:

  ```console
  $ grpcurl -unix -plaintext ~/.arcbox/run/arcbox.sock list
  $ grpcurl -unix -plaintext -d '{}' \
        ~/.arcbox/run/arcbox.sock arcbox.sandbox.v1.SandboxService/List
  ```

## Proto stability

`arcbox.sandbox.v1` is **pre-release**: it is being redesigned contract-first
under CORE-52 (the execution API below is the CORE-55/56 shape) and is
exempted from the CI `buf breaking` gate until it ships in a public SDK
(`rpc/arcbox-protocol/proto/buf.yaml`). Every other proto in the
repository stays additive-only. Fields documented as "NOT supported in
Sandbox V1" (`image`, `mounts`, `ssh_public_key`) are rejected with
`FAILED_PRECONDITION` rather than silently ignored, and will gain
behavior in later releases without a wire break.

## Sandbox state machine

```
STARTING ──► READY ──► RUNNING ──► READY   (execution exited; IDLE event)
               │          │
               └──────────┴──► STOPPING ──► STOPPED
                                    │
                                 FAILED
```

States are the `SandboxState` enum (`SANDBOX_STATE_*`); events carry the
`SandboxEventKind` enum. All timestamps are `google.protobuf.Timestamp`.

- A sandbox is **not destroyed** when its execution exits — it returns to
  `READY` and accepts further `StartExecution` calls.
- Destruction happens via `Stop`/`Remove` or `ttl_seconds` expiry.
- `stopped` sandboxes have released their TAP/IP, CoW device, and chroot;
  only the inspectable record and logs remain until `Remove`.

## SandboxService

### Create

`rpc Create(CreateSandboxRequest) returns (CreateSandboxResponse)`

Returns immediately with `state: STARTING`; wait for readiness via
`Events(kind: READY)` or by polling `Inspect`.

Key fields:

| Field | Semantics |
|---|---|
| `id` | caller-supplied for durable retry idempotency; empty → a fresh UUID on every attempt |
| `limits.vcpus` / `limits.memory_mib` | 0 → daemon defaults (1 vCPU, 512 MiB) |
| `template` | opaque reference to what boots — see **Templates** below |
| `cmd`, `env`, `working_dir`, `user` | initial workload launched automatically once ready; exit returns the sandbox to `READY` with an `IDLE` event |
| `network.mode` | `NETWORK_MODE_ENABLED` (default, IP from 172.20.0.0/16) or `NETWORK_MODE_NONE` |
| `ttl_seconds` | auto-destroy timer from creation (not reset by activity) |
| `mounts`, `ssh_public_key` | **rejected in V1** with `FAILED_PRECONDITION` (see Proto stability) |

### Templates

`template` is the only way to say what runs inside a sandbox, and it is
deliberately opaque: no host path, image store layout, or boot recipe
crosses the API (CORE-54). Local mode accepts:

| Value | Meaning |
|---|---|
| `""` | the built-in minimal image (busybox + init), built on first use |
| `"docker:<ref>"` | a Docker image in the guest's own image store |

Anything else is rejected with `INVALID_ARGUMENT` — a bare name is
reserved for the cloud template registry (CORE-21), so it is never
guessed at as an image reference.

A `docker:` template is resolved **inside the VM**: the guest exports the
image from its own dockerd, converts it to ext4, and caches the result
keyed on the image's layer diff IDs, so an unchanged image is converted
once. Make the image available first — `docker pull` / `docker build`
through the ArcBox Docker context both land in that store. CLI:
`abctl sandbox create --from-image <ref>` / `--from-dockerfile <path>` /
`--from-template <name>` produce the reference for you.

### Executions (CORE-55)

An execution is an addressable, resumable process. It survives any
client connection: output is offset-addressed per channel, stdin writes
are offset-idempotent, and signal/resize/wait go through the execution
id, never through a stream.

```
rpc StartExecution(StartExecutionRequest) returns (Execution)
rpc AttachExecution(AttachExecutionRequest) returns (stream ExecutionEvent)
rpc WriteStdin(WriteStdinRequest) returns (StdinStatus)
rpc StreamStdin(stream WriteStdinRequest) returns (StdinStatus)
rpc GetStdinStatus(GetStdinStatusRequest) returns (StdinStatus)
rpc SignalExecution(SignalExecutionRequest) returns (google.protobuf.Empty)
rpc ResizeExecutionTty(ResizeExecutionTtyRequest) returns (google.protobuf.Empty)
rpc WaitExecution(WaitExecutionRequest) returns (Execution)
```

- **Start**: requires state `READY`; a `RUNNING` sandbox answers
  `FAILED_PRECONDITION` (one execution at a time in V1). A
  caller-supplied `execution_id` makes the start idempotent: retrying
  with the same id and command returns the existing execution.
  `stdin: false` starts the process with stdin already at EOF (run
  semantics); `tty: true` allocates a PTY. `user` accepts Docker-style
  specs (`uid`, `uid:gid`, `name`, `name:group`) resolved against the
  sandbox rootfs. A failed spawn or user resolution reports a stderr
  chunk plus exit code 126/127.
- **Attach**: streams `ExecutionEvent` frames — a `started` preamble,
  offset-addressed `output` chunks (`STDOUT`/`STDERR`, or the merged
  `PTY` channel for TTY executions), interleaved `keep_alive` frames
  while idle, and a terminal `exited` frame carrying the final
  `Execution`. Reconnect at your last offsets to resume without loss;
  when retention (8 MiB per channel) already dropped the requested
  offset, the next chunk's `offset` exposes the gap. Multiple
  concurrent attaches are allowed, including after exit (records are
  kept ~5 minutes).
- **Stdin**: `WriteStdin{offset, data, eof}` deduplicates bytes below
  the accepted count (safe retries) and rejects offsets past it with
  `OUT_OF_RANGE`; resync via `GetStdinStatus`. `eof` closes stdin —
  rejected for TTY executions (send Ctrl-D, 0x04, as data instead).
- **Exit status**: `Execution.exit_status` is a oneof — `code` for a
  normal exit, `signal` for a signal death — so `exit(137)` and SIGKILL
  are distinguishable. `WaitExecution{timeout_seconds}` long-polls
  (0 = poll now).

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

- `Inspect` → full `SandboxInfo` (state, limits, network incl. IP and
  gateway, timestamps, `last_exit_status`, `error`).
- `List{state, labels, page_size, page_token}` → `SandboxSummary` per
  sandbox, id-ordered; follow `next_page_token` until it is empty
  (default page size 100, capped at 1000).
- `Events{sandbox_id, kind}` → server stream of `WatchEventsResponse`
  frames: lifecycle events (`CREATED`, `READY`, `RUNNING`, `IDLE` with
  `exit_code`/`signal` attributes, `STOPPING`, `STOPPED`, `FAILED` with
  `error`, `REMOVED`) interleaved with `keep_alive` frames while idle.

## SandboxSnapshotService

| RPC | Behavior |
|---|---|
| `Checkpoint{sandbox_id, name}` | pause → snapshot (vmstate + mem) → resume; requires state `READY`; returns the snapshot ID (its on-disk location stays inside the guest) |
| `Restore{snapshot_id, id, network_override, ttl_seconds}` | new sandbox in `READY` state with near-zero boot; set `network_override` for a fresh TAP/IP when restoring concurrently |
| `ListSnapshots` / `DeleteSnapshot` | catalog management; `ListSnapshots` paginates like `List` |

Restore requires jailer mode. Direct-mode vmstate pins origin sandbox paths
and is rejected rather than risking mutation of the origin or path collisions.
Restore retries are durably replayed only when `id` is caller-supplied. An
empty `id` creates a fresh UUID on every attempt, so retry-capable clients must
generate and retain the ID before the first call.

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
| stdin write offset past the accepted count | `OUT_OF_RANGE` (resync via `GetStdinStatus`) |
| sandbox service initialisation failure | `UNAVAILABLE` |
| daemon still starting (runtime not ready) | `UNAVAILABLE` |
| everything else | `INTERNAL` |

## Typical client flow

1. `Create({id, template, limits, cmd})` → `STARTING`
2. `Events({sandbox_id, kind: READY})` → wait for readiness
3. `WriteFile` project files in, `StartExecution` + `AttachExecution`
   workloads (`WriteStdin` for input), `ExposePort` for services,
   `ReadFile` results out
4. On a dropped connection: re-`AttachExecution` at your last offsets,
   `GetStdinStatus` for the stdin resume point, `WaitExecution` for the
   outcome — the execution never dies with the connection
5. `Checkpoint` a warmed-up sandbox; `Restore` clones later
6. `Stop`/`Remove`, or let `ttl_seconds` reap it
