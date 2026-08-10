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
| `template.proto` | `TemplateService` | control — the template catalog (CORE-107) |
| `process.proto` | `SandboxProcessService` | data — executions |
| `filesystem.proto` | `SandboxFilesystemService` | data — file transfer + path verbs |
| `snapshot.proto` | `SandboxSnapshotService` | checkpoint / restore |
| `errors.proto` | — | the `ErrorCode` registry / `ErrorInfo` detail |

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

`arcbox.sandbox.v1` shipped in the public SDKs (npm `@arcbox/sandbox`,
PyPI `arcbox`) and is **additive-only**, enforced by the CI
`buf breaking` gate like every other proto in the repository
(`rpc/arcbox-protocol/proto/buf.yaml` — the pre-release exemption was
removed when the template catalog, its last surface, shipped under
CORE-107). Fields documented as "NOT supported in Sandbox V1" (`image`,
`mounts`, `ssh_public_key`) are rejected with `FAILED_PRECONDITION`
rather than silently ignored, and will gain behavior in later releases
without a wire break.

Every declared RPC is implemented: the lifecycle plane
(`Pause`/`Resume` with transparent auto-resume, the idle detector,
`SetLifecycle`, `GetCapabilities`), the data plane (executions incl.
`ListExecutions`/`WaitForPort`, file transfer + path verbs +
`WatchDir`), snapshots, and the template catalog (`TemplateService`,
see **Templates**). The `errors.proto` registry is attached as an
`ErrorInfo` Connect error detail on the principal error paths (see
**Error model**).

## Sandbox state machine

```
STARTING ──► READY ──► RUNNING ──► READY   (execution exited; IDLE event)
               │          │
               ├──────────┴──► STOPPING ──► STOPPED
               │
               ├──► PAUSING ──► PAUSED ──(Resume)──► STARTING  (same ID)
               │          │
               └──────────┴──► FAILED   (error + failed_at set)
```

States are the `SandboxState` enum (`SANDBOX_STATE_*`); events carry the
`SandboxEventKind` enum. All timestamps are `google.protobuf.Timestamp`.

- `READY` means the in-VM agent is accepting executions: on a cold boot
  the transition (and its event) fires only after the guest has booted
  and the agent answers over vsock, not when the VM process starts. A
  template `ready_probe` moves it later still — the initial cmd starts
  and the probe must pass first (see **Templates**).
- A sandbox is **not destroyed** when its execution exits — it returns to
  `READY` and accepts further `StartExecution` calls.
- Destruction happens via `Stop`/`Remove`, `ttl_seconds` (hard maximum
  lifetime) expiry, or `idle_timeout_seconds` expiry with the default
  `KILL` policy; `on_idle: PAUSE` checkpoints instead (CORE-21). Idle
  means "no running execution": the timer arms on every `READY` edge and
  cancels when an execution starts — file activity does **not** re-arm it.
- `stopped` sandboxes have released their TAP/IP, CoW device, and chroot;
  only the inspectable record and logs remain until `Remove`.
- `paused` sandboxes keep their record, an on-disk checkpoint, **and their
  disk overlay** (`storage_bytes`, `paused_at`) under the same ID;
  data-plane calls resume them transparently, `Inspect`/`List` never do.
- `PAUSING` branches from `READY` only: a `RUNNING` sandbox has a live
  execution whose session cannot survive the VM being checkpointed and
  killed, so `Pause` on it answers `FAILED_PRECONDITION` — finish or stop
  the execution first.

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
| `no_default_cmd`, `no_default_env` | explicit-empty overrides of a catalog template's default cmd/env — proto3 repeated/map fields cannot distinguish omitted from empty |
| `network.mode` | `NETWORK_MODE_ENABLED` (default, IP from 172.20.0.0/16) or `NETWORK_MODE_NONE` |
| `ttl_seconds` | hard maximum lifetime from creation (not reset by activity; re-armable via `SetLifecycle`); always destroys |
| `idle_timeout_seconds`, `on_idle` | idle reaping after this many seconds without a running execution: `KILL` (default) destroys, `PAUSE` checkpoints (CORE-21); both knobs are replaceable via `SetLifecycle` |
| `mounts`, `ssh_public_key` | **rejected in V1** with `FAILED_PRECONDITION` (see Proto stability) |

### Templates

`template` is the only way to say what runs inside a sandbox, and it is
deliberately opaque: no host path, image store layout, or boot recipe
crosses the API (CORE-54). Local mode accepts:

| Value | Meaning |
|---|---|
| `""` | the built-in minimal image (busybox + init), built on first use |
| `"docker:<ref>"` | a Docker image in the guest's own image store |
| `"name[:version]"` | a catalog template (`TemplateService`, CORE-107); a bare name resolves to the newest published version, or the draft when nothing is published |

An unresolvable catalog reference is `NOT_FOUND` with a
`TEMPLATE_NOT_FOUND` detail — it is never guessed at as an image
reference. Before either idempotency layer runs, the daemon substitutes
the resolved canonical reference (`name:version@sha256:<digest>`) into
the request, so a retry that races a `Publish` diverges loudly instead
of silently replaying older content.

**The catalog** (`TemplateService`: `Build`, `Publish`, `Get`, `List`,
`Delete`) lives inside the VM alongside the artifacts it describes.
`Build` registers the result as the template's mutable **draft**;
`Publish` freezes the draft as an immutable version under a
content digest. Build sources (exactly one):

- `docker_ref` — a local Docker image reference, exported from the
  guest's dockerd and converted to ext4 (cached on layer diff IDs).
- `dockerfile` — inline Dockerfile content, built in-guest first (the
  build context is the file alone), then converted like `docker_ref`.
- `snapshot_id` — promote an existing checkpoint: no build runs, and a
  private copy of the checkpoint becomes the template's warm snapshot.
  The promoted snapshot leaves the user-checkpoint surface: it is hidden
  from `ListSnapshots` and shielded from `DeleteSnapshot` while
  referenced.

`prewarm: true` additionally boots the built rootfs once (ready probe
included) and checkpoints it at READY, so the template carries a warm
snapshot. Creating from a warm template **restores that snapshot's
memory image** for sub-second READY, provided the effective geometry
matches the snapshot's (`limits` overridden per create → cold boot from
the template rootfs, correct per the wholesale-replace rule below).
Unlike the warm-create cache, a kernel bump does not invalidate a
template's snapshot: a published template pins its artifacts.

Catalog templates carry defaults (`limits`, `cmd`, `env`,
`exposed_ports`, `ready_probe`). A create request overrides them
field-wise: a set `limits` replaces the default limits wholesale, a
non-empty `cmd` replaces the default cmd, and `env` merges per key with
the request winning. Inside a set `limits`, a zero `vcpus` or
`memory_mib` means the *daemon* default for that resource — never a
per-field fall-through to the template, since the scalars have no
presence. `no_default_cmd` / `no_default_env` express the
explicitly-empty case that proto3 repeated/map shape cannot
(`exposed_ports` and `ready_probe` have no per-create counterpart).

A `ready_probe` default (port form: something listens on a TCP port;
command form: a command exits 0; `timeout_seconds` 0 → 30 s, capped at
600 s) moves the READY transition: the initial cmd is started first,
the probe must pass before the sandbox reports READY, and probe expiry
transitions the sandbox to `FAILED`. Resuming a paused sandbox does not
re-probe — the probe is a creation-readiness contract.

A `docker:` template is resolved **inside the VM**: the guest exports the
image from its own dockerd, converts it to ext4, and caches the result
keyed on the image's layer diff IDs, so an unchanged image is converted
once. Make the image available first — `docker pull` / `docker build`
through the ArcBox Docker context both land in that store. CLI:
`abctl sandbox create --from-image <ref>` / `--from-dockerfile <path>` /
`--from-preset <name>` produce the reference for you;
`--template <name[:version]>` passes a catalog reference through, and
`abctl sandbox template build|publish|get|ls|rm` drives the catalog
itself.

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

### ExposePort / ListExposedPorts / UnexposePort

```
rpc ExposePort(ExposePortRequest) returns (ExposePortResponse)
rpc ListExposedPorts(ListExposedPortsRequest) returns (ListExposedPortsResponse)
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

`ListExposedPorts{id}` returns the daemon's current host listeners as
`{sandbox_port, host_port, protocol}` records in stable order. A known
sandbox with no listeners returns an empty list; an unknown sandbox returns
`NOT_FOUND`, and an unready daemon, an unreachable sandbox registry, or a
concurrent cleanup that prevents a stable snapshot returns `UNAVAILABLE`.
The guest relay port is deliberately internal and is not part of Desktop
reconciliation. Stop, Remove, Pause, TTL cleanup, and daemon restart discard
these mappings; the response is a current snapshot, not history or persisted
configuration.

### Pause / Resume (CORE-21)

- `Pause{id}`: checkpoints the sandbox (memory + device state) and
  releases its VM, TAP/IP, and chroot while **retaining the disk
  overlay** — both memory and disk survive under the same ID. Requires
  `READY`; `Pause` on a `PAUSED` sandbox is a no-op. The VM is not
  resumed after the snapshot, so the checkpoint and disk can never
  diverge. Port exposures are dropped with the released network.
- `Resume{id}`: restores the checkpoint against the retained overlay in a
  fresh microVM with a **fresh IP** (the `sandbox-id.arcbox.local` DNS
  name follows it), then returns once `READY`. `Resume` on a
  `READY`/`RUNNING` sandbox is a no-op; re-expose ports as needed. The
  internal pause checkpoint is deleted on a successful resume.
- **Transparent auto-resume**: data-plane RPCs (executions, files)
  hitting a paused sandbox resume it first and then proceed — one shared
  resume even under concurrent callers. Calls that address execution
  *history* (attach, wait, stdin status, signal, resize) are served from
  the retained records without waking the sandbox. Opt out per request
  with the `x-arcbox-no-auto-resume: 1` header to receive the honest
  `FAILED_PRECONDITION` carrying the `SANDBOX_PAUSED` `ErrorInfo` detail.
- **Events**: `PAUSING` (attributes `reason: pause`, later
  `idle_timeout`), `PAUSED`, and `RESUMED` (attributes `reason: resume`
  or `auto_resume`) make every automated transition visible.
- Paused sandboxes report `paused_at` and `storage_bytes` (checkpoint +
  overlay footprint) in `Inspect`/`List`, survive daemon and VM restarts,
  and still honor `ttl_seconds` — the hard cap destroys a paused sandbox
  too. Idle-driven auto-pause (`idle_timeout_seconds` + `on_idle: PAUSE`)
  rides the same flow: the `PAUSING` event carries
  `reason: idle_timeout`, and the next data-plane call resumes the
  sandbox transparently.

### SetLifecycle (CORE-60)

`rpc SetLifecycle(SetLifecycleRequest) returns (Empty)`

Replaces a sandbox's lifecycle deadlines; absent fields are left
unchanged, so each knob adjusts independently:

- `ttl_seconds`: the hard cap expires this many seconds **from now** —
  calling repeatedly keeps a busy sandbox alive indefinitely (E2B
  timeout semantics); `0` removes the limit. `Inspect.ttl_deadline`
  reports the resulting deadline.
- `idle_timeout_seconds`: replaces the idle window, re-arming a live
  timer; `0` disables idle detection.
- `on_idle` (`optional`): absent = unchanged; an explicit
  `IDLE_ACTION_UNSPECIFIED` restores the daemon default (`KILL`).

Allowed in any non-terminal state — updating a `PAUSED` sandbox works
(its TTL keeps applying while asleep; new idle knobs take effect on the
next `READY`). `STOPPING`/`STOPPED`/`FAILED` answer
`FAILED_PRECONDITION`.

### GetCapabilities (CORE-13)

`rpc GetCapabilities(GetCapabilitiesRequest) returns (GetCapabilitiesResponse)`

The SDK handshake, answered host-side (no guest round-trip, works before
any sandbox exists):

- `daemon_version` — informational.
- `protocol` — the sandbox API protocol level (currently `1`); SDKs
  compare it against their floor and raise `PROTOCOL_MISMATCH`.
- `features` — append-only named flags: `pause_resume`, `auto_resume`,
  `idle_policy`, `set_lifecycle`, `list_exposed_ports`.
- `nested_virt` — `{supported, reason}` for the **current** backend and
  hardware (VZ on Apple Silicon M3+/macOS 15+). When unsupported,
  `Create` fails fast with `FAILED_PRECONDITION` carrying the
  `NESTED_VIRT_UNSUPPORTED` `ErrorInfo` detail and the same `reason`,
  instead of booting into an opaque KVM failure.

### Stop / Remove

- `Stop{id, timeout_seconds}` (default 30 s): drains an active workload
  up to the budget, asks the guest to shut down, and force-kills only on
  timeout. Releases network/CoW/chroot resources. A `paused` sandbox has
  no VM to stop — `Stop` answers `FAILED_PRECONDITION`; use
  `Resume`+`Stop` or `Remove`.
- `Remove{id, force}`: destroys the sandbox and every remaining resource,
  including a paused sandbox's checkpoint and disk overlay. `force: true`
  removes even a `running` sandbox.

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

Snapshots are network-agnostic: every sandbox guest boots the identical
fixed link-local identity, and the pool IP reported as `ip_address` is a
host-side property of the TAP (per-TAP 1:1 NAT in the System VM). An
invariant-addressed restore therefore performs zero guest-side network
work; snapshots taken before this scheme keep the guest reconfig path.
`ip_address`, DNS records, and expose always carry the external pool IP.

## Error model

Agent-reported failures carry HTTP-style codes over the internal wire and
map onto gRPC statuses:

| Condition | Status |
|---|---|
| malformed request / oversized file | `INVALID_ARGUMENT` |
| unknown sandbox / snapshot | `NOT_FOUND` |
| duplicate sandbox ID | `ALREADY_EXISTS` |
| wrong state, missing nested virt, V1-unsupported field | `FAILED_PRECONDITION` |
| paused sandbox, transparent resume not applied (opt-out header or control-plane call) | `FAILED_PRECONDITION` + `SANDBOX_PAUSED` `ErrorInfo` detail |
| stdin write offset past the accepted count | `OUT_OF_RANGE` (resync via `GetStdinStatus`) |
| sandbox service initialisation failure | `UNAVAILABLE` |
| daemon still starting (runtime not ready) | `UNAVAILABLE` |
| everything else | `INTERNAL` |

The daemon additionally attaches the `errors.proto` registry as an
`arcbox.sandbox.v1.ErrorInfo` Connect error detail (code + actionable
suggestion + structured context) on the principal paths, which SDKs map
to typed exceptions: `SANDBOX_NOT_FOUND` / `EXECUTION_NOT_FOUND` /
`TEMPLATE_NOT_FOUND` on not-found, `SANDBOX_NOT_READY` (context
`state`) / `SANDBOX_FAILED` on wrong-state, `SANDBOX_PAUSED`,
`TEMPLATE_INVALID`, and `NESTED_VIRT_UNSUPPORTED` (both the host
fail-fast and the guest probe).
`TTL_EXPIRED` is not yet attachable: TTL expiry removes the record, so a
later call sees plain `SANDBOX_NOT_FOUND`.

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
