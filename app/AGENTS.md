# app/ — Daemon & Core Agent Guidance

Covers `arcbox-daemon` (startup/shutdown), `arcbox-core` (`vm_lifecycle`),
`arcbox-api` (gRPC/diagnostics), `arcbox-cli` (daemon handoff), and
`arcbox-docker` (Engine API proxy). Reference material lives in
`docs/daemon-lifecycle.md` (lock/handoff, residual-state tables) and
`docs/data-directories.md` (filesystem paths) — point there, don't restate.

`arcbox-cli` ships one binary, `abctl`. User-facing strings must name it.

## Startup & readiness contract

- Startup is a phased, typed pipeline and the order is load-bearing — see
  root CLAUDE.md "Architecture Principles" and `docs/daemon-lifecycle.md`
  before reordering. The current chain is 8 steps
  (`prepare_host → acquire_daemon_lease → start_control_plane →
  release_stale_resources → prepare_assets → boot_runtime →
  start_runtime_services → mark_ready`, `arcbox-daemon/src/main.rs`), each
  producing a richer context type so skipping a phase is a compile error
  (`context.rs`). gRPC (`start_control_plane`) must come before the slow
  boot phases so clients can watch progress.
- Two runtime handles, do not conflate them (`context.rs`): `shared_runtime`
  is filled only after full init and gates normal RPCs with `UNAVAILABLE`
  via `runtime.ready()`; `early_runtime` is filled the moment `Runtime` is
  constructed, before the VM boots, and is diagnostics-only. WHY: a stuck
  boot never fills `shared_runtime`, so any RPC needed to debug it must read
  `early_runtime`. `GetVirtioDebug` is the one such RPC
  (`arcbox-api/src/system.rs`, `self.early_runtime.ready()`). Never gate a
  diagnostic on `shared_runtime`; gate on `early_runtime.ready()` instead —
  `ready()` is the `SharedRuntimeExt` method (`grpc/mod.rs`) that returns
  `UNAVAILABLE` only while the handle's `OnceLock` is empty, and
  `early_runtime` fills the moment `Runtime` is constructed.
- `WatchSetupStatus` is the sole readiness/failure signal clients (desktop,
  e2e) may use — never log-grep or sleep. Fatal startup failures MUST call
  `SetupState::set_failed` before exit (200ms flush grace, `main.rs`) so
  clients see the cause instead of a bare disconnect. Route-install state is
  mirrored into `SetupState.route_installed` by `services::route_status_loop`
  (`ContainerRouteInstalled` sets, `MachineStopped` clears) — WHY: VM
  restarts install the route outside the cold-start path that sets the flag
  directly, so without the bridge the flag goes stale until the next daemon
  restart.
- **A `SetupStatus.Phase` value that nothing publishes is invisible as a
  gap** — it simply never arrives, so a client waits forever or reports a
  plausible zero. Declaring a phase in `api.proto` therefore obliges you to
  publish it; the happy-path progression and which phases are conditional
  live in the enum's own doc comment (`api.proto`) and
  `docs/daemon-lifecycle.md`, and must be updated with any change. This
  was CORE-67: `VM_STARTING`/`VM_READY`/`NETWORK_READY` sat declared and
  unpublished, leaving the slowest stretch of startup silent.
- **The VM phases are reported from inside `Runtime::init`, not derived
  from pipeline order** (`InitProgress` → `SetupPhase` in
  `startup/mod.rs::init_runtime`). WHY: `boot_runtime` is one stage that
  stages guest binaries, boots the VM, waits for the agent, then waits for
  dockerd. Publishing at the stage boundaries would bill the binary
  download to `VM_STARTING` and make `VM_READY` mean "dockerd answered" —
  the span ABX-309 budgets would measure the wrong thing. `init` reports
  `SystemVmStarting` after the binaries are staged and `SystemVmReady` when
  `vm_lifecycle.ensure_ready` returns (readiness level 2 below); the
  dockerd wait lands in the `VM_READY → NETWORK_READY` window. `init`
  reports nothing under `--no-linux-vm`, which is what keeps the VM pair
  off the wire when no guest boots.
- **`SetupState` streams every update, not the newest snapshot**
  (`arcbox-api/src/system.rs`: a `watch` for `GetSetupStatus`, a `broadcast`
  for `WatchSetupStatus`). WHY: `NETWORK_READY` and `READY` are published
  ~300 µs apart with no await point between them, so a snapshot channel
  hands a subscriber only `READY` whenever it does not get scheduled in
  that window — indistinguishable from a phase that was never published,
  and the exact bug CORE-67 set out to remove. The two halves are kept
  atomic by opposite sides of one lock: `publish` broadcasts from inside
  `send_modify`, holding the write lock, and `subscribe` takes the snapshot
  and the receiver together under the read lock that write lock excludes.
  Split either pair and you drop an update or replay one already folded
  into the snapshot, walking a client's phase backwards. Regressions:
  `back_to_back_phases_are_all_delivered`,
  `the_snapshot_is_not_replayed_as_an_update`.
- **A listener the phase promises is bound before `start_services` returns,
  never inside its spawned task** (`DnsService::bind`, then
  `DockerApiServer::bind` + `serve` — CORE-71). WHY: a task that binds and
  only logs its error cannot fail startup, so the pipeline publishes
  `NETWORK_READY` and `READY` for a daemon whose primary API no client can
  reach. `NETWORK_READY` therefore covers whichever services this daemon
  runs — `--no-linux-vm` reaches it with DNS alone — and the Kubernetes
  proxy is the deliberate exception: a taken 16443 is tolerated, so it is
  started here but not promised. Adding a listener means deciding which of
  those two it is.
- **`SetupStatus.vm_running` is owned by `services::vm_running_loop`**, which
  mirrors `VmLifecycleState::is_ready` (readiness level 2 below) off
  `Runtime::subscribe_system_vm_state`. WHY: it used to be set once by
  cold-start recovery on a successful guest query and never cleared, so it
  read `true` for the rest of the daemon's life after any stop (CORE-70). A
  second writer re-introduces that class of drift — the loop owns both
  edges. It is armed from `init_runtime` *before* `Runtime::init`, not from
  `start_services`: the VM goes ready partway through `init`, so a later
  start would report it down for the whole dockerd wait. And it is only as
  good as the lifecycle state — an unmanaged guest crash leaves that
  `Running` (ABX-414: no `HealthMonitor` loop), so the flag says "the daemon
  believes the VM is up", not "the VM answered just now". Regression:
  `vm_running_loop_follows_the_lifecycle_both_ways`.
- Startup-cancellation invariant: the flock (`daemon_lock`) and
  `early_runtime` are held in `StartupHandles`, not only in pipeline-local
  context (`context.rs`, `main::run` keeps a clone). WHY: a signal can drop
  the startup future mid-boot while the VM keeps booting in its own
  lifecycle tasks — `interrupt_startup` reaches that orphan VM through
  `handles.early_runtime` (`shutdown.rs`), and the flock must survive the
  cancellation or a concurrent daemon boots into the same disk images. Do
  not move these into pipeline-local state.
- `main::run` keeps a signal watcher armed for the entire startup window;
  the default SIGTERM disposition would otherwise kill the process mid-boot
  and orphan the VM + its Virtualization.framework helpers.

## Failure signatures (symptom → first commands → likely cause)

- Guest boots and daemon reaches READY, but every registry pull / TLS
  handshake fails certificate-validity checks. First: check the daemon log
  for `guest clock sync ping failed` (a warn, not an error);
  `rg -n "sync_guest_clock" engine/arcbox-engine/src/vm_lifecycle/boot.rs`.
  Likely cause: the HV backend has no RTC (ABX-416); the guest wall clock is
  pushed only by the best-effort post-readiness agent ping
  (`AgentPingRequest.timestamp_secs` → agent `clock_settime`). If that ping
  fails
  the guest sits at the kernel default epoch and boot still succeeds, so the
  symptom surfaces far downstream. Do NOT remove the ping until a PL031 RTC
  device lands.
- Large VM (>8 vCPUs) boot-wedges; guest PID 1 in D-state. First, while the
  VM is still alive, capture the live snapshot — do NOT do console-log
  archaeology (it produced multiple wrong root causes on ABX-386): call the
  `GetVirtioDebug` RPC (`SystemService`, served from `early_runtime`) or read
  the e2e-captured `virtio-debug.json`. Compare per-queue live avail/used
  indices. Likely cause: a per-queue register-file bound too small for
  one-blk-queue-per-vCPU (ABX-386 class; `MAX_VIRTQUEUES` lives in
  `virt/arcbox-vmm`). See `virt/AGENTS.md` "Debugging" and
  `virt/arcbox-vmm/AGENTS.md` "MMIO Register File".
- `docker` commands hang or hit a dead pooled connection right after a
  backend switch / VM restart. First:
  `rg -n "reset_if_restarted|restart_generation" app/arcbox-docker app/arcbox-core`.
  Likely cause: the proxy's restart-detection ordering broke (see Docker
  proxy contract below).
- Operations fail with stale-CID / connection-refused errors while both
  `MachineManager` state and `VmLifecycleState` still say `Running`. First:
  confirm whether the guest actually died (`GetVirtioDebug`, guest
  console). Likely cause: no crash auto-recovery — `HealthMonitor`'s
  monitoring loop is unimplemented (`vm_lifecycle/health.rs`: `interval` is
  stored, no loop consumes it) and `on_ensure_ready` (`actor.rs`)
  short-circuits on `is_ready()`, returning the cached CID without probing,
  so a dead guest never leaves `Running` (ABX-414).
- Daemon log's `ARCBOX_BUILD_SHA` ("arcbox-daemon starting", `main.rs`)
  doesn't match the commit you built ("which binary am I running?"). First:
  `cargo clean -p arcbox-daemon && cargo build -p arcbox-daemon`. Likely
  cause: `arcbox-daemon/build.rs` emits no `rerun-if-changed` on
  `.git/HEAD`, so a rebuild that changes no package source file reuses the
  cached SHA — a new commit alone logs a STALE sha (the build.rs comment
  claiming it stays "fresh" holds only when a package file also changed).

## Backend transport & agent

- `MachineManager::connect_agent` yields different transports by backend:
  blocking on the HV AF_UNIX socketpair, async on VZ AF_VSOCK and on Linux.
  Branch on `AgentClient::is_blocking()`
  (`engine/arcbox-engine/src/agent_client.rs`); calling a `*_blocking` RPC on VZ (or
  an async RPC on HV) fails deterministically. `sync_guest_clock`
  (`vm_lifecycle/boot.rs`) is the reference pattern: `spawn_blocking` the
  connect, then dispatch `ping_blocking` vs `ping` on `is_blocking()`.

## VM lifecycle internals (`engine/arcbox-engine/src/vm_lifecycle`)

- `VmLifecycleManager` is a thin facade over a single actor
  (`actor.rs`): mutations go through `Command` variants on an `mpsc`
  channel; reads (`state`, `is_running`) come lock-free from a `watch`
  channel and must never block. Slow I/O (create/start/agent-wait/stop) runs
  in preemptible sub-tasks (`boot.rs`) so `force_stop` can preempt an
  in-flight boot or graceful stop. Adding a synchronous mutation or blocking
  the actor loop breaks force-stop preemption.
- The actor is spawned lazily on the first async facade call (`ensure_actor`,
  `mod.rs`). WHY: constructors are synchronous and may run outside a tokio
  runtime (e.g. `Runtime::new` in tests) where `tokio::spawn` panics.
- `DEFAULT_STARTUP_TIMEOUT_SECS = 90` is deliberately generous (erofs rootfs
  + large `docker.img` mount under CPU/I/O pressure). A tight 30s budget
  raced the cold-boot path into "timeout waiting for agent" loops — do not
  tighten it toward the <1.5s cold-boot target.
- **The idle balloon never shrinks today: no macOS backend reclaims** —
  the gate is `BalloonDeps::reclaim_capable` (`balloon/controller.rs`),
  false on both backends, and it is load-bearing (measured 2026-07-29,
  macOS 26.4; full evidence in `balloon/mod.rs` docs). VZ inflation
  releases NOTHING host-side (15.35 GB inflated, daemon `phys_footprint`
  byte-identical, pages *compressed as live data* under real host
  pressure). HV inflates via `MADV_DONTNEED`, which Darwin treats as a
  deactivation hint (calibrated footprint-inert; contents preserved).
  Host footprint is NOT the configured `memory_mb` — VZ commits guest RAM
  lazily, so the cost is the high-water mark of guest-*touched* pages
  (measured 2026-08-01: a fresh idle 16 GB VM = ~718MB; the guest
  allocating 3GB of tmpfs takes it to 3717MB and freeing it changes
  nothing). With no reclaim path that mark is a one-way ratchet, and
  `memory_mb` is a ceiling on the eventual cost rather than an upfront
  charge. The only macOS levers are `memory_mb`, a VM restart, and the
  macOS compressor. Do not flip a backend to reclaim-capable without a
  measured host `phys_footprint` drop on inflate (HV path: switch the
  device to `MADV_FREE_REUSABLE` first).
- `set_backend` only changes the backend used on the next (re)boot; it does
  NOT stop or restart a running VM. To apply immediately the caller forces a
  recreate via `Runtime::switch_system_vm_backend`. The backend is seeded
  from the persisted machine, so it survives daemon restarts.
  WARNING: `Runtime::switch_system_vm_backend` (`runtime.rs`) runs
  `shutdown` → `set_backend` → `ensure_ready` with NO serialization against
  a concurrent `ensure_ready`; a boot landing between the stop and
  `set_backend` boots the OLD backend and the switch still reports success
  (ABX-414).
- Three readiness levels, never read one as another — each gates a
  different call surface. (1) `MachineManager` `MachineState::Running`
  (`machine.rs::start`): for the System VM (`distro: None`) this flips the
  instant the VM *process* starts, BEFORE the agent answers — the agent
  wait (`wait_for_machine_ready`) is gated on `distro.is_some()` and never
  runs for the System VM, so it means only "VM process exists," which is
  exactly what `connect_agent`/`connect_vsock_port` gate on. (2)
  `VmLifecycleState::Running`: the agent replied to a ping. (3)
  docker-ready: guest dockerd answers `/_ping` (`GuestDockerBackend`
  watch). A consumer reading `MachineManager` `Running` as "usable" issues
  RPCs into a VM whose agent/dockerd is not up. The `MachineManager`
  `MachineState` lives outside the lifecycle actor on purpose (physical vs
  logical layering) — do not unify them.
- **`restart_generation` reports departures, not arrivals.** It is bumped on
  VM *stop* (`Effect::BumpGeneration`, fired from `stopping` on
  `VmEvent::Stopped`), so a task that waits for it to advance wakes at the
  START of the gap where no guest exists. Under
  `switch_system_vm_backend` it then races the reboot with the same
  `DEFAULT_STARTUP_TIMEOUT_SECS` budget the boot itself gets; after a plain
  stop with the daemon still alive, no guest is coming at all. Anything that
  must act when the VM comes *up* watches
  `VmLifecycleManager::subscribe_state` (`Runtime::subscribe_system_vm_state`)
  instead: wait for `VmLifecycleState::is_ready`, do the work, then wait for
  it to clear. Reference consumer: the `~/ArcBox` export reconcile
  (`arcbox-daemon/src/nfs_mount.rs`), whose per-incarnation supervisor loop
  also carries the companion rule — one pass's failure must be retried, not
  propagated out of the loop, or every later incarnation inherits the broken
  state (ABX-426).
- Two startup timeouts cover SEQUENTIAL phases; don't conflate them.
  `DEFAULT_STARTUP_TIMEOUT_SECS = 90` (`mod.rs`) budgets VM boot → agent
  ready; `ContainerRuntimeConfig::startup_timeout_ms = 150_000`
  (`config.rs`) budgets agent ready → dockerd `/_ping`. Residual skew: the
  guest watch loop (`guest/arcbox-agent/src/agent/linux/rpc.rs`
  `handle_watch_readiness`) emits `RuntimeFailed` at exactly its own
  deadline, which equals the host's recv deadline, so the host can drop the
  stream before the failure detail lands (ABX-414).

## Docker proxy ↔ lifecycle contract (cross-crate)

`VmLifecycleManager::restart_generation()` is bumped on every VM stop
(the `fetch_add` lives in `actor.rs`'s `Effect::BumpGeneration` arm;
`mod.rs` holds only the read accessor). The Docker proxy compares it via
the request path to detect a
System VM restart (backend switch / recovery) and reset stale state
(`arcbox-docker/src/proxy/state.rs`). Reading a stop-edge counter is correct
*here* precisely because the proxy acts on its next request, which by
definition arrives once the VM is back — do not copy the pattern into a task
that must act at the restart itself (see "reports departures, not arrivals"
above). When editing either side, keep in lockstep:

- `reset_if_restarted` must drop the pooled connections BEFORE flipping
  cached readiness to `Unverified`. WHY: a concurrent verifier that sees
  `Unverified` dials `_ping` immediately and must use the fresh client;
  resetting after would race it onto a connection to the dead VM.
- Endpoint readiness is verified with an HTTP `GET /_ping` against guest
  dockerd (ABX-408), not mere socket-connectability. Do not substitute a
  connect check.
- Both the request path (`ensure_endpoint_verified`) and the host-networking
  reconciler go through the same `reset_if_restarted` so they react to a
  restart through one pool.

## Host port forwarding & image pull (`arcbox-docker`)

- Published container ports are forwarded in userspace: container inspect →
  `parse_port_bindings` → `PortForwarder` binds a host `TcpListener`/`UdpSocket`
  per rule (`virt/arcbox-net/src/port_forward.rs`), reachable via loopback. No
  privileged helper is involved, so a high/ephemeral host port is safe to
  publish under an isolated test daemon (it touches none of the three e2e
  host-globals). A low (<1024) host port simply fails to bind under the
  non-root daemon — there is no helper fallback — so keep published test ports
  ephemeral.
- Image pull is NOT an ArcBox code path: `POST /images/create` (docker pull) is
  proxied verbatim to guest dockerd, which does the registry pull. This is what
  `runtime/AGENTS.md` means by "the pull path elsewhere" — there is no host-side
  pull module to call; drive it through the Docker API proxy.

## Boot-asset pin (`engine/arcbox-image`)

- `assets.lock` is embedded at COMPILE TIME
  (`include_str!("../../../../assets.lock")`, `lockfile.rs`): the daemon
  verifies against whatever `assets.lock` existed when it was built.
  Changing the boot manifest/rootfs requires editing the repo `assets.lock`
  AND rebuilding the daemon — editing the file alone changes nothing.
- The `manifest_sha256` pin is verified on BOTH `get_assets` and
  `prepare_binaries` (`verify_manifest_pin`, `provider.rs`), fail-closed on
  mismatch. A pin MISMATCH makes `resolve_desired_boot` error; `boot.rs`
  catches it and downgrades to a `could not resolve desired boot params;
  skipping drift check` warn, then boots on the PERSISTED cmdline (drift
  recreate skipped). A MISSING pin is a loud warn + skipped verification,
  kept deliberately so local dev can boot unreleased assets (#369). Symptom
  of an accidental stale/missing pin: boots keep an old kernel/cmdline with
  only that warn — grep the daemon log for it.

## Extending checklists

- Changing a phase's ordering or adding a phase: update the chain in
  `main::start`, the context types in `context.rs`, and
  `docs/daemon-lifecycle.md` together; re-check the gRPC-before-slow-phases
  and lock-before-gRPC constraints.
- Adding a diagnostic RPC: serve it from `early_runtime`, not
  `shared_runtime`, and add a test that it answers while `shared_runtime` is
  empty.
- Touching the daemon lock / socket paths / spawn handoff: the CLI's
  matching logic (`arcbox-cli` `daemon-spawn.lock` + `daemon.lock` handoff)
  must change with it — see `docs/daemon-lifecycle.md` "Spawn serialization".
- Validate untrusted RPC/request inputs once at the daemon boundary. The
  checked-arithmetic rule for virtqueue/ring values (ring GPA, descriptor
  field, queue index) lives in `virt/AGENTS.md` "Guest-controlled input" —
  that surface belongs to `virt/`, not this layer.

## Validation ladder (cheapest first)

VZ is the oracle backend: HV-only red points at the HV implementation;
double red (HV and VZ) points above the hypervisor. Run cheapest first:

1. Crate unit tests for the touched crate.
2. Daemon-level e2e with `ARCBOX_VM_BACKEND=hv`:
   `cargo test -p arcbox-e2e --test virtio_debug -- --ignored` (live
   `GetVirtioDebug` snapshot) and `--test boot_assets -- --ignored`. The
   e2e targets are `#[ignore]`d — without `-- --ignored` the run reports
   "0 tests run" and validates nothing.
3. Race-class fixes: `cargo xtask e2e --repeat N` (prebuilds once, archives
   per-run logs/metrics, preserves failed data dirs).

e2e realities (see `tests/e2e/AGENTS.md`): readiness only via
`WatchSetupStatus`; failures self-preserve forensics (data dir kept,
`virtio-debug.json` captured while the VM is alive, `metrics.json` phase
timings) — read those before re-running; a stale staged `arcbox-agent`
fails boots confusingly (newest mtime wins); point `ARCBOX_E2E_IMAGE` at a
reachable mirror rather than weakening a test.

## Known gaps / open issues

- ABX-415: daemon SIGSEGV on SIGTERM teardown after successful runs. The
  daemon's `shutdown.rs` only triggers the VM stop; the suspect crash site
  is the HV teardown ordering (`virt/arcbox-vmm/AGENTS.md` "Teardown
  ordering") — do not misdiagnose it as a new regression from your change.
- ABX-416: no PL031 RTC on HV (see the clock-sync failure signature above).
- Current HV daemon perf is far from targets (root CLAUDE.md table):
  daemon-ready ~11s (target <1.5s), idle CPU ~3.87% (<0.05%), idle RSS
  ~1.04GB (<150MB). These are known baselines, not per-change regressions.
- Per-boot counters (~2301 unpark-broadcasts / ~71 kick-broadcasts) drive
  R2/R3 acceptance in Linear — a refactor must keep the counter sites honest
  (see `virt/arcbox-vmm/AGENTS.md`).
- ABX-413: tgz-packaged docker-tools are verified only via their sha
  sidecar at download time; the EXTRACTED binary is never re-hashed.
- ABX-414: lifecycle-hardening umbrella — the three-level readiness split,
  the unimplemented `HealthMonitor` loop (no crash auto-recovery), the
  unserialized `switch_system_vm_backend`, and the guest-vs-host readiness
  deadline skew (all detailed above).
- ABX-417: the `arcbox-boot` registry crate still carries the upstream
  fixed-temp-name download bug, and the staged `arcbox-agent` binary is
  verified by existence + exec-bit only (no hash).
