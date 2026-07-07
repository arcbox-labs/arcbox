# Daemon Lifecycle

## Startup Sequence

The daemon starts in five ordered phases. Each phase must complete before
the next begins.

```
init_early        Create directories, resolve config          ~instant
    │
acquire_lock      flock(daemon.lock), terminate stale daemon  ~instant or ≤30 s
    │
start_grpc        Bind arcbox.sock, SystemService available   ~instant
    │             Desktop can connect from this point on.
    │
wait_for_resources  Wait for docker.img holders to release    0–10 s
    │               Reported as CLEANING_UP phase via gRPC.
    │
init_runtime      Seed/download boot assets, start VM         variable
                  Reported as DOWNLOADING_ASSETS → ASSETS_READY
                  → VM_STARTING → VM_READY → NETWORK_READY.
    │
start_services    DNS, Docker API, Docker CLI integration     ~instant
    │
Ready             SetupPhase::Ready
```

If any phase fails, the daemon publishes `SetupPhase::Failed` with the
error text in `SetupStatus.error`, waits ~200 ms so connected
`WatchSetupStatus` streams flush the final event, and exits non-zero.
Clients should treat FAILED (or stream EOF plus daemon exit) as
startup failure.

### Why gRPC starts before resource cleanup

The desktop app polls the daemon's gRPC `WatchSetupStatus` stream with a
30 s timeout. If gRPC were started after stale-daemon cleanup (which can
block for up to 40 s), the desktop would time out. Moving gRPC earlier
lets clients observe the full phase progression in real time.

## Daemon Lock (`daemon.lock`)

Exclusive ownership is managed by a POSIX advisory lock (`flock(2)`) on
`~/.arcbox/run/daemon.lock`. The lock file also stores the current PID
for diagnostics.

### Properties

- **Kernel-managed**: released automatically on process exit, crash, or
  SIGKILL. No stale-lock scenarios are possible.
- **Reentrant-safe**: the file is never deleted. New daemons reuse it.
- **Non-blocking probe**: `flock(LOCK_EX | LOCK_NB)` tests whether
  another daemon is alive without polling.

### Acquisition flow

```
open(daemon.lock, O_CREAT | O_RDWR)
    │
flock(LOCK_EX | LOCK_NB)
    ├─ success → no stale daemon, proceed
    └─ EWOULDBLOCK → lock held
        │
        read PID from file
        │
        is_arcbox_daemon(pid)?
        ├─ yes → SIGTERM, wait up to 30 s, SIGKILL fallback
        └─ no  → log warning, wait for lock release
        │
        flock(LOCK_EX)   ← blocks until holder exits
        │
write current PID
```

## Graceful Shutdown (SIGTERM / Ctrl+C)

```
signal received
  ├─ cancel CancellationToken         → all services begin draining
  ├─ drain(DNS, Docker, gRPC)         → 5 s timeout, then abort
  ├─ remove_route()                   → clean up container subnet route (macOS)
  ├─ runtime.shutdown()
  │   ├─ stop port forwarders
  │   ├─ vm_lifecycle.shutdown()       → graceful VM stop, flush disk
  │   ├─ stop remaining machines
  │   └─ network_manager.stop()
  ├─ DockerContextManager.disable()   → remove Docker CLI integration
  ├─ cleanup_files()                  → delete docker.sock, arcbox.sock
  │                                     daemon.lock kept (flock auto-releases)
  └─ process exits
```

### Residual state after graceful exit

| File | State | Next startup |
|------|-------|-------------|
| `daemon.lock` | exists, old PID, **lock released** | `try_flock` succeeds instantly |
| `docker.sock` | deleted | — |
| `arcbox.sock` | deleted | — |
| `docker.img` | exists, no holders | — |
| VM | gracefully stopped | — |

No manual intervention needed.

## Crash / SIGKILL

When the daemon is killed without graceful shutdown:

- `flock` is released by the kernel (fd closed).
- Socket files are **not** cleaned up.
- VM is **not** gracefully stopped.
- Container subnet route is **not** removed.
- `docker.img` may still be held by Virtualization.framework XPC helpers.

### Residual state after crash

| File | State | Next startup |
|------|-------|-------------|
| `daemon.lock` | exists, old PID, **lock released** | `try_flock` succeeds instantly |
| `docker.sock` | **stale** | `DockerApiServer::run` removes before bind |
| `arcbox.sock` | **stale** | `start_grpc` removes before bind |
| `docker.img` | **possibly held by XPC helpers** | `wait_for_resources` waits up to 10 s |
| VM | non-graceful termination | Virtualization.framework cleans up |
| Route | **stale** | `recovery::run()` rebuilds |

All residual state is handled automatically on next startup. No manual
intervention needed.

## Stale Daemon Takeover

When a new daemon starts while an old one is still running:

1. `acquire_lock` detects the held lock.
2. Reads the old PID from `daemon.lock`.
3. Verifies it is an arcbox-daemon process (`libproc::pidpath`).
4. Sends SIGTERM → old daemon begins graceful shutdown.
5. Waits up to 30 s for the old daemon to exit.
6. Falls back to SIGKILL if unresponsive.
7. Acquires the lock once released.
8. `start_grpc` removes any stale sockets before binding.
9. `wait_for_resources` waits for `docker.img` holders to release.

The old daemon's graceful shutdown runs its full sequence (drain, VM stop,
socket cleanup). The new daemon only needs to handle the `docker.img`
holdover case.

## Socket Lifecycle

Each server owns its socket file. Sockets are **not** cleaned up
centrally during startup — each server removes and rebinds independently:

| Socket | Owner | Cleanup |
|--------|-------|---------|
| `arcbox.sock` | `services::start_grpc` | `remove_file` before `UnixListener::bind` |
| `docker.sock` | `DockerApiServer::run` | `remove_file` before `UnixListener::bind` |

This avoids race conditions where a centralized cleanup could delete a
socket that another component has already bound.

## Edge Cases

### docker.img held by orphaned XPC helpers

Virtualization.framework spawns XPC helper processes that may outlive the
daemon. These processes hold `docker.img` open. The daemon waits up to
10 s for them to exit (`wait_for_resources`), then proceeds. If they
persist, `init_runtime` may fail because the disk image is locked.

**Manual fix**: `ps aux | grep -i virtualization` and kill the orphaned
helpers, then restart the daemon.

The daemon does **not** SIGKILL these processes automatically because
forceful termination risks corrupting the guest filesystem.

### Lock held by non-arcbox process

If `daemon.lock` is held by a process that is not an arcbox-daemon (e.g.,
a debugger or strace wrapper), `acquire_lock` logs a warning and blocks
until the lock is released. It does not send signals to non-arcbox
processes.

### PID reuse

With `flock`, PID reuse is not a concern. The lock is tied to the file
descriptor, not the PID. Even if the kernel reuses a PID for an unrelated
process, the new daemon detects that the lock is not held (because the
original holder's fd was closed on exit) and proceeds immediately.

The CLI (`arcbox daemon status/stop/start`) also uses `flock` probing
(`LOCK_EX | LOCK_NB`) rather than `kill(pid, 0)` for liveness detection.
PID is only read from the lock file for SIGTERM delivery and display.

### Spawn serialization (`daemon-spawn.lock`)

The alive probe releases its flock immediately, so two racing
`arcbox daemon start` invocations could both observe "not running" and
both spawn a daemon — the flock loser would then displace the winner
mid-boot via the stale-daemon takeover. To close this TOCTOU, the CLI
holds a separate `daemon-spawn.lock` (in the run directory) from the
alive check until the spawned daemon owns `daemon.lock` (bounded by a
10 s handoff timeout). A concurrent start blocks on the spawn lock and
then re-checks liveness, reporting "already running" instead of
spawning a duplicate. `daemon.lock` itself remains exclusively the
daemon's resource.

launchd (`RunAtLoad`/`KeepAlive`) does not take the spawn lock; a
launchd-vs-CLI race still resolves through the daemon-side takeover,
which is orderly now that signals are handled during startup.
