# tests/e2e — Agent Guidance

Commands and the full env-var table live in README.md. This file is the
behavioral rules plus the debugging entry points — what to run first when a
run fails, and which paths must change together.

## Isolation invariants

- One data dir per daemon. `DaemonHandle::spawn` calls `assert_isolated`,
  which refuses a data dir at or inside `~/.arcbox` / `~/.arcbox-dev`
  (canonicalized, so symlinked roots are caught too). WHY: a test daemon
  there contends with the developer's daemon for the flock, sockets, and
  machine state. Do not weaken the guard.
- Never touch the three host-globals a data dir does not cover: privileged
  helper state (`/var/run/arcbox*`, `/etc/resolver`, host routes), the
  Docker CLI context (no `--docker-integration`; point `DOCKER_HOST` at the
  handle's socket), and fixed published host ports. WHY: concurrent runs
  collide on them. Rationale per item: README.md "Parallel daemons".

## Readiness

- Observe readiness ONLY via `WatchSetupStatus` (`DaemonHandle::wait_ready`
  / `wait_ready_blocking`). WHY: the stream fails fast on the FAILED phase
  (with the daemon's reported error) or on daemon exit (with the log tail);
  log-grep and sleep both race the startup sequence. Never grep logs or
  sleep for readiness.

## Forensics: where to look when a run fails

- Always written vs failure-only. `metrics.json` (phase timings) is written
  on every run, pass or fail — `metrics.passed = result.is_ok()` runs before
  the failure branch. The preserved data dir (`keep_test_dir = true`) and
  `virtio-debug.json` appear only on failure.
- `virtio-debug.json` is HV-only: `dump_virtio_debug` returns an empty
  device list under VZ. On a VZ-side failure there is no virtio forensic
  content — do not go looking for it.
- Two logs, different roles: `harness-daemon.log` is the daemon process's
  raw stdout/stderr (panics, failures that precede logging init);
  `log/daemon.log` is the daemon's own structured rotating log (the success
  path points at it). Read both before re-running or theorizing.

## Guest agent: two provisioning paths (do not confuse)

- `boot_assets` / `backend_matrix` / `virtio_debug` stage the agent via
  `stage_dev_boot_assets`: newest-mtime wins across `boot-assets/dev`,
  `target/aarch64-unknown-linux-musl/release`, and `~/.arcbox/bin`, copied
  into `<data_dir>/boot/<version>/arcbox-agent`. A stale agent boots but
  fails confusingly.
- The `hv_e2e` probe (`--test hv_vmm`) instead shares the real `~/.arcbox`
  (or `ARCBOX_DATA_DIR`) and execs `<share>/bin/arcbox-agent` directly,
  hard-failing if absent. It needs a musl cross-compile placed there
  (`cargo build -p arcbox-agent --target aarch64-unknown-linux-musl
  --release`), not the mtime staging. The isolation guard refuses
  `~/.arcbox` for daemons, but this probe deliberately reads it.

## Validation ladder (cheapest first)

1. Crate unit tests — `cargo test -p arcbox-e2e --lib`. Covers the isolation
   guard (`assert_isolated`) and metrics writing. Seconds, no VM.
2. Bare HV probe — `cargo test -p arcbox-e2e --test hv_vmm -- --ignored`.
   Drives the HV backend directly, no daemon: boot, vsock agent RPC, DAX,
   supervision, pause/resume. Rules the hypervisor/agent layer in or out
   without the daemon on top.
3. Daemon level — `cargo test -p arcbox-e2e --test virtio_debug -- --ignored`
   (queue snapshot from a live HV daemon) and `--test boot_assets` with
   `ARCBOX_VM_BACKEND=hv` (full Docker lifecycle). Adds the daemon,
   runtime, and Docker API surface.
4. Race-class — `cargo xtask e2e --backend both --repeat N` (archives
   per-run logs/metrics, records preserved dirs). Never hand-loop
   `cargo test` for stress runs.

- This ladder proves liveness, not datapath throughput — there is no
  automated throughput target. Prove an RX/TX regression fixed (iperf
  zero -> baseline restored) with the manual reproducer in
  `docs/net-perf-limits.md`, checked against that doc's baseline on both
  HV and VZ. Auto-forensics don't help a datapath failure
  (`virtio-debug.json` is HV-only queue/boot state) — preserve the
  scenario's own evidence (assigned `docker port`/inspect, host connect
  result) into the kept data dir.

## Debugging boot / queue failures

- Config-matrix bisect (the ABX-386 method). The `hv_e2e` probe's knobs
  shift one dimension at a time from the minimal probe (`vcpus=2`,
  `memory_mb=1024`, everything else off) toward the daemon's System VM
  shape: `ARCBOX_HV_E2E_VCPUS`, `_MEMORY_MB`, `_BALLOON`, `_NETWORKING`,
  `_DATA_IMG_MB`, `_EXTRA_SHARES`, `_BRIDGE`, `_BOOT_ONLY=1` (stop after
  agent readiness), `_LOGLEVEL` (8 = full guest console). First commands
  for a daemon boot that the bare probe survives: rerun the probe raising
  ONE knob until it also wedges. ABX-386 was pinned to "vCPU count,
  threshold exactly 8" this way — the queue register file (`MAX_VIRTQUEUES`)
  was capped at 8 while virtio-blk configures one queue per vCPU.
- Capture the live snapshot, not the console log. `GetVirtioDebug` /
  `dump_virtio_debug` records per-queue kicks and live avail/used indices
  while the VM is alive; console-log archaeology produced multiple WRONG
  root causes during the HV campaign before the snapshot found the real one.
- VZ is the oracle. `backend_matrix` already classifies the failure in its
  final `bail!`: HV-only -> "points at the HV backend implementation",
  VZ-only -> "suspect the scenario or shared layers, not HV", both ->
  "suspect layers above the hypervisor". Read that verdict line rather than
  re-deriving it.

## Known failure signatures

- `docker pull` fails with TLS / cert-time errors on a cold HV boot ->
  the guest wall clock is unset. HV has no RTC; the clock is set by the
  post-readiness agent ping (`AgentPingRequest.timestamp_secs`, see app/AGENTS.md)
  until PL031 lands (ABX-416). Route to the clock/ping path, not the
  registry.
- Daemon exits with a signal (e.g. SIGSEGV/signal 11) AFTER the assertions
  passed -> known teardown bug ABX-415. No code path turns a teardown
  signal-exit into a test failure. `DaemonHandle::drop` discards the status
  (`let _ = self.terminate()`); it is surfaced only by `TestContext::drop`
  (`boot_assets`/`backend_matrix`), which calls `daemon.shutdown()` and logs
  `info!(%status, "daemon stopped")` — a handle dropped directly (e.g.
  `virtio_debug`) logs the signal nowhere. Not a correctness regression.
- Boots fail in confusing ways -> a stale staged agent (newest-mtime wins),
  or the `hv_e2e` home fallback missing a newer version: `home_asset` is
  pinned to `~/.arcbox/boot/0.5.5/`, so once `assets.lock` moves past 0.5.5
  the probe reports "no kernel/rootfs found" despite a newer install. Prefer
  `boot-assets/dev` or `ARCBOX_HV_E2E_KERNEL`/`_ROOTFS`.
- Guest cannot reach docker.io -> point `ARCBOX_E2E_IMAGE` at a reachable
  mirror instead of weakening the test.

## Contracts to keep honest

- `metrics.json` phase names are a stable vocabulary. The daemon scenario
  emits `daemon_ready`, `image_pull`, `container_create_smoke`,
  `container_run`, `background_container`, `docker_logs`, `docker_exec`,
  `docker_stop_rm`; the probe emits `create_vmm`, `start_vm`, `agent_ready`,
  `stop_vm`. R2/R3 baselines and the `xtask e2e` archive key off these — do
  not rename a phase casually.
- Signing: `ensure_signed` is idempotent (re-signs only when the
  virtualization entitlement is missing, e.g. after a cargo relink). Dev
  entitlements (`bundle/arcbox.dev.entitlements`) boot both HV and VZ;
  `ensure_signed` signs with a `Developer ID Application: ArcBox` identity
  when one is in the keychain and falls back to ad-hoc `-` only when none
  is found. Only bridged vmnet (`com.apple.vm.networking`) needs a Developer
  ID signature backed by a provisioning profile.
