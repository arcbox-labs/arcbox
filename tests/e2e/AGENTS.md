# tests/e2e — Agent Guidance

Commands and env-var reference live in README.md; these are the behavioral
rules for agents working with or extending the harness.

## Isolation

- One data dir per daemon. `DaemonHandle::spawn` enforces it (refuses
  `~/.arcbox` / `~/.arcbox-dev`, including symlinked roots) — do not
  weaken the guard.
- Never touch the three host-globals from a test: privileged-helper state
  (`/var/run/arcbox*`, `/etc/resolver`, host routes), the Docker CLI
  context (no `--docker-integration`; use `DOCKER_HOST`), and fixed
  published host ports.

## Readiness & Forensics

- Readiness is observed only via `WatchSetupStatus`
  (`DaemonHandle::wait_ready`). Never grep logs or sleep for readiness.
- Failures self-preserve forensics: the data dir is kept,
  `virtio-debug.json` is captured while the VM is still alive, and
  `metrics.json` records phase timings. Read those artifacts before
  re-running or theorizing. Keep this property when adding scenarios.

## Environment realities

- `stage_dev_boot_assets` stages kernel/rootfs/manifest and the freshest
  locally available `arcbox-agent` (dev tree → musl target →
  `~/.arcbox/bin`, newest mtime wins) — a stale agent fails boots in
  confusing ways.
- Guest registry access is environment-dependent; point `ARCBOX_E2E_IMAGE`
  at a reachable mirror instead of weakening a test.
- `ARCBOX_VM_BACKEND=hv|vz` selects the first-boot backend (a persisted
  machine backend wins after a switch). VZ is the oracle: HV-only red
  points at the HV implementation, double red points above the hypervisor.
- Signing: `ensure_signed` is idempotent; dev entitlements boot both
  HV and VZ — only bridged vmnet needs Developer ID + provisioning
  profile.

## Repetition

- Repeated runs go through `cargo xtask e2e` (prebuilds once, archives
  per-run logs and metrics, records preserved dirs). Do not loop
  `cargo test` by hand for stress runs.
