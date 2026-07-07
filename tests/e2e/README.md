# ArcBox E2E tests

This crate contains end-to-end tests that orchestrate ArcBox binaries, VM boot
assets, Docker, and external test fixtures. Keep long-running test process
management here rather than in `xtask`.

E2E tests use Rust's standard test harness instead of a custom runner. Tests are
ignored by default because they build release binaries, boot a VM, and require
macOS virtualization support (plus a local Docker CLI for the daemon-level test).

## Fixtures

- `signing::ensure_signed` — idempotently signs a test binary with the
  virtualization entitlements: Developer ID when the ArcBox identity is in the
  keychain, otherwise ad-hoc with `bundle/arcbox.dev.entitlements` (sufficient
  for HV/VZ; only bridged vmnet needs Developer ID).
- `daemon::DaemonHandle` — spawns a signed `arcbox-daemon` under an isolated
  `--data-dir` and waits for readiness on the daemon's `WatchSetupStatus` gRPC
  stream, failing fast on a FAILED phase or daemon exit (with the log tail).
  Drop terminates the daemon gracefully (SIGTERM, then SIGKILL). The isolated
  data dir means tests never touch `~/.arcbox` and can run alongside a
  developer's daemon.

## Parallel daemons: one data dir per daemon

Everything a daemon contends on — flock, gRPC/Docker sockets, logs, machine
state — derives from `--data-dir` (`HostLayout`), so daemons with distinct data
dirs run side by side. That is the isolation contract for parallel fix work:
**one worktree/agent = one data dir**, and the harness enforces it —
`DaemonHandle::spawn` refuses a data dir inside `~/.arcbox` or `~/.arcbox-dev`.

Three host-global resources are *not* covered by the data dir. Tests must not
touch them:

- **Privileged helper state** (`/var/run/arcbox*`, `/etc/resolver`, host
  routes) — never run the helper from a test.
- **Docker CLI context** (`~/.docker`) — never pass `--docker-integration`;
  point the Docker CLI at the handle's socket with `DOCKER_HOST` instead.
- **Published host ports** — don't publish fixed host ports from containers;
  concurrent runs would collide.

## Commands

Daemon-level test — boots the VM through a real daemon and runs Docker
lifecycle checks over the Docker API socket:

```bash
cargo test -p arcbox-e2e --test boot_assets -- --ignored --nocapture
```

VMM-level HV probe — drives the HV backend directly (no daemon): boot, vsock
agent RPC, DAX, agent supervision, pause/resume, stop:

```bash
cargo test -p arcbox-e2e --test hv_vmm -- --ignored --nocapture
```

Dual-backend matrix — the boot-assets scenario once per backend, VZ first.
VZ is the oracle: HV-only red means an HV implementation bug, double red means
the bug is above the hypervisor layer:

```bash
cargo test -p arcbox-e2e --test backend_matrix -- --ignored --nocapture
```

When using the repository development shell, prefix with `devenv shell --`.

List available E2E tests without running ignored tests:

```bash
cargo test -p arcbox-e2e -- --list
```

## Configuration

Environment variables read by the tests:

- `SKIP_BUILD=1` — reuse existing `target/release` binaries.
- `KEEP_TEST_DIR=1` — always preserve the temporary test directory (it is
  preserved automatically when the test fails).
- `ARCBOX_BOOT_ASSET_VERSION=<version>` — override `assets.lock`
  `[boot].version`.
- `ARCBOX_VM_BACKEND=vz|hv` — System VM backend for the daemon under test
  (first-boot default; the daemon reads the same variable). The matrix test
  overrides it per run.
- `ARCBOX_GUEST_DOCKER_VSOCK_PORT=<port>` — pass a custom guest Docker vsock
  port to `arcbox-daemon`.
- `ARCBOX_HV_E2E_KERNEL` / `ARCBOX_HV_E2E_ROOTFS` / `ARCBOX_HV_E2E_TIMEOUT` /
  `ARCBOX_DATA_DIR` — HV probe overrides; see `src/bin/hv_e2e.rs`.

Tracing is controlled with `RUST_LOG`; it defaults to `info` when unset.
