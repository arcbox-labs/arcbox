# ArcBox E2E tests

This crate contains end-to-end tests that orchestrate ArcBox binaries, VM boot
assets, Docker, and external test fixtures. Keep long-running test process
management here rather than in `xtask`.

E2E tests use Rust's standard test harness instead of a custom runner. Tests are
ignored by default because they build release binaries, boot a VM, and require a
local Docker CLI plus macOS virtualization support.

## Commands

Run the boot assets VM and Docker lifecycle integration test:

```bash
cargo test -p arcbox-e2e --test boot_assets -- --ignored --nocapture
```

When using the repository development shell:

```bash
devenv shell -- cargo test -p arcbox-e2e --test boot_assets -- --ignored --nocapture
```

List available E2E tests without running ignored tests:

```bash
cargo test -p arcbox-e2e -- --list
```

## Configuration

The boot assets test reads configuration from environment variables:

- `SKIP_BUILD=1` — reuse existing `target/release` binaries.
- `KEEP_TEST_DIR=1` — preserve the temporary test directory for debugging.
- `ARCBOX_BOOT_ASSET_VERSION=<version>` — override `assets.lock`
  `[boot].version`.
- `ARCBOX_GUEST_DOCKER_VSOCK_PORT=<port>` — pass a custom guest Docker vsock
  port to `arcbox-daemon`.

Tracing is controlled with `RUST_LOG`; it defaults to `info` when unset.
