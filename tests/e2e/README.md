# ArcBox E2E tests

This crate contains end-to-end test runners that orchestrate ArcBox binaries,
VM boot assets, Docker, and external test fixtures. Keep long-running test
process management here rather than in `xtask`.

## Commands

```bash
cargo run --manifest-path tests/e2e/Cargo.toml -- boot-assets
```

`boot-assets` runs the boot assets VM and Docker lifecycle integration test.

Options:

- `--skip-build` or `SKIP_BUILD=1` — reuse existing release binaries.
- `--keep-test-dir` or `KEEP_TEST_DIR=1` — preserve the temporary test directory.
- `--version <version>` or `ARCBOX_BOOT_ASSET_VERSION` — override
  `assets.lock` `[boot].version`.
- `--guest-docker-vsock-port <port>` or `ARCBOX_GUEST_DOCKER_VSOCK_PORT` — pass
  a custom guest Docker vsock port to `arcbox-daemon`.
