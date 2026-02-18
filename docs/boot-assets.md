# Boot Assets Ownership

## Scope

This repository (`arcbox`) is the **consumer** of boot assets.

Boot asset **build and release** are being migrated to the dedicated repository:

1. `arcbox-labs/boot-assets`

## Responsibilities In This Repository

1. Download, verify, and cache boot assets at runtime:
   `crates/arcbox-core/src/boot_assets.rs`
2. Wire boot assets into VM lifecycle:
   `crates/arcbox-core/src/vm_lifecycle.rs`
3. Provide CLI operations (`prefetch/status/list/clear`):
   `crates/arcbox-cli/src/commands/boot.rs`
4. Development and integration tests:
   `scripts/setup-dev-boot-assets.sh`, `scripts/test-boot-assets.sh`

## Responsibilities In boot-assets Repository

1. Build kernel/initramfs artifacts
2. Package tarball + checksum + manifest
3. Publish GitHub Releases for versioned boot assets (tag: `v{version}`)

## Transitional Notes

1. `tests/resources/*` in this repository are test fixtures.
2. Release-grade boot assets are generated in `arcbox-labs/boot-assets` workflows.
3. `arcbox` repository should not carry release workflows for boot assets.
4. Runtime should eventually require manifest presence to guarantee traceability.
