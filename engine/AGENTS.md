# engine/ — Engine Layer Agent Guidance

The embeddable, daemon-free engine library. Crates here are the
platform-neutral core that three shells assemble: the macOS daemon
(`app/`), the in-guest `vm-agent`, and (future) a bare-Linux node daemon.
The restructure plan and its locked decisions live in the company repo:
`engineering/arcbox/architecture-charter.md`.

## Layer rules (the `common/` "no VM dep" discipline, one level up)

- **No `app/` dependency, ever**: nothing here may reference the daemon,
  CLI, API, or docker-compat crates, nor daemon artifacts (lock file,
  socket paths, startup pipeline).
- **No direct macOS-only dependency** (`arcbox-vz`, `arcbox-vmnet`,
  `arcbox-route`, `ifbridge`): platform backends are reached only through
  the `virt/arcbox-hypervisor` trait layer.
- **Platform-neutral**: every crate must compile and pass unit tests on
  Linux as well as macOS.
- **Own your errors**: each crate defines its own `thiserror` type built
  on `arcbox_error::CommonError`; `arcbox-core` converts via `From` (see
  `CoreError`'s `From<ImageError>`), so `is_not_found()`-style predicates
  answer identically through either type.
- During the migration, `arcbox-core` keeps compatibility re-exports of
  moved modules; consumers migrate to the engine crates in follow-up
  commits and the re-exports then die. Prefer importing from the engine
  crate in new code.

## Crates

- `arcbox-image` — the boot-asset chain, distro machine-image index, and
  shared remote-image fetch/staging primitives. `assets.lock` is
  `include_str!`-embedded at COMPILE TIME
  (`engine/arcbox-image/src/boot_assets/lockfile.rs`, path
  `../../../../assets.lock` — four levels up to the repo root, same depth
  as its old home under `app/arcbox-core/src/`); editing `assets.lock`
  without rebuilding the daemon changes nothing. The pin semantics and
  failure signatures stay documented in `app/AGENTS.md` ("Boot-asset
  pin").
- `arcbox-snapshot` — snapshot lineage: the checkpoint catalog
  (`snapshot`), the device-mapper copy-on-write rootfs manager checkpoints
  are cloned through (`snapshot_cow`), and the template catalog that
  promotes a snapshot into a versioned base image (`template_catalog`).
  Consumed by `virt/arcbox-vm` guest-side today; the charter's snapshot
  registry client belongs here rather than above it.
  - The device-mapper paths only *do* anything on Linux (`dmsetup`, thin
    pools) but compile everywhere, which is what lets the layer above
    keep its own platform-neutrality promise.
  - Loop-device tooling is a seam, not an assumption: `CowManager` takes
    `CowOptions { block_tools: Arc<dyn BlockTools>, dmsetup_candidates, .. }`
    (`snapshot_cow/block_tools.rs`). `BusyboxBlockTools` is the reference
    (the System VM's `/bin/busybox` applets); a consumer on a stock distro
    supplies its own — `util-linux` binaries or the loop ioctls — without
    forking the module. `stat`/`mknod` are syscalls, not applets, so they
    have no seam. Adding a new host operation means adding a trait method,
    never a hard-coded binary path.
  - `CowManager`'s test seam (`CowTestProbe`, `new_with_test_probe`) is
    behind the **`test-probe` feature**, not `#[cfg(test)]`: a
    `cfg(test)` item does not exist for another crate's tests, and its
    only consumer — `arcbox-vm`'s cleanup tests — now lives in one.
    `arcbox-vm` turns the feature on in its dev-dependencies.

## Durable writes

New code that atomically replaces a **file** uses
`common/arcbox-atomic-file` rather than hand-rolling temp-then-rename. It
is **not** the same primitive as `arcbox-engine`'s private
`atomic_write`, which deliberately skips `fsync` for config files: the
crate fsyncs the file *and* the parent directory, and reports
`NotCommitted` separately from `DurabilityUncertain` so a caller can tell
"nothing happened" from "it happened, but might not survive power loss".
Pick the variant handling deliberately — a catalog that must not lie
about what it persisted treats the second as an error; a record store may
keep the record and warn.

Two places in `arcbox-snapshot` still roll their own, and both are
deliberate rather than missed:

- `snapshot::PendingSnapshot::commit` renames a whole **directory** into
  place. The crate covers files only; there is nothing to reuse.
- `snapshot_cow::persistence::write_owner_marker` writes the
  template-loop recovery markers. Migrating it is not a drop-in: it also
  `create_dir_all`s the marker directory, chmods it `0o700`, and fsyncs
  the **grandparent** so the directory creation itself is durable — and,
  less obviously, `cleanup_stale_template_markers` reaps leftover temps
  by matching the `TEMPLATE_MARKER_TEMP_PREFIX` (`.tmp-`) *prefix*, which
  the crate's `.{stem}.{uuid}.tmp` names do not have. Migrate the writer
  and that sweep together or crash recovery silently stops collecting
  its own orphans.
