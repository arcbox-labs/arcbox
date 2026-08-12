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
