# ArcBox xtask

`xtask` is the repository-level automation entrypoint for ArcBox. It owns tasks
that coordinate multiple tools, generate or package release artifacts, or manage
structured repo metadata. It is not a dumping ground for thin wrappers around
existing canonical tools.

## Running commands

From the repository root:

```bash
cargo xtask <command>
```

Inside the project development environment, use the same entrypoint:

```bash
devenv shell -- cargo xtask <command>
```

`cargo xtask` is configured in `.cargo/config.toml` as an alias for
`cargo run --package xtask --`.

## Commands

- `cargo xtask dev boot-assets` — prepare `boot-assets/dev` from the user boot
  cache or a neighboring `arcbox-kernel` checkout.
- `cargo xtask macos dev` — build, locally sign, and run `arcbox-daemon` for
  development.
- `cargo xtask release check-tool-updates` — check Docker/Kubernetes tool
  updates, compute SHA-256 checksums, and rewrite `assets.lock`.
- `cargo xtask release package-tarball` — build the desktop release `.tar.gz`
  from CI artifacts and write the matching `.sha256` file.
- `cargo xtask release fleet-asset` — stage a CI-built `arcbox-fleet-agent`
  binary as a raw per-platform release asset (`arcbox-fleet-agent-<os>-<arch>`)
  and write the matching `.sha256` file. The fleet agent ships as a bare
  binary: the release tag carries the version, and the checksum is what the
  gateway pins for agent self-update.

## Layout

```text
xtask/
  README.md
  src/
    main.rs                  # CLI shape and dispatch only
    commands/
      mod.rs
      dev.rs                 # development orchestration
      e2e.rs                 # e2e stress-run orchestration
      idle.rs                # idle CPU/memory sampling
      macos.rs               # macOS build/sign/run tasks
      release.rs             # release command dispatch
      release/
        check_tool_updates.rs
        fleet_asset.rs
        package_tarball.rs
```

`commands/<domain>.rs` is the domain entrypoint. Split a subcommand into
`commands/<domain>/<subcommand>.rs` once the implementation has real substance.
Do not keep modules named after removed scripts.

## Design rules

- Use `xshell` for short-lived external commands such as `cargo build` and
  `codesign`.
- Use `std::process::Command` for long-running processes or commands whose
  stdout/stderr/process lifetime needs direct control.
- Use Rust crates for structured formats and portable primitives: `serde_json`
  for JSON, `toml_edit` for TOML, `sha2` for SHA-256, and `tar`/`flate2` for
  release archives.
- Do not shell out merely to avoid a small, appropriate dependency.
- Do not reintroduce thin wrappers. If a command is already owned by a canonical
  package script or purpose-built binary, call that tool directly instead of
  adding an `xtask` facade.
