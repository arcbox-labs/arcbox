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
- `cargo xtask dev bpf` — rebuild the committed sandbox NAT BPF object and its
  source-hash sidecar under `virt/arcbox-vm/bpf` (requires a clang with the
  BPF backend).
- `cargo xtask macos dev` — build, locally sign, and run `arcbox-daemon` for
  development.
- `cargo xtask release check-tool-updates` — check Docker/Kubernetes tool
  updates, compute SHA-256 checksums, and rewrite `assets.lock`.
- `cargo xtask release package-tarball` — build the release `.tar.gz` from CI
  artifacts and write the matching `.sha256` file.

## Layout

```text
xtask/
  README.md
  src/
    main.rs                  # CLI shape and dispatch only
    commands/
      mod.rs
      dev.rs                 # development orchestration
      e2e.rs                 # e2e stress runner (prebuild + artifact archive)
      idle.rs                # idle CPU/RSS sampler
      macos.rs               # macOS build/sign/run tasks
      release.rs             # release command dispatch
      release/
        check_tool_updates.rs
        package_tarball.rs
```

Shared helpers (process running, fs utilities) come from the external
`xtask-kit` crate, not a local `support/` module.

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
