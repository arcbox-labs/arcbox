# Repository Guidelines for Coding Agents

## Project Overview

ArcBox is a high-performance container and virtual machine runtime in Rust, targeting macOS (primary) and Linux. The goal is to surpass OrbStack on every metric.

The project is in **alpha**. Breaking changes (internal or user-facing) are acceptable — always prioritize consistency, coherence, and long-term maintainability, even if that means large-scale rewrites.

## Performance Targets

| Metric | Target | OrbStack |
|--------|--------|----------|
| Cold boot | <1.5s | ~2s |
| Warm boot | <500ms | <1s |
| Idle memory | <150MB¹ | ~200MB |
| Idle CPU | <0.05% | <0.1% |
| File I/O | ≥100% of the best competitor guest² | 75-95% (vs native, their claim) |
| Network throughput | >50 Gbps | ~45 Gbps |

¹ Host cost is the high-water mark of guest-*touched* pages, not the
  configured `memory_mb`: a fresh idle 16 GB VZ VM measured ~718MB of
  host `phys_footprint` (2026-08-01). But no macOS backend reclaims, so
  that mark is a one-way ratchet — the guest freeing 3GB leaves the host
  paying for it forever. Only HV can ever release it (VZ guest RAM lives
  in Apple's XPC process, unreachable by `madvise`). Evidence in
  `engine/arcbox-engine/src/vm_lifecycle/balloon/mod.rs`.
² Same-context comparison (container vs container, same-day pairing).
  Cache-hot native is not a valid denominator for FUSE metadata —
  methodology and current numbers in `docs/fs-perf-limits.md`.

## Platform Priority

1. **P0**: macOS Apple Silicon
2. **P1**: macOS Intel
3. **P2**: Linux x86_64/ARM64

## Project Structure

- `common/` — shared error types, constants, asset utilities
- `virt/` — Virtualization.framework bindings, cross-platform hypervisor traits, VMM, VirtIO devices, VirtioFS, networking (NAT/DHCP/DNS)
- `rpc/` — protobuf definitions, gRPC services, vsock/unix transport
- `runtime/` — container state, OCI image/runtime
- `engine/` — embeddable, daemon-free engine library (boot assets, machine images, VM/machine lifecycle, agent client; growing per the architecture charter in the company repo)
- `computer/` — agent-computer domain layer: transport-free sandbox protocols behind the `SandboxHost` seam
- `app/` — core orchestration, API server, Docker Engine API compat, thin CLI (`abctl`, not `arcbox`), daemon binary (`arcbox-daemon`), facade crate
- `guest/` — in-VM agent (cross-compiled for Linux)
- `tests/` — test resources and fixture build scripts
- `.agents/skills/` — shared Claude Code skills (symlinked from `.claude/skills/`)
- `docs/` — supplementary documentation (boot assets, daemon lifecycle)

## Component Rules

Per-directory agent rules live in `AGENTS.md` files next to the code they
govern, and are imported here:

@virt/AGENTS.md
@virt/arcbox-vmm/AGENTS.md
@virt/arcbox-vz/AGENTS.md
@virt/arcbox-virtio-blk/AGENTS.md
@engine/AGENTS.md
@computer/AGENTS.md
@app/AGENTS.md
@guest/AGENTS.md
@rpc/AGENTS.md
@common/AGENTS.md
@runtime/AGENTS.md
@tests/e2e/AGENTS.md
@xtask/AGENTS.md

(`common/arcbox-route/AGENTS.md` is crate-local reference material and is
loaded on demand rather than imported.)

When a change touches files under a directory that has an `AGENTS.md`,
read that file before editing — imported or not. The set above is the
complete list; if you add a new `AGENTS.md`, add it here too.

## Planning

When asked to plan, the plan must be fully resolved before implementation begins. Every decision must be locked — no "TBD", no "option A or B", no open questions. The plan should have exactly one possible outcome. If anything is unclear or uncertain, ask the user before finalizing.

## Code Standards

- Run `cargo clippy` and `cargo fmt` before committing. All code must pass both with zero warnings.
- All comments in English
- When behavior or public API changes, update related comments and documentation in the same change.
- `unsafe` blocks require `// SAFETY:` comments
- Use `thiserror` for crate-specific errors, `anyhow` in CLI/API layers
- Hot paths: prefer lock-free / `RwLock` over `Arc<Mutex<T>>`, use `#[repr(C, align(64))]` to avoid false sharing
- Performance-critical paths (VirtioFS, network stack, VirtIO devices) are all custom-built, not vendored
- Prefer extension traits over free helper functions when the operation is specific to a type (e.g. `request.machine_id()?` not `extract_machine_id(&request)?`; `self.runtime.ready()?` not `get_runtime(&self.runtime)?`).
- Prefer `From`/`Into` trait chains for error conversion. Don't write manual mapping helpers like `core_to_status()` — instead, implement `From<LocalError> for ForeignType` (using a crate-local error type to satisfy the orphan rule) and let `.map_err(LocalError::from)?` drive the conversion.
- **Section dividers (`// ===...`) mean the file should be split.** If you find or are about to add a `// ====` section divider, that is the signal that the file contains multiple distinct implementations and must be refactored into a module directory (`foo/mod.rs` + one file per logical unit). Do not add new section dividers to keep a monolithic file — split immediately. Shared types and trait extensions go in `mod.rs`.
- Prefer refactoring over layered, patchy fixes. Code changes must be coherent, not duct-taped on.
- No hacky workarounds. If a workaround is truly unavoidable, pause and get user approval first.
- When the right choice is obvious, make the decision — don't ask unnecessary questions. But when a plan or request is blocked or infeasible, surface the blocker with enough context for the user to decide the path forward.
- If a request appears to conflict with these guidelines, double-check intent with the user before proceeding.
- When project conventions or processes change, this file (`CLAUDE.md`/`AGENTS.md`) must be updated promptly. All changes to this file require human approval.

## Architecture Principles

- **Resource ownership**: each component manages its own resources. Servers own their sockets (remove-before-bind), the daemon owns its lock file. Never centralize cleanup of resources owned by other components — it creates ordering dependencies and race conditions.
- **Daemon ↔ CLI contract**: `arcbox-daemon` and `arcbox-cli` share a contract via `daemon.lock` (flock-based liveness) and socket paths. When changing daemon internals (lock mechanism, socket paths, startup protocol), always check and update the CLI's matching logic.
- **Daemon startup order is load-bearing**: the 5-phase sequence (`init_early` → `acquire_lock` → `start_grpc` → `wait_for_resources` → `init_runtime`) has specific ordering constraints. gRPC must start before slow phases so desktop clients can connect. The lock must be acquired before gRPC so the old daemon's sockets are freed. Changes to startup ordering require careful analysis of these dependencies. See `docs/daemon-lifecycle.md`.

## Testing

- Tests are expected for code changes. Only test meaningful logic (branching, transformations, error handling). Don't test code that can only break if the language, runtime, or a dependency breaks.

## Change Discipline

- For coherent change sets, create a new branch before starting work. Use `type/short-description` naming (e.g. `feat/virtio-console`, `fix/dhcp-lease-expiry`).
- Commit messages: `type(scope): summary` (e.g. `fix(net): correct checksum on fragmented packets`). Do not add Co-Authored-By or "Generated by" lines — the master branch ruleset rejects commits whose messages match AI-attribution patterns.
- Merging a PR into `master`: the ruleset requires every review thread to be **resolved** (0 approvals required; squash or rebase only). Address or answer each bot/reviewer thread, resolve it (GraphQL `resolveReviewThread` if working from the CLI), then merge normally — do not reach for `--admin`.
- Keep each commit atomic — compilable, runnable. Target ~200 lines changed (excluding generated files); hard limit 400. Don't make commits too small either — group related changes into one coherent commit unless that's all there is.
- Commit along the way. Do not batch all changes into a single commit at the end.
- Use `cargo add` / `cargo remove` for dependency changes, not manual Cargo.toml edits.
- PR merges are squash-only (merge commits are disabled on the repo). For stacked PRs, merge the base PR first — and expect GitHub to close the stacked PR when the base branch is deleted; recovery is: re-push the old base ref, reopen the PR, retarget it to master, delete the ref again, then close/reopen once more to trigger CI (pushes made while a PR is closed fire no events).
- Review-bot findings (pullfrog/Codex/Greptile) get verified against the code first, then either fixed with a reply + thread resolution, or refuted with evidence in the reply. Never resolve a thread silently.

## Licensing

- All crates: MIT OR Apache-2.0

## macOS Development

- Virtualization.framework requires Developer ID signing after every build (ad-hoc `-s -` will NOT work — restricted entitlements cause the binary to be killed on launch):
  ```bash
  codesign --force --options runtime \
      --entitlements bundle/arcbox.entitlements \
      -s "Developer ID Application: ArcBox, Inc. (422ACSY6Y5)" \
      target/debug/arcbox-daemon
  ```
- Requires Developer ID certificate (`.p12`) + provisioning profile (`.provisionprofile`). See `CONTRIBUTING.md` "Code Signing" section for setup.
- Requires Xcode Command Line Tools
- Some tasks require a running daemon. Start it in a background terminal: `abctl daemon start`

## Guest Agent Cross-Compilation

The `arcbox-agent` crate runs inside Linux guest VMs and must be cross-compiled:

```bash
brew install FiloSottile/musl-cross/musl-cross
rustup target add aarch64-unknown-linux-musl
cargo build -p arcbox-agent --target aarch64-unknown-linux-musl --release
```

## Platform-Specific Pitfalls

- **libc `mode_t`**: `u16` on macOS, `u32` on Linux. Always use `u32::from(libc::S_IFMT)` for cross-platform code.
- **xattr API**: Parameter order differs between macOS and Linux. Implement separately with `#[cfg(target_os)]`.
- **`fallocate`**: Not available on macOS. Use `ftruncate` as fallback.
- **VirtIO batching**: Not batching virtqueue pop/push causes excessive VM exits.
