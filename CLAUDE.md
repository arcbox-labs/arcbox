# Repository Guidelines for Coding Agents

## Project Overview

ArcBox is a high-performance container and virtual machine runtime in Rust, targeting macOS (primary) and Linux. The goal is to surpass OrbStack on every metric.

## Performance Targets

| Metric | Target | OrbStack |
|--------|--------|----------|
| Cold boot | <1.5s | ~2s |
| Warm boot | <500ms | <1s |
| Idle memory | <150MB | ~200MB |
| Idle CPU | <0.05% | <0.1% |
| File I/O (vs native) | >90% | 75-95% |
| Network throughput | >50 Gbps | ~45 Gbps |

## Platform Priority

1. **P0**: macOS Apple Silicon
2. **P1**: macOS Intel
3. **P2**: Linux x86_64/ARM64

## Project Structure

- `common/` — shared error types
- `hypervisor/` — Virtualization.framework bindings, cross-platform hypervisor traits, VMM, VirtIO devices
- `services/` — filesystem (VirtioFS), networking (NAT/DHCP/DNS), container state, OCI image/runtime
- `comm/` — protobuf definitions, gRPC services, vsock/unix transport
- `app/` — core orchestration, API server, Docker Engine API compat, CLI, facade crate
- `pro/` — enhanced filesystem, advanced networking, snapshots, performance monitoring (BSL-1.1)
- `guest/` — in-VM agent (cross-compiled for Linux)
- `tests/` — e2e tests and test resources

## Code Standards

- Run `cargo clippy` and `cargo fmt` before committing. All code must pass both with zero warnings.
- All comments in English
- `unsafe` blocks require `// SAFETY:` comments
- Use `thiserror` for crate-specific errors, `anyhow` in CLI/API layers
- Hot paths: prefer lock-free / `RwLock` over `Arc<Mutex<T>>`, use `#[repr(C, align(64))]` to avoid false sharing
- Performance-critical paths (VirtioFS, network stack, VirtIO devices) are all custom-built, not vendored
- Prefer refactoring over layered, patchy fixes. Code changes must be coherent, not duct-taped on.
- No hacky workarounds. If a workaround is truly unavoidable, pause and get user approval first.
- When the right choice is obvious, make the decision — don't ask unnecessary questions. But when a plan or request is blocked or infeasible, surface the blocker with enough context for the user to decide the path forward.
- If a request appears to conflict with these guidelines, double-check intent with the user before proceeding.
- When project conventions or processes change, this file (`CLAUDE.md`/`AGENTS.md`) must be updated promptly. All changes to this file require human approval.

## Testing

- Tests are expected for code changes. Only test meaningful logic (branching, transformations, error handling). Don't test code that can only break if the language, runtime, or a dependency breaks.

## Change Discipline

- Commit messages: `type(scope): summary` (e.g. `fix(net): correct checksum on fragmented packets`). Do not add Co-Authored-By lines.
- Keep each commit atomic — compilable, runnable. Target ~200 lines changed (excluding generated files); hard limit 400. Don't make commits too small either — group related changes into one coherent commit unless that's all there is.
- Commit along the way. Do not batch all changes into a single commit at the end.
- Use `cargo add` / `cargo remove` for dependency changes, not manual Cargo.toml edits.

## Licensing

- Core + Guest crates: MIT OR Apache-2.0
- `pro/` crates: BSL-1.1 (converts to MIT after 4 years)

## macOS Development

- Virtualization.framework requires entitlement signing: `codesign --entitlements tests/resources/entitlements.plist --force -s - <binary>`
- Without signing, you get "Virtualization not available" errors
- Requires Xcode Command Line Tools
- Some tasks require a running daemon. Start it in a background terminal: `arcbox daemon -f`

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
