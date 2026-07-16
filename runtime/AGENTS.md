# runtime/ — Container & OCI Model Agent Guidance

Two host-side, `std`-only model crates. No hypervisor, no guest memory, no
virtqueue surface — none of the `virt/AGENTS.md` HV/e2e invariants apply here.

- `arcbox-container` — domain types (`Container`, `ContainerId`,
  `ContainerState`) + exec orchestration primitives (`ExecManager`,
  `ExecAgentConnection`).
- `arcbox-oci` — OCI **runtime-spec** v1.2.0 modeling: `config.json`
  (`config/`), bundle dir (`bundle.rs`), OCI state (`state.rs`), hooks
  (`hooks.rs`). This is NOT image/pull/layer code — there is no manifest,
  digest, layer, or tar-unpack anywhere in `runtime/`. Look for image bugs
  in the pull path elsewhere, not here.

## Load-bearing wiring reality (read before "fixing container lifecycle")

- **Neither crate is on the live container/exec path.** `arcbox-oci` has
  **zero** workspace consumers (`rg arcbox_oci` outside its own crate returns
  nothing). `arcbox-container`'s only app reference is a **commented-out**
  re-export: `// pub use arcbox_container as container;`
  (`app/arcbox/src/lib.rs:29`). The running daemon's container + exec flow
  lives in `app/` (Docker Engine API compat) and the guest agent. Editing
  these crates changes **no** daemon behavior until you also wire them in.
  WHY: prevents hours of "my change did nothing" debugging. Confirm with
  `rg arcbox_oci` / `rg arcbox_container` before assuming impact.
- `ExecManager` with **no** agent returns a fake `exit_code: Some(0)`
  (`arcbox-container/src/exec.rs:294-302`) — a test stub, not real exec.
  Real exec requires an `ExecAgentConnection` impl (`exec.rs:157`).

## Two same-named `ContainerState` — do not conflate

| Type | Semantics | Transitions |
|------|-----------|-------------|
| `arcbox-container::ContainerState` (`state.rs:47`) | Docker-facing enum, 8 variants (Created/Starting/Running/Paused/Restarting/Exited/Removing/Dead) | **NONE** — no guard, any assignment allowed |
| `arcbox-oci::ContainerState` (`state.rs:213`) — metadata **struct**, not an enum: `#[serde(flatten)]`s a `State` (`state.rs:21`) + timestamps/exit_code/name. The 4-variant status **enum** is `Status` (`state.rs:118`: Creating/Created/Running/Stopped) | OCI runtime-spec state carrier; no variants of its own | **Validated** on the embedded `State` via `State::transition_to` (`state.rs:94`) → `Status::can_transition_to` (`state.rs:143`); `Stopped` terminal; non-terminal `-> Stopped` on error |

The two enums do not map 1:1 (OCI has no Paused/Restarting/Dead). When wiring
one to the other, state explicitly which side owns which surface; never
silently unify them. WHY: wrong import / lost state distinctions.

## Advertised-but-inert features (do not trust as working boundaries)

- **OCI hooks are parsed and validated but NEVER executed.** `hooks.rs` has
  no `Command`/spawn; `HookContext` (`hooks.rs:176`) and `HookResult`
  (`hooks.rs:198`) are inert data with no non-test consumer. `Hooks::validate`
  only checks path-absolute + timeout>0. Adding real hooks means: add the
  spawn/executor path, feed `HookContext::state_json()` on stdin, AND add
  tests that assert a process actually ran — don't assume the types fire.
- **`Spec::validate` is shallow** (`config/spec.rs:89`): checks only
  `ociVersion` non-empty + `>=2` dotted segments, `root.path` non-empty,
  `process.cwd` non-empty & absolute, and each `mounts[].destination`
  non-empty & absolute. It does NOT validate namespaces, resources, seccomp,
  capabilities, or hook paths. Document what you rely on before treating it
  as a security boundary.

## Conventions & pitfalls

- **ID schemes differ — not interchangeable.** `ContainerId::new` strips
  dashes and TRUNCATES to 12 chars (`container/src/state.rs:16`);
  `ExecId::new` strips dashes, keeps full 32 (`exec.rs:18`);
  `State::with_generated_id` keeps the full dashed 36-char UUID
  (`oci/src/state.rs:59`).
- `config.rs` was split into `config/` (mod + one file per unit, commit
  `03e81c0d`). Per the root CLAUDE.md section-divider rule, keep new spec
  types one-per-file — do not re-monolithize.
- Guest-controlled numeric fields (limits, sizes from an untrusted spec)
  must use checked arithmetic and cover near-`u64::MAX` in tests — debug
  panics on overflow, release wraps past bounds checks.

## Validation

Pure host-side unit tests, cheapest first:

```
cargo test -p arcbox-oci -p arcbox-container
cargo clippy -p arcbox-oci -p arcbox-container
cargo fmt -p arcbox-oci -p arcbox-container
```

The HV/e2e ladders (`hv_vmm`, `virtio_debug`, `ARCBOX_VM_BACKEND`,
`cargo xtask e2e`) do NOT apply to changes scoped to `runtime/` — running
them here is wasted effort. Integration tests live in
`arcbox-oci/tests/integration.rs` plus in-module `#[cfg(test)]` blocks.
