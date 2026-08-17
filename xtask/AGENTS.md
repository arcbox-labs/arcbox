# xtask — Agent Guidance

xtask is the repository automation hub: new developer workflows (test
runners, samplers, asset staging, release tooling) belong here, not in
ad-hoc shell scripts. Command shape lives in `src/main.rs`; design rules
(when to use `xshell` vs `std::process::Command`, no script-wrapper
facades) live in `README.md` — follow them, don't restate them. Commands
today: `check-layers`, `dev boot-assets`, `e2e`, `idle`, `macos dev`,
`release {check-tool-updates,package-tarball}`. This file focuses on
`e2e` and `idle`, the two the HV fix campaign leans on, and on
`check-layers`, the CI layer-rule gate.

## `xtask e2e` — the SKIP_BUILD / prebuild contract

INVARIANT: a prebuild recipe in `commands/e2e.rs::prebuild` must reproduce
EXACTLY what the target's own build does — same packages AND same profile.
WHY: when a recipe matches, the runner sets `SKIP_BUILD=1`, the test skips
its own `cargo build`, and every repeat trusts whatever binaries already
sit in `target/`. A recipe that builds the wrong packages or wrong profile
makes all N repeats silently run stale/wrong binaries with no error — pure
ghost debugging.

`SKIP_BUILD` is a cross-crate env contract, not an xtask-internal flag.
Every `arcbox-e2e` target gates its build on
`arcbox_e2e::env_flag("SKIP_BUILD")` (`tests/e2e/src/lib.rs`). The runner
only exports it when `prebuild` returned `true`; the `other =>` fallback
prints a notice and omits it, so unknown targets build themselves once.

Current recipe ↔ self-build mapping (keep both columns identical):

| test target      | prebuild recipe (`e2e.rs`)                        | self-build (`tests/e2e`)                     |
|------------------|---------------------------------------------------|----------------------------------------------|
| `boot_assets`    | `cargo build --release -p arcbox-cli -p arcbox-daemon` | `boot_assets.rs::build_release_binaries` (same) |
| `backend_matrix` | same as above                                     | `build_release_binaries` (same)              |
| `hv_vmm`         | `cargo build --release -p arcbox-e2e --bin hv_e2e`| `hv_vmm.rs` (same)                           |
| `stats_watch`    | release daemon + musl `arcbox-agent`              | `stats_watch.rs` (same)                      |
| `sandbox`        | release cli+daemon + musl `arcbox-agent`/`arcbox-vm-agent` bins | `sandbox.rs::build_binaries` (same)   |
| `egress_throughput` | `cargo build --release -p arcbox-daemon`       | `scenario.rs::run_vz_scenario_with_log` (same) |
| `docker_build`   | same as above                                     | `scenario.rs::run_vz_scenario_with_log` (same) |
| `docker_build_external` | same as above                              | `scenario.rs::run_vz_scenario_with_log` (same) |
| `virtio_debug`   | none (self-builds)                                | `cargo build --release -p arcbox-daemon` (RELEASE only) |
| `daemon_failure` | none (self-builds)                                | `cargo build -p arcbox-daemon` (**DEBUG**)   |
| anything else    | none — fallback notice, no `SKIP_BUILD`           | its own build                                |

Note `virtio_debug` and `daemon_failure` deliberately have NO recipe and
their profiles differ (release vs debug daemon). If you ever add a recipe
for either, it must reproduce that exact profile.

## `xtask e2e` — `--backend` cannot move a pinned target

Most e2e targets hardcode `ARCBOX_VM_BACKEND` and stamp that backend into
their metrics, so the runner's `--backend` env has no effect on them. Only a
few (`boot_assets`, `backend_matrix`) actually read it. The runner therefore
**errors** when the requested backend conflicts with a pinned one. WHY: the
alternative is a run archived under the wrong backend's label — the same
ghost-debugging class as a mismatched `SKIP_BUILD` recipe, and it silently
corrupts any HV↔VZ oracle comparison read from the artifacts.

This cuts both ways: `virtio_debug` and `hv_reboot` pin **hv**, so
`--backend vz` on them is exactly as wrong as `--backend hv` on a vz-pinned
target. `--backend both` conflicts with any pin.

Only an **explicit** `--backend` can conflict. The flag carries no clap
default, because a default is indistinguishable from a typed value and would
make `cargo xtask e2e --test virtio_debug` bail on a backend nobody asked
for; unset adopts the target's own pin, and falls back to vz for targets that
pin nothing.

`pinned_backend` (`commands/e2e.rs`) derives this from the sources rather
than from a list, deliberately: the set changes whenever someone adds a
target, and a list goes stale exactly when a new target needs the guard
most. It scans the target's own source for a line carrying both
`ARCBOX_VM_BACKEND` and a `"vz"`/`"hv"` literal, then the `arcbox_e2e`
modules it imports — one level of indirection, which is where
`scenario::run_vz_scenario*` and the `sandbox` harness keep their pin. A
line that merely reads the variable carries no literal and is correctly
ignored. Nothing to keep in lockstep; the unit tests in that file pin the
shapes.

### Extending — adding a new e2e target (lockstep set)
1. The test must gate its build on `arcbox_e2e::env_flag("SKIP_BUILD")`,
   or `xtask e2e` cannot prebuild it and it rebuilds every repeat.
2. Either add a matching arm in `commands/e2e.rs::prebuild` (return `true`)
   or accept the self-build fallback — never a half-match.
3. If you add a recipe, verify the packages AND profile match the test's
   own `cargo build` line character-for-character.
4. Nothing to do for the backend pin — `pinned_backend` reads it off the
   sources, so a new target gets the `--backend` guard for free as long as
   it pins the way every existing one does (an `ARCBOX_VM_BACKEND` line with
   a `"vz"`/`"hv"` literal, in the target or in an `arcbox_e2e` module it
   imports).

## `xtask e2e` — forensics linkage (fragile string/env coupling)

The per-failure `preserved=` column is produced by string-matching the
harness log line containing `preserving test directory` and splitting out
the `path=` token (`e2e.rs::preserved_dir_from_log` ↔
`tests/e2e/src/boot_assets.rs:172`, `warn!(path=…, "preserving test
directory")`). The runner also wires `ARCBOX_E2E_METRICS_DIR` +
`ARCBOX_E2E_RUN_LABEL` so the harness drops `<label>.metrics.json` next to
the logs (`tests/e2e/src/metrics.rs`). If someone rewords that log line or
renames the metrics file, xtask loses forensics silently — empty
`preserved=` column, missing metrics, exactly the data a race-class
failure needs. Change the harness wording and the xtask matcher together.

## `xtask e2e` — place in the HV validation ladder

`cargo xtask e2e --repeat N` is the TOP (most expensive) rung, reserved for
race-class HV fixes. Exhaust the cheaper rungs first (see `virt/AGENTS.md`):
crate unit tests → bare probe (`cargo test -p arcbox-e2e --test hv_vmm`) →
daemon level (`--test virtio_debug`, `--test boot_assets` with
`ARCBOX_VM_BACKEND=hv`). The e2e targets are `#[ignore]`; the runner passes
`-- --ignored --nocapture`, so running them by hand WITHOUT `--ignored`
reports "0 tests run". `--backend both` runs vz THEN hv within each
iteration — VZ is the oracle: HV-only red points at the HV impl, double red
points above the hypervisor. Defaults: `--test boot_assets --backend vz
--repeat 1`.

### Debugging: repeats behave inconsistently or run stale code
1. Confirm the prebuild recipe matches the target's self-build — compare
   the `prebuild` arm against the test's `cargo build` line (packages AND
   profile). A mismatch is the prime suspect; `SKIP_BUILD=1` then runs old
   binaries.
2. Read the preserved dir the runner prints (`test dir preserved: …`):
   daemon log, guest logs, `virtio-debug.json` (captured while the VM is
   alive), and `<label>.metrics.json` for phase timings. Never log-grep or
   sleep for readiness — that is `WatchSetupStatus`'s job in the harness.
3. Empty `preserved=` on a real failure means the log-string/env contract
   above broke, not that forensics are absent — check the harness wording.
4. For config-dependent HV failures, bisect with the `hv_e2e` probe knobs
   (`ARCBOX_HV_E2E_VCPUS/MEMORY_MB/BALLOON/BOOT_ONLY=1`) one dimension
   at a time (this is how ABX-386's "vCPU count, threshold exactly 8" was
   localized). See `virt/AGENTS.md`.

## `xtask check-layers` — the layer rules live in code

`cargo xtask check-layers` reads `cargo metadata --no-deps`, builds the
graph of **direct** edges between workspace members, and fails on any
edge a layer rule forbids; CI runs it in the `linux-engine` job. The
rules and the grandfathered edges are data in
`src/commands/check_layers/rules.rs` (`RULES`, `EXCEPTIONS`); the
evaluator (`evaluate.rs`) is a pure function over a small typed graph and
is unit-tested on synthetic graphs, so a rule change comes with a test
there, not with a manifest edit. `--verbose` prints every member edge and
every grandfathered edge. Rules cover engine/computer (no `app/`, no
macOS-only crate, no `arcbox-vmm` / `arcbox-hypervisor` / VMM adapter —
engine's two edges are grandfathered until vm-stack-redesign R4), common
(no virt/engine/computer/app/guest),
`arcbox-vm-proto` and `arcbox-vm-driver` (leaf crates) and
`arcbox-vm-agent` (no `arcbox-vm`/`arcbox-snapshot`/`tokio`/`aya`/`fc-sdk`).

- **Adding a rule**: append a `Rule` whose `reason` names the document
  that owns it (charter decision, design doc, AGENTS.md section) — the
  reason is what a violation prints. A rule may name a crate that does not
  exist yet (`arcbox-fc-driver`, `arcbox-vm-driver`); it is a no-op until
  the crate lands. Every dependency kind counts (normal, dev, build), only
  workspace members are walked, and an external crate is checked only
  where a rule names it (`Forbidden::Crates`).
- **Adding an exception**: append an `Exception` with the `reason` the
  edge exists and the phase (`until`) that removes it. Exceptions are
  checked before the rules, so they hold as rules tighten; an exception
  whose edge no longer exists **fails the gate** — remove it with the
  edge. Today's two: `arcbox-engine -> arcbox-vmm` and
  `arcbox-engine -> arcbox-hypervisor`, until vm-stack-redesign R4.
- **A new top-level directory** fails the gate until it is added to
  `Layer` (`graph.rs`) — the rules must know every layer.

## `xtask idle`

Computes CPU% from `ps` cputime deltas over the window, NOT `%cpu` (a
decaying average that lies on short windows) — keep it that way. It does
NOT launch anything: it requires an already-running `--pid` (e.g. a live
`arcbox-daemon`) and samples cputime/RSS over `--seconds` (default 30). The
verdict thresholds (`cpu <0.05%`, `rss <150MB`) are hardcoded in
`commands/idle.rs` and must track the root CLAUDE.md performance table;
change them together.

MISS is EXPECTED today, not a regression. HV baselines from the 2026-07 HV
fix campaign sit far from target (idle CPU ~3.87%, RSS ~1.04GB vs
0.05%/150MB). The sampler exists to measure R3 (tickless WFI /
event-driven workers) progress toward those numbers; read MISS as
"distance to go", not "you broke it".

## Counters honesty (campaign metrics)

R2/R3 acceptance in Linear is measured from the HV broadcast counters
(per-boot ~2301 unpark-broadcasts / ~71 kick-broadcasts) surfaced through
the debug snapshot, not from anything xtask computes. A refactor that
bypasses those counter sites falsifies the metrics — see
`virt/arcbox-vmm/AGENTS.md`.
