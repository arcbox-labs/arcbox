# computer/ — Agent-Computer Layer Agent Guidance

Two different things live here, and most rules below bind only one of
them: `arcbox-computer`, the transport-free protocols, and
`arcbox-computer-runtime`, the runtime that actually boots Computers. Read
the Crates section before assuming a rule applies to your crate. The
restructure plan and its locked decisions live in the company repo:
`engineering/arcbox/architecture-charter.md`.

## Layer rules

- **Never import `connectrpc`.** Wire *message* types (`arcbox-connect`)
  are the domain vocabulary and are allowed; the transport (ConnectError,
  RequestContext, routers) belongs to `arcbox-api`, which adapts these
  protocols onto the wire.
- **No `app/` dependency**: the composing runtime reaches this layer
  through the [`SandboxHost`] seam (`src/host.rs`), implemented by
  `arcbox_core::Runtime` (`app/arcbox-core/src/runtime/sandbox_host.rs`).
  Protocol code is generic over the trait — do not add a concrete
  `Runtime` type anywhere here.
- **Platform-neutral**: must compile and pass unit tests on Linux as well
  as macOS. The gate differs per crate: `arcbox-computer` is in the
  `linux-engine` CI job's package list; `arcbox-computer-runtime` is
  deliberately not, because `test-vm-linux` already builds, lints and
  tests it on real KVM — that suite is its Linux gate and its oracle.
- **Mechanically checked**: `cargo xtask check-layers` (the `linux-engine`
  job) fails on a direct edge from `computer/` into `app/`, `arcbox-vmm`,
  `arcbox-hypervisor`, a macOS-only crate or a VMM adapter — the rules
  live in `xtask/src/commands/check_layers/rules.rs`. Two of those edges
  are grandfathered for `arcbox-computer-runtime` (below); an `Exception`
  whose edge disappears **fails** the gate, which is what retires them.
- Errors speak `arcbox_engine::EngineError` **in `arcbox-computer`**;
  predicates like `EngineError::Agent { code }` carry the agent's
  HTTP-style wire codes (404/412 obsolete-ticket, 423 paused, 503 retry)
  — those codes are protocol contract, mirrored guest-side.
  `arcbox-computer-runtime` has its own `VmmError` and does not speak
  `EngineError`; the guest agent converts at its boundary.

## Crates

- `arcbox-computer` — `cleanup` (durable cleanup-ticket protocol: the
  generation fence bump, startup-vs-targeted teardown, obsolete-ticket
  swallowing, and `register_live_sandbox_dns`, the shared
  Create/Restore/Resume DNS discipline), `resume` (transparent-resume
  protocol: 503 retry budget, paused wire code 423, write pre-flight),
  `ports` (exposure protocols and the port value types: guest-DNAT-then-
  host-bind with compensating rollbacks, the generation-fenced list
  snapshot, host-half-first unexpose), `locks` (weak-map per-`(machine,
  sandbox)` operation locks), `host` (the `SandboxHost` seam + Arc
  blanket impl), `capability` (can this host run sandboxes at all).
  Domain errors are modeled, not stringified
  (`ExposePortError::Raced`, `ListExposedPortsError::Unstable`) — the
  arcbox-api adapters map them onto Connect codes.
- `arcbox-computer-runtime` — the runtime that boots Computers: lifecycle,
  exec, files, checkpoints, pause/resume, warm pools, over the
  `arcbox-vm-driver` port. It ran as `virt/arcbox-vm` until
  vm-stack-redesign R3 moved it here; the in-sandbox init is
  `arcbox-vm-agent` and the wire vocabulary `arcbox-vm-proto`, both still
  under `virt/`. Its own README has the crate map.
  - **It names no adapter at all** — the last two edges
    (`arcbox-fc-driver`, `arcbox-tap-net`) died in R3's PR-G5 and their
    `EXCEPTIONS` entries with them, so `cargo xtask check-layers` now
    fails on any adapter edge from here with no escape hatch. What used
    to arrive through those edges arrives from the composition root
    instead: the adapters themselves as a `NodeEnvironment`, and the
    `[firecracker]` keys that configure them as the composer's own
    config type (`arcbox_agent::config::AdapterConfig`), read out of the
    same TOML section this crate's `FirecrackerConfig` reads. Do not
    reintroduce an adapter edge, in any dependency section — a test that
    wants a real adapter belongs to the composer or to the adapter's own
    contract run.
  - **The on-disk vocabulary is frozen.** `sandbox-records/`,
    `sandboxes/`, `state.json`, `sandbox-network-quarantine`,
    `arcbox-pause`, `paused-rootfs.ext4`, `arcbox.warm_key`, the `pool-`
    id prefix, `arcbox-cow-{id}` / `arcbox-snap-{id}`. `RECORD_VERSION`
    is 1 and there is no migration story, so renaming any of them breaks
    upgrade-in-place — the R3 rename deliberately leaves every one of
    them alone.
  - **Transitional naming**: the crate is `arcbox-computer-runtime` but
    its types still read `SandboxManager` / `SandboxSpec` / `VmmError`,
    and its config still calls the section-shaped struct
    `FirecrackerConfig` though what is left in it is the runtime's own —
    a data dir, an isolation spec, pool and CoW policy — the adapter's
    settings having gone to the composer (the TOML key is frozen; the
    type name is not, and follows in that rename).
    `VmmConfig` is already `RuntimeConfig`. The `Computer*` rename is its
    own PR, with `compat.rs` aliases for the guest agent. Not an
    inconsistency to file.

## Reaching the platform without a `#[cfg]`

`capability` is the reference for how this layer asks a platform
question. It composes two halves, neither of which it implements:
`VmBackend::supports_nested_virt` (a property of the backend, defined
with the enum in `arcbox-vmm`) and `arcbox_hypervisor::host_nested_virt`
(the hardware/kernel probe, which carries the *platform's own* reason
string so the caller does not have to write one per target). Both arrive
re-exported from `arcbox-engine`, which is why this crate depends on
neither `arcbox-vmm` nor `arcbox-hypervisor` directly (charter D4).

The rule it embodies: a `#[cfg(target_os)]` in this layer means a
platform difference leaked past its seam. Push the difference down to
where the platform knowledge already lives, and let this layer compose
the answers.
