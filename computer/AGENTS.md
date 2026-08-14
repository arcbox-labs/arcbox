# computer/ — Agent-Computer Domain Layer Agent Guidance

The transport-free sandbox/agent-computer protocols. The restructure plan
and its locked decisions live in the company repo:
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
  as macOS (the `linux-engine` CI job gates it).
- Errors speak `arcbox_engine::EngineError`; predicates like
  `EngineError::Agent { code }` carry the agent's HTTP-style wire codes
  (404/412 obsolete-ticket, 423 paused, 503 retry) — those codes are
  protocol contract, mirrored guest-side.

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
