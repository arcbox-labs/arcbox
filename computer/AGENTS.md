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
  swallowing), `locks` (weak-map per-`(machine, sandbox)` operation
  locks), `host` (the `SandboxHost` seam + Arc blanket impl). Later cuts
  add the resume and port-exposure protocols per the charter.
