# rpc/ — Protocol & Transport Agent Guidance

Basics live in the crate READMEs — don't duplicate them:
- Message layout & the additive-only / `buf breaking` / handshake policy:
  `rpc/arcbox-protocol/README.md`.
- Transport usage, `VsockStream`/`VsockShutdown` and the port-1024 note:
  `rpc/arcbox-transport/README.md`. The CID (host=2, guest=3+) table is in the
  `src/vsock/mod.rs` module docs; the `CID_HOST = 2` constant is
  `src/vsock/addr.rs`, and `AGENT_PORT = 1024` is
  `common/arcbox-constants/src/ports.rs`.
- gRPC service/client exports: `rpc/arcbox-grpc/README.md`.
- Backend-specific transport selection (`is_blocking()`): `app/AGENTS.md`.

This file is only the non-obvious operational knowledge.

## Three surfaces in one directory (read this first)

- **Daemon control plane = Connect** (`arcbox-connect` + `connectrpc`),
  served over the Unix socket. Every daemon service — Machine, Kubernetes,
  Migration, System, Stats, Icon, the four sandbox services, plus Macos on
  macOS — registers on `arcbox_api::connect::router`, and
  `app/arcbox-daemon/src/control_plane.rs` serves that router directly
  through hyper's protocol-detecting builder (HTTP/1.1 **and** HTTP/2). WHY:
  one set of handlers answers Connect (HTTP POST, JSON or binary), gRPC, and
  gRPC-Web, so a caller with no proto toolchain can `curl --unix-socket` the
  API while native clients keep gRPC. tonic is no longer in the serving
  path; `arcbox-grpc`'s generated tonic **clients** are deliberately kept
  and used by e2e and the daemon's own tests as the standing proof that the
  gRPC format still answers at the same endpoint. (The CLI has none: `abctl`
  speaks Connect only, and `tonic` is absent from its dependency tree.)
  - `connectrpc` is bound to `buffa::Message` and has no prost interop, so
    every served proto package is generated **twice**: buffa types for the
    public boundary, prost types for the internal and vsock payloads. Both
    encode standard protobuf bytes, so the two are wire-identical and the
    guest agent stays on prost. `app/arcbox-api/src/connect/bridge.rs` is
    the crossing — a decode of the bytes already in hand, never a conversion
    table.
  - Reflection is served by `connectrpc-reflection` from the whole daemon's
    descriptor set. It answers `501` over HTTP/1.1 Connect because
    `ServerReflectionInfo` is bidi-streaming and Connect carries bidi only
    over HTTP/2 — that is the RPC's shape, not a wiring bug.
- **Host↔guest agent channel is NOT gRPC.** `service AgentService`
  (`arcbox-protocol/proto/agent.proto`) is schema-only and **never served** —
  `AgentServiceClient/Server` are re-exported (`arcbox-grpc/src/lib.rs`) with
  zero consumers. The real channel is a custom length-prefixed frame keyed by
  `arcbox_constants::wire::MessageType`, dispatched in
  `guest/arcbox-agent/src/rpc.rs` and driven by `AgentClient`
  (`app/arcbox-core/src/agent_client.rs`). Editing the tonic `AgentService`
  does nothing at runtime.
- The `arcbox-protocol/src/lib.rs` top-of-file doc says "ttrpc" — **stale**.
  There is no ttrpc dependency; trust this file over that comment.

## Invariants (each with a one-clause why)

- **Generated prost code is committed** (`arcbox-protocol/src/generated/*.rs`)
  and rustfmt'd by `build.rs` (writes into `src/`, not `OUT_DIR`) — a `.proto`
  edit without a rebuild+commit ships a stale/unformatted file that fails
  `cargo fmt --check` only in CI.
- **Generated types carry NO serde impls — persisted/user-facing JSON must
  come from hand-written DTOs, never from codegen shapes.** WHY: it keeps the
  message-layer codec swappable without silently rewriting on-disk or
  scripted formats (`buf breaking` checks protobuf wire only and would never
  catch such a rewrite). The one existing DTO is the `virtio-debug.json`
  mirror (`tests/e2e/src/virtio_debug.rs`, shape pinned by test); `abctl
  --json` output is likewise hand-mapped (`serde_json::json!` payloads in
  `app/arcbox-cli/src/commands/`). Do not reintroduce blanket
  `type_attribute` serde derives in `arcbox-protocol/build.rs`.
- **`protocol_version` (enforced) ≠ `version` (debug-only).**
  `AgentPingResponse.protocol_version` is gated against
  `MIN_AGENT_PROTOCOL_VERSION`; `.version` is informational log text only
  (`agent_client.rs::check_agent_protocol`). Don't conflate them.
- **Bump `AGENT_PROTOCOL_VERSION` only when a change alters the *meaning* of
  existing messages** — purely additive fields don't need a bump; unknown
  `MessageType`s already fail cleanly (`common/arcbox-constants/src/wire.rs`).
- **`MAX_FRAME_SIZE` (16 MiB) must stay identical** in both
  `arcbox-transport/src/vsock/blocking.rs` (HV, no tokio, `poll` deadlines) and
  `.../transport.rs` (async VZ/Linux) — the only thing keeping them equal is a
  comment; diverge and cross-backend frames silently mismatch.
- **`AgentClient::connect()` is a no-op on the blocking path** — the HV
  transport is connected at creation (`from_fd`); only the async path dials.
- **`arcbox-protocol/proto/buf.yaml` exempts ONLY the sandbox surface from
  the CI `buf breaking` gate** — both `arcbox/sandbox/v1` (the package dir)
  and the flat `sandbox.proto` it replaced, since deleting a file is itself a
  break. The sandbox surface is pre-release and being redesigned
  contract-first (CORE-52); every other proto in the dir stays under the
  default `FILE` breaking rules. Remove the exemption when the
  sandbox API ships in a public SDK. The fleet protos'
  `fleet/arcbox-fleet-proto/buf.yaml` is a separate, unrelated gate.
- **Well-known types map to `pbjson-types`, not `prost-types`**
  (`extern_path(".google.protobuf", "::pbjson_types")` in BOTH
  `arcbox-protocol/build.rs` and `arcbox-grpc/build.rs` — keep them in
  lockstep). Historically forced by the blanket serde derives; kept after
  their removal so public field types (`pbjson_types::Timestamp` etc.) stay
  stable for every consumer — reverting to `prost-types` would churn all of
  them for zero benefit.

## Extending checklists (change every path together)

**Add/change a daemon gRPC message or service:**
1. Edit the `.proto`.
2. If it's a *new* `.proto` file, add it to **both** proto arrays:
   `arcbox-protocol/build.rs` (prost, messages) **and**
   `arcbox-grpc/build.rs` (tonic, services). Miss one → missing message types
   or missing service stubs with a confusing compile error.
3. Rebuild (regenerates + rustfmts `src/generated/*.rs`) and commit the result.
4. Add a hand-written re-export in `arcbox-protocol/src/lib.rs` (the flat
   `pub use v1::{...}` block and the per-module `pub mod`) — nothing generates
   or checks these; a new message is invisible downstream until listed.
5. If it's a new gRPC service the daemon must serve, `add_service()` it in
   `app/arcbox-daemon/src/services.rs`.

**Add/change something under `arcbox.sandbox.v1` (the Connect surface):**
1. Edit the `.proto`, then add a *new* file to `arcbox-connect/build.rs` as
   well as the two arrays above — the sandbox package is compiled by three
   build scripts, and connectrpc codegen is the one that emits the service
   traits the daemon implements.
2. Implement the method in `app/arcbox-api/src/connect/` against the
   connectrpc trait, not a tonic one. Cross to the prost twin with
   `bridge::wire_request` / `wire_response`; do not hand-map fields.
3. A new *service* goes on `arcbox_api::connect::router` (or
   `router_with_system`). The daemon serves only that router, so a service
   missing there is a 404 on every format — the
   `migrated_daemon_services_are_registered_on_the_connect_router` test in
   `control_plane.rs` is where that surfaces.
4. Nothing else changes: the guest agent, `AgentClient`, and the vsock frames
   keep using the prost types, and the two encodings are identical bytes.

**Add a host↔guest agent RPC (NOT a tonic method):**
1. Define the proto *message* in `agent.proto`.
2. Add a `MessageType` enum variant **and** its `from_u32` arm in
   `common/arcbox-constants/src/wire.rs` (and a roundtrip test case).
3. Handle it in the guest dispatcher `guest/arcbox-agent/src/rpc.rs`.
4. Add a method on `AgentClient` (`app/arcbox-core/src/agent_client.rs`) that
   prost-encodes and frames the message via `rpc_call`.

**Change the wire contract / add a meaning-bearing field:**
- Bump `AGENT_PROTOCOL_VERSION` (and `MIN_AGENT_PROTOCOL_VERSION` if dropping
  old-agent support) in `wire.rs`.
- The handshake gate (`check_agent_protocol`) is called from **three** sites —
  update/verify all: `app/arcbox-core/src/machine.rs` (ready probe) and both
  boot arms in `app/arcbox-core/src/vm_lifecycle/boot.rs` (blocking HV +
  async VZ/Linux). Miss one and a stale staged agent yields an opaque
  readiness timeout instead of the actionable "staged agent is stale" error
  (the ABX-410 / commit b90d2368 class this was built to prevent).

## Failure signatures (symptom → first commands → likely cause)

- **New agent RPC "does nothing" / method never runs.** `rg -n "add_service"
  app/arcbox-daemon/src/services.rs` (Agent absent) → `rg -n "MessageType::"
  guest/arcbox-agent/src/rpc.rs`. Cause: you implemented the tonic
  `AgentService` instead of adding a `MessageType` + guest dispatcher arm.
- **Old staged agent → opaque readiness timeout, not "stale agent" error.**
  `rg -n "check_agent_protocol" app` — confirm all three call sites present.
  Cause: a handshake gate arm was missed. (Stale-agent selection itself: newest
  mtime across dev tree / musl target / `~/.arcbox/bin` — see `tests/e2e`.)
- **An RPC returns 404 on every format while its neighbours work.**
  `rg -n "add_service" app/arcbox-api/src/connect/mod.rs` — the service was
  never added to `arcbox_api::connect::router`, and the daemon serves only
  that router. The registration test in `control_plane.rs` pins the full
  service list; extend it with the new service.
- **A sandbox field is silently empty on one surface only.** Both codegens
  read the same `.proto`, so this is a stale build, not drift: rebuild
  `arcbox-connect` (its `build.rs` reruns on the proto files) and re-check.
  `bridge` never copies fields, so there is no mapping to have missed.
- **`cargo fmt --check` fails only in CI.** `git status
  rpc/arcbox-protocol/src/generated/` → cause: you edited a `.proto` without
  rebuilding (or rebuilt without rustfmt), shipping stale/unformatted
  generated code.
- **A forensic/`--json` field is missing though the proto has it.** The
  hand-written DTO mirror was not extended with the proto change (e.g. a new
  `VirtioQueueDebug` field never added to `tests/e2e/src/virtio_debug.rs`).
  Codegen no longer feeds these surfaces, so proto edits reach them only by
  hand — update the mirror and its shape-pinning test together.

## Validation ladder (cheapest first)

1. `cargo test -p arcbox-protocol -p arcbox-grpc -p arcbox-transport`
   (frame roundtrip, `MessageType` roundtrip, handshake unit tests).
   For the Connect surface add `-p arcbox-api` (the buffa/prost wire-identity
   test) and `cargo test -p arcbox-daemon control_plane` (one endpoint
   answering Connect, gRPC, and gRPC-Web, plus reflection) — both are
   VM-free.
2. Reproduce the CI proto gate locally (compares PR against its base, not a
   hardcoded master):
   `buf breaking rpc/arcbox-protocol/proto --against '.git#branch=origin/master,subdir=rpc/arcbox-protocol/proto'`.
3. For agent-protocol changes, continue up the HV validation ladder in
   `virt/AGENTS.md` (bare probe → daemon-level → `cargo xtask e2e`); VZ is the
   oracle backend, so HV-only red points at the HV transport/boot arm.
