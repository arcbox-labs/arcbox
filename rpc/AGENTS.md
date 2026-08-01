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

- **Daemon control plane = gRPC/tonic** (`arcbox-grpc`), served over the Unix
  socket. The daemon `add_service()`s exactly: Machine, Kubernetes, Migration,
  System, Stats, Icon, plus Macos on macOS
  (`app/arcbox-daemon/src/services.rs`).
- **The sandbox API = Connect** (`arcbox-connect`), served on the **same**
  socket. `connectrpc` is bound to `buffa::Message` and has no prost interop,
  so the four `arcbox.sandbox.v1` protos are generated **twice**: buffa types
  for the public boundary, prost types for the vsock payloads. Both encode
  standard protobuf bytes, so the two are wire-identical and the guest agent
  stays on prost. `app/arcbox-api/src/connect/bridge.rs` is the crossing — a
  decode of the bytes already in hand, never a conversion table. WHY: one set
  of handlers answers Connect (HTTP POST, JSON or binary), gRPC, and
  gRPC-Web, so a caller with no proto toolchain can `curl --unix-socket` the
  API while native clients keep gRPC.
  - Composition lives in `app/arcbox-daemon/src/control_plane.rs`: tonic
    claims a route per registered service, the Connect router is the
    fallback, and connections are served by hyper's protocol-detecting
    builder (HTTP/1.1 **and** HTTP/2) rather than tonic's HTTP/2-only server.
    Registering a sandbox service on tonic would shadow its Connect handler —
    add it to `arcbox_api::connect::router` instead.
  - Reflection is served by `connectrpc-reflection` from the whole daemon's
    descriptor set, so it covers every service on both stacks. It answers
    `501` over HTTP/1.1 Connect because `ServerReflectionInfo` is
    bidi-streaming and Connect carries bidi only over HTTP/2 — that is the
    RPC's shape, not a wiring bug.
  - The generated tonic sandbox **clients** are deliberately kept and used by
    the CLI and e2e: unchanged, they are the standing proof that the gRPC
    format still answers at the same endpoint.
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
- **Every message derives serde `Serialize/Deserialize` in `camelCase`**
  (`arcbox-protocol/build.rs`: `type_attribute(".", ...)`) — proto types double
  as JSON DTOs (debug snapshots, config), so a proto field rename also breaks
  JSON consumers, which `buf breaking` (protobuf-wire only) will NOT catch.
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
  lockstep). WHY: every message derives serde (see above) and
  `prost_types::Timestamp` has no serde impls; `pbjson_types` serializes
  WKTs per the canonical protobuf JSON mapping (Timestamp → RFC3339).

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
3. A new *service* goes on `arcbox_api::connect::router`, never on the tonic
   `Routes` — the Connect router is the fallback, so a tonic registration
   would shadow it.
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
- **A sandbox RPC returns `unimplemented` or 404 while its neighbours work.**
  `rg -n "add_service" app/arcbox-daemon/src/services.rs` — if the method's
  service is registered on the tonic `Routes`, it shadows the Connect handler
  (tonic matches the path first; the Connect router only sees what tonic
  declines). Move it to `arcbox_api::connect::router`.
- **A sandbox field is silently empty on one surface only.** Both codegens
  read the same `.proto`, so this is a stale build, not drift: rebuild
  `arcbox-connect` (its `build.rs` reruns on the proto files) and re-check.
  `bridge` never copies fields, so there is no mapping to have missed.
- **`cargo fmt --check` fails only in CI.** `git status
  rpc/arcbox-protocol/src/generated/` → cause: you edited a `.proto` without
  rebuilding (or rebuilt without rustfmt), shipping stale/unformatted
  generated code.
- **JSON consumer breaks though `buf breaking` passed.** You renamed a proto
  field; the serde/`camelCase` view changed and buf only checks protobuf wire
  compat.

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
