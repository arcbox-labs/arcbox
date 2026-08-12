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
  Migration, System, Stats, Icon, the five sandbox services (Sandbox,
  Template, Process, Filesystem, Snapshot), plus Macos on
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
  - `connectrpc` is bound to `buffa::Message`, and since CORE-73 the buffa
    types in `arcbox-connect` are the ONE runtime representation: daemon
    handlers, `abctl`, the fleet agent's daemon client, reflection's
    descriptor set, and both ends of the vsock wire. The prost twins in
    `arcbox-protocol` are still generated, but ONLY test support consumes
    them: the tonic test clients (daemon/e2e wire-format proofs) and the
    fleet agent's tonic mock daemon. The two codegens emit identical
    bytes, which is what lets a prost test peer prove the buffa server's
    wire format.
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
- **Every proto in the dir is additive-only under the CI `buf breaking`
  gate — there are NO exemptions.** The historical sandbox carve-out
  (pre-release CORE-52 redesign) was removed when the template catalog,
  the surface's last piece, shipped in the public SDKs (CORE-107):
  `arcbox.sandbox.v1` now breaks the gate like everything else. The fleet
  protos' `fleet/arcbox-fleet-proto/buf.yaml` is a separate, unrelated
  gate.
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
2. If it's a *new* `.proto` file, add it to all **three** proto lists:
   `arcbox-protocol/build.rs` (prost, messages), `arcbox-grpc/build.rs`
   (tonic, services), **and** `arcbox-connect/descriptor/protos.txt` (buffa
   messages plus the Connect service traits the daemon actually implements —
   a plain list, read by both that crate's build script and its refresh
   script, so there is only ever one of it). Miss one → missing message types
   or service stubs with a confusing compile error; miss the last and step 6
   has no trait to register.
3. For any edit under `arcbox-protocol/proto/` that arcbox-connect compiles,
   run `make refresh-connect-descriptor`. That crate generates from a
   committed descriptor set, because its sources live in another package and
   cargo cannot package another package's directory; its build script hashes
   the sources and fails until the descriptor matches. protoc is needed for
   this step and no other.
4. Rebuild (regenerates + rustfmts `src/generated/*.rs`) and commit the result.
5. Add a hand-written re-export in `arcbox-protocol/src/lib.rs` (the flat
   `pub use v1::{...}` block and the per-module `pub mod`) — nothing generates
   or checks these; a new message is invisible downstream until listed.
6. If it's a new service the daemon must serve, register it on
   `arcbox_api::connect::router` with `.add_service(...)` — the daemon
   serves only that router (see the sandbox checklist below). What died
   with tonic is the daemon's `Server::builder().add_service()` chain in
   `app/arcbox-daemon/src/services.rs`, not the connectrpc router builder
   method of the same name.

**Add/change something under `arcbox.sandbox.v1` (the Connect surface):**
1. Edit the `.proto`; a *new* file goes into all three proto lists named in
   step 2 above (`arcbox-connect`, `arcbox-protocol`, `arcbox-grpc`) —
   connectrpc codegen is the one that emits the service traits the daemon
   implements. Any edit here also needs step 3's
   `make refresh-connect-descriptor`.
2. Implement the method in `app/arcbox-api/src/connect/` against the
   connectrpc trait, not a tonic one, working in the buffa types directly
   (`request.to_owned_message()` in, owned messages out — the blanket
   `Encodable` impl covers them). There is no bridge to cross.
3. A new *service* goes on `arcbox_api::connect::router` (or
   `router_with_system`). The daemon serves only that router, so a service
   missing there is a 404 on every format — the
   `migrated_daemon_services_are_registered_on_the_connect_router` test in
   `control_plane.rs` is where that surfaces.
4. No codec step remains: the guest agent, `AgentClient`, and the vsock
   frames use the same `arcbox-connect` buffa types, so a new message is
   *available* to them the moment it is generated. Available is not wired:
   a message that must actually cross the vsock channel still needs the
   host↔guest checklist below (`MessageType`, guest dispatcher arm,
   `AgentClient` method).

**Add a host↔guest agent RPC (NOT a tonic method):**
1. Define the proto *message* in `agent.proto`.
2. Add a `MessageType` enum variant **and** its `from_u32` arm in
   `common/arcbox-constants/src/wire.rs` (and a roundtrip test case).
3. Wire the guest side in BOTH files: the frame codec arms in
   `guest/arcbox-agent/src/rpc.rs` (`parse_request`, `message_type`,
   `encode_payload`) and the `handle_request` dispatch in
   `guest/arcbox-agent/src/agent/linux/rpc.rs` — `guest/AGENTS.md`'s
   extending checklist is authoritative for this half.
4. Add a method on `AgentClient` (`app/arcbox-core/src/agent_client.rs`) that
   buffa-encodes and frames the message via `rpc_call`.

**EXCEPTION — the sandbox family (every `MessageType` for which
`is_sandbox_request()` is true: the `Sandbox*` types incl. the
`SandboxTemplate*` catalog types, plus `WatchSandboxCleanupRequest`)**
skips step 3's codec half: `MessageType::is_sandbox_request()` routes the
whole family to `handle_sandbox_message`
(`guest/arcbox-agent/src/agent/linux/sandbox.rs`) *before* the `rpc.rs`
codec, which therefore has no arms for it. Step 1's proto file splits by
audience: messages of the public sandbox API live in the
`arcbox/sandbox/v1` protos (all three build-script arrays), while
host↔guest-internal control frames (`SandboxPortForwardRequest`,
`SandboxCleanupTicket`, `SandboxResumeCommand`, …) stay in `agent.proto` —
never expose an internal frame through the public schema. A new
sandbox-family message needs: the proto (in the right file per that
split), the `MessageType` variant + `is_sandbox_request()` arm, a
`handle_sandbox_message` dispatch arm, and the `AgentClient` method.
`MachineExecRequest` is the one other codec bypass: it is dispatched by
name before `parse_request` (`guest/arcbox-agent/src/agent/linux/rpc.rs`),
so it has no `rpc.rs` arms either. Streaming alone does not waive the
codec — `WatchReadiness`/`WatchStats`/`WatchMemoryPressure` stream too and
keep their `rpc.rs` arms.

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
