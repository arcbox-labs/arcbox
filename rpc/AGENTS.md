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

## Two protocols in one directory (read this first)

- **Daemon control plane = gRPC/tonic** (`arcbox-grpc`), served over the Unix
  socket. The daemon `add_service()`s exactly: Machine, Kubernetes, Migration,
  Sandbox, SandboxSnapshot, System, Icon (`app/arcbox-daemon/src/services.rs`).
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
- **`arcbox-protocol/proto/buf.yaml` exempts ONLY `sandbox.proto` from the
  CI `buf breaking` gate** — the sandbox surface is pre-release and being
  redesigned contract-first (CORE-52); every other proto in the dir stays
  under the default `FILE` breaking rules. Remove the exemption when the
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
2. Reproduce the CI proto gate locally (compares PR against its base, not a
   hardcoded master):
   `buf breaking rpc/arcbox-protocol/proto --against '.git#branch=origin/master,subdir=rpc/arcbox-protocol/proto'`.
3. For agent-protocol changes, continue up the HV validation ladder in
   `virt/AGENTS.md` (bare probe → daemon-level → `cargo xtask e2e`); VZ is the
   oracle backend, so HV-only red points at the HV transport/boot arm.
