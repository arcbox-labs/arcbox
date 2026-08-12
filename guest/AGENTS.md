# guest/ — Guest Agent Agent Guidance

`arcbox-agent` runs as PID 1 (or the respawned service) inside the Linux VM and
serves the host over vsock port 1024 (`arcbox_constants::ports::AGENT_PORT`). The
substantive code is `cfg(target_os = "linux")`-gated. For the RPC surface and
bootstrap role see `guest/arcbox-agent/README.md`; for the wire/proto evolution
policy see `rpc/arcbox-protocol/README.md`. This file carries only the
non-obvious invariants and failure signatures.

## Build & validate

- **Musl cross-compile is mandatory.** On a macOS dev host `agent::Agent` is
  the 39-line no-op `stub.rs` (`agent/mod.rs` cfg-selects `linux` vs `stub`), so
  `cargo test -p arcbox-agent` only exercises the stub + pure helpers and proves
  *nothing* about guest behavior. Build for `aarch64-unknown-linux-musl` (recipe
  in `guest/arcbox-agent/README.md` / root CLAUDE.md) and validate through e2e.
- **CI never lints the agent — you must, locally.** The workspace gate excludes
  it (`cargo clippy --workspace --exclude arcbox-agent -- -D warnings`,
  `.github/workflows/ci.yml`; the build and test steps exclude it too) and no
  job runs clippy against `aarch64-unknown-linux-musl` (`release.yml` only
  `cargo build`s that target). So `agent/linux` carries a pre-existing
  pedantic/nursery warning backlog no gate catches. Run
  `cargo clippy -p arcbox-agent --target aarch64-unknown-linux-musl --all-targets`
  and hold *your changed lines* to zero new warnings; do NOT bulk-fix the
  backlog in an unrelated PR — it buries your diff.
- **Validation ladder, cheapest first** (from `virt/AGENTS.md`): crate unit
  tests → bare probe `cargo test -p arcbox-e2e --test hv_vmm -- --ignored` →
  daemon level `--test boot_assets` / `--test virtio_debug` (each with
  `-- --ignored`) under `ARCBOX_VM_BACKEND=hv` →
  `cargo xtask e2e --repeat N` for race-class fixes.
- **VZ is the oracle**: HV-only red points at the HV implementation; double red
  points above the hypervisor. Readiness is observed host-side *only* via
  `WatchSetupStatus` — never log-grep or sleep for it.

## Invariants (each with WHY)

- **Protocol is additive-only.** Never remove/renumber proto fields; proto3
  field skew is silent (an old agent decodes new fields as defaults and
  misbehaves with zero diagnostics). Bump `AGENT_PROTOCOL_VERSION`
  (`common/arcbox-constants/src/wire.rs`) only when the *meaning* of an existing
  message changes; the host rejects agents below `MIN_AGENT_PROTOCOL_VERSION`
  (currently 1, so pre-handshake `0` agents are refused). `Ping` is the one
  message every agent generation understands and carries `protocol_version`.
- **Daemon and agent must ship from the same master state.** Both binaries are
  built from this repo, and the daemon stages the agent it shipped with into the
  guest's `/arcbox/bin/arcbox-agent` (the agent is NOT baked into the EROFS rootfs — the
  rootfs only wires that path into inittab). Pairing a new daemon with a stale
  agent trips the handshake above: boot fails with the intentional, actionable
  "staged agent binary is stale" error (`check_agent_protocol`, `agent_client.rs`)
  rather than a silent misdecode — do not treat it as a regression. The
  rootfs/kernel/FEX half is a SEPARATE, tag-driven release from the sibling repo
  `../boot-assets`: pushing a `vX.Y.Z` tag there builds the EROFS rootfs for both
  arches and publishes a merged `manifest.json` to `boot.arcboxcdn.com`
  (`.github/workflows/release.yml`). arcbox consumes a new release by bumping
  BOTH `[boot] version` and `manifest_sha256` in `assets.lock`, which is
  `include_str!`-embedded into the daemon at COMPILE time
  (`engine/arcbox-image/src/boot_assets/lockfile.rs`) — editing `assets.lock`
  without rebuilding the daemon changes nothing.
- **Guest wall clock comes from the Ping handler.** HV exposes no RTC (ABX-416),
  so `handle_ping` calls `sync_clock_from_host(req.timestamp_secs)` →
  `clock_settime(CLOCK_REALTIME)` (`agent/linux/rpc.rs`). Before that
  post-readiness ping the guest sits at the kernel default epoch and *all* TLS
  cert validation fails. It looks like a liveness no-op — do not "refactor away"
  the clock set until PL031 lands.
- **Docker readiness gates on the `/_ping` API probe, not socket-connectable**
  (`DockerProbe::ready()` in `agent/linux/runtime.rs`): dockerd binds its unix
  socket before it finishes loading containers, so a socket-only gate fires
  ready while the first proxied calls 500/EOF (ABX-408). A bound-but-initializing
  socket is NOT_READY progress, not an error. The host
  `ContainerRuntimeConfig::startup_timeout_ms` (150s) must stay above the guest
  ensure-runtime poll budget (~90s dockerd + 30s containerd), or a slow-but-fine
  boot produces a spurious RuntimeFailed.
- **init vs serve asymmetry** (`main.rs` `parse_mode`): `arcbox-agent init` (the
  busybox rcS one-shot) MUST fail fast — it returns `Err` if
  `verify_critical_mounts()` finds `/etc /run /var /tmp` unmounted, because
  running on read-only EROFS fails obscurely later. But `init_system()` on the
  PID 1 path is deliberately best-effort and must NEVER abort — PID 1 death
  panics the kernel. Do not unify these two paths.
- **Peer-closed vsock errors are routine teardown, not agent faults**
  (`is_peer_closed_error` in `agent/linux/vsock.rs`:
  BrokenPipe/ConnectionReset/ConnectionAborted/UnexpectedEof). The daemon closes
  the socketpair mid-write during normal teardown/retry and reopens on its next
  poll — log at warn/debug, never error.
- **`MmapReadFileRequest` (0x000B) and `KillAgentRequest` (0x000E) are test-only
  wire types** (see doc comments in `wire.rs`): the ABX-362 DAX path and the
  busybox-respawn supervision test. Keep them, but keep them test-scoped — do
  not wire a CLI to them or "clean them up."

## Debugging (symptom → first commands → likely cause)

- **Boot hang / readiness timeout / host logs "agent binary is stale"** →
  `ls -lt boot-assets/dev/arcbox-agent target/aarch64-unknown-linux-musl/release/arcbox-agent ~/.arcbox/bin/arcbox-agent`
  then `file <newest>`. `stage_dev_boot_assets` (`tests/e2e/src/boot_assets.rs`)
  copies the **newest-mtime** agent across those three locations, so a fresh
  build that wasn't re-staged loses to an old binary from another tree (ABX-385
  field-skew class). Wrong-version agents now surface as the handshake rejection
  (`app/arcbox-core/src/agent_client.rs`).
- **"engine ready" then intermittent 500/EOF on first API calls** →
  read `~/.arcbox/log/agent.log`, grep for `DockerProbe` / `/_ping`. Cause:
  readiness gated on socket rather than the `/_ping` probe (ABX-408 regression).
- **TLS / cert-validation failures early in boot** → check whether the host's
  post-readiness Ping was delivered (`sync_clock_from_host` log line in
  `agent.log`). Cause: guest still at kernel epoch — Ping not yet delivered or
  the `clock_settime` was removed (ABX-416).
- **Agent misbehaves on read-only rootfs (can't write resolv.conf, etc.)** →
  grep `agent.log` for `verify_critical_mounts` / missing mount targets. Cause:
  a critical tmpfs (`/etc /run /var /tmp`) didn't mount and the init-path check
  was bypassed.
- **Forensic entry point**: guest logs go to `/arcbox/log/agent.log` (VirtioFS,
  visible host-side as `~/.arcbox/log/agent.log`) with a `/dev/hvc1` console
  fallback (`main.rs`). e2e failures self-preserve the data dir and capture
  `virtio-debug.json` while the VM is alive — read those before re-running.

## Extending: add or change an RPC (lockstep set)

Every link below must change together; missing one fails as an opaque
"unexpected message type" or a silent no-op:

1. `rpc/arcbox-protocol/proto/agent.proto` — message definition (additive only).
2. `common/arcbox-constants/src/wire.rs` — `MessageType` enum variant + value.
3. `guest/arcbox-agent/src/rpc.rs` — `RpcRequest`/`RpcResponse` variants plus
   `parse_request`, `message_type`, and `encode_payload` (all three).
4. `guest/arcbox-agent/src/agent/linux/rpc.rs` — dispatch in `handle_request`
   (or a streaming handler like `handle_watch_readiness`, which holds the
   connection open and emits a sequence of `ReadinessEvent` frames rather than a
   single response — mirror that shape for new streaming RPCs).
5. `app/arcbox-core/src/agent_client.rs` — the host caller.

The full set above is for a **new message type**. Adding a *field* to an
already-wired message (e.g. a new `AgentPingRequest` field) touches only 1, the
generated file, the guest handler (4), and the host caller (5): the
`MessageType` variant (2) and the `rpc.rs` parse/`message_type`/`encode_payload`
arms (3) already exist — do not duplicate them.

**EXCEPTION — the sandbox family (every `MessageType` for which
`is_sandbox_request()` is true: the `Sandbox*` types incl. the
`SandboxTemplate*` catalog types, plus `WatchSandboxCleanupRequest`)**
replaces steps 3 and 4: `MessageType::is_sandbox_request()` routes the
whole family to `handle_sandbox_message` (`agent/linux/sandbox.rs`)
*before* the `rpc.rs` codec — do not add `rpc.rs` arms for it. Step 1's
proto file splits by audience: public sandbox API messages live in the
`arcbox/sandbox/v1` protos (all three build-script arrays, see
`rpc/AGENTS.md`); host↔guest-internal control frames
(`SandboxPortForwardRequest`, `SandboxCleanupTicket`,
`SandboxResumeCommand`, …) stay in `agent.proto` — never expose an
internal frame through the public schema. A new sandbox-family message
needs: the proto (in the right file per that split), the `MessageType`
variant + `is_sandbox_request()` arm, a `handle_sandbox_message` dispatch
arm, and the `AgentClient` method. `MachineExecRequest` is the one other
codec bypass: dispatched by name before `parse_request`
(`agent/linux/rpc.rs`), so it has no `rpc.rs` arms either. Streaming
alone does not waive step 3 — `WatchReadiness`/`WatchStats`/
`WatchMemoryPressure` stream too and keep their codec arms (step 4's
`handle_watch_readiness` pattern).

Then run the `buf` breaking check, decide whether the change alters existing
message *meaning* (if so, bump `AGENT_PROTOCOL_VERSION`), and add a test on the
real request path — not just a leaf helper.

## Guest-controlled input hygiene

Every value the host/guest boundary carries (offsets, lengths, indices) is
arbitrary bits: use checked arithmetic and bail on overflow (`req.length` bounds
in `handle_mmap_read_file` is the pattern). Debug builds panic on overflow;
release wraps past bounds checks — tests must cover near-`u64::MAX` inputs.
