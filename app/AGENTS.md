# app/ — Daemon & Core Agent Guidance

- Daemon startup: the 5-phase order is load-bearing — see the root
  CLAUDE.md "Architecture Principles" and `docs/daemon-lifecycle.md`
  before reordering anything.
- Two runtime handles exist in the daemon: `shared_runtime` (set after
  full init; gates normal RPCs with UNAVAILABLE) and `early_runtime`
  (set right after `Runtime` construction, before the VM boots).
  Diagnostic RPCs (`GetVirtioDebug`) must serve from `early_runtime` —
  a stuck boot is their main use case. Never gate a diagnostic on
  `ready()`.
- Fatal startup failures must be published via `SetupState::set_failed`
  before exiting, so `WatchSetupStatus` clients see the cause instead of
  a bare disconnect.
- `connect_agent` transport differs by backend: blocking on the HV
  AF_UNIX socketpair, async on VZ AF_VSOCK and on Linux. Branch on
  `AgentClient::is_blocking()`; calling a `*_blocking` RPC on VZ fails
  deterministically.
- The HV guest's wall clock is set by the post-readiness ping in
  `vm_lifecycle` (`PingRequest.timestamp_secs` → agent `clock_settime`).
  Do not remove that ping until a PL031 RTC device lands (ABX-416).
