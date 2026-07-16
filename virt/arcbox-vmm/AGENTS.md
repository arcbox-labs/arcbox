# arcbox-vmm Agent Guidance

Scope: the macOS Hypervisor.framework (HV) backend. VZ is the oracle — HV-only
red points at code here; double red points above the hypervisor. The parent
`virt/AGENTS.md` owns the SplitQueue and validation-ladder invariants; this
file owns the HV-framework-specific footguns.

## Async-Worker Completion Contract (read first)

Raising a GIC SPI alone does NOT wake a WFI-parked vCPU on this backend — the
guest services the IRQ only on its next VM exit. Any async worker that
completes guest I/O (blk, net-rx, vsock, console, or a future device) MUST do
all three, in this order:

1. `VirtioMmioState::trigger_interrupt(1)` — set interrupt_status (INT_VRING).
2. Fire the `DeviceIrqCallback` (`irq_callback(irq, true)`) — assert the SPI.
3. Call the worker's `exit_vcpus()` closure — kick every vCPU out of WFI.

Omitting step 3 produces intermittent guest hangs (guest sleeps until an
unrelated exit) that are invisible in logs. Reference: `blk_worker.rs::trigger_irq`
(blk_worker.rs:719-729, rationale 176-181); the GIC callback's complementary
unpark-all loop is `setup.rs:145-154`. Worker `exit_vcpus` closures are built by
`make_exit_vcpus_fn` (`vmm/darwin_hv/mod.rs:157-181`) and wired at
`console.rs:31`, `vsock.rs:136`, `lifecycle.rs:143,212`.

## vCPU Exit Loop: PC-advance is asymmetric by exit class

Hypervisor.framework auto-advances ELR/PC on HVC/SMC but NOT on DataAbort
(MMIO) or trapped SystemRegister exits (`vcpu_loop.rs`):

- MMIO (DataAbort): manually `PC += 4` after handling — else the instruction
  re-traps (vcpu_loop.rs:331-334).
- HVC/SMC: do NOT manually advance — auto-advanced; a manual +4 skips an
  instruction (vcpu_loop.rs:378-380).
- Unknown sysreg: treat as RAZ/WI (read → write 0 into Xrt, writes dropped) and
  force `PC += 4`. Without it, Linux early boot writes OSDLR_EL1 and wedges in an
  infinite MSR-trap loop (vcpu_loop.rs:436-469).

Adding a new exit-class handler: decide its advance behavior explicitly; don't
copy a neighbor blindly.

## macOS HV Block Worker Contract

`blk_worker.rs` re-implements only virtio-blk request PARSING/EXECUTION; it does
not inherit that logic from `arcbox-virtio-blk::VirtioBlock`. Feature-bit and
config-space advertisement is NOT duplicated — the HV MMIO device wraps
`VirtioBlock`'s `VirtioDevice` impl, so `register_virtio_device` reads `features()`
(mod.rs:758) and config-space reads hit `read_config` (dispatch.rs:48) through it;
edit those in one place, not two. `arcbox-virtio-blk/AGENTS.md` is the source of
truth for feature semantics and request-parsing validation; keep this worker in
lockstep with it. If the worker cannot honor a feature on P0 macOS, do not
advertise that feature for devices using this backend.

Worker-specific coupling not in the shared doc:

- FLUSH spin-waits on the cross-queue `FlushBarrier.in_flight`
  (blk_worker.rs:345-353, 769-788). Only Read/Write/WriteZeroes enroll (inc/dec)
  in the barrier; DISCARD is deliberately excluded (advisory)
  (blk_worker.rs:332-361). Any NEW data-mutating request type must enroll, or a
  following FLUSH returns before its data hits disk.
- Tests must exercise the worker parser/executor, not just shared leaf helpers.

## macOS HV Net RX Worker Contract

RX injection has two flavors — the channel-based `RxInjectThread`
(`arcbox_net_inject::inject`, preferred) and the legacy kqueue-on-socketpair
`net_rx_worker.rs` (fallback; try_spawn picks between them, net_worker.rs:118) —
and both drive frames through `arcbox_net_inject::queue::inject_one_frame`.
`arcbox-net-inject` is the source of truth for RX ring walk, notify, and
MRG_RXBUF `num_buffers` semantics; a fix there lands for both flavors. Any change
must keep both flavors' `QueueConfig` snapshot and `Arc<GuestMemWriter>` wiring in
lockstep — they share the one inject entry point, so diverging their wiring
silently breaks whichever path is not exercised in your test.

## MMIO Register File

`MAX_VIRTQUEUES` (`device/mmio_state.rs:95`, currently 64) bounds every per-queue
array and every queue-indexed dispatch path. virtio-blk sets
`num_queues = vcpu_count` (one queue per vCPU, `setup.rs:333`), so a bound
smaller than the max supported vCPU count silently drops queue config for
`queue_sel >= bound` and boot-wedges the guest (ABX-386). Keep the regressions in
`device/tests.rs`: `queue_config_beyond_eight_round_trips` (round-trips a
selector > 8) and the near-`u64::MAX` ring-address snapshot test.

## Diagnostic Counters (never reset — post-mortems need history)

- `VirtioMmioState::kicks`/`interrupts` (mmio_state.rs:134,136) and
  `vcpu_stats::VcpuStats` are cumulative across device resets.
- `hv_kick_broadcasts`: incremented ONLY by `make_exit_vcpus_fn` (mod.rs:169) —
  i.e. every io-worker all-vCPU wake. Teardown (`stop`/`pause`) calls
  `vm.exit_vcpus` directly (lifecycle.rs:433,557) and is intentionally NOT
  counted; do not expect this counter to move during shutdown.
- `hv_unpark_broadcasts`: incremented by the GIC IRQ callback's unpark-all loop
  (setup.rs:148).
- R2/R3 acceptance is measured from these numbers. A refactor that bypasses the
  counter sites falsifies the metrics.

## Debugging: entry points and failure signatures

Two snapshots (HV only; empty/zero under VZ — devices belong to VZ):

- `Vmm::debug_snapshot` (vmm/mod.rs:642) — devices + per-vCPU exit counters +
  kick/unpark broadcasts.
- `DeviceManager::virtio_debug` (device/debug.rs:75) — devices/queues only;
  reads MMIO mirror + live guest ring memory, THROUGH poisoned locks.

Both are observational and MUST be captured while the VM is alive (a stuck boot
is the main use case). Exposed via the `GetVirtioDebug` RPC — served from
`early_runtime`, never gated on readiness (see `app/AGENTS.md`). Console-log
archaeology produced multiple WRONG root causes for ABX-386; snapshot first.

| Symptom | First move | Likely cause |
|---|---|---|
| >8-vCPU cold boot: guest wedges D-state / `folio_wait_bit_common` stall | live snapshot → find a blk queue whose `avail_idx` advances while `used_idx` stays stuck, or config dropped for high `queue_sel` | per-queue register array too small (`MAX_VIRTQUEUES` vs one-queue-per-vCPU), ABX-386 |
| Guest TLS/cert validation fails right after boot | check whether agent-up ping has fired | no RTC; guest sits at kernel default epoch until the post-readiness ping sets the clock (ABX-416) |
| Intermittent guest hang just after an I/O completes | audit the worker's completion path | missing `exit_vcpus()` — see Async-Worker Completion Contract |

For config-dependent boot failures, bisect with the `hv_e2e` config-matrix knobs
(`ARCBOX_HV_E2E_VCPUS/MEMORY_MB/BALLOON/BOOT_ONLY/...`, all share the
`ARCBOX_HV_E2E_` prefix) one dimension at a
time — see `virt/AGENTS.md`. This is how ABX-386 was localized to "vCPU count,
threshold exactly 8".

## Teardown ordering is a contract (ABX-415 open SIGSEGV)

`stop_darwin_hv` (lifecycle.rs) has a load-bearing order:

1. Join all vCPU threads (via the targeted `exit_vcpus` + unpark cancel loop).
2. Join every worker that holds a `GuestMemWriter`: blk (457-464), net-rx
   (466-477), vsock (479-486), console (488-495). These reference guest RAM;
   dropping guest memory before they exit is a use-after-free.
3. Cleanup strictly DAX `drain_all` → GIC → `hv_vm` → `hv_guest_mem`
   (497-517). DAX `hv_vm_unmap` must run while the VM is alive; guest memory
   must outlive `hv_vm` so mapped pages stay valid until `hv_vm_destroy`.

ABX-415 (SIGSEGV on SIGTERM) lives in exactly this path — do not reorder without
re-reading every join site's comment.

## vCPU registration ordering (ABX-367)

`hv_vcpus_exit` on arm64 is a silent no-op for NULL/0 — it needs a concrete list
of vCPU IDs (mod.rs:153-156). Each vCPU pushes its raw handle then its `Thread`
into the shared registries ONLY after all register-setup calls succeed
(vcpu_loop.rs:152-171); pushing earlier risks a dangling handle (UB in Apple's
framework) or an unbounded registry across failed boots. `make_exit_vcpus_fn`
snapshots the registry each call and early-returns when empty (mod.rs:162-168);
`stop` warns when the registry is empty while threads are alive
(lifecycle.rs:400-404). Consequence: a worker's `exit_vcpus()` firing before
secondaries register is a no-op for those vCPUs.

## Guest-controlled input

Parent `virt/AGENTS.md` "Guest-controlled input" owns the rule (checked
arithmetic on every guest-programmed value, tests near `u64::MAX`). HV-specific
coverage: the near-`u64::MAX` ring-address snapshot regression in
`device/tests.rs` — keep it green.

## Platform Gaps

- No RTC: guest wall time comes from the post-readiness agent ping
  (`AgentPingRequest.timestamp_secs` → agent `clock_settime`) until a PL031 device
  lands (ABX-416). Anything time-sensitive before agent-up sees the kernel
  default epoch — TLS cert validation in particular fails.

## Validation

Follow the ladder in `virt/AGENTS.md`, cheapest first: crate unit tests →
`cargo test -p arcbox-e2e --test hv_vmm -- --ignored` (bare probe) →
`--test virtio_debug` / `--test boot_assets` (each with `-- --ignored`)
under `ARCBOX_VM_BACKEND=hv` (daemon level) → `cargo xtask e2e --repeat N`
for race-class fixes.
