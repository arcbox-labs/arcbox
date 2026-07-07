# arcbox-vmm Agent Guidance

## macOS HV Block Worker Contract

`src/blk_worker.rs` is an independent virtio-blk request parser and executor for the macOS HV backend. It does not automatically inherit behavior from `arcbox-virtio-blk::VirtioBlock`.

When adding, advertising, or changing a virtio-blk feature, keep the HV worker in lockstep with `virt/arcbox-virtio-blk`:

- parse the same request types;
- validate the same guest-controlled fields, flags, limits, and capacity bounds;
- preserve the same read/write/flush ordering guarantees;
- report malformed mandatory requests as I/O errors instead of silently succeeding;
- add tests that exercise the worker parser/executor, not just shared leaf helpers.

If the worker cannot honor a feature on P0 macOS, do not advertise that feature for devices using this backend.

## MMIO Register File

- `MAX_VIRTQUEUES` (device/mmio_state.rs) bounds every per-queue array and
  every queue-indexed dispatch path. virtio-blk configures one queue per
  vCPU, so any "N slots is plenty" assumption silently drops queue config
  on large VMs and boot-wedges the guest (ABX-386). When touching queue
  bookkeeping, keep the regression tests that round-trip a queue selector
  above 8 and near-`u64::MAX` ring addresses.

## Diagnostic Counters

- `VirtioMmioState::kicks`/`interrupts` and `vcpu_stats::VcpuStats` are
  cumulative and must never be reset (post-mortems need history across
  device resets).
- Keep the broadcast counter sites honest: every all-vCPU `hv_vcpus_exit`
  goes through `make_exit_vcpus_fn` (counts `kick_broadcasts`); the GIC IRQ
  callback's unpark-all loop counts `unpark_broadcasts`. R2/R3 acceptance
  is measured from these numbers — a refactor that bypasses the counters
  falsifies the metrics.

## Platform Gaps

- The HV backend exposes no RTC: guest wall time comes from the
  post-readiness agent ping until a PL031 device lands (ABX-416). Anything
  time-sensitive in the guest before agent-up sees the kernel default
  epoch.
