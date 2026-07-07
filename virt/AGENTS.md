# virt/ — VirtIO & Hypervisor Agent Guidance

Invariants distilled from the HV fix campaign (Linear project "HV Backend").
Each of these was violated once and cost a multi-session debugging hunt.

## One SplitQueue

- Every split-virtqueue operation — avail walk, used publish, notify
  decision — goes through `arcbox-virtio-core::SplitQueue`. Never hand-roll
  ring walks, used-ring writes, or EVENT_IDX math in device or worker code.
  `queue.rs::VirtQueue` remains only for the live VZ/device-local paths;
  do not add new consumers.
- Notify semantics are asymmetric by design: TX publishes the consumed
  cursor (`write_avail_event`), RX polling consumers publish the guest's
  current avail.idx (`write_avail_event_current`). Do not "unify" them.
- RX invariant: `last_avail_idx == used.idx` — one used entry per consumed
  avail entry. Speculative gathers must rewind the avail cursor on every
  early-exit path (short read, WouldBlock, EOF, validation failure);
  never rewind used.idx.

## Guest-controlled input

- Every guest-programmed value (ring GPA, queue size, descriptor field,
  index) is arbitrary bits. All arithmetic on them must be checked
  (`checked_add`/`checked_sub` → bail), and bounds must be verified before
  any `unsafe` guest-memory access. Debug builds panic on overflow while
  release wraps past bounds checks — both are bugs; tests must cover
  near-`u64::MAX` inputs.

## Diagnosis before theory

- For boot/queue failures, capture the debug snapshot (`Vmm::debug_snapshot`
  / `SystemService.GetVirtioDebug`: per-queue kicks, live avail/used
  indices, per-vCPU exit counters) while the VM is alive. Console-log
  archaeology has produced multiple wrong root causes in this tree.
- To localize a config-dependent failure, bisect with the `hv_e2e`
  config-matrix knobs (`ARCBOX_HV_E2E_VCPUS/MEMORY_MB/BALLOON/...` +
  `BOOT_ONLY=1`), one dimension at a time from the minimal probe toward
  the daemon shape.
- Validation ladder for HV changes: crate unit tests → bare probe
  (`cargo test -p arcbox-e2e --test hv_vmm`) → daemon level
  (`--test virtio_debug`, `--test boot_assets` with `ARCBOX_VM_BACKEND=hv`)
  → `cargo xtask e2e --repeat N` for race-class fixes.
