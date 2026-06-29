# VirtIO Queue Abstraction Convergence

## Status

Planned. Gated on Phase 0 (cold-boot hang root cause). Locked decisions:
**full unification** of every datapath, and **root-cause the cold-boot hang
before converging notification semantics**.

## Problem

The same split-virtqueue logic (walk the avail ring, parse the descriptor
chain, write the used ring, decide whether to interrupt) is currently
duplicated across five parallel implementations that disagree with each other:

| # | Implementation | Location | State |
|---|----------------|----------|-------|
| 1 | `VirtQueue` (local `Vec` rings) | `virtio-core/src/queue.rs` | Half-dead: each device allocates one in `activate()` but `process_queue` never reads it |
| 2 | `GuestMemoryVirtQueue` (raw `*mut u8`) | `virtio-core/src/queue_guest.rs` | Fully dead: zero production references |
| 3 | Inline hand-rolled GPA walks | each device's `process_queue` | Live (one of the production paths) |
| 4 | `virtqueue_util` + `GuestMemWriter` | `arcbox-vmm/src/{virtqueue_util,blk_worker,net_rx_worker}.rs` | Live (worker-thread path) |
| 5 | Net-TX inline used-ring write | `device/mod.rs` QUEUE_NOTIFY handler | Live (vCPU-thread inline) |

Consequences:

- **Cycle-guard divergence.** The two library queues cap chain traversal at
  `queue.size`. The inline blk walks used unbounded `loop {}` — a cyclic
  `next` chain (`0 -> 1 -> 0`) spins the vCPU thread forever. (Fixed
  surgically as a precursor; see "Precursor".)
- **EVENT_IDX divergence.** Only `arcbox-net-inject` honors `used_event`
  suppression before firing. Others delegate to the VMM, do not advertise
  EVENT_IDX, or carry dead EVENT_IDX branches.
- **`gpa_base` handling divergence.** `GuestMemWriter` correctly does
  `gpa.checked_sub(gpa_base)`; the dead `GuestMemoryVirtQueue` assumes
  `GPA 0 == ram_base` — wrong for ARM RAM layouts that do not start at 0.

## Target Design

One queue type in `arcbox-virtio-core`, backed by the proven, `gpa_base`-aware
`GuestMemWriter`. The `gpa_base` subtraction, the cycle guard, and the
EVENT_IDX suppression decision each live in exactly one place.

```rust
pub struct SplitQueue {
    mem: Arc<GuestMemWriter>,   // the only place gpa_base subtraction happens
    queue_idx: u16,
    size: u16,
    desc_gpa: u64,
    avail_gpa: u64,
    used_gpa: u64,
    last_avail_idx: u16,
    used_idx: u16,
    event_idx: bool,
}

impl SplitQueue {
    pub fn new(mem: Arc<GuestMemWriter>, queue_idx: u16, cfg: &QueueConfig) -> Self;
    pub fn has_avail(&self) -> bool;
    /// Bounded by `size` (cycle-safe) — centralizes the precursor fix.
    pub fn pop_avail(&mut self) -> Option<DescChain<'_>>;
    /// Returns whether the guest must be interrupted (the single EVENT_IDX +
    /// NO_INTERRUPT decision point).
    pub fn push_used(&mut self, head_idx: u16, len: u32) -> bool;
    pub fn push_used_batch(&mut self, completions: &[(u16, u32)]) -> bool;
    pub fn write_avail_event(&self);
}
```

`DescChain` yields descriptors whose `addr` is a **GPA**; buffer access goes
through `mem.slice(gpa, len)` / `mem.slice_mut(gpa, len)`. This removes the
`checked_sub(gpa_base)` scattered across every device.

New `VirtioDevice` trait (drops `memory: &mut [u8]` and the per-notify
`QueueConfig`):

```rust
// Called by the VMM at QUEUE_READY; device builds its SplitQueue from the
// DeviceCtx-bound Arc<GuestMemWriter>.
fn configure_queue(&mut self, queue_idx: u16, cfg: QueueConfig);
// Device pops/serves/push_used via its own SplitQueue; returns whether to IRQ.
fn process_queue(&mut self, queue_idx: u16) -> Result<bool>;
```

- **Synchronous devices** (rng, balloon, console, fs, vsock-TX, net-TX):
  `process_queue` does the work via the held `SplitQueue` and returns the
  notify decision; the VMM raises the IRQ accordingly.
- **Worker-thread devices** (blk, net-RX, vsock-RX): the `SplitQueue` is owned
  by the worker thread. `configure_queue` hands it the config; `process_queue`
  only signals a kick and returns `false`; the worker pops/pushes via its
  `SplitQueue` and raises its own IRQ (as today).
- The VMM `handle_mmio_write` QUEUE_NOTIFY arm collapses to
  `if dev.process_queue(idx)? { raise_irq() }`. The net-TX inline used-ring
  write, `blk_worker::dispatch` parsing, and `virtqueue_util` all fold into
  `SplitQueue`.

## Phases

Each phase is an independently compilable, runnable set of commits
(~200 lines each). Worker hot paths come last.

### Phase 0 — Root-cause the cold-boot hang (gate)

Not a deterministic refactor; tracked by an exit criterion. Determine whether
the `blk_worker` "local-only DIAGNOSTIC" (which bypasses `should_notify`)
masks an EVENT_IDX suppression race or a WFI/`exit_vcpus` wakeup timing issue
(ABX-367). See "Cold-boot investigation" below.

**Exit criterion:** with correct `should_notify` restored, >= 20 consecutive
cold boots are green; the diagnostic bypass and its three `unused` warnings
(`should_notify` / `avail_addr` / `queue_size`) are removed.

Until this lands, no path's notification semantics change.

### Phase 1 — Land `SplitQueue` (no callers)

- Rewrite `virtio-core/src/queue.rs`: `SplitQueue` + `DescChain` over
  `Arc<GuestMemWriter>`.
- Merge the cycle / EVENT_IDX / push_used tests from `queue.rs` and
  `queue_guest.rs` onto `SplitQueue`; add a non-zero-`gpa_base` GPA->offset
  test (closes the `queue_guest` base-assumption bug).
- Old types stay; zero call-site changes. Verify: `cargo test -p arcbox-virtio-core`.

### Phase 2 — Trait change + VMM dispatch skeleton

- `virtio-core/src/lib.rs`: new `VirtioDevice` (`configure_queue`, new
  `process_queue`).
- `arcbox-vmm/src/device/mod.rs`: QUEUE_READY -> `configure_queue`;
  QUEUE_NOTIFY -> unified `process_queue(idx)` -> `raise_irq`. `mmio_state.rs`
  invokes `configure_queue` on QUEUE_READY.
- Devices get a temporary `process_queue` stub (`Ok(false)`) so the tree
  compiles. Verify: workspace `cargo build`.

### Phase 3 — Migrate synchronous devices (one commit each)

Order: rng -> balloon -> console -> fs -> vsock-TX. Each drops its hand-rolled
walk + `Option<VirtQueue>` + `last_avail_idx` for the held `SplitQueue`, with
per-device tests. Verify: per-crate `cargo test`.

### Phase 4 — Migrate worker / hot paths (last, per-device, with perf checks)

- `blk_worker.rs`: worker holds a persistent `SplitQueue`; delete `dispatch`
  parsing and `virtqueue_util` use.
- net: `drain_tx_queue` / `poll_rx` + `net_rx_worker.rs` + `arcbox-net-inject`
  (`queue.rs`, `irq.rs`) onto `SplitQueue`; net-TX moves from the
  `device/mod.rs` inline block into `VirtioNet::process_queue`.
- vsock RX worker likewise.
- Verify: cold boot + blk/net/fs/vsock functional regression + throughput /
  boot-time no regression against the performance targets.

### Phase 5 — Delete dead code

`queue_guest.rs`, the old local-ring `VirtQueue`, `virtqueue_util.rs`,
vestigial device fields; the unwired `AsyncBlockBackend` / `DirectIoBackend` /
`MmapBackend` if still unused; trim umbrella re-exports. Verify:
`cargo clippy --workspace` with zero warnings.

### Phase 6 — Final verification

Full cold/warm boot, end-to-end across the four device classes, the precursor
cycle test now living as a `SplitQueue` unit test, performance against
baseline.

## Branch & commit strategy

The convergence runs on `refactor/virtio-queue-unify`, cut from `master` after
Phase 0 merges. Atomic commits per phase / per device, ~200 lines each,
compilable and runnable. Everything but Phase 4 is low risk.

## Precursor (already done)

The inline blk cycle-guard was the immediate bleeding and was fixed ahead of
this refactor: `blk/device.rs::process_queue` and `blk_worker.rs::dispatch`
changed from unbounded `loop {}` to bounded `for _ in 0..q_size`, with a
`process_queue_terminates_on_cyclic_descriptor_chain` regression test. The
other ten inline walks were verified to already be bounded `for _ in 0..q_size`.
