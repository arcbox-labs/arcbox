# arcbox-virtio-blk Agent Guidance

This crate owns the virtio-blk wire contract (feature bits, config, request
headers, status, checked sector→byte conversion, and the shared host-side
punch/zero primitives in `punch.rs` — the only place a new host op lands; the
`backend.rs`/`mmap.rs`/`direct_io.rs` traits are vestigial, no runtime caller).
`README.md` has the path inventory, the DISCARD/WRITE_ZEROES advisory-vs-mandatory
contract, and the basic review checklist — read it first. This file carries the
invariants, the two-path lockstep checklist, failure signatures, and the
validation ladder that the README and code do not spell out.

## Advertising a feature bit: two edits the parsers never touch

Before either parser sees a request, a new feature needs two sites wired up:

- **The bit** — `device/mod.rs` `FEATURE_*` = `1 << virtio_bindings::
  virtio_blk::VIRTIO_BLK_F_*`. The bindings export bit *positions*, not masks;
  shifting the wrong number (or, for a bit the bindings lack, its spec position)
  is a silent off-by-a-power-of-two.
- **Config-space bytes** — `read_config` (`device/virtio_device.rs:23-66`)
  hand-lays `virtio_blk_config` at fixed offsets (discard fields at 36,
  write-zeroes at 48). Guests read these at probe time and treat a **zeroed
  field as "unsupported"**, so the op is never emitted despite the feature bit
  being set. Advertising a new limit means growing this array too.

## Two block I/O parsers (advertise a feature only if BOTH honor it)

A virtio-blk feature bit lives in one place but is executed by two independent
parsers. Advertising a bit that only one parser honors ships a broken feature —
see the parent `README.md` for why. VZ is NOT one of them: the VZ backend uses
Apple's `VZVirtioBlockDeviceConfiguration` (`arcbox-vz/src/device/storage.rs:41`)
and has zero dependency on this crate — VZ block I/O is Apple's, never our code.

- **Generic / reference parser** — `VirtioBlock::process_descriptor_chain`
  (`device/io.rs`), driven by `process_queue` (`device/virtio_device.rs`). The
  feature-semantics source of truth, but **exercised only by this crate's unit
  tests** in production: HV setup constructs `VirtioBlock` only for metadata
  (fd/blk_size/capacity) and dispatch routes block to the worker doorbell, so
  `process_queue` is never reached. It **deliberately hand-rolls the avail/used
  ring walk** (`virtio_device.rs:114-283`) — the exemption the parent
  `virt/AGENTS.md` "One SplitQueue" rule carves out. **Do NOT migrate it onto
  `SplitQueue`.**
- **macOS HV worker parser** — `arcbox-vmm/src/blk_worker.rs`. This is the only
  arcbox block path that runs at runtime (P0 macOS) and IS the `SplitQueue`
  consumer (`blk_worker.rs:260`, `pop_avail`/`push_used`/`enable_notification`).
  One worker thread owns each queue end-to-end (doorbell model). It does not
  inherit anything from `VirtioBlock` — a new feature must be mirrored by hand.

## Divergence checklist (keep the two paths in lockstep)

When you change one path, mirror the intent (not the code) in the other. The
paths differ in load-bearing ways that are easy to break silently:

- **I/O syscall.** Generic loops per-descriptor `pread`/`pwrite`
  (`io.rs:49-73, 96-120`); worker issues one `preadv`/`pwritev` scatter-gather
  syscall (`blk_worker.rs:411, 467`). A partial transfer is an I/O error in both.
- **used-ring `len`.** Generic returns bytes of data moved (`io.rs:300`); worker
  returns `total_data_len + 1` on success / `1` on error — it **includes the
  status byte** (`blk_worker.rs:368-373`). Don't "fix" one to match the other.
- **Sector stride.** The generic multi-descriptor loop hardcodes `512`
  (`io.rs:295, 316`), not `blk_size`. If you touch that loop, keep the stride
  consistent with what the header sector means.
- **FLUSH.** Generic just `sync_all()`s (`io.rs:124-139`). The worker first
  spin-waits the cross-queue `FlushBarrier` so in-flight I/O on ALL queues
  drains before `fsync` (`blk_worker.rs:345-353`) — see below.
- **Per-request caps.** `MAX_WRITE_ZEROES_SECTORS` (2048, `device/mod.rs:69`)
  and `MAX_DISCARD_SECTORS` (32768, `device/mod.rs:74`) are defined once.
  The worker imports them via `arcbox_virtio::blk::VirtioBlock::MAX_*`
  (`blk_worker.rs:638,659`) — never redefine them worker-side.
- **Not enforced (don't chase a phantom sync point):** advertised
  `seg_max`/`max_discard_seg`/`discard_sector_alignment` are NOT range-checked
  by either path (alignment is 1, the single-range seg limit is never hit).
  Only the `num_sectors` caps above are enforced.

## FlushBarrier ordering invariant (HV worker only)

A FLUSH on one queue must wait for data-mutating ops on **every** queue, so
`process_item` counts WRITE_ZEROES into `flush_barrier.in_flight` alongside
Read/Write, but **excludes DISCARD** (`blk_worker.rs:333-336`): WRITE_ZEROES
mutates data the guest will read back, DISCARD is advisory. Reclassifying
DISCARD as in-flight only slows flush; dropping WRITE_ZEROES from the barrier
silently breaks durability ordering on crash — a non-reproducible corruption
class. This barrier exists only in the worker, so it is invisible from the
generic path; keep it when refactoring either.

## Guest-input hygiene (every sector/length field is arbitrary bits)

All sector→byte arithmetic MUST route through the shared checked helpers in
`request.rs`: `checked_io_byte_range` (read/write) and
`DiscardWriteZeroesRange::checked_byte_range` (discard/write-zeroes). Both use
`checked_add`/`checked_mul` → `VirtioError`. Both paths already call them
(`io.rs:40,87,186,232`; `blk_worker.rs:399,455,590`). A new fast path that does
raw `sector * blk_size` arithmetic **panics in debug and silently wraps past the
capacity bound in release** — both are bugs. Tests for any new parser must cover
near-`u64::MAX` sectors/lengths, not just the happy path (parent
`virt/AGENTS.md` "Guest-controlled input").

## Failure signatures (what to run FIRST)

- **>8-vCPU cold boot wedges; guest PID 1 stuck in D-state /
  `folio_wait_bit_common`.** blk-mq creates one queue per vCPU
  (`vmm/darwin_hv/setup.rs:332-333` sets `num_queues = vcpu_count`), so virtio-blk
  is the device that stresses the per-queue MMIO register file. First: capture a
  **live** debug snapshot while the VM is alive — `SystemService.GetVirtioDebug`
  / `Vmm::debug_snapshot` (per-queue kicks + avail/used indices). Do NOT read
  console logs first; log archaeology produced multiple WRONG root causes for
  this exact bug (ABX-386). Likely cause is dropped queue config **above the
  hypervisor**: the `MAX_VIRTQUEUES` bound on the MMIO arrays in
  `arcbox-vmm/src/device/mmio_state.rs` (now 64), not this crate. If a queue
  selector ≥ that bound is silently ignored, the guest's blk-mq queues exist
  guest-side only and PID 1 hangs on the first page-in.
- **A blk bug reproduces under HV but not VZ (HV-only red).** VZ is the oracle,
  but its block I/O is Apple's framework (none of this crate runs under VZ), so
  the split is one-sided: HV-only red points at `blk_worker.rs` (or `request.rs`,
  which is HV-only in production — `io.rs` is test-only). Double red (both
  backends) can NOT be this crate's block code; it points **above the
  hypervisor** — guest, config, or kernel.

## Validation ladder (cheapest first)

1. Unit tests in **both** crates — the generic parser
   (`cargo test -p arcbox-virtio-blk`, see `device/tests.rs` + `request.rs`) AND
   the worker parser/executor (`cargo test -p arcbox-vmm blk_worker` — covers
   `write_past_capacity_is_rejected`, `punch_discard_ranges_reclaims_blocks`,
   `zero_ranges_zeroes_backing_file`,
   `range_parser_concatenates_split_payload_descriptors`). A feature test must
   exercise the real request path, not a leaf helper.
2. Bare HV probe: `cargo test -p arcbox-e2e --test hv_vmm`.
3. Daemon-level boot: `cargo test -p arcbox-e2e --test virtio_debug` and
   `--test boot_assets` with `ARCBOX_VM_BACKEND=hv`.
4. Race-class fixes: `cargo xtask e2e --repeat N` (never hand-loop `cargo test`).

The harness self-preserves forensics on failure (`virtio-debug.json` captured
while the VM is alive, `metrics.json` phase timings) — read those before
re-running; see `tests/e2e/AGENTS.md` for readiness/isolation rules.
