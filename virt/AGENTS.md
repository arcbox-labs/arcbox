# virt/ — VirtIO & Hypervisor Agent Guidance

Invariants distilled from the HV fix campaign (Linear project "HV Backend").
Each was violated once and cost a multi-session debugging hunt. VZ is the
oracle backend (see Debugging): if you can only fix one thing, keep these
invariants intact.

## Datapath map — open the right file first

Every VirtIO device has **two coexisting queue datapaths**. Know which one
the failing backend drives before you edit anything.

- **HV production hot path** — `arcbox-virtio-core::SplitQueue`, built
  per-call from a `QueueConfig` (no persistent ring object). This is what
  a real HV boot runs:
  - net RX injection: `RxInjectThread` in
    `virt/arcbox-net-inject/src/inject.rs` is the production RX engine —
    spawned whenever `rx_inject_channel` is set, which the standard HV NAT
    datapath always does (`set_rx_inject_channel`); the spawn lives in
    `virt/arcbox-vmm/src/device/net_worker.rs` (note the `device/` subdir,
    unlike `net_rx_worker.rs` which sits directly in `src/`).
    `virt/arcbox-vmm/src/net_rx_worker.rs` is the **legacy kqueue fallback**,
    reached only when that channel is unset; a default HV boot never enters
    it, so do not "fix HV RX" there. The bridge NIC uses its own
    `set_bridge_host_fd` datapath, also not net_rx_worker.
  - net drain/poll: `virt/arcbox-virtio-net/src/device/hot_path.rs`.
  - blk: `virt/arcbox-vmm/src/blk_worker.rs` (independent parser — see
    `arcbox-vmm/AGENTS.md`).
- **VZ + unit-test / local-sim path** — `queue.rs::VirtQueue` local rings,
  driven through `VirtioDevice::process_queue(memory: &mut [u8], ..)` in
  `virt/arcbox-virtio-core/src/lib.rs`, which returns a
  `Vec<(head, bytes)>` completions list the VMM publishes. Net's
  `process_tx_queue` / `poll_backend_batch` in
  `virt/arcbox-virtio-net/src/device/tx_rx.rs` and each device's
  `activate()` live here. Queue sizing is per-device, not a blanket 256:
  blk/net/vsock RX+TX use `VirtQueue::new(256)`, but vsock's event queue is
  `VirtQueue::new(64)` and VirtioFS uses `VirtQueue::new(self.config.queue_size)`.

WHY it matters: editing `tx_rx.rs`/`process_queue` to fix an HV throughput
or hang bug touches code that is dead for HV. Fix HV bugs in the SplitQueue
files above.

## One SplitQueue

- Every split-virtqueue operation — avail walk, used publish, notify
  decision, EVENT_IDX math — goes through `arcbox-virtio-core::SplitQueue`.
  Never hand-roll ring walks or used-ring writes in device/worker code.
  `queue.rs::VirtQueue` stays only for the VZ/test path above; do not add
  new consumers. WHY: one implementation means one place to get the memory
  ordering and EVENT_IDX handshake right.
- **The `should_notify` SeqCst StoreLoad fence is load-bearing — never
  remove or weaken it** (`split_queue.rs`, `should_notify`). Under
  EVENT_IDX the `used.idx` store must be ordered before the `used_event`
  load; on ARM64 the load otherwise reorders ahead, reads a stale
  `used_event`, suppresses a needed IRQ, and the guest sleeps in WFI
  forever. WHY: this is the root-cause class of the HV cold-boot
  completion-notification hang.
- **Worker drain loops must call `SplitQueue::enable_notification` before
  sleeping** (the EVENT_IDX re-arm handshake; used by `blk_worker.rs` as
  `if !queue.enable_notification()`). It publishes `avail_event`, inserts a
  SeqCst barrier, re-reads `avail.idx`, and returns `true` if the guest
  added more — the caller must then drain again. WHY: skip it and a buffer
  the guest posted-but-suppressed-the-kick-for strands the queue forever.
- Notify semantics are asymmetric by design: TX publishes the consumed
  cursor (`write_avail_event`), RX polling consumers publish the guest's
  current avail.idx (`write_avail_event_current`). Do not "unify" them.
- RX invariant: `last_avail_idx == used.idx` — one used entry per consumed
  avail entry. Speculative gathers must rewind the avail cursor on every
  early-exit path (short read, WouldBlock, EOF, validation failure);
  never rewind used.idx.
- **MRG_RXBUF: `num_buffers` must equal the count of used entries the frame
  spans, and only the head carries the `virtio_net_hdr`** (stamped at bytes
  10..12; trailing buffers are pure payload). A wrong count silently drops
  every multi-buffer (bulk/GSO) frame while single-buffer traffic (ping)
  still flows — the classic "ping works, iperf reads zero" signature. Stamp
  sites: `inject.rs` (HV RX injection, `num_buffers = num_used`) and
  `tx_rx.rs` (VZ, `num_buffers = chains.len()`). WHY: the guest reassembles
  exactly `num_buffers` consecutive used entries into one packet.

## Guest-controlled input

- Every guest-programmed value (ring GPA, queue size, descriptor field,
  index) is arbitrary bits. All arithmetic on them must be checked
  (`checked_add`/`checked_sub` → bail), and bounds must be verified before
  any `unsafe` guest-memory access. Debug builds panic on overflow while
  release wraps past bounds checks — both are bugs; tests must cover
  near-`u64::MAX` inputs.

## vmnet relay (bridge NIC, `arcbox-vmnet`)

- The vmnet → guest read path is **event-driven** via
  `vmnet_interface_set_event_callback` (ABX-517) — do not reintroduce a
  polling/blocking read thread; the deleted 1 kHz poll cost ~half of the
  daemon's idle CPU and its cancel-then-join teardown could hang
  `Runtime::drop`. The callback context is owned by the handler block
  (copy retains, dispose releases) and must never be freed manually;
  `Vmnet::clear_event_callback` — called from both `Vmnet::stop` and the
  relay's exit path, idempotent — is what breaks the
  interface → block → ctx → `Arc<Vmnet>` cycle. Keep both call sites.

## Debugging — failure signature → first commands → likely cause

Triage rule first: **re-run the same scenario under
`ARCBOX_VM_BACKEND=vz`.** HV-only red points at the HV SplitQueue/worker
implementation; double red (VZ also fails) points above the hypervisor
(device logic, guest, image).

Before theorizing, read the forensics a failed e2e run already preserves on
disk (it keeps the data dir): `virtio-debug.json` (snapshot captured while
the VM was alive), `metrics.json` (phase timings). Readiness is observed
**only** via `WatchSetupStatus` — never log-grep or sleep for it. Console-log
archaeology produced multiple wrong root causes in this tree.
Those two feeds are queue-state and readiness. The guest-side view below
complements them — use it when a boot is wedged *before* it ever reports
readiness (nothing to snapshot, nothing on `WatchSetupStatus`), not as a
readiness signal.

- **Interactive serial shell into a hung HV guest.** On the custom-HV
  backend, `resolve_desired_boot` (`engine/arcbox-engine/src/vm_lifecycle/boot.rs`,
  the `DEBUG_CONSOLE_KEY` block) always appends
  `arcbox.debug_console=<data_dir>/run/console.sock` to the kernel cmdline;
  the guest rcS spawns a root shell keyed on the same token
  (`DEBUG_CONSOLE_KEY = "arcbox.debug_console="`, `common/arcbox-constants`).
  Attach with `socat - UNIX-CONNECT:<data_dir>/run/console.sock`. It reaches
  the guest even when early boot hangs before networking — the dominant
  historical HV cold-boot failure shape — because it rides the virtio-console
  device (`virt/arcbox-vmm/src/console_rx_worker.rs` +
  `arcbox-virtio::console::SocketConsole`), not the net stack.
  `ARCBOX_NO_DEBUG_CONSOLE=1` strips the token (host attaches no console,
  guest spawns no shell) to A/B-test whether the console itself perturbs the
  flaky boot. HV-only — the token targets the HV console wiring; VZ owns its
  console internally. The socket lives under the per-user data dir, so
  same-user access only.
- **Guest boot output lands on two tracing targets, both already in the
  daemon's `default_filter`** (`app/arcbox-daemon/src/main.rs`, so no
  `RUST_LOG` needed): `guest_serial` (PL011 earlycon, pre-handoff early
  kernel messages — `virt/arcbox-vmm/src/vmm/darwin_hv/pl011.rs`) and
  `guest_console` (VirtioConsole `hvc0`, post-handoff kernel console plus
  anything the agent writes to `hvc0` —
  `virt/arcbox-virtio-console/src/device.rs`). The handoff between them is
  the kernel line `legacy console [hvc0] enabled`. Symptom: a wedged boot
  shows nothing under either target -> confirm the run is HV (`guest_serial`
  is HV-only) and that `RUST_LOG` isn't set — it *replaces* the default
  filter rather than adding to it, so a stray `RUST_LOG` silently drops both
  guest targets.

- **>8-vCPU guest boot wedge / PID 1 in D-state.** First: capture the live
  snapshot (`Vmm::debug_snapshot` / `SystemService.GetVirtioDebug`:
  per-queue kicks, live avail/used indices, per-vCPU exit counters) *while
  the VM is alive*; then bisect `ARCBOX_HV_E2E_VCPUS`. Likely cause: virtio
  MMIO per-queue register file too small — virtio-blk configures one queue
  per vCPU, so a register file smaller than the queue count silently drops
  queue config (ABX-386, `MAX_VIRTQUEUES`; see `arcbox-vmm/AGENTS.md`).
  Already fixed by raising `MAX_VIRTQUEUES` to 64: the old limit wedged at
  exactly 8 vCPUs, but that is the *historical* signature, not a live
  threshold — an 8-vCPU boot no longer wedges, so don't expect a bisect to
  break at 8 unless the register file has regressed below the queue count.
- **Guest TLS/cert validation fails immediately after boot.** Not a net or
  DNS bug — HV exposes no RTC, so the guest sits at the kernel default epoch
  until the post-readiness agent ping sets `clock_settime`
  (`AgentPingRequest.timestamp_secs`; ABX-416, PL031 RTC pending). Do not chase
  it in the DNS/net stack.
- **Queue stall that appears only under an EVENT_IDX guest.** Suspect a
  dropped `enable_notification` re-arm in a worker drain loop, or a
  weakened `should_notify` SeqCst fence. Diff against the "One SplitQueue"
  rules above.
- **Daemon SIGSEGV at shutdown after an otherwise successful run.**
  Known-benign teardown crash (ABX-415), not a boot/queue regression you
  introduced. Do not open a false-alarm investigation on the queue path.

To localize any config-dependent failure, bisect the `hv_e2e` probe one
dimension at a time from the minimal probe toward the daemon shape
(`ARCBOX_HV_E2E_VCPUS` / `_MEMORY_MB` / `_BALLOON` / `_NETWORKING` /
`_DATA_IMG_MB` / `_EXTRA_SHARES` / `_BRIDGE` / `_BOOT_ONLY` / `_LOGLEVEL`;
full list in the `tests/e2e/src/bin/hv_e2e.rs` header). This is how ABX-386
was localized to "vCPU count, threshold exactly 8".

## Validation ladder (cheapest first)

1. crate unit tests for the touched crate;
2. bare probe: `cargo test -p arcbox-e2e --test hv_vmm -- --ignored`;
3. daemon level: `cargo test -p arcbox-e2e --test virtio_debug -- --ignored`
   and `--test boot_assets -- --ignored` with `ARCBOX_VM_BACKEND=hv`;
4. race-class fixes: `cargo xtask e2e --repeat N`.

The e2e targets are `#[ignore]`d: without `-- --ignored` the run reports
"0 tests run" and validates nothing (`cargo xtask e2e` passes it for you).

R2/R3 acceptance in Linear is read from the cumulative broadcast counters
(per-boot ≈ 2301 unpark-broadcasts / 71 kick-broadcasts). A refactor must
keep those counter sites honest (see `arcbox-vmm/AGENTS.md` "Diagnostic
Counters") or it falsifies the metrics.

## Pointers (reference material, not duplicated here)

- `virt/arcbox-vz/AGENTS.md` — the VZ backend's Swift shim (ArcBoxVZShim):
  the C ABI boundary contract (normative symbol order, link-time drift
  detection, handle and callback conventions), queue-affinity design, and
  build.rs landmines. VZ has no Rust-side ObjC interop anymore; fix VZ bugs
  there.

- `docs/fs-perf-limits.md` — the settled VirtioFS story: the per-op
  cross-vCPU IPI mechanism, the kernel `fuse-spin-wait` fix (+58%
  metadata_stat), everything ruled out en route (dax was never active on
  VZ; idle=poll, sched features, kernel version all measured), and the
  measurement discipline (same-context/same-day pairing; only the
  in-process trio is ratio-safe). Read this before any "make file I/O
  faster" work. VZ runs Apple's virtio-fs device — the custom VirtioFS
  is HV-only and still unmeasured.
- `docs/net-perf-limits.md` — the settled multi-flow Host→VM ceiling
  (~10–12 Gbps combined vs ~22–29 Gbps single-flow) and its root cause
  (per-IRQ host-side cost: `hv_vcpus_exit` / `hv_gic_set_spi` /
  `pthread_cond_signal`), with multi-queue / more-CPU / ring-size
  explicitly ruled out by profiling. Read this before any "make net faster"
  work. NOTE: the doc's recommended next step (EVENT_IDX IRQ suppression)
  has since shipped in `arcbox-net-inject` (`write_avail_event_current` in
  `flush_interrupt`), so its "unconditionally fire" claim is stale.
- `docs/virtio-queue-convergence.md` — historical rationale for the
  SplitQueue unification only. Its `Status: Planned` and the target
  `VirtioDevice` trait it describes (dropping `memory: &mut [u8]`) no longer
  match the shipped code; treat it as history.
