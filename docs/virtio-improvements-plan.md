# VirtIO Improvements — implementation plan

Derived from auditing the current device tree against several mature reference VMMs. Each item below states the gap, the *why* behind the design choice, and the locked fix.

## Phase structure

Phases ordered by risk × effort. Each phase is one PR-sized chunk; each commit inside a phase is atomic (builds + clippy + tests).

---

## Phase 1 — Correctness & security hotfixes

Small, localised commits landing now.

### ✅ Commit 1 — `arcbox-virtio-rng`: fail loudly on entropy failure *(landed: c308159)*

**Why the old behaviour was wrong.** On `getrandom` error the device silently zero-filled the buffer and reported the full length back as valid entropy. A guest kernel has no way to distinguish random bytes from zeroes, so it seeded its CSPRNG with a known-value and downstream TLS/SSH keys were compromised without any signal.

**Locked fix.** Log at warn, break out of the descriptor chain. The used ring carries whatever bytes we actually filled with real entropy; the guest sees a short read and re-requests. `getrandom` is effectively infallible on supported platforms, so the error path is primarily a safety net, not a hot path.

### ✅ Commit 2 — `arcbox-virtio-vsock`: tighten credit-update threshold *(landed: c4a1d1e)*

**Why the old threshold was wrong.** `advance_fwd_cnt` only sent `CREDIT_UPDATE` after 48 KB (3/4 of the 64 KB TX buffer) was drained since the last update. Any guest-side burst between 4 KB and 48 KB exhausts the peer's view of our free buffer before we send them the refresh — TX stalls waiting for a packet we're not sending.

**Locked fix.** Threshold → 4 KB (one page). Granular enough to prevent stall on common burst sizes, coarse enough to avoid spamming credit-only packets. Two tests cover the ≥threshold (enqueue) and <threshold (don't enqueue) cases.

### ✅ Commit 3 — `arcbox-virtio-core`: cap descriptor-chain iteration *(landed: 09a9c89)*

**Why the old behaviour was wrong.** `DescriptorChain::next()` followed `desc.next` unboundedly. A malicious (or buggy) guest can publish a descriptor whose `next` field forms a cycle; iterating the chain spins the host thread forever on every queue kick. This is a one-line denial-of-service from any unprivileged guest code that can write to the descriptor table.

**Locked fix.** Add `ttl: u16` to `DescriptorChain`, initialised to `queue.size` in `pop_avail`. Every legitimate chain has at most `queue.size` descriptors (one per descriptor-table slot), so that's the tightest safe upper bound. Iterator returns `None` once ttl hits zero; caller gets a truncated chain and the guest's malformed request simply fails closed. `queue_guest.rs` already has the equivalent inline cap in `pop_avail` (the `count >= self.size` check).

### Out of scope for Phase 1

- `CREDIT_REQUEST` send path → Phase 2
- Half-close / real state machine → Phase 2
- Everything below

---

## Phase 2 — vsock correctness

### ✅ 2.1 CREDIT_REQUEST emission *(landed: a2f3402)*

**Why it mattered.** When we want to inject an RW packet but our view of peer `fwd_cnt` is stale, we may believe we have no credit even though the peer has freed buffer. Without a way to ask the peer "what's your current fwd_cnt?", we'd deadlock waiting for a credit update that wouldn't arrive.

**What shipped.**
- `RxOps::CREDIT_REQUEST = 0x20` (after RESET in priority order).
- `VsockConnection::credit_request_pending` flag prevents duplicate requests while one is in flight; cleared on `update_peer_credit`.
- `conn.maybe_request_credit()` called from the RW-send path enqueues `CREDIT_REQUEST` when `peer_avail_credit < peer_buf_alloc / 2` and no request is outstanding.
- The existing zero-credit fallback now also marks the flag via `note_credit_request_sent` so the two paths don't spam duplicate requests.
- Four unit tests cover below-half fires, above-half noop, dedup, and pending-clears-on-peer-response.

### ✅ 2.2 Half-close SHUTDOWN handling *(landed: a52b896)*

**Why it mattered.** `OP_SHUTDOWN` and `OP_RST` shared a match arm that called `remove_connection` regardless of the shutdown flags. A guest doing `shutdown(fd, SHUT_WR)` (half-close on its send side) destroyed the whole connection even though the guest's RX was still active — common TCP-style half-close was broken.

**What shipped.**
- `VSOCK_SHUTDOWN_F_RECEIVE` / `VSOCK_SHUTDOWN_F_SEND` / `VSOCK_SHUTDOWN_F_BOTH` constants.
- New `VsockHostConnections::handle_shutdown(gp, hp, flags)` trait method with a default impl that mirrors `remove_connection` so third-party implementors stay source-compatible.
- `VsockConnectionManager` dispatches on flags: both-bits → teardown; F_RECEIVE only → `conn.mark_peer_no_recv()`; F_SEND only → informational no-op; flags=0 → conservative teardown.
- `VsockConnection::peer_no_recv()` / `accepts_data()` accessors; RX path skips RW for half-closed connections but keeps the fd open so the peer's own sends continue to drain.
- Four unit tests cover F_BOTH, F_RECEIVE, F_SEND, and flags=0.

**Still deferred (not done).** Full `ConnState` enum (`LocalInit` / `Established` / `PeerClosed{no_send, no_recv}` / `Killed`), per-connection expiry, and `PeerInit` peer-originated connections. The `connect: bool` + `peer_no_recv: bool` pair covers the current correctness gap; a richer enum can come when peer-initiated listens land.

---

## Phase 3 — net correctness & perf

### ✅ 3.1 MRG_RXBUF multi-chain RX delivery *(landed: 17a90dd)*

**Why it mattered.** `VIRTIO_NET_F_MRG_RXBUF` was advertised but the RX path only ever wrote into one descriptor chain and never stamped `num_buffers`. Guests that negotiate the feature pre-post small buffers expecting the device to concatenate — frames larger than a single buffer silently truncated.

**What shipped.** `inject_rx_batch` now pops chains until accumulated write-only capacity covers the full frame, stamps the chain count into bytes 10..12 of the first chain's `virtio_net_hdr`, and writes payload across chains with each used-ring entry reporting the correct per-buffer length. Non-MRG_RXBUF guests still get exactly one chain. Two unit tests cover the spanning and single-chain cases.

### ✅ 3.2 TAP offload configuration *(landed: 3c7c73a)*

**Why it mattered.** We advertised `CSUM` / `GUEST_CSUM` / `GUEST_TSO4/6` / `GUEST_UFO` but never called `TUNSETOFFLOAD` on the TAP fd. The Linux kernel TUN driver dropped or mangled partial-checksum and TSO frames that the guest emitted based on our advertisement.

**What shipped.** `NetOffloadFlags` struct + `configure_offload` / `set_vnet_hdr_sz` methods on `NetBackend` trait (default no-op). TAP backend translates `NetOffloadFlags` into `TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_TSO_ECN | TUN_F_UFO` and sets `TUNSETVNETHDRSZ = 12`. `VirtioNet::activate` reads `acked_features` and drives both calls.

### ✅ 3.3 RX scratch buffer reuse *(landed: 18d0b92)*

**Why it mattered.** `poll_backend_batch` allocated a fresh `vec![0u8; 65536]` per packet. At sustained rates the allocator dominated CPU even though typical frames are ≤1500 bytes.

**What shipped.** Persistent `rx_scratch: Box<[u8]>` on `VirtioNet`, allocated once in `new()` and reused on every `poll_backend_batch` call. Existing 62 tests still pass unchanged.

**What's explicitly *not* shipped (intentional deferral).** True `readv`-direct-to-guest zero-copy via a `recv_iovec` trait method. The hot path for production RX on the custom VMM is the dedicated net-io worker at `virt/arcbox-vmm/src/net_rx_worker.rs`, which already uses a stack scratch buffer (no heap) and writes directly into guest memory via `GuestMemWriter::slice_mut`. The `poll_backend_batch` path is used by tests, the VZ backend, and the `rx_buffer` staging model; those don't justify the trait-level API restructure today. Revisit when a production caller wants the readv path — at which point the locked design (extend `NetBackend` with a default-copy `recv_iovec`, TAP-override with `readv`, call from `inject_rx_batch`) still applies.

---

## Phase 4 — fs DAX (mandatory for >90% native target)

**Why it matters.** The in-process FUSE architecture wins on metadata ops by eliminating IPC round-trips (every FUSE_STAT saves a Unix-socket hop vs. a vhost-user daemon). But for large sequential reads, the win evaporates without DAX: we're still copying the file contents through the virtqueue, which is the same cost as vhost-user without DAX would pay. With DAX, the file's page cache is directly mapped into guest GPA and the guest reads with zero kernel involvement — that's the "90% native" path.

### ✅ 4.1 Core DAX plumbing *(landed before this plan, verified during Phase 5 audit)*

**What's already shipped.** On audit, Phase 4's correctness wiring is already in the tree from earlier work. Inventory of what exists today:

- `HvDaxMapper` at `virt/arcbox-vmm/src/dax.rs:36` — `libc::mmap` of host files, `hv_vm_map` / `hv_vm_unmap` into guest IPA. Implements `arcbox_fs::DaxMapper`.
- `DaxMapper` trait at `virt/arcbox-fs/src/lib.rs:56` — `setup_mapping` / `remove_mapping` with the exact signatures needed by the FUSE dispatcher.
- `FuseOpcode::SetupMapping` / `RemoveMapping` at `virt/arcbox-fs/src/fuse.rs:91` with full request structs (`FuseSetupMappingIn`, `FuseRemoveMappingIn`, `FuseRemoveMappingOne`) and flag constants (`FUSE_SETUPMAPPING_FLAG_READ/WRITE`).
- `FuseDispatcher::handle_setup_mapping` / `handle_remove_mapping` at `virt/arcbox-fs/src/dispatcher.rs:810,847` — look up the host fd from the FUSE file handle, dispatch to the mapper, translate errno. Returns `ENOSYS` when no mapper is wired (graceful degradation).
- INIT-time negotiation at `dispatcher.rs:334`: when `FUSE_MAP_ALIGNMENT` is offered by the guest and a mapper is available, we set the flag + `map_alignment=12` (4 KiB pages).
- MMIO transport SHM region registers at `virt/arcbox-vmm/src/device/mmio_state.rs:174-199`: `SHMSel` (0x0ac) + `SHMLen{Low,High}` (0x0b0/0x0b4) + `SHMBase{Low,High}` (0x0b8/0x0bc) per the VirtIO 1.2 MMIO layout — the guest discovers the DAX window by writing the region index to SHMSel and reading back base/len.
- Per-share DAX window allocation + IPA registration at `virt/arcbox-vmm/src/vmm/darwin_hv/mod.rs:538-592`: each VirtioFS share gets its own non-overlapping DAX slice (`DAX_WINDOW_PER_SHARE`, default 128 MiB) published via `state.shm_regions.push(...)`.

**Why the design deviates from the plan.** The original plan envisaged `fn shm_regions() -> &[SharedMemoryRegion]` on the `VirtioDevice` trait. The actual implementation stores the regions directly on `VirtioMmioState` during registration — simpler, same externally observable behavior, no trait extension needed. A trait method would have been useful if multiple devices wanted to report SHM regions, but only virtio-fs does, and the MMIO-state approach keeps the regions and the registers they're exposed through in the same module.

### Still deferred

- **End-to-end DAX test.** The plumbing is wired but unverified at the integration level. No test covers the full path: guest `mmap()` → `FUSE_SETUPMAPPING` → `hv_vm_map` → guest page fault → host file read. Verifying requires a Linux guest image with a virtiofs driver that negotiates `FUSE_MAP_ALIGNMENT` and an `arcbox-e2e-test` script that measures read throughput with/without DAX.
- **FUSE response buffer pool.** The per-request `Vec<u8>` allocation for FUSE responses is still live. Measurable only under sustained metadata-op pressure (directory walks across millions of inodes); not on the critical path for bulk I/O.
- **`MAX_DAX_WINDOW` tuning + config.** The 128 MiB per-share cap is a hardcoded constant. For workloads that mmap many multi-hundred-MB container layers, the window needs to be sized larger (1 GiB per the original plan) or dynamically re-mapped under pressure. Today the dispatcher's SETUPMAPPING calls will `ENOMEM` once the window fills.

---

## Phase 5 — blk async backend

### ✅ 5.1 DISCARD + WRITE_ZEROES + dead-backend cleanup *(landed: 12aeb58)*

**Why it mattered.** Container image layer teardown, `fstrim`, and freshly-sparse-file init all round-trip through virtio-blk's DISCARD / WRITE_ZEROES opcodes. The device returned `BlockStatus::Unsupp` for both, so the guest kernel saw the feature bits as absent and fell back to the slow path (explicit zero-filled writes for WRITE_ZEROES; silent no-ops for DISCARD that bypassed the spec's ability to let the device reclaim sparse storage). Alongside this, `AsyncFileBackend` was `#[allow(dead_code)]` because it reopened the backing file on every call — it had to go.

**What shipped.**
- Deleted `AsyncFileBackend` (`async_file.rs`) — structurally broken, unused.
- Advertised `VIRTIO_BLK_F_DISCARD` + `VIRTIO_BLK_F_WRITE_ZEROES` from `VirtioBlock::new`.
- Extended the config space (offsets 36..=59) with `max_discard_sectors`, `max_discard_seg=1`, `discard_sector_alignment=1`, `max_write_zeroes_sectors`, `max_write_zeroes_seg=1`, `write_zeroes_may_unmap=0`. Caps: DISCARD 32768 sectors (16 MiB), WRITE_ZEROES 2048 sectors (1 MiB).
- `handle_discard_list` — parses the range list, validates each against `MAX_DISCARD_SECTORS`, returns Ok without touching the backing file. Spec-compliant: DISCARD is advisory, the device "MAY" reclaim storage or ignore. Real `fallocate(PUNCH_HOLE)` / `F_PUNCHHOLE` can slot in later without a wire change.
- `handle_write_zeroes_list` — parses the range list, bounded `pwrite` of a zero buffer per range. Ignores the UNMAP flag since we advertise `write_zeroes_may_unmap=0`.
- `process_descriptor_chain` routes both opcodes through a read-only-descriptor concatenator (guests are free to split the range list across chained descriptors) + dispatches to the new handlers. Also fixed GET_ID, which was returning `Unsupp` via the fall-through.
- Nine unit tests: features advertised, config-space fields readable, range-list parsing round-trip + malformed rejection, DISCARD accepts valid / rejects oversize, WRITE_ZEROES actually zeros / rejects oversize / rejects read-only.

### Still deferred

**Why not swap to async.** The synchronous `libc::pread`/`pwrite` hot path still blocks the vCPU thread. The async migration is a separate effort because: (a) the `AsyncBlockBackend` trait is unimplemented — picking io_uring on Linux + dispatch_io on macOS is itself design work; (b) without the core foundation from Phase 7 (real `EventFd` / irqfd and a queue abstraction that devices own end-to-end), an async backend can't signal completions efficiently anyway. The inline pread/pwrite path is correct; it's not the bottleneck for typical container workloads at current scale. Revisit alongside Phase 7.

- Async backend (`AsyncBlockBackend` wired, io_uring on Linux, mmap/dispatch on macOS) — deferred to post-Phase 7.
- `VIRTIO_BLK_F_TOPOLOGY` — requires querying the underlying storage's physical block size, which isn't trivially portable. Skipped; config space currently reports topology=0 (unused).
- Real `fallocate(PUNCH_HOLE)` for DISCARD — no user-visible difference today; add when sparse-file reclamation becomes measurable.

---

## Phase 6 — macOS `vmnet.framework` backend

**Why it matters.** A UDP-tunnel or userspace-NAT primary NIC plateaus well below line rate on Apple Silicon. `vmnet.framework` provides a kernel-level shared-memory ring (plus NAT/DHCP/DNS in-kernel), which is the only viable path to ≥10 Gbps on macOS. The `com.apple.vm.networking` entitlement is already in the binary.

### ✅ 6.1 vmnet bridge NIC *(landed before this plan, verified during audit)*

**What's already shipped.** The vmnet layer is substantially built:

- FFI at `virt/arcbox-net/src/darwin/vmnet_ffi.rs` (556 lines): `vmnet_start_interface`, `vmnet_read`, `vmnet_write`, `vmnet_stop_interface`, event-callback setup, XPC dict helpers, full `VmnetCompletionBlock` ObjC layout.
- High-level wrapper at `virt/arcbox-net/src/darwin/vmnet.rs` (848 lines): `Vmnet` + `VmnetConfig` with Shared / HostOnly / Bridged modes, DHCP range config, subnet mask, MTU/MAC/max_packet_size from the interface-start XPC reply.
- `VmnetRelay` at `virt/arcbox-net/src/darwin/vmnet_relay.rs` (172 lines): bridges the blocking vmnet read/write API with an async socketpair. vmnet→guest runs on a blocking thread; guest→vmnet runs async via `AsyncFd`. Shared by the VZ and HV bridge NIC paths.
- Bridge NIC wiring in HV at `virt/arcbox-vmm/src/vmm/darwin_hv/mod.rs:661-670` (gated on `#[cfg(feature = "vmnet")]`) plumbs the relay through `set_bridge_host_fd`.

### Still deferred

- **Primary NIC on vmnet.** HV path's primary NIC today is `NetworkDatapath` (smoltcp NAT + in-process DHCP/DNS + socket proxy at `arcbox-net/src/darwin/datapath_loop.rs`). Swapping to vmnet is a **policy** change: vmnet's kernel NAT means users lose fine-grained control over the guest's routing, port-forwarding has to go through `vmnet`'s built-in rules instead of arcbox's, and the entitlement is required at install time. The vmnet code itself is ready. What's missing is a CLI flag (e.g. `--net=vmnet` vs `--net=userspace`) and the corresponding `create_hv_vmnet_primary_nic` function that mirrors the existing bridge wiring but targets the primary NIC device ID.
- **`NetBackend` trait adapter.** The current `Vmnet` type implements `arcbox-net::NetworkBackend`, not `arcbox-virtio-net::NetBackend`. This only matters if we want `VirtioNet::new(Box<dyn NetBackend>)` to accept vmnet directly (e.g. for tests or VZ path symmetry). The production HV path uses raw fd injection via `set_net_host_fd` and doesn't go through the trait.
### ✅ 6.2 Dead `SocketBackend` removal

**Why.** `virt/arcbox-virtio-net/src/socket.rs` had no call site outside its own unit tests. The original plan called for keeping it "behind a CLI flag for environments where the entitlement isn't granted", but the actual fallback for that scenario is `NetworkDatapath` (the current primary NIC backend), not a UDP-tunneled `NetBackend`.

**What shipped.** Deleted `socket.rs`, removed the `mod socket` / `pub use socket::SocketBackend` entries from `virt/arcbox-virtio-net/src/lib.rs`, updated the module-layout docstring.

---

## Phase 7 — core foundation

**Why the current code is limiting.** Two design choices from the initial custom-VMM work constrain everything downstream:

1. `GuestMemWriter` holds a single flat `*mut u8` + length. Memory hotplug, MMIO holes below 4 GiB, and ballooning all require discontiguous guest memory; none can be expressed.
2. IRQ injection is an `Arc<dyn Fn(u32)>` closure. No `EventFd`, so there's no path for KVM irqfd injection — every interrupt round-trips through the userspace event loop, bounding high-IOPS block and network devices' latency.

**Locked fix.**
- Adopt a multi-region `GuestMemoryMmap`-style abstraction (the ecosystem has a battle-tested crate; alternative: roll our own multi-region type keeping the same API shape as `GuestMemWriter::slice`).
- Replace both `queue.rs` and `queue_guest.rs` with a single `Queue` type that encapsulates configuration and memory access — devices stop choosing between host-sim and guest-mem paths.
- `EventFd`-based IRQ via a `VirtioInterrupt` trait, wiring to KVM irqfd on Linux and a userspace pipe (acceptable for now; optimise later) on macOS.

This phase is invasive and unlocks nothing on its own — it must follow Phases 3/4/5/6 so their perf work lands first, then they migrate onto the new foundation.

---

## Verification gates (every phase)

1. `cargo build -p <affected crate>` + downstream `cargo build -p arcbox-vmm`.
2. `cargo clippy --all-targets` zero new warnings. Known pre-existing: `len_without_is_empty` at `virt/arcbox-virtio-vsock/src/manager.rs:344`, deferred to Phase 7 cleanup.
3. `cargo test -p <affected crate>`.
4. `arcbox-e2e-test` skill run after Phases 3, 4, 5, 6.
5. Throughput regression check: `iperf3` ≥ 10 Gbps baseline after Phases 3 and 6.
