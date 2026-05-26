# HV Backend Architecture

Custom VMM built on Apple Hypervisor.framework — manual vCPU execution, device
emulation, and interrupt management. Alternative to the Virtualization.framework
(VZ) managed path.

## Why HV Instead of VZ

VZ is a black box. It handles virtqueues, interrupt injection, and device state
internally. That convenience comes at the cost of control:

| Capability | VZ | HV |
|---|---|---|
| TCP Segmentation Offload | No | Custom virtio-net with TSO |
| VirtioFS cache policy | Framework-managed | Direct FUSE control, custom TTL |
| Vsock data path | fd returned after handshake | mmap guest memory, zero-copy |
| IRQ coalescing | Framework-managed | Custom batching |
| Guest memory access | Opaque | Direct mmap slice |

The entire point is full control over the I/O data path.

## Crate Map

```
arcbox-hv          Safe Hypervisor.framework bindings    1,705 LOC
arcbox-vmm         VMM orchestration + MMIO transport    ~3,300 LOC (darwin_hv + device)
arcbox-virtio      VirtIO device emulation               10,908 LOC
arcbox-fs          VirtioFS / FUSE passthrough            5,780 LOC
```

### arcbox-hv (1,705 LOC)

Thin safe wrapper over `<Hypervisor/hv.h>`.

| Module | Lines | Purpose |
|---|---|---|
| `ffi.rs` | 228 | Raw FFI declarations |
| `vm.rs` | 164 | `HvVm` — VM lifecycle, IPA memory mapping |
| `vcpu.rs` | 291 | `HvVcpu` (`!Send`) — register access, run loop |
| `exit.rs` | 580 | `VcpuExit` parsing — DataAbort, HVC, WFI, VTimer |
| `gic.rs` | 214 | `Gic` — GICv3 SPI injection (feature-gated, macOS 15+) |
| `error.rs` | 97 | `HvError` with framework error code mapping |
| `memory.rs` | 81 | `MemoryPermission` (RWX) for IPA mapping |

Key constraint: `HvVcpu` is `!Send` — each vCPU lives on a dedicated OS
thread. The framework enforces this.

### arcbox-vmm darwin_hv (1,750 LOC)

Three-phase lifecycle:

1. **`initialize_darwin_hv()`** — VM create, RAM map, GIC init, device
   registration, FDT generation, kernel load
2. **`start_darwin_hv()`** — Spawn vCPU threads (BSP immediate, secondaries
   parked on mpsc channels for PSCI CPU_ON)
3. **`stop_darwin_hv()`** — Signal threads, exit vCPUs, teardown in order
   (GIC → VM → guest memory)

### Device Manager + MMIO Transport (1,558 LOC)

`VirtioMmioState` holds the full VirtIO 1.1 MMIO register bank per device.
`DeviceManager` routes MMIO accesses to the correct device and builds
`QueueConfig` for `process_queue()` dispatch.

Guest memory is passed as a raw slice indexed by GPA:
```rust
let guest_mem = slice::from_raw_parts_mut(
    ram_base.sub(gpa_base),   // index 0 = GPA 0
    gpa_base + ram_size,
);
```

Devices read/write descriptors at `guest_mem[desc.addr]` — zero-copy, no
address translation syscalls.

## Guest Physical Address Layout

```
0x0800_0000   GIC Distributor (GICD)       64 KB
0x080A_0000   GIC Redistributor (GICR)     32 MB
0x0B00_0000   PL011 UART                   4 KB
0x0C00_0000   VirtIO MMIO region           32 × 512 B
0x4000_0000   Guest RAM                    Variable
```

RAM starts at 1 GB to stay clear of all MMIO / GIC regions.

## VirtIO Devices

All devices implement `VirtioDevice::process_queue()` for the HV guest-memory
path:

| Device | LOC | Queue handling |
|---|---|---|
| Block | 1,459 | Read/write/flush sectors via host fd |
| Network | 1,846 | TX/RX with GSO/TSO feature negotiation |
| Console | 1,329 | TX extraction → tracing log (guest_console target) |
| VirtioFS | 1,698 | FUSE request extraction → FsServer dispatch |
| Vsock | 2,259 | TX packet parsing + host fd forwarding; RX injection |

### VirtioFS Chain

```
Guest virtiofs driver
  → VirtIO MMIO QUEUE_NOTIFY
  → VirtioFs::process_queue()     (descriptor walk, FUSE packet extract)
  → FuseDispatcher::dispatch()    (opcode routing)
  → PassthroughFs                 (host filesystem syscalls)
```

`PassthroughFs` maps guest FUSE operations to host syscalls (openat, read,
write, getxattr, etc.) with inode-to-path tracking and negative-entry caching.

**errno translation**: macOS errno values differ from Linux. `FsError::to_errno()`
translates host errno to Linux errno before sending the FUSE response. Critical
example: macOS `ENOATTR` (93) → Linux `ENODATA` (61). Without this, `exec()`
on VirtioFS files fails with "Protocol not supported".

### Vsock Protocol

Connection handshake (host-initiated):

```
Host                          Guest
  │                             │
  │── OP_REQUEST (RX inject) ──→│  inject_vsock_rx_raw()
  │                             │  guest kernel virtio_transport_recv_pkt()
  │←── OP_RESPONSE (TX queue) ──│  handle_tx_packet_with_fds()
  │                             │
  │── OP_RW (RX inject) ──────→│  poll_vsock_rx() reads host fd
  │←── OP_RW (TX queue) ───────│  process_queue() writes to host fd
```

Port mapping:
- Guest agent listens on port 1024
- Host uses ephemeral port 50000 + guest_port
- `vsock_host_fds` keyed by guest port
- `vsock_connected_ports` tracks established connections

On OP_RST: close host fd (causes daemon's read to return EOF, triggering
retry). On INTERRUPT_ACK: deassert GIC SPI so subsequent `set_spi(true)`
produces a rising edge.

## Boot Protocol

ARM64 Linux boot convention:

1. Load kernel Image at `RAM_BASE` via `linux-loader` (PE format detection)
2. Place FDT at `RAM_BASE + ram_size - 4KB` (end of RAM, page-aligned)
3. Set vCPU registers:
   - `PC = kernel_entry`, `X0 = fdt_addr`, `X1-X3 = 0`
   - `CPSR = EL1h`, DAIF masked
   - `SCTLR_EL1 = RES1 bits | MMU off`
   - `MPIDR_EL1 = vcpu_id` (Aff0)
4. BSP runs immediately; secondaries park until PSCI CPU_ON

PSCI implementation: CPU_ON_64 delivers (entry_point, context_id) via mpsc
channel to the parked vCPU thread.

## Interrupt Flow

```
Device completion
  → VirtioMmioState::trigger_interrupt(INT_VRING)   // set interrupt_status
  → irq_callback(gsi, level=true)
    → Gic::set_spi(gsi, true)                       // hardware GIC injection
    → unpark all vCPU threads                        // wake from WFI

Guest IRQ handler
  → read InterruptStatus MMIO register
  → write InterruptACK MMIO register
    → interrupt_status &= !ack_bits
    → if interrupt_status == 0: irq_callback(gsi, level=false)  // deassert
```

Deassert on ACK is critical — without it, subsequent `set_spi(true)` calls
produce no rising edge, and the guest never sees the new interrupt.

## Threading Model

```
Main thread         init + shutdown + vsock connect
hv-vcpu-0 (BSP)    run loop + vsock polling (exclusive)
hv-vcpu-1..N        run loop only (parked until PSCI CPU_ON)
IRQ callback        called from any vCPU context; unparks all threads
```

Vsock host-fd polling runs only on BSP (vCPU 0) at the top of each run loop
iteration to avoid lock contention.

## Feature Flags

| Feature | Scope | Effect |
|---|---|---|
| `gic` | arcbox-hv → arcbox-vmm → arcbox-core → arcbox-daemon | Enables GICv3 hardware interrupt controller. **Required for HV boot.** |
| `vmnet` | arcbox-net → arcbox-vmm | Enables macOS vmnet bridge networking |

`gic` is in `arcbox-daemon`'s default features. Without it, the VMM falls back
to no-interrupt mode (kernel limps along on timer polling, VirtIO devices
non-functional).

## Known Limitations

- **Vsock polling on BSP only**: All host-fd reads happen on vCPU 0's run loop.
  High-throughput scenarios may need a dedicated I/O thread.
- **No DAX for VirtioFS**: All file I/O goes through FUSE read/write. Future
  optimization: shared memory mapping for large file access.
- **VirtioNet**: TSO features negotiated but host-side socket proxy not yet
  wired (DHCP/DNS pending).
- **No balloon**: VirtIO balloon device registered but inflation/deflation not
  implemented on HV path.
- **macOS errno translation**: Currently only translates ENOATTR→ENODATA. A
  comprehensive mapping may be needed for edge cases (e.g. EFTYPE, ENOPOLICY).
