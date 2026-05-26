# HV Backend Architecture Plan

## Status: Draft (2026-04-07)

This document captures the architecture redesign for ArcBox's custom VMM using
Apple Hypervisor.framework (HV backend), informed by the rust-vmm ecosystem
evaluation and E2E testing findings.

---

## 1. Problem Statement

The current HV backend implementation was built "fill-in" style on top of the
existing VZ (Virtualization.framework) architecture. E2E testing revealed
fundamental issues:

1. **Kernel loading**: Hand-written loader doesn't handle PE/gzip compressed
   kernels or ARM64 Image header parsing (text_offset, flags). This was the
   direct cause of the InstructionAbort at boot.
2. **Memory layout**: `RAM_BASE_IPA=0` conflicted with GIC address space.
   Fixed to `0x40000000` but the layout is still fragile hard-coded constants.
3. **GIC API**: Xcode 26 SDK changed the GIC creation API from framework-chosen
   addresses to VMM-chosen addresses via config object. Fixed but revealed that
   the FFI layer needs to track SDK evolution.
4. **Boot state**: vCPU initial register state was incomplete (missing
   SCTLR_EL1, MPIDR_EL1, X1-X3=0).
5. **Device I/O**: All device implementations use raw pointer arithmetic for
   guest memory access — no bounds checking, easy to trigger UB.

These are not bugs to patch — they indicate the need for a proper VMM
architecture built on proven abstractions.

---

## 2. rust-vmm Ecosystem Evaluation

### 2.1 Core Blocker: `vmm-sys-util`

`vmm-sys-util` is the transitive dependency of many rust-vmm crates. Its
`eventfd` and `epoll` modules are **Linux-only**. This is the single biggest
obstacle for macOS adoption. Crates that hard-depend on these modules cannot
be used on macOS without patching.

### 2.2 Crate-by-Crate Verdict

#### Directly Usable on macOS (no patching needed)

| Crate | Version | Last Updated | What It Provides |
|-------|---------|-------------|-----------------|
| `vm-memory` | 0.18.0 | 2025-12 | GuestMemory trait, MmapRegion, GPA→HVA translation with bounds checking |
| `vm-allocator` | 0.1.3 | 2025-06 | MMIO/PIO address space allocation, IRQ allocation |
| `vm-fdt` | 0.3.0 | 2023-11 | FDT blob generation (ARM64 boot requirement) |
| `linux-loader` | 0.13.2 | 2025-11 | Linux kernel loading (ELF/PE/bzImage/ARM64 Image), cmdline, DTB placement |
| `virtio-queue` | 0.17.0 | 2025-11 | Virtqueue descriptor chain parsing, avail/used ring operations |
| `virtio-bindings` | 0.2.7 | 2026-01 | VirtIO constants and struct definitions from Linux headers |
| `virtio-device` | workspace | 2025-11 | VirtioDevice trait definition (git dependency required) |
| `vm-superio` | 0.8.1 | 2025-09 | UART 16550A, i8042, PL031 RTC — uses generic `Trigger` trait, no eventfd |
| `acpi_tables` | 0.2.1 | 2026-03 | ACPI table generation (FADT, MCFG, DSDT/AML) |

#### Not Usable on macOS

| Crate | Reason |
|-------|--------|
| `event-manager` | Hard dependency on Linux epoll via vmm-sys-util |
| `kvm-ioctls` / `kvm-bindings` | Linux KVM ioctl interface |
| `mshv-ioctls` | Microsoft Hyper-V specific |
| `vhost` (vhost-kern feature) | Requires Linux `/dev/vhost-*` |

#### Needs Adaptation

| Crate | Issue | Workaround |
|-------|-------|------------|
| `virtio-blk` | Not published to crates.io, in vm-virtio workspace | Git dependency, needs compile verification |
| `virtio-vsock` | Same as above | Git dependency |
| `vhost` (vhost-user feature) | vmm-sys-util eventfd dependency | Fork/patch or wait for upstream macOS support |
| `vm-device` | Stale (4+ years), concept useful but impl outdated | Reference API design, implement own version |

#### Does Not Exist (Must Implement)

| Component | Notes |
|-----------|-------|
| virtio-net device | No standalone crate in rust-vmm. cloud-hypervisor and libkrun implement internally |
| VirtioFS (FUSE) | No rust-vmm crate. We have `arcbox-fs` (2K+ LOC passthrough + FUSE) |
| macOS network backend | vmnet.framework bindings, socket proxy. We have `arcbox-net` |
| ARM timer handling | HV.framework vtimer trap + interrupt injection |

### 2.3 HV.framework Rust Bindings

| Crate | Version | Status | Verdict |
|-------|---------|--------|---------|
| `applevisor` | 1.0.0 (2026-01) | Active, most complete ARM64 API coverage | Recommended if starting fresh |
| `hv`/`hv-sys` | 0.1.2 (2022-01) | Stale 4 years, missing GIC/macOS 13+ APIs | Not recommended |
| `ahv` | 0.3.0 (2023-07) | Archived | Not usable |
| `arcbox-hv` (ours) | 0.3.20 | Active, updated for Xcode 26 GIC API | Keep — already tailored to our needs |

**Decision**: Keep `arcbox-hv`. It's already updated for Xcode 26 SDK and
tailored to our exit handling. Reference `applevisor` for missing system
register constants (MPIDR_EL1, etc.) and API coverage gaps.

### 2.4 Reference: Existing macOS Rust VMMs

| Project | Status | rust-vmm Usage on macOS |
|---------|--------|------------------------|
| **libkrun** (Docker VMM backend) | Production | Almost none — own HV.framework bindings, own device model |
| **cloud-hypervisor** | Linux-only | N/A (no macOS support) |
| **crosvm** | Linux/ChromeOS only | N/A |
| **Firecracker** | Linux KVM only | N/A |

Key insight: libkrun, the only production Rust VMM on macOS, chose to implement
most components from scratch rather than adapting rust-vmm crates. This validates
our hybrid approach — use rust-vmm where it works, keep our own code where it doesn't.

---

## 3. What Hypervisor.framework Gives You vs What You Must Build

### HV.framework provides (3 things):
1. Virtual CPU creation + run loop (`hv_vcpu_create`, `hv_vcpu_run`)
2. Guest physical memory mapping (`hv_vm_map`)
3. VM exit capture mechanism (exit info struct after each `hv_vcpu_run`)
4. GICv3 hardware-accelerated emulation (macOS 15+, `hv_gic_*` APIs)

### Everything else is our responsibility:

```
┌──────────────────────────────────────────────────────────┐
│                    Must Implement                         │
├──────────────────────────────────────────────────────────┤
│ vCPU Management    │ Run loop, exit dispatch, multi-core │
│                    │ sync, PSCI (CPU_ON/OFF/RESET)       │
├────────────────────┼─────────────────────────────────────┤
│ Memory Layout      │ GPA map design, DMA translation,    │
│                    │ MMIO vs RAM routing                  │
├────────────────────┼─────────────────────────────────────┤
│ Boot Protocol      │ Kernel loading (PE/Image/gzip),     │
│                    │ initrd placement, FDT construction,  │
│                    │ initial CPU register state           │
├────────────────────┼─────────────────────────────────────┤
│ Interrupt Mgmt     │ GIC configuration (GICD/GICR bases),│
│                    │ SPI injection, interrupt windows,    │
│                    │ IRQ-to-device routing                │
├────────────────────┼─────────────────────────────────────┤
│ Platform Devices   │ UART (serial console), timers,      │
│                    │ RTC, entropy source                  │
├────────────────────┼─────────────────────────────────────┤
│ VirtIO Stack       │ MMIO transport, virtqueue processing,│
│                    │ device feature negotiation           │
├────────────────────┼─────────────────────────────────────┤
│ Storage            │ virtio-blk backend (disk I/O)       │
├────────────────────┼─────────────────────────────────────┤
│ Network            │ virtio-net + host backend (socket    │
│                    │ proxy / vmnet.framework)             │
├────────────────────┼─────────────────────────────────────┤
│ Filesystem         │ VirtioFS + FUSE protocol + arcbox-fs │
├────────────────────┼─────────────────────────────────────┤
│ Host-Guest IPC     │ virtio-vsock for agent RPC           │
├────────────────────┼─────────────────────────────────────┤
│ Power Management   │ PSCI SYSTEM_OFF/SYSTEM_RESET        │
│                    │ (no ACPI needed for ARM64 Linux)     │
└────────────────────┴─────────────────────────────────────┘
```

---

## 4. Proposed Architecture

### 4.1 Crate Dependency Graph

```
┌─────────────────────────────────────────────────────────────┐
│                     arcbox-vmm (orchestrator)                │
│  VmmConfig → initialize → start → run loop → stop           │
├──────────────┬──────────────┬────────────────┬──────────────┤
│              │              │                │              │
│  arcbox-hv   │  Device Bus  │  Boot Loader   │  FDT Builder │
│  (HV.fwk     │  (MMIO       │  (linux-loader │  (vm-fdt)    │
│   bindings)  │   dispatch)  │   crate)       │              │
│              │              │                │              │
├──────────────┤              │                │              │
│  GIC config  │              │                │              │
│  (hv_gic_*)  │              │                │              │
├──────────────┴──────────────┴────────────────┴──────────────┤
│                                                              │
│              ┌─────────────────────────┐                     │
│              │     vm-memory           │                     │
│              │  (GuestMemoryMmap)      │                     │
│              └─────────┬───────────────┘                     │
│                        │                                     │
│    ┌───────────┬───────┼───────┬───────────┬──────────┐     │
│    │           │       │       │           │          │     │
│  virtio-blk  v-net  v-console v-vsock   v-fs      v-rng   │
│  (arcbox-    (arcbox-(arcbox-  (arcbox-  (arcbox-  (arcbox-│
│   virtio)    virtio) virtio)   virtio)    fs)      virtio) │
│    │           │       │       │           │          │     │
│    └───────────┴───────┴───────┴───────────┴──────────┘     │
│                        │                                     │
│              ┌─────────┴───────────────┐                     │
│              │   virtio-queue          │                     │
│              │   (rust-vmm crate)      │                     │
│              │   OR arcbox queue_guest  │                     │
│              └─────────────────────────┘                     │
│                                                              │
│  ┌────────────┐  ┌─────────────┐  ┌──────────────────┐     │
│  │ vm-superio │  │ vm-allocator│  │ virtio-bindings  │     │
│  │ (UART,RTC) │  │ (MMIO/IRQ) │  │ (constants)      │     │
│  └────────────┘  └─────────────┘  └──────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 GPA (Guest Physical Address) Memory Layout

Standard ARM64 VM layout. All addresses are GPA (IPA in Apple terminology).

```
0x0000_0000 ─ 0x07FF_FFFF   Reserved (128 MB)
0x0800_0000 ─ 0x080F_FFFF   GIC Distributor (GICD)    [64 KB]
0x080A_0000 ─ 0x0A09_FFFF   GIC Redistributor (GICR)  [32 MB]
              ← GICR region absorbs MMIO in 0x0900_0000..0x0A0A_0000
0x0B00_0000 ─ 0x0B00_0FFF   PL011 UART (serial)       [4 KB]
0x0C00_0000 ─ 0x0C00_FFFF   VirtIO MMIO devices       [32 slots x 4KB]
0x0C01_0000 ─ 0x3FFF_FFFF   Reserved for future MMIO
0x4000_0000 ─ END           Guest RAM                  [configurable]
```

Production boot uses kernel + rootfs.erofs (virtio-blk), no initramfs:
- Kernel: `RAM_BASE + text_offset` (from Image header via linux-loader)
- rootfs.erofs: virtio-blk /dev/vda (read-only)
- FDT: End of RAM, page-aligned backward

### 4.3 Boot Sequence

```
1. Allocate host memory for guest RAM
2. Create HvVm (40-bit IPA)
3. Map guest RAM at GPA 0x4000_0000
4. Create GIC with config (GICD=0x0800_0000, GICR=0x080A_0000)
5. Load kernel via linux-loader:
   a. Parse ARM64 Image header (text_offset, image_size, flags)
   b. Handle PE/gzip decompression if needed
   c. Load at RAM_BASE + text_offset
6. Load initrd into guest RAM (after kernel, page-aligned)
7. Generate FDT via vm-fdt:
   a. /memory node with RAM base and size
   b. /cpus with PSCI enable-method
   c. /intc GICv3 node with GICD/GICR addresses
   d. /timer with ARM arch timer interrupts
   e. /psci node
   f. /chosen with bootargs, stdout-path, initrd addresses
   g. /pl011 UART node
   h. /virtio_mmio nodes for each device
8. Write FDT into guest RAM
9. Register VirtIO devices with DeviceManager
10. Set up IRQ chip with GIC SPI callback
11. Create vCPU threads:
    a. Set initial register state:
       - PC = kernel_entry (GPA)
       - X0 = FDT address (GPA)
       - X1 = X2 = X3 = 0
       - CPSR = 0x3C5 (EL1h, DAIF masked)
       - SCTLR_EL1 = RES1 bits only (MMU off, caches off)
       - MPIDR_EL1 = vCPU affinity
    b. BSP starts immediately
    c. Secondary vCPUs park, await PSCI CPU_ON
12. Enter run loop
```

### 4.4 vCPU Run Loop

```
loop {
    hv_vcpu_run(vcpu)

    match exit_reason {
        DataAbort(mmio) => {
            if pl011.contains(mmio.addr) {
                pl011.handle(mmio)          // PL011 UART
            } else if device_bus.contains(mmio.addr) {
                device_bus.handle(mmio)     // VirtIO MMIO devices
            } else {
                log_unhandled(mmio)
            }
            advance_pc(+4)
        }

        WaitForInterrupt => {
            thread::park_timeout(1ms)       // IRQ callback calls unpark()
        }

        HypercallHvc | SmcCall => {
            handle_psci(func_id)            // VERSION, CPU_ON, CPU_OFF,
            advance_pc(+4)                  //   SYSTEM_OFF, SYSTEM_RESET
        }

        VtimerActivated => {
            vcpu.set_vtimer_mask(false)     // Let guest see timer interrupt
        }

        Canceled => break,                  // Forced exit from stop()
    }
}
```

### 4.5 Interrupt Flow

```
Device completes I/O (e.g., virtio-blk read done)
  │
  ▼
VirtioMmioState.trigger_interrupt(VIRTIO_MMIO_INT_VRING)
  │  Sets interrupt_status bit in MMIO register
  │
  ▼
IrqChip.trigger(device_irq, level=true)
  │
  ▼
GIC callback: hv_gic_set_spi(irq_number, true)
  │  Hardware GIC raises interrupt to guest vCPU
  │
  ▼
Unpark WFI-blocked vCPU threads
  │
  ▼
Guest kernel handles interrupt
  │  Reads InterruptStatus register (MMIO 0x060)
  │  Processes used ring entries
  │  Writes InterruptACK register (MMIO 0x064)
  │
  ▼
hv_gic_set_spi(irq_number, false)
  │  Clear interrupt line
```

---

## 5. Adoption Plan

### Phase 1: Unblock E2E Boot (Priority: Immediate)

**Goal**: Kernel boots to serial output using correct Image format handling.

**Changes**:

| Action | Details |
|--------|---------|
| Add `linux-loader` to `arcbox-vmm/Cargo.toml` | Version 0.13.2, features: `elf`, `pe`, `bzimage` |
| Add `vm-memory` to `arcbox-vmm/Cargo.toml` | Version 0.18.0 |
| Add `vm-fdt` to `arcbox-vmm/Cargo.toml` | Version 0.3.0 |
| Replace `load_kernel_into_ram()` | Use `linux_loader::loader::KernelLoader::load()` with `GuestMemoryMmap` |
| Replace `FdtBuilder` | Use `vm_fdt::FdtWriter` for FDT generation |
| Create `GuestMemoryMmap` wrapper | Implement `hv_vm_map()` on the same mmap'd region |
| Fix vCPU initial state | Set SCTLR_EL1 (MMU off), MPIDR_EL1, clear X1-X3 |
| Add MPIDR_EL1 to `arcbox-hv/ffi.rs` | System register constant |
| Handle compressed kernel | linux-loader handles PE decompression automatically |

**Verification**: `hv_boot_test` example shows kernel boot messages via PL011.

### Phase 2: Solidify Infrastructure

**Goal**: Type-safe memory abstractions, proper device models.

| Action | Details |
|--------|---------|
| Add `vm-superio` | Replace hand-written PL011 with full UART 16550A + PL031 RTC |
| Add `vm-allocator` | Replace manual MMIO/IRQ allocation in DeviceManager |
| Add `virtio-bindings` | Replace hand-written VirtIO constants |
| Wrap GuestMemoryMmap for device I/O | Devices use `GuestMemory::read/write` instead of raw pointers |
| Evaluate `virtio-queue` | Compare with our `queue_guest.rs` for correctness and performance |

**Verification**: All existing unit tests pass. DeviceManager uses vm-allocator.

### Phase 3: Complete Device Stack

**Goal**: Full boot to Docker.

| Action | Details |
|--------|---------|
| Wire virtio-blk with `GuestMemory` | Block device reads/writes through safe abstraction |
| Wire virtio-console | Serial output via virtqueue, not just PL011 |
| Wire virtio-vsock | Agent RPC connection |
| Wire virtio-net | Network via socket proxy (existing `arcbox-net`) |
| Wire virtio-fs | VirtioFS via `arcbox-fs` FUSE handler |
| Implement secondary vCPU spawn | PSCI CPU_ON via channel mechanism (already coded) |

**Verification**: `docker run hello-world` succeeds on HV backend.

### Phase 4: Production Readiness

**Goal**: Performance parity with OrbStack, default backend switch.

| Action | Details |
|--------|---------|
| VirtioFS tuning | Adaptive negative cache TTL, READDIRPLUS, batch interrupts |
| WFI optimization | kqueue-based blocking instead of park_timeout |
| Benchmark suite | Compare HV vs VZ vs native vs OrbStack |
| `VmBackend::Auto` defaults to HV | After 7-day validation period |

---

## 6. Crate Integration Decisions

### 6.1 What We Replace (use rust-vmm instead)

| Our Code | rust-vmm Replacement | Reason |
|----------|---------------------|--------|
| `arcbox-vmm/fdt.rs` (457 LOC) | `vm-fdt` | Battle-tested, supports memory reservation map |
| `load_kernel_into_ram()` (30 LOC) | `linux-loader` | Handles PE/gzip, Image header parsing, text_offset |
| `PL011` in darwin_hv.rs (80 LOC) | `vm-superio::Serial` | Complete UART with FIFO, interrupt generation |
| `MemoryManager` (315 LOC) | `vm-memory::GuestMemoryMmap` + `vm-allocator` | Type-safe GPA→HVA, bounds-checked access |
| Hand-written VirtIO constants | `virtio-bindings` | Authoritative source from Linux headers |

### 6.2 What We Keep (our implementation is better for our use case)

| Component | Lines | Reason to Keep |
|-----------|-------|---------------|
| `arcbox-hv` (HV.framework bindings) | 1.7K | Already updated for Xcode 26 SDK. Tailored exit handling |
| `arcbox-virtio/blk.rs` | 1.1K | Full process_descriptor_chain with pread/pwrite backend |
| `arcbox-virtio/console.rs` | 650 | PTY, socket, buffer backends already implemented |
| `arcbox-virtio/net.rs` | 760 | TSO feature negotiation, integrated with arcbox-net |
| `arcbox-virtio/vsock.rs` | 1.6K | Complete packet processing, HostVsockBackend |
| `arcbox-virtio/fs.rs` | 1.8K | Full FUSE handler integrated with arcbox-fs |
| `arcbox-virtio/queue_guest.rs` | 870 | Zero-copy GPA→HVA for hot path (evaluate against virtio-queue later) |
| `arcbox-fs` (VirtioFS) | 4K+ | Core competitive advantage — adaptive caching, READDIRPLUS |
| `arcbox-net` (network stack) | 5K+ | Socket proxy, DHCP, DNS — deeply integrated |
| `arcbox-vmm/irq.rs` | 1K | IRQ chip with coalescing, wired to GIC |
| `arcbox-vmm/device.rs` | 960 | MMIO transport + DeviceManager with QUEUE_NOTIFY processing |
| `arcbox-vmm/vcpu.rs` | 437 | VcpuManager for manual execution mode |
| `darwin_hv.rs` (VMM core) | 1.4K | Full HV lifecycle, PSCI, PL011, device registration |

### 6.3 What We Evaluate Later

| Component | Candidate | Decision Point |
|-----------|-----------|---------------|
| `arcbox-virtio/queue.rs` (891 LOC) | `virtio-queue` (rust-vmm) | After Phase 2, benchmark both |
| `VirtioDevice` trait | `virtio-device` (rust-vmm) | If trait is compatible, adopt for interop |
| Event loop | `mio` or `polling` crate | If tokio overhead is too high for vCPU path |

---

## 7. Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| `vm-memory` API mismatch with HV.framework | Medium | GuestMemoryMmap uses POSIX mmap; we call hv_vm_map on same allocation. Proven pattern (libkrun does this) |
| `linux-loader` doesn't handle our kernel format | High | Our production kernel is ARM64 Image (verified). linux-loader supports this. Test with both dev and production kernels |
| `vm-fdt` generates incompatible DTB | Medium | We control all DTB content. Verify with `dtc -I dtb` after generation |
| rust-vmm crate breaking changes | Low | Pin exact versions. These crates have stable APIs (vm-memory 0.18, etc.) |
| Performance regression from vm-memory abstraction | Low | GuestMemoryMmap is zero-cost for aligned accesses. Keep queue_guest.rs for hot path if needed |
| Xcode SDK changes break arcbox-hv again | Medium | Already happened once (Xcode 26 GIC API). Monitor Apple developer docs. Consider applevisor as backup |

---

## 8. File Change Map

### New Dependencies (Cargo.toml)

```toml
# virt/arcbox-vmm/Cargo.toml
[dependencies]
vm-memory = "0.18"
linux-loader = "0.13"
vm-fdt = "0.3"
vm-superio = "0.8"
vm-allocator = "0.1"
virtio-bindings = "0.2"
```

### Files to Modify

| File | Change |
|------|--------|
| `virt/arcbox-vmm/src/vmm/darwin_hv.rs` | Replace load_kernel_into_ram with linux-loader; replace FDT generation with vm-fdt; add SCTLR_EL1/MPIDR init; wrap GuestRam with GuestMemoryMmap |
| `virt/arcbox-vmm/src/fdt.rs` | Deprecate in favor of vm-fdt (keep for VZ path compatibility) |
| `virt/arcbox-vmm/src/memory.rs` | Bridge with vm-memory's GuestMemoryMmap |
| `virt/arcbox-vmm/src/device.rs` | Use GuestMemory trait for MMIO dispatch instead of raw pointers |
| `virt/arcbox-hv/src/ffi.rs` | Add MPIDR_EL1 system register constant |
| `virt/arcbox-hv/src/lib.rs` | Export MPIDR_EL1 in sys_reg module |

### Files Unchanged

All `arcbox-virtio/src/*.rs` device implementations, `arcbox-fs/src/*`,
`arcbox-net/src/*`, and the VZ backend path (`darwin.rs`) remain unchanged.
