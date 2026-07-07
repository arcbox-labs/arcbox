//! macOS custom VMM using Hypervisor.framework (manual execution).
//!
//! This is the **alternative** to the VZ framework managed-execution path in
//! `darwin.rs`. It uses `arcbox-hv` directly, giving us full control over
//! VirtIO device emulation — critically, the ability to negotiate TSO with
//! the guest and handle VirtIO-net headers in userspace.
//!
//! The design mirrors `linux.rs` (KVM manual execution):
//! - Guest RAM is allocated on the host and mapped into guest IPA.
//! - VirtIO devices are registered with `DeviceManager` and exposed via
//!   MMIO transport. The guest discovers them through the FDT.
//! - vCPU threads call `HvVcpu::run()` in a loop, dispatching MMIO traps
//!   to the device manager.
//! - GICv3 is provided by Hypervisor.framework's hardware emulation
//!   (macOS 15+); device interrupts are injected via `Gic::set_spi()`.

use std::sync::{Arc, Mutex};

use vm_memory::GuestMemoryMmap;

#[cfg(test)]
use crate::boot::arm64;
#[cfg(test)]
use crate::device::DeviceTreeEntry;
#[cfg(test)]
use crate::error::Result;
use crate::error::VmmError;

use super::*;

mod console;
#[cfg(test)]
mod guest_ram;
mod hvc_blk;
mod inline_sink;
mod lifecycle;
mod network;
pub(super) mod pl011;
mod psci;
mod setup;
mod vcpu_loop;
mod vsock;

pub(super) use pl011::Pl011;
#[cfg(test)]
use pl011::{PL011_BASE, PL011_DR, PL011_FR, PL011_SIZE};
pub use psci::CpuOnRequest;

/// Shared registry of vCPU thread handles for WFI unparking.
///
/// When a GIC interrupt is injected, the IRQ callback iterates this list
/// and calls `unpark()` on every thread so that WFI-parked vCPUs wake up.
pub(super) type VcpuThreadHandles = Arc<Mutex<Vec<std::thread::Thread>>>;

/// Shared registry of Hypervisor.framework vCPU IDs (opaque `hv_vcpu_t`
/// handles).
///
/// Used by `stop_darwin_hv` / `pause_darwin_hv` to target `hv_vcpus_exit`
/// correctly. On arm64, `hv_vcpus_exit(NULL, 0)` is a **no-op** — the
/// framework expects a concrete list of vCPU IDs. See ABX-367.
pub(super) type HvVcpuIds = Arc<Mutex<Vec<u64>>>;

/// Page size on ARM64.
#[cfg(test)]
const PAGE_SIZE: usize = 4096;

/// Base address for VirtIO MMIO device region.
/// Starts at 0x0C00_0000 to avoid the GIC redistributor region
/// (GICR ends at 0x080A_0000 + 32 MB = 0x0A0A_0000) and PL011 UART (0x0B00_0000).
const VIRTIO_MMIO_BASE: u64 = 0x0C00_0000;

/// Size of each VirtIO MMIO device region.
#[cfg(test)]
const VIRTIO_MMIO_SIZE: u64 = 0x200;

/// Maximum number of VirtIO MMIO devices.
const VIRTIO_MMIO_MAX_DEVICES: u64 = 32;

/// First SPI interrupt number for VirtIO devices (GIC SPI numbering).
#[cfg(test)]
const VIRTIO_IRQ_BASE: u32 = 48;

/// Guest RAM is mapped starting at IPA 0.
/// Guest RAM is mapped at 1 GiB to leave the lower address space for
/// GIC (0x0800_0000), PL011 (0x0B00_0000) and VirtIO MMIO (0x0C00_0000).
const RAM_BASE_IPA: u64 = 0x4000_0000;

/// GIC distributor base address.
const GIC_DIST_ADDR: u64 = 0x0800_0000;
/// GIC distributor region size (64 KB from hv_gic_get_distributor_size).
const GIC_DIST_SIZE: u64 = 0x1_0000;
/// GIC redistributor base address.
const GIC_REDIST_ADDR: u64 = 0x080A_0000;
/// GIC redistributor region size (32 MB, enough for max vCPUs).
const GIC_REDIST_SIZE: u64 = 0x200_0000;

/// Type alias for the guest memory backing used by the parent `Vmm` struct
/// (HV backend). Now backed by `vm-memory`'s mmap abstraction.
pub(super) type HvGuestMem = GuestMemoryMmap;

#[cfg(test)]
use guest_ram::GuestRam;

/// Device slot tracking for MMIO address and IRQ assignment.
/// Superseded by DeviceManager::register_virtio_device(); retained for tests.
#[cfg(test)]
struct DeviceSlot {
    /// MMIO base address in guest IPA.
    mmio_base: u64,
    /// MMIO region size.
    mmio_size: u64,
    /// Assigned SPI interrupt number.
    irq: u32,
    /// Device name for diagnostics.
    name: String,
}

#[cfg(test)]
fn build_device_tree_entries(slots: &[DeviceSlot]) -> Vec<DeviceTreeEntry> {
    slots
        .iter()
        .map(|s| DeviceTreeEntry {
            compatible: "virtio,mmio".to_string(),
            reg_base: s.mmio_base,
            reg_size: s.mmio_size,
            irq: s.irq,
        })
        .collect()
}

#[cfg(test)]
fn allocate_device_slot(index: u64, name: impl Into<String>) -> Result<DeviceSlot> {
    if index >= VIRTIO_MMIO_MAX_DEVICES {
        return Err(VmmError::Device("too many VirtIO MMIO devices".to_string()));
    }
    Ok(DeviceSlot {
        mmio_base: VIRTIO_MMIO_BASE + index * VIRTIO_MMIO_SIZE,
        mmio_size: VIRTIO_MMIO_SIZE,
        irq: VIRTIO_IRQ_BASE + index as u32,
        name: name.into(),
    })
}

/// Convert a `vm_fdt::Error` into our `VmmError`.
fn fdt_err(e: vm_fdt::Error) -> VmmError {
    VmmError::Memory(format!("FDT error: {e}"))
}

/// Builds a thread-safe closure that force-exits every registered vCPU out
/// of `hv_vcpu_run`, used by io-worker threads (net-rx, vsock-io) to wake a
/// guest that is idle in WFI for interrupt delivery.
///
/// On arm64 `hv_vcpus_exit` requires a concrete list of vCPU IDs; NULL/0 is
/// a silent no-op. The registry is snapshotted on each invocation so
/// late-arriving secondaries (PSCI CPU_ON) are picked up. Safe to call from
/// any thread. See ABX-367.
fn make_exit_vcpus_fn(
    ids: HvVcpuIds,
    broadcasts: Arc<std::sync::atomic::AtomicU64>,
) -> Arc<dyn Fn() + Send + Sync> {
    Arc::new(move || {
        let ids_snapshot: Vec<u64> = ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if ids_snapshot.is_empty() {
            return;
        }
        broadcasts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // SAFETY: `ids_snapshot` is a live Vec owned by this closure for
        // the duration of the FFI call; the pointer and length are
        // consistent.
        #[allow(clippy::cast_possible_truncation)]
        let ret = unsafe {
            arcbox_hv::ffi::hv_vcpus_exit(ids_snapshot.as_ptr(), ids_snapshot.len() as u32)
        };
        if let Err(e) = arcbox_hv::check(ret) {
            tracing::warn!("exit_vcpus: hv_vcpus_exit failed: {e}");
        }
    })
}

#[cfg(test)]
fn choose_fdt_addr_hv(memory_size: u64, fdt_size: usize) -> Result<u64> {
    let fdt_size = fdt_size as u64;
    let gib: u64 = 1024 * 1024 * 1024;
    let preferred = if memory_size >= gib {
        arm64::FDT_LOAD_ADDR
    } else {
        0x0800_0000
    };

    if fdt_size > memory_size {
        return Err(VmmError::Memory("FDT exceeds guest memory".into()));
    }
    if preferred + fdt_size > memory_size {
        return Err(VmmError::Memory("FDT does not fit at load address".into()));
    }

    Ok(preferred)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_device_slot() {
        let slot = allocate_device_slot(0, "test").unwrap();
        assert_eq!(slot.mmio_base, VIRTIO_MMIO_BASE);
        assert_eq!(slot.mmio_size, VIRTIO_MMIO_SIZE);
        assert_eq!(slot.irq, VIRTIO_IRQ_BASE);
        assert_eq!(slot.name, "test");
    }

    #[test]
    fn test_allocate_device_slot_second() {
        let slot = allocate_device_slot(1, "net").unwrap();
        assert_eq!(slot.mmio_base, VIRTIO_MMIO_BASE + VIRTIO_MMIO_SIZE);
        assert_eq!(slot.irq, VIRTIO_IRQ_BASE + 1);
    }

    #[test]
    fn test_allocate_device_slot_overflow() {
        let result = allocate_device_slot(VIRTIO_MMIO_MAX_DEVICES, "overflow");
        assert!(result.is_err());
    }

    #[test]
    fn test_build_device_tree_entries() {
        let slots = vec![
            DeviceSlot {
                mmio_base: 0x0900_0000,
                mmio_size: 0x200,
                irq: 48,
                name: "net".into(),
            },
            DeviceSlot {
                mmio_base: 0x0900_0200,
                mmio_size: 0x200,
                irq: 49,
                name: "blk".into(),
            },
        ];
        let entries = build_device_tree_entries(&slots);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].reg_base, 0x0900_0000);
        assert_eq!(entries[0].irq, 48);
        assert_eq!(entries[1].reg_base, 0x0900_0200);
        assert_eq!(entries[1].irq, 49);
    }

    #[test]
    fn test_choose_fdt_addr_large_ram() {
        let addr = choose_fdt_addr_hv(2 * 1024 * 1024 * 1024, 0x1000).unwrap();
        assert_eq!(addr, arm64::FDT_LOAD_ADDR);
    }

    #[test]
    fn test_choose_fdt_addr_small_ram() {
        let addr = choose_fdt_addr_hv(512 * 1024 * 1024, 0x1000).unwrap();
        assert_eq!(addr, 0x0800_0000);
    }

    #[test]
    fn test_choose_fdt_addr_too_big() {
        let result = choose_fdt_addr_hv(1024, 2048);
        assert!(result.is_err());
    }

    #[test]
    fn test_guest_ram_allocation() {
        let ram = GuestRam::new(4096).unwrap();
        assert!(!ram.as_ptr().is_null());
        assert_eq!(ram.size(), 4096);
    }

    #[test]
    fn test_guest_ram_write_read() {
        let mut ram = GuestRam::new(4096).unwrap();
        let slice = ram.as_mut_slice();
        slice[0] = 0xAB;
        slice[4095] = 0xCD;
        assert_eq!(slice[0], 0xAB);
        assert_eq!(slice[4095], 0xCD);
    }

    #[test]
    fn test_pl011_contains() {
        let uart = Pl011::new();
        assert!(uart.contains(PL011_BASE));
        assert!(uart.contains(PL011_BASE + PL011_DR));
        assert!(uart.contains(PL011_BASE + PL011_SIZE - 1));
        assert!(!uart.contains(PL011_BASE + PL011_SIZE));
        assert!(!uart.contains(VIRTIO_MMIO_BASE));
    }

    #[test]
    fn test_pl011_write_and_flush() {
        let mut uart = Pl011::new();
        // Write "Hi\n" byte by byte.
        uart.write(PL011_BASE + PL011_DR, 1, b'H' as u64);
        uart.write(PL011_BASE + PL011_DR, 1, b'i' as u64);
        assert_eq!(uart.output().len(), 2);
        // Newline flushes the buffer.
        uart.write(PL011_BASE + PL011_DR, 1, b'\n' as u64);
        assert!(uart.output().is_empty());
    }

    #[test]
    fn test_pl011_read_flags() {
        let uart = Pl011::new();
        // Idle flag register: RXFE (bit 4) and TXFE (bit 7) set, TXFF (bit 5)
        // clear — the line is empty and ready, with no phantom RX data.
        let fr = uart.read(PL011_BASE + PL011_FR, 4);
        assert_eq!(fr & (1 << 4), 1 << 4, "RXFE must be set");
        assert_eq!(fr & (1 << 7), 1 << 7, "TXFE must be set");
        assert_eq!(fr & (1 << 5), 0, "TXFF must be clear");
    }

    #[test]
    fn test_pl011_flush_partial() {
        let mut uart = Pl011::new();
        uart.write(PL011_BASE + PL011_DR, 1, b'X' as u64);
        assert_eq!(uart.output().len(), 1);
        uart.flush();
        assert!(uart.output().is_empty());
    }

    #[test]
    fn test_duplicate_client_vsock_fd_uses_high_fd_without_breaking_socketpair() {
        let mut fds = [0; 2];
        // SAFETY: `fds` is a 2-element array; socketpair fills it on success.
        let ret =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(
            ret,
            0,
            "socketpair failed: {}",
            std::io::Error::last_os_error()
        );

        let original_host_fd = fds[0];
        // SAFETY: Both fds are fresh from socketpair with sole ownership.
        let host_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: Same as above for the peer fd.
        let peer_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        let duplicated = Vmm::duplicate_client_vsock_fd(host_fd, 50_000).unwrap();
        // The dup clamps `min_fd` below RLIMIT_NOFILE to stay portable across
        // runners with a low soft limit (CI macOS defaults to ~2560). We
        // only require that the result escapes the low socketpair-recycle
        // band (fds 1–20 ish). A couple-hundred floor is safe on every
        // environment we target.
        assert!(
            duplicated.as_raw_fd() >= 512,
            "duplicated fd should move out of the low recycled range (got {})",
            duplicated.as_raw_fd(),
        );

        // SAFETY: fcntl F_GETFD is a pure query; EBADF is the expected result
        // since the original fd was consumed by `duplicate_client_vsock_fd`.
        let probe = unsafe { libc::fcntl(original_host_fd, libc::F_GETFD) };
        assert_eq!(probe, -1, "original fd should be closed after duplication");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );

        let payload = b"ok";
        // SAFETY: `peer_fd` is live; `payload` is a valid slice covering
        // `payload.len()` bytes for the duration of the write.
        let written = unsafe {
            libc::write(
                peer_fd.as_raw_fd(),
                payload.as_ptr().cast::<libc::c_void>(),
                payload.len(),
            )
        };
        assert_eq!(written, isize::try_from(payload.len()).unwrap());

        let mut buf = [0u8; 2];
        // SAFETY: `duplicated` is live; `buf` is a valid mutable slice
        // covering `buf.len()` bytes for the duration of the read.
        let read = unsafe {
            libc::read(
                duplicated.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        assert_eq!(read, isize::try_from(buf.len()).unwrap());
        assert_eq!(&buf, payload);
    }

    #[test]
    fn test_mmio_regions_do_not_overlap() {
        // GIC redistributor ends at 0x080A_0000 + 0x200_0000 = 0x0A0A_0000.
        // VirtIO MMIO starts at VIRTIO_MMIO_BASE (0x0A00_0000) — may overlap
        // with GICR tail, but HV.framework handles GIC internally.
        // PL011 is at 0x0B00_0000, after both GIC and VirtIO regions.
        let gicr_end = GIC_REDIST_ADDR + GIC_REDIST_SIZE;
        assert!(PL011_BASE >= gicr_end, "PL011 must be outside GIC region");
        // Both operands are constants — evaluated at compile time.
        const {
            assert!(
                PL011_BASE + PL011_SIZE <= RAM_BASE_IPA,
                "PL011 must be below guest RAM"
            );
        };
        // PL011 and VirtIO MMIO must not overlap.
        let pl011_range = PL011_BASE..PL011_BASE + PL011_SIZE;
        let virtio_start = VIRTIO_MMIO_BASE;
        let virtio_end = VIRTIO_MMIO_BASE + VIRTIO_MMIO_MAX_DEVICES * 0x1000;
        assert!(
            !pl011_range.contains(&virtio_start) && PL011_BASE >= virtio_end
                || PL011_BASE + PL011_SIZE <= virtio_start,
            "PL011 and VirtIO MMIO regions overlap"
        );
    }
}
