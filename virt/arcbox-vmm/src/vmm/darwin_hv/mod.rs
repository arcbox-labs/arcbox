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

use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex, mpsc};

use arcbox_hv::{HvVm, MemoryPermission};
use linux_loader::loader::{KernelLoader as LinuxKernelLoader, pe::PE};
use vm_fdt::FdtWriter;
use vm_memory::{
    Address, Bytes, GuestAddress, GuestMemory as VmGuestMemory, GuestMemoryMmap, GuestMemoryRegion,
};

use crate::boot::arm64;
#[cfg(test)]
use crate::device::DeviceTreeEntry;
use crate::device::DeviceType;
use crate::error::{Result, VmmError};
#[allow(unused_imports)] // Used by retained VZ-path / test helpers below.
use crate::fdt::{FdtConfig, generate_fdt};
use crate::irq::IrqChip;
#[cfg(feature = "gic")]
use crate::irq::{Gsi, IrqTriggerCallback};

use super::*;

#[cfg(test)]
mod guest_ram;
mod hvc_blk;
mod inline_sink;
mod network;
pub(super) mod pl011;
mod psci;
mod vcpu_loop;

use inline_sink::InlineConnSinkAdapter;
use pl011::PL011_BASE;
use pl011::PL011_SIZE;
pub(super) use pl011::Pl011;
#[cfg(test)]
use pl011::{PL011_DR, PL011_FR};
pub use psci::CpuOnRequest;
use psci::CpuOnSenders;
use vcpu_loop::{VcpuContext, vcpu_run_loop};

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

// ---------------------------------------------------------------------------
// Device slot tracking
// ---------------------------------------------------------------------------

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

impl Vmm {
    /// Duplicates a daemon-facing socketpair fd into a monotonically increasing
    /// descriptor range derived from the connection's host port.
    ///
    /// During guest boot, the daemon opens and drops several short-lived vsock
    /// probe connections in quick succession. On macOS the low socketpair fd
    /// number was being recycled immediately (`20`, `20`, `20`, ...), which in
    /// turn let Tokio/kqueue reuse the same registration slot across retries.
    /// When a previous registration had not been fully torn down yet, later
    /// attempts could miss both EOF and timeout wakeups. Rebinding the daemon
    /// end to the per-connection host port avoids that fd-number reuse while
    /// keeping the actual socket semantics unchanged.
    fn duplicate_client_vsock_fd(fd: OwnedFd, min_fd: RawFd) -> Result<OwnedFd> {
        // Clamp `min_fd` below the current RLIMIT_NOFILE soft limit. Port
        // numbers passed in as `min_fd` can legitimately reach ~65 k, but on
        // macOS CI runners the soft limit defaults to ~2560, making a raw
        // F_DUPFD_CLOEXEC return EINVAL. The caller only needs an fd number
        // that avoids the recycled low range — any value well above the
        // socketpair/tokio-registration churn band (say, fd > 1024) works.
        let clamped_min = {
            let mut rl = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: `getrlimit` writes a single `rlimit` struct; the raw
            // pointer is valid for the duration of the call.
            let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, std::ptr::from_mut(&mut rl)) };
            if rc == 0 && (rl.rlim_cur as RawFd) > 128 {
                // Reserve ~64 fds for the rest of the process; clamp min_fd
                // to whichever is smaller.
                let ceiling = (rl.rlim_cur as RawFd).saturating_sub(64);
                min_fd.min(ceiling)
            } else {
                min_fd
            }
        };

        // SAFETY: `fd` is a live OwnedFd; fcntl(F_DUPFD_CLOEXEC) is a
        // read-only operation on the open file table and cannot cause UB.
        let dup_fd = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, clamped_min) };
        if dup_fd < 0 {
            return Err(VmmError::Device(format!(
                "vsock client fd dup failed: {} (clamped_min={clamped_min})",
                std::io::Error::last_os_error()
            )));
        }

        // SAFETY: `dup_fd` is a fresh fd produced by the kernel on success;
        // no other owner exists, so `OwnedFd` takes sole ownership.
        Ok(unsafe { OwnedFd::from_raw_fd(dup_fd) })
    }

    /// Custom VMM initialization using Hypervisor.framework (manual execution).
    ///
    /// This path is an alternative to `initialize_darwin()` (VZ framework).
    /// It creates a VM via `arcbox-hv`, allocates guest RAM, sets up GIC,
    /// registers VirtIO devices, generates an FDT, and prepares vCPU state
    /// for boot.
    pub(super) fn initialize_darwin_hv(&mut self) -> Result<()> {
        tracing::info!("Initializing custom VMM via Hypervisor.framework");

        let ram_size = self.config.memory_size as usize;

        // --- 1. Allocate guest RAM via vm-memory's mmap abstraction ---
        // This allocates anonymous memory and provides type-safe GPA access.
        let guest_mem =
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(RAM_BASE_IPA), ram_size)])
                .map_err(|e| VmmError::Memory(format!("guest memory allocation failed: {e}")))?;
        tracing::debug!(
            "Allocated {} MB guest RAM via vm-memory",
            ram_size / (1024 * 1024)
        );

        // --- 2. Create Hypervisor.framework VM ---
        // Use 40-bit IPA for up to ~1 TB guest physical address space,
        // which accommodates RAM + MMIO + GIC regions.
        let vm = HvVm::with_ipa_size(40)
            .map_err(|e| VmmError::Device(format!("hv_vm_create failed: {e}")))?;

        // --- 3. Map guest RAM into HV IPA space ---
        // Get the host virtual address for the mmap'd region and map it
        // into the guest's physical address space via Hypervisor.framework.
        for region in guest_mem.iter() {
            let host_ptr = region.as_ptr();
            let guest_addr = region.start_addr().raw_value();
            let size = region.len() as usize;
            // SAFETY: `region` is a live GuestMemoryMmap region owned by
            // `guest_mem`, which is moved into `self` below and kept alive
            // for the VM's lifetime. The host mapping therefore remains
            // valid for `size` bytes as long as the HV mapping exists.
            unsafe {
                vm.map_memory(
                    host_ptr,
                    guest_addr,
                    size,
                    MemoryPermission::READ_WRITE | MemoryPermission::EXEC,
                )
                .map_err(|e| VmmError::Memory(format!("hv_vm_map failed: {e}")))?;
            }
            tracing::debug!(
                "Mapped guest RAM: IPA {:#x}..{:#x} (host={:p})",
                guest_addr,
                guest_addr + size as u64,
                host_ptr,
            );
        }

        // --- 3b. Reserve the DAX window IPA range for VirtioFS DAX ---
        // The window is placed immediately above guest RAM so the guest
        // kernel's `devm_memremap_pages` sees it as ZONE_DEVICE (must be
        // above RAM, not in the MMIO gap). We do *not* pre-map an anonymous
        // backing here: `hv_vm_map` on Apple Silicon does not support
        // overlapping remaps (an existing stage-2 mapping at the target IPA
        // makes every subsequent `hv_vm_map` for a sub-range return
        // `HV_ERROR`, even after a matching `hv_vm_unmap`). Instead the
        // window stays logically reserved and each FUSE_SETUPMAPPING call
        // installs a per-file stage-2 mapping into its slice via
        // `HvDaxMapper::setup_mapping`. If the guest touches the window
        // before SETUPMAPPING lands it faults — which is the correct DAX
        // contract.
        let dax_base = crate::dax::dax_window_base(RAM_BASE_IPA, ram_size as u64);
        let dax_size = crate::dax::dax_window_total(self.config.shared_dirs.len()) as usize;
        tracing::info!(
            "DAX window reserved: IPA {:#x}..{:#x} ({}MB, on-demand)",
            dax_base,
            dax_base + dax_size as u64,
            dax_size / (1024 * 1024),
        );

        // --- 4. Initialize GIC (macOS 15+) ---
        #[cfg(feature = "gic")]
        let gic = {
            let gic_config = arcbox_hv::GicConfig {
                distributor_base: 0x0800_0000,
                redistributor_base: 0x080A_0000,
            };
            let g = arcbox_hv::Gic::new(gic_config)
                .map_err(|e| VmmError::Device(format!("GIC initialization failed: {e}")))?;
            tracing::info!(
                "GICv3 initialized: GICD @ {:#x}, GICR @ {:#x}",
                g.distributor_base(),
                g.redistributor_base(),
            );
            Some(Arc::new(g))
        };
        #[cfg(not(feature = "gic"))]
        tracing::warn!("GIC feature not enabled — interrupts will not work with custom VMM");

        // --- 5. Set up IRQ chip with GIC callback ---
        let irq_chip = Arc::new(IrqChip::new()?);

        // Shared registry for vCPU thread handles — the IRQ callback uses
        // this to unpark WFI-blocked vCPU threads when an interrupt fires.
        let vcpu_thread_handles: VcpuThreadHandles = Arc::new(Mutex::new(Vec::new()));

        // Shared registry for Hypervisor.framework vCPU IDs. Each
        // `vcpu_run_loop` pushes its `HvVcpu::raw_handle()` here after
        // creation so the stop/pause paths can target `hv_vcpus_exit`
        // with a concrete list (arm64 requires that; see ABX-367).
        let hv_vcpu_ids: HvVcpuIds = Arc::new(Mutex::new(Vec::new()));

        #[cfg(feature = "gic")]
        if let Some(ref gic_ref) = gic {
            let gic_weak = Arc::downgrade(gic_ref);
            let threads_weak = Arc::downgrade(&vcpu_thread_handles);
            let callback: IrqTriggerCallback = Box::new(move |gsi: Gsi, level: bool| {
                if let Some(g) = gic_weak.upgrade() {
                    g.set_spi(gsi, level).map_err(|e| {
                        VmmError::Irq(format!("GIC set_spi({gsi}, {level}) failed: {e}"))
                    })?;
                    tracing::trace!("GIC: SPI {gsi} level={level}");
                } else {
                    tracing::warn!("GIC: dropped, cannot inject SPI {gsi}");
                }
                // Wake any WFI-parked vCPU threads so they can service the
                // interrupt. Only unpark on assertion (level=true) to avoid
                // spurious wakeups on de-assertion.
                if level {
                    if let Some(handles) = threads_weak.upgrade() {
                        if let Ok(handles) = handles.lock() {
                            for t in handles.iter() {
                                t.unpark();
                            }
                        }
                    }
                }
                Ok(())
            });
            irq_chip.set_trigger_callback(Arc::new(callback));
            tracing::debug!("IRQ callback wired to hardware GIC (with WFI unpark)");
        }

        // --- 6. Initialize managers ---
        // Use a custom MMIO base matching the ARM64 VirtIO MMIO layout so
        // that device addresses in the FDT match what the allocator assigns.
        // MMIO allocator aligns each slot to 4 KB, so reserve enough space
        // for the maximum number of devices at page granularity.
        let mmio_region_size = VIRTIO_MMIO_MAX_DEVICES * 0x1000;
        let mut memory_manager = MemoryManager::with_mmio_base(VIRTIO_MMIO_BASE, mmio_region_size);
        memory_manager.initialize(self.config.memory_size)?;

        let mut device_manager = DeviceManager::new();

        // Provide guest memory access so the QUEUE_NOTIFY handler can read
        // descriptors and write completions directly in guest RAM.
        // Get host pointer from the GuestMemoryMmap region for DeviceManager's
        // raw access path.
        {
            let region = guest_mem
                .iter()
                .next()
                .ok_or_else(|| VmmError::Memory("no guest memory regions".into()))?;
            let host_ptr = region.as_ptr();
            // SAFETY: guest_mem is stored in the Vmm struct and outlives the
            // DeviceManager, so the pointer remains valid.
            unsafe {
                device_manager.set_guest_memory(host_ptr, ram_size, RAM_BASE_IPA);
            }
        }

        // Wire IRQ callback so device completions trigger GIC interrupts.
        // For level-triggered SPIs, the callback must support both assert
        // (level=true) and deassert (level=false) to keep the SPI in sync
        // with the device's interrupt_status register.
        {
            let irq_chip_clone = Arc::clone(&irq_chip);
            let callback: crate::device::DeviceIrqCallback = Arc::new(move |irq, level| {
                if level {
                    irq_chip_clone
                        .trigger_irq(irq)
                        .map_err(|e| VmmError::Irq(format!("trigger_irq({irq}): {e}")))
                } else {
                    irq_chip_clone
                        .deassert_irq(irq)
                        .map_err(|e| VmmError::Irq(format!("deassert_irq({irq}): {e}")))
                }
            });
            device_manager.set_irq_callback(callback);
        }

        // --- 7. Register actual VirtIO device instances ---

        // Console
        if self.config.serial_console || self.config.virtio_console {
            let console = arcbox_virtio::console::VirtioConsole::new(
                arcbox_virtio::console::ConsoleConfig::default(),
            );
            let (_console_id, _console_arc) = device_manager.register_virtio_device(
                DeviceType::VirtioConsole,
                "virtio-console",
                console,
                &mut memory_manager,
                &irq_chip,
            )?;
        }

        // VirtioFS shared directories — create FsServer handler for each share.
        // Each VirtioFS device gets its own DAX window slice so devm_request_mem_region
        // doesn't collide. Total DAX space is split equally among shares.
        let per_share_dax = crate::dax::DAX_WINDOW_PER_SHARE;
        let mut dax_offset: u64 = 0;

        for dir in &self.config.shared_dirs {
            let fs_config = arcbox_virtio::fs::FsConfig {
                tag: dir.tag.clone(),
                num_queues: 1,
                queue_size: 1024,
                shared_dir: dir.host_path.to_string_lossy().into_owned(),
            };

            let server_config = arcbox_fs::FsConfig {
                tag: dir.tag.clone(),
                source: dir.host_path.to_string_lossy().into_owned(),
                ..arcbox_fs::FsConfig::default()
            };
            let mut server = arcbox_fs::FsServer::new(server_config);
            server
                .start()
                .map_err(|e| VmmError::Device(format!("FsServer start failed: {e}")))?;

            // Wire a per-share DAX mapper with the correct base IPA.
            // Each share's DAX window is a disjoint slice of the global DAX
            // region. Using a shared mapper would cause all shares to map
            // into share 0's window, corrupting guest page tables.
            //
            // Keep a concrete `Arc<HvDaxMapper>` on `Vmm` alongside the
            // trait-object form handed to `FsServer`, so observability code
            // (ABX-362) and integration tests can read the per-share
            // `DaxStats` counters directly.
            let this_dax_base = dax_base + dax_offset;
            let concrete_mapper =
                std::sync::Arc::new(crate::dax::HvDaxMapper::new(this_dax_base, per_share_dax));
            let share_mapper: std::sync::Arc<dyn arcbox_fs::DaxMapper> = concrete_mapper.clone();
            server.set_dax_mapper(share_mapper);
            self.hv_dax_mappers.push(concrete_mapper);

            let handler: std::sync::Arc<dyn arcbox_virtio::fs::FuseRequestHandler> =
                std::sync::Arc::new(server);

            let fs_dev = arcbox_virtio::fs::VirtioFs::with_handler(fs_config, handler);
            let name = format!("virtiofs-{}", dir.tag);
            let (fs_device_id, _fs_arc) = device_manager.register_virtio_device(
                DeviceType::VirtioFs,
                name,
                fs_dev,
                &mut memory_manager,
                &irq_chip,
            )?;

            // Configure per-device SHM region (non-overlapping DAX window slice).
            if let Some(dev) = device_manager.get_registered_device(fs_device_id) {
                if let Some(ref mmio_arc) = dev.mmio_state {
                    if let Ok(mut state) = mmio_arc.write() {
                        state.shm_regions.push((this_dax_base, per_share_dax));
                        tracing::info!(
                            "VirtioFS '{}': DAX window at IPA {:#x}, size {}MB",
                            dir.tag,
                            this_dax_base,
                            per_share_dax / (1024 * 1024),
                        );
                    }
                }
            }
            dax_offset += per_share_dax;
        }

        // Block devices — capture raw_fd for async I/O worker.
        // Set num_queues = vcpu_count for multi-queue (one queue per vCPU).
        let blk_num_queues = self.config.vcpu_count.max(1) as u16;
        for block_dev in &self.config.block_devices {
            let mut blk =
                arcbox_virtio::blk::VirtioBlock::from_path(&block_dev.path, block_dev.read_only)
                    .map_err(|e| VmmError::Device(format!("block device: {e}")))?;
            blk.set_num_queues(blk_num_queues);
            let raw_fd = blk.raw_fd().unwrap_or(-1);
            let blk_size = blk.blk_size();
            let read_only = blk.is_read_only();
            let num_queues = blk.num_queues();
            let dev_id_str = blk.device_id_string().to_string();
            let name = format!("virtio-blk-{}", block_dev.path.display());
            let (device_id, _blk_arc) = device_manager.register_virtio_device(
                DeviceType::VirtioBlock,
                name,
                blk,
                &mut memory_manager,
                &irq_chip,
            )?;
            if raw_fd >= 0 {
                self.hv_blk_devices.push((
                    device_id, raw_fd, blk_size, read_only, dev_id_str, num_queues,
                ));
            }
        }

        // Build HVC fast-path fd table from all block devices.
        // device_idx 0 = first block device (vda), 1 = second (vdb), etc.
        {
            let fds: Vec<(i32, u32)> = self
                .hv_blk_devices
                .iter()
                .map(|(_, raw_fd, blk_size, _, _, _)| (*raw_fd, *blk_size))
                .collect();
            self.hvc_blk_fds = Arc::new(fds);
        }

        // Network (TSO-enabled) with custom socket-proxy datapath.
        // Creates a SOCK_DGRAM socketpair: one end feeds the VirtioNet device
        // (via DeviceManager TX/RX bridging), the other end goes to the same
        // NetworkDatapath used by the VZ path (DHCP, DNS, NAT, TCP proxy).
        if self.config.networking {
            let net_config = arcbox_virtio::net::NetConfig {
                mac: arcbox_virtio::net::NetConfig::random_mac(),
                ..Default::default()
            };
            let mut net_dev = arcbox_virtio::net::VirtioNet::new(net_config);
            net_dev.enable_tso_features();
            let (primary_net_id, primary_net_arc) = device_manager.register_virtio_device(
                DeviceType::VirtioNet,
                "virtio-net",
                net_dev,
                &mut memory_manager,
                &irq_chip,
            )?;
            // Hand DeviceManager the typed handle so QUEUE_NOTIFY dispatch
            // can reach the concrete VirtioNet's `drain_tx_queue` without
            // a HashMap lookup + dyn dispatch.
            device_manager.set_primary_net(primary_net_id, primary_net_arc);

            // Set up the network datapath (reuses VZ path's entire stack).
            self.create_hv_network_datapath(&mut device_manager, primary_net_id)?;

            // Bridge NIC (NIC2): vmnet for host→container L3 routing.
            #[cfg(feature = "vmnet")]
            {
                if let Err(e) =
                    self.create_hv_bridge_nic(&mut device_manager, &mut memory_manager, &irq_chip)
                {
                    tracing::warn!("vmnet bridge NIC failed (non-fatal): {e}");
                    // Bridge NIC is optional — container IP routing won't work
                    // but everything else (outbound, vsock, Docker API) is fine.
                }
            }
        }

        // Entropy (RNG) — provides /dev/hwrng to the guest. Without this,
        // the kernel's crng never initializes and dockerd blocks on
        // /dev/urandom indefinitely.
        {
            let rng_dev = arcbox_virtio::rng::VirtioRng::new();
            let (_rng_id, _rng_arc) = device_manager.register_virtio_device(
                DeviceType::VirtioRng,
                "virtio-rng",
                rng_dev,
                &mut memory_manager,
                &irq_chip,
            )?;
        }

        // Vsock
        if self.config.vsock {
            let vsock_config = arcbox_virtio::vsock::VsockConfig {
                guest_cid: self.config.guest_cid.unwrap_or(3) as u64,
            };
            let vsock_dev = arcbox_virtio::vsock::VirtioVsock::new(vsock_config);
            let (vsock_id, vsock_arc) = device_manager.register_virtio_device(
                DeviceType::VirtioVsock,
                "virtio-vsock",
                vsock_dev,
                &mut memory_manager,
                &irq_chip,
            )?;
            // Bind DeviceCtx + connection manager so the device's
            // `process_queue` reaches them directly without QueueConfig
            // plumbing, and the future `poll_rx_injection` migration has
            // its prerequisites in place.
            device_manager.set_vsock(vsock_id, vsock_arc);
        }

        // Memory balloon (ABX-363). Lets the host reclaim unused guest
        // pages via `madvise(MADV_DONTNEED)` when the daemon's idle
        // monitor signals via `set_balloon_target`.
        if self.config.balloon {
            let balloon_dev = arcbox_virtio::balloon::VirtioBalloon::new();
            let (_balloon_id, balloon_arc) = device_manager.register_virtio_device(
                DeviceType::VirtioBalloon,
                "virtio-balloon",
                balloon_dev,
                &mut memory_manager,
                &irq_chip,
            )?;
            self.hv_balloon = Some(balloon_arc);
            tracing::info!("Added memory balloon device (HV)");
        }

        for dev_info in device_manager.iter() {
            tracing::info!(
                "VirtIO device: {} ({:?}) @ MMIO {:#x} IRQ {:?}",
                dev_info.name,
                dev_info.device_type,
                dev_info.mmio_base.unwrap_or(0),
                dev_info.irq
            );
        }

        // --- 8. Load kernel via linux-loader PE loader ---
        let mut kernel_file = std::fs::File::open(&self.config.kernel_path)
            .map_err(|e| VmmError::config(format!("cannot open kernel: {e}")))?;

        // PE::load writes the kernel image directly into GuestMemoryMmap.
        // The kernel_offset must be 2 MB aligned (ARM64 boot protocol).
        let kernel_result = PE::load(
            &guest_mem,
            Some(GuestAddress(RAM_BASE_IPA)),
            &mut kernel_file,
            None,
        )
        .map_err(|e| VmmError::config(format!("kernel loading failed: {e}")))?;

        let kernel_entry = kernel_result.kernel_load.raw_value();
        tracing::info!(
            "Kernel loaded via linux-loader: entry={:#x}, end={:#x}",
            kernel_entry,
            kernel_result.kernel_end,
        );

        // --- 9. Load initrd via vm-memory ---
        // Pass the initrd as-is to guest memory. The Linux kernel has built-in
        // decompression for gzip/xz/lz4/zstd compressed initramfs archives.
        let initrd_info: Option<(u64, u64)> = if let Some(ref initrd_path) = self.config.initrd_path
        {
            let initrd_data = std::fs::read(initrd_path)
                .map_err(|e| VmmError::config(format!("cannot read initrd: {e}")))?;

            // Place initrd well after the kernel to avoid corruption during
            // early boot memory setup. Use a fixed high address within RAM.
            // RAM: 0x40000000..0xC0000000, place initrd at 0x48000000 (128MB from RAM base).
            let initrd_addr = GuestAddress(RAM_BASE_IPA + 0x0800_0000);

            guest_mem
                .write_slice(&initrd_data, initrd_addr)
                .map_err(|e| VmmError::Memory(format!("failed to write initrd: {e}")))?;

            // Verify initrd was written correctly by reading back the first bytes.
            let mut verify = [0u8; 4];
            guest_mem
                .read_slice(&mut verify, initrd_addr)
                .map_err(|e| VmmError::Memory(format!("initrd verify read failed: {e}")))?;
            tracing::info!(
                "Initrd loaded: addr={:#x}, size={} bytes, magic={:02x}{:02x}{:02x}{:02x}",
                initrd_addr.raw_value(),
                initrd_data.len(),
                verify[0],
                verify[1],
                verify[2],
                verify[3],
            );

            Some((initrd_addr.raw_value(), initrd_data.len() as u64))
        } else {
            None
        };

        // --- 10. Generate FDT via vm-fdt ---
        let fdt_entries = device_manager.device_tree_entries();

        let fdt_blob = {
            let mut fdt = FdtWriter::new().map_err(fdt_err)?;

            // Root node
            let root = fdt.begin_node("").map_err(fdt_err)?;
            fdt.property_string("compatible", "linux,dummy-virt")
                .map_err(fdt_err)?;
            fdt.property_u32("#address-cells", 2).map_err(fdt_err)?;
            fdt.property_u32("#size-cells", 2).map_err(fdt_err)?;
            fdt.property_u32("interrupt-parent", 1).map_err(fdt_err)?; // GIC phandle

            // Chosen node
            let chosen = fdt.begin_node("chosen").map_err(fdt_err)?;
            fdt.property_string("bootargs", &self.config.kernel_cmdline)
                .map_err(fdt_err)?;
            fdt.property_string("stdout-path", "/pl011@b000000")
                .map_err(fdt_err)?;
            if let Some((initrd_start, initrd_size)) = initrd_info {
                fdt.property_u64("linux,initrd-start", initrd_start)
                    .map_err(fdt_err)?;
                fdt.property_u64("linux,initrd-end", initrd_start + initrd_size)
                    .map_err(fdt_err)?;
            }
            fdt.end_node(chosen).map_err(fdt_err)?;

            // Memory node
            let mem_node = fdt
                .begin_node(&format!("memory@{RAM_BASE_IPA:x}"))
                .map_err(fdt_err)?;
            fdt.property_string("device_type", "memory")
                .map_err(fdt_err)?;
            let mut reg = Vec::new();
            reg.extend_from_slice(&RAM_BASE_IPA.to_be_bytes());
            reg.extend_from_slice(&(ram_size as u64).to_be_bytes());
            fdt.property("reg", &reg).map_err(fdt_err)?;
            fdt.end_node(mem_node).map_err(fdt_err)?;

            // CPUs
            let cpus = fdt.begin_node("cpus").map_err(fdt_err)?;
            fdt.property_u32("#address-cells", 1).map_err(fdt_err)?;
            fdt.property_u32("#size-cells", 0).map_err(fdt_err)?;
            for i in 0..self.config.vcpu_count {
                let cpu = fdt.begin_node(&format!("cpu@{i}")).map_err(fdt_err)?;
                fdt.property_string("device_type", "cpu").map_err(fdt_err)?;
                fdt.property_string("compatible", "arm,arm-v8")
                    .map_err(fdt_err)?;
                fdt.property_string("enable-method", "psci")
                    .map_err(fdt_err)?;
                fdt.property_u32("reg", i).map_err(fdt_err)?;
                fdt.end_node(cpu).map_err(fdt_err)?;
            }
            fdt.end_node(cpus).map_err(fdt_err)?;

            // Timer
            let timer = fdt.begin_node("timer").map_err(fdt_err)?;
            fdt.property_string("compatible", "arm,armv8-timer")
                .map_err(fdt_err)?;
            fdt.property_null("always-on").map_err(fdt_err)?;
            // PPI interrupts: secure phys, non-secure phys, virt, hyp
            fdt.property_array_u32(
                "interrupts",
                &[
                    1, 13, 0x304, // Secure phys timer
                    1, 14, 0x304, // Non-secure phys timer
                    1, 11, 0x304, // Virtual timer
                    1, 10, 0x304, // Hyperphysical timer
                ],
            )
            .map_err(fdt_err)?;
            fdt.end_node(timer).map_err(fdt_err)?;

            // PSCI
            let psci = fdt.begin_node("psci").map_err(fdt_err)?;
            fdt.property_string("compatible", "arm,psci-1.0")
                .map_err(fdt_err)?;
            fdt.property_string("method", "hvc").map_err(fdt_err)?;
            fdt.end_node(psci).map_err(fdt_err)?;

            // GIC v3
            let intc = fdt
                .begin_node(&format!("intc@{GIC_DIST_ADDR:x}"))
                .map_err(fdt_err)?;
            fdt.property_string("compatible", "arm,gic-v3")
                .map_err(fdt_err)?;
            fdt.property_u32("#interrupt-cells", 3).map_err(fdt_err)?;
            fdt.property_null("interrupt-controller").map_err(fdt_err)?;
            fdt.property_phandle(1).map_err(fdt_err)?;
            // reg: distributor base+size, redistributor base+size
            let mut gic_reg = Vec::new();
            gic_reg.extend_from_slice(&GIC_DIST_ADDR.to_be_bytes());
            gic_reg.extend_from_slice(&GIC_DIST_SIZE.to_be_bytes());
            gic_reg.extend_from_slice(&GIC_REDIST_ADDR.to_be_bytes());
            gic_reg.extend_from_slice(&GIC_REDIST_SIZE.to_be_bytes());
            fdt.property("reg", &gic_reg).map_err(fdt_err)?;
            fdt.end_node(intc).map_err(fdt_err)?;

            // PL011 UART
            let uart = fdt.begin_node("pl011@b000000").map_err(fdt_err)?;
            fdt.property_string("compatible", "arm,pl011")
                .map_err(fdt_err)?;
            let mut uart_reg = Vec::new();
            uart_reg.extend_from_slice(&PL011_BASE.to_be_bytes());
            uart_reg.extend_from_slice(&PL011_SIZE.to_be_bytes());
            fdt.property("reg", &uart_reg).map_err(fdt_err)?;
            fdt.property_array_u32("interrupts", &[0, 1, 4])
                .map_err(fdt_err)?; // SPI 1, level
            fdt.property_u32("clock-frequency", 24_000_000)
                .map_err(fdt_err)?;
            fdt.end_node(uart).map_err(fdt_err)?;

            // VirtIO MMIO devices from DeviceManager
            for entry in &fdt_entries {
                let node = fdt
                    .begin_node(&format!("virtio_mmio@{:x}", entry.reg_base))
                    .map_err(fdt_err)?;
                fdt.property_string("compatible", &entry.compatible)
                    .map_err(fdt_err)?;
                let mut dev_reg = Vec::new();
                dev_reg.extend_from_slice(&entry.reg_base.to_be_bytes());
                dev_reg.extend_from_slice(&entry.reg_size.to_be_bytes());
                fdt.property("reg", &dev_reg).map_err(fdt_err)?;
                // GIC SPI numbering: FDT SPI number = INTID - 32.
                // hv_gic_set_spi uses INTID directly (starting at 32).
                fdt.property_array_u32("interrupts", &[0, entry.irq.saturating_sub(32), 4])
                    .map_err(fdt_err)?; // SPI, level
                fdt.property_null("dma-coherent").map_err(fdt_err)?;
                fdt.end_node(node).map_err(fdt_err)?;
            }

            fdt.end_node(root).map_err(fdt_err)?;
            fdt.finish().map_err(fdt_err)?
        };

        if fdt_blob.len() > arm64::FDT_MAX_SIZE {
            return Err(VmmError::Memory("generated FDT exceeds 2 MB limit".into()));
        }

        // Place FDT at end of RAM, page-aligned backward.
        let fdt_addr =
            GuestAddress((RAM_BASE_IPA + ram_size as u64 - fdt_blob.len() as u64) & !0xFFF);
        guest_mem
            .write_slice(&fdt_blob, fdt_addr)
            .map_err(|e| VmmError::Memory(format!("failed to write FDT: {e}")))?;

        tracing::info!(
            "FDT written: addr={:#x}, size={} bytes, devices={}",
            fdt_addr.raw_value(),
            fdt_blob.len(),
            fdt_entries.len()
        );

        // --- 11. Store managers ---
        let event_loop = crate::event::EventLoop::new()?;

        self.memory_manager = Some(memory_manager);
        self.device_manager = Some(device_manager);
        self.irq_chip = Some(irq_chip);
        self.event_loop = Some(event_loop);

        // Store HV-specific state in the Vmm struct for lifecycle management.
        // GuestMemoryMmap must outlive the HvVm since the mapped memory must
        // remain valid for the entire VM lifetime.
        self.hv_vm = Some(vm);
        self.hv_guest_mem = Some(guest_mem);
        #[cfg(feature = "gic")]
        {
            self.hv_gic = gic;
        }
        self.hv_kernel_entry = Some(kernel_entry);
        self.hv_fdt_addr = Some(fdt_addr.raw_value());
        self.hv_vcpu_thread_handles = Some(vcpu_thread_handles);
        self.hv_vcpu_ids = Some(hv_vcpu_ids);

        tracing::info!("Custom Hypervisor.framework VMM initialized");
        Ok(())
    }

    /// Starts the custom HV VMM by spawning vCPU threads.
    ///
    /// The BSP (vCPU 0) runs immediately. Secondary vCPUs (1..N) are spawned
    /// in a "parked" state and wait on a channel for a PSCI CPU_ON request
    /// from the BSP before entering their run loop.
    pub(super) fn start_darwin_hv(&mut self) -> Result<()> {
        let kernel_entry = self
            .hv_kernel_entry
            .ok_or_else(|| VmmError::config("HV kernel entry not set".to_string()))?;
        let fdt_addr = self
            .hv_fdt_addr
            .ok_or_else(|| VmmError::config("HV FDT address not set".to_string()))?;

        // Both registries are created during initialize_darwin_hv. Callers
        // must not invoke start before initialize — guard against that here.
        if self.hv_vcpu_ids.is_none() {
            return Err(VmmError::invalid_state(
                "hv_vcpu_ids not initialized; call initialize() first".to_string(),
            ));
        }
        if self.hv_vcpu_thread_handles.is_none() {
            return Err(VmmError::invalid_state(
                "hv_vcpu_thread_handles not initialized; call initialize() first".to_string(),
            ));
        }

        let mut device_manager = Arc::new(
            self.device_manager
                .take()
                .ok_or_else(|| VmmError::config("device manager not initialized".to_string()))?,
        );

        // Spawn async block I/O worker threads (one per block device).
        // Uses device info captured during initialize_darwin_hv.
        // Must happen before Arc is cloned to other threads.
        {
            let dm = Arc::get_mut(&mut device_manager).expect("single Arc ref");
            let (guest_ptr, guest_len, guest_gpa_base) = if let (Some(base), size, gpa) = (
                dm.guest_ram_base_ptr(),
                dm.guest_ram_size(),
                dm.guest_ram_gpa(),
            ) {
                (base, size, gpa as usize)
            } else {
                (std::ptr::null_mut(), 0, 0)
            };

            // Collect IRQ info for each block device before spawning workers.
            let blk_infos = std::mem::take(&mut self.hv_blk_devices)
                .into_iter()
                .filter_map(
                    |(dev_id, raw_fd, blk_size, read_only, dev_id_str, num_queues)| {
                        let dev = dm.get_registered_device(dev_id)?;
                        let irq = dev.info.irq?;
                        let mmio_state = dev.mmio_state.as_ref()?.clone();
                        Some((
                            dev_id, raw_fd, blk_size, read_only, dev_id_str, num_queues, irq,
                            mmio_state,
                        ))
                    },
                )
                .collect::<Vec<_>>();

            for (dev_id, raw_fd, blk_size, read_only, dev_id_str, num_queues, irq, mmio_state) in
                blk_infos
            {
                let irq_cb = dm.irq_callback_clone().unwrap_or_else(|| {
                    Arc::new(|_: crate::irq::Irq, _: bool| -> crate::error::Result<()> { Ok(()) })
                });
                let flush_barrier = Arc::new(crate::blk_worker::FlushBarrier::new());
                let mut queue_workers = Vec::with_capacity(num_queues as usize);

                for qi in 0..num_queues {
                    let (tx, rx) = std::sync::mpsc::channel::<crate::blk_worker::BlkWorkItem>();

                    let worker_ctx = crate::blk_worker::BlkWorkerContext {
                        // SAFETY: `guest_ptr` is the host mapping returned by
                        // Virtualization.framework, valid for `guest_len` bytes
                        // for the lifetime of the VM.
                        guest_mem: unsafe {
                            crate::blk_worker::GuestMemWriter::new(
                                guest_ptr,
                                guest_len,
                                guest_gpa_base,
                            )
                        },
                        raw_fd,
                        blk_size,
                        read_only,
                        device_id: dev_id_str.clone(),
                        mmio_state: mmio_state.clone(),
                        irq_callback: irq_cb.clone(),
                        irq,
                        running: self.running.clone(),
                        flush_barrier: flush_barrier.clone(),
                    };

                    let thread_name = format!("blk-io-{}-q{}", dev_id_str, qi);
                    match std::thread::Builder::new()
                        .name(thread_name.clone())
                        .spawn(move || {
                            crate::blk_worker::blk_io_worker_loop(worker_ctx, rx);
                        }) {
                        Ok(t) => {
                            self.hv_blk_worker_threads.push(t);
                            queue_workers.push(crate::blk_worker::BlkQueueWorker {
                                tx,
                                last_avail_idx: std::sync::atomic::AtomicU16::new(0),
                            });
                        }
                        Err(e) => {
                            tracing::warn!("Failed to spawn {}: {}", thread_name, e);
                        }
                    }
                }

                if !queue_workers.is_empty() {
                    dm.set_blk_worker(
                        dev_id,
                        crate::blk_worker::BlkWorkerHandle {
                            queues: queue_workers,
                        },
                    );
                    tracing::info!(
                        "Spawned {} async block I/O workers for {}",
                        num_queues,
                        dev_id_str,
                    );
                }
            }
        }

        // Wire net-io worker hooks before the Arc is shared.
        // The net-io thread will be spawned later at DRIVER_OK time.
        {
            let dm = Arc::get_mut(&mut device_manager).expect("single Arc ref for net-rx hooks");

            // Build IRQ callback for the net-io thread (same GIC + unpark logic).
            #[cfg(feature = "gic")]
            if let Some(ref gic_ref) = self.hv_gic {
                let gic_clone = Arc::clone(gic_ref);
                let threads_clone = self
                    .hv_vcpu_thread_handles
                    .clone()
                    .expect("hv_vcpu_thread_handles asserted Some above");
                let net_irq_cb: crate::device::DeviceIrqCallback =
                    Arc::new(move |gsi: crate::irq::Gsi, level: bool| {
                        gic_clone.set_spi(gsi, level).map_err(|e| {
                            VmmError::Irq(format!("GIC set_spi({gsi}, {level}) failed: {e}"))
                        })?;
                        if level {
                            if let Ok(handles) = threads_clone.lock() {
                                for t in handles.iter() {
                                    t.unpark();
                                }
                            }
                        }
                        Ok(())
                    });
                // Force-exit all vCPUs closure used by the net-rx worker to
                // wake a guest that is idle in WFI for interrupt delivery.
                // On arm64 `hv_vcpus_exit` requires a concrete list of vCPU
                // IDs; NULL/0 is a silent no-op. Snapshot `hv_vcpu_ids` each
                // invocation so late-arriving secondaries (PSCI CPU_ON) are
                // picked up. Safe to call from any thread. See ABX-367.
                let exit_ids = self
                    .hv_vcpu_ids
                    .clone()
                    .expect("hv_vcpu_ids asserted Some above");
                let exit_fn: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                    let ids_snapshot: Vec<u64> = exit_ids
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone();
                    if ids_snapshot.is_empty() {
                        return;
                    }
                    // SAFETY: `ids_snapshot` is a live Vec owned by this
                    // closure for the duration of the FFI call; the pointer
                    // and length are consistent.
                    #[allow(clippy::cast_possible_truncation)]
                    let ret = unsafe {
                        arcbox_hv::ffi::hv_vcpus_exit(
                            ids_snapshot.as_ptr(),
                            ids_snapshot.len() as u32,
                        )
                    };
                    if let Err(e) = arcbox_hv::check(ret) {
                        tracing::warn!("net-rx exit_fn: hv_vcpus_exit failed: {e}");
                    }
                });
                dm.set_net_rx_hooks(net_irq_cb, exit_fn);
            }

            dm.set_running(self.running.clone());
        }

        // Store a shared reference for connect_vsock_hv to use after start.
        self.hv_device_manager = Some(Arc::clone(&device_manager));
        let running = self.running.clone();
        let paused = self.hv_paused.clone();
        // Ensure a fresh start always begins unpaused, even if a prior
        // session was stopped while paused.
        paused.store(false, std::sync::atomic::Ordering::SeqCst);
        let vcpu_count = self.config.vcpu_count;
        let pl011 = Arc::new(std::sync::Mutex::new(Pl011::new()));

        let vcpu_thread_handles = self
            .hv_vcpu_thread_handles
            .clone()
            .expect("hv_vcpu_thread_handles asserted Some above");
        let hv_vcpu_ids = self
            .hv_vcpu_ids
            .clone()
            .expect("hv_vcpu_ids asserted Some above");

        // --- Set up PSCI CPU_ON channels for secondary vCPUs ---
        let cpu_on_senders: Option<CpuOnSenders> = if vcpu_count > 1 {
            let mut senders_vec: Vec<Option<mpsc::Sender<CpuOnRequest>>> = Vec::new();
            senders_vec.push(None); // Slot 0 = BSP

            for i in 1..vcpu_count {
                let (tx, rx) = mpsc::channel::<CpuOnRequest>();
                senders_vec.push(Some(tx));

                let r = running.clone();
                let p = paused.clone();
                let dm = device_manager.clone();
                let th = vcpu_thread_handles.clone();
                let ids = hv_vcpu_ids.clone();
                let uart = pl011.clone();
                let hvc_fds_clone = self.hvc_blk_fds.clone();
                let senders_placeholder: Option<CpuOnSenders> = None;

                let t = std::thread::Builder::new()
                    .name(format!("hv-vcpu-{i}"))
                    .spawn(move || match rx.recv() {
                        Ok(req) => {
                            tracing::info!(
                                "vCPU {i}: received CPU_ON, starting at {:#x}",
                                req.entry_point
                            );
                            vcpu_run_loop(
                                i,
                                req.entry_point,
                                req.context_id,
                                VcpuContext {
                                    device_manager: dm,
                                    running: r,
                                    paused: p,
                                    pl011: uart,
                                    cpu_on_senders: senders_placeholder,
                                    vcpu_thread_handles: th,
                                    hv_vcpu_ids: ids,
                                    hvc_blk_fds: hvc_fds_clone,
                                },
                            );
                        }
                        Err(_) => {
                            tracing::debug!("vCPU {i}: channel closed, never started");
                        }
                    })
                    .map_err(|e| VmmError::Vcpu(format!("spawn vcpu-{i}: {e}")))?;
                self.hv_vcpu_threads.push(t);
            }

            let senders = Arc::new(Mutex::new(senders_vec));
            self.hv_cpu_on_senders = Some(senders.clone());
            Some(senders)
        } else {
            None
        };

        // --- Spawn BSP (vCPU 0) ---
        let hvc_blk_fds = self.hvc_blk_fds.clone();
        let bsp_hv_vcpu_ids = hv_vcpu_ids;
        {
            let t = std::thread::Builder::new()
                .name("hv-vcpu-0".to_string())
                .spawn(move || {
                    vcpu_run_loop(
                        0,
                        kernel_entry,
                        fdt_addr,
                        VcpuContext {
                            device_manager,
                            running,
                            paused,
                            pl011,
                            cpu_on_senders,
                            vcpu_thread_handles,
                            hv_vcpu_ids: bsp_hv_vcpu_ids,
                            hvc_blk_fds,
                        },
                    );
                })
                .map_err(|e| VmmError::Vcpu(format!("spawn vcpu-0: {e}")))?;
            self.hv_vcpu_threads.push(t);
        }

        tracing::info!(
            "Custom HV VMM started: {} vCPU(s) (BSP running, {} secondary parked)",
            vcpu_count,
            vcpu_count.saturating_sub(1)
        );
        Ok(())
    }

    /// Stops the HV backend by signaling vCPU threads and cleaning up resources.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn stop_darwin_hv(&mut self) -> Result<()> {
        // Signal all vCPU threads to exit.
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);

        // Drop the PSCI CPU_ON channel senders. Secondary vCPU threads
        // spawn with `rx.recv()` waiting for a CPU_ON request; when the
        // guest only brought up the BSP they stay parked indefinitely.
        // Dropping the senders makes their `recv()` return `Err(RecvError)`
        // so they exit the recv and hit the `running=false` check. See
        // ABX-364 — before this drop the secondary vCPU join could take
        // 20+ seconds.
        self.hv_cpu_on_senders.take();

        // Drop block-I/O worker senders so `rx.recv()` in
        // `blk_io_worker_loop` returns `Err(RecvError)` and the workers
        // exit cleanly. The senders live on the `DeviceManager` via
        // `BlkWorkerHandle`; clearing the map releases our last
        // reference. ABX-364.
        if let Some(ref dm) = self.hv_device_manager {
            dm.clear_blk_workers();
        }

        // Drive every vCPU thread to exit. `hv_vcpus_exit` needs a concrete
        // list of vCPU IDs on arm64 (see ABX-367); we snapshot the ID
        // registry once up front because all vCPUs have been created by the
        // time stop runs. A single well-formed cancel is normally enough,
        // but we loop until threads self-exit or a deadline trips, since a
        // vCPU observed outside `vcpu.run()` will pick up the cancel on its
        // next re-entry.
        let vcpu_ids_snapshot: Vec<u64> = self
            .hv_vcpu_ids
            .as_ref()
            .map(|ids| {
                ids.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            })
            .unwrap_or_default();

        // Warn if the snapshot is empty while threads are still alive: this
        // means vCPU threads were spawned before they registered their IDs,
        // so `hv_vcpus_exit` will be a no-op and the loop may spin until the
        // deadline. See ABX-367 regression class.
        if vcpu_ids_snapshot.is_empty() && self.hv_vcpu_threads.iter().any(|t| !t.is_finished()) {
            tracing::warn!(
                "stop_darwin_hv: vCPU ID registry empty; threads may not exit cleanly (ABX-367 regression class)"
            );
        }

        let stop_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut iterations: u32 = 0;
        loop {
            if self
                .hv_vcpu_threads
                .iter()
                .all(std::thread::JoinHandle::is_finished)
            {
                tracing::debug!(
                    "stop_darwin_hv: all vCPU threads finished after {iterations} cancel iterations"
                );
                break;
            }
            if std::time::Instant::now() >= stop_deadline {
                let alive = self
                    .hv_vcpu_threads
                    .iter()
                    .filter(|t| !t.is_finished())
                    .count();
                tracing::warn!(
                    "stop_darwin_hv: {alive} vCPU thread(s) did not exit within 5s after {iterations} cancel iterations, proceeding to join (may block)"
                );
                break;
            }

            iterations += 1;
            if let Some(ref vm) = self.hv_vm {
                if let Err(e) = vm.exit_vcpus(&vcpu_ids_snapshot) {
                    tracing::warn!("hv_vcpus_exit failed (iter {iterations}): {e}");
                }
            }
            if let Some(ref handles) = self.hv_vcpu_thread_handles {
                let guard = handles
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for t in guard.iter() {
                    t.unpark();
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        // Join all vCPU threads — the loop above has either confirmed they
        // are `is_finished()` (join is instant) or we timed out and accept a
        // possible block.
        for t in self.hv_vcpu_threads.drain(..) {
            if let Err(e) = t.join() {
                tracing::warn!("vCPU thread join failed: {e:?}");
            }
        }

        // Join all block I/O worker threads before dropping guest memory.
        // Workers hold GuestMemWriter which references the guest RAM mapping;
        // dropping guest memory first would create a use-after-free.
        for t in self.hv_blk_worker_threads.drain(..) {
            if let Err(e) = t.join() {
                tracing::warn!("blk worker thread join failed: {e:?}");
            }
        }

        // Join the net RX worker (rx-inject or legacy net-io) for the same
        // reason: it also holds GuestMemWriter. The thread polls `running`
        // every POLL_TIMEOUT (1 ms) so it will observe the store above and
        // exit promptly, but we must still wait for it before unmapping
        // guest memory.
        if let Some(ref dm) = self.hv_device_manager {
            if let Some(t) = dm.take_net_rx_worker_handle() {
                if let Err(e) = t.join() {
                    tracing::warn!("net rx worker thread join failed: {e:?}");
                }
            }
        }

        // Cleanup in correct order: DAX → GIC → VM → guest memory.
        //
        // DAX mappers must be drained first because `hv_vm_unmap` must be
        // called while the VM is still alive. `drain_all` calls `hv_vm_unmap`
        // + `munmap` for every active mapping and marks the mapper drained so
        // its `Drop` impl becomes a no-op. After this point it is safe to
        // call `hv_vm_destroy` (via `hv_vm.take()`).
        for mapper in &self.hv_dax_mappers {
            mapper.drain_all();
        }
        self.hv_dax_mappers.clear();

        #[cfg(feature = "gic")]
        {
            self.hv_gic.take();
        }
        self.hv_vm.take();

        // Guest memory must outlive hv_vm so the mapped pages remain valid
        // until hv_vm_destroy completes (taken above).
        self.hv_guest_mem.take();

        tracing::info!("Custom VMM stopped");
        Ok(())
    }

    /// Cooperatively pauses every vCPU thread in the HV backend.
    ///
    /// Sets `hv_paused` and calls `hv_vcpus_exit` to kick all vCPUs out of
    /// their in-progress `vcpu.run()` calls. Each vCPU observes the flag on
    /// its next loop iteration and parks itself. Block, net, and vsock
    /// worker threads are left running — their virtqueue state lives in
    /// guest memory and naturally quiesces once no vCPU is executing.
    ///
    /// Returns immediately after the exit kick; parking is best-effort and
    /// there is no explicit "all vCPUs parked" acknowledgement. Callers
    /// needing synchronous pause semantics must rely on the fact that the
    /// guest cannot observe any externally-visible change once all vCPU
    /// threads are parked.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn pause_darwin_hv(&self) -> Result<()> {
        self.hv_paused
            .store(true, std::sync::atomic::Ordering::SeqCst);

        // Snapshot the registered vCPU IDs and issue a targeted
        // `hv_vcpus_exit`. On arm64 the NULL/0 form is a no-op, so without
        // an explicit list no vCPU actually leaves `vcpu.run()` and pause
        // becomes best-effort in the worst sense — observable pause latency
        // matches the time to the guest's next natural exit (timer tick,
        // MMIO, …). See ABX-367.
        let ids: Vec<u64> = self
            .hv_vcpu_ids
            .as_ref()
            .map(|ids| {
                ids.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            })
            .unwrap_or_default();
        if let Some(ref vm) = self.hv_vm {
            if let Err(e) = vm.exit_vcpus(&ids) {
                tracing::warn!("hv_vcpus_exit during pause failed: {e}");
            }
        }

        tracing::info!("HV VMM paused");
        Ok(())
    }

    /// Resumes every vCPU thread paused by `pause_darwin_hv`.
    ///
    /// Clears `hv_paused` and unparks every registered vCPU thread via
    /// `hv_vcpu_thread_handles`. Each thread wakes from `park()`, re-checks
    /// the flag, and re-enters the run loop.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn resume_darwin_hv(&self) -> Result<()> {
        self.hv_paused
            .store(false, std::sync::atomic::Ordering::SeqCst);

        if let Some(ref handles) = self.hv_vcpu_thread_handles {
            let guard = handles
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for t in guard.iter() {
                t.unpark();
            }
        }

        tracing::info!("HV VMM resumed");
        Ok(())
    }

    /// Connects to a vsock port on the guest VM (HV backend).
    ///
    /// Creates a Unix `SOCK_STREAM` socketpair; one end is returned to the
    /// caller for host-side I/O, the other is registered with
    /// `VsockConnectionManager` so the VirtIO vsock device can relay data
    /// between the socketpair and the guest's RX/TX queues.
    ///
    /// Returns immediately after allocating and enqueueing the connection —
    /// OP_REQUEST injection into the guest RX queue is deferred to
    /// `poll_vsock_rx` running on the vCPU thread. The returned fd is
    /// usable right away; the guest responds with OP_RESPONSE or OP_RST
    /// within one vCPU cycle of injection.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn connect_vsock_hv(&self, port: u32) -> Result<std::os::unix::io::RawFd> {
        // Create a Unix SOCK_STREAM socketpair for bidirectional data.
        let mut fds: [libc::c_int; 2] = [0; 2];
        // SAFETY: `fds` is a valid 2-element array; socketpair writes two
        // fds into it on success.
        let ret =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        if ret != 0 {
            return Err(VmmError::Device(format!(
                "vsock socketpair failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Set non-blocking + cloexec on internal fd (for poll_vsock_rx peek).
        // The daemon-side fd (fds[0]) stays BLOCKING with a receive timeout —
        // tokio's AsyncFd will set O_NONBLOCK when it wraps the fd.
        // SAFETY: `fds[0]` and `fds[1]` are live kernel fds from the
        // socketpair above. fcntl is side-effect-only; none of the branches
        // escape the fds outside this function.
        unsafe {
            // fds[1]: internal end — needs O_NONBLOCK for poll_vsock_rx libc::read.
            let flags = libc::fcntl(fds[1], libc::F_GETFL);
            if flags == -1 {
                return Err(VmmError::Device(format!(
                    "vsock fcntl F_GETFL failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            if libc::fcntl(fds[1], libc::F_SETFL, flags | libc::O_NONBLOCK) == -1 {
                return Err(VmmError::Device(format!(
                    "vsock fcntl F_SETFL O_NONBLOCK failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            // Both ends: FD_CLOEXEC.
            for &fd in &fds {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags == -1 {
                    tracing::warn!(
                        "vsock fcntl F_GETFD failed on fd {fd}: {}",
                        std::io::Error::last_os_error()
                    );
                    continue;
                }
                if libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) == -1 {
                    tracing::warn!(
                        "vsock fcntl F_SETFD FD_CLOEXEC failed on fd {fd}: {}",
                        std::io::Error::last_os_error()
                    );
                }
            }

            // Bump socketpair send/receive buffers so large RPC responses
            // don't hit SO_SNDBUF backpressure on the vsock device's
            // write path. macOS defaults are typically ~8 KiB, which
            // caused silent truncation of DAX read responses > 8 KiB
            // (ABX-365). 1 MiB fits anything the agent currently emits.
            let bufsize: libc::c_int = 1 << 20;
            for &fd in &fds {
                for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
                    if libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        opt,
                        (&raw const bufsize).cast::<libc::c_void>(),
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    ) == -1
                    {
                        tracing::debug!(
                            "vsock setsockopt(opt={opt}, 1MiB) on fd {fd} failed: {}",
                            std::io::Error::last_os_error()
                        );
                    }
                }
            }
        }

        // fds[0] = returned to caller (daemon agent client)
        // fds[1] = internal, owned by VsockConnectionManager
        // SAFETY: Both fds are fresh from socketpair above with sole
        // ownership; wrapping them in OwnedFd is the standard transfer
        // pattern, and OwnedFd's Drop closes them on error paths.
        let host_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: Same as above for the peer fd.
        let internal_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        let dm = self
            .hv_device_manager
            .as_ref()
            .ok_or_else(|| VmmError::Device("DeviceManager not initialized".to_string()))?;

        let guest_cid = self.config.guest_cid.unwrap_or(3) as u64;

        let conns = dm.vsock_connections();
        let (conn_id, connect_rx) = {
            let mut mgr = conns
                .lock()
                .map_err(|e| VmmError::Device(format!("vsock manager lock failed: {e}")))?;
            mgr.allocate(port, guest_cid, internal_fd)
        };

        let min_fd = RawFd::try_from(conn_id.host_port).map_err(|_| {
            VmmError::Device(format!(
                "vsock host_port {} exceeds RawFd range",
                conn_id.host_port
            ))
        })?;
        let host_fd = Self::duplicate_client_vsock_fd(host_fd, min_fd).inspect_err(|_| {
            if let Ok(mut mgr) = conns.lock() {
                mgr.remove(&conn_id);
            }
        })?;

        tracing::info!(
            "HV vsock connect: guest_port={}, host_port={}, host_fd={}",
            port,
            conn_id.host_port,
            host_fd.as_raw_fd(),
        );

        // OP_REQUEST is in backend_rxq. The vCPU BSP thread's poll_vsock_rx
        // will inject it and fire injected_notify. We do NOT block here —
        // the daemon's ping().await handles the timing:
        // - If REQUEST not yet injected: ping timeout (2s) → retry
        // - If injected + RST: read returns EOF → retry
        // - If injected + RESPONSE: read returns data → success
        //
        // The injected_notify channel is kept alive via the VsockConnection's
        // OwnedFd lifetime. When the connection is removed (RST), the sender
        // is dropped, which is fine — we don't read it.
        let _ = connect_rx; // Drop receiver — we don't wait on it.

        Ok(host_fd.into_raw_fd())
    }
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
        // Flag register should always return 0 (TX FIFO not full).
        assert_eq!(uart.read(PL011_BASE + PL011_FR, 4), 0);
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
