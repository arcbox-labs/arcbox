use std::sync::{Arc, Mutex};

use arcbox_hv::{HvVm, MemoryPermission};
use linux_loader::loader::{KernelLoader as LinuxKernelLoader, pe::PE};
use vm_fdt::FdtWriter;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryRegion};

use crate::boot::arm64;
use crate::device::DeviceType;
use crate::error::{Result, VmmError};
use crate::irq::IrqChip;
#[cfg(feature = "gic")]
use crate::irq::{Gsi, IrqTriggerCallback};
use crate::vmm::darwin_hv::pl011::{PL011_BASE, PL011_SIZE};

use super::*;

/// Fills `buf` with fresh entropy from the host CSPRNG for the FDT boot seeds
/// (`rng-seed`, `kaslr-seed`). Fails fast: a weak or absent boot seed is a real
/// security regression, so we propagate the error rather than seed with a
/// predictable value.
fn read_boot_entropy(buf: &mut [u8]) -> Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .map_err(|e| VmmError::Memory(format!("FDT seed: reading /dev/urandom failed: {e}")))
}

impl Vmm {
    /// Custom VMM initialization using Hypervisor.framework (manual execution).
    ///
    /// This path is an alternative to `initialize_darwin()` (VZ framework).
    /// It creates a VM via `arcbox-hv`, allocates guest RAM, sets up GIC,
    /// registers VirtIO devices, generates an FDT, and prepares vCPU state
    /// for boot.
    pub(in crate::vmm) fn initialize_darwin_hv(&mut self) -> Result<()> {
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
            let unpark_broadcasts = self.hv_unpark_broadcasts.clone();
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
                            unpark_broadcasts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
            let mut console = arcbox_virtio::console::VirtioConsole::new(
                arcbox_virtio::console::ConsoleConfig::default(),
            );

            // Optional interactive debug console: wire a bidirectional
            // Unix-socket backend so an operator can attach a shell even when
            // early boot hangs before networking. The RX worker that injects
            // operator input is spawned later, once the shared DeviceManager
            // Arc and vCPU IDs are available.
            let debug_socket = match &self.config.debug_console_socket {
                Some(path) => match arcbox_virtio::console::SocketConsole::new(path) {
                    Ok(sock) => {
                        let sock = Arc::new(Mutex::new(sock));
                        let io: Arc<Mutex<dyn arcbox_virtio::console::ConsoleIo>> = sock.clone();
                        console.set_io(io);
                        tracing::warn!(
                            socket = %path.display(),
                            "interactive debug console enabled \
                             (attach: socat - UNIX-CONNECT:<socket>)"
                        );
                        Some(sock)
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            socket = %path.display(),
                            "failed to create debug console socket; continuing without it"
                        );
                        None
                    }
                },
                None => None,
            };

            let (_console_id, console_arc) = device_manager.register_virtio_device(
                DeviceType::VirtioConsole,
                "virtio-console",
                console,
                &mut memory_manager,
                &irq_chip,
            )?;

            if let Some(sock) = debug_socket {
                device_manager.set_console(console_arc);
                device_manager.set_debug_console_socket(sock);
            }
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
            let capacity_sectors = blk.capacity_bytes() / u64::from(blk_size);
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
                    device_id,
                    raw_fd,
                    blk_size,
                    capacity_sectors,
                    read_only,
                    dev_id_str,
                    num_queues,
                ));
            }
        }

        // Build HVC fast-path fd table from all block devices.
        // device_idx 0 = first block device (vda), 1 = second (vdb), etc.
        {
            let fds: Vec<(i32, u32, u64)> = self
                .hv_blk_devices
                .iter()
                .map(|(_, raw_fd, blk_size, capacity_sectors, _, _, _)| {
                    (*raw_fd, *blk_size, *capacity_sectors)
                })
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
            // Seed the guest's entropy pool and KASLR from the host CSPRNG.
            // Without rng-seed the guest CRNG initializes late (it otherwise
            // blocks until virtio-rng feeds it); without kaslr-seed the kernel
            // gets no early KASLR entropy. VZ's bootloader supplies both.
            let mut rng_seed = [0u8; 64];
            read_boot_entropy(&mut rng_seed)?;
            fdt.property("rng-seed", &rng_seed).map_err(fdt_err)?;
            let mut kaslr = [0u8; 8];
            read_boot_entropy(&mut kaslr)?;
            fdt.property_u64("kaslr-seed", u64::from_le_bytes(kaslr))
                .map_err(fdt_err)?;
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
}
