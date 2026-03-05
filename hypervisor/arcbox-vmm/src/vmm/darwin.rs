//! Darwin (macOS) platform-specific VMM implementation.
//!
//! Uses Apple's Virtualization.framework for managed VM execution.

use super::*;

use arcbox_hypervisor::darwin::DarwinVm;
use arcbox_hypervisor::traits::VirtualMachine;
use tokio_util::sync::CancellationToken;

impl Vmm {
    /// Darwin-specific initialization using Virtualization.framework.
    pub(super) fn initialize_darwin(&mut self) -> Result<()> {
        use arcbox_hypervisor::VirtioDeviceConfig;
        use arcbox_hypervisor::darwin::DarwinHypervisor;
        use arcbox_hypervisor::traits::Hypervisor;

        let hypervisor = DarwinHypervisor::new()?;
        tracing::debug!("Platform capabilities: {:?}", hypervisor.capabilities());

        let vm_config = self.config.to_vm_config();
        let mut vm = hypervisor.create_vm(vm_config)?;

        // Check if this is managed execution
        self.managed_execution = vm.is_managed_execution();
        tracing::info!("Using managed execution mode: {}", self.managed_execution);

        // Add VirtioFS devices for shared directories
        for shared_dir in &self.config.shared_dirs {
            let device_config = VirtioDeviceConfig::filesystem(
                shared_dir.host_path.to_string_lossy(),
                &shared_dir.tag,
                shared_dir.read_only,
            );
            vm.add_virtio_device(device_config)?;
            tracing::info!(
                "Added VirtioFS share: {} -> {} (read_only: {})",
                shared_dir.tag,
                shared_dir.host_path.display(),
                shared_dir.read_only
            );
        }

        // Add block devices
        for block_dev in &self.config.block_devices {
            let device_config =
                VirtioDeviceConfig::block(block_dev.path.to_string_lossy(), block_dev.read_only);
            vm.add_virtio_device(device_config)?;
            tracing::info!(
                "Added block device: {} (read_only: {})",
                block_dev.path.display(),
                block_dev.read_only
            );
        }

        // Add networking if enabled.
        //
        // We try to set up a custom network stack using
        // VZFileHandleNetworkDeviceAttachment (socketpair) so that all
        // network traffic (ARP, DHCP, DNS, NAT) flows through our own
        // code. If any step fails, fall back to Apple's built-in NAT.
        if self.config.networking {
            match self.create_network_device() {
                Ok(net_config) => {
                    vm.add_virtio_device(net_config)?;
                }
                Err(e) => {
                    tracing::warn!(
                        "Custom network stack unavailable, falling back to Apple NAT: {}",
                        e
                    );
                    let net_config = VirtioDeviceConfig::network();
                    vm.add_virtio_device(net_config)?;
                    tracing::info!("Added network device with Apple NAT");
                }
            }
        }

        // Add vsock if enabled
        if self.config.vsock {
            let vsock_config = VirtioDeviceConfig::vsock();
            vm.add_virtio_device(vsock_config)?;
            tracing::info!("Added vsock device");
        }

        // Add balloon device if enabled
        if self.config.balloon {
            let balloon_config = VirtioDeviceConfig::balloon();
            vm.add_virtio_device(balloon_config)?;
            tracing::info!("Added memory balloon device");
        }

        // Initialize memory manager
        let mut memory_manager = MemoryManager::new();
        memory_manager.initialize(self.config.memory_size)?;

        // Initialize device manager
        let device_manager = DeviceManager::new();

        // Initialize IRQ chip
        let irq_chip = Arc::new(IrqChip::new()?);

        // Set up IRQ callback for Darwin.
        // Virtualization.framework handles VirtIO interrupts internally,
        // so we set up a no-op callback that logs when IRQ is triggered.
        {
            let callback: IrqTriggerCallback = Box::new(|gsi: Gsi, level: bool| {
                // Darwin Virtualization.framework handles VirtIO interrupts internally.
                // For custom devices, interrupt injection is not supported.
                tracing::trace!(
                    "Darwin IRQ callback: gsi={}, level={} (handled by framework)",
                    gsi,
                    level
                );
                Ok(())
            });
            irq_chip.set_trigger_callback(Arc::new(callback));
            tracing::debug!("Darwin: IRQ callback configured (framework-managed)");
        }

        // Initialize event loop
        let event_loop = EventLoop::new()?;

        // Store managers
        self.memory_manager = Some(memory_manager);
        self.device_manager = Some(device_manager);
        self.irq_chip = Some(irq_chip);
        self.event_loop = Some(event_loop);

        // For managed execution, we don't create vCPU threads
        // Instead, store the VM for lifecycle management
        if self.managed_execution {
            tracing::debug!("Managed execution: skipping vCPU thread creation");
            self.managed_vm = Some(Box::new(vm));
        } else {
            // This shouldn't happen on Darwin, but handle it anyway
            let vcpu_manager = VcpuManager::new(self.config.vcpu_count);
            // Note: Darwin vCPUs are placeholders, but we add them anyway
            self.vcpu_manager = Some(vcpu_manager);
        }

        Ok(())
    }

    /// Creates the network device configuration for Darwin.
    ///
    /// Sets up a socketpair for `VZFileHandleNetworkDeviceAttachment` and a
    /// socket proxy that routes guest traffic through host OS sockets. No
    /// utun device or pf NAT is needed — this works in any network environment
    /// including VPNs.
    ///
    /// Returns a `VirtioDeviceConfig` with the VZ-side FDs embedded.
    fn create_network_device(&mut self) -> Result<VirtioDeviceConfig> {
        use arcbox_net::darwin::datapath_loop::NetworkDatapath;
        use arcbox_net::darwin::inbound_relay::InboundListenerManager;
        use arcbox_net::darwin::socket_proxy::SocketProxy;
        use arcbox_net::dhcp::{DhcpConfig, DhcpServer};
        use arcbox_net::dns::{DnsConfig, DnsForwarder};
        use std::net::Ipv4Addr;

        let gateway_ip = Ipv4Addr::new(192, 168, 64, 1);
        let guest_ip = Ipv4Addr::new(192, 168, 64, 2);
        let netmask = Ipv4Addr::new(255, 255, 255, 0);
        let gateway_mac: [u8; 6] = [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x01];

        // 1. Create a SOCK_DGRAM socketpair for L2 Ethernet frame exchange.
        let mut fds: [libc::c_int; 2] = [0; 2];
        // SAFETY: socketpair with valid parameters.
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        if ret != 0 {
            return Err(VmmError::Device(format!(
                "socketpair failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // fds[0] = VZ framework side (read guest tx, write guest rx)
        // fds[1] = host datapath side
        //
        // SAFETY: fds are valid file descriptors returned by socketpair.
        let vz_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: fds are valid file descriptors returned by socketpair.
        let host_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        // Set a large socket buffer for the VZ side to avoid drops.
        // SAFETY: setsockopt with valid fd and parameters.
        let buf_size: libc::c_int = 2 * 1024 * 1024;
        unsafe {
            libc::setsockopt(
                vz_fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw const buf_size).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            libc::setsockopt(
                vz_fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&raw const buf_size).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        // 2. Create the socket proxy, reply channel, and inbound command channel.
        let (reply_tx, reply_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(64);
        let socket_proxy = SocketProxy::new(gateway_ip, gateway_mac, guest_ip, reply_tx);

        // Create the inbound listener manager for port forwarding.
        self.inbound_listener_manager = Some(InboundListenerManager::new(cmd_tx));

        tracing::info!(
            "Custom network stack: socket proxy (gateway={}, guest={})",
            gateway_ip,
            guest_ip,
        );

        // 3. Create the network stack components.
        let dhcp_config = DhcpConfig::new(gateway_ip, netmask)
            .with_pool_range(guest_ip, Ipv4Addr::new(192, 168, 64, 254))
            .with_dns_servers(vec![gateway_ip]);
        let dhcp_server = DhcpServer::new(dhcp_config);

        let dns_config = DnsConfig::new(gateway_ip);
        let dns_forwarder = DnsForwarder::new(dns_config);

        // 4. Build the datapath and spawn it on the tokio runtime.
        let cancel = CancellationToken::new();
        self.net_cancel = Some(cancel.clone());

        let datapath = NetworkDatapath::new(
            host_fd,
            socket_proxy,
            reply_rx,
            cmd_rx,
            dhcp_server,
            dns_forwarder,
            gateway_ip,
            guest_ip,
            gateway_mac,
            cancel,
        );

        let runtime = tokio::runtime::Handle::try_current().map_err(|e| {
            VmmError::Device(format!(
                "tokio runtime not available for network datapath: {e}"
            ))
        })?;
        runtime.spawn(async move {
            if let Err(e) = datapath.run().await {
                tracing::error!("Network datapath exited with error: {}", e);
            }
        });

        tracing::info!("Network datapath task spawned");

        // 5. Keep ownership of the VZ-side fd for VM lifetime and pass the raw
        // fd into the hypervisor attachment config.
        let vz_raw_fd = vz_fd.as_raw_fd();
        self.net_vz_fd = Some(vz_fd);
        Ok(VirtioDeviceConfig::network_file_handle(vz_raw_fd))
    }

    /// Starts the managed VM.
    pub(super) fn start_managed_vm(&mut self) -> Result<()> {
        if let Some(ref mut managed_vm) = self.managed_vm {
            if let Some(vm) = managed_vm.downcast_mut::<DarwinVm>() {
                vm.start().map_err(VmmError::Hypervisor)?;
            }
        }
        Ok(())
    }

    /// Pauses the managed VM.
    pub(super) fn pause_managed_vm(&mut self) -> Result<()> {
        if let Some(ref mut managed_vm) = self.managed_vm {
            if let Some(vm) = managed_vm.downcast_mut::<DarwinVm>() {
                vm.pause().map_err(VmmError::Hypervisor)?;
            }
        }
        Ok(())
    }

    /// Resumes the managed VM.
    pub(super) fn resume_managed_vm(&mut self) -> Result<()> {
        if let Some(ref mut managed_vm) = self.managed_vm {
            if let Some(vm) = managed_vm.downcast_mut::<DarwinVm>() {
                vm.resume().map_err(VmmError::Hypervisor)?;
            }
        }
        Ok(())
    }

    /// Stops the managed VM.
    pub(super) fn stop_managed_vm(&mut self) -> Result<()> {
        if let Some(ref mut managed_vm) = self.managed_vm {
            if let Some(vm) = managed_vm.downcast_mut::<DarwinVm>() {
                vm.stop().map_err(VmmError::Hypervisor)?;
            }
        }
        Ok(())
    }

    /// Cancels the custom file-handle network datapath and releases VZ-side fd.
    pub(super) fn stop_network(&mut self) {
        if let Some(cancel) = self.net_cancel.take() {
            cancel.cancel();
        }
        let _ = self.net_vz_fd.take();
    }

    /// Requests graceful guest shutdown via ACPI and waits for it to stop.
    ///
    /// Returns `Ok(true)` if the VM stopped, `Ok(false)` on timeout or when
    /// graceful stop is unavailable.
    pub fn request_stop(&self, timeout: Duration) -> Result<bool> {
        if self.state != VmmState::Running {
            return Ok(false);
        }

        let vm = self
            .managed_vm
            .as_ref()
            .and_then(|managed_vm| managed_vm.downcast_ref::<DarwinVm>())
            .ok_or_else(|| VmmError::invalid_state("no managed DarwinVm".to_string()))?;

        vm.request_stop_and_wait(timeout)
            .map_err(VmmError::Hypervisor)
    }

    /// Connects to a vsock port on the guest VM.
    pub fn connect_vsock(&self, port: u32) -> Result<std::os::unix::io::RawFd> {
        if self.state != VmmState::Running {
            return Err(VmmError::invalid_state(format!(
                "cannot connect vsock: VMM is {:?}",
                self.state
            )));
        }

        if let Some(ref managed_vm) = self.managed_vm {
            if let Some(vm) = managed_vm.downcast_ref::<DarwinVm>() {
                return vm.connect_vsock(port).map_err(VmmError::Hypervisor);
            }
        }

        Err(VmmError::invalid_state(
            "vsock not available in manual execution mode".to_string(),
        ))
    }

    /// Reads serial console output from a managed VM.
    pub fn read_console_output(&self) -> Result<String> {
        if let Some(ref managed_vm) = self.managed_vm {
            if let Some(vm) = managed_vm.downcast_ref::<DarwinVm>() {
                return vm.read_console_output().map_err(VmmError::Hypervisor);
            }
        }

        Ok(String::new())
    }

    /// Sets the target memory size for the balloon device.
    ///
    /// The balloon device will inflate or deflate to reach the target:
    /// - **Smaller target**: Balloon inflates, reclaiming memory from guest
    /// - **Larger target**: Balloon deflates, returning memory to guest
    pub fn set_balloon_target(&self, target_bytes: u64) -> Result<()> {
        if self.state != VmmState::Running {
            return Err(VmmError::invalid_state(format!(
                "cannot set balloon target: VMM is {:?}",
                self.state
            )));
        }

        if let Some(ref managed_vm) = self.managed_vm {
            if let Some(vm) = managed_vm.downcast_ref::<DarwinVm>() {
                return vm
                    .set_balloon_target_memory(target_bytes)
                    .map_err(VmmError::Hypervisor);
            }
        }

        Err(VmmError::invalid_state(
            "balloon not available in manual execution mode".to_string(),
        ))
    }

    /// Gets the current target memory size from the balloon device.
    ///
    /// Returns the target memory size in bytes, or 0 if no balloon is configured
    /// or the VM is not running.
    #[must_use]
    pub fn get_balloon_target(&self) -> u64 {
        if self.state != VmmState::Running {
            return 0;
        }

        if let Some(ref managed_vm) = self.managed_vm {
            if let Some(vm) = managed_vm.downcast_ref::<DarwinVm>() {
                return vm.get_balloon_target_memory();
            }
        }

        0
    }

    /// Gets balloon statistics.
    ///
    /// Returns current balloon stats including target, current, and configured memory sizes.
    #[must_use]
    pub fn get_balloon_stats(&self) -> arcbox_hypervisor::BalloonStats {
        arcbox_hypervisor::BalloonStats {
            target_bytes: self.get_balloon_target(),
            current_bytes: 0, // macOS doesn't expose current balloon size
            configured_bytes: self.config.memory_size,
        }
    }

    /// Returns a mutable reference to the inbound listener manager.
    pub const fn inbound_listener_manager(
        &mut self,
    ) -> Option<&mut arcbox_net::darwin::inbound_relay::InboundListenerManager> {
        self.inbound_listener_manager.as_mut()
    }

    /// Takes the inbound listener manager out of the VMM.
    ///
    /// After this call, the VMM no longer owns the manager. The caller is
    /// responsible for calling `stop_all()` on shutdown.
    pub const fn take_inbound_listener_manager(
        &mut self,
    ) -> Option<arcbox_net::darwin::inbound_relay::InboundListenerManager> {
        self.inbound_listener_manager.take()
    }

    /// Captures a VM snapshot context from the running Darwin VM.
    pub(super) fn capture_snapshot_darwin(
        &self,
    ) -> Option<Result<crate::snapshot::VmSnapshotContext>> {
        use arcbox_hypervisor::traits::{GuestMemory, VirtualMachine};

        let managed_vm = self.managed_vm.as_ref()?;
        let vm = managed_vm.downcast_ref::<DarwinVm>()?;

        let device_snapshots = match vm.snapshot_devices() {
            Ok(s) => s,
            Err(e) => return Some(Err(e.into())),
        };
        let memory_size = vm.memory().size();
        let memory_len = match usize::try_from(memory_size) {
            Ok(l) => l,
            Err(_) => {
                return Some(Err(VmmError::Memory(format!(
                    "guest memory size {} does not fit in usize",
                    memory_size
                ))));
            }
        };

        let mut memory = vec![0u8; memory_len];
        if let Err(e) = vm.memory().dump_all(&mut memory) {
            return Some(Err(e.into()));
        }

        let memory_len = memory.len();
        let memory_reader = Box::new(move |buf: &mut [u8]| {
            if buf.len() != memory_len {
                return Err(crate::snapshot::SnapshotError::Internal(format!(
                    "snapshot buffer size mismatch: expected {}, got {}",
                    memory_len,
                    buf.len()
                )));
            }
            buf.copy_from_slice(&memory);
            Ok(())
        });

        Some(Ok(crate::snapshot::VmSnapshotContext {
            vcpu_snapshots: placeholder_vcpu_snapshots(self.config.vcpu_count),
            device_snapshots,
            memory_size,
            memory_reader,
        }))
    }

    /// Restores snapshot data to the running Darwin VM.
    pub(super) fn restore_snapshot_darwin(
        &mut self,
        restore_data: &crate::snapshot::VmRestoreData,
    ) -> Option<Result<()>> {
        use arcbox_hypervisor::traits::{GuestMemory, VirtualMachine};

        let managed_vm = self.managed_vm.as_mut()?;
        let vm = managed_vm.downcast_mut::<DarwinVm>()?;

        if let Err(e) = vm.restore_devices(restore_data.device_snapshots()) {
            return Some(Err(e.into()));
        }
        if let Err(e) = vm.memory().write(
            arcbox_hypervisor::GuestAddress::new(0),
            restore_data.memory(),
        ) {
            return Some(Err(e.into()));
        }

        if restore_data
            .vcpu_snapshots()
            .iter()
            .any(|s| !s.is_placeholder())
        {
            return Some(Err(VmmError::invalid_state(
                "vCPU register restore is not yet supported; snapshot contains non-placeholder vCPU state".to_string(),
            )));
        }

        Some(Ok(()))
    }
}
