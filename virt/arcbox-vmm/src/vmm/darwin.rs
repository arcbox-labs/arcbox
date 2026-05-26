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

        tracing::info!(
            "Using managed execution mode: {}",
            vm.is_managed_execution()
        );

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

        // Add Rosetta x86_64 translation share if enabled (best-effort).
        if self.config.enable_rosetta {
            if let Err(e) = vm.add_rosetta_share() {
                tracing::warn!(
                    "Rosetta share setup failed, continuing without x86_64 translation: {e}"
                );
            }
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

        // Add a second NIC for host→container L3 routing.
        //
        // With the `vmnet` feature: create a vmnet.framework interface directly,
        // relay it through a socketpair, and use VZFileHandleNetworkDeviceAttachment.
        // Bridge discovery is instant (no FDB learning delay).
        //
        // Without: use VZNATNetworkDeviceAttachment (Apple creates bridge100,
        // requiring FDB scanning to discover it).
        if self.config.networking {
            #[cfg(feature = "vmnet")]
            {
                match self.create_vmnet_bridge_nic() {
                    Ok(bridge_nic) => {
                        vm.add_virtio_device(bridge_nic)?;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "vmnet bridge NIC failed, falling back to VZNATNetworkDeviceAttachment: {e}"
                        );
                        let bridge_nic = match self.config.bridge_nic_mac.as_deref() {
                            Some(mac_address) => VirtioDeviceConfig::network_with_mac(mac_address),
                            None => VirtioDeviceConfig::network(),
                        };
                        vm.add_virtio_device(bridge_nic)?;
                    }
                }
            }

            #[cfg(not(feature = "vmnet"))]
            {
                let bridge_nic = match self.config.bridge_nic_mac.as_deref() {
                    Some(mac_address) => VirtioDeviceConfig::network_with_mac(mac_address),
                    None => VirtioDeviceConfig::network(),
                };
                vm.add_virtio_device(bridge_nic)?;
                tracing::info!(
                    mac_address = self.config.bridge_nic_mac.as_deref().unwrap_or("random"),
                    "Added bridge NIC (VZNATNetworkDeviceAttachment) for L3 routing"
                );
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

        // Darwin uses managed execution — store the typed VM handle directly.
        tracing::debug!("Managed execution: skipping vCPU thread creation");
        self.darwin_vm = Some(vm);

        Ok(())
    }

    /// Sets `O_NONBLOCK` and `FD_CLOEXEC` on a raw file descriptor.
    ///
    /// Socketpair fds are blocking and inheritable by default. Setting
    /// `CLOEXEC` prevents leaking them to child processes, and `NONBLOCK`
    /// is required for async I/O via tokio.
    fn set_nonblock_cloexec(fd: libc::c_int) -> Result<()> {
        // SAFETY: fcntl F_GETFD/F_SETFD/F_GETFL/F_SETFL are standard POSIX
        // operations on a valid fd.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags == -1 {
                return Err(VmmError::Device(format!(
                    "fcntl F_GETFD failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            if libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) == -1 {
                return Err(VmmError::Device(format!(
                    "fcntl F_SETFD FD_CLOEXEC failed: {}",
                    std::io::Error::last_os_error()
                )));
            }

            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags == -1 {
                return Err(VmmError::Device(format!(
                    "fcntl F_GETFL failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) == -1 {
                return Err(VmmError::Device(format!(
                    "fcntl F_SETFL O_NONBLOCK failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
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

        let gateway_ip = Ipv4Addr::new(10, 0, 2, 1);
        let guest_ip = Ipv4Addr::new(10, 0, 2, 2);
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

        // Prevent fd inheritance to child processes and enable non-blocking I/O.
        Self::set_nonblock_cloexec(fds[0])?;
        Self::set_nonblock_cloexec(fds[1])?;

        // fds[0] = VZ framework side (read guest tx, write guest rx)
        // fds[1] = host datapath side
        //
        // SAFETY: fds are valid file descriptors returned by socketpair.
        let vz_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: fds are valid file descriptors returned by socketpair.
        let host_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        // Set a large socket buffer for the VZ side to avoid drops.
        // 8 MB accommodates burst traffic (increased from 2 MB).
        // SAFETY: setsockopt with valid fd and parameters.
        let buf_size: libc::c_int = 8 * 1024 * 1024;
        unsafe {
            if libc::setsockopt(
                vz_fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw const buf_size).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                tracing::warn!(
                    "setsockopt SO_SNDBUF failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            if libc::setsockopt(
                vz_fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&raw const buf_size).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                tracing::warn!(
                    "setsockopt SO_RCVBUF failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        // 2. Cancellation token shared by all spawned network tasks.
        let cancel = CancellationToken::new();
        self.net_cancel = Some(cancel.clone());

        // 3. Create the socket proxy, reply channel, and inbound command channel.
        let (reply_tx, reply_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(256);
        let socket_proxy =
            SocketProxy::new(gateway_ip, gateway_mac, guest_ip, reply_tx, cancel.clone());

        // Create the inbound listener manager for port forwarding.
        self.inbound_listener_manager = Some(InboundListenerManager::new(cmd_tx));

        tracing::info!(
            "Custom network stack: socket proxy (gateway={}, guest={})",
            gateway_ip,
            guest_ip,
        );

        // 4. Create the network stack components.
        let dhcp_config = DhcpConfig::new(gateway_ip, netmask)
            .with_pool_range(guest_ip, Ipv4Addr::new(10, 0, 2, 254))
            .with_dns_servers(vec![gateway_ip]);
        let dhcp_server = DhcpServer::new(dhcp_config);

        let dns_config = DnsConfig::new(gateway_ip);
        let dns_forwarder = if let Some(ref shared_table) = self.shared_dns_hosts {
            DnsForwarder::with_shared_hosts(dns_config, std::sync::Arc::clone(shared_table))
        } else {
            DnsForwarder::new(dns_config)
        };

        // 5. Build the datapath and spawn it on the tokio runtime.

        // NOTE(MTU): Hardcoded to 4000 intentionally — our platform target is
        // macOS 14+ Apple Silicon (P0) where VZ's setMaximumTransmissionUnit:
        // always succeeds. On macOS <14 the VZ setter is skipped via
        // respondsToSelector: (see arcbox-vz/device/network.rs), and the VZ
        // device stays at 1500 while the classifier gets 4000. This mismatch
        // would cause frames >1500 to be dropped — acceptable since macOS <14
        // is not a supported target. If macOS <14 support is ever needed,
        // plumb the actual MTU from NetworkDeviceConfiguration::mtu() through
        // the hypervisor abstraction layer.
        let net_mtu = arcbox_net::darwin::classifier::ENHANCED_ETHERNET_MTU;

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
            net_mtu,
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

    /// Creates the bridge NIC via vmnet.framework and a socketpair relay.
    ///
    /// Returns a `VirtioDeviceConfig` with the VZ-side raw fd.
    #[cfg(feature = "vmnet")]
    fn create_vmnet_bridge_nic(&mut self) -> Result<VirtioDeviceConfig> {
        use arcbox_vmnet::{Vmnet, VmnetConfig, VmnetRelay};

        // Parse MAC from config.
        let config = if let Some(ref mac_str) = self.config.bridge_nic_mac {
            let mac = arcbox_net::darwin::parse_mac(mac_str)
                .map_err(|e| VmmError::Device(format!("invalid bridge NIC MAC: {e}")))?;
            VmnetConfig::shared().with_mac(mac)
        } else {
            VmnetConfig::shared()
        };

        let vmnet = std::sync::Arc::new(
            Vmnet::new(config).map_err(|e| VmmError::Device(format!("vmnet start failed: {e}")))?,
        );

        let info = vmnet
            .interface_info()
            .ok_or_else(|| VmmError::Device("vmnet interface_info unavailable".to_string()))?;

        tracing::info!(
            mac = arcbox_net::darwin::format_mac(&info.mac),
            mtu = info.mtu,
            max_packet_size = info.max_packet_size,
            "vmnet bridge NIC created"
        );

        // Create socketpair for the relay.
        let mut fds: [libc::c_int; 2] = [0; 2];
        // SAFETY: socketpair with valid parameters.
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        if ret != 0 {
            return Err(VmmError::Device(format!(
                "socketpair for vmnet bridge failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Prevent fd inheritance to child processes and enable non-blocking I/O.
        Self::set_nonblock_cloexec(fds[0])?;
        Self::set_nonblock_cloexec(fds[1])?;

        // SAFETY: fds are valid from socketpair.
        let vz_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: fds are valid from socketpair.
        let relay_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        // Set large buffers on the VZ side (8 MB, matching primary NIC).
        let buf_size: libc::c_int = 8 * 1024 * 1024;
        // SAFETY: setsockopt with valid fd and parameters.
        unsafe {
            if libc::setsockopt(
                vz_fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw const buf_size).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                tracing::warn!(
                    "setsockopt SO_SNDBUF (vmnet bridge) failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            if libc::setsockopt(
                vz_fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&raw const buf_size).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                tracing::warn!(
                    "setsockopt SO_RCVBUF (vmnet bridge) failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        // Spawn the relay task.
        let cancel = CancellationToken::new();
        let relay = VmnetRelay::new(std::sync::Arc::clone(&vmnet), cancel.clone());

        let runtime = tokio::runtime::Handle::try_current().map_err(|e| {
            VmmError::Device(format!("tokio runtime not available for vmnet relay: {e}"))
        })?;

        runtime.spawn(async move {
            if let Err(e) = relay.run(relay_fd).await {
                tracing::error!("vmnet relay exited with error: {e}");
            }
        });

        tracing::info!("vmnet relay task spawned");

        // Extract MAC string before moving vmnet (info borrows the Arc).
        let mac_str = arcbox_net::darwin::format_mac(&info.mac);

        // Store state for cleanup.
        let vz_raw_fd = vz_fd.as_raw_fd();
        self.vmnet_bridge = Some(vmnet);
        self.vmnet_relay_cancel = Some(cancel);
        self.vmnet_bridge_fd = Some(vz_fd);

        // Pass the vmnet MAC to the VZ-side NIC so bridge FDB lookups match.
        Ok(VirtioDeviceConfig::network_file_handle_with_mac(
            vz_raw_fd, mac_str,
        ))
    }

    /// Starts the Darwin VM.
    pub(super) fn start_darwin_vm(&mut self) -> Result<()> {
        if let Some(ref mut vm) = self.darwin_vm {
            vm.start().map_err(VmmError::Hypervisor)?;
        }
        Ok(())
    }

    /// Pauses the Darwin VM.
    pub(super) fn pause_darwin_vm(&mut self) -> Result<()> {
        if let Some(ref mut vm) = self.darwin_vm {
            vm.pause().map_err(VmmError::Hypervisor)?;
        }
        Ok(())
    }

    /// Resumes the Darwin VM.
    pub(super) fn resume_darwin_vm(&mut self) -> Result<()> {
        if let Some(ref mut vm) = self.darwin_vm {
            vm.resume().map_err(VmmError::Hypervisor)?;
        }
        Ok(())
    }

    /// Stops the Darwin VM.
    pub(super) fn stop_darwin_vm(&mut self) -> Result<()> {
        if let Some(ref mut vm) = self.darwin_vm {
            vm.stop().map_err(VmmError::Hypervisor)?;
        }
        Ok(())
    }

    /// Marks the inner `DarwinVm` to skip its `stop()` call on drop.
    pub(super) fn mark_darwin_vm_skip_stop(&mut self) {
        if let Some(ref mut vm) = self.darwin_vm {
            vm.set_skip_stop_on_drop();
        }
    }

    /// Cancels the custom file-handle network datapath and releases VZ-side fd.
    pub(super) fn stop_network(&mut self) {
        if let Some(cancel) = self.net_cancel.take() {
            cancel.cancel();
        }
        let _ = self.net_vz_fd.take();
        let _ = self.hv_bridge_net_fd.take();

        // Stop vmnet relay and bridge interface.
        #[cfg(feature = "vmnet")]
        {
            if let Some(cancel) = self.vmnet_relay_cancel.take() {
                cancel.cancel();
            }
            let _ = self.vmnet_bridge_fd.take();
            if let Some(vmnet) = self.vmnet_bridge.take() {
                vmnet.stop();
            }
        }
    }

    /// Waits for the guest VM to reach the Stopped state.
    ///
    /// The actual shutdown is initiated by the vsock shutdown RPC at the
    /// `VmManager` layer. This method only polls the hypervisor state.
    ///
    /// Returns `Ok(true)` if the VM stopped within `timeout`, `Ok(false)` on timeout.
    pub fn wait_for_stopped(&self, timeout: Duration) -> Result<bool> {
        if self.state != VmmState::Running {
            return Ok(false);
        }

        let vm = self
            .darwin_vm
            .as_ref()
            .ok_or_else(|| VmmError::invalid_state("no DarwinVm".to_string()))?;

        vm.wait_for_stopped(timeout).map_err(VmmError::Hypervisor)
    }

    /// Connects to a vsock port on the guest VM.
    ///
    /// For the HV backend, this blocks until the vCPU thread has injected
    /// the OP_REQUEST into guest memory (up to 30s). After return, the guest
    /// will respond with RST or RESPONSE — the caller handles both via
    /// read() returning EOF (RST) or data (RESPONSE + subsequent OP_RW).
    ///
    /// For the VZ backend, the fd is immediately usable.
    pub fn connect_vsock(&self, port: u32) -> Result<std::os::unix::io::RawFd> {
        if self.state != VmmState::Running {
            return Err(VmmError::invalid_state(format!(
                "cannot connect vsock: VMM is {:?}",
                self.state
            )));
        }

        match self.resolved_backend {
            Some(ResolvedBackend::Hv) => self.connect_vsock_hv(port),
            _ => {
                let vm = self
                    .darwin_vm
                    .as_ref()
                    .ok_or_else(|| VmmError::invalid_state("no DarwinVm".to_string()))?;
                vm.connect_vsock(port).map_err(VmmError::Hypervisor)
            }
        }
    }

    /// Reads console output (hvc0) from the VM.
    pub fn read_console_output(&self) -> Result<String> {
        if let Some(ref vm) = self.darwin_vm {
            return vm.read_console_output().map_err(VmmError::Hypervisor);
        }

        Ok(String::new())
    }

    /// Reads agent log output (hvc1) from the VM.
    pub fn read_agent_log_output(&self) -> Result<String> {
        if let Some(ref vm) = self.darwin_vm {
            return vm.read_agent_log_output().map_err(VmmError::Hypervisor);
        }

        Ok(String::new())
    }

    /// Sets the target memory size for the balloon device.
    ///
    /// The balloon device will inflate or deflate to reach the target:
    /// - **Smaller target**: Balloon inflates, reclaiming memory from guest
    /// - **Larger target**: Balloon deflates, returning memory to guest
    ///
    /// Dispatches to VZ's `VZVirtioTraditionalMemoryBalloonDevice` on the VZ
    /// backend, or to the in-tree `arcbox-virtio-balloon` device on HV.
    pub fn set_balloon_target(&self, target_bytes: u64) -> Result<()> {
        if self.state != VmmState::Running {
            return Err(VmmError::invalid_state(format!(
                "cannot set balloon target: VMM is {:?}",
                self.state
            )));
        }

        match self.resolved_backend {
            Some(ResolvedBackend::Hv) => {
                let balloon = self
                    .hv_balloon
                    .as_ref()
                    .ok_or_else(|| VmmError::invalid_state("HV balloon not configured"))?;
                // Convert bytes → 4 KiB pages, saturating at u32::MAX.
                let pages = u32::try_from(target_bytes / 4096).unwrap_or(u32::MAX);
                let guard = balloon
                    .lock()
                    .map_err(|e| VmmError::Device(format!("balloon lock poisoned: {e}")))?;
                guard.set_num_pages(pages);
                Ok(())
            }
            Some(ResolvedBackend::Vz) | None => {
                let vm = self
                    .darwin_vm
                    .as_ref()
                    .ok_or_else(|| VmmError::invalid_state("no DarwinVm".to_string()))?;
                vm.set_balloon_target_memory(target_bytes)
                    .map_err(VmmError::Hypervisor)
            }
        }
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

        match self.resolved_backend {
            Some(ResolvedBackend::Hv) => self.hv_balloon.as_ref().map_or(0, |b| {
                b.lock().map_or(0, |g| u64::from(g.num_pages()) * 4096)
            }),
            Some(ResolvedBackend::Vz) | None => self
                .darwin_vm
                .as_ref()
                .map_or(0, DarwinVm::get_balloon_target_memory),
        }
    }

    /// Gets balloon statistics.
    ///
    /// Returns current balloon stats including target, current, and configured memory sizes.
    #[must_use]
    pub fn get_balloon_stats(&self) -> arcbox_hypervisor::BalloonStats {
        let (target_bytes, current_bytes) = match self.resolved_backend {
            Some(ResolvedBackend::Hv) => self.hv_balloon.as_ref().map_or((0, 0), |b| {
                b.lock().map_or((0, 0), |g| {
                    (
                        u64::from(g.num_pages()) * 4096,
                        u64::from(g.actual()) * 4096,
                    )
                })
            }),
            Some(ResolvedBackend::Vz) | None => (self.get_balloon_target(), 0),
        };
        arcbox_hypervisor::BalloonStats {
            target_bytes,
            current_bytes,
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

        let vm = self.darwin_vm.as_ref()?;

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

        let vm = self.darwin_vm.as_mut()?;

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
