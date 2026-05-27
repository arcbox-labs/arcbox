//! Network datapath creation for the HV backend.
//!
//! Contains `create_hv_network_datapath` (primary NIC1 socketpair + frame
//! classifier datapath) and `create_hv_bridge_nic` (NIC2 vmnet bridge). Both are
//! `impl Vmm` methods that set up socketpairs, configure socket options,
//! and spawn async tasks for frame forwarding.

use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

use super::InlineConnSinkAdapter;
use crate::error::{Result, VmmError};
use crate::vmm::Vmm;

impl Vmm {
    /// Creates the network datapath for the HV backend.
    ///
    /// Sets up a SOCK_DGRAM socketpair. One end is registered with DeviceManager
    /// for VirtioNet TX/RX bridging. The other end feeds NetworkDatapath (the
    /// same stack used by VZ: DHCP, DNS, socket proxy, TCP bridge).
    pub(in crate::vmm) fn create_hv_network_datapath(
        &mut self,
        device_manager: &mut crate::device::DeviceManager,
        primary_net_id: crate::device::DeviceId,
    ) -> Result<()> {
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
        // SAFETY: `fds` is a valid 2-element array; socketpair writes two
        // fds into it on success.
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        if ret != 0 {
            return Err(VmmError::Device(format!(
                "net socketpair failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // fds[0] = HV side (DeviceManager reads/writes raw ethernet frames)
        // fds[1] = datapath side (NetworkDatapath reads/writes)
        // SAFETY: Both fds are fresh from socketpair with sole ownership;
        // wrapping them in OwnedFd is the standard transfer pattern.
        let hv_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: Same as above for the peer fd.
        let host_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        // Set large socket buffers and non-blocking on HV side.
        // SAFETY: `hv_fd` is a live OwnedFd from the socketpair above.
        // `buf_size` lives on the stack for the whole block; setsockopt
        // copies out during the call. fcntl F_SETFL is side-effect-only.
        unsafe {
            let buf_size: libc::c_int = 8 * 1024 * 1024;
            if libc::setsockopt(
                hv_fd.as_raw_fd(),
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
                hv_fd.as_raw_fd(),
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
            let flags = libc::fcntl(hv_fd.as_raw_fd(), libc::F_GETFL, 0);
            if flags == -1 {
                return Err(VmmError::Device(format!(
                    "fcntl F_GETFL failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            if libc::fcntl(hv_fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) == -1 {
                return Err(VmmError::Device(format!(
                    "fcntl F_SETFL O_NONBLOCK failed: {}",
                    std::io::Error::last_os_error()
                )));
            }

            // For AF_UNIX SOCK_DGRAM the receive queue belongs to the
            // *peer*'s side: `write(hv_fd)` delivers into host_fd's
            // recv queue. Without sizing host_fd's SO_RCVBUF, guest→host
            // bulk TX (iperf3 -R, container-to-host flows) hits ENOBUFS
            // at the system default (≈8 KiB) and packets are dropped.
            if libc::setsockopt(
                host_fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&raw const buf_size).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                tracing::warn!(
                    "setsockopt host_fd SO_RCVBUF failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            if libc::setsockopt(
                host_fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw const buf_size).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                tracing::warn!(
                    "setsockopt host_fd SO_SNDBUF failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        // Register the HV-side fd with DeviceManager for TX/RX bridging.
        device_manager.set_net_host_fd(hv_fd.as_raw_fd(), primary_net_id);

        // 2. Cancellation token.
        let cancel = tokio_util::sync::CancellationToken::new();
        self.net_cancel = Some(cancel.clone());

        // 3. Create socket proxy and channels.
        let (reply_tx, reply_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(256);
        let socket_proxy =
            SocketProxy::new(gateway_ip, gateway_mac, guest_ip, reply_tx, cancel.clone());

        self.inbound_listener_manager = Some(InboundListenerManager::new(cmd_tx));

        // 4. Create DHCP + DNS.
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

        // 5. Build and spawn the datapath.
        let net_mtu = arcbox_net::darwin::classifier::ENHANCED_ETHERNET_MTU;
        let mut datapath = NetworkDatapath::new(
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

        // Create bounded channel for RX frame injection. The datapath loop
        // sends frames through the FrameSink; the RxInjectThread (spawned at
        // DRIVER_OK) receives them and writes directly to guest memory.
        let (frame_tx, frame_rx) = crossbeam_channel::bounded::<Vec<u8>>(4096);
        let sink = std::sync::Arc::new(arcbox_net::direct_rx::ChannelFrameSink::new(frame_tx));
        datapath.set_frame_sink(sink);

        // Store the receiving half so DeviceManager can hand it to the
        // RxInjectThread at DRIVER_OK time.
        device_manager.set_rx_inject_channel(frame_rx);

        // Create bounded channel for promoted inline TCP connections.
        // The datapath sends PromotedConn via the ConnSink trait; the
        // adapter converts to InlineConn and forwards to the inject thread.
        let (conn_tx, conn_rx) =
            crossbeam_channel::bounded::<arcbox_net_inject::inline_conn::InlineConn>(256);

        let conn_sink: std::sync::Arc<dyn arcbox_net::direct_rx::ConnSink> =
            std::sync::Arc::new(InlineConnSinkAdapter { tx: conn_tx });
        datapath.set_conn_sink(conn_sink);

        device_manager.set_inline_conn_channel(conn_rx);

        let runtime = tokio::runtime::Handle::try_current().map_err(|e| {
            VmmError::Device(format!(
                "tokio runtime not available for network datapath: {e}"
            ))
        })?;

        runtime.spawn(async move {
            if let Err(e) = datapath.run().await {
                tracing::error!("HV network datapath exited with error: {}", e);
            }
        });

        // Keep the HV-side fd alive for VM lifetime.
        self.hv_net_fd = Some(hv_fd);

        tracing::info!(
            "HV network datapath: gateway={}, guest={}, MTU={}",
            gateway_ip,
            guest_ip,
            net_mtu,
        );
        Ok(())
    }

    /// Creates the bridge NIC (NIC2) backed by vmnet.framework for container
    /// IP routing. The vmnet interface runs in Shared (NAT) mode, providing a
    /// macOS bridge interface (e.g., bridge101) that the host route reconciler
    /// can target with `route add 172.16.0.0/12 → bridge101`.
    ///
    /// Data path: vmnet <-> VmnetRelay (async) <-> socketpair <-> DeviceManager <-> Guest NIC2.
    #[cfg(feature = "vmnet")]
    pub(in crate::vmm) fn create_hv_bridge_nic(
        &mut self,
        device_manager: &mut crate::device::DeviceManager,
        memory_manager: &mut crate::memory::MemoryManager,
        irq_chip: &crate::irq::IrqChip,
    ) -> Result<()> {
        use arcbox_vmnet::{Vmnet, VmnetConfig, VmnetRelay};

        // Parse MAC from config (stable per VM for bridge FDB lookup).
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

        let vmnet_mac = info.mac;
        tracing::info!(
            mac = arcbox_net::darwin::format_mac(&vmnet_mac),
            mtu = info.mtu,
            "HV bridge NIC: vmnet interface created"
        );

        // Create socketpair for the relay (same pattern as NIC1).
        let mut fds: [libc::c_int; 2] = [0; 2];
        // SAFETY: `fds` is a valid 2-element array; socketpair writes two
        // fds into it on success.
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        if ret != 0 {
            return Err(VmmError::Device(format!(
                "socketpair for vmnet bridge failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // fds[0] = HV side (DeviceManager reads/writes bridge frames)
        // fds[1] = relay side (VmnetRelay forwards to vmnet)
        // SAFETY: Both fds are fresh from socketpair with sole ownership.
        let hv_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: Same as above for the peer fd.
        let relay_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        // Set large buffers + non-blocking on HV side.
        // SAFETY: `hv_fd` is a live OwnedFd from the socketpair above.
        // `buf_size` lives on the stack for the whole block; setsockopt
        // copies out during the call. fcntl F_SETFL is side-effect-only.
        unsafe {
            let buf_size: libc::c_int = 8 * 1024 * 1024;
            if libc::setsockopt(
                hv_fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw const buf_size).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                tracing::warn!(
                    "bridge setsockopt SO_SNDBUF failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            if libc::setsockopt(
                hv_fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&raw const buf_size).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                tracing::warn!(
                    "bridge setsockopt SO_RCVBUF failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            let flags = libc::fcntl(hv_fd.as_raw_fd(), libc::F_GETFL, 0);
            if flags == -1 {
                return Err(VmmError::Device(format!(
                    "bridge fcntl F_GETFL failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            if libc::fcntl(hv_fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) == -1 {
                return Err(VmmError::Device(format!(
                    "bridge fcntl F_SETFL O_NONBLOCK failed: {}",
                    std::io::Error::last_os_error()
                )));
            }

            // AF_UNIX SOCK_DGRAM buffers live on the *peer*'s side: the
            // guest→host direction (DeviceManager write → relay_fd read)
            // needs relay_fd's SO_RCVBUF sized. Without this, bulk guest
            // TX on the bridge NIC hits ENOBUFS at the system default
            // (≈8 KiB) and drops packets.
            if libc::setsockopt(
                relay_fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&raw const buf_size).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                tracing::warn!(
                    "bridge setsockopt relay_fd SO_RCVBUF failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            if libc::setsockopt(
                relay_fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw const buf_size).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                tracing::warn!(
                    "bridge setsockopt relay_fd SO_SNDBUF failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        // Register the bridge VirtioNet device with the vmnet MAC.
        let net_config = arcbox_virtio::net::NetConfig {
            mac: vmnet_mac,
            ..Default::default()
        };
        let bridge_dev = arcbox_virtio::net::VirtioNet::new(net_config);
        let (bridge_device_id, bridge_arc) = device_manager.register_virtio_device(
            crate::device::DeviceType::VirtioNet,
            "virtio-net-bridge",
            bridge_dev,
            memory_manager,
            irq_chip,
        )?;
        // Hand DeviceManager the typed handle so hot-path methods can reach
        // the concrete VirtioNet without a HashMap lookup + dyn dispatch.
        device_manager.set_bridge_net(bridge_device_id, bridge_arc);

        // Wire the bridge fd to the DeviceManager.
        device_manager.set_bridge_host_fd(hv_fd.as_raw_fd(), bridge_device_id);

        // Spawn vmnet relay task.
        let cancel = tokio_util::sync::CancellationToken::new();
        let relay = VmnetRelay::new(std::sync::Arc::clone(&vmnet), cancel.clone());

        let runtime = tokio::runtime::Handle::try_current().map_err(|e| {
            VmmError::Device(format!("tokio runtime not available for vmnet relay: {e}"))
        })?;

        runtime.spawn(async move {
            if let Err(e) = relay.run(relay_fd).await {
                tracing::error!("HV vmnet relay exited with error: {e}");
            }
        });

        // Store state for cleanup (reuses the same Vmm fields as VZ path).
        self.vmnet_bridge = Some(vmnet);
        self.vmnet_relay_cancel = Some(cancel);
        self.hv_bridge_net_fd = Some(hv_fd);

        tracing::info!("HV bridge NIC (NIC2) ready: vmnet relay running");
        Ok(())
    }
}
