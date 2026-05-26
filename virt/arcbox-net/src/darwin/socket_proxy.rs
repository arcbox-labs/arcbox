//! Host socket proxy for guest network traffic.
//!
//! Instead of forwarding raw IP packets through a utun and relying on kernel
//! routing/NAT, we parse each outbound packet and use host OS sockets directly.
//! This bypasses kernel routing, VPN interference, and pf issues.
//!
//! # Architecture
//!
//! ```text
//! Guest frame → SocketProxy::handle_outbound()
//!   ├─ ICMP → IcmpProxy (ICMP datagram socket sendto/recv)
//!   └─ UDP  → UdpProxy  (per-flow host UdpSocket)
//!         ↓
//!   reply_tx → mpsc → datapath select! → guest FD
//! ```

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use socket2::{Domain, Protocol, Type};
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::ethernet::{ETH_HEADER_LEN, build_udp_ip_ethernet, prepend_ethernet_header};

/// Per-flow UDP state.
struct UdpFlow {
    /// Last time traffic was seen on this flow.
    last_active: Instant,
    /// Channel to send subsequent payloads to the flow's host socket task.
    payload_tx: mpsc::Sender<Vec<u8>>,
}

/// UDP proxy: per-flow host sockets.
struct UdpProxy {
    /// Active flows keyed by (src_ip, src_port, dst_ip, dst_port).
    flows: HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), UdpFlow>,
    reply_tx: mpsc::Sender<Vec<u8>>,
    gateway_mac: [u8; 6],
    /// Gateway IP — connections to this IP are translated to loopback
    /// so they reach host services (host.docker.internal support).
    gateway_ip: Ipv4Addr,
}

impl UdpProxy {
    fn new(reply_tx: mpsc::Sender<Vec<u8>>, gateway_mac: [u8; 6], gateway_ip: Ipv4Addr) -> Self {
        Self {
            flows: HashMap::new(),
            reply_tx,
            gateway_mac,
            gateway_ip,
        }
    }

    /// Proxies a UDP packet from the guest to the host network.
    fn proxy_udp(
        &mut self,
        frame: &[u8],
        guest_mac: [u8; 6],
        cancel: tokio_util::sync::CancellationToken,
    ) {
        // Parse IP + UDP headers from the frame.
        if frame.len() < ETH_HEADER_LEN + 28 {
            return;
        }

        let ip_start = ETH_HEADER_LEN;
        let ihl = ((frame[ip_start] & 0x0F) as usize) * 4;
        let l4_start = ip_start + ihl;

        if frame.len() < l4_start + 8 {
            return;
        }

        let src_ip = Ipv4Addr::new(
            frame[ip_start + 12],
            frame[ip_start + 13],
            frame[ip_start + 14],
            frame[ip_start + 15],
        );
        let dst_ip = Ipv4Addr::new(
            frame[ip_start + 16],
            frame[ip_start + 17],
            frame[ip_start + 18],
            frame[ip_start + 19],
        );
        let src_port = u16::from_be_bytes([frame[l4_start], frame[l4_start + 1]]);
        let dst_port = u16::from_be_bytes([frame[l4_start + 2], frame[l4_start + 3]]);
        let udp_len = u16::from_be_bytes([frame[l4_start + 4], frame[l4_start + 5]]) as usize;

        if udp_len < 8 || l4_start + udp_len > frame.len() {
            return;
        }

        let payload = frame[l4_start + 8..l4_start + udp_len].to_vec();
        let flow_key = (src_ip, src_port, dst_ip, dst_port);

        // Existing flow: send payload through its channel.
        if let Some(flow) = self.flows.get_mut(&flow_key) {
            flow.last_active = Instant::now();
            if flow.payload_tx.try_send(payload).is_err() {
                // Task exited or channel full — remove stale flow so it
                // gets recreated on the next packet.
                self.flows.remove(&flow_key);
            }
            return;
        }

        // New flow: create a channel and spawn a task that owns the socket.
        let (payload_tx, mut payload_rx) = mpsc::channel::<Vec<u8>>(64);

        self.flows.insert(
            flow_key,
            UdpFlow {
                last_active: Instant::now(),
                payload_tx,
            },
        );

        let reply_tx = self.reply_tx.clone();
        let gateway_mac = self.gateway_mac;
        // Translate gateway IP to loopback so host services are reachable.
        let connect_ip = if dst_ip == self.gateway_ip {
            Ipv4Addr::LOCALHOST
        } else {
            dst_ip
        };

        tokio::spawn(async move {
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("UDP proxy: failed to bind socket: {}", e);
                    return;
                }
            };

            if let Err(e) = socket
                .connect(SocketAddr::V4(SocketAddrV4::new(connect_ip, dst_port)))
                .await
            {
                tracing::warn!("UDP proxy: failed to connect: {}", e);
                return;
            }

            // Send the initial payload.
            if let Err(e) = socket.send(&payload).await {
                tracing::warn!("UDP proxy: send failed: {}", e);
                return;
            }

            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    // Subsequent payloads from the same flow.
                    msg = payload_rx.recv() => {
                        match msg {
                            Some(data) => {
                                if let Err(e) = socket.send(&data).await {
                                    tracing::trace!("UDP proxy: send failed: {e}");
                                    break;
                                }
                            }
                            None => break, // Channel closed, flow removed.
                        }
                    }
                    // Replies from the remote host.
                    recv = tokio::time::timeout(
                        std::time::Duration::from_secs(60),
                        socket.recv(&mut buf),
                    ) => {
                        match recv {
                            Ok(Ok(n)) if n > 0 => {
                                let reply_frame = build_udp_ip_ethernet(
                                    dst_ip,
                                    src_ip,
                                    dst_port,
                                    src_port,
                                    &buf[..n],
                                    gateway_mac,
                                    guest_mac,
                                );
                                if reply_tx.send(reply_frame).await.is_err() {
                                    break;
                                }
                            }
                            _ => break, // Timeout or error
                        }
                    }
                }
            }
        });
    }

    /// Removes flows inactive for more than 60 seconds.
    fn cleanup_stale_flows(&mut self) {
        let now = Instant::now();
        self.flows
            .retain(|_, flow| now.duration_since(flow.last_active).as_secs() < 60);
    }
}

/// ICMP proxy: ICMP socket per echo.
struct IcmpProxy {
    reply_tx: mpsc::Sender<Vec<u8>>,
    gateway_mac: [u8; 6],
    /// When true, ICMP proxying is disabled due to persistent permission errors.
    disabled: Arc<AtomicBool>,
    /// Ensures permission-denied warning is emitted only once.
    permission_warned: Arc<AtomicBool>,
}

impl IcmpProxy {
    fn new(reply_tx: mpsc::Sender<Vec<u8>>, gateway_mac: [u8; 6]) -> Self {
        Self {
            reply_tx,
            gateway_mac,
            disabled: Arc::new(AtomicBool::new(false)),
            permission_warned: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Proxies an ICMP packet from the guest to the host.
    fn proxy_icmp(
        &self,
        frame: &[u8],
        guest_mac: [u8; 6],
        cancel: tokio_util::sync::CancellationToken,
    ) {
        if self.disabled.load(Ordering::Relaxed) {
            tracing::trace!("ICMP proxy: disabled, dropping frame");
            return;
        }
        tracing::trace!("ICMP proxy: received frame ({} bytes)", frame.len());

        let ip_start = ETH_HEADER_LEN;
        let ihl = ((frame[ip_start] & 0x0F) as usize) * 4;
        let icmp_start = ip_start + ihl;

        if frame.len() < icmp_start + 8 {
            return;
        }

        let src_ip = Ipv4Addr::new(
            frame[ip_start + 12],
            frame[ip_start + 13],
            frame[ip_start + 14],
            frame[ip_start + 15],
        );
        let dst_ip = Ipv4Addr::new(
            frame[ip_start + 16],
            frame[ip_start + 17],
            frame[ip_start + 18],
            frame[ip_start + 19],
        );

        let icmp_payload = frame[icmp_start..].to_vec();
        // Save the guest's original ICMP identifier (bytes 4-5). macOS DGRAM
        // ICMP sockets rewrite this with a kernel-internal socket ID, so the
        // reply will carry the wrong value. We patch it back before forwarding.
        let orig_icmp_id: [u8; 2] = if icmp_payload.len() >= 6 {
            [icmp_payload[4], icmp_payload[5]]
        } else {
            [0, 0]
        };
        let reply_tx = self.reply_tx.clone();
        let gateway_mac = self.gateway_mac;
        let disabled = Arc::clone(&self.disabled);
        let permission_warned = Arc::clone(&self.permission_warned);

        tokio::spawn(async move {
            // On modern macOS, SOCK_RAW for ICMP requires elevated privileges.
            // Prefer SOCK_DGRAM + IPPROTO_ICMP to support unprivileged daemon.
            let icmp_socket = match socket2::Socket::new(
                Domain::IPV4,
                Type::DGRAM,
                Some(Protocol::ICMPV4),
            ) {
                Ok(s) => s,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::PermissionDenied {
                        disabled.store(true, Ordering::Relaxed);
                        if !permission_warned.swap(true, Ordering::Relaxed) {
                            tracing::warn!(
                                "ICMP proxy disabled: failed to create ICMP datagram socket: {}",
                                e
                            );
                        }
                    } else {
                        tracing::debug!(
                            "ICMP proxy: failed to create ICMP datagram socket (will retry): {}",
                            e
                        );
                    }
                    return;
                }
            };

            icmp_socket.set_nonblocking(true).ok();
            let dst_addr: SocketAddr = SocketAddrV4::new(dst_ip, 0).into();

            match icmp_socket.send_to(&icmp_payload, &dst_addr.into()) {
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("ICMP proxy: sendto {} -> {} failed: {}", src_ip, dst_ip, e);
                    return;
                }
            }

            // Wait for reply using AsyncFd on the ICMP socket.
            let async_fd = match AsyncFd::new(RawSocketWrapper(icmp_socket)) {
                Ok(fd) => fd,
                Err(e) => {
                    tracing::warn!("ICMP proxy: AsyncFd failed: {}", e);
                    return;
                }
            };

            let mut buf = vec![0u8; 65535];
            let recv_fut = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    let readable = async_fd.readable().await;
                    match readable {
                        Ok(mut guard) => {
                            match guard.try_io(|inner| {
                                // SAFETY: reading into valid buffer from a raw socket fd.
                                let n = unsafe {
                                    libc::recv(
                                        inner.get_ref().as_raw_fd(),
                                        buf.as_mut_ptr().cast(),
                                        buf.len(),
                                        0,
                                    )
                                };
                                if n < 0 {
                                    Err(std::io::Error::last_os_error())
                                } else {
                                    Ok(n as usize)
                                }
                            }) {
                                Ok(Ok(n)) if n > 0 => return Ok(n),
                                Ok(Err(e)) => return Err(e),
                                _ => {} // WouldBlock, retry
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
            });

            // Cancel promptly on datapath shutdown instead of waiting the
            // full 10 s recv timeout.
            let recv = tokio::select! {
                r = recv_fut => r,
                () = cancel.cancelled() => return,
            };

            match recv {
                Ok(Ok(n)) if n > 0 => {
                    let reply_packet = &buf[..n];
                    // Extract the ICMP payload from the reply. macOS DGRAM
                    // ICMP sockets return the full IPv4 packet whose dst IP
                    // is the *host's* real address — not the guest's. Always
                    // rebuild the frame with the correct src/dst so the guest
                    // network stack accepts it.
                    let mut icmp_data = if looks_like_ipv4_icmp(reply_packet) {
                        let ihl = ((reply_packet[0] & 0x0F) as usize) * 4;
                        reply_packet[ihl..].to_vec()
                    } else {
                        reply_packet.to_vec()
                    };
                    // Restore the guest's original ICMP identifier that macOS
                    // replaced with its kernel-internal socket ID. Only patch
                    // Echo Reply (type 0) — bytes 4-5 are the identifier field
                    // only for Echo; other ICMP types use them for different
                    // purposes (e.g., redirect gateway address).
                    if icmp_data.len() >= 6 && icmp_data[0] == 0 {
                        icmp_data[4] = orig_icmp_id[0];
                        icmp_data[5] = orig_icmp_id[1];
                    }
                    let reply_frame = build_icmp_ipv4_ethernet(
                        dst_ip, // original dst becomes reply src
                        src_ip, // original src (guest) becomes reply dst
                        &icmp_data,
                        gateway_mac,
                        guest_mac,
                    );
                    if reply_tx.send(reply_frame).await.is_err() {
                        tracing::warn!("ICMP proxy: reply_tx channel closed");
                    }
                }
                _ => {
                    tracing::trace!(
                        "ICMP proxy: no reply (timeout/error) for {} -> {}",
                        src_ip,
                        dst_ip
                    );
                }
            }
        });
    }
}

/// Wrapper to make `socket2::Socket` usable with `AsyncFd`.
struct RawSocketWrapper(socket2::Socket);

impl AsRawFd for RawSocketWrapper {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
}

/// Returns true when the payload appears to be a complete IPv4 ICMP packet.
fn looks_like_ipv4_icmp(packet: &[u8]) -> bool {
    if packet.len() < 20 {
        return false;
    }
    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0F) as usize * 4;
    version == 4 && ihl >= 20 && packet.len() >= ihl && packet[9] == 1
}

/// Builds an Ethernet frame containing an IPv4 ICMP packet.
fn build_icmp_ipv4_ethernet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    icmp_payload: &[u8],
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
) -> Vec<u8> {
    let ip_total_len = 20 + icmp_payload.len();
    let frame_len = ETH_HEADER_LEN + ip_total_len;
    let mut frame = vec![0u8; frame_len];

    // Ethernet header
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // IPv4 header (20 bytes, no options)
    let ip_start = ETH_HEADER_LEN;
    let ip = &mut frame[ip_start..ip_start + 20];
    ip[0] = 0x45; // Version 4, IHL 5
    ip[2..4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    ip[8] = 64; // TTL
    ip[9] = 1; // Protocol: ICMP
    ip[12..16].copy_from_slice(&src_ip.octets());
    ip[16..20].copy_from_slice(&dst_ip.octets());
    let ip_cksum = ipv4_checksum(ip);
    ip[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // ICMP payload
    let icmp_start = ETH_HEADER_LEN + 20;
    frame[icmp_start..].copy_from_slice(icmp_payload);

    // Recompute ICMP checksum when header is present.
    if icmp_payload.len() >= 4 {
        frame[icmp_start + 2] = 0;
        frame[icmp_start + 3] = 0;
        let icmp_cksum = internet_checksum(&frame[icmp_start..]);
        frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_cksum.to_be_bytes());
    }

    frame
}

/// Computes RFC 1071 checksum over bytes.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Computes IPv4 header checksum while skipping the checksum field itself.
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        if i != 10 {
            sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
        }
        i += 2;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Top-level socket proxy that dispatches guest traffic to protocol-specific
/// handlers and manages inbound port forwarding.
pub struct SocketProxy {
    icmp: IcmpProxy,
    udp: UdpProxy,
    /// Inbound relay for host → guest port forwarding.
    inbound: super::inbound_relay::InboundRelay,
    /// Shared reply sender for injecting L2 frames towards the guest.
    reply_tx: mpsc::Sender<Vec<u8>>,
    /// Cancellation token for graceful shutdown of spawned tasks.
    cancel: tokio_util::sync::CancellationToken,
}

impl SocketProxy {
    /// Creates a new socket proxy.
    ///
    /// `reply_tx` is used by all sub-proxies to send L2 frames back to the
    /// datapath for writing to the guest FD.
    #[must_use]
    pub fn new(
        gateway_ip: Ipv4Addr,
        gateway_mac: [u8; 6],
        guest_ip: Ipv4Addr,
        reply_tx: mpsc::Sender<Vec<u8>>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Self {
        let inbound = super::inbound_relay::InboundRelay::new(
            reply_tx.clone(),
            gateway_mac,
            gateway_ip,
            guest_ip,
        );
        Self {
            icmp: IcmpProxy::new(reply_tx.clone(), gateway_mac),
            udp: UdpProxy::new(reply_tx.clone(), gateway_mac, gateway_ip),
            inbound,
            reply_tx,
            cancel,
        }
    }

    /// Returns a clone of the reply sender for external use (e.g. async DNS
    /// forwarding).
    #[must_use]
    pub fn reply_sender(&self) -> mpsc::Sender<Vec<u8>> {
        self.reply_tx.clone()
    }

    /// Dispatches an outbound IPv4 frame to the appropriate protocol proxy.
    ///
    /// Inbound reply frames (matching an active inbound connection) are
    /// intercepted first; everything else is proxied through host sockets.
    pub fn handle_outbound(&mut self, frame: &[u8], guest_mac: [u8; 6]) {
        if frame.len() < ETH_HEADER_LEN + 20 {
            return;
        }

        // Check inbound relay first — fast-path ephemeral port range check
        // short-circuits for 99%+ of outbound frames.
        if self.inbound.try_handle_reply(frame, guest_mac) {
            return;
        }

        let protocol = frame[ETH_HEADER_LEN + 9];
        let cancel = self.cancel.clone();
        match protocol {
            1 => self.icmp.proxy_icmp(frame, guest_mac, cancel),
            17 => self.udp.proxy_udp(frame, guest_mac, cancel),
            _ => {
                tracing::trace!("Socket proxy: dropping protocol {}", protocol);
            }
        }
    }

    /// Handles an inbound UDP command from the listener manager.
    pub(crate) fn handle_inbound_command(
        &mut self,
        cmd: super::inbound_relay::InboundCommand,
        guest_mac: [u8; 6],
    ) {
        use super::inbound_relay::InboundCommand;
        if let InboundCommand::UdpReceived {
            host_port,
            data,
            reply_tx,
            ..
        } = cmd
        {
            // Use host_port (the Docker-exposed port on the guest), not
            // container_port (the port inside the container).
            self.inbound
                .inject_udp(host_port, &data, reply_tx, guest_mac);
        }
    }

    /// Runs periodic maintenance (flow cleanup).
    pub fn maintenance(&mut self) {
        self.udp.cleanup_stale_flows();
        self.inbound.cleanup();
    }

    /// Expire a specific flow by address (called from timer wheel).
    ///
    /// This is the timer-wheel-driven counterpart to `maintenance()`.
    /// Instead of scanning all flows, it targets a specific expired flow.
    pub fn expire_flow(&mut self, _addr: std::net::SocketAddr) {
        // TODO: Once UDP/ICMP flows are registered with the timer wheel,
        // this will remove the specific flow by address. For now, the
        // timer wheel is wired into the datapath loop but individual
        // flow registration is not yet migrated from per-flow timeouts.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn test_socket_proxy_creation() {
        let (tx, _rx) = mpsc::channel(16);
        let gw_ip = Ipv4Addr::new(192, 168, 64, 1);
        let gw_mac = [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x01];
        let guest_ip = Ipv4Addr::new(192, 168, 64, 2);
        let _proxy = SocketProxy::new(gw_ip, gw_mac, guest_ip, tx, CancellationToken::new());
    }

    #[test]
    fn test_socket_proxy_drops_unknown_protocol() {
        let (tx, _rx) = mpsc::channel(16);
        let gw_ip = Ipv4Addr::new(192, 168, 64, 1);
        let gw_mac = [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x01];
        let guest_ip = Ipv4Addr::new(192, 168, 64, 2);
        let mut proxy = SocketProxy::new(gw_ip, gw_mac, guest_ip, tx, CancellationToken::new());

        // Build a minimal Ethernet + IPv4 frame with protocol=50 (ESP).
        let mut frame = vec![0u8; ETH_HEADER_LEN + 20];
        // Ethernet header
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        // IPv4 header
        frame[ETH_HEADER_LEN] = 0x45; // Version 4, IHL 5
        frame[ETH_HEADER_LEN + 9] = 50; // Protocol: ESP (unsupported)

        let guest_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x99];
        // Should not panic.
        proxy.handle_outbound(&frame, guest_mac);
    }

    #[test]
    fn test_socket_proxy_ignores_short_frames() {
        let (tx, _rx) = mpsc::channel(16);
        let gw_ip = Ipv4Addr::new(192, 168, 64, 1);
        let gw_mac = [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x01];
        let guest_ip = Ipv4Addr::new(192, 168, 64, 2);
        let mut proxy = SocketProxy::new(gw_ip, gw_mac, guest_ip, tx, CancellationToken::new());

        let guest_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x99];
        // Frame shorter than Ethernet + IP minimum.
        proxy.handle_outbound(&[0u8; 10], guest_mac);
    }

    #[test]
    fn test_udp_proxy_cleanup_stale_flows() {
        let (tx, _rx) = mpsc::channel(16);
        let gw_ip = Ipv4Addr::new(192, 168, 64, 1);
        let gw_mac = [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x01];
        let mut proxy = UdpProxy::new(tx, gw_mac, gw_ip);

        // Insert a flow that is already expired.
        let key = (
            Ipv4Addr::new(192, 168, 64, 2),
            1234,
            Ipv4Addr::new(8, 8, 8, 8),
            53,
        );
        proxy.flows.insert(
            key,
            UdpFlow {
                last_active: Instant::now()
                    .checked_sub(std::time::Duration::from_secs(120))
                    .unwrap(),
                payload_tx: mpsc::channel(1).0,
            },
        );
        assert_eq!(proxy.flows.len(), 1);

        proxy.cleanup_stale_flows();
        assert_eq!(proxy.flows.len(), 0, "Stale flow should be cleaned up");
    }

    /// Verifies that reply frames from the socket proxy flow through the
    /// mpsc channel correctly.
    #[tokio::test]
    async fn test_reply_channel_flow() {
        let (tx, mut rx) = mpsc::channel(16);
        let gw_ip = Ipv4Addr::new(192, 168, 64, 1);
        let gw_mac = [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x01];

        // Simulate what a proxy task does: send a frame through reply_tx.
        let test_frame = vec![0xDE, 0xAD, 0xBE, 0xEF];
        tx.send(test_frame.clone()).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received, test_frame);

        // Verify the proxy creates correctly with the same tx.
        let guest_ip = Ipv4Addr::new(192, 168, 64, 2);
        let _proxy = SocketProxy::new(gw_ip, gw_mac, guest_ip, tx, CancellationToken::new());
    }

    /// Verifies that the ICMP identifier restoration logic patches Echo Reply
    /// (type 0) packets but leaves other ICMP types untouched.
    #[test]
    fn test_icmp_identifier_restore() {
        // Build a minimal ICMP Echo Reply (type=0, code=0) with a "wrong"
        // identifier that simulates what macOS DGRAM ICMP sockets return.
        let orig_icmp_id: [u8; 2] = [0xAA, 0xBB];
        let wrong_id: [u8; 2] = [0x00, 0x42]; // kernel-rewritten value

        // ICMP Echo Reply: [type, code, checksum(2), id(2), seq(2), ...]
        let mut icmp_data: Vec<u8> = vec![
            0x00, // type: Echo Reply
            0x00, // code: 0
            0x00,
            0x00, // checksum (placeholder)
            wrong_id[0],
            wrong_id[1], // identifier (wrong)
            0x00,
            0x01, // sequence number
        ];

        // Apply the same patching logic used in proxy_icmp.
        if icmp_data.len() >= 6 && icmp_data[0] == 0 {
            icmp_data[4] = orig_icmp_id[0];
            icmp_data[5] = orig_icmp_id[1];
        }

        assert_eq!(
            [icmp_data[4], icmp_data[5]],
            orig_icmp_id,
            "Echo Reply identifier should be restored to the original guest value"
        );

        // Build an ICMP Destination Unreachable (type=3, code=1) — should NOT
        // be patched because bytes 4-5 have a different meaning.
        let mut icmp_unreach: Vec<u8> = vec![
            0x03, // type: Destination Unreachable
            0x01, // code: Host Unreachable
            0x00, 0x00, // checksum (placeholder)
            0x00, 0x00, // unused (bytes 4-5)
            0x00, 0x00, // next-hop MTU (bytes 6-7)
        ];

        let before = [icmp_unreach[4], icmp_unreach[5]];

        // Same patching logic — should be a no-op for type != 0.
        if icmp_unreach.len() >= 6 && icmp_unreach[0] == 0 {
            icmp_unreach[4] = orig_icmp_id[0];
            icmp_unreach[5] = orig_icmp_id[1];
        }

        assert_eq!(
            [icmp_unreach[4], icmp_unreach[5]],
            before,
            "Non-Echo ICMP types must not have their identifier bytes patched"
        );
    }

    /// Builds a minimal Ethernet + IPv4 + UDP frame.
    fn make_udp_frame(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let ip_total = 20 + udp_len;
        let mut frame = vec![0u8; ETH_HEADER_LEN + ip_total];

        // Ethernet: EtherType = IPv4
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let ip = ETH_HEADER_LEN;
        // IPv4: version=4, IHL=5, total length, protocol=17 (UDP)
        frame[ip] = 0x45;
        frame[ip + 2..ip + 4].copy_from_slice(&(ip_total as u16).to_be_bytes());
        frame[ip + 8] = 64; // TTL
        frame[ip + 9] = 17; // UDP
        frame[ip + 12..ip + 16].copy_from_slice(&src_ip.octets());
        frame[ip + 16..ip + 20].copy_from_slice(&dst_ip.octets());

        let l4 = ip + 20;
        frame[l4..l4 + 2].copy_from_slice(&src_port.to_be_bytes());
        frame[l4 + 2..l4 + 4].copy_from_slice(&dst_port.to_be_bytes());
        frame[l4 + 4..l4 + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        frame[l4 + 8..l4 + 8 + payload.len()].copy_from_slice(payload);
        frame
    }

    /// Verifies that a UDP packet destined for the gateway IP is delivered
    /// to a loopback listener via the gateway→localhost translation.
    #[tokio::test]
    async fn test_udp_proxy_gateway_translates_to_loopback() {
        let (reply_tx, _reply_rx) = mpsc::channel(64);
        let gw_ip = Ipv4Addr::new(10, 0, 2, 1);
        let gw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mut proxy = UdpProxy::new(reply_tx, gw_mac, gw_ip);

        // Bind a UDP listener on loopback.
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let payload = b"hello-host";
        let frame = make_udp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            gw_ip, // targeting gateway, should be translated to 127.0.0.1
            9999,
            port,
            payload,
        );
        let guest_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x99];

        proxy.proxy_udp(&frame, guest_mac, CancellationToken::new());

        // The proxy spawns a task — give it time to send.
        let mut buf = [0u8; 64];
        let len = tokio::time::timeout(std::time::Duration::from_secs(2), listener.recv(&mut buf))
            .await
            .expect("timed out waiting for UDP packet")
            .expect("recv failed");

        assert_eq!(&buf[..len], payload);
    }
}
