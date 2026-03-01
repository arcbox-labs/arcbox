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
}

/// UDP proxy: per-flow host sockets.
struct UdpProxy {
    /// Active flows keyed by (src_ip, src_port, dst_ip, dst_port).
    flows: HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), UdpFlow>,
    reply_tx: mpsc::Sender<Vec<u8>>,
    gateway_mac: [u8; 6],
}

impl UdpProxy {
    fn new(reply_tx: mpsc::Sender<Vec<u8>>, gateway_mac: [u8; 6]) -> Self {
        Self {
            flows: HashMap::new(),
            reply_tx,
            gateway_mac,
        }
    }

    /// Proxies a UDP packet from the guest to the host network.
    fn proxy_udp(&mut self, frame: &[u8], guest_mac: [u8; 6]) {
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

        // Update or create flow.
        if let Some(flow) = self.flows.get_mut(&flow_key) {
            flow.last_active = Instant::now();
        } else {
            self.flows.insert(
                flow_key,
                UdpFlow {
                    last_active: Instant::now(),
                },
            );

            // Spawn a recv task for this flow.
            let reply_tx = self.reply_tx.clone();
            let gateway_mac = self.gateway_mac;

            tokio::spawn(async move {
                let socket = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("UDP proxy: failed to bind socket: {}", e);
                        return;
                    }
                };

                if let Err(e) = socket
                    .connect(SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port)))
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

                // Receive replies and forward them to the guest.
                let mut buf = vec![0u8; 65535];
                loop {
                    let recv = tokio::time::timeout(
                        std::time::Duration::from_secs(60),
                        socket.recv(&mut buf),
                    )
                    .await;

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
            });

            // Return here — the initial payload send happens in the spawned task.
            return;
        }

        // For existing flows, send via a one-shot task.
        let dst = SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port));
        tokio::spawn(async move {
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => return,
            };
            let _ = socket.send_to(&payload, dst).await;
        });
    }

    /// Removes flows inactive for more than 60 seconds.
    fn cleanup_stale_flows(&mut self) {
        let cutoff = Instant::now() - std::time::Duration::from_secs(60);
        self.flows.retain(|_, flow| flow.last_active > cutoff);
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
    fn proxy_icmp(&self, frame: &[u8], guest_mac: [u8; 6]) {
        if self.disabled.load(Ordering::Relaxed) {
            return;
        }

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
        let reply_tx = self.reply_tx.clone();
        let gateway_mac = self.gateway_mac;
        let disabled = Arc::clone(&self.disabled);
        let permission_warned = Arc::clone(&self.permission_warned);

        tokio::spawn(async move {
            // On modern macOS, SOCK_RAW for ICMP requires elevated privileges.
            // Prefer SOCK_DGRAM + IPPROTO_ICMP to support unprivileged daemon.
            let icmp_socket =
                match socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)) {
                    Ok(s) => s,
                    Err(e) => {
                        disabled.store(true, Ordering::Relaxed);
                        if e.kind() == std::io::ErrorKind::PermissionDenied
                            && !permission_warned.swap(true, Ordering::Relaxed)
                        {
                            tracing::warn!(
                                "ICMP proxy disabled: failed to create ICMP datagram socket: {}",
                                e
                            );
                        } else {
                            tracing::debug!(
                                "ICMP proxy disabled: failed to create ICMP datagram socket: {}",
                                e
                            );
                        }
                        return;
                    }
                };

            icmp_socket.set_nonblocking(true).ok();
            let dst_addr: SocketAddr = SocketAddrV4::new(dst_ip, 0).into();

            if let Err(e) = icmp_socket.send_to(&icmp_payload, &dst_addr.into()) {
                tracing::warn!("ICMP proxy: sendto failed: {}", e);
                return;
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
            let recv = tokio::time::timeout(std::time::Duration::from_secs(10), async {
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
                                _ => continue, // WouldBlock, retry
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
            })
            .await;

            match recv {
                Ok(Ok(n)) if n > 0 => {
                    let reply_packet = &buf[..n];
                    // Some systems return full IPv4 packet, others return ICMP payload.
                    let reply_frame = if looks_like_ipv4_icmp(reply_packet) {
                        prepend_ethernet_header(reply_packet, guest_mac, gateway_mac)
                    } else {
                        build_icmp_ipv4_ethernet(
                            dst_ip,
                            src_ip,
                            reply_packet,
                            gateway_mac,
                            guest_mac,
                        )
                    };
                    let _ = reply_tx.send(reply_frame).await;
                }
                _ => {
                    tracing::trace!("ICMP proxy: no reply for {} -> {}", src_ip, dst_ip);
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
    ) -> Self {
        let inbound = super::inbound_relay::InboundRelay::new(
            reply_tx.clone(),
            gateway_mac,
            gateway_ip,
            guest_ip,
        );
        Self {
            icmp: IcmpProxy::new(reply_tx.clone(), gateway_mac),
            udp: UdpProxy::new(reply_tx.clone(), gateway_mac),
            inbound,
            reply_tx,
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
        match protocol {
            1 => self.icmp.proxy_icmp(frame, guest_mac),
            17 => self.udp.proxy_udp(frame, guest_mac),
            _ => {
                tracing::trace!("Socket proxy: dropping protocol {}", protocol);
            }
        }
    }

    /// Handles an inbound command from the listener manager.
    pub(crate) fn handle_inbound_command(
        &mut self,
        cmd: super::inbound_relay::InboundCommand,
        guest_mac: [u8; 6],
    ) {
        use super::inbound_relay::InboundCommand;
        match cmd {
            InboundCommand::TcpAccepted {
                container_port,
                stream,
                ..
            } => {
                self.inbound.initiate_tcp(container_port, stream, guest_mac);
            }
            InboundCommand::UdpReceived {
                container_port,
                data,
                reply_tx,
                ..
            } => {
                self.inbound
                    .inject_udp(container_port, &data, reply_tx, guest_mac);
            }
        }
    }

    /// Runs periodic maintenance (flow cleanup).
    pub fn maintenance(&mut self) {
        self.udp.cleanup_stale_flows();
        self.inbound.cleanup();
    }
}

/// Returns true when sequence number `a` is before `b` in TCP sequence space.
///
/// Uses signed arithmetic to handle 32-bit wrapping correctly (RFC 1323 §4.2).
pub(crate) fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Generates a pseudo-random initial sequence number.
pub(crate) fn rand_isn() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    // Simple hash to spread ISNs.
    (t.wrapping_mul(6364136223846793005).wrapping_add(1) >> 16) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rand_isn_spread() {
        // Two successive ISNs should differ.
        let a = rand_isn();
        std::thread::sleep(std::time::Duration::from_micros(1));
        let b = rand_isn();
        assert_ne!(a, b);
    }

    #[test]
    fn test_socket_proxy_creation() {
        let (tx, _rx) = mpsc::channel(16);
        let gw_ip = Ipv4Addr::new(192, 168, 64, 1);
        let gw_mac = [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x01];
        let guest_ip = Ipv4Addr::new(192, 168, 64, 2);
        let _proxy = SocketProxy::new(gw_ip, gw_mac, guest_ip, tx);
    }

    #[test]
    fn test_socket_proxy_drops_unknown_protocol() {
        let (tx, _rx) = mpsc::channel(16);
        let gw_ip = Ipv4Addr::new(192, 168, 64, 1);
        let gw_mac = [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x01];
        let guest_ip = Ipv4Addr::new(192, 168, 64, 2);
        let mut proxy = SocketProxy::new(gw_ip, gw_mac, guest_ip, tx);

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
        let mut proxy = SocketProxy::new(gw_ip, gw_mac, guest_ip, tx);

        let guest_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x99];
        // Frame shorter than Ethernet + IP minimum.
        proxy.handle_outbound(&[0u8; 10], guest_mac);
    }

    #[test]
    fn test_udp_proxy_cleanup_stale_flows() {
        let (tx, _rx) = mpsc::channel(16);
        let gw_ip = Ipv4Addr::new(192, 168, 64, 1);
        let gw_mac = [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x01];
        let mut proxy = UdpProxy::new(tx, gw_mac);

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
                last_active: Instant::now() - std::time::Duration::from_secs(120),
            },
        );
        assert_eq!(proxy.flows.len(), 1);

        proxy.cleanup_stale_flows();
        assert_eq!(proxy.flows.len(), 0, "Stale flow should be cleaned up");
    }

    #[test]
    fn test_seq_before_basic() {
        assert!(seq_before(100, 200));
        assert!(!seq_before(200, 100));
        assert!(!seq_before(100, 100));
    }

    #[test]
    fn test_seq_before_wrapping() {
        // Near the 32-bit wraparound boundary.
        assert!(seq_before(u32::MAX - 10, u32::MAX));
        assert!(seq_before(u32::MAX, 10)); // wraps around
        assert!(!seq_before(10, u32::MAX)); // 10 is "after" MAX in TCP space
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
        let _proxy = SocketProxy::new(gw_ip, gw_mac, guest_ip, tx);
    }
}
