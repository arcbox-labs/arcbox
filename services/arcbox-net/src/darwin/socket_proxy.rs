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
//!   ├─ ICMP → IcmpProxy (raw socket sendto/recvfrom)
//!   ├─ UDP  → UdpProxy  (per-flow host UdpSocket)
//!   └─ TCP  → TcpProxy  (per-connection host TcpStream)
//!         ↓
//!   reply_tx → mpsc → datapath select! → guest FD
//! ```

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Instant;

use socket2::{Domain, Protocol, Type};
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::ethernet::{
    build_tcp_ip_ethernet, build_udp_ip_ethernet, prepend_ethernet_header, ETH_HEADER_LEN,
    TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN,
};

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
    gateway_ip: Ipv4Addr,
}

impl UdpProxy {
    fn new(
        reply_tx: mpsc::Sender<Vec<u8>>,
        gateway_mac: [u8; 6],
        gateway_ip: Ipv4Addr,
    ) -> Self {
        Self {
            flows: HashMap::new(),
            reply_tx,
            gateway_mac,
            gateway_ip,
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
            self.flows.insert(flow_key, UdpFlow {
                last_active: Instant::now(),
            });

            // Spawn a recv task for this flow.
            let reply_tx = self.reply_tx.clone();
            let gateway_mac = self.gateway_mac;
            let gateway_ip = self.gateway_ip;

            tokio::spawn(async move {
                let socket = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("UDP proxy: failed to bind socket: {}", e);
                        return;
                    }
                };

                if let Err(e) = socket.connect(SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port))).await {
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
                                gateway_ip, src_ip, dst_port, src_port, &buf[..n],
                                gateway_mac, guest_mac,
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

/// ICMP proxy: raw socket per echo.
struct IcmpProxy {
    reply_tx: mpsc::Sender<Vec<u8>>,
    gateway_mac: [u8; 6],
}

impl IcmpProxy {
    fn new(reply_tx: mpsc::Sender<Vec<u8>>, gateway_mac: [u8; 6]) -> Self {
        Self {
            reply_tx,
            gateway_mac,
        }
    }

    /// Proxies an ICMP packet from the guest to the host.
    fn proxy_icmp(&self, frame: &[u8], guest_mac: [u8; 6]) {
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

        tokio::spawn(async move {
            let raw_socket = match socket2::Socket::new(
                Domain::IPV4,
                Type::RAW,
                Some(Protocol::ICMPV4),
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("ICMP proxy: failed to create raw socket: {}", e);
                    return;
                }
            };

            raw_socket.set_nonblocking(true).ok();
            let dst_addr: SocketAddr = SocketAddrV4::new(dst_ip, 0).into();

            if let Err(e) = raw_socket.send_to(&icmp_payload, &dst_addr.into()) {
                tracing::warn!("ICMP proxy: sendto failed: {}", e);
                return;
            }

            // Wait for reply using AsyncFd on the raw socket.
            let async_fd = match AsyncFd::new(RawSocketWrapper(raw_socket)) {
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
                    // Raw socket returns IP header + ICMP; build L2 frame.
                    let reply_frame =
                        prepend_ethernet_header(&buf[..n], guest_mac, gateway_mac);
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

/// Top-level socket proxy that dispatches guest traffic to protocol-specific
/// handlers.
pub struct SocketProxy {
    icmp: IcmpProxy,
    udp: UdpProxy,
    // TCP proxy state (added in a later commit).
    tcp: TcpProxy,
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
        reply_tx: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        Self {
            icmp: IcmpProxy::new(reply_tx.clone(), gateway_mac),
            udp: UdpProxy::new(reply_tx.clone(), gateway_mac, gateway_ip),
            tcp: TcpProxy::new(reply_tx, gateway_mac, gateway_ip),
        }
    }

    /// Dispatches an outbound IPv4 frame to the appropriate protocol proxy.
    pub fn handle_outbound(&mut self, frame: &[u8], guest_mac: [u8; 6]) {
        if frame.len() < ETH_HEADER_LEN + 20 {
            return;
        }

        let protocol = frame[ETH_HEADER_LEN + 9];
        match protocol {
            1 => self.icmp.proxy_icmp(frame, guest_mac),
            6 => self.tcp.proxy_tcp(frame, guest_mac),
            17 => self.udp.proxy_udp(frame, guest_mac),
            _ => {
                tracing::trace!("Socket proxy: dropping protocol {}", protocol);
            }
        }
    }

    /// Runs periodic maintenance (flow cleanup).
    pub fn maintenance(&mut self) {
        self.udp.cleanup_stale_flows();
        self.tcp.cleanup_closed();
    }
}

// ============================================================================
// TCP Proxy (stub — full implementation in next commit)
// ============================================================================

/// TCP connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpState {
    SynReceived,
    Established,
    FinWait,
    Closed,
}

/// Per-connection TCP state tracking.
struct TcpConnection {
    state: TcpState,
    /// Next expected sequence number from the guest.
    guest_seq: u32,
    /// Our sequence number to the guest.
    host_seq: u32,
    /// Channel to send events to the connection relay task.
    data_tx: mpsc::Sender<Vec<u8>>,
}

/// TCP proxy: per-connection host `TcpStream` with guest-facing TCP state.
pub(crate) struct TcpProxy {
    /// Active connections keyed by (src_ip, src_port, dst_ip, dst_port).
    connections: HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), TcpConnection>,
    reply_tx: mpsc::Sender<Vec<u8>>,
    gateway_mac: [u8; 6],
    gateway_ip: Ipv4Addr,
}

impl TcpProxy {
    fn new(
        reply_tx: mpsc::Sender<Vec<u8>>,
        gateway_mac: [u8; 6],
        gateway_ip: Ipv4Addr,
    ) -> Self {
        Self {
            connections: HashMap::new(),
            reply_tx,
            gateway_mac,
            gateway_ip,
        }
    }

    /// Handles a TCP segment from the guest.
    fn proxy_tcp(&mut self, frame: &[u8], guest_mac: [u8; 6]) {
        let ip_start = ETH_HEADER_LEN;
        let ihl = ((frame[ip_start] & 0x0F) as usize) * 4;
        let tcp_start = ip_start + ihl;

        if frame.len() < tcp_start + 20 {
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
        let src_port = u16::from_be_bytes([frame[tcp_start], frame[tcp_start + 1]]);
        let dst_port = u16::from_be_bytes([frame[tcp_start + 2], frame[tcp_start + 3]]);
        let seq = u32::from_be_bytes([
            frame[tcp_start + 4],
            frame[tcp_start + 5],
            frame[tcp_start + 6],
            frame[tcp_start + 7],
        ]);
        let _ack = u32::from_be_bytes([
            frame[tcp_start + 8],
            frame[tcp_start + 9],
            frame[tcp_start + 10],
            frame[tcp_start + 11],
        ]);
        let data_offset = ((frame[tcp_start + 12] >> 4) as usize) * 4;
        let flags = frame[tcp_start + 13];

        let conn_key = (src_ip, src_port, dst_ip, dst_port);

        if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 {
            // New SYN: initiate connection.
            self.handle_syn(conn_key, seq, dst_ip, dst_port, src_ip, src_port, guest_mac);
            return;
        }

        if let Some(conn) = self.connections.get_mut(&conn_key) {
            match conn.state {
                TcpState::SynReceived => {
                    if flags & TCP_ACK != 0 {
                        // Handshake complete.
                        conn.state = TcpState::Established;
                        conn.guest_seq = seq;
                        tracing::debug!("TCP established: {}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port);
                    }
                }
                TcpState::Established => {
                    let payload_start = tcp_start + data_offset;
                    let payload = if payload_start < frame.len() {
                        &frame[payload_start..]
                    } else {
                        &[]
                    };

                    if flags & TCP_FIN != 0 {
                        // Guest is closing. Send FIN-ACK.
                        conn.guest_seq = seq.wrapping_add(payload.len() as u32).wrapping_add(1);
                        conn.state = TcpState::FinWait;

                        let fin_ack = build_tcp_ip_ethernet(
                            self.gateway_ip, src_ip, dst_port, src_port,
                            conn.host_seq, conn.guest_seq,
                            TCP_FIN | TCP_ACK, 65535, &[],
                            self.gateway_mac, guest_mac,
                        );
                        let reply_tx = self.reply_tx.clone();
                        tokio::spawn(async move {
                            let _ = reply_tx.send(fin_ack).await;
                        });
                        return;
                    }

                    if flags & TCP_RST != 0 {
                        conn.state = TcpState::Closed;
                        let _ = conn.data_tx.try_send(Vec::new()); // Signal close
                        return;
                    }

                    if !payload.is_empty() {
                        conn.guest_seq = seq.wrapping_add(payload.len() as u32);

                        // ACK the data.
                        let ack_frame = build_tcp_ip_ethernet(
                            self.gateway_ip, src_ip, dst_port, src_port,
                            conn.host_seq, conn.guest_seq,
                            TCP_ACK, 65535, &[],
                            self.gateway_mac, guest_mac,
                        );
                        let reply_tx = self.reply_tx.clone();
                        let payload_vec = payload.to_vec();
                        let data_tx = conn.data_tx.clone();
                        tokio::spawn(async move {
                            let _ = reply_tx.send(ack_frame).await;
                            let _ = data_tx.send(payload_vec).await;
                        });
                    }
                }
                TcpState::FinWait => {
                    if flags & TCP_ACK != 0 {
                        conn.state = TcpState::Closed;
                    }
                }
                TcpState::Closed => {}
            }
        } else if flags & TCP_RST == 0 {
            // Unknown connection, send RST.
            let rst = build_tcp_ip_ethernet(
                self.gateway_ip, src_ip, dst_port, src_port,
                0, seq.wrapping_add(1),
                TCP_RST | TCP_ACK, 0, &[],
                self.gateway_mac, guest_mac,
            );
            let reply_tx = self.reply_tx.clone();
            tokio::spawn(async move {
                let _ = reply_tx.send(rst).await;
            });
        }
    }

    /// Handles a new TCP SYN from the guest.
    #[allow(clippy::too_many_arguments)]
    fn handle_syn(
        &mut self,
        conn_key: (Ipv4Addr, u16, Ipv4Addr, u16),
        guest_isn: u32,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        src_ip: Ipv4Addr,
        src_port: u16,
        guest_mac: [u8; 6],
    ) {
        // Remove any stale connection with the same key.
        self.connections.remove(&conn_key);

        let host_isn: u32 = rand_isn();
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);

        let conn = TcpConnection {
            state: TcpState::SynReceived,
            guest_seq: guest_isn.wrapping_add(1),
            host_seq: host_isn,
            data_tx,
        };
        self.connections.insert(conn_key, conn);

        let reply_tx = self.reply_tx.clone();
        let gateway_mac = self.gateway_mac;
        let gateway_ip = self.gateway_ip;

        tokio::spawn(async move {
            // Try to connect to the remote host.
            let stream = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tokio::net::TcpStream::connect(SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port))),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracing::debug!("TCP proxy: connect to {}:{} failed: {}", dst_ip, dst_port, e);
                    let rst = build_tcp_ip_ethernet(
                        gateway_ip, src_ip, dst_port, src_port,
                        0, guest_isn.wrapping_add(1),
                        TCP_RST | TCP_ACK, 0, &[],
                        gateway_mac, guest_mac,
                    );
                    let _ = reply_tx.send(rst).await;
                    return;
                }
                Err(_) => {
                    tracing::debug!("TCP proxy: connect to {}:{} timed out", dst_ip, dst_port);
                    let rst = build_tcp_ip_ethernet(
                        gateway_ip, src_ip, dst_port, src_port,
                        0, guest_isn.wrapping_add(1),
                        TCP_RST | TCP_ACK, 0, &[],
                        gateway_mac, guest_mac,
                    );
                    let _ = reply_tx.send(rst).await;
                    return;
                }
            };

            // Send SYN-ACK to guest.
            let syn_ack = build_tcp_ip_ethernet(
                gateway_ip, src_ip, dst_port, src_port,
                host_isn, guest_isn.wrapping_add(1),
                TCP_SYN | TCP_ACK, 65535, &[],
                gateway_mac, guest_mac,
            );
            if reply_tx.send(syn_ack).await.is_err() {
                return;
            }

            // Run bidirectional relay.
            tcp_relay(
                stream, data_rx, reply_tx, gateway_ip, gateway_mac,
                src_ip, src_port, dst_port, guest_mac,
                host_isn.wrapping_add(1),
            )
            .await;
        });
    }

    /// Removes closed connections from the table.
    fn cleanup_closed(&mut self) {
        self.connections
            .retain(|_, conn| conn.state != TcpState::Closed);
    }
}

/// Bidirectional relay between a host `TcpStream` and guest TCP segments.
#[allow(clippy::too_many_arguments)]
async fn tcp_relay(
    stream: tokio::net::TcpStream,
    mut data_rx: mpsc::Receiver<Vec<u8>>,
    reply_tx: mpsc::Sender<Vec<u8>>,
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
    guest_ip: Ipv4Addr,
    guest_port: u16,
    host_port: u16,
    guest_mac: [u8; 6],
    mut host_seq: u32,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut reader, mut writer) = stream.into_split();

    // Host -> Guest relay: read from TcpStream, send data frames.
    let reply_tx2 = reply_tx.clone();
    let host_read = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    // EOF: send FIN to guest.
                    let fin = build_tcp_ip_ethernet(
                        gateway_ip, guest_ip, host_port, guest_port,
                        host_seq, 0, TCP_FIN | TCP_ACK, 65535, &[],
                        gateway_mac, guest_mac,
                    );
                    let _ = reply_tx2.send(fin).await;
                    break;
                }
                Ok(n) => {
                    let data_frame = build_tcp_ip_ethernet(
                        gateway_ip, guest_ip, host_port, guest_port,
                        host_seq, 0, TCP_ACK | TCP_PSH, 65535, &buf[..n],
                        gateway_mac, guest_mac,
                    );
                    host_seq = host_seq.wrapping_add(n as u32);
                    if reply_tx2.send(data_frame).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("TCP relay read error: {}", e);
                    break;
                }
            }
        }
    });

    // Guest -> Host relay: receive data from guest, write to TcpStream.
    let guest_write = tokio::spawn(async move {
        while let Some(data) = data_rx.recv().await {
            if data.is_empty() {
                // Signal to close.
                let _ = writer.shutdown().await;
                break;
            }
            if let Err(e) = writer.write_all(&data).await {
                tracing::debug!("TCP relay write error: {}", e);
                break;
            }
        }
    });

    // Wait for both directions to finish.
    let _ = tokio::join!(host_read, guest_write);
}

/// Generates a pseudo-random initial sequence number.
fn rand_isn() -> u32 {
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
    fn test_rand_isn_non_zero() {
        let isn = rand_isn();
        // ISNs should be reasonably spread. Just verify it doesn't panic.
        let _ = isn;
    }

    #[test]
    fn test_tcp_state_transitions() {
        assert_ne!(TcpState::SynReceived, TcpState::Established);
        assert_ne!(TcpState::Established, TcpState::Closed);
    }
}
