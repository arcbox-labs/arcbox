//! TCP bridge: smoltcp socket pool ↔ host `TcpStream` bidirectional relay.
//!
//! Manages outbound TCP connections through smoltcp's TCP socket
//! implementation, bridging each to a host-side `TcpStream` for actual network
//! I/O.
//!
//! # Architecture
//!
//! ```text
//! Guest VM  (sends SYN to 1.1.1.1:443)
//!     ↕ smoltcp tcp::Socket (listen on port 443, any_ip)
//! TcpBridge
//!     ↕ tokio channels (smoltcp is !Send, host I/O is async)
//! HostConn task (tokio::spawn)
//!     ↕ TcpStream::connect(1.1.1.1:443)
//! Remote server
//! ```
//!
//! # Design
//!
//! Since smoltcp can only listen on a specific port (not port 0), we
//! dynamically create listen sockets when we see new TCP SYN destination ports
//! from the guest. Each listen socket accepts one connection at a time and is
//! recycled back to listening state after the connection closes.
//!
//! Host connections use tokio async I/O through channels:
//! - `host_to_guest_rx`: host TcpStream read data → smoltcp socket.send()
//! - `guest_to_host_tx`: smoltcp socket.recv() → host TcpStream write

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use smoltcp::iface::SocketHandle;
use smoltcp::iface::SocketSet;
use smoltcp::socket::tcp;
use smoltcp::wire::IpEndpoint;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// Size of each smoltcp socket's rx/tx buffer. 256 KiB enables window scaling
/// and provides enough headroom for high-bandwidth transfers.
const SOCKET_BUF_SIZE: usize = 256 * 1024;

/// Number of pre-allocated listen sockets per port is 1 (created on demand).
/// Additional connections to the same port reuse the socket after it returns
/// to Closed state.
///
/// Maximum segments the host→guest channel can buffer. Provides backpressure
/// when smoltcp's tx buffer is full.
const HOST_TO_GUEST_CHANNEL: usize = 64;

/// Maximum payload chunks the guest→host channel can buffer. Backpressure
/// propagates through smoltcp's flow control when the host socket is slow.
const GUEST_TO_HOST_CHANNEL: usize = 64;

/// Tracks a single outbound TCP connection bridged between smoltcp and a host
/// TcpStream.
struct OutboundConn {
    /// smoltcp socket handle.
    handle: SocketHandle,
    /// Actual remote IP:port the guest connected to.
    remote: SocketAddr,
    /// Receives data from the host TcpStream read task.
    host_to_guest_rx: mpsc::Receiver<Vec<u8>>,
    /// Sends data consumed from smoltcp socket to the host TcpStream write task.
    guest_to_host_tx: mpsc::Sender<Vec<u8>>,
    /// Set to true when the host read task has sent all data (EOF).
    host_eof: bool,
    /// Set to true when the host connect failed — abort the smoltcp socket.
    connect_failed: bool,
}

/// Manages outbound TCP connections through the smoltcp socket pool.
pub struct TcpBridge {
    /// Active outbound connections keyed by smoltcp socket handle.
    connections: HashMap<SocketHandle, OutboundConn>,
    /// Ports that have at least one listen socket in the socket set.
    listening_ports: HashSet<u16>,
    /// Free listen socket handles (Closed/TimeWait) available for re-listen.
    free_handles: Vec<SocketHandle>,
    /// Maps a port to the socket handles listening on it, so we can track
    /// which ports are covered.
    port_handles: HashMap<u16, Vec<SocketHandle>>,
}

impl Default for TcpBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpBridge {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            listening_ports: HashSet::new(),
            free_handles: Vec::new(),
            port_handles: HashMap::new(),
        }
    }

    /// Ensures listen sockets exist for the given TCP SYN destination ports.
    ///
    /// Called before `iface.poll()` so that when smoltcp processes the SYN,
    /// a matching listen socket is ready to accept it.
    pub fn ensure_listen_sockets(
        &mut self,
        syn_ports: &[crate::darwin::smoltcp_device::TcpSynInfo],
        sockets: &mut SocketSet<'_>,
    ) {
        for syn in syn_ports {
            let port = syn.dst_port;
            if self.listening_ports.contains(&port) {
                continue;
            }

            // Try to reuse a free handle first.
            let handle = if let Some(h) = self.free_handles.pop() {
                let sock = sockets.get_mut::<tcp::Socket>(h);
                sock.listen(port)
                    .expect("failed to re-listen on free socket");
                sock.set_nagle_enabled(false);
                h
            } else {
                // Create a new socket.
                let rx_buf = tcp::SocketBuffer::new(vec![0u8; SOCKET_BUF_SIZE]);
                let tx_buf = tcp::SocketBuffer::new(vec![0u8; SOCKET_BUF_SIZE]);
                let mut sock = tcp::Socket::new(rx_buf, tx_buf);
                sock.listen(port).expect("failed to listen on new socket");
                sock.set_nagle_enabled(false);
                sock.set_ack_delay(None);
                sockets.add(sock)
            };

            self.listening_ports.insert(port);
            self.port_handles.entry(port).or_default().push(handle);

            tracing::debug!("TCP bridge: listen socket created for port {port}");
        }
    }

    /// Polls all connections, performing bidirectional data relay and detecting
    /// new/closed connections.
    ///
    /// Must be called after `iface.poll()`.
    pub fn poll(&mut self, sockets: &mut SocketSet<'_>) {
        self.detect_new_connections(sockets);
        self.relay_all(sockets);
        self.cleanup_closed(sockets);
    }

    /// Detects smoltcp sockets that have transitioned from Listen to an active
    /// state (SYN received), and opens host TcpStream connections for them.
    fn detect_new_connections(&mut self, sockets: &mut SocketSet<'_>) {
        // Collect ports to scan: only ports we know have listen sockets.
        let ports: Vec<u16> = self.listening_ports.iter().copied().collect();

        for port in ports {
            let Some(handles) = self.port_handles.get(&port) else {
                continue;
            };

            for &handle in handles {
                // Skip handles already tracked as active connections.
                if self.connections.contains_key(&handle) {
                    continue;
                }

                let sock = sockets.get_mut::<tcp::Socket>(handle);
                if !sock.is_active() {
                    continue;
                }

                // Socket accepted a SYN — extract the remote endpoint.
                let Some(remote_ep) = sock.remote_endpoint() else {
                    continue;
                };
                let Some(local_ep) = sock.local_endpoint() else {
                    continue;
                };

                let remote_addr = endpoint_to_sockaddr(remote_ep);
                let dest_addr = endpoint_to_sockaddr(local_ep);

                tracing::debug!(
                    "TCP bridge: new connection detected  guest:{remote_addr} → {dest_addr}"
                );

                // Create channels for host↔guest data bridging.
                let (h2g_tx, h2g_rx) = mpsc::channel::<Vec<u8>>(HOST_TO_GUEST_CHANNEL);
                let (g2h_tx, g2h_rx) = mpsc::channel::<Vec<u8>>(GUEST_TO_HOST_CHANNEL);

                // Spawn host connection task.
                tokio::spawn(host_conn_task(dest_addr, h2g_tx, g2h_rx));

                self.connections.insert(
                    handle,
                    OutboundConn {
                        handle,
                        remote: dest_addr,
                        host_to_guest_rx: h2g_rx,
                        guest_to_host_tx: g2h_tx,
                        host_eof: false,
                        connect_failed: false,
                    },
                );

                // This port's listen socket is now occupied. Remove from
                // listening_ports so the next SYN on the same port creates a
                // new listen socket.
                self.listening_ports.remove(&port);
            }
        }
    }

    /// Relays data between smoltcp sockets and host TcpStreams for all active
    /// connections.
    fn relay_all(&mut self, sockets: &mut SocketSet<'_>) {
        for conn in self.connections.values_mut() {
            let sock = sockets.get_mut::<tcp::Socket>(conn.handle);

            // Host → Guest: drain channel into smoltcp tx buffer.
            while sock.can_send() {
                match conn.host_to_guest_rx.try_recv() {
                    Ok(data) => {
                        if data.is_empty() {
                            // EOF signal from host.
                            conn.host_eof = true;
                            break;
                        }
                        match sock.send_slice(&data) {
                            Ok(sent) if sent < data.len() => {
                                // Partial send — this shouldn't happen since we
                                // check can_send(), but handle gracefully.
                                tracing::debug!(
                                    "TCP bridge: partial send {sent}/{} to {}",
                                    data.len(),
                                    conn.remote
                                );
                            }
                            Err(e) => {
                                tracing::debug!("TCP bridge: send error to {}: {e:?}", conn.remote);
                                break;
                            }
                            _ => {}
                        }
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        // Host task exited (connect failed or stream closed).
                        conn.connect_failed = true;
                        break;
                    }
                }
            }

            // If host read EOF'd and all data flushed to smoltcp, close the
            // smoltcp socket (sends FIN to guest).
            if conn.host_eof && sock.may_send() {
                sock.close();
                conn.host_eof = false; // Only close once.
            }

            // If host connect failed, abort (RST to guest).
            if conn.connect_failed {
                sock.abort();
                continue;
            }

            // Guest → Host: drain smoltcp rx buffer into channel.
            if sock.may_recv() {
                let _ = sock.recv(|buf| {
                    if buf.is_empty() {
                        return (0, ());
                    }
                    match conn.guest_to_host_tx.try_send(buf.to_vec()) {
                        Ok(()) => (buf.len(), ()),
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            // Backpressure: don't dequeue from smoltcp.
                            // smoltcp will shrink the window automatically.
                            (0, ())
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            // Host write task gone, consume and drop.
                            (buf.len(), ())
                        }
                    }
                });
            }

            // If the guest has sent FIN and we've consumed all data, signal
            // close to the host task.
            if !sock.may_recv() && sock.state() != tcp::State::Listen {
                // Close the guest_to_host channel so the host write task sees
                // EOF and shuts down the write half.
                // (Dropping the sender is handled in cleanup.)
            }
        }
    }

    /// Removes closed connections and recycles their socket handles.
    fn cleanup_closed(&mut self, sockets: &mut SocketSet<'_>) {
        let mut to_remove = Vec::new();

        for (&handle, conn) in &self.connections {
            let sock = sockets.get_mut::<tcp::Socket>(handle);
            if !sock.is_open() || sock.state() == tcp::State::Closed {
                to_remove.push(handle);
                tracing::debug!("TCP bridge: connection to {} closed", conn.remote);
            }
        }

        for handle in to_remove {
            self.connections.remove(&handle);
            // Don't recycle to free_handles — the socket still has its large
            // buffers allocated. We'll create new sockets on demand as needed
            // to avoid unbounded memory growth. When smoltcp finishes
            // TIME-WAIT, the socket returns to Closed and we could re-listen.
            // For now, just remove from the socket set.
            sockets.remove(handle);
        }
    }

    /// Returns the number of active connections.
    pub fn active_count(&self) -> usize {
        self.connections.len()
    }
}

/// Host connection task: connects to the remote server and bridges data
/// through channels back to the smoltcp poll loop.
async fn host_conn_task(
    remote: SocketAddr,
    h2g_tx: mpsc::Sender<Vec<u8>>,
    mut g2h_rx: mpsc::Receiver<Vec<u8>>,
) {
    // Connect to the remote host.
    let stream = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(remote),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::debug!("TCP bridge: connect to {remote} failed: {e}");
            // Drop h2g_tx — bridge will detect Disconnected and abort.
            return;
        }
        Err(_) => {
            tracing::debug!("TCP bridge: connect to {remote} timed out");
            return;
        }
    };

    tracing::debug!("TCP bridge: connected to {remote}");

    let (mut reader, mut writer) = stream.into_split();

    // Host → Guest: read from TcpStream, send via channel.
    let read_task = {
        let h2g_tx = h2g_tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 32768];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => {
                        // EOF — send empty vec as signal.
                        let _ = h2g_tx.send(Vec::new()).await;
                        break;
                    }
                    Ok(n) => {
                        if h2g_tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("TCP bridge: host read error for {remote}: {e}");
                        break;
                    }
                }
            }
        })
    };

    // Guest → Host: receive from channel, write to TcpStream.
    let write_task = tokio::spawn(async move {
        while let Some(data) = g2h_rx.recv().await {
            if data.is_empty() {
                // Guest closed connection.
                let _ = writer.shutdown().await;
                break;
            }
            if let Err(e) = writer.write_all(&data).await {
                tracing::debug!("TCP bridge: host write error for {remote}: {e}");
                break;
            }
        }
    });

    let _ = tokio::join!(read_task, write_task);
}

/// Converts a smoltcp `IpEndpoint` to a `SocketAddr`.
fn endpoint_to_sockaddr(ep: IpEndpoint) -> SocketAddr {
    let smoltcp::wire::IpAddress::Ipv4(v4) = ep.addr;
    SocketAddr::V4(SocketAddrV4::new(v4, ep.port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::iface::{Config, Interface};
    use smoltcp::wire::{EthernetAddress, IpCidr};

    use crate::darwin::smoltcp_device::{SmoltcpDevice, TcpSynInfo};
    use crate::ethernet::ETH_HEADER_LEN;

    const GW_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 64, 1);
    const GW_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const GUEST_MAC: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    const GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 64, 2);

    fn make_iface_and_sockets(device: &mut SmoltcpDevice) -> (Interface, SocketSet<'static>) {
        let hw_addr = EthernetAddress(GW_MAC);
        let config = Config::new(hw_addr.into());
        let mut iface = Interface::new(config, device, smoltcp::time::Instant::now());
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(GW_IP.into(), 24)).unwrap();
        });
        iface.set_any_ip(true);
        // Add a default route via the gateway so smoltcp can send replies.
        iface.routes_mut().add_default_ipv4_route(GW_IP).unwrap();
        let sockets = SocketSet::new(vec![]);
        (iface, sockets)
    }

    /// Builds a minimal TCP SYN frame from guest to remote.
    fn make_syn_frame(dst_ip: Ipv4Addr, dst_port: u16) -> Vec<u8> {
        let mut frame = vec![0u8; ETH_HEADER_LEN + 40]; // 20 IP + 20 TCP
        // Ethernet
        frame[0..6].copy_from_slice(&GW_MAC); // dst
        frame[6..12].copy_from_slice(&GUEST_MAC); // src
        frame[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4
        // IPv4
        let ip = ETH_HEADER_LEN;
        frame[ip] = 0x45;
        frame[ip + 2..ip + 4].copy_from_slice(&40u16.to_be_bytes()); // total len
        frame[ip + 8] = 64; // TTL
        frame[ip + 9] = 6; // TCP
        frame[ip + 12..ip + 16].copy_from_slice(&GUEST_IP.octets());
        frame[ip + 16..ip + 20].copy_from_slice(&dst_ip.octets());
        // IP checksum
        let cksum = ip_checksum(&frame[ip..ip + 20]);
        frame[ip + 10..ip + 12].copy_from_slice(&cksum.to_be_bytes());
        // TCP
        let tcp = ip + 20;
        frame[tcp..tcp + 2].copy_from_slice(&12345u16.to_be_bytes()); // src port
        frame[tcp + 2..tcp + 4].copy_from_slice(&dst_port.to_be_bytes()); // dst port
        frame[tcp + 4..tcp + 8].copy_from_slice(&1000u32.to_be_bytes()); // seq
        frame[tcp + 12] = 0x50; // data offset = 5 (20 bytes)
        frame[tcp + 13] = 0x02; // SYN
        frame[tcp + 14..tcp + 16].copy_from_slice(&65535u16.to_be_bytes()); // window
        // TCP checksum (pseudo-header + TCP segment)
        let tcp_cksum = tcp_checksum(&GUEST_IP.octets(), &dst_ip.octets(), &frame[tcp..ip + 40]);
        frame[tcp + 16..tcp + 18].copy_from_slice(&tcp_cksum.to_be_bytes());
        frame
    }

    fn ip_checksum(header: &[u8]) -> u16 {
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

    fn tcp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_segment: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        // Pseudo-header
        sum += u32::from(u16::from_be_bytes([src_ip[0], src_ip[1]]));
        sum += u32::from(u16::from_be_bytes([src_ip[2], src_ip[3]]));
        sum += u32::from(u16::from_be_bytes([dst_ip[0], dst_ip[1]]));
        sum += u32::from(u16::from_be_bytes([dst_ip[2], dst_ip[3]]));
        sum += 6u32; // protocol TCP
        sum += tcp_segment.len() as u32;
        // TCP segment (skip checksum field at offset 16-17)
        let mut i = 0;
        while i + 1 < tcp_segment.len() {
            if i != 16 {
                sum += u32::from(u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]));
            }
            i += 2;
        }
        if i < tcp_segment.len() {
            sum += u32::from(tcp_segment[i]) << 8;
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !sum as u16
    }

    #[test]
    fn ensure_listen_sockets_creates_on_demand() {
        let mut device = SmoltcpDevice::new(0, GW_IP);
        let (_iface, mut sockets) = make_iface_and_sockets(&mut device);
        let mut bridge = TcpBridge::new();

        let syns = vec![TcpSynInfo { dst_port: 443 }, TcpSynInfo { dst_port: 80 }];

        bridge.ensure_listen_sockets(&syns, &mut sockets);

        assert!(bridge.listening_ports.contains(&443));
        assert!(bridge.listening_ports.contains(&80));
        assert!(bridge.port_handles.contains_key(&443));
        assert!(bridge.port_handles.contains_key(&80));
    }

    #[test]
    fn ensure_listen_sockets_deduplicates() {
        let mut device = SmoltcpDevice::new(0, GW_IP);
        let (_iface, mut sockets) = make_iface_and_sockets(&mut device);
        let mut bridge = TcpBridge::new();

        let syns = vec![TcpSynInfo { dst_port: 443 }];
        bridge.ensure_listen_sockets(&syns, &mut sockets);
        bridge.ensure_listen_sockets(&syns, &mut sockets);

        assert_eq!(bridge.port_handles[&443].len(), 1);
    }

    #[test]
    fn smoltcp_accepts_syn_with_listen_socket() {
        let mut device = SmoltcpDevice::new(0, GW_IP);
        let (mut iface, mut sockets) = make_iface_and_sockets(&mut device);
        let mut bridge = TcpBridge::new();

        // Ensure a listen socket for port 443.
        let syns = vec![TcpSynInfo { dst_port: 443 }];
        bridge.ensure_listen_sockets(&syns, &mut sockets);

        // First, inject an ARP request from the guest to populate smoltcp's
        // neighbor cache with the guest MAC. Without this, smoltcp can't
        // send SYN-ACK because it doesn't know the destination MAC.
        let mut arp = vec![0u8; 42];
        arp[0..6].copy_from_slice(&[0xFF; 6]); // broadcast
        arp[6..12].copy_from_slice(&GUEST_MAC);
        arp[12..14].copy_from_slice(&[0x08, 0x06]); // ARP
        arp[14..16].copy_from_slice(&[0x00, 0x01]); // HW: Ethernet
        arp[16..18].copy_from_slice(&[0x08, 0x00]); // Proto: IPv4
        arp[18] = 6; // HLEN
        arp[19] = 4; // PLEN
        arp[20..22].copy_from_slice(&[0x00, 0x01]); // Op: Request
        arp[22..28].copy_from_slice(&GUEST_MAC);
        arp[28..32].copy_from_slice(&GUEST_IP.octets());
        arp[32..38].copy_from_slice(&[0x00; 6]);
        arp[38..42].copy_from_slice(&GW_IP.octets());
        device.inject_rx(arp);

        let ts = smoltcp::time::Instant::now();
        iface.poll(ts, &mut device, &mut sockets);
        // Clear the ARP reply.
        let _ = device.take_tx_pending();

        // Inject a SYN frame into the device.
        let syn = make_syn_frame(Ipv4Addr::new(1, 1, 1, 1), 443);
        device.inject_rx(syn);

        // Poll smoltcp.
        let ts = smoltcp::time::Instant::now();
        iface.poll(ts, &mut device, &mut sockets);

        // Check that the socket accepted the SYN (should be SynReceived).
        let handle = bridge.port_handles[&443][0];
        let sock = sockets.get_mut::<tcp::Socket>(handle);
        assert!(
            sock.is_active(),
            "Socket should be active after SYN; state={:?}",
            sock.state()
        );
    }

    #[test]
    fn bridge_active_count_starts_at_zero() {
        let bridge = TcpBridge::new();
        assert_eq!(bridge.active_count(), 0);
    }
}
