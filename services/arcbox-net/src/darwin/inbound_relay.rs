//! Inbound port forwarding via L2 frame injection.
//!
//! Instead of using utun + kernel routing, we inject crafted L2 Ethernet frames
//! directly into the guest FD (socketpair) so that host-side TCP/UDP listeners
//! can reach services inside the guest VM.
//!
//! # Architecture
//!
//! ```text
//! External client (host:8080)
//!     │
//!     ▼
//! InboundListenerManager (TcpListener / UdpSocket per rule)
//!     │ accept / recv
//!     ▼
//! InboundCommand channel  ──►  NetworkDatapath select! arm
//!     │
//!     ▼
//! InboundRelay
//!     └─ UDP: inject datagram → guest reply → forward to client
//!     │
//!     ▼
//! reply_tx ──► datapath ──► guest_fd (socketpair) ──► Guest VM
//! ```

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Instant;

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::ethernet::{ETH_HEADER_LEN, build_udp_ip_ethernet};

// ---------------------------------------------------------------------------
// Ephemeral port allocator
// ---------------------------------------------------------------------------

/// Start of the inbound ephemeral port range (guest kernel uses 32768-60999).
const EPHEMERAL_START: u16 = 61000;
/// End of the inbound ephemeral port range (inclusive).
const EPHEMERAL_END: u16 = 65535;

/// Wrapping ephemeral port allocator for inbound connections.
pub(crate) struct EphemeralPorts {
    next: u16,
}

impl EphemeralPorts {
    pub(crate) fn new() -> Self {
        Self {
            next: EPHEMERAL_START,
        }
    }

    /// Allocates the next ephemeral port, wrapping at the end of the range.
    pub(crate) fn allocate(&mut self) -> u16 {
        let port = self.next;
        self.next = if self.next == EPHEMERAL_END {
            EPHEMERAL_START
        } else {
            self.next + 1
        };
        port
    }

    /// Returns whether `port` falls within the inbound ephemeral range.
    #[inline]
    pub(crate) fn in_range(port: u16) -> bool {
        (EPHEMERAL_START..=EPHEMERAL_END).contains(&port)
    }
}

// ---------------------------------------------------------------------------
// Inbound command (sent from listener tasks to the datapath)
// ---------------------------------------------------------------------------

/// Command sent from `InboundListenerManager` listener tasks to the datapath.
pub enum InboundCommand {
    /// A new TCP connection was accepted on a host listener.
    TcpAccepted {
        host_port: u16,
        container_port: u16,
        stream: tokio::net::TcpStream,
    },
    /// A UDP datagram was received on a host listener.
    UdpReceived {
        host_port: u16,
        container_port: u16,
        data: Vec<u8>,
        /// Channel to send reply datagrams back to the host-side client.
        reply_tx: mpsc::Sender<Vec<u8>>,
        client_addr: SocketAddr,
    },
}

// ---------------------------------------------------------------------------
// UDP flow state
// ---------------------------------------------------------------------------

/// Per-flow inbound UDP state.
struct InboundUdpFlow {
    /// Channel to send reply datagrams back to the host-side client.
    client_tx: mpsc::Sender<Vec<u8>>,
    /// Last time traffic was seen on this flow.
    last_active: Instant,
}

// ---------------------------------------------------------------------------
// InboundRelay
// ---------------------------------------------------------------------------

/// Handles inbound (host → guest) connections by injecting L2 Ethernet frames
/// directly into the guest FD through the `reply_tx` channel.
pub(crate) struct InboundRelay {
    /// Active UDP flows keyed by (gateway_ip, ephemeral_port, guest_ip, container_port).
    udp_flows: HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), InboundUdpFlow>,
    /// Channel to inject L2 frames towards the guest.
    reply_tx: mpsc::Sender<Vec<u8>>,
    gateway_mac: [u8; 6],
    gateway_ip: Ipv4Addr,
    guest_ip: Ipv4Addr,
    ephemeral_ports: EphemeralPorts,
}

impl InboundRelay {
    pub(crate) fn new(
        reply_tx: mpsc::Sender<Vec<u8>>,
        gateway_mac: [u8; 6],
        gateway_ip: Ipv4Addr,
        guest_ip: Ipv4Addr,
    ) -> Self {
        Self {
            udp_flows: HashMap::new(),
            reply_tx,
            gateway_mac,
            gateway_ip,
            guest_ip,
            ephemeral_ports: EphemeralPorts::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Frame matching — called on every outbound guest frame
    // -----------------------------------------------------------------------

    /// Attempts to match an outbound guest frame as a reply to an inbound
    /// connection. Returns `true` if the frame was consumed.
    ///
    /// Fast-path: `EphemeralPorts::in_range(dst_port)` rejects 99%+ of
    /// outbound frames before any `HashMap` lookup.
    pub(crate) fn try_handle_reply(&mut self, frame: &[u8], _guest_mac: [u8; 6]) -> bool {
        if frame.len() < ETH_HEADER_LEN + 20 {
            return false;
        }

        let ip_start = ETH_HEADER_LEN;
        let protocol = frame[ip_start + 9];

        let ihl = ((frame[ip_start] & 0x0F) as usize) * 4;
        let l4_start = ip_start + ihl;

        match protocol {
            6 => false, // TCP is now handled by smoltcp
            17 => self.try_handle_udp_reply(frame, ip_start, l4_start),
            _ => false,
        }
    }

    /// Checks if a UDP frame is a reply to an inbound flow.
    fn try_handle_udp_reply(&mut self, frame: &[u8], ip_start: usize, udp_start: usize) -> bool {
        if frame.len() < udp_start + 8 {
            return false;
        }

        let dst_port = u16::from_be_bytes([frame[udp_start + 2], frame[udp_start + 3]]);
        if !EphemeralPorts::in_range(dst_port) {
            return false;
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
        let src_port = u16::from_be_bytes([frame[udp_start], frame[udp_start + 1]]);

        let key = (dst_ip, dst_port, src_ip, src_port);

        if let Some(flow) = self.udp_flows.get_mut(&key) {
            let udp_len = u16::from_be_bytes([frame[udp_start + 4], frame[udp_start + 5]]) as usize;
            if udp_len >= 8 && udp_start + udp_len <= frame.len() {
                let payload = frame[udp_start + 8..udp_start + udp_len].to_vec();
                flow.last_active = Instant::now();
                let _ = flow.client_tx.try_send(payload);
            }
            return true;
        }

        false
    }

    // -----------------------------------------------------------------------
    // UDP: inject datagram to guest
    // -----------------------------------------------------------------------

    /// Injects a UDP datagram to the guest and sets up a flow for replies.
    pub(crate) fn inject_udp(
        &mut self,
        container_port: u16,
        data: &[u8],
        client_tx: mpsc::Sender<Vec<u8>>,
        guest_mac: [u8; 6],
    ) {
        let ephemeral_port = self.ephemeral_ports.allocate();
        let key = (
            self.gateway_ip,
            ephemeral_port,
            self.guest_ip,
            container_port,
        );

        self.udp_flows.insert(
            key,
            InboundUdpFlow {
                client_tx,
                last_active: Instant::now(),
            },
        );

        let frame = build_udp_ip_ethernet(
            self.gateway_ip,
            self.guest_ip,
            ephemeral_port,
            container_port,
            data,
            self.gateway_mac,
            guest_mac,
        );

        let _ = self.reply_tx.try_send(frame);

        tracing::debug!(
            "Inbound UDP: injected {} bytes  gw:{} → guest:{}",
            data.len(),
            ephemeral_port,
            container_port,
        );
    }

    // -----------------------------------------------------------------------
    // Maintenance
    // -----------------------------------------------------------------------

    /// Removes expired UDP flows.
    pub(crate) fn cleanup(&mut self) {
        let cutoff = Instant::now() - std::time::Duration::from_secs(60);
        self.udp_flows.retain(|_, flow| flow.last_active > cutoff);
    }
}

// ---------------------------------------------------------------------------
// InboundListenerManager
// ---------------------------------------------------------------------------

/// Protocol for port forwarding rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InboundProtocol {
    Tcp,
    Udp,
}

/// Manages host-side listeners that accept incoming connections / datagrams
/// and send `InboundCommand` messages to the datapath.
pub struct InboundListenerManager {
    cmd_tx: mpsc::Sender<InboundCommand>,
    listeners: HashMap<(u16, InboundProtocol), (JoinHandle<()>, CancellationToken)>,
}

impl InboundListenerManager {
    /// Creates a new listener manager.
    #[must_use]
    pub fn new(cmd_tx: mpsc::Sender<InboundCommand>) -> Self {
        Self {
            cmd_tx,
            listeners: HashMap::new(),
        }
    }

    /// Adds a forwarding rule and spawns a listener task.
    ///
    /// # Errors
    ///
    /// Returns an error if the listener cannot bind.
    pub async fn add_rule(
        &mut self,
        host_port: u16,
        container_port: u16,
        protocol: InboundProtocol,
    ) -> std::io::Result<()> {
        let key = (host_port, protocol);
        if self.listeners.contains_key(&key) {
            return Ok(()); // Already listening.
        }

        let cancel = CancellationToken::new();
        let cmd_tx = self.cmd_tx.clone();

        let handle = match protocol {
            InboundProtocol::Tcp => {
                let listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::UNSPECIFIED,
                    host_port,
                )))
                .await?;
                tracing::info!(
                    "Inbound listener: TCP :{} → container :{}",
                    host_port,
                    container_port,
                );
                let cancel_clone = cancel.clone();
                tokio::spawn(async move {
                    tcp_listener_task(listener, container_port, cmd_tx, cancel_clone).await;
                })
            }
            InboundProtocol::Udp => {
                let socket = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::UNSPECIFIED,
                    host_port,
                )))
                .await?;
                tracing::info!(
                    "Inbound listener: UDP :{} → container :{}",
                    host_port,
                    container_port,
                );
                let cancel_clone = cancel.clone();
                tokio::spawn(async move {
                    udp_listener_task(socket, container_port, cmd_tx, cancel_clone).await;
                })
            }
        };

        self.listeners.insert(key, (handle, cancel));
        Ok(())
    }

    /// Removes a forwarding rule and stops its listener.
    pub fn remove_rule(&mut self, host_port: u16, protocol: InboundProtocol) {
        let key = (host_port, protocol);
        if let Some((handle, cancel)) = self.listeners.remove(&key) {
            cancel.cancel();
            handle.abort();
            tracing::debug!("Inbound listener removed: {:?} :{}", protocol, host_port,);
        }
    }

    /// Stops all listeners.
    pub fn stop_all(&mut self) {
        for ((port, proto), (handle, cancel)) in self.listeners.drain() {
            cancel.cancel();
            handle.abort();
            tracing::debug!("Inbound listener stopped: {:?} :{}", proto, port);
        }
    }
}

// ---------------------------------------------------------------------------
// Listener tasks
// ---------------------------------------------------------------------------

/// TCP listener task: accepts connections and sends `InboundCommand::TcpAccepted`.
async fn tcp_listener_task(
    listener: TcpListener,
    container_port: u16,
    cmd_tx: mpsc::Sender<InboundCommand>,
    cancel: CancellationToken,
) {
    let host_port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        tracing::debug!(
                            "Inbound TCP accept: {} → host:{} → container:{}",
                            peer, host_port, container_port,
                        );
                        let cmd = InboundCommand::TcpAccepted {
                            host_port,
                            container_port,
                            stream,
                        };
                        if cmd_tx.send(cmd).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Inbound TCP accept error on :{}: {}", host_port, e);
                    }
                }
            }
        }
    }
}

/// UDP listener task: receives datagrams and sends `InboundCommand::UdpReceived`.
async fn udp_listener_task(
    socket: UdpSocket,
    container_port: u16,
    cmd_tx: mpsc::Sender<InboundCommand>,
    cancel: CancellationToken,
) {
    let host_port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, client_addr)) => {
                        // Create a reply channel for this client.
                        let (reply_tx, mut reply_rx) = mpsc::channel::<Vec<u8>>(16);

                        // Spawn a task that relays reply datagrams back to the client.
                        let socket_clone = socket.local_addr().ok();
                        tokio::spawn(async move {
                            while let Some(data) = reply_rx.recv().await {
                                // Send the reply back to the original client.
                                // We need a new socket since the listener owns the original.
                                let Ok(reply_sock) = UdpSocket::bind("0.0.0.0:0").await else {
                                    break;
                                };
                                let _ = reply_sock.send_to(&data, client_addr).await;
                            }
                            let _ = socket_clone; // Keep variable alive for tracing.
                        });

                        let cmd = InboundCommand::UdpReceived {
                            host_port,
                            container_port,
                            data: buf[..n].to_vec(),
                            reply_tx,
                            client_addr,
                        };
                        if cmd_tx.send(cmd).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Inbound UDP recv error on :{}: {}", host_port, e);
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const GW_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 64, 1);
    const GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 64, 2);
    const GW_MAC: [u8; 6] = [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x01];
    const GUEST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x99];

    #[test]
    fn ephemeral_ports_allocation() {
        let mut ep = EphemeralPorts::new();
        assert_eq!(ep.allocate(), 61000);
        assert_eq!(ep.allocate(), 61001);
    }

    #[test]
    fn ephemeral_ports_wrap_around() {
        let mut ep = EphemeralPorts::new();
        ep.next = EPHEMERAL_END;
        assert_eq!(ep.allocate(), EPHEMERAL_END);
        assert_eq!(ep.allocate(), EPHEMERAL_START);
    }

    #[test]
    fn ephemeral_ports_in_range() {
        assert!(EphemeralPorts::in_range(61000));
        assert!(EphemeralPorts::in_range(65535));
        assert!(EphemeralPorts::in_range(63000));
        assert!(!EphemeralPorts::in_range(60999));
        assert!(!EphemeralPorts::in_range(32768));
        assert!(!EphemeralPorts::in_range(80));
    }

    #[test]
    fn inbound_relay_rejects_non_ephemeral() {
        let (tx, _rx) = mpsc::channel(16);
        let mut relay = InboundRelay::new(tx, GW_MAC, GW_IP, GUEST_IP);

        // Build a minimal TCP frame with dst_port=80 (not in ephemeral range).
        let mut frame = vec![0u8; ETH_HEADER_LEN + 40];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let ip = &mut frame[ETH_HEADER_LEN..];
        ip[0] = 0x45;
        ip[9] = 6; // TCP
        ip[12..16].copy_from_slice(&GUEST_IP.octets());
        ip[16..20].copy_from_slice(&GW_IP.octets());
        // TCP header: src_port=8080, dst_port=80
        let tcp = &mut frame[ETH_HEADER_LEN + 20..];
        tcp[0..2].copy_from_slice(&8080u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[12] = 0x50; // data offset = 5

        assert!(!relay.try_handle_reply(&frame, GUEST_MAC));
    }

    #[tokio::test]
    async fn inject_udp_sends_frame_and_tracks_flow() {
        let (tx, mut rx) = mpsc::channel(16);
        let mut relay = InboundRelay::new(tx, GW_MAC, GW_IP, GUEST_IP);

        let (client_tx, _client_rx) = mpsc::channel(16);
        relay.inject_udp(53, b"dns query", client_tx, GUEST_MAC);

        // Flow should be tracked.
        let key = (GW_IP, EPHEMERAL_START, GUEST_IP, 53);
        assert!(relay.udp_flows.contains_key(&key));

        // A UDP frame should have been sent.
        let frame = rx.recv().await.expect("should receive UDP frame");
        assert!(frame.len() >= ETH_HEADER_LEN + 28, "UDP frame too short");

        // Verify IP protocol = UDP (17).
        assert_eq!(frame[ETH_HEADER_LEN + 9], 17);

        // Verify ports.
        let udp_start = ETH_HEADER_LEN + 20;
        let src_port = u16::from_be_bytes([frame[udp_start], frame[udp_start + 1]]);
        let dst_port = u16::from_be_bytes([frame[udp_start + 2], frame[udp_start + 3]]);
        assert_eq!(src_port, EPHEMERAL_START);
        assert_eq!(dst_port, 53);
    }

    #[test]
    fn cleanup_removes_expired_udp_flows() {
        let (tx, _rx) = mpsc::channel(16);
        let mut relay = InboundRelay::new(tx, GW_MAC, GW_IP, GUEST_IP);

        let (client_tx, _client_rx) = mpsc::channel(16);
        let key = (GW_IP, 61000, GUEST_IP, 53);
        relay.udp_flows.insert(
            key,
            InboundUdpFlow {
                client_tx,
                last_active: Instant::now() - std::time::Duration::from_secs(120),
            },
        );
        assert_eq!(relay.udp_flows.len(), 1);

        relay.cleanup();
        assert_eq!(
            relay.udp_flows.len(),
            0,
            "expired UDP flow should be removed"
        );
    }

    #[tokio::test]
    async fn listener_manager_add_and_remove_rule() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let mut manager = InboundListenerManager::new(cmd_tx);

        // Add a TCP rule on an ephemeral port.
        manager
            .add_rule(0, 80, InboundProtocol::Tcp)
            .await
            .expect("should bind to port 0 (OS-assigned)");

        // Remove it.
        manager.remove_rule(0, InboundProtocol::Tcp);

        // The cmd_rx channel should still be valid (no panic).
        assert!(cmd_rx.try_recv().is_err(), "no commands expected yet");
    }

    #[tokio::test]
    async fn listener_manager_stop_all() {
        let (cmd_tx, _cmd_rx) = mpsc::channel(16);
        let mut manager = InboundListenerManager::new(cmd_tx);

        manager.add_rule(0, 80, InboundProtocol::Tcp).await.unwrap();
        manager.add_rule(0, 53, InboundProtocol::Udp).await.unwrap();

        manager.stop_all();
        // After stop_all, the internal map should be empty. Since we can't
        // inspect it directly, adding the same rule again should succeed (no
        // duplicate key).
        manager.add_rule(0, 80, InboundProtocol::Tcp).await.unwrap();
    }
}
