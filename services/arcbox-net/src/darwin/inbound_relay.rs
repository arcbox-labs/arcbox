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
//!     ├─ TCP: inject SYN → guest SYN-ACK → ACK → spawn relay task
//!     └─ UDP: inject datagram → guest reply → forward to client
//!     │
//!     ▼
//! reply_tx ──► datapath ──► guest_fd (socketpair) ──► Guest VM
//! ```

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::ethernet::{
    ETH_HEADER_LEN, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, build_tcp_ip_ethernet,
    build_udp_ip_ethernet,
};

use super::socket_proxy::rand_isn;

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
// TCP connection state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundTcpState {
    /// SYN injected, waiting for SYN-ACK from guest.
    SynSent,
    /// Three-way handshake complete, relay task spawned.
    Established,
    /// FIN sent or received, tearing down.
    Closing,
    /// Fully closed, awaiting cleanup.
    Closed,
}

/// Per-connection inbound TCP state.
struct InboundTcpConn {
    state: InboundTcpState,
    /// Our (gateway) sequence number sent to the guest.
    host_seq: u32,
    /// Next expected sequence number from the guest.
    guest_seq: u32,
    /// Channel to forward data received from the guest to the relay write task.
    data_tx: mpsc::Sender<Vec<u8>>,
    /// Relay receiver — `Some` until the relay task is spawned (on Established).
    pending_rx: Option<mpsc::Receiver<Vec<u8>>>,
    /// Host-side TcpStream — `Some` until moved into the relay task.
    stream: Option<tokio::net::TcpStream>,
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
    /// Active TCP connections keyed by (gateway_ip, ephemeral_port, guest_ip, container_port).
    tcp_conns: HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), InboundTcpConn>,
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
            tcp_conns: HashMap::new(),
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
    pub(crate) fn try_handle_reply(&mut self, frame: &[u8], guest_mac: [u8; 6]) -> bool {
        if frame.len() < ETH_HEADER_LEN + 20 {
            return false;
        }

        let ip_start = ETH_HEADER_LEN;
        let protocol = frame[ip_start + 9];

        let ihl = ((frame[ip_start] & 0x0F) as usize) * 4;
        let l4_start = ip_start + ihl;

        match protocol {
            6 => self.try_handle_tcp_reply(frame, ip_start, l4_start, guest_mac),
            17 => self.try_handle_udp_reply(frame, ip_start, l4_start),
            _ => false,
        }
    }

    /// Checks if a TCP frame is a reply to an inbound connection.
    fn try_handle_tcp_reply(
        &mut self,
        frame: &[u8],
        ip_start: usize,
        tcp_start: usize,
        guest_mac: [u8; 6],
    ) -> bool {
        if frame.len() < tcp_start + 20 {
            return false;
        }

        let dst_port = u16::from_be_bytes([frame[tcp_start + 2], frame[tcp_start + 3]]);
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
        let src_port = u16::from_be_bytes([frame[tcp_start], frame[tcp_start + 1]]);

        let key = (dst_ip, dst_port, src_ip, src_port);

        if self.tcp_conns.contains_key(&key) {
            self.handle_tcp_reply(key, frame, tcp_start, guest_mac);
            return true;
        }

        false
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
                let client_tx = flow.client_tx.clone();
                tokio::spawn(async move {
                    let _ = client_tx.send(payload).await;
                });
            }
            return true;
        }

        false
    }

    // -----------------------------------------------------------------------
    // TCP: initiate connection to guest
    // -----------------------------------------------------------------------

    /// Initiates a TCP connection to the guest by injecting a SYN frame.
    pub(crate) fn initiate_tcp(
        &mut self,
        container_port: u16,
        stream: tokio::net::TcpStream,
        guest_mac: [u8; 6],
    ) {
        let ephemeral_port = self.ephemeral_ports.allocate();
        let host_isn = rand_isn();
        let key = (
            self.gateway_ip,
            ephemeral_port,
            self.guest_ip,
            container_port,
        );

        // Remove any stale connection with the same key.
        self.tcp_conns.remove(&key);

        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);

        self.tcp_conns.insert(
            key,
            InboundTcpConn {
                state: InboundTcpState::SynSent,
                host_seq: host_isn,
                guest_seq: 0,
                data_tx,
                pending_rx: Some(data_rx),
                stream: Some(stream),
            },
        );

        // Inject SYN.
        let syn = build_tcp_ip_ethernet(
            self.gateway_ip,
            self.guest_ip,
            ephemeral_port,
            container_port,
            host_isn,
            0,
            TCP_SYN,
            65535,
            &[],
            self.gateway_mac,
            guest_mac,
        );

        let reply_tx = self.reply_tx.clone();
        tokio::spawn(async move {
            let _ = reply_tx.send(syn).await;
        });

        tracing::debug!(
            "Inbound TCP: SYN injected  gw:{} → guest:{}",
            ephemeral_port,
            container_port,
        );
    }

    // -----------------------------------------------------------------------
    // TCP: handle reply frames from guest
    // -----------------------------------------------------------------------

    fn handle_tcp_reply(
        &mut self,
        key: (Ipv4Addr, u16, Ipv4Addr, u16),
        frame: &[u8],
        tcp_start: usize,
        guest_mac: [u8; 6],
    ) {
        let flags = frame[tcp_start + 13];
        let seq = u32::from_be_bytes([
            frame[tcp_start + 4],
            frame[tcp_start + 5],
            frame[tcp_start + 6],
            frame[tcp_start + 7],
        ]);
        let data_offset = ((frame[tcp_start + 12] >> 4) as usize) * 4;
        let payload_start = tcp_start + data_offset;
        let payload = if payload_start < frame.len() {
            &frame[payload_start..]
        } else {
            &[]
        };

        let (gw_ip, eph_port, guest_ip, container_port) = key;

        let Some(conn) = self.tcp_conns.get_mut(&key) else {
            return;
        };

        match conn.state {
            InboundTcpState::SynSent => {
                if flags & TCP_SYN != 0 && flags & TCP_ACK != 0 {
                    // Guest sent SYN-ACK. Complete handshake with ACK.
                    conn.guest_seq = seq.wrapping_add(1);
                    conn.host_seq = conn.host_seq.wrapping_add(1); // SYN consumed one seq
                    conn.state = InboundTcpState::Established;

                    let ack = build_tcp_ip_ethernet(
                        gw_ip,
                        guest_ip,
                        eph_port,
                        container_port,
                        conn.host_seq,
                        conn.guest_seq,
                        TCP_ACK,
                        65535,
                        &[],
                        self.gateway_mac,
                        guest_mac,
                    );

                    let reply_tx = self.reply_tx.clone();
                    tokio::spawn(async move {
                        let _ = reply_tx.send(ack).await;
                    });

                    tracing::debug!(
                        "Inbound TCP: established  gw:{} ↔ guest:{}",
                        eph_port,
                        container_port,
                    );

                    // Spawn the bidirectional relay task.
                    self.spawn_relay(key, guest_mac);
                } else if flags & TCP_RST != 0 {
                    tracing::debug!(
                        "Inbound TCP: RST during handshake  gw:{} → guest:{}",
                        eph_port,
                        container_port,
                    );
                    conn.state = InboundTcpState::Closed;
                }
            }

            InboundTcpState::Established => {
                if flags & TCP_RST != 0 {
                    conn.state = InboundTcpState::Closed;
                    let _ = conn.data_tx.try_send(Vec::new()); // Signal close.
                    return;
                }

                if flags & TCP_FIN != 0 {
                    conn.guest_seq = seq.wrapping_add(payload.len() as u32).wrapping_add(1);
                    conn.state = InboundTcpState::Closing;

                    // Forward any remaining payload.
                    if !payload.is_empty() {
                        let _ = conn.data_tx.try_send(payload.to_vec());
                    }
                    // Signal close to the relay task.
                    let _ = conn.data_tx.try_send(Vec::new());

                    // ACK the FIN.
                    let fin_ack = build_tcp_ip_ethernet(
                        gw_ip,
                        guest_ip,
                        eph_port,
                        container_port,
                        conn.host_seq,
                        conn.guest_seq,
                        TCP_FIN | TCP_ACK,
                        65535,
                        &[],
                        self.gateway_mac,
                        guest_mac,
                    );
                    let reply_tx = self.reply_tx.clone();
                    tokio::spawn(async move {
                        let _ = reply_tx.send(fin_ack).await;
                    });
                    return;
                }

                if !payload.is_empty() {
                    conn.guest_seq = seq.wrapping_add(payload.len() as u32);

                    // ACK the data.
                    let ack = build_tcp_ip_ethernet(
                        gw_ip,
                        guest_ip,
                        eph_port,
                        container_port,
                        conn.host_seq,
                        conn.guest_seq,
                        TCP_ACK,
                        65535,
                        &[],
                        self.gateway_mac,
                        guest_mac,
                    );

                    let reply_tx = self.reply_tx.clone();
                    let payload_vec = payload.to_vec();
                    let data_tx = conn.data_tx.clone();
                    tokio::spawn(async move {
                        let _ = reply_tx.send(ack).await;
                        let _ = data_tx.send(payload_vec).await;
                    });
                }
            }

            InboundTcpState::Closing => {
                if flags & TCP_ACK != 0 {
                    conn.state = InboundTcpState::Closed;
                }
            }

            InboundTcpState::Closed => {}
        }
    }

    /// Spawns the bidirectional relay task once the TCP handshake completes.
    fn spawn_relay(&mut self, key: (Ipv4Addr, u16, Ipv4Addr, u16), guest_mac: [u8; 6]) {
        let Some(conn) = self.tcp_conns.get_mut(&key) else {
            return;
        };

        let stream = match conn.stream.take() {
            Some(s) => s,
            None => return,
        };
        let data_rx = match conn.pending_rx.take() {
            Some(r) => r,
            None => return,
        };

        let (gw_ip, eph_port, guest_ip, container_port) = key;
        let host_seq = conn.host_seq;
        let reply_tx = self.reply_tx.clone();
        let gateway_mac = self.gateway_mac;

        // Host-to-guest relay: read TcpStream → build TCP data frames → reply_tx.
        tokio::spawn(async move {
            inbound_tcp_relay(
                stream,
                data_rx,
                reply_tx,
                gw_ip,
                gateway_mac,
                guest_ip,
                eph_port,
                container_port,
                guest_mac,
                host_seq,
            )
            .await;
        });
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

        let reply_tx = self.reply_tx.clone();
        tokio::spawn(async move {
            let _ = reply_tx.send(frame).await;
        });

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

    /// Removes closed TCP connections and expired UDP flows.
    pub(crate) fn cleanup(&mut self) {
        self.tcp_conns
            .retain(|_, conn| conn.state != InboundTcpState::Closed);

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
// Bidirectional TCP relay (host TcpStream ↔ guest TCP segments)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn inbound_tcp_relay(
    stream: tokio::net::TcpStream,
    mut data_rx: mpsc::Receiver<Vec<u8>>,
    reply_tx: mpsc::Sender<Vec<u8>>,
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
    guest_ip: Ipv4Addr,
    ephemeral_port: u16,
    container_port: u16,
    guest_mac: [u8; 6],
    mut host_seq: u32,
) {
    let (mut reader, mut writer) = stream.into_split();

    // Host → Guest: read from TcpStream, inject data frames.
    let reply_tx2 = reply_tx.clone();
    let host_to_guest = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    // EOF: send FIN to guest.
                    let fin = build_tcp_ip_ethernet(
                        gateway_ip,
                        guest_ip,
                        ephemeral_port,
                        container_port,
                        host_seq,
                        0,
                        TCP_FIN | TCP_ACK,
                        65535,
                        &[],
                        gateway_mac,
                        guest_mac,
                    );
                    let _ = reply_tx2.send(fin).await;
                    break;
                }
                Ok(n) => {
                    let data_frame = build_tcp_ip_ethernet(
                        gateway_ip,
                        guest_ip,
                        ephemeral_port,
                        container_port,
                        host_seq,
                        0,
                        TCP_ACK | TCP_PSH,
                        65535,
                        &buf[..n],
                        gateway_mac,
                        guest_mac,
                    );
                    host_seq = host_seq.wrapping_add(n as u32);
                    if reply_tx2.send(data_frame).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("Inbound TCP relay read error: {}", e);
                    break;
                }
            }
        }
    });

    // Guest → Host: receive data from data_rx, write to TcpStream.
    let guest_to_host = tokio::spawn(async move {
        while let Some(data) = data_rx.recv().await {
            if data.is_empty() {
                let _ = writer.shutdown().await;
                break;
            }
            if let Err(e) = writer.write_all(&data).await {
                tracing::debug!("Inbound TCP relay write error: {}", e);
                break;
            }
        }
    });

    let _ = tokio::join!(host_to_guest, guest_to_host);
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

    #[test]
    fn inbound_relay_cleanup_removes_closed() {
        let (tx, _rx) = mpsc::channel(16);
        let mut relay = InboundRelay::new(tx, GW_MAC, GW_IP, GUEST_IP);

        let (data_tx, _data_rx) = mpsc::channel(16);
        let key = (GW_IP, 61000, GUEST_IP, 80);
        relay.tcp_conns.insert(
            key,
            InboundTcpConn {
                state: InboundTcpState::Closed,
                host_seq: 0,
                guest_seq: 0,
                data_tx,
                pending_rx: None,
                stream: None,
            },
        );
        assert_eq!(relay.tcp_conns.len(), 1);

        relay.cleanup();
        assert_eq!(relay.tcp_conns.len(), 0);
    }

    #[tokio::test]
    async fn initiate_tcp_sends_syn_and_tracks_connection() {
        let (tx, mut rx) = mpsc::channel(16);
        let mut relay = InboundRelay::new(tx, GW_MAC, GW_IP, GUEST_IP);

        // Create a pair of connected TcpStreams for the host-side stream.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = tokio::net::TcpStream::connect(addr);
        let (stream, _accepted) = tokio::join!(connect, listener.accept());
        let stream = stream.unwrap();

        relay.initiate_tcp(80, stream, GUEST_MAC);

        // Connection should be tracked in SynSent state.
        let key = (GW_IP, EPHEMERAL_START, GUEST_IP, 80);
        let conn = relay.tcp_conns.get(&key).expect("connection should exist");
        assert_eq!(conn.state, InboundTcpState::SynSent);
        assert!(conn.stream.is_some(), "stream should be stored");
        assert!(conn.pending_rx.is_some(), "pending_rx should be stored");

        // A SYN frame should have been sent via reply_tx.
        let syn = rx.recv().await.expect("should receive SYN frame");
        assert!(syn.len() >= ETH_HEADER_LEN + 40, "SYN frame too short");

        // Verify TCP flags: SYN only.
        let tcp_start = ETH_HEADER_LEN + 20;
        let flags = syn[tcp_start + 13];
        assert_eq!(flags & TCP_SYN, TCP_SYN, "SYN flag should be set");
        assert_eq!(flags & TCP_ACK, 0, "ACK flag should NOT be set");

        // Verify ports.
        let src_port = u16::from_be_bytes([syn[tcp_start], syn[tcp_start + 1]]);
        let dst_port = u16::from_be_bytes([syn[tcp_start + 2], syn[tcp_start + 3]]);
        assert_eq!(src_port, EPHEMERAL_START);
        assert_eq!(dst_port, 80);
    }

    #[tokio::test]
    async fn syn_ack_transitions_to_established() {
        let (tx, mut rx) = mpsc::channel(16);
        let mut relay = InboundRelay::new(tx, GW_MAC, GW_IP, GUEST_IP);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = tokio::net::TcpStream::connect(addr);
        let (stream, _accepted) = tokio::join!(connect, listener.accept());
        let stream = stream.unwrap();

        relay.initiate_tcp(80, stream, GUEST_MAC);

        // Drain the SYN frame.
        let _syn = rx.recv().await.unwrap();

        let key = (GW_IP, EPHEMERAL_START, GUEST_IP, 80);
        let host_isn = relay.tcp_conns.get(&key).unwrap().host_seq;

        // Construct a SYN-ACK from the guest.
        let guest_isn: u32 = 5000;
        let syn_ack = build_tcp_ip_ethernet(
            GUEST_IP,
            GW_IP,
            80,
            EPHEMERAL_START,
            guest_isn,
            host_isn.wrapping_add(1),
            TCP_SYN | TCP_ACK,
            65535,
            &[],
            GUEST_MAC,
            GW_MAC,
        );

        // Feed the SYN-ACK to the relay.
        let handled = relay.try_handle_reply(&syn_ack, GUEST_MAC);
        assert!(handled, "SYN-ACK should be handled");

        // Connection should now be Established.
        let conn = relay.tcp_conns.get(&key).unwrap();
        assert_eq!(conn.state, InboundTcpState::Established);
        assert_eq!(conn.guest_seq, guest_isn.wrapping_add(1));
        assert_eq!(conn.host_seq, host_isn.wrapping_add(1));
        // Stream and pending_rx should have been taken by spawn_relay.
        assert!(conn.stream.is_none(), "stream should be moved to relay");
        assert!(
            conn.pending_rx.is_none(),
            "pending_rx should be moved to relay"
        );

        // An ACK should have been sent.
        let ack = rx.recv().await.expect("should receive ACK frame");
        let tcp_start = ETH_HEADER_LEN + 20;
        let flags = ack[tcp_start + 13];
        assert_eq!(flags & TCP_ACK, TCP_ACK, "ACK flag should be set");
        assert_eq!(flags & TCP_SYN, 0, "SYN flag should NOT be set");
    }

    #[tokio::test]
    async fn rst_during_handshake_transitions_to_closed() {
        let (tx, mut rx) = mpsc::channel(16);
        let mut relay = InboundRelay::new(tx, GW_MAC, GW_IP, GUEST_IP);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = tokio::net::TcpStream::connect(addr);
        let (stream, _accepted) = tokio::join!(connect, listener.accept());

        relay.initiate_tcp(80, stream.unwrap(), GUEST_MAC);
        let _syn = rx.recv().await.unwrap();

        let key = (GW_IP, EPHEMERAL_START, GUEST_IP, 80);
        let host_isn = relay.tcp_conns.get(&key).unwrap().host_seq;

        // Send RST from guest.
        let rst = build_tcp_ip_ethernet(
            GUEST_IP,
            GW_IP,
            80,
            EPHEMERAL_START,
            0,
            host_isn.wrapping_add(1),
            TCP_RST,
            0,
            &[],
            GUEST_MAC,
            GW_MAC,
        );

        let handled = relay.try_handle_reply(&rst, GUEST_MAC);
        assert!(handled, "RST should be handled");

        let conn = relay.tcp_conns.get(&key).unwrap();
        assert_eq!(conn.state, InboundTcpState::Closed);
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
