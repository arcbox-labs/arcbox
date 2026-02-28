//! Inbound port forwarding via L2 frame injection.
//!
//! Instead of using utun + kernel routing, we inject crafted L2 Ethernet frames
//! directly into the guest FD (socketpair) so that host-side TCP listeners can
//! reach services inside the guest VM.
//!
//! # Architecture
//!
//! ```text
//! External client (host:8080)
//!     │
//!     ▼
//! InboundListenerManager (TcpListener per rule)
//!     │ accept
//!     ▼
//! InboundCommand channel  ──►  NetworkDatapath select! arm
//!     │
//!     ▼
//! InboundRelay
//!     └─ TCP: inject SYN → guest SYN-ACK → ACK → spawn relay task
//!     │
//!     ▼
//! reply_tx ──► datapath ──► guest_fd (socketpair) ──► Guest VM
//! ```

use std::collections::HashMap;
use std::net::Ipv4Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::ethernet::{
    ETH_HEADER_LEN, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, build_tcp_ip_ethernet,
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
pub(crate) enum InboundCommand {
    /// A new TCP connection was accepted on a host listener.
    TcpAccepted {
        host_port: u16,
        container_port: u16,
        stream: tokio::net::TcpStream,
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
// InboundRelay
// ---------------------------------------------------------------------------

/// Handles inbound (host → guest) connections by injecting L2 Ethernet frames
/// directly into the guest FD through the `reply_tx` channel.
pub(crate) struct InboundRelay {
    /// Active TCP connections keyed by (gateway_ip, ephemeral_port, guest_ip, container_port).
    tcp_conns: HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), InboundTcpConn>,
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

        if protocol != 6 {
            return false;
        }

        let ihl = ((frame[ip_start] & 0x0F) as usize) * 4;
        let tcp_start = ip_start + ihl;
        if frame.len() < tcp_start + 20 {
            return false;
        }

        let dst_port = u16::from_be_bytes([frame[tcp_start + 2], frame[tcp_start + 3]]);

        // Fast reject: destination port not in our ephemeral range.
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

        // Guest sends: src=(guest_ip, container_port) dst=(gateway_ip, ephemeral_port)
        // Our key:  (gateway_ip, ephemeral_port, guest_ip, container_port)
        let key = (dst_ip, dst_port, src_ip, src_port);

        if self.tcp_conns.contains_key(&key) {
            self.handle_tcp_reply(key, frame, tcp_start, guest_mac);
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
    // Maintenance
    // -----------------------------------------------------------------------

    /// Removes closed connections.
    pub(crate) fn cleanup(&mut self) {
        self.tcp_conns
            .retain(|_, conn| conn.state != InboundTcpState::Closed);
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
        let gw_ip = Ipv4Addr::new(192, 168, 64, 1);
        let guest_ip = Ipv4Addr::new(192, 168, 64, 2);
        let gw_mac = [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x01];
        let guest_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x99];

        let mut relay = InboundRelay::new(tx, gw_mac, gw_ip, guest_ip);

        // Build a minimal TCP frame with dst_port=80 (not in ephemeral range).
        let mut frame = vec![0u8; ETH_HEADER_LEN + 40];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let ip = &mut frame[ETH_HEADER_LEN..];
        ip[0] = 0x45;
        ip[9] = 6; // TCP
        ip[12..16].copy_from_slice(&guest_ip.octets());
        ip[16..20].copy_from_slice(&gw_ip.octets());
        // TCP header: src_port=8080, dst_port=80
        let tcp = &mut frame[ETH_HEADER_LEN + 20..];
        tcp[0..2].copy_from_slice(&8080u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[12] = 0x50; // data offset = 5

        assert!(!relay.try_handle_reply(&frame, guest_mac));
    }

    #[test]
    fn inbound_relay_cleanup_removes_closed() {
        let (tx, _rx) = mpsc::channel(16);
        let gw_ip = Ipv4Addr::new(192, 168, 64, 1);
        let guest_ip = Ipv4Addr::new(192, 168, 64, 2);
        let gw_mac = [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x01];

        let mut relay = InboundRelay::new(tx.clone(), gw_mac, gw_ip, guest_ip);

        let (data_tx, _data_rx) = mpsc::channel(16);
        let key = (gw_ip, 61000, guest_ip, 80);
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
}
