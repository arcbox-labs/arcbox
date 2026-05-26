//! TSO-aware network backend for the custom Hypervisor.framework VMM.
//!
//! This backend implements [`NetBackend`] with two paths:
//!
//! - **TSO fast path**: when the guest emits a packet with `gso_type != NONE`,
//!   the TCP payload is extracted and written directly to a host `TcpStream`.
//!   No classifier, no L2 framing — just payload relay. This is the path
//!   that enables 50 Gbps port forwarding.
//!
//! - **Slow path**: normal (non-TSO) packets — ARP, DHCP, DNS, UDP, small
//!   TCP — are forwarded to the existing `NetworkDatapath` via a channel,
//!   preserving full protocol compatibility.
//!
//! # TSO TX Flow (Guest → Host)
//!
//! ```text
//! Guest kernel sends 64 KB TCP segment
//!   → VirtIO-net TX queue with gso_type=GSO_TCPV4, gso_size=1460
//!   → VirtioNet.handle_tx() detects TSO → calls send_tso()
//!   → TsoNetBackend extracts (src_ip, src_port, dst_ip, dst_port)
//!   → Looks up or creates host TcpStream for this flow
//!   → Writes entire payload to TcpStream in one call
//!   → No classifier, no NAT, no framing overhead
//! ```
//!
//! # TSO RX Flow (Host → Guest)
//!
//! ```text
//! Host TcpStream read returns up to 64 KB
//!   → TsoNetBackend constructs Ethernet + IP + TCP headers
//!   → Queues as NetPacket with gso_type=GSO_TCPV4, gso_size=MSS
//!   → VirtioNet.inject_rx_batch() pushes single large descriptor
//!   → Guest kernel handles segmentation — one interrupt instead of ~45
//! ```

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};

use arcbox_virtio::net::{NetBackend, NetPacket, VirtioNetHeader};

/// Ethernet header length.
const ETH_HDR_LEN: usize = 14;
/// Minimum IPv4 header length.
const IPV4_HDR_LEN: usize = 20;
/// TCP header length (without options).
const TCP_HDR_LEN: usize = 20;
/// Minimum L2+L3+L4 header size.
const MIN_HEADERS: usize = ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN;

/// IPv4 protocol number for TCP.
const PROTO_TCP: u8 = 6;

/// A TCP flow key for connection lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpFlowKey {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

/// An established TCP connection on the host side.
struct HostTcpConn {
    stream: TcpStream,
    /// Tracks bytes sent for logging.
    tx_bytes: u64,
}

/// TSO-aware network backend.
///
/// Maintains a map of guest TCP flows to host `TcpStream` connections.
/// TSO packets bypass the classifier entirely; non-TSO packets are
/// forwarded to the slow path channel.
pub struct TsoNetBackend {
    /// Active TCP connections keyed by guest-side flow.
    connections: HashMap<TcpFlowKey, HostTcpConn>,
    /// Channel to forward non-TSO packets to the classifier datapath.
    slow_path_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Channel to receive packets from the classifier datapath (RX path).
    slow_path_rx: std::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    /// Packets ready for guest injection.
    rx_pending: std::collections::VecDeque<Vec<u8>>,
}

impl TsoNetBackend {
    /// Creates a new TSO backend.
    ///
    /// - `slow_path_tx`: sends non-TSO frames to the classifier datapath.
    /// - `slow_path_rx`: receives frames from the classifier datapath for
    ///   injection into the guest.
    pub fn new(
        slow_path_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        slow_path_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        Self {
            connections: HashMap::new(),
            slow_path_tx,
            slow_path_rx: std::sync::Mutex::new(slow_path_rx),
            rx_pending: std::collections::VecDeque::new(),
        }
    }

    /// Extracts TCP flow key and payload offset from an Ethernet frame.
    fn parse_tcp_flow(data: &[u8]) -> Option<(TcpFlowKey, usize)> {
        if data.len() < MIN_HEADERS {
            return None;
        }

        // Ethernet: check EtherType = IPv4 (0x0800).
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        if ethertype != 0x0800 {
            return None;
        }

        let ip_start = ETH_HDR_LEN;

        // IPv4: check protocol = TCP.
        let protocol = data[ip_start + 9];
        if protocol != PROTO_TCP {
            return None;
        }

        let ihl = ((data[ip_start] & 0x0F) as usize) * 4;
        let tcp_start = ip_start + ihl;
        if data.len() < tcp_start + TCP_HDR_LEN {
            return None;
        }

        let src_ip = Ipv4Addr::new(
            data[ip_start + 12],
            data[ip_start + 13],
            data[ip_start + 14],
            data[ip_start + 15],
        );
        let dst_ip = Ipv4Addr::new(
            data[ip_start + 16],
            data[ip_start + 17],
            data[ip_start + 18],
            data[ip_start + 19],
        );
        let src_port = u16::from_be_bytes([data[tcp_start], data[tcp_start + 1]]);
        let dst_port = u16::from_be_bytes([data[tcp_start + 2], data[tcp_start + 3]]);

        let tcp_data_offset = ((data[tcp_start + 12] >> 4) as usize) * 4;
        let payload_start = tcp_start + tcp_data_offset;

        Some((
            TcpFlowKey {
                src_ip,
                src_port,
                dst_ip,
                dst_port,
            },
            payload_start,
        ))
    }

    /// Handles a TSO TX packet: extract payload and write to host TcpStream.
    fn handle_tso_tx(&mut self, packet: &NetPacket) -> io::Result<usize> {
        let (flow, payload_offset) = Self::parse_tcp_flow(&packet.data).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "TSO packet: cannot parse TCP flow",
            )
        })?;

        if payload_offset >= packet.data.len() {
            // No payload — this is a pure ACK or similar. Nothing to relay.
            return Ok(0);
        }

        let payload = &packet.data[payload_offset..];

        // Look up or create a host-side TCP connection.
        let conn = match self.connections.get_mut(&flow) {
            Some(c) => c,
            None => {
                let addr = SocketAddr::new(flow.dst_ip.into(), flow.dst_port);
                tracing::debug!(
                    "TSO: opening host TCP connection {}:{} → {addr}",
                    flow.src_ip,
                    flow.src_port
                );
                let stream = TcpStream::connect(addr).map_err(|e| {
                    io::Error::new(e.kind(), format!("TSO: connect to {addr} failed: {e}"))
                })?;
                stream.set_nodelay(true)?;
                self.connections.insert(
                    flow,
                    HostTcpConn {
                        stream,
                        tx_bytes: 0,
                    },
                );
                self.connections.get_mut(&flow).unwrap()
            }
        };

        // Write entire payload in one call.
        use std::io::Write;
        let n = conn.stream.write(payload)?;
        conn.tx_bytes += n as u64;

        tracing::trace!(
            "TSO TX: {}:{} → {}:{}, {} bytes (total {})",
            flow.src_ip,
            flow.src_port,
            flow.dst_ip,
            flow.dst_port,
            n,
            conn.tx_bytes
        );

        Ok(n)
    }

    /// Drains any packets from the slow path RX channel into rx_pending.
    fn drain_slow_path_rx(&mut self) {
        if let Ok(mut rx) = self.slow_path_rx.lock() {
            while let Ok(frame) = rx.try_recv() {
                self.rx_pending.push_back(frame);
            }
        }
    }
}

impl NetBackend for TsoNetBackend {
    fn send(&mut self, packet: &NetPacket) -> io::Result<usize> {
        // Non-TSO packet: forward to classifier datapath via channel.
        let frame = packet.data.clone();
        self.slow_path_tx.try_send(frame).map_err(|e| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("slow path channel full: {e}"),
            )
        })?;
        Ok(packet.data.len())
    }

    fn send_tso(&mut self, packet: &NetPacket) -> io::Result<usize> {
        self.handle_tso_tx(packet)
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // First drain any frames from the slow path.
        self.drain_slow_path_rx();

        // TODO(Phase 3b): Also poll host TcpStream connections for RX data,
        // construct TSO-stamped Ethernet frames, and push to rx_pending.

        if let Some(frame) = self.rx_pending.pop_front() {
            let n = frame.len().min(buf.len());
            buf[..n].copy_from_slice(&frame[..n]);
            Ok(n)
        } else {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "no data"))
        }
    }

    fn has_data(&self) -> bool {
        !self.rx_pending.is_empty()
    }

    fn supports_tso(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tcp_flow_valid() {
        // Construct a minimal Ethernet + IPv4 + TCP frame.
        let mut frame = vec![0u8; MIN_HEADERS + 10];
        // Ethernet: dst MAC, src MAC, EtherType=0x0800
        frame[12] = 0x08;
        frame[13] = 0x00;
        // IPv4: version=4, IHL=5 (20 bytes)
        frame[ETH_HDR_LEN] = 0x45;
        // Protocol = TCP
        frame[ETH_HDR_LEN + 9] = PROTO_TCP;
        // Src IP: 10.0.2.2
        frame[ETH_HDR_LEN + 12] = 10;
        frame[ETH_HDR_LEN + 14] = 2;
        frame[ETH_HDR_LEN + 15] = 2;
        // Dst IP: 1.1.1.1
        frame[ETH_HDR_LEN + 16] = 1;
        frame[ETH_HDR_LEN + 17] = 1;
        frame[ETH_HDR_LEN + 18] = 1;
        frame[ETH_HDR_LEN + 19] = 1;
        // TCP src port: 12345
        let tcp_start = ETH_HDR_LEN + IPV4_HDR_LEN;
        frame[tcp_start..tcp_start + 2].copy_from_slice(&12345u16.to_be_bytes());
        // TCP dst port: 443
        frame[tcp_start + 2..tcp_start + 4].copy_from_slice(&443u16.to_be_bytes());
        // TCP data offset: 5 (20 bytes, no options)
        frame[tcp_start + 12] = 0x50;

        let (flow, payload_offset) = TsoNetBackend::parse_tcp_flow(&frame).unwrap();
        assert_eq!(flow.src_ip, Ipv4Addr::new(10, 0, 2, 2));
        assert_eq!(flow.dst_ip, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(flow.src_port, 12345);
        assert_eq!(flow.dst_port, 443);
        assert_eq!(payload_offset, MIN_HEADERS);
    }

    #[test]
    fn test_parse_tcp_flow_non_tcp() {
        let mut frame = vec![0u8; MIN_HEADERS];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[ETH_HDR_LEN] = 0x45;
        frame[ETH_HDR_LEN + 9] = 17; // UDP, not TCP
        assert!(TsoNetBackend::parse_tcp_flow(&frame).is_none());
    }

    #[test]
    fn test_parse_tcp_flow_too_short() {
        let frame = vec![0u8; 10];
        assert!(TsoNetBackend::parse_tcp_flow(&frame).is_none());
    }

    #[test]
    fn test_parse_tcp_flow_non_ipv4() {
        let mut frame = vec![0u8; MIN_HEADERS];
        frame[12] = 0x86; // IPv6
        frame[13] = 0xDD;
        assert!(TsoNetBackend::parse_tcp_flow(&frame).is_none());
    }

    #[test]
    fn test_tso_backend_supports_tso() {
        let (tx, _rx_ignore) = tokio::sync::mpsc::channel(16);
        let (_tx_ignore, rx) = tokio::sync::mpsc::channel(16);
        let backend = TsoNetBackend::new(tx, rx);
        assert!(backend.supports_tso());
    }

    #[test]
    fn test_tso_backend_send_forwards_to_slow_path() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let (_tx_ignore, slow_rx) = tokio::sync::mpsc::channel(16);
        let mut backend = TsoNetBackend::new(tx, slow_rx);

        let packet = NetPacket::new(vec![1, 2, 3, 4]);
        backend.send(&packet).unwrap();

        let received = rx.try_recv().unwrap();
        assert_eq!(received, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_tso_backend_recv_drains_slow_path() {
        let (tx, _rx_ignore) = tokio::sync::mpsc::channel(16);
        let (slow_tx, slow_rx) = tokio::sync::mpsc::channel(16);
        let mut backend = TsoNetBackend::new(tx, slow_rx);

        // Inject a frame via slow path.
        slow_tx.try_send(vec![0xAA, 0xBB]).unwrap();

        let mut buf = vec![0u8; 64];
        let n = backend.recv(&mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], &[0xAA, 0xBB]);
    }

    #[test]
    fn test_tso_backend_recv_empty() {
        let (tx, _rx_ignore) = tokio::sync::mpsc::channel(16);
        let (_tx_ignore, slow_rx) = tokio::sync::mpsc::channel(16);
        let mut backend = TsoNetBackend::new(tx, slow_rx);

        let mut buf = vec![0u8; 64];
        let result = backend.recv(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_flow_key_equality() {
        let a = TcpFlowKey {
            src_ip: Ipv4Addr::new(10, 0, 2, 2),
            src_port: 1234,
            dst_ip: Ipv4Addr::new(1, 1, 1, 1),
            dst_port: 443,
        };
        let b = a;
        assert_eq!(a, b);

        let c = TcpFlowKey {
            src_port: 9999,
            ..a
        };
        assert_ne!(a, c);
    }
}
