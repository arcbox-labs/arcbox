//! NAT network backend bridging VirtioNet to NatEngine.
//!
//! This module provides `NatNetBackend`, which implements the `NetBackend` trait
//! from `arcbox-virtio` and routes packets through the NAT engine for address
//! translation.
//!
//! # Packet Flow
//!
//! ```text
//! TX (guest -> host):
//!   NetBackend::send(NetPacket)
//!     -> NatEngine::translate(Outbound)
//!       -> HostNetIO::send_packet()
//!
//! RX (host -> guest):
//!   HostNetIO::recv_packet()
//!     -> NatEngine::translate(Inbound)
//!       -> NetBackend::recv() returns data
//! ```

use std::collections::VecDeque;
use std::io;
use std::net::Ipv4Addr;

use arcbox_virtio::net::{NetBackend, NetPacket};

use crate::nat_engine::{NatDirection, NatEngine, NatEngineConfig, NatResult};

/// Trait for host-side network I/O.
///
/// This abstracts the actual mechanism used to send/receive packets on the host
/// network interface. Implementations may use utun, vmnet.framework, raw sockets,
/// TAP devices, or other mechanisms.
///
/// Methods take `&self` because the underlying I/O (file descriptor read/write)
/// is inherently thread-safe for datagram sockets.
pub trait HostNetIO: Send + Sync {
    /// Sends a raw IP packet to the host network stack.
    fn send_packet(&self, packet: &[u8]) -> io::Result<usize>;

    /// Receives a raw IP packet from the host network stack.
    ///
    /// Returns 0 if no data is available (non-blocking).
    fn recv_packet(&self, buf: &mut [u8]) -> io::Result<usize>;

    /// Returns true if there is data available to read.
    fn has_data(&self) -> bool;

    /// Returns the name/identifier of this I/O backend.
    fn name(&self) -> &str;
}

/// NAT network backend configuration.
#[derive(Debug, Clone)]
pub struct NatNetBackendConfig {
    /// External IP address for SNAT.
    pub external_ip: Ipv4Addr,
    /// Internal network prefix.
    pub internal_prefix: Ipv4Addr,
    /// Internal network prefix length.
    pub internal_prefix_len: u8,
    /// NAT port range start.
    pub port_range_start: u16,
    /// NAT port range end.
    pub port_range_end: u16,
    /// Connection timeout in seconds.
    pub connection_timeout_secs: u32,
}

impl Default for NatNetBackendConfig {
    fn default() -> Self {
        Self {
            external_ip: Ipv4Addr::new(192, 168, 64, 1),
            internal_prefix: Ipv4Addr::new(192, 168, 64, 0),
            internal_prefix_len: 24,
            port_range_start: 49152,
            port_range_end: 65535,
            connection_timeout_secs: 300,
        }
    }
}

/// NAT network backend bridging VirtioNet to NatEngine.
///
/// Implements the `NetBackend` trait from arcbox-virtio, performing NAT
/// translation on all packets flowing between the guest VM and the host
/// network.
pub struct NatNetBackend {
    /// NAT engine for packet translation.
    nat_engine: NatEngine,
    /// Host-side network I/O (shared ref for `&self` trait methods).
    host_io: Box<dyn HostNetIO>,
    /// Receive buffer for inbound packets pending delivery to guest.
    rx_queue: VecDeque<Vec<u8>>,
    /// Scratch buffer for receiving packets from host.
    rx_scratch: Vec<u8>,
}

impl NatNetBackend {
    /// Creates a new NAT network backend.
    pub fn new(config: NatNetBackendConfig, host_io: Box<dyn HostNetIO>) -> Self {
        let nat_config = NatEngineConfig::new(config.external_ip)
            .with_port_range(config.port_range_start, config.port_range_end)
            .with_timeout(config.connection_timeout_secs);

        let mut nat_engine = NatEngine::new(&nat_config);
        nat_engine.set_internal_network(config.internal_prefix, config.internal_prefix_len);

        Self {
            nat_engine,
            host_io,
            rx_queue: VecDeque::new(),
            rx_scratch: vec![0u8; 65536],
        }
    }

    /// Creates a backend with default NAT configuration.
    pub fn with_defaults(host_io: Box<dyn HostNetIO>) -> Self {
        Self::new(NatNetBackendConfig::default(), host_io)
    }

    /// Polls the host network for incoming packets and queues them for the guest.
    ///
    /// Performs NAT inbound translation on each received packet.
    fn poll_host(&mut self) {
        while self.host_io.has_data() {
            let n = match self.host_io.recv_packet(&mut self.rx_scratch) {
                Ok(n) if n > 0 => n,
                _ => break,
            };

            let mut packet_data = self.rx_scratch[..n].to_vec();

            // Safety: packet_data is a valid Ethernet frame received from host.
            let result = unsafe {
                self.nat_engine
                    .translate(&mut packet_data, NatDirection::Inbound)
            };

            match result {
                Ok(NatResult::Translated | NatResult::PassThrough) => {
                    self.rx_queue.push_back(packet_data);
                }
                Ok(NatResult::Dropped) => {
                    // No matching connection, drop silently.
                    tracing::trace!("NAT inbound: packet dropped (no connection)");
                }
                Err(e) => {
                    tracing::trace!("NAT inbound translation error: {}", e);
                }
            }
        }
    }

    /// Returns the number of active NAT connections.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.nat_engine.connection_count()
    }

    /// Expires old NAT connections.
    pub fn expire_connections(&mut self) -> usize {
        self.nat_engine.expire_connections()
    }
}

impl NetBackend for NatNetBackend {
    fn send(&mut self, packet: &NetPacket) -> io::Result<usize> {
        // packet.data is the Ethernet frame from the guest.
        let mut frame = packet.data.clone();

        // Safety: frame is a valid Ethernet frame from the guest VM.
        let result = unsafe {
            self.nat_engine
                .translate(&mut frame, NatDirection::Outbound)
        };

        match result {
            Ok(NatResult::Translated | NatResult::PassThrough) => self.host_io.send_packet(&frame),
            Ok(NatResult::Dropped) => {
                tracing::trace!("NAT outbound: packet dropped");
                Ok(0)
            }
            Err(e) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("NAT translation failed: {}", e),
            )),
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Poll host for new packets first.
        self.poll_host();

        // Return the next queued packet.
        if let Some(packet) = self.rx_queue.pop_front() {
            let len = packet.len().min(buf.len());
            buf[..len].copy_from_slice(&packet[..len]);
            Ok(len)
        } else {
            Ok(0)
        }
    }

    fn has_data(&self) -> bool {
        !self.rx_queue.is_empty() || self.host_io.has_data()
    }
}

impl std::fmt::Debug for NatNetBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NatNetBackend")
            .field("nat_engine", &self.nat_engine)
            .field("rx_queue_len", &self.rx_queue.len())
            .finish()
    }
}

/// Loopback host I/O for testing.
///
/// Packets sent are looped back directly, useful for unit testing
/// the NAT backend without real network access.
#[cfg(test)]
pub struct LoopbackHostIO {
    packets: std::cell::RefCell<VecDeque<Vec<u8>>>,
}

#[cfg(test)]
impl Default for LoopbackHostIO {
    fn default() -> Self {
        Self {
            packets: std::cell::RefCell::new(VecDeque::new()),
        }
    }
}

#[cfg(test)]
impl LoopbackHostIO {
    pub fn new() -> Self {
        Self::default()
    }
}

// Safety: LoopbackHostIO is only used in single-threaded tests.
#[cfg(test)]
unsafe impl Send for LoopbackHostIO {}
#[cfg(test)]
unsafe impl Sync for LoopbackHostIO {}

#[cfg(test)]
impl HostNetIO for LoopbackHostIO {
    fn send_packet(&self, packet: &[u8]) -> io::Result<usize> {
        self.packets.borrow_mut().push_back(packet.to_vec());
        Ok(packet.len())
    }

    fn recv_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(packet) = self.packets.borrow_mut().pop_front() {
            let len = packet.len().min(buf.len());
            buf[..len].copy_from_slice(&packet[..len]);
            Ok(len)
        } else {
            Ok(0)
        }
    }

    fn has_data(&self) -> bool {
        !self.packets.borrow().is_empty()
    }

    fn name(&self) -> &str {
        "loopback"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a minimal Ethernet+IPv4+TCP test packet.
    fn create_test_frame(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Vec<u8> {
        let mut frame = vec![0u8; 54]; // Ethernet(14) + IP(20) + TCP/UDP(20)

        // Ethernet header
        frame[0..6].copy_from_slice(&dst_mac);
        frame[6..12].copy_from_slice(&src_mac);
        frame[12] = 0x08; // EtherType: IPv4
        frame[13] = 0x00;

        // IP header
        frame[14] = 0x45; // Version 4, IHL 5
        frame[16] = 0x00; // Total length high
        frame[17] = 40; // Total length low (20 IP + 20 TCP)
        frame[23] = protocol;
        frame[26..30].copy_from_slice(&src_ip);
        frame[30..34].copy_from_slice(&dst_ip);

        // TCP/UDP header
        frame[34..36].copy_from_slice(&src_port.to_be_bytes());
        frame[36..38].copy_from_slice(&dst_port.to_be_bytes());

        frame
    }

    #[test]
    fn test_nat_backend_creation() {
        let host_io = Box::new(LoopbackHostIO::new());
        let backend = NatNetBackend::with_defaults(host_io);
        assert_eq!(backend.connection_count(), 0);
        assert!(backend.rx_queue.is_empty());
    }

    #[test]
    fn test_nat_backend_send_outbound() {
        let host_io = Box::new(LoopbackHostIO::new());
        let mut backend = NatNetBackend::with_defaults(host_io);

        // Create a packet from internal network going outbound.
        let frame = create_test_frame(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01], // src MAC
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // dst MAC
            [192, 168, 64, 100],                  // src IP (internal)
            [8, 8, 8, 8],                         // dst IP (external)
            12345,                                // src port
            80,                                   // dst port
            6,                                    // TCP
        );
        let packet = NetPacket::new(frame);

        let result = backend.send(&packet);
        assert!(result.is_ok());
        assert!(result.unwrap() > 0);

        // Should have created a NAT connection.
        assert_eq!(backend.connection_count(), 1);
    }

    #[test]
    fn test_nat_backend_non_ip_passthrough() {
        let host_io = Box::new(LoopbackHostIO::new());
        let mut backend = NatNetBackend::with_defaults(host_io);

        // Create a non-IPv4 frame (ARP, EtherType 0x0806).
        let mut frame = vec![0u8; 42];
        frame[12] = 0x08;
        frame[13] = 0x06; // ARP

        let packet = NetPacket::new(frame);
        let result = backend.send(&packet);
        assert!(result.is_ok());

        // No NAT connection for non-IP traffic.
        assert_eq!(backend.connection_count(), 0);
    }

    #[test]
    fn test_nat_backend_recv_empty() {
        let host_io = Box::new(LoopbackHostIO::new());
        let mut backend = NatNetBackend::with_defaults(host_io);

        let mut buf = [0u8; 1500];
        let n = backend.recv(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_nat_backend_has_data() {
        let host_io = Box::new(LoopbackHostIO::new());
        let backend = NatNetBackend::with_defaults(host_io);
        assert!(!backend.has_data());
    }

    #[test]
    fn test_nat_backend_expire_connections() {
        let host_io = Box::new(LoopbackHostIO::new());
        let mut backend = NatNetBackend::with_defaults(host_io);

        let expired = backend.expire_connections();
        assert_eq!(expired, 0);
    }

    #[test]
    fn test_nat_backend_custom_config() {
        let config = NatNetBackendConfig {
            external_ip: Ipv4Addr::new(10, 0, 0, 1),
            internal_prefix: Ipv4Addr::new(10, 0, 0, 0),
            internal_prefix_len: 24,
            port_range_start: 30000,
            port_range_end: 40000,
            connection_timeout_secs: 60,
        };
        let host_io = Box::new(LoopbackHostIO::new());
        let backend = NatNetBackend::new(config, host_io);
        assert_eq!(backend.connection_count(), 0);
    }

    #[test]
    fn test_nat_backend_debug() {
        let host_io = Box::new(LoopbackHostIO::new());
        let backend = NatNetBackend::with_defaults(host_io);
        let debug_str = format!("{:?}", backend);
        assert!(debug_str.contains("NatNetBackend"));
    }
}
