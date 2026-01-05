//! VirtIO network device (virtio-net).
//!
//! Implements the VirtIO network device for Ethernet connectivity.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::error::{Result, VirtioError};
use crate::queue::VirtQueue;
use crate::{VirtioDevice, VirtioDeviceId};

/// Network device configuration.
#[derive(Debug, Clone)]
pub struct NetConfig {
    /// MAC address.
    pub mac: [u8; 6],
    /// MTU size.
    pub mtu: u16,
    /// TAP device name (if applicable).
    pub tap_name: Option<String>,
    /// Number of queue pairs.
    pub num_queues: u16,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56], // Default QEMU MAC prefix
            mtu: 1500,
            tap_name: None,
            num_queues: 1,
        }
    }
}

impl NetConfig {
    /// Generates a random MAC address.
    #[must_use]
    pub fn random_mac() -> [u8; 6] {
        let mut mac = [0u8; 6];
        // Use ArcBox OUI prefix: 52:54:AB
        mac[0] = 0x52;
        mac[1] = 0x54;
        mac[2] = 0xAB;
        // Random bytes for the rest
        let random = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        mac[3] = ((random >> 16) & 0xFF) as u8;
        mac[4] = ((random >> 8) & 0xFF) as u8;
        mac[5] = (random & 0xFF) as u8;
        mac
    }
}

/// VirtIO network header.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioNetHeader {
    /// Flags.
    pub flags: u8,
    /// GSO type.
    pub gso_type: u8,
    /// Header length.
    pub hdr_len: u16,
    /// GSO size.
    pub gso_size: u16,
    /// Checksum start.
    pub csum_start: u16,
    /// Checksum offset.
    pub csum_offset: u16,
    /// Number of buffers.
    pub num_buffers: u16,
}

impl VirtioNetHeader {
    /// Size of the header in bytes.
    pub const SIZE: usize = 12;

    /// No GSO.
    pub const GSO_NONE: u8 = 0;
    /// TCP/IPv4 GSO.
    pub const GSO_TCPV4: u8 = 1;
    /// UDP GSO.
    pub const GSO_UDP: u8 = 3;
    /// TCP/IPv6 GSO.
    pub const GSO_TCPV6: u8 = 4;
    /// ECN flag.
    pub const GSO_ECN: u8 = 0x80;

    /// Header needs checksum.
    pub const FLAG_NEEDS_CSUM: u8 = 1;
    /// Data is valid.
    pub const FLAG_DATA_VALID: u8 = 2;

    /// Creates a new header.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses from bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            flags: bytes[0],
            gso_type: bytes[1],
            hdr_len: u16::from_le_bytes([bytes[2], bytes[3]]),
            gso_size: u16::from_le_bytes([bytes[4], bytes[5]]),
            csum_start: u16::from_le_bytes([bytes[6], bytes[7]]),
            csum_offset: u16::from_le_bytes([bytes[8], bytes[9]]),
            num_buffers: u16::from_le_bytes([bytes[10], bytes[11]]),
        })
    }

    /// Converts to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0] = self.flags;
        bytes[1] = self.gso_type;
        bytes[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
        bytes[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
        bytes[10..12].copy_from_slice(&self.num_buffers.to_le_bytes());
        bytes
    }
}

/// Network packet.
#[derive(Debug, Clone)]
pub struct NetPacket {
    /// VirtIO header.
    pub header: VirtioNetHeader,
    /// Packet data (Ethernet frame).
    pub data: Vec<u8>,
}

impl NetPacket {
    /// Creates a new packet.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            header: VirtioNetHeader::new(),
            data,
        }
    }

    /// Returns the total size including header.
    #[must_use]
    pub fn total_size(&self) -> usize {
        VirtioNetHeader::SIZE + self.data.len()
    }
}

/// Network backend trait.
pub trait NetBackend: Send + Sync {
    /// Sends a packet.
    fn send(&mut self, packet: &NetPacket) -> std::io::Result<usize>;

    /// Receives a packet.
    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;

    /// Returns whether packets are available to receive.
    fn has_data(&self) -> bool;
}

/// Loopback network backend for testing.
pub struct LoopbackBackend {
    /// Packet queue.
    packets: VecDeque<Vec<u8>>,
}

// ============================================================================
// TAP Backend (Linux)
// ============================================================================

/// TAP network backend for Linux.
#[cfg(target_os = "linux")]
pub struct TapBackend {
    /// TAP file descriptor.
    fd: std::os::unix::io::RawFd,
    /// TAP device name.
    name: String,
    /// Non-blocking mode.
    nonblocking: bool,
}

#[cfg(target_os = "linux")]
impl TapBackend {
    /// Creates a new TAP device.
    ///
    /// # Errors
    ///
    /// Returns an error if TAP device creation fails.
    pub fn new(name: Option<&str>) -> std::io::Result<Self> {
        use std::ffi::CString;
        use std::os::unix::io::RawFd;

        // Open /dev/net/tun
        let fd: RawFd = unsafe {
            libc::open(
                b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_CLOEXEC,
            )
        };

        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Prepare ifreq structure
        #[repr(C)]
        struct Ifreq {
            ifr_name: [libc::c_char; libc::IFNAMSIZ],
            ifr_flags: libc::c_short,
            _padding: [u8; 22], // Padding to match ifreq size
        }

        let mut ifr = Ifreq {
            ifr_name: [0; libc::IFNAMSIZ],
            ifr_flags: (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short,
            _padding: [0; 22],
        };

        // Set device name if provided
        if let Some(dev_name) = name {
            let name_bytes = dev_name.as_bytes();
            let len = name_bytes.len().min(libc::IFNAMSIZ - 1);
            for (i, &b) in name_bytes[..len].iter().enumerate() {
                ifr.ifr_name[i] = b as libc::c_char;
            }
        }

        // Create TAP device
        const TUNSETIFF: libc::c_ulong = 0x400454ca;
        let ret = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(std::io::Error::last_os_error());
        }

        // Extract device name
        let name = {
            let len = ifr.ifr_name.iter().position(|&c| c == 0).unwrap_or(libc::IFNAMSIZ);
            let bytes: Vec<u8> = ifr.ifr_name[..len].iter().map(|&c| c as u8).collect();
            String::from_utf8_lossy(&bytes).into_owned()
        };

        tracing::info!("Created TAP device: {}", name);

        Ok(Self {
            fd,
            name,
            nonblocking: false,
        })
    }

    /// Sets non-blocking mode.
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> std::io::Result<()> {
        let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let new_flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };

        let ret = unsafe { libc::fcntl(self.fd, libc::F_SETFL, new_flags) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        self.nonblocking = nonblocking;
        Ok(())
    }

    /// Returns the TAP device name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Brings the interface up.
    pub fn bring_up(&self) -> std::io::Result<()> {
        use std::process::Command;

        let status = Command::new("ip")
            .args(["link", "set", &self.name, "up"])
            .status()?;

        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to bring interface up",
            ))
        }
    }

    /// Sets the IP address.
    pub fn set_ip(&self, ip: &str, prefix_len: u8) -> std::io::Result<()> {
        use std::process::Command;

        let addr = format!("{}/{}", ip, prefix_len);
        let status = Command::new("ip")
            .args(["addr", "add", &addr, "dev", &self.name])
            .status()?;

        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to set IP address",
            ))
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for TapBackend {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

#[cfg(target_os = "linux")]
impl NetBackend for TapBackend {
    fn send(&mut self, packet: &NetPacket) -> std::io::Result<usize> {
        let ret = unsafe {
            libc::write(self.fd, packet.data.as_ptr() as *const libc::c_void, packet.data.len())
        };

        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let ret = unsafe {
            libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                Ok(0)
            } else {
                Err(err)
            }
        } else {
            Ok(ret as usize)
        }
    }

    fn has_data(&self) -> bool {
        // Use poll to check for data
        let mut pollfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };

        let ret = unsafe { libc::poll(&mut pollfd, 1, 0) };
        ret > 0 && (pollfd.revents & libc::POLLIN) != 0
    }
}

// ============================================================================
// macOS Userspace Network Backend
// ============================================================================

/// Socket-based network backend for macOS using UDP tunnel.
#[cfg(target_os = "macos")]
pub struct SocketBackend {
    /// Socket file descriptor.
    socket: std::net::UdpSocket,
    /// Remote address.
    remote: std::net::SocketAddr,
    /// Pending packets.
    pending: VecDeque<Vec<u8>>,
}

#[cfg(target_os = "macos")]
impl SocketBackend {
    /// Creates a new socket backend.
    ///
    /// This creates a UDP socket for packet exchange with an external network daemon.
    pub fn new(local_addr: &str, remote_addr: &str) -> std::io::Result<Self> {
        let socket = std::net::UdpSocket::bind(local_addr)?;
        socket.set_nonblocking(true)?;

        let remote: std::net::SocketAddr = remote_addr.parse().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
        })?;

        tracing::info!("Created socket backend: {} -> {}", local_addr, remote_addr);

        Ok(Self {
            socket,
            remote,
            pending: VecDeque::new(),
        })
    }

    /// Creates a loopback socket backend on random ports.
    pub fn loopback() -> std::io::Result<Self> {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let local_addr = socket.local_addr()?;
        socket.set_nonblocking(true)?;
        socket.connect(local_addr)?;

        tracing::info!("Created loopback socket backend: {}", local_addr);

        Ok(Self {
            socket,
            remote: local_addr,
            pending: VecDeque::new(),
        })
    }
}

#[cfg(target_os = "macos")]
impl NetBackend for SocketBackend {
    fn send(&mut self, packet: &NetPacket) -> std::io::Result<usize> {
        self.socket.send_to(&packet.data, self.remote)
    }

    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // First check pending queue
        if let Some(data) = self.pending.pop_front() {
            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);
            return Ok(len);
        }

        // Try to receive from socket
        match self.socket.recv(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }
    }

    fn has_data(&self) -> bool {
        !self.pending.is_empty() || {
            // Peek at socket
            let mut buf = [0u8; 1];
            matches!(self.socket.peek(&mut buf), Ok(n) if n > 0)
        }
    }
}

impl LoopbackBackend {
    /// Creates a new loopback backend.
    #[must_use]
    pub fn new() -> Self {
        Self {
            packets: VecDeque::new(),
        }
    }
}

impl Default for LoopbackBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl NetBackend for LoopbackBackend {
    fn send(&mut self, packet: &NetPacket) -> std::io::Result<usize> {
        // Loop back to ourselves
        self.packets.push_back(packet.data.clone());
        Ok(packet.data.len())
    }

    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(packet) = self.packets.pop_front() {
            let len = packet.len().min(buf.len());
            buf[..len].copy_from_slice(&packet[..len]);
            Ok(len)
        } else {
            Ok(0)
        }
    }

    fn has_data(&self) -> bool {
        !self.packets.is_empty()
    }
}

/// Network device status.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetStatus {
    /// Link is up.
    LinkUp = 1,
    /// Announce required.
    Announce = 2,
}

/// VirtIO network device.
pub struct VirtioNet {
    config: NetConfig,
    features: u64,
    acked_features: u64,
    /// Link status.
    status: u16,
    /// Receive queue.
    rx_queue: Option<VirtQueue>,
    /// Transmit queue.
    tx_queue: Option<VirtQueue>,
    /// Network backend.
    backend: Option<Arc<Mutex<dyn NetBackend>>>,
    /// RX buffer.
    rx_buffer: VecDeque<NetPacket>,
    /// TX statistics.
    tx_packets: u64,
    tx_bytes: u64,
    /// RX statistics.
    rx_packets: u64,
    rx_bytes: u64,
}

impl VirtioNet {
    /// Feature: Checksum offload.
    pub const FEATURE_CSUM: u64 = 1 << 0;
    /// Feature: Guest checksum offload.
    pub const FEATURE_GUEST_CSUM: u64 = 1 << 1;
    /// Feature: Control virtqueue.
    pub const FEATURE_CTRL_VQ: u64 = 1 << 17;
    /// Feature: MTU.
    pub const FEATURE_MTU: u64 = 1 << 3;
    /// Feature: MAC address.
    pub const FEATURE_MAC: u64 = 1 << 5;
    /// Feature: GSO.
    pub const FEATURE_GSO: u64 = 1 << 6;
    /// Feature: Guest TSO4.
    pub const FEATURE_GUEST_TSO4: u64 = 1 << 7;
    /// Feature: Guest TSO6.
    pub const FEATURE_GUEST_TSO6: u64 = 1 << 8;
    /// Feature: Guest ECN.
    pub const FEATURE_GUEST_ECN: u64 = 1 << 9;
    /// Feature: Guest UFO.
    pub const FEATURE_GUEST_UFO: u64 = 1 << 10;
    /// Feature: Host TSO4.
    pub const FEATURE_HOST_TSO4: u64 = 1 << 11;
    /// Feature: Host TSO6.
    pub const FEATURE_HOST_TSO6: u64 = 1 << 12;
    /// Feature: Host ECN.
    pub const FEATURE_HOST_ECN: u64 = 1 << 13;
    /// Feature: Host UFO.
    pub const FEATURE_HOST_UFO: u64 = 1 << 14;
    /// Feature: Merge RX buffers.
    pub const FEATURE_MRG_RXBUF: u64 = 1 << 15;
    /// Feature: Status.
    pub const FEATURE_STATUS: u64 = 1 << 16;
    /// Feature: Multiple queues.
    pub const FEATURE_MQ: u64 = 1 << 22;
    /// VirtIO 1.0 feature.
    pub const FEATURE_VERSION_1: u64 = 1 << 32;

    /// Creates a new network device.
    #[must_use]
    pub fn new(config: NetConfig) -> Self {
        let features = Self::FEATURE_MAC
            | Self::FEATURE_MTU
            | Self::FEATURE_STATUS
            | Self::FEATURE_CSUM
            | Self::FEATURE_GUEST_CSUM
            | Self::FEATURE_VERSION_1;

        Self {
            config,
            features,
            acked_features: 0,
            status: NetStatus::LinkUp as u16,
            rx_queue: None,
            tx_queue: None,
            backend: None,
            rx_buffer: VecDeque::new(),
            tx_packets: 0,
            tx_bytes: 0,
            rx_packets: 0,
            rx_bytes: 0,
        }
    }

    /// Creates a new network device with loopback backend.
    #[must_use]
    pub fn with_loopback() -> Self {
        let mut net = Self::new(NetConfig::default());
        net.backend = Some(Arc::new(Mutex::new(LoopbackBackend::new())));
        net
    }

    /// Sets the network backend.
    pub fn set_backend(&mut self, backend: Arc<Mutex<dyn NetBackend>>) {
        self.backend = Some(backend);
    }

    /// Returns the MAC address.
    #[must_use]
    pub fn mac(&self) -> &[u8; 6] {
        &self.config.mac
    }

    /// Returns TX statistics.
    #[must_use]
    pub fn tx_stats(&self) -> (u64, u64) {
        (self.tx_packets, self.tx_bytes)
    }

    /// Returns RX statistics.
    #[must_use]
    pub fn rx_stats(&self) -> (u64, u64) {
        (self.rx_packets, self.rx_bytes)
    }

    /// Sets the link status.
    pub fn set_link_up(&mut self, up: bool) {
        if up {
            self.status |= NetStatus::LinkUp as u16;
        } else {
            self.status &= !(NetStatus::LinkUp as u16);
        }
    }

    /// Returns whether the link is up.
    #[must_use]
    pub fn is_link_up(&self) -> bool {
        self.status & (NetStatus::LinkUp as u16) != 0
    }

    /// Queues a packet for reception by the guest.
    pub fn queue_rx(&mut self, packet: NetPacket) {
        self.rx_buffer.push_back(packet);
    }

    /// Handles TX from guest.
    fn handle_tx(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < VirtioNetHeader::SIZE {
            return Err(VirtioError::InvalidOperation("Packet too small".into()));
        }

        let header = VirtioNetHeader::from_bytes(data).ok_or_else(|| {
            VirtioError::InvalidOperation("Invalid header".into())
        })?;

        let packet = NetPacket {
            header,
            data: data[VirtioNetHeader::SIZE..].to_vec(),
        };

        self.tx_packets += 1;
        self.tx_bytes += packet.data.len() as u64;

        if let Some(backend) = &self.backend {
            let mut backend = backend.lock().map_err(|e| {
                VirtioError::Io(format!("Failed to lock backend: {}", e))
            })?;
            backend.send(&packet).map_err(|e| {
                VirtioError::Io(format!("Send failed: {}", e))
            })?;
        }

        tracing::trace!("Net TX: {} bytes", packet.data.len());
        Ok(())
    }

    /// Processes the TX queue.
    ///
    /// # Errors
    ///
    /// Returns an error if processing fails.
    pub fn process_tx_queue(&mut self, memory: &[u8]) -> Result<Vec<(u16, u32)>> {
        // Collect data first to avoid borrow issues
        let mut tx_data: Vec<(u16, Vec<u8>)> = Vec::new();

        {
            let queue = self.tx_queue.as_mut().ok_or_else(|| {
                VirtioError::NotReady("TX queue not ready".into())
            })?;

            while let Some((head_idx, chain)) = queue.pop_avail() {
                let mut data = Vec::new();

                for desc in chain {
                    if !desc.is_write_only() {
                        let start = desc.addr as usize;
                        let end = start + desc.len as usize;
                        if end <= memory.len() {
                            data.extend_from_slice(&memory[start..end]);
                        }
                    }
                }

                tx_data.push((head_idx, data));
            }
        }

        let mut completed = Vec::new();
        for (head_idx, data) in tx_data {
            let len = data.len() as u32;
            self.handle_tx(&data)?;
            completed.push((head_idx, len));
        }

        Ok(completed)
    }

    /// Returns the number of packets in the RX buffer.
    #[must_use]
    pub fn rx_pending(&self) -> usize {
        self.rx_buffer.len()
    }

    /// Polls the backend for incoming packets.
    ///
    /// # Errors
    ///
    /// Returns an error if polling fails.
    pub fn poll_backend(&mut self) -> Result<()> {
        if let Some(backend) = &self.backend {
            let mut backend = backend.lock().map_err(|e| {
                VirtioError::Io(format!("Failed to lock backend: {}", e))
            })?;

            while backend.has_data() {
                let mut buf = vec![0u8; 65536];
                let n = backend.recv(&mut buf).map_err(|e| {
                    VirtioError::Io(format!("Recv failed: {}", e))
                })?;

                if n > 0 {
                    buf.truncate(n);
                    let packet = NetPacket::new(buf);
                    self.rx_packets += 1;
                    self.rx_bytes += n as u64;
                    self.rx_buffer.push_back(packet);
                }
            }
        }

        Ok(())
    }
}

impl VirtioDevice for VirtioNet {
    fn device_id(&self) -> VirtioDeviceId {
        VirtioDeviceId::Net
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, features: u64) {
        self.acked_features = self.features & features;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Configuration space layout (VirtIO 1.1):
        // offset 0: mac (6 bytes)
        // offset 6: status (u16)
        // offset 8: max_virtqueue_pairs (u16)
        // offset 10: mtu (u16)
        let mut config_data = vec![0u8; 12];
        config_data[0..6].copy_from_slice(&self.config.mac);
        config_data[6..8].copy_from_slice(&self.status.to_le_bytes());
        config_data[8..10].copy_from_slice(&self.config.num_queues.to_le_bytes());
        config_data[10..12].copy_from_slice(&self.config.mtu.to_le_bytes());

        let offset = offset as usize;
        let len = data.len().min(config_data.len().saturating_sub(offset));
        if len > 0 {
            data[..len].copy_from_slice(&config_data[offset..offset + len]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // Network config is mostly read-only
    }

    fn activate(&mut self) -> Result<()> {
        // Create queues
        self.rx_queue = Some(VirtQueue::new(256)?);
        self.tx_queue = Some(VirtQueue::new(256)?);

        tracing::info!(
            "VirtIO net activated: MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, MTU={}",
            self.config.mac[0],
            self.config.mac[1],
            self.config.mac[2],
            self.config.mac[3],
            self.config.mac[4],
            self.config.mac[5],
            self.config.mtu
        );

        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
        self.rx_queue = None;
        self.tx_queue = None;
        self.rx_buffer.clear();
        self.tx_packets = 0;
        self.tx_bytes = 0;
        self.rx_packets = 0;
        self.rx_bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // NetConfig Tests
    // ==========================================================================

    #[test]
    fn test_net_config_default() {
        let config = NetConfig::default();
        assert_eq!(config.mac, [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        assert_eq!(config.mtu, 1500);
        assert!(config.tap_name.is_none());
        assert_eq!(config.num_queues, 1);
    }

    #[test]
    fn test_net_config_custom() {
        let config = NetConfig {
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            mtu: 9000, // Jumbo frames
            tap_name: Some("tap0".to_string()),
            num_queues: 4,
        };
        assert_eq!(config.mac[0], 0x00);
        assert_eq!(config.mtu, 9000);
        assert_eq!(config.tap_name.as_deref(), Some("tap0"));
        assert_eq!(config.num_queues, 4);
    }

    #[test]
    fn test_random_mac() {
        let mac1 = NetConfig::random_mac();
        let mac2 = NetConfig::random_mac();

        // Should have ArcBox OUI prefix
        assert_eq!(mac1[0], 0x52);
        assert_eq!(mac1[1], 0x54);
        assert_eq!(mac1[2], 0xAB);

        // Should also have ArcBox prefix
        assert_eq!(mac2[0], 0x52);
        assert_eq!(mac2[1], 0x54);
        assert_eq!(mac2[2], 0xAB);
    }

    // ==========================================================================
    // VirtioNetHeader Tests
    // ==========================================================================

    #[test]
    fn test_header_size() {
        assert_eq!(VirtioNetHeader::SIZE, 12);
    }

    #[test]
    fn test_header_constants() {
        assert_eq!(VirtioNetHeader::GSO_NONE, 0);
        assert_eq!(VirtioNetHeader::GSO_TCPV4, 1);
        assert_eq!(VirtioNetHeader::GSO_UDP, 3);
        assert_eq!(VirtioNetHeader::GSO_TCPV6, 4);
        assert_eq!(VirtioNetHeader::GSO_ECN, 0x80);
        assert_eq!(VirtioNetHeader::FLAG_NEEDS_CSUM, 1);
        assert_eq!(VirtioNetHeader::FLAG_DATA_VALID, 2);
    }

    #[test]
    fn test_header_new() {
        let header = VirtioNetHeader::new();
        assert_eq!(header.flags, 0);
        assert_eq!(header.gso_type, 0);
        assert_eq!(header.hdr_len, 0);
        assert_eq!(header.gso_size, 0);
        assert_eq!(header.csum_start, 0);
        assert_eq!(header.csum_offset, 0);
        assert_eq!(header.num_buffers, 0);
    }

    #[test]
    fn test_header_serialization() {
        let header = VirtioNetHeader {
            flags: 1,
            gso_type: 2,
            hdr_len: 0x1234,
            gso_size: 0x5678,
            csum_start: 0x9ABC,
            csum_offset: 0xDEF0,
            num_buffers: 0x1111,
        };

        let bytes = header.to_bytes();
        let parsed = VirtioNetHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.flags, header.flags);
        assert_eq!(parsed.gso_type, header.gso_type);
        assert_eq!(parsed.hdr_len, header.hdr_len);
        assert_eq!(parsed.gso_size, header.gso_size);
        assert_eq!(parsed.csum_start, header.csum_start);
        assert_eq!(parsed.csum_offset, header.csum_offset);
        assert_eq!(parsed.num_buffers, header.num_buffers);
    }

    #[test]
    fn test_header_from_bytes_too_small() {
        let bytes = [0u8; 11]; // One byte short
        assert!(VirtioNetHeader::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_header_from_bytes_exact_size() {
        let bytes = [0u8; 12];
        assert!(VirtioNetHeader::from_bytes(&bytes).is_some());
    }

    #[test]
    fn test_header_from_bytes_larger() {
        let bytes = [0u8; 100]; // Larger than needed
        let header = VirtioNetHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header.flags, 0);
    }

    #[test]
    fn test_header_endianness() {
        let header = VirtioNetHeader {
            flags: 0,
            gso_type: 0,
            hdr_len: 0x0102,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 0,
        };

        let bytes = header.to_bytes();
        // Little-endian: 0x0102 should be stored as [0x02, 0x01]
        assert_eq!(bytes[2], 0x02);
        assert_eq!(bytes[3], 0x01);
    }

    // ==========================================================================
    // NetPacket Tests
    // ==========================================================================

    #[test]
    fn test_packet_new() {
        let data = vec![0xAA, 0xBB, 0xCC];
        let packet = NetPacket::new(data.clone());

        assert_eq!(packet.data, data);
        assert_eq!(packet.header.flags, 0);
    }

    #[test]
    fn test_packet_total_size() {
        let data = vec![0u8; 100];
        let packet = NetPacket::new(data);

        assert_eq!(packet.total_size(), VirtioNetHeader::SIZE + 100);
    }

    #[test]
    fn test_packet_empty() {
        let packet = NetPacket::new(vec![]);
        assert_eq!(packet.total_size(), VirtioNetHeader::SIZE);
        assert!(packet.data.is_empty());
    }

    #[test]
    fn test_packet_large() {
        // Maximum Ethernet frame with jumbo
        let data = vec![0u8; 9000];
        let packet = NetPacket::new(data);
        assert_eq!(packet.total_size(), VirtioNetHeader::SIZE + 9000);
    }

    // ==========================================================================
    // LoopbackBackend Tests
    // ==========================================================================

    #[test]
    fn test_loopback_backend_new() {
        let backend = LoopbackBackend::new();
        assert!(!backend.has_data());
    }

    #[test]
    fn test_loopback_backend_default() {
        let backend = LoopbackBackend::default();
        assert!(!backend.has_data());
    }

    #[test]
    fn test_loopback_backend_send_recv() {
        let mut backend = LoopbackBackend::new();

        let packet = NetPacket::new(vec![1, 2, 3, 4, 5]);
        let sent = backend.send(&packet).unwrap();
        assert_eq!(sent, 5);

        assert!(backend.has_data());

        let mut buf = [0u8; 10];
        let n = backend.recv(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], &[1, 2, 3, 4, 5]);

        assert!(!backend.has_data());
    }

    #[test]
    fn test_loopback_backend_recv_empty() {
        let mut backend = LoopbackBackend::new();

        let mut buf = [0u8; 10];
        let n = backend.recv(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_loopback_backend_multiple_packets() {
        let mut backend = LoopbackBackend::new();

        // Send multiple packets
        for i in 0..5 {
            let packet = NetPacket::new(vec![i; 10]);
            backend.send(&packet).unwrap();
        }

        // Receive in FIFO order
        for i in 0..5 {
            assert!(backend.has_data());
            let mut buf = [0u8; 20];
            let n = backend.recv(&mut buf).unwrap();
            assert_eq!(n, 10);
            assert!(buf[..n].iter().all(|&b| b == i));
        }

        assert!(!backend.has_data());
    }

    #[test]
    fn test_loopback_backend_small_buffer() {
        let mut backend = LoopbackBackend::new();

        let packet = NetPacket::new(vec![0xAA; 100]);
        backend.send(&packet).unwrap();

        // Receive with buffer smaller than packet
        let mut buf = [0u8; 10];
        let n = backend.recv(&mut buf).unwrap();
        assert_eq!(n, 10);
        assert!(buf.iter().all(|&b| b == 0xAA));
    }

    // ==========================================================================
    // SocketBackend Tests (macOS)
    // ==========================================================================

    #[cfg(target_os = "macos")]
    mod socket_backend_tests {
        use super::*;

        #[test]
        fn test_socket_backend_loopback() {
            let backend = SocketBackend::loopback();
            assert!(backend.is_ok());
        }

        #[test]
        fn test_socket_backend_new_invalid_remote() {
            let result = SocketBackend::new("127.0.0.1:0", "invalid-address");
            assert!(result.is_err());
        }

        #[test]
        fn test_socket_backend_has_data_empty() {
            let backend = SocketBackend::loopback().unwrap();
            // Initially no data
            assert!(!backend.has_data());
        }

        #[test]
        fn test_socket_backend_recv_would_block() {
            let mut backend = SocketBackend::loopback().unwrap();
            let mut buf = [0u8; 100];
            let n = backend.recv(&mut buf).unwrap();
            assert_eq!(n, 0); // Would block returns 0
        }
    }

    // ==========================================================================
    // VirtioNet Device Tests
    // ==========================================================================

    #[test]
    fn test_net_device_creation() {
        let net = VirtioNet::new(NetConfig::default());
        assert_eq!(net.device_id(), VirtioDeviceId::Net);
        assert!(net.features() & VirtioNet::FEATURE_MAC != 0);
    }

    #[test]
    fn test_net_device_features() {
        let net = VirtioNet::new(NetConfig::default());
        let features = net.features();

        assert!(features & VirtioNet::FEATURE_MAC != 0);
        assert!(features & VirtioNet::FEATURE_MTU != 0);
        assert!(features & VirtioNet::FEATURE_STATUS != 0);
        assert!(features & VirtioNet::FEATURE_CSUM != 0);
        assert!(features & VirtioNet::FEATURE_GUEST_CSUM != 0);
        assert!(features & VirtioNet::FEATURE_VERSION_1 != 0);
    }

    #[test]
    fn test_net_device_ack_features() {
        let mut net = VirtioNet::new(NetConfig::default());

        // Ack only some features
        let requested = VirtioNet::FEATURE_MAC | VirtioNet::FEATURE_MTU;
        net.ack_features(requested);

        // Acked features should be intersection
        assert_eq!(net.acked_features, requested & net.features());
    }

    #[test]
    fn test_net_device_ack_features_unsupported() {
        let mut net = VirtioNet::new(NetConfig::default());

        // Try to ack unsupported feature
        let unsupported = 1 << 63;
        net.ack_features(unsupported);

        // Should be 0 since unsupported
        assert_eq!(net.acked_features, 0);
    }

    #[test]
    fn test_mac_address() {
        let config = NetConfig {
            mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            ..Default::default()
        };
        let net = VirtioNet::new(config);

        let mut data = [0u8; 6];
        net.read_config(0, &mut data);
        assert_eq!(data, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_read_config_status() {
        let net = VirtioNet::new(NetConfig::default());

        let mut data = [0u8; 2];
        net.read_config(6, &mut data);

        let status = u16::from_le_bytes(data);
        assert_eq!(status, NetStatus::LinkUp as u16);
    }

    #[test]
    fn test_read_config_mtu() {
        let config = NetConfig {
            mtu: 9000,
            ..Default::default()
        };
        let net = VirtioNet::new(config);

        let mut data = [0u8; 2];
        net.read_config(10, &mut data);

        let mtu = u16::from_le_bytes(data);
        assert_eq!(mtu, 9000);
    }

    #[test]
    fn test_read_config_num_queues() {
        let config = NetConfig {
            num_queues: 4,
            ..Default::default()
        };
        let net = VirtioNet::new(config);

        let mut data = [0u8; 2];
        net.read_config(8, &mut data);

        let num_queues = u16::from_le_bytes(data);
        assert_eq!(num_queues, 4);
    }

    #[test]
    fn test_read_config_beyond_end() {
        let net = VirtioNet::new(NetConfig::default());

        let mut data = [0xFFu8; 4];
        net.read_config(100, &mut data); // Way beyond config space

        // Should not crash, data might be unchanged or zeroed
    }

    #[test]
    fn test_read_config_partial() {
        let net = VirtioNet::new(NetConfig::default());

        let mut data = [0u8; 20]; // Larger than config space
        net.read_config(0, &mut data);

        // First 6 bytes should be MAC
        assert_eq!(&data[0..6], &[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    }

    #[test]
    fn test_write_config_noop() {
        let mut net = VirtioNet::new(NetConfig::default());

        // Write config is no-op for net
        net.write_config(0, &[0xFF; 6]);

        // MAC should be unchanged
        assert_eq!(net.mac(), &[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    }

    #[test]
    fn test_net_with_loopback() {
        let mut net = VirtioNet::with_loopback();
        net.activate().unwrap();

        assert!(net.is_link_up());
        assert!(net.backend.is_some());

        // Initially no stats
        assert_eq!(net.tx_stats(), (0, 0));
        assert_eq!(net.rx_stats(), (0, 0));
    }

    #[test]
    fn test_link_status() {
        let mut net = VirtioNet::new(NetConfig::default());

        assert!(net.is_link_up());

        net.set_link_up(false);
        assert!(!net.is_link_up());

        net.set_link_up(true);
        assert!(net.is_link_up());
    }

    #[test]
    fn test_link_status_toggle_multiple() {
        let mut net = VirtioNet::new(NetConfig::default());

        for _ in 0..10 {
            net.set_link_up(false);
            assert!(!net.is_link_up());
            net.set_link_up(true);
            assert!(net.is_link_up());
        }
    }

    #[test]
    fn test_net_activate() {
        let mut net = VirtioNet::new(NetConfig::default());

        assert!(net.rx_queue.is_none());
        assert!(net.tx_queue.is_none());

        net.activate().unwrap();

        assert!(net.rx_queue.is_some());
        assert!(net.tx_queue.is_some());
    }

    #[test]
    fn test_net_reset() {
        let mut net = VirtioNet::with_loopback();
        net.activate().unwrap();

        // Queue some RX packets
        net.queue_rx(NetPacket::new(vec![1, 2, 3]));
        assert_eq!(net.rx_pending(), 1);

        // Set some features
        net.ack_features(VirtioNet::FEATURE_MAC);

        net.reset();

        // Everything should be reset
        assert_eq!(net.acked_features, 0);
        assert!(net.rx_queue.is_none());
        assert!(net.tx_queue.is_none());
        assert_eq!(net.rx_pending(), 0);
        assert_eq!(net.tx_stats(), (0, 0));
        assert_eq!(net.rx_stats(), (0, 0));
    }

    #[test]
    fn test_queue_rx() {
        let mut net = VirtioNet::new(NetConfig::default());

        assert_eq!(net.rx_pending(), 0);

        net.queue_rx(NetPacket::new(vec![1, 2, 3]));
        assert_eq!(net.rx_pending(), 1);

        net.queue_rx(NetPacket::new(vec![4, 5, 6]));
        assert_eq!(net.rx_pending(), 2);
    }

    #[test]
    fn test_set_backend() {
        let mut net = VirtioNet::new(NetConfig::default());

        assert!(net.backend.is_none());

        let backend = Arc::new(Mutex::new(LoopbackBackend::new()));
        net.set_backend(backend);

        assert!(net.backend.is_some());
    }

    #[test]
    fn test_poll_backend_no_data() {
        let mut net = VirtioNet::with_loopback();

        // Poll with no data should succeed
        net.poll_backend().unwrap();
        assert_eq!(net.rx_pending(), 0);
    }

    #[test]
    fn test_poll_backend_with_data() {
        let mut net = VirtioNet::with_loopback();

        // Send packet through backend
        if let Some(backend) = &net.backend {
            let mut backend = backend.lock().unwrap();
            backend.send(&NetPacket::new(vec![1, 2, 3, 4, 5])).unwrap();
        }

        // Poll should receive it
        net.poll_backend().unwrap();
        assert_eq!(net.rx_pending(), 1);
        assert_eq!(net.rx_stats(), (1, 5));
    }

    #[test]
    fn test_poll_backend_multiple() {
        let mut net = VirtioNet::with_loopback();

        // Send multiple packets
        if let Some(backend) = &net.backend {
            let mut backend = backend.lock().unwrap();
            for i in 0..5 {
                backend.send(&NetPacket::new(vec![i; 100])).unwrap();
            }
        }

        // Poll should receive all
        net.poll_backend().unwrap();
        assert_eq!(net.rx_pending(), 5);
        assert_eq!(net.rx_stats(), (5, 500));
    }

    #[test]
    fn test_handle_tx_too_small() {
        let mut net = VirtioNet::with_loopback();

        // Packet smaller than header
        let data = [0u8; 5];
        let result = net.handle_tx(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_net_no_backend() {
        let mut net = VirtioNet::new(NetConfig::default());

        // Poll with no backend should succeed
        net.poll_backend().unwrap();
        assert_eq!(net.rx_pending(), 0);
    }

    #[test]
    fn test_process_tx_queue_not_ready() {
        let mut net = VirtioNet::new(NetConfig::default());

        let memory = vec![0u8; 1024];
        let result = net.process_tx_queue(&memory);

        assert!(result.is_err());
    }

    // ==========================================================================
    // NetStatus Tests
    // ==========================================================================

    #[test]
    fn test_net_status_values() {
        assert_eq!(NetStatus::LinkUp as u16, 1);
        assert_eq!(NetStatus::Announce as u16, 2);
    }

    // ==========================================================================
    // Feature Constants Tests
    // ==========================================================================

    #[test]
    fn test_feature_constants() {
        assert_eq!(VirtioNet::FEATURE_CSUM, 1 << 0);
        assert_eq!(VirtioNet::FEATURE_GUEST_CSUM, 1 << 1);
        assert_eq!(VirtioNet::FEATURE_MTU, 1 << 3);
        assert_eq!(VirtioNet::FEATURE_MAC, 1 << 5);
        assert_eq!(VirtioNet::FEATURE_GSO, 1 << 6);
        assert_eq!(VirtioNet::FEATURE_GUEST_TSO4, 1 << 7);
        assert_eq!(VirtioNet::FEATURE_GUEST_TSO6, 1 << 8);
        assert_eq!(VirtioNet::FEATURE_GUEST_ECN, 1 << 9);
        assert_eq!(VirtioNet::FEATURE_GUEST_UFO, 1 << 10);
        assert_eq!(VirtioNet::FEATURE_HOST_TSO4, 1 << 11);
        assert_eq!(VirtioNet::FEATURE_HOST_TSO6, 1 << 12);
        assert_eq!(VirtioNet::FEATURE_HOST_ECN, 1 << 13);
        assert_eq!(VirtioNet::FEATURE_HOST_UFO, 1 << 14);
        assert_eq!(VirtioNet::FEATURE_MRG_RXBUF, 1 << 15);
        assert_eq!(VirtioNet::FEATURE_STATUS, 1 << 16);
        assert_eq!(VirtioNet::FEATURE_CTRL_VQ, 1 << 17);
        assert_eq!(VirtioNet::FEATURE_MQ, 1 << 22);
        assert_eq!(VirtioNet::FEATURE_VERSION_1, 1 << 32);
    }

    // ==========================================================================
    // Edge Case Tests
    // ==========================================================================

    #[test]
    fn test_loopback_large_packet() {
        let mut backend = LoopbackBackend::new();

        // Send a very large packet
        let data = vec![0xAB; 65536];
        let packet = NetPacket::new(data.clone());
        let sent = backend.send(&packet).unwrap();
        assert_eq!(sent, 65536);

        let mut buf = vec![0u8; 65536];
        let n = backend.recv(&mut buf).unwrap();
        assert_eq!(n, 65536);
        assert_eq!(buf, data);
    }

    #[test]
    fn test_config_clone() {
        let config = NetConfig {
            mac: [1, 2, 3, 4, 5, 6],
            mtu: 1234,
            tap_name: Some("test".to_string()),
            num_queues: 2,
        };

        let cloned = config.clone();
        assert_eq!(cloned.mac, config.mac);
        assert_eq!(cloned.mtu, config.mtu);
        assert_eq!(cloned.tap_name, config.tap_name);
        assert_eq!(cloned.num_queues, config.num_queues);
    }

    #[test]
    fn test_header_clone_copy() {
        let header = VirtioNetHeader {
            flags: 1,
            gso_type: 2,
            hdr_len: 3,
            gso_size: 4,
            csum_start: 5,
            csum_offset: 6,
            num_buffers: 7,
        };

        let cloned = header.clone();
        let copied = header; // Copy

        assert_eq!(cloned.flags, 1);
        assert_eq!(copied.flags, 1);
    }

    #[test]
    fn test_packet_clone() {
        let packet = NetPacket {
            header: VirtioNetHeader::new(),
            data: vec![1, 2, 3],
        };

        let cloned = packet.clone();
        assert_eq!(cloned.data, packet.data);
    }
}
