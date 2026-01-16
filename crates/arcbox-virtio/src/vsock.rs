//! VirtIO socket device (virtio-vsock).
//!
//! Provides socket communication between host and guest without requiring
//! network configuration.
//!
//! On Darwin, the native VZ framework handles vsock. This implementation
//! is primarily used for Linux KVM.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, RwLock};

use crate::error::{Result, VirtioError};
use crate::{VirtioDevice, VirtioDeviceId};

/// Vsock device configuration.
#[derive(Debug, Clone)]
pub struct VsockConfig {
    /// Guest CID (Context Identifier).
    pub guest_cid: u64,
}

impl Default for VsockConfig {
    fn default() -> Self {
        Self {
            guest_cid: 3, // First available guest CID
        }
    }
}

/// VirtIO vsock device.
///
/// Enables socket communication between host (CID 2) and guest using
/// virtio transport.
pub struct VirtioVsock {
    config: VsockConfig,
    features: u64,
    acked_features: u64,
    /// Backend for host-side socket handling.
    backend: Option<Arc<Mutex<dyn VsockBackend>>>,
    /// Active connections.
    connections: RwLock<HashMap<(u32, u32), VsockConnection>>,
}

impl VirtioVsock {
    /// Feature: Stream socket.
    pub const FEATURE_STREAM: u64 = 1 << 0;
    /// Feature: Seqpacket socket.
    pub const FEATURE_SEQPACKET: u64 = 1 << 1;

    /// Well-known CID for host.
    pub const HOST_CID: u64 = 2;
    /// Reserved CID.
    pub const RESERVED_CID: u64 = 1;

    /// Creates a new vsock device.
    #[must_use]
    pub fn new(config: VsockConfig) -> Self {
        Self {
            config,
            features: Self::FEATURE_STREAM,
            acked_features: 0,
            backend: None,
            connections: RwLock::new(HashMap::new()),
        }
    }

    /// Creates a vsock device with a backend.
    #[must_use]
    pub fn with_backend<B: VsockBackend + 'static>(config: VsockConfig, backend: B) -> Self {
        Self {
            config,
            features: Self::FEATURE_STREAM,
            acked_features: 0,
            backend: Some(Arc::new(Mutex::new(backend))),
            connections: RwLock::new(HashMap::new()),
        }
    }

    /// Sets the backend.
    pub fn set_backend<B: VsockBackend + 'static>(&mut self, backend: B) {
        self.backend = Some(Arc::new(Mutex::new(backend)));
    }

    /// Returns the guest CID.
    #[must_use]
    pub fn guest_cid(&self) -> u64 {
        self.config.guest_cid
    }

    /// Handles a connection request from guest.
    pub fn handle_connect(&self, src_port: u32, dst_port: u32) -> Result<()> {
        let local = VsockAddr::new(self.config.guest_cid, src_port);
        let remote = VsockAddr::new(Self::HOST_CID, dst_port);

        // Create connection
        let mut conn = VsockConnection::new(local, remote);
        conn.state = ConnectionState::Connecting;

        // Notify backend
        if let Some(ref backend) = self.backend {
            backend.lock().unwrap().on_connect(local)?;
            conn.state = ConnectionState::Connected;
        }

        self.connections
            .write()
            .unwrap()
            .insert((src_port, dst_port), conn);
        tracing::debug!(
            "Vsock connect: {}:{} -> {}:{}",
            self.config.guest_cid,
            src_port,
            Self::HOST_CID,
            dst_port
        );

        Ok(())
    }

    /// Handles data from guest.
    pub fn handle_send(&self, src_port: u32, dst_port: u32, data: &[u8]) -> Result<usize> {
        let local = VsockAddr::new(self.config.guest_cid, src_port);

        if let Some(ref backend) = self.backend {
            backend.lock().unwrap().on_send(local, data)
        } else {
            // Store in connection buffer
            let mut conns = self.connections.write().unwrap();
            if let Some(conn) = conns.get_mut(&(src_port, dst_port)) {
                conn.enqueue_tx(data);
                Ok(data.len())
            } else {
                Err(VirtioError::InvalidOperation("Connection not found".into()))
            }
        }
    }

    /// Handles receive request from guest.
    pub fn handle_recv(&self, src_port: u32, dst_port: u32, buf: &mut [u8]) -> Result<usize> {
        let local = VsockAddr::new(self.config.guest_cid, src_port);

        if let Some(ref backend) = self.backend {
            backend.lock().unwrap().on_recv(local, buf)
        } else {
            // Read from connection buffer
            let mut conns = self.connections.write().unwrap();
            if let Some(conn) = conns.get_mut(&(src_port, dst_port)) {
                let data = conn.dequeue_rx(buf.len());
                buf[..data.len()].copy_from_slice(&data);
                Ok(data.len())
            } else {
                Err(VirtioError::InvalidOperation("Connection not found".into()))
            }
        }
    }

    /// Handles connection close from guest.
    pub fn handle_close(&self, src_port: u32, dst_port: u32) -> Result<()> {
        let local = VsockAddr::new(self.config.guest_cid, src_port);

        if let Some(ref backend) = self.backend {
            backend.lock().unwrap().on_close(local)?;
        }

        self.connections
            .write()
            .unwrap()
            .remove(&(src_port, dst_port));
        tracing::debug!("Vsock close: {}:{}", self.config.guest_cid, src_port);

        Ok(())
    }

    /// Returns the number of active connections.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connections.read().unwrap().len()
    }
}

impl VirtioDevice for VirtioVsock {
    fn device_id(&self) -> VirtioDeviceId {
        VirtioDeviceId::Vsock
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, features: u64) {
        self.acked_features = self.features & features;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Configuration space layout:
        // offset 0: guest_cid (u64)
        let config_data = self.config.guest_cid.to_le_bytes();

        let offset = offset as usize;
        let len = data.len().min(config_data.len().saturating_sub(offset));
        if len > 0 {
            data[..len].copy_from_slice(&config_data[offset..offset + len]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // Vsock config is read-only
    }

    fn activate(&mut self) -> Result<()> {
        // If no backend is set, use loopback for testing
        if self.backend.is_none() {
            tracing::info!("Vsock: using loopback backend (no backend configured)");
            self.backend = Some(Arc::new(Mutex::new(LoopbackBackend::new())));
        }
        tracing::info!(
            "Vsock device activated, guest CID: {}",
            self.config.guest_cid
        );
        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
        self.connections.write().unwrap().clear();
        self.backend = None;
    }
}

/// Vsock address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VsockAddr {
    /// Context Identifier.
    pub cid: u64,
    /// Port number.
    pub port: u32,
}

impl VsockAddr {
    /// Creates a new vsock address.
    #[must_use]
    pub const fn new(cid: u64, port: u32) -> Self {
        Self { cid, port }
    }

    /// Returns the host address for a given port.
    #[must_use]
    pub const fn host(port: u32) -> Self {
        Self::new(VirtioVsock::HOST_CID, port)
    }
}

// ============================================================================
// Vsock Packet Types
// ============================================================================

/// Vsock operation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum VsockOp {
    /// Invalid operation.
    Invalid = 0,
    /// Request connection.
    Request = 1,
    /// Connection response.
    Response = 2,
    /// Reset connection.
    Rst = 3,
    /// Shutdown connection.
    Shutdown = 4,
    /// Data transfer.
    Rw = 5,
    /// Credit update.
    CreditUpdate = 6,
    /// Credit request.
    CreditRequest = 7,
}

impl VsockOp {
    /// Converts from u16.
    #[must_use]
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            0 => Some(Self::Invalid),
            1 => Some(Self::Request),
            2 => Some(Self::Response),
            3 => Some(Self::Rst),
            4 => Some(Self::Shutdown),
            5 => Some(Self::Rw),
            6 => Some(Self::CreditUpdate),
            7 => Some(Self::CreditRequest),
            _ => None,
        }
    }
}

/// Vsock packet header.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct VsockHeader {
    /// Source CID.
    pub src_cid: u64,
    /// Destination CID.
    pub dst_cid: u64,
    /// Source port.
    pub src_port: u32,
    /// Destination port.
    pub dst_port: u32,
    /// Payload length.
    pub len: u32,
    /// Socket type (stream = 1).
    pub socket_type: u16,
    /// Operation.
    pub op: u16,
    /// Flags.
    pub flags: u32,
    /// Buffer allocation.
    pub buf_alloc: u32,
    /// Forward count.
    pub fwd_cnt: u32,
}

impl VsockHeader {
    /// Header size in bytes.
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// Creates a new header.
    #[must_use]
    pub fn new(src: VsockAddr, dst: VsockAddr, op: VsockOp) -> Self {
        Self {
            src_cid: src.cid,
            dst_cid: dst.cid,
            src_port: src.port,
            dst_port: dst.port,
            len: 0,
            socket_type: 1, // SOCK_STREAM
            op: op as u16,
            flags: 0,
            buf_alloc: 64 * 1024,
            fwd_cnt: 0,
        }
    }

    /// Returns the operation type.
    #[must_use]
    pub fn operation(&self) -> Option<VsockOp> {
        VsockOp::from_u16(self.op)
    }
}

// ============================================================================
// Connection State
// ============================================================================

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state.
    Idle,
    /// Connection requested.
    Connecting,
    /// Connected.
    Connected,
    /// Shutting down.
    Closing,
    /// Closed.
    Closed,
}

/// A vsock connection.
#[derive(Debug)]
pub struct VsockConnection {
    /// Local address.
    pub local: VsockAddr,
    /// Remote address.
    pub remote: VsockAddr,
    /// Connection state.
    pub state: ConnectionState,
    /// Receive buffer.
    rx_buf: Vec<u8>,
    /// Transmit buffer.
    tx_buf: Vec<u8>,
    /// Buffer allocation (credit).
    buf_alloc: u32,
    /// Forward count.
    fwd_cnt: u32,
    /// Peer buffer allocation.
    peer_buf_alloc: u32,
    /// Peer forward count.
    peer_fwd_cnt: u32,
}

impl VsockConnection {
    /// Creates a new connection.
    #[must_use]
    pub fn new(local: VsockAddr, remote: VsockAddr) -> Self {
        Self {
            local,
            remote,
            state: ConnectionState::Idle,
            rx_buf: Vec::with_capacity(64 * 1024),
            tx_buf: Vec::with_capacity(64 * 1024),
            buf_alloc: 64 * 1024,
            fwd_cnt: 0,
            peer_buf_alloc: 0,
            peer_fwd_cnt: 0,
        }
    }

    /// Returns bytes available to send.
    #[must_use]
    pub fn tx_available(&self) -> usize {
        self.tx_buf.len()
    }

    /// Returns bytes available to receive.
    #[must_use]
    pub fn rx_available(&self) -> usize {
        self.rx_buf.len()
    }

    /// Enqueues data for transmission.
    pub fn enqueue_tx(&mut self, data: &[u8]) {
        self.tx_buf.extend_from_slice(data);
    }

    /// Dequeues transmitted data.
    pub fn dequeue_tx(&mut self, max_len: usize) -> Vec<u8> {
        let len = max_len.min(self.tx_buf.len());
        self.tx_buf.drain(..len).collect()
    }

    /// Enqueues received data.
    pub fn enqueue_rx(&mut self, data: &[u8]) {
        self.rx_buf.extend_from_slice(data);
        self.fwd_cnt = self.fwd_cnt.wrapping_add(data.len() as u32);
    }

    /// Dequeues received data.
    pub fn dequeue_rx(&mut self, max_len: usize) -> Vec<u8> {
        let len = max_len.min(self.rx_buf.len());
        self.rx_buf.drain(..len).collect()
    }

    /// Updates peer credit info.
    pub fn update_peer_credit(&mut self, buf_alloc: u32, fwd_cnt: u32) {
        self.peer_buf_alloc = buf_alloc;
        self.peer_fwd_cnt = fwd_cnt;
    }
}

// ============================================================================
// Vsock Backend
// ============================================================================

/// Vsock backend trait for handling host-side socket operations.
pub trait VsockBackend: Send + Sync {
    /// Called when guest requests a connection.
    fn on_connect(&mut self, addr: VsockAddr) -> Result<()>;

    /// Called when guest sends data.
    fn on_send(&mut self, addr: VsockAddr, data: &[u8]) -> Result<usize>;

    /// Called when guest requests data.
    fn on_recv(&mut self, addr: VsockAddr, buf: &mut [u8]) -> Result<usize>;

    /// Called when guest closes connection.
    fn on_close(&mut self, addr: VsockAddr) -> Result<()>;

    /// Checks if there's pending data for a connection.
    fn has_pending_data(&self, addr: VsockAddr) -> bool;
}

/// Loopback vsock backend for testing.
#[derive(Debug, Default)]
pub struct LoopbackBackend {
    /// Pending data per connection.
    pending: HashMap<VsockAddr, Vec<u8>>,
}

impl LoopbackBackend {
    /// Creates a new loopback backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl VsockBackend for LoopbackBackend {
    fn on_connect(&mut self, addr: VsockAddr) -> Result<()> {
        self.pending.insert(addr, Vec::new());
        tracing::debug!("Loopback: connection from {:?}", addr);
        Ok(())
    }

    fn on_send(&mut self, addr: VsockAddr, data: &[u8]) -> Result<usize> {
        // Echo back the data
        if let Some(buf) = self.pending.get_mut(&addr) {
            buf.extend_from_slice(data);
        }
        Ok(data.len())
    }

    fn on_recv(&mut self, addr: VsockAddr, buf: &mut [u8]) -> Result<usize> {
        if let Some(pending) = self.pending.get_mut(&addr) {
            let len = buf.len().min(pending.len());
            buf[..len].copy_from_slice(&pending[..len]);
            pending.drain(..len);
            Ok(len)
        } else {
            Ok(0)
        }
    }

    fn on_close(&mut self, addr: VsockAddr) -> Result<()> {
        self.pending.remove(&addr);
        tracing::debug!("Loopback: connection closed {:?}", addr);
        Ok(())
    }

    fn has_pending_data(&self, addr: VsockAddr) -> bool {
        self.pending.get(&addr).map_or(false, |b| !b.is_empty())
    }
}

/// TCP-based vsock backend.
///
/// Maps vsock ports to TCP ports for host-side handling.
pub struct TcpBackend {
    /// Guest CID.
    guest_cid: u64,
    /// Base TCP port (vsock port N maps to TCP port base + N).
    base_port: u16,
    /// Active connections.
    connections: RwLock<HashMap<VsockAddr, TcpStream>>,
    /// Listeners for incoming connections.
    listeners: RwLock<HashMap<u32, TcpListener>>,
}

impl TcpBackend {
    /// Creates a new TCP backend.
    #[must_use]
    pub fn new(guest_cid: u64, base_port: u16) -> Self {
        Self {
            guest_cid,
            base_port,
            connections: RwLock::new(HashMap::new()),
            listeners: RwLock::new(HashMap::new()),
        }
    }

    /// Listens on a vsock port.
    pub fn listen(&self, port: u32) -> Result<()> {
        let tcp_port = self.base_port + port as u16;
        let listener = TcpListener::bind(format!("127.0.0.1:{}", tcp_port))
            .map_err(|e| VirtioError::Io(format!("Failed to bind: {}", e)))?;

        listener
            .set_nonblocking(true)
            .map_err(|e| VirtioError::Io(format!("Failed to set nonblocking: {}", e)))?;

        self.listeners.write().unwrap().insert(port, listener);
        tracing::info!("Vsock listening on port {} (TCP {})", port, tcp_port);
        Ok(())
    }

    /// Accepts a pending connection.
    pub fn accept(&self, port: u32) -> Result<Option<VsockAddr>> {
        let listeners = self.listeners.read().unwrap();
        if let Some(listener) = listeners.get(&port) {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    stream.set_nonblocking(true).map_err(|e| {
                        VirtioError::Io(format!("Failed to set nonblocking: {}", e))
                    })?;

                    let local = VsockAddr::new(VirtioVsock::HOST_CID, port);
                    let remote = VsockAddr::new(self.guest_cid, port);

                    self.connections.write().unwrap().insert(remote, stream);
                    Ok(Some(local))
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
                Err(e) => Err(VirtioError::Io(format!("Accept failed: {}", e))),
            }
        } else {
            Ok(None)
        }
    }
}

impl VsockBackend for TcpBackend {
    fn on_connect(&mut self, addr: VsockAddr) -> Result<()> {
        let tcp_port = self.base_port + addr.port as u16;
        let stream = TcpStream::connect(format!("127.0.0.1:{}", tcp_port))
            .map_err(|e| VirtioError::Io(format!("Connect failed: {}", e)))?;

        stream
            .set_nonblocking(true)
            .map_err(|e| VirtioError::Io(format!("Failed to set nonblocking: {}", e)))?;

        self.connections.write().unwrap().insert(addr, stream);
        Ok(())
    }

    fn on_send(&mut self, addr: VsockAddr, data: &[u8]) -> Result<usize> {
        let mut connections = self.connections.write().unwrap();
        if let Some(stream) = connections.get_mut(&addr) {
            stream
                .write(data)
                .map_err(|e| VirtioError::Io(format!("Send failed: {}", e)))
        } else {
            Err(VirtioError::InvalidOperation("Connection not found".into()))
        }
    }

    fn on_recv(&mut self, addr: VsockAddr, buf: &mut [u8]) -> Result<usize> {
        let mut connections = self.connections.write().unwrap();
        if let Some(stream) = connections.get_mut(&addr) {
            match stream.read(buf) {
                Ok(n) => Ok(n),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
                Err(e) => Err(VirtioError::Io(format!("Recv failed: {}", e))),
            }
        } else {
            Err(VirtioError::InvalidOperation("Connection not found".into()))
        }
    }

    fn on_close(&mut self, addr: VsockAddr) -> Result<()> {
        self.connections.write().unwrap().remove(&addr);
        Ok(())
    }

    fn has_pending_data(&self, addr: VsockAddr) -> bool {
        // TCP streams don't have a simple way to check pending data
        // Would need peek() or poll()
        self.connections.read().unwrap().contains_key(&addr)
    }
}

impl std::fmt::Debug for TcpBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpBackend")
            .field("guest_cid", &self.guest_cid)
            .field("base_port", &self.base_port)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // VsockConfig Tests
    // ==========================================================================

    #[test]
    fn test_vsock_config_default() {
        let config = VsockConfig::default();
        assert_eq!(config.guest_cid, 3);
    }

    #[test]
    fn test_vsock_config_custom() {
        let config = VsockConfig { guest_cid: 100 };
        assert_eq!(config.guest_cid, 100);
    }

    #[test]
    fn test_vsock_config_clone() {
        let config = VsockConfig { guest_cid: 42 };
        let cloned = config.clone();
        assert_eq!(cloned.guest_cid, 42);
    }

    // ==========================================================================
    // VirtioVsock Tests
    // ==========================================================================

    #[test]
    fn test_vsock_new() {
        let vsock = VirtioVsock::new(VsockConfig::default());
        assert_eq!(vsock.guest_cid(), 3);
    }

    #[test]
    fn test_vsock_device_id() {
        let vsock = VirtioVsock::new(VsockConfig::default());
        assert_eq!(vsock.device_id(), VirtioDeviceId::Vsock);
    }

    #[test]
    fn test_vsock_features() {
        let vsock = VirtioVsock::new(VsockConfig::default());
        let features = vsock.features();
        assert!(features & VirtioVsock::FEATURE_STREAM != 0);
    }

    #[test]
    fn test_vsock_ack_features() {
        let mut vsock = VirtioVsock::new(VsockConfig::default());

        vsock.ack_features(VirtioVsock::FEATURE_STREAM);
        assert_eq!(vsock.acked_features, VirtioVsock::FEATURE_STREAM);
    }

    #[test]
    fn test_vsock_ack_unsupported_feature() {
        let mut vsock = VirtioVsock::new(VsockConfig::default());

        // SEQPACKET is not supported by default
        vsock.ack_features(VirtioVsock::FEATURE_SEQPACKET);
        assert_eq!(vsock.acked_features, 0);
    }

    #[test]
    fn test_vsock_read_config() {
        let config = VsockConfig {
            guest_cid: 0x12345678,
        };
        let vsock = VirtioVsock::new(config);

        let mut data = [0u8; 8];
        vsock.read_config(0, &mut data);

        let cid = u64::from_le_bytes(data);
        assert_eq!(cid, 0x12345678);
    }

    #[test]
    fn test_vsock_read_config_partial() {
        let config = VsockConfig {
            guest_cid: 0xDEADBEEF,
        };
        let vsock = VirtioVsock::new(config);

        // Read only first 4 bytes
        let mut data = [0u8; 4];
        vsock.read_config(0, &mut data);

        let low_bytes = u32::from_le_bytes(data);
        assert_eq!(low_bytes, 0xDEADBEEF);
    }

    #[test]
    fn test_vsock_read_config_offset() {
        let config = VsockConfig {
            guest_cid: 0xAABBCCDD_11223344,
        };
        let vsock = VirtioVsock::new(config);

        // Read from offset 4
        let mut data = [0u8; 4];
        vsock.read_config(4, &mut data);

        let high_bytes = u32::from_le_bytes(data);
        assert_eq!(high_bytes, 0xAABBCCDD);
    }

    #[test]
    fn test_vsock_read_config_beyond() {
        let vsock = VirtioVsock::new(VsockConfig::default());

        let mut data = [0xFFu8; 4];
        vsock.read_config(100, &mut data);

        // Should not crash, data might be unchanged
    }

    #[test]
    fn test_vsock_write_config_noop() {
        let mut vsock = VirtioVsock::new(VsockConfig { guest_cid: 42 });

        // Write should be no-op
        vsock.write_config(0, &[0xFF; 8]);

        // CID should be unchanged
        assert_eq!(vsock.guest_cid(), 42);
    }

    #[test]
    fn test_vsock_activate() {
        let mut vsock = VirtioVsock::new(VsockConfig::default());
        assert!(vsock.activate().is_ok());
    }

    #[test]
    fn test_vsock_reset() {
        let mut vsock = VirtioVsock::new(VsockConfig::default());
        vsock.ack_features(VirtioVsock::FEATURE_STREAM);
        assert_ne!(vsock.acked_features, 0);

        vsock.reset();
        assert_eq!(vsock.acked_features, 0);
    }

    // ==========================================================================
    // VsockAddr Tests
    // ==========================================================================

    #[test]
    fn test_vsock_addr_new() {
        let addr = VsockAddr::new(3, 1234);
        assert_eq!(addr.cid, 3);
        assert_eq!(addr.port, 1234);
    }

    #[test]
    fn test_vsock_addr_host() {
        let addr = VsockAddr::host(8080);
        assert_eq!(addr.cid, VirtioVsock::HOST_CID);
        assert_eq!(addr.cid, 2);
        assert_eq!(addr.port, 8080);
    }

    #[test]
    fn test_vsock_addr_clone_copy() {
        let addr = VsockAddr::new(10, 5000);
        let cloned = addr.clone();
        let copied = addr; // Copy

        assert_eq!(cloned.cid, 10);
        assert_eq!(copied.port, 5000);
    }

    #[test]
    fn test_vsock_addr_eq() {
        let addr1 = VsockAddr::new(3, 1234);
        let addr2 = VsockAddr::new(3, 1234);
        let addr3 = VsockAddr::new(3, 5678);

        assert_eq!(addr1, addr2);
        assert_ne!(addr1, addr3);
    }

    #[test]
    fn test_vsock_addr_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(VsockAddr::new(3, 1234));
        set.insert(VsockAddr::new(3, 1234)); // Duplicate
        set.insert(VsockAddr::new(4, 1234));

        assert_eq!(set.len(), 2);
    }

    // ==========================================================================
    // Constants Tests
    // ==========================================================================

    #[test]
    fn test_vsock_constants() {
        assert_eq!(VirtioVsock::HOST_CID, 2);
        assert_eq!(VirtioVsock::RESERVED_CID, 1);
        assert_eq!(VirtioVsock::FEATURE_STREAM, 1 << 0);
        assert_eq!(VirtioVsock::FEATURE_SEQPACKET, 1 << 1);
    }

    // ==========================================================================
    // Backend Tests
    // ==========================================================================

    #[test]
    fn test_loopback_backend() {
        let mut backend = LoopbackBackend::new();
        let addr = VsockAddr::new(3, 1234);

        // Connect
        backend.on_connect(addr).unwrap();

        // Send data (echo)
        let data = b"hello world";
        let sent = backend.on_send(addr, data).unwrap();
        assert_eq!(sent, data.len());

        // Check pending
        assert!(backend.has_pending_data(addr));

        // Receive
        let mut buf = [0u8; 64];
        let received = backend.on_recv(addr, &mut buf).unwrap();
        assert_eq!(received, data.len());
        assert_eq!(&buf[..received], data);

        // Close
        backend.on_close(addr).unwrap();
        assert!(!backend.has_pending_data(addr));
    }

    #[test]
    fn test_vsock_with_loopback_backend() {
        let vsock = VirtioVsock::with_backend(VsockConfig::default(), LoopbackBackend::new());
        assert_eq!(vsock.guest_cid(), 3);
        assert_eq!(vsock.connection_count(), 0);
    }

    #[test]
    fn test_vsock_connect_send_recv() {
        let vsock = VirtioVsock::with_backend(VsockConfig::default(), LoopbackBackend::new());

        // Connect
        vsock.handle_connect(1000, 80).unwrap();
        assert_eq!(vsock.connection_count(), 1);

        // Send
        let data = b"GET / HTTP/1.1";
        let sent = vsock.handle_send(1000, 80, data).unwrap();
        assert_eq!(sent, data.len());

        // Receive (loopback echoes back)
        let mut buf = [0u8; 64];
        let received = vsock.handle_recv(1000, 80, &mut buf).unwrap();
        assert_eq!(received, data.len());
        assert_eq!(&buf[..received], data);

        // Close
        vsock.handle_close(1000, 80).unwrap();
        assert_eq!(vsock.connection_count(), 0);
    }

    #[test]
    fn test_vsock_connection_state() {
        let conn = VsockConnection::new(VsockAddr::new(3, 1000), VsockAddr::new(2, 80));
        assert_eq!(conn.state, ConnectionState::Idle);
        assert_eq!(conn.tx_available(), 0);
        assert_eq!(conn.rx_available(), 0);
    }

    #[test]
    fn test_vsock_connection_buffers() {
        let mut conn = VsockConnection::new(VsockAddr::new(3, 1000), VsockAddr::new(2, 80));

        // TX buffer
        conn.enqueue_tx(b"hello");
        assert_eq!(conn.tx_available(), 5);
        let data = conn.dequeue_tx(3);
        assert_eq!(&data, b"hel");
        assert_eq!(conn.tx_available(), 2);

        // RX buffer
        conn.enqueue_rx(b"world");
        assert_eq!(conn.rx_available(), 5);
        let data = conn.dequeue_rx(10);
        assert_eq!(&data, b"world");
        assert_eq!(conn.rx_available(), 0);
    }

    #[test]
    fn test_vsock_header() {
        let src = VsockAddr::new(3, 1000);
        let dst = VsockAddr::new(2, 80);
        let header = VsockHeader::new(src, dst, VsockOp::Request);

        // Copy fields to avoid unaligned reference issues with packed struct
        let src_cid = header.src_cid;
        let dst_cid = header.dst_cid;
        let src_port = header.src_port;
        let dst_port = header.dst_port;

        assert_eq!(src_cid, 3);
        assert_eq!(dst_cid, 2);
        assert_eq!(src_port, 1000);
        assert_eq!(dst_port, 80);
        assert_eq!(header.operation(), Some(VsockOp::Request));
    }

    #[test]
    fn test_vsock_op_from_u16() {
        assert_eq!(VsockOp::from_u16(0), Some(VsockOp::Invalid));
        assert_eq!(VsockOp::from_u16(1), Some(VsockOp::Request));
        assert_eq!(VsockOp::from_u16(5), Some(VsockOp::Rw));
        assert_eq!(VsockOp::from_u16(100), None);
    }

    #[test]
    fn test_tcp_backend_creation() {
        let backend = TcpBackend::new(3, 10000);
        assert!(!backend.has_pending_data(VsockAddr::new(3, 1234)));
    }
}
