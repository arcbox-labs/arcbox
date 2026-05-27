//! TCP-based vsock backend — maps vsock ports to TCP ports for host-side handling.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::RwLock;

use arcbox_virtio_core::error::{Result, VirtioError};

use crate::addr::{HOST_CID, VsockAddr};
use crate::backend::VsockBackend;

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
        let listener = TcpListener::bind(format!("127.0.0.1:{tcp_port}"))
            .map_err(|e| VirtioError::Io(format!("Failed to bind: {e}")))?;

        listener
            .set_nonblocking(true)
            .map_err(|e| VirtioError::Io(format!("Failed to set nonblocking: {e}")))?;

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
                    stream
                        .set_nonblocking(true)
                        .map_err(|e| VirtioError::Io(format!("Failed to set nonblocking: {e}")))?;

                    let local = VsockAddr::new(HOST_CID, port);
                    let remote = VsockAddr::new(self.guest_cid, port);

                    self.connections.write().unwrap().insert(remote, stream);
                    Ok(Some(local))
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
                Err(e) => Err(VirtioError::Io(format!("Accept failed: {e}"))),
            }
        } else {
            Ok(None)
        }
    }
}

impl VsockBackend for TcpBackend {
    fn on_connect(&mut self, addr: VsockAddr) -> Result<()> {
        let tcp_port = self.base_port + addr.port as u16;
        let stream = TcpStream::connect(format!("127.0.0.1:{tcp_port}"))
            .map_err(|e| VirtioError::Io(format!("Connect failed: {e}")))?;

        stream
            .set_nonblocking(true)
            .map_err(|e| VirtioError::Io(format!("Failed to set nonblocking: {e}")))?;

        self.connections.write().unwrap().insert(addr, stream);
        Ok(())
    }

    fn on_send(&mut self, addr: VsockAddr, data: &[u8]) -> Result<usize> {
        let mut connections = self.connections.write().unwrap();
        if let Some(stream) = connections.get_mut(&addr) {
            stream
                .write(data)
                .map_err(|e| VirtioError::Io(format!("Send failed: {e}")))
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
                Err(e) => Err(VirtioError::Io(format!("Recv failed: {e}"))),
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
        // TCP streams don't have a simple way to check pending data; existence
        // of the connection entry stands in as a coarse signal.
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

    #[test]
    fn test_tcp_backend_creation() {
        let backend = TcpBackend::new(3, 10000);
        assert!(!backend.has_pending_data(VsockAddr::new(3, 1234)));
    }
}
