//! Host-side vsock backend (Hypervisor.framework) — relays guest connections to Unix sockets.

#![cfg(unix)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use arcbox_virtio_core::error::{Result, VirtioError};

use crate::addr::VsockAddr;
use crate::backend::VsockBackend;

/// Active forwarding channel between a guest vsock port and a host-side Unix
/// socket.
#[derive(Debug)]
struct VsockChannel {
    /// The connected Unix socket on the host side.
    stream: UnixStream,
}

/// Host-side vsock backend for the HV (Hypervisor.framework) backend.
///
/// Accepts connections from the guest and forwards them to host-side Unix
/// domain sockets. Each guest port is mapped to a Unix socket path on the host;
/// when the guest opens a connection the backend connects to the corresponding
/// socket and relays data bidirectionally.
///
/// This is the primary backend used for arcbox-agent RPC communication on
/// macOS.
pub struct HostVsockBackend {
    /// Port to Unix socket path mappings.
    port_map: HashMap<u32, String>,
    /// Active forwarding channels keyed by (`src_port`, `dst_port`).
    channels: HashMap<(u32, u32), VsockChannel>,
}

impl std::fmt::Debug for HostVsockBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostVsockBackend")
            .field("port_map", &self.port_map)
            .field("channels_count", &self.channels.len())
            .finish()
    }
}

impl HostVsockBackend {
    /// Creates a new host vsock backend with no port mappings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            port_map: HashMap::new(),
            channels: HashMap::new(),
        }
    }

    /// Registers a mapping from guest vsock port to a host-side Unix socket
    /// path.
    ///
    /// When the guest opens a connection to `port`, the backend will connect
    /// to `socket_path` on the host and relay traffic.
    pub fn add_port_mapping(&mut self, port: u32, socket_path: String) {
        self.port_map.insert(port, socket_path);
    }

    /// Creates a backend with pre-configured port mappings.
    #[must_use]
    pub fn with_port_map(port_map: HashMap<u32, String>) -> Self {
        Self {
            port_map,
            channels: HashMap::new(),
        }
    }
}

impl Default for HostVsockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl VsockBackend for HostVsockBackend {
    fn on_connect(&mut self, addr: VsockAddr) -> Result<()> {
        let socket_path = self.port_map.get(&addr.port).ok_or_else(|| {
            VirtioError::InvalidOperation(format!("No port mapping for vsock port {}", addr.port))
        })?;

        let stream = UnixStream::connect(socket_path).map_err(|e| {
            VirtioError::Io(format!(
                "Failed to connect to Unix socket {}: {}",
                socket_path, e
            ))
        })?;

        stream
            .set_nonblocking(true)
            .map_err(|e| VirtioError::Io(format!("Failed to set nonblocking: {}", e)))?;

        tracing::debug!(
            "HostVsockBackend: connected port {} to {}",
            addr.port,
            socket_path
        );

        // Use (port, port) as channel key — the guest side always uses the same
        // port for the connection.
        self.channels
            .insert((addr.port, addr.port), VsockChannel { stream });
        Ok(())
    }

    fn on_send(&mut self, addr: VsockAddr, data: &[u8]) -> Result<usize> {
        let channel = self
            .channels
            .get_mut(&(addr.port, addr.port))
            .ok_or_else(|| {
                VirtioError::InvalidOperation(format!("No channel for vsock port {}", addr.port))
            })?;

        channel
            .stream
            .write(data)
            .map_err(|e| VirtioError::Io(format!("Failed to write to Unix socket: {}", e)))
    }

    fn on_recv(&mut self, addr: VsockAddr, buf: &mut [u8]) -> Result<usize> {
        let channel = self
            .channels
            .get_mut(&(addr.port, addr.port))
            .ok_or_else(|| {
                VirtioError::InvalidOperation(format!("No channel for vsock port {}", addr.port))
            })?;

        match channel.stream.read(buf) {
            Ok(n) => Ok(n),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(VirtioError::Io(format!(
                "Failed to read from Unix socket: {}",
                e
            ))),
        }
    }

    fn on_close(&mut self, addr: VsockAddr) -> Result<()> {
        self.channels.remove(&(addr.port, addr.port));
        tracing::debug!("HostVsockBackend: closed port {}", addr.port);
        Ok(())
    }

    fn has_pending_data(&self, addr: VsockAddr) -> bool {
        // Existence of the channel entry stands in as a coarse signal —
        // non-blocking peek is the alternative.
        self.channels.contains_key(&(addr.port, addr.port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_vsock_backend_new() {
        let backend = HostVsockBackend::new();
        assert!(backend.port_map.is_empty());
        assert!(backend.channels.is_empty());
    }

    #[test]
    fn test_host_vsock_backend_add_port_mapping() {
        let mut backend = HostVsockBackend::new();
        backend.add_port_mapping(1234, "/tmp/test.sock".to_string());
        assert_eq!(backend.port_map.get(&1234).unwrap(), "/tmp/test.sock");
    }

    #[test]
    fn test_host_vsock_backend_connect_no_mapping() {
        let mut backend = HostVsockBackend::new();
        let addr = VsockAddr::new(3, 9999);
        let result = backend.on_connect(addr);
        assert!(result.is_err());
    }

    #[test]
    fn test_host_vsock_backend_with_unix_socket() {
        use std::os::unix::net::UnixListener;

        let tmpdir = tempfile::tempdir().unwrap();
        let sock_path = tmpdir.path().join("test.sock");
        let sock_path_str = sock_path.to_str().unwrap().to_string();

        let _listener = UnixListener::bind(&sock_path).unwrap();

        let mut backend = HostVsockBackend::new();
        backend.add_port_mapping(5000, sock_path_str);

        let addr = VsockAddr::new(3, 5000);
        backend.on_connect(addr).unwrap();

        let data = b"ping";
        let sent = backend.on_send(addr, data).unwrap();
        assert_eq!(sent, data.len());

        backend.on_close(addr).unwrap();
        assert!(!backend.has_pending_data(addr));
    }
}
