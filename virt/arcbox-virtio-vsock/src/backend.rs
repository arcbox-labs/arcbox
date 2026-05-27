//! `VsockBackend` trait + `LoopbackBackend` (in-process echo).

use std::collections::HashMap;

use arcbox_virtio_core::error::Result;

use crate::addr::VsockAddr;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loopback_backend() {
        let mut backend = LoopbackBackend::new();
        let addr = VsockAddr::new(3, 1234);

        backend.on_connect(addr).unwrap();

        let data = b"hello world";
        let sent = backend.on_send(addr, data).unwrap();
        assert_eq!(sent, data.len());

        assert!(backend.has_pending_data(addr));

        let mut buf = [0u8; 64];
        let received = backend.on_recv(addr, &mut buf).unwrap();
        assert_eq!(received, data.len());
        assert_eq!(&buf[..received], data);

        backend.on_close(addr).unwrap();
        assert!(!backend.has_pending_data(addr));
    }
}
