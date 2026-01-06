//! Network backend implementations.

use crate::error::Result;

/// Network backend trait.
pub trait NetworkBackend: Send + Sync {
    /// Sends a packet.
    fn send(&self, data: &[u8]) -> Result<usize>;

    /// Receives a packet.
    fn recv(&self, buf: &mut [u8]) -> Result<usize>;

    /// Gets the MAC address.
    fn mac(&self) -> [u8; 6];

    /// Gets the MTU.
    fn mtu(&self) -> u16;
}

/// TAP backend for Linux.
#[cfg(target_os = "linux")]
pub struct TapBackend {
    // TODO: TAP file descriptor
    mac: [u8; 6],
    mtu: u16,
}

#[cfg(target_os = "linux")]
impl TapBackend {
    /// Creates a new TAP backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the TAP device cannot be created.
    pub fn new(name: &str, mac: [u8; 6], mtu: u16) -> Result<Self> {
        // TODO: Create TAP device
        let _ = name;
        Ok(Self { mac, mtu })
    }
}

#[cfg(target_os = "linux")]
impl NetworkBackend for TapBackend {
    fn send(&self, _data: &[u8]) -> Result<usize> {
        // TODO: Write to TAP
        Ok(0)
    }

    fn recv(&self, _buf: &mut [u8]) -> Result<usize> {
        // TODO: Read from TAP
        Ok(0)
    }

    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }
}

/// vmnet backend for macOS.
#[cfg(target_os = "macos")]
pub struct VmnetBackend {
    // TODO: vmnet interface handle
    mac: [u8; 6],
    mtu: u16,
}

#[cfg(target_os = "macos")]
impl VmnetBackend {
    /// Creates a new vmnet backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the vmnet interface cannot be created.
    pub fn new(mac: [u8; 6], mtu: u16) -> Result<Self> {
        // TODO: Create vmnet interface
        Ok(Self { mac, mtu })
    }
}

#[cfg(target_os = "macos")]
impl NetworkBackend for VmnetBackend {
    fn send(&self, _data: &[u8]) -> Result<usize> {
        // TODO: Write to vmnet
        Ok(0)
    }

    fn recv(&self, _buf: &mut [u8]) -> Result<usize> {
        // TODO: Read from vmnet
        Ok(0)
    }

    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }
}
