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
///
/// This is a wrapper around `LinuxTap` that conforms to the `NetworkBackend` trait.
#[cfg(target_os = "linux")]
pub struct TapBackend {
    /// Inner TAP device.
    inner: crate::linux::LinuxTap,
}

#[cfg(target_os = "linux")]
impl TapBackend {
    /// Creates a new TAP backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the TAP device cannot be created.
    pub fn new(name: &str, mac: [u8; 6], mtu: u16) -> Result<Self> {
        let config = crate::linux::TapConfig::new()
            .with_name(name)
            .with_mac(mac)
            .with_mtu(mtu);
        let inner = crate::linux::LinuxTap::new(config)?;
        Ok(Self { inner })
    }

    /// Creates a new TAP backend with default settings.
    ///
    /// # Errors
    ///
    /// Returns an error if the TAP device cannot be created.
    pub fn new_default() -> Result<Self> {
        let inner = crate::linux::LinuxTap::new(crate::linux::TapConfig::default())?;
        Ok(Self { inner })
    }

    /// Creates a new TAP backend with custom configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the TAP device cannot be created.
    pub fn with_config(config: crate::linux::TapConfig) -> Result<Self> {
        let inner = crate::linux::LinuxTap::new(config)?;
        Ok(Self { inner })
    }

    /// Returns the TAP device name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Brings the TAP interface up.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn bring_up(&self) -> Result<()> {
        self.inner.bring_up()
    }

    /// Brings the TAP interface down.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn bring_down(&self) -> Result<()> {
        self.inner.bring_down()
    }

    /// Returns the raw file descriptor.
    #[must_use]
    pub fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.inner.as_raw_fd()
    }
}

#[cfg(target_os = "linux")]
impl NetworkBackend for TapBackend {
    fn send(&self, data: &[u8]) -> Result<usize> {
        self.inner.send(data)
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        self.inner.recv(buf)
    }

    fn mac(&self) -> [u8; 6] {
        self.inner.mac()
    }

    fn mtu(&self) -> u16 {
        self.inner.mtu()
    }
}

/// vmnet backend for macOS.
///
/// This is a wrapper around the low-level `Vmnet` implementation that
/// conforms to the `NetworkBackend` trait.
#[cfg(target_os = "macos")]
pub struct VmnetBackend {
    /// Inner vmnet interface.
    inner: crate::darwin::Vmnet,
}

#[cfg(target_os = "macos")]
impl VmnetBackend {
    /// Creates a new vmnet backend with default NAT (shared) configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the vmnet interface cannot be created.
    /// This typically requires root privileges or appropriate entitlements.
    pub fn new(mac: [u8; 6], mtu: u16) -> Result<Self> {
        let config = crate::darwin::VmnetConfig::shared()
            .with_mac(mac)
            .with_mtu(mtu);
        let inner = crate::darwin::Vmnet::new(config)?;
        Ok(Self { inner })
    }

    /// Creates a new vmnet backend with custom configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the vmnet interface cannot be created.
    pub fn with_config(config: crate::darwin::VmnetConfig) -> Result<Self> {
        let inner = crate::darwin::Vmnet::new(config)?;
        Ok(Self { inner })
    }

    /// Creates a new NAT (shared) vmnet backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the vmnet interface cannot be created.
    pub fn new_shared() -> Result<Self> {
        let inner = crate::darwin::Vmnet::new_shared()?;
        Ok(Self { inner })
    }

    /// Creates a new host-only vmnet backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the vmnet interface cannot be created.
    pub fn new_host_only() -> Result<Self> {
        let inner = crate::darwin::Vmnet::new_host_only()?;
        Ok(Self { inner })
    }

    /// Creates a new bridged vmnet backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the vmnet interface cannot be created.
    pub fn new_bridged(interface: &str) -> Result<Self> {
        let inner = crate::darwin::Vmnet::new_bridged(interface)?;
        Ok(Self { inner })
    }

    /// Returns true if the interface is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.inner.is_running()
    }

    /// Returns the maximum packet size.
    #[must_use]
    pub fn max_packet_size(&self) -> usize {
        self.inner.max_packet_size()
    }

    /// Stops the vmnet interface.
    pub fn stop(&self) {
        self.inner.stop();
    }
}

#[cfg(target_os = "macos")]
impl NetworkBackend for VmnetBackend {
    fn send(&self, data: &[u8]) -> Result<usize> {
        self.inner.write_packet(data)
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        self.inner.read_packet(buf)
    }

    fn mac(&self) -> [u8; 6] {
        self.inner.mac()
    }

    fn mtu(&self) -> u16 {
        self.inner.mtu()
    }
}
