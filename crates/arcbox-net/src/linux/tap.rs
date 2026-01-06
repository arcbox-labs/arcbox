//! Linux TAP device management.
//!
//! This module provides functionality for creating and managing TAP (network tap)
//! devices. TAP devices are virtual Ethernet devices that can be used to connect
//! VMs to the host network.
//!
//! The implementation is based on the standard Linux tun/tap interface using
//! `/dev/net/tun` and the `TUNSETIFF` ioctl.

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use ipnetwork::Ipv4Network;

use super::netlink::NetlinkHandle;
use crate::backend::NetworkBackend;
use crate::error::{NetError, Result};

/// TAP device configuration.
#[derive(Debug, Clone)]
pub struct TapConfig {
    /// TAP device name (None for auto-generated name like "tap0").
    pub name: Option<String>,
    /// MAC address (None for kernel-generated).
    pub mac: Option<[u8; 6]>,
    /// MTU size.
    pub mtu: u16,
    /// Enable vnet header for virtio-net compatibility.
    pub vnet_hdr: bool,
}

impl Default for TapConfig {
    fn default() -> Self {
        Self {
            name: None,
            mac: None,
            mtu: 1500,
            vnet_hdr: false,
        }
    }
}

impl TapConfig {
    /// Creates a new TAP configuration with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the TAP device name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the MAC address.
    #[must_use]
    pub fn with_mac(mut self, mac: [u8; 6]) -> Self {
        self.mac = Some(mac);
        self
    }

    /// Sets the MTU.
    #[must_use]
    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Enables vnet header.
    #[must_use]
    pub fn with_vnet_hdr(mut self, enabled: bool) -> Self {
        self.vnet_hdr = enabled;
        self
    }
}

/// Linux TAP device.
///
/// Provides a TAP device interface for sending and receiving Ethernet frames.
/// The device is automatically cleaned up when dropped.
///
/// # Example
///
/// ```no_run
/// use arcbox_net::linux::{LinuxTap, TapConfig};
///
/// let config = TapConfig::new()
///     .with_name("tap0")
///     .with_mtu(1500);
///
/// let mut tap = LinuxTap::new(config).unwrap();
/// tap.bring_up().unwrap();
///
/// // Send and receive packets
/// let mut buf = [0u8; 1514];
/// let n = tap.recv(&mut buf).unwrap();
/// ```
pub struct LinuxTap {
    /// TAP file descriptor.
    fd: OwnedFd,
    /// TAP device name.
    name: String,
    /// MAC address.
    mac: [u8; 6],
    /// MTU.
    mtu: u16,
    /// Non-blocking mode.
    nonblocking: bool,
    /// Whether vnet header is enabled.
    vnet_hdr: bool,
}

// ioctl constants
const TUNSETIFF: libc::c_ulong = 0x400454ca;
const TUNSETOFFLOAD: libc::c_ulong = 0x400454d0;
const TUNSETVNETHDRSZ: libc::c_ulong = 0x400454d8;

// TUN/TAP flags
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFF_VNET_HDR: libc::c_short = 0x4000;

// Offload flags for TUNSETOFFLOAD
const TUN_F_CSUM: u32 = 0x01;
const TUN_F_TSO4: u32 = 0x02;
const TUN_F_TSO6: u32 = 0x04;

/// ifreq structure for ioctl calls.
#[repr(C)]
struct Ifreq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_flags: libc::c_short,
    _padding: [u8; 22],
}

impl LinuxTap {
    /// Creates a new TAP device.
    ///
    /// # Errors
    ///
    /// Returns an error if the TAP device cannot be created.
    pub fn new(config: TapConfig) -> Result<Self> {
        // Open /dev/net/tun
        let fd = unsafe {
            libc::open(
                b"/dev/net/tun\0".as_ptr().cast::<libc::c_char>(),
                libc::O_RDWR | libc::O_CLOEXEC,
            )
        };

        if fd < 0 {
            return Err(NetError::Tap(format!(
                "failed to open /dev/net/tun: {}",
                io::Error::last_os_error()
            )));
        }

        // Prepare ifreq structure
        let mut ifr = Ifreq {
            ifr_name: [0; libc::IFNAMSIZ],
            ifr_flags: IFF_TAP | IFF_NO_PI,
            _padding: [0; 22],
        };

        // Enable vnet header if requested
        if config.vnet_hdr {
            ifr.ifr_flags |= IFF_VNET_HDR;
        }

        // Set device name if provided
        if let Some(ref dev_name) = config.name {
            let name_bytes = dev_name.as_bytes();
            let len = name_bytes.len().min(libc::IFNAMSIZ - 1);
            for (i, &b) in name_bytes[..len].iter().enumerate() {
                ifr.ifr_name[i] = b as libc::c_char;
            }
        }

        // Create TAP device
        let ret = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(NetError::Tap(format!(
                "TUNSETIFF failed: {}",
                io::Error::last_os_error()
            )));
        }

        // Extract device name
        let name = {
            let len = ifr
                .ifr_name
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(libc::IFNAMSIZ);
            let bytes: Vec<u8> = ifr.ifr_name[..len].iter().map(|&c| c as u8).collect();
            String::from_utf8_lossy(&bytes).into_owned()
        };

        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        // Set vnet header size if enabled
        if config.vnet_hdr {
            let hdr_sz: i32 = 12; // sizeof(virtio_net_hdr_v1)
            let ret = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETVNETHDRSZ, &hdr_sz) };
            if ret < 0 {
                return Err(NetError::Tap(format!(
                    "TUNSETVNETHDRSZ failed: {}",
                    io::Error::last_os_error()
                )));
            }

            // Enable offload features
            let offload = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
            let ret = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETOFFLOAD, offload) };
            if ret < 0 {
                tracing::warn!(
                    "TUNSETOFFLOAD failed (non-fatal): {}",
                    io::Error::last_os_error()
                );
            }
        }

        // Get MAC address from the interface
        let mac = Self::get_mac_address(&name)?;

        tracing::info!("Created TAP device: {}", name);

        Ok(Self {
            fd,
            name,
            mac,
            mtu: config.mtu,
            nonblocking: false,
            vnet_hdr: config.vnet_hdr,
        })
    }

    /// Gets the MAC address of an interface.
    fn get_mac_address(ifname: &str) -> Result<[u8; 6]> {
        // Read MAC from /sys/class/net/<ifname>/address
        let path = format!("/sys/class/net/{}/address", ifname);
        let mac_str = std::fs::read_to_string(&path)
            .map_err(|e| NetError::Tap(format!("failed to read MAC address: {}", e)))?;

        let mac_str = mac_str.trim();
        let bytes: Vec<u8> = mac_str
            .split(':')
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .collect();

        if bytes.len() != 6 {
            return Err(NetError::Tap(format!("invalid MAC address: {}", mac_str)));
        }

        let mut mac = [0u8; 6];
        mac.copy_from_slice(&bytes);
        Ok(mac)
    }

    /// Sets non-blocking mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the mode cannot be changed.
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> Result<()> {
        let flags = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(NetError::Tap(format!(
                "F_GETFL failed: {}",
                io::Error::last_os_error()
            )));
        }

        let new_flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };

        let ret = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, new_flags) };
        if ret < 0 {
            return Err(NetError::Tap(format!(
                "F_SETFL failed: {}",
                io::Error::last_os_error()
            )));
        }

        self.nonblocking = nonblocking;
        Ok(())
    }

    /// Returns the TAP device name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the raw file descriptor.
    ///
    /// This can be used to integrate with async runtimes or for select/poll.
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Brings the TAP interface up.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn bring_up(&self) -> Result<()> {
        let mut netlink = NetlinkHandle::new()?;
        let ifindex = netlink.get_ifindex(&self.name)?;
        netlink.set_link_state(ifindex, true)?;

        tracing::debug!("Brought up TAP device {}", self.name);
        Ok(())
    }

    /// Brings the TAP interface down.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn bring_down(&self) -> Result<()> {
        let mut netlink = NetlinkHandle::new()?;
        let ifindex = netlink.get_ifindex(&self.name)?;
        netlink.set_link_state(ifindex, false)?;

        tracing::debug!("Brought down TAP device {}", self.name);
        Ok(())
    }

    /// Sets the IP address on the TAP device.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn set_ip(&self, addr: Ipv4Network) -> Result<()> {
        let mut netlink = NetlinkHandle::new()?;
        let ifindex = netlink.get_ifindex(&self.name)?;
        netlink.add_address(ifindex, ipnetwork::IpNetwork::V4(addr))?;

        tracing::debug!("Set IP {} on TAP device {}", addr, self.name);
        Ok(())
    }

    /// Returns the interface index.
    ///
    /// # Errors
    ///
    /// Returns an error if the interface cannot be found.
    pub fn ifindex(&self) -> Result<u32> {
        let netlink = NetlinkHandle::new()?;
        netlink.get_ifindex(&self.name)
    }

    /// Returns whether vnet header is enabled.
    #[must_use]
    pub fn has_vnet_hdr(&self) -> bool {
        self.vnet_hdr
    }

    /// Sends a packet through the TAP device.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    pub fn send_packet(&mut self, data: &[u8]) -> Result<usize> {
        let ret =
            unsafe { libc::write(self.fd.as_raw_fd(), data.as_ptr().cast(), data.len()) };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(NetError::Io(err));
        }

        Ok(ret as usize)
    }

    /// Receives a packet from the TAP device.
    ///
    /// Returns the number of bytes read.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    pub fn recv_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
        let ret = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(NetError::Io(err));
        }

        Ok(ret as usize)
    }

    /// Checks if data is available to read.
    ///
    /// Returns true if there is pending data.
    #[must_use]
    pub fn has_data(&self) -> bool {
        let mut pollfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };

        let ret = unsafe { libc::poll(&mut pollfd, 1, 0) };
        ret > 0 && (pollfd.revents & libc::POLLIN) != 0
    }
}

impl NetworkBackend for LinuxTap {
    fn send(&self, data: &[u8]) -> Result<usize> {
        let ret =
            unsafe { libc::write(self.fd.as_raw_fd(), data.as_ptr().cast(), data.len()) };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(NetError::Io(err));
        }

        Ok(ret as usize)
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let ret = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(NetError::Io(err));
        }

        Ok(ret as usize)
    }

    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }
}

impl Drop for LinuxTap {
    fn drop(&mut self) {
        tracing::debug!("Closing TAP device {}", self.name);
        // OwnedFd handles closing the file descriptor
    }
}

/// Generates a random MAC address with the locally administered bit set.
#[must_use]
pub fn generate_mac() -> [u8; 6] {
    let mut mac = [0u8; 6];

    // Use /dev/urandom for randomness
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = file.read_exact(&mut mac);
    }

    // Set locally administered bit (bit 1 of first byte)
    mac[0] = (mac[0] & 0xfe) | 0x02;
    // Clear multicast bit (bit 0 of first byte)
    mac[0] &= 0xfe;

    mac
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tap_config_default() {
        let config = TapConfig::default();
        assert!(config.name.is_none());
        assert!(config.mac.is_none());
        assert_eq!(config.mtu, 1500);
        assert!(!config.vnet_hdr);
    }

    #[test]
    fn test_tap_config_builder() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let config = TapConfig::new()
            .with_name("tap-test")
            .with_mac(mac)
            .with_mtu(9000)
            .with_vnet_hdr(true);

        assert_eq!(config.name, Some("tap-test".to_string()));
        assert_eq!(config.mac, Some(mac));
        assert_eq!(config.mtu, 9000);
        assert!(config.vnet_hdr);
    }

    #[test]
    fn test_generate_mac() {
        let mac = generate_mac();
        // Check locally administered bit is set
        assert_eq!(mac[0] & 0x02, 0x02);
        // Check multicast bit is clear
        assert_eq!(mac[0] & 0x01, 0x00);
    }

    #[test]
    fn test_tap_creation_requires_root() {
        // This test requires root privileges
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping test: requires root privileges");
            return;
        }

        let config = TapConfig::new().with_name("arcbox-tap-test");
        let tap = LinuxTap::new(config);
        assert!(tap.is_ok());

        let tap = tap.unwrap();
        assert_eq!(tap.name(), "arcbox-tap-test");
        assert_eq!(tap.mtu(), 1500);
    }
}
