//! vmnet.framework backend implementation.
//!
//! This module provides a high-level Rust interface to Apple's vmnet.framework
//! for creating virtual network interfaces on macOS.
//!
//! # Modes
//!
//! - **Shared (NAT)**: VMs share host network via NAT, with DHCP
//! - **Host-only**: Isolated network between VMs and host
//! - **Bridged**: VMs appear as separate devices on physical network
//!
//! # Requirements
//!
//! - macOS 11.0 or later
//! - Privileged user or appropriate entitlements

use std::ffi::CString;
use std::net::Ipv4Addr;
use std::os::raw::c_int;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

use super::vmnet_ffi::*;
use crate::backend::NetworkBackend;
use crate::error::{NetError, Result};

/// Default MTU size.
const DEFAULT_MTU: u16 = 1500;

/// Default maximum packet size (Ethernet frame + VLAN tag).
/// The actual value is returned by vmnet_start_interface completion handler,
/// but without proper Objective-C block support, we use this default.
const DEFAULT_MAX_PACKET_SIZE: usize = 1518;

/// vmnet interface configuration.
#[derive(Debug, Clone)]
pub struct VmnetConfig {
    /// Operating mode.
    pub mode: VmnetMode,
    /// MAC address (auto-generated if None).
    pub mac: Option<[u8; 6]>,
    /// MTU size.
    pub mtu: u16,
    /// Bridge interface name (for bridged mode).
    pub bridge_interface: Option<String>,
    /// Start IP address for DHCP range (shared mode).
    pub dhcp_start: Option<Ipv4Addr>,
    /// End IP address for DHCP range (shared mode).
    pub dhcp_end: Option<Ipv4Addr>,
    /// Subnet mask (shared mode).
    pub subnet_mask: Option<Ipv4Addr>,
    /// Enable isolation (host mode).
    pub isolated: bool,
}

impl Default for VmnetConfig {
    fn default() -> Self {
        Self {
            mode: VmnetMode::Shared,
            mac: None,
            mtu: DEFAULT_MTU,
            bridge_interface: None,
            dhcp_start: None,
            dhcp_end: None,
            subnet_mask: None,
            isolated: false,
        }
    }
}

impl VmnetConfig {
    /// Creates a new shared (NAT) mode configuration.
    #[must_use]
    pub fn shared() -> Self {
        Self {
            mode: VmnetMode::Shared,
            ..Default::default()
        }
    }

    /// Creates a new host-only mode configuration.
    #[must_use]
    pub fn host_only() -> Self {
        Self {
            mode: VmnetMode::HostOnly,
            ..Default::default()
        }
    }

    /// Creates a new bridged mode configuration.
    #[must_use]
    pub fn bridged(interface: impl Into<String>) -> Self {
        Self {
            mode: VmnetMode::Bridged,
            bridge_interface: Some(interface.into()),
            ..Default::default()
        }
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

    /// Sets the DHCP range (shared mode).
    #[must_use]
    pub fn with_dhcp_range(mut self, start: Ipv4Addr, end: Ipv4Addr) -> Self {
        self.dhcp_start = Some(start);
        self.dhcp_end = Some(end);
        self
    }

    /// Sets the subnet mask (shared mode).
    #[must_use]
    pub fn with_subnet_mask(mut self, mask: Ipv4Addr) -> Self {
        self.subnet_mask = Some(mask);
        self
    }

    /// Enables isolation (host mode).
    #[must_use]
    pub fn with_isolation(mut self, isolated: bool) -> Self {
        self.isolated = isolated;
        self
    }
}

/// vmnet operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmnetMode {
    /// Shared (NAT) mode.
    #[default]
    Shared,
    /// Host-only mode.
    HostOnly,
    /// Bridged mode.
    Bridged,
}

impl From<VmnetMode> for VmnetOperatingMode {
    fn from(mode: VmnetMode) -> Self {
        match mode {
            VmnetMode::Shared => VmnetOperatingMode::Shared,
            VmnetMode::HostOnly => VmnetOperatingMode::Host,
            VmnetMode::Bridged => VmnetOperatingMode::Bridged,
        }
    }
}

/// vmnet backend for macOS.
///
/// Provides network connectivity for VMs using Apple's vmnet.framework.
pub struct Vmnet {
    /// vmnet interface handle.
    interface: VmnetInterfaceRef,
    /// Dispatch queue for vmnet operations.
    queue: DispatchQueue,
    /// MAC address.
    mac: [u8; 6],
    /// MTU size.
    mtu: u16,
    /// Maximum packet size.
    max_packet_size: usize,
    /// Running state.
    running: AtomicBool,
}

// Safety: Vmnet uses thread-safe primitives and vmnet.framework is thread-safe.
unsafe impl Send for Vmnet {}
unsafe impl Sync for Vmnet {}

impl Vmnet {
    /// Creates a new vmnet interface with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The vmnet interface cannot be created
    /// - The user doesn't have sufficient privileges
    /// - The configuration is invalid
    pub fn new(config: VmnetConfig) -> Result<Self> {
        // Create dispatch queue for vmnet operations.
        let queue_label = CString::new("com.arcbox.vmnet").unwrap();

        // Safety: dispatch_queue_create is safe to call with valid parameters.
        let queue = unsafe { dispatch_queue_create(queue_label.as_ptr(), ptr::null()) };

        if queue.is_null() {
            return Err(NetError::config(
                "failed to create dispatch queue".to_string(),
            ));
        }

        // Build configuration dictionary.
        // Safety: Core Foundation functions are safe when used correctly.
        let config_dict = unsafe {
            let dict = create_vmnet_config_dict();
            if dict.is_null() {
                dispatch_release(queue as *mut _);
                return Err(NetError::config(
                    "failed to create config dictionary".to_string(),
                ));
            }

            // Set operating mode.
            let mode_value: i64 = VmnetOperatingMode::from(config.mode) as i64;
            let mode_num = cfnumber_from_i64(mode_value);
            CFDictionarySetValue(dict, vmnet_operation_mode_key as _, mode_num as _);
            CFRelease(mode_num as _);

            // Set MAC address if provided.
            if let Some(mac) = config.mac {
                let mac_str = format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                );
                let mac_cf = cfstring_from_str(&mac_str);
                CFDictionarySetValue(dict, vmnet_mac_address_key as _, mac_cf as _);
                CFRelease(mac_cf as _);
            }

            // Set MTU.
            let mtu_value: i64 = i64::from(config.mtu);
            let mtu_num = cfnumber_from_i64(mtu_value);
            CFDictionarySetValue(dict, vmnet_mtu_key as _, mtu_num as _);
            CFRelease(mtu_num as _);

            // Mode-specific configuration.
            match config.mode {
                VmnetMode::Shared => {
                    // Set DHCP range if provided.
                    if let Some(start) = config.dhcp_start {
                        let start_cf = cfstring_from_str(&start.to_string());
                        CFDictionarySetValue(dict, vmnet_start_address_key as _, start_cf as _);
                        CFRelease(start_cf as _);
                    }
                    if let Some(end) = config.dhcp_end {
                        let end_cf = cfstring_from_str(&end.to_string());
                        CFDictionarySetValue(dict, vmnet_end_address_key as _, end_cf as _);
                        CFRelease(end_cf as _);
                    }
                    if let Some(mask) = config.subnet_mask {
                        let mask_cf = cfstring_from_str(&mask.to_string());
                        CFDictionarySetValue(dict, vmnet_subnet_mask_key as _, mask_cf as _);
                        CFRelease(mask_cf as _);
                    }
                }
                VmnetMode::HostOnly => {
                    // Set isolation if enabled.
                    if config.isolated {
                        CFDictionarySetValue(dict, vmnet_enable_isolation_key as _, kCFBooleanTrue);

                        // Generate unique interface ID for isolation.
                        let uuid = CFUUIDCreate(kCFAllocatorDefault);
                        let uuid_str = CFUUIDCreateString(kCFAllocatorDefault, uuid);
                        CFDictionarySetValue(dict, vmnet_interface_id_key as _, uuid_str as _);
                        CFRelease(uuid_str as _);
                        CFRelease(uuid as _);
                    }
                }
                VmnetMode::Bridged => {
                    // Set bridge interface.
                    if let Some(ref iface) = config.bridge_interface {
                        let iface_cf = cfstring_from_str(iface);
                        CFDictionarySetValue(
                            dict,
                            vmnet_shared_interface_name_key as _,
                            iface_cf as _,
                        );
                        CFRelease(iface_cf as _);
                    } else {
                        CFRelease(dict as _);
                        dispatch_release(queue as *mut _);
                        return Err(NetError::config(
                            "bridge mode requires interface name".to_string(),
                        ));
                    }
                }
            }

            dict
        };

        // Start the interface.
        // Note: vmnet_start_interface requires an Objective-C block for the completion handler.
        // Passing NULL for the handler causes it to operate synchronously.
        // A production implementation might use proper block support for async operation.

        // Safety: We're calling vmnet with valid configuration.
        let interface = unsafe { vmnet_start_interface(config_dict as _, queue, ptr::null()) };

        // Release the config dictionary.
        unsafe {
            CFRelease(config_dict as _);
        }

        if interface.is_null() {
            unsafe {
                dispatch_release(queue as *mut _);
            }
            return Err(NetError::config(
                "failed to start vmnet interface (requires root or entitlements)".to_string(),
            ));
        }

        // Use default max packet size.
        // The actual value is returned by the completion handler, but without
        // proper Objective-C block support, we use a safe default.
        let max_packet_size = DEFAULT_MAX_PACKET_SIZE;

        // Use provided or generated MAC.
        let mac = config.mac.unwrap_or_else(super::generate_mac);

        Ok(Self {
            interface,
            queue,
            mac,
            mtu: config.mtu,
            max_packet_size,
            running: AtomicBool::new(true),
        })
    }

    /// Creates a vmnet interface with default NAT (shared) configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the interface cannot be created.
    pub fn new_shared() -> Result<Self> {
        Self::new(VmnetConfig::shared())
    }

    /// Creates a vmnet interface with host-only configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the interface cannot be created.
    pub fn new_host_only() -> Result<Self> {
        Self::new(VmnetConfig::host_only())
    }

    /// Creates a vmnet interface bridged to the specified interface.
    ///
    /// # Errors
    ///
    /// Returns an error if the interface cannot be created.
    pub fn new_bridged(interface: &str) -> Result<Self> {
        Self::new(VmnetConfig::bridged(interface))
    }

    /// Returns true if the interface is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// Returns the maximum packet size.
    #[must_use]
    pub fn max_packet_size(&self) -> usize {
        self.max_packet_size
    }

    /// Reads a packet from the vmnet interface.
    ///
    /// # Errors
    ///
    /// Returns an error if the read operation fails.
    pub fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
        if !self.is_running() {
            return Err(NetError::config("interface not running".to_string()));
        }

        // Create iovec for the buffer.
        let mut iov = iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: buf.len(),
        };

        // Create packet descriptor.
        let mut packet = VmnetPacket {
            vm_pkt_iov: &mut iov,
            vm_pkt_iovcnt: 1,
            vm_pkt_size: 0,
            vm_flags: 0,
        };

        let mut pktcnt: c_int = 1;

        // Safety: vmnet_read is safe when called with valid parameters.
        let status = unsafe { vmnet_read(self.interface, &mut packet, &mut pktcnt) };

        if !status.is_success() {
            if status == VmnetReturnT::BufferExhausted {
                // No packets available.
                return Ok(0);
            }
            return Err(NetError::io(std::io::Error::new(
                std::io::ErrorKind::Other,
                status.message(),
            )));
        }

        if pktcnt == 0 {
            return Ok(0);
        }

        Ok(packet.vm_pkt_size as usize)
    }

    /// Writes a packet to the vmnet interface.
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails.
    pub fn write_packet(&self, data: &[u8]) -> Result<usize> {
        if !self.is_running() {
            return Err(NetError::config("interface not running".to_string()));
        }

        if data.len() > self.max_packet_size {
            return Err(NetError::config(format!(
                "packet too large: {} > {}",
                data.len(),
                self.max_packet_size
            )));
        }

        // Create iovec for the data.
        // Note: vmnet_write expects mutable pointers even though it doesn't modify the data.
        let mut iov = iovec {
            iov_base: data.as_ptr() as *mut _,
            iov_len: data.len(),
        };

        // Create packet descriptor.
        let mut packet = VmnetPacket {
            vm_pkt_iov: &mut iov,
            vm_pkt_iovcnt: 1,
            vm_pkt_size: data.len() as u32,
            vm_flags: 0,
        };

        let mut pktcnt: c_int = 1;

        // Safety: vmnet_write is safe when called with valid parameters.
        let status = unsafe { vmnet_write(self.interface, &mut packet, &mut pktcnt) };

        if !status.is_success() {
            return Err(NetError::io(std::io::Error::new(
                std::io::ErrorKind::Other,
                status.message(),
            )));
        }

        if pktcnt == 0 {
            return Err(NetError::io(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "no packets written",
            )));
        }

        Ok(data.len())
    }

    /// Stops the vmnet interface.
    pub fn stop(&self) {
        if self.running.swap(false, Ordering::AcqRel) {
            // Safety: vmnet_stop_interface is safe when called with valid parameters.
            unsafe {
                vmnet_stop_interface(self.interface, self.queue, ptr::null());
            }
        }
    }
}

impl NetworkBackend for Vmnet {
    fn send(&self, data: &[u8]) -> Result<usize> {
        self.write_packet(data)
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        self.read_packet(buf)
    }

    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }
}

impl Drop for Vmnet {
    fn drop(&mut self) {
        self.stop();

        // Release the dispatch queue.
        // Safety: dispatch_release is safe for a valid queue.
        unsafe {
            dispatch_release(self.queue as *mut _);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_vmnet_config_default() {
        let config = VmnetConfig::default();
        assert_eq!(config.mode, VmnetMode::Shared);
        assert_eq!(config.mtu, DEFAULT_MTU);
        assert!(config.mac.is_none());
        assert!(config.bridge_interface.is_none());
        assert!(config.dhcp_start.is_none());
        assert!(config.dhcp_end.is_none());
        assert!(config.subnet_mask.is_none());
        assert!(!config.isolated);
    }

    #[test]
    fn test_vmnet_config_builders() {
        let config = VmnetConfig::shared()
            .with_mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
            .with_mtu(9000);

        assert_eq!(config.mode, VmnetMode::Shared);
        assert_eq!(config.mac, Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]));
        assert_eq!(config.mtu, 9000);

        let config = VmnetConfig::host_only().with_isolation(true);
        assert_eq!(config.mode, VmnetMode::HostOnly);
        assert!(config.isolated);

        let config = VmnetConfig::bridged("en0");
        assert_eq!(config.mode, VmnetMode::Bridged);
        assert_eq!(config.bridge_interface, Some("en0".to_string()));
    }

    #[test]
    fn test_vmnet_config_dhcp_range() {
        let config = VmnetConfig::shared()
            .with_dhcp_range(
                Ipv4Addr::new(192, 168, 64, 2),
                Ipv4Addr::new(192, 168, 64, 254),
            )
            .with_subnet_mask(Ipv4Addr::new(255, 255, 255, 0));

        assert_eq!(config.dhcp_start, Some(Ipv4Addr::new(192, 168, 64, 2)));
        assert_eq!(config.dhcp_end, Some(Ipv4Addr::new(192, 168, 64, 254)));
        assert_eq!(config.subnet_mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
    }

    #[test]
    fn test_vmnet_config_jumbo_frame() {
        let config = VmnetConfig::shared().with_mtu(9000);
        assert_eq!(config.mtu, 9000);
    }

    #[test]
    fn test_vmnet_mode_conversion() {
        assert_eq!(
            VmnetOperatingMode::from(VmnetMode::Shared),
            VmnetOperatingMode::Shared
        );
        assert_eq!(
            VmnetOperatingMode::from(VmnetMode::HostOnly),
            VmnetOperatingMode::Host
        );
        assert_eq!(
            VmnetOperatingMode::from(VmnetMode::Bridged),
            VmnetOperatingMode::Bridged
        );
    }

    #[test]
    fn test_vmnet_mode_default() {
        assert_eq!(VmnetMode::default(), VmnetMode::Shared);
    }

    #[test]
    fn test_vmnet_config_clone() {
        let config = VmnetConfig::shared()
            .with_mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
            .with_mtu(1500);
        let cloned = config.clone();

        assert_eq!(config.mode, cloned.mode);
        assert_eq!(config.mac, cloned.mac);
        assert_eq!(config.mtu, cloned.mtu);
    }

    // Integration tests that require root/entitlements.
    // Run with: sudo cargo test -p arcbox-net vmnet_integration -- --ignored
    #[test]
    #[ignore]
    fn test_vmnet_create_shared() {
        let vmnet = Vmnet::new_shared();
        assert!(
            vmnet.is_ok(),
            "Failed to create shared vmnet: {:?}",
            vmnet.err()
        );

        let vmnet = vmnet.unwrap();
        assert!(vmnet.is_running());
        assert!(vmnet.max_packet_size() > 0);
        assert_eq!(vmnet.mtu(), DEFAULT_MTU);
    }

    #[test]
    #[ignore]
    fn test_vmnet_create_host_only() {
        let vmnet = Vmnet::new_host_only();
        assert!(
            vmnet.is_ok(),
            "Failed to create host-only vmnet: {:?}",
            vmnet.err()
        );

        let vmnet = vmnet.unwrap();
        assert!(vmnet.is_running());
    }

    #[test]
    #[ignore]
    fn test_vmnet_stop() {
        let vmnet = Vmnet::new_shared().expect("Failed to create vmnet");
        assert!(vmnet.is_running());

        vmnet.stop();
        assert!(!vmnet.is_running());
    }

    #[test]
    #[ignore]
    fn test_vmnet_read_no_data() {
        let vmnet = Vmnet::new_shared().expect("Failed to create vmnet");
        let mut buf = [0u8; 1500];

        // Reading with no data should return 0 or BufferExhausted.
        let result = vmnet.read_packet(&mut buf);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    #[ignore]
    fn test_vmnet_write_packet() {
        let vmnet = Vmnet::new_shared().expect("Failed to create vmnet");

        // Create a minimal Ethernet frame (14 bytes header + payload).
        let mut packet = vec![0u8; 64];
        // Destination MAC (broadcast).
        packet[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // Source MAC.
        packet[6..12].copy_from_slice(&vmnet.mac());
        // EtherType (0x0800 = IPv4).
        packet[12..14].copy_from_slice(&[0x08, 0x00]);

        let result = vmnet.write_packet(&packet);
        assert!(result.is_ok(), "Failed to write packet: {:?}", result.err());
    }

    #[test]
    #[ignore]
    fn test_vmnet_custom_mac() {
        let mac = [0x02, 0x00, 0x00, 0x12, 0x34, 0x56];
        let config = VmnetConfig::shared().with_mac(mac);
        let vmnet = Vmnet::new(config).expect("Failed to create vmnet");

        assert_eq!(vmnet.mac(), mac);
    }
}
