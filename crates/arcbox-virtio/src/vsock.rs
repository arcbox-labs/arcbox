//! VirtIO socket device (virtio-vsock).
//!
//! Provides socket communication between host and guest without requiring
//! network configuration.

use crate::{error::Result, VirtioDevice, VirtioDeviceId};

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
        }
    }

    /// Returns the guest CID.
    #[must_use]
    pub fn guest_cid(&self) -> u64 {
        self.config.guest_cid
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
        // TODO: Initialize vsock backend
        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
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
        let config = VsockConfig { guest_cid: 0x12345678 };
        let vsock = VirtioVsock::new(config);

        let mut data = [0u8; 8];
        vsock.read_config(0, &mut data);

        let cid = u64::from_le_bytes(data);
        assert_eq!(cid, 0x12345678);
    }

    #[test]
    fn test_vsock_read_config_partial() {
        let config = VsockConfig { guest_cid: 0xDEADBEEF };
        let vsock = VirtioVsock::new(config);

        // Read only first 4 bytes
        let mut data = [0u8; 4];
        vsock.read_config(0, &mut data);

        let low_bytes = u32::from_le_bytes(data);
        assert_eq!(low_bytes, 0xDEADBEEF);
    }

    #[test]
    fn test_vsock_read_config_offset() {
        let config = VsockConfig { guest_cid: 0xAABBCCDD_11223344 };
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
}
