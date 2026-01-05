//! VirtIO filesystem device (virtio-fs).
//!
//! This implements the high-performance shared filesystem using virtiofs
//! protocol for host-guest file sharing.

use crate::{error::Result, VirtioDevice, VirtioDeviceId};

/// Filesystem device configuration.
#[derive(Debug, Clone)]
pub struct FsConfig {
    /// Filesystem tag (mount identifier).
    pub tag: String,
    /// Number of request queues.
    pub num_queues: u32,
    /// Queue size.
    pub queue_size: u16,
    /// Shared directory path on host.
    pub shared_dir: String,
}

impl Default for FsConfig {
    fn default() -> Self {
        Self {
            tag: "arcbox".to_string(),
            num_queues: 1,
            queue_size: 1024,
            shared_dir: String::new(),
        }
    }
}

/// VirtIO filesystem device.
///
/// Provides high-performance file sharing between host and guest using
/// the FUSE protocol over virtio transport.
pub struct VirtioFs {
    config: FsConfig,
    features: u64,
    acked_features: u64,
}

impl VirtioFs {
    /// Feature: Notification.
    pub const FEATURE_NOTIFICATION: u64 = 1 << 0;

    /// Creates a new filesystem device.
    #[must_use]
    pub fn new(config: FsConfig) -> Self {
        Self {
            config,
            features: 0,
            acked_features: 0,
        }
    }

    /// Returns the filesystem tag.
    #[must_use]
    pub fn tag(&self) -> &str {
        &self.config.tag
    }

    /// Returns the shared directory path.
    #[must_use]
    pub fn shared_dir(&self) -> &str {
        &self.config.shared_dir
    }
}

impl VirtioDevice for VirtioFs {
    fn device_id(&self) -> VirtioDeviceId {
        VirtioDeviceId::Fs
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, features: u64) {
        self.acked_features = self.features & features;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Configuration space layout:
        // offset 0: tag (36 bytes, null-padded)
        // offset 36: num_request_queues (u32)
        let mut config_data = vec![0u8; 40];

        // Copy tag (up to 36 bytes)
        let tag_bytes = self.config.tag.as_bytes();
        let tag_len = tag_bytes.len().min(36);
        config_data[..tag_len].copy_from_slice(&tag_bytes[..tag_len]);

        // Number of request queues
        config_data[36..40].copy_from_slice(&self.config.num_queues.to_le_bytes());

        let offset = offset as usize;
        let len = data.len().min(config_data.len().saturating_sub(offset));
        if len > 0 {
            data[..len].copy_from_slice(&config_data[offset..offset + len]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // Filesystem config is read-only
    }

    fn activate(&mut self) -> Result<()> {
        // TODO: Initialize FUSE session
        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // FsConfig Tests
    // ==========================================================================

    #[test]
    fn test_fs_config_default() {
        let config = FsConfig::default();
        assert_eq!(config.tag, "arcbox");
        assert_eq!(config.num_queues, 1);
        assert_eq!(config.queue_size, 1024);
        assert!(config.shared_dir.is_empty());
    }

    #[test]
    fn test_fs_config_custom() {
        let config = FsConfig {
            tag: "myfs".to_string(),
            num_queues: 4,
            queue_size: 256,
            shared_dir: "/home/user/shared".to_string(),
        };
        assert_eq!(config.tag, "myfs");
        assert_eq!(config.num_queues, 4);
        assert_eq!(config.queue_size, 256);
        assert_eq!(config.shared_dir, "/home/user/shared");
    }

    #[test]
    fn test_fs_config_clone() {
        let config = FsConfig {
            tag: "test".to_string(),
            num_queues: 2,
            queue_size: 512,
            shared_dir: "/tmp".to_string(),
        };
        let cloned = config.clone();
        assert_eq!(cloned.tag, "test");
        assert_eq!(cloned.num_queues, 2);
    }

    // ==========================================================================
    // VirtioFs Tests
    // ==========================================================================

    #[test]
    fn test_fs_new() {
        let fs = VirtioFs::new(FsConfig::default());
        assert_eq!(fs.tag(), "arcbox");
        assert!(fs.shared_dir().is_empty());
    }

    #[test]
    fn test_fs_device_id() {
        let fs = VirtioFs::new(FsConfig::default());
        assert_eq!(fs.device_id(), VirtioDeviceId::Fs);
    }

    #[test]
    fn test_fs_features() {
        let fs = VirtioFs::new(FsConfig::default());
        // Default has no features
        assert_eq!(fs.features(), 0);
    }

    #[test]
    fn test_fs_ack_features() {
        let mut fs = VirtioFs::new(FsConfig::default());
        fs.ack_features(VirtioFs::FEATURE_NOTIFICATION);
        // Since feature is not supported, acked should be 0
        assert_eq!(fs.acked_features, 0);
    }

    #[test]
    fn test_fs_read_config_tag() {
        let config = FsConfig {
            tag: "testfs".to_string(),
            ..Default::default()
        };
        let fs = VirtioFs::new(config);

        let mut data = [0u8; 36];
        fs.read_config(0, &mut data);

        // Tag should be at beginning
        assert_eq!(&data[0..6], b"testfs");
        // Rest should be null-padded
        assert!(data[6..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_fs_read_config_tag_long() {
        let config = FsConfig {
            tag: "a".repeat(50), // Longer than 36 bytes
            ..Default::default()
        };
        let fs = VirtioFs::new(config);

        let mut data = [0u8; 36];
        fs.read_config(0, &mut data);

        // Should be truncated to 36 bytes
        assert!(data.iter().all(|&b| b == b'a'));
    }

    #[test]
    fn test_fs_read_config_num_queues() {
        let config = FsConfig {
            num_queues: 4,
            ..Default::default()
        };
        let fs = VirtioFs::new(config);

        let mut data = [0u8; 4];
        fs.read_config(36, &mut data);

        let num_queues = u32::from_le_bytes(data);
        assert_eq!(num_queues, 4);
    }

    #[test]
    fn test_fs_read_config_partial() {
        let fs = VirtioFs::new(FsConfig::default());

        let mut data = [0u8; 10];
        fs.read_config(35, &mut data);

        // Should read last byte of tag + first 4 bytes of num_queues
        // (or less depending on bounds)
    }

    #[test]
    fn test_fs_read_config_beyond() {
        let fs = VirtioFs::new(FsConfig::default());

        let mut data = [0xFFu8; 4];
        fs.read_config(100, &mut data);

        // Should not crash
    }

    #[test]
    fn test_fs_write_config_noop() {
        let config = FsConfig {
            tag: "original".to_string(),
            ..Default::default()
        };
        let mut fs = VirtioFs::new(config);

        fs.write_config(0, b"newvalue");

        // Tag should be unchanged
        assert_eq!(fs.tag(), "original");
    }

    #[test]
    fn test_fs_activate() {
        let mut fs = VirtioFs::new(FsConfig::default());
        assert!(fs.activate().is_ok());
    }

    #[test]
    fn test_fs_reset() {
        let mut fs = VirtioFs::new(FsConfig::default());
        fs.acked_features = 0xFF;

        fs.reset();

        assert_eq!(fs.acked_features, 0);
    }

    #[test]
    fn test_fs_tag_accessor() {
        let config = FsConfig {
            tag: "mytag".to_string(),
            ..Default::default()
        };
        let fs = VirtioFs::new(config);
        assert_eq!(fs.tag(), "mytag");
    }

    #[test]
    fn test_fs_shared_dir_accessor() {
        let config = FsConfig {
            shared_dir: "/mnt/share".to_string(),
            ..Default::default()
        };
        let fs = VirtioFs::new(config);
        assert_eq!(fs.shared_dir(), "/mnt/share");
    }

    // ==========================================================================
    // Constants Tests
    // ==========================================================================

    #[test]
    fn test_fs_feature_constants() {
        assert_eq!(VirtioFs::FEATURE_NOTIFICATION, 1 << 0);
    }
}
