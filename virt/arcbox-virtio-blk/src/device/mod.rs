//! `VirtioBlock` device — request dispatch, queue handling, `VirtioDevice` impl.

mod io;
mod virtio_device;

#[cfg(test)]
mod tests;

use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use arcbox_virtio_core::error::{Result, VirtioError};
use arcbox_virtio_core::queue::VirtQueue;
use arcbox_virtio_core::virtio_bindings;

use crate::request::BlockConfig;

/// `VirtIO` block device.
pub struct VirtioBlock {
    config: BlockConfig,
    features: u64,
    acked_features: u64,
    /// Backing file handle (for flush/close).
    file: Option<Arc<RwLock<File>>>,
    /// Raw fd for pread/pwrite — avoids seek+lock on every I/O.
    raw_fd: Option<std::os::unix::io::RawFd>,
    /// Request queue.
    queue: Option<VirtQueue>,
    /// Device ID string.
    device_id: String,
    /// Last-seen available ring index for guest-memory queue processing.
    last_avail_idx: u16,
}

impl VirtioBlock {
    // Feature bits sourced from `virtio_bindings::virtio_blk`.
    // The crate exports bit *positions*, so we shift 1 left by that position.

    /// Feature: Maximum segment size.
    pub const FEATURE_SIZE_MAX: u64 = 1 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_SIZE_MAX;
    /// Feature: Maximum number of segments.
    pub const FEATURE_SEG_MAX: u64 = 1 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_SEG_MAX;
    /// Feature: Disk geometry.
    pub const FEATURE_GEOMETRY: u64 = 1 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_GEOMETRY;
    /// Feature: Read-only.
    pub const FEATURE_RO: u64 = 1 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_RO;
    /// Feature: Block size.
    pub const FEATURE_BLK_SIZE: u64 = 1 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_BLK_SIZE;
    /// Feature: Flush command.
    pub const FEATURE_FLUSH: u64 = 1 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_FLUSH;
    /// Feature: Topology.
    pub const FEATURE_TOPOLOGY: u64 = 1 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_TOPOLOGY;
    /// Feature: Configuration writeback.
    pub const FEATURE_CONFIG_WCE: u64 = 1 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_CONFIG_WCE;
    /// Feature: Discard command.
    pub const FEATURE_DISCARD: u64 = 1 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_DISCARD;
    /// Feature: Write zeroes command.
    pub const FEATURE_WRITE_ZEROES: u64 =
        1 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_WRITE_ZEROES;
    /// Feature: Multiple request queues.
    pub const FEATURE_MQ: u64 = 1 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_MQ;
    /// `VirtIO` 1.0 feature.
    pub const FEATURE_VERSION_1: u64 = 1 << virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;

    /// Largest range a single WRITE_ZEROES request may cover, in 512-byte
    /// sectors. Capped at 1 MiB so each range fits in one bounded zero-buffer
    /// allocation + one `pwrite` syscall. The guest splits larger requests.
    pub const MAX_WRITE_ZEROES_SECTORS: u32 = 2048;

    /// Largest range a single DISCARD request may cover. Since DISCARD is a
    /// spec-compliant no-op on our backend (advisory hint), we accept any
    /// reasonable cap — 16 MiB keeps the guest from fragmenting `fstrim`.
    pub const MAX_DISCARD_SECTORS: u32 = 32768;

    /// Creates a new block device.
    #[must_use]
    pub fn new(config: BlockConfig) -> Self {
        let mut features = Self::FEATURE_SIZE_MAX
            | Self::FEATURE_SEG_MAX
            | Self::FEATURE_BLK_SIZE
            | Self::FEATURE_FLUSH
            | Self::FEATURE_VERSION_1
            | arcbox_virtio_core::queue::VIRTIO_F_EVENT_IDX;

        if config.read_only {
            features |= Self::FEATURE_RO;
        } else {
            // DISCARD and WRITE_ZEROES both mutate the backing file, so only a
            // writable device advertises them. (A read-only device that
            // advertised DISCARD would force the handler to error on requests
            // it cannot honor.)
            features |= Self::FEATURE_DISCARD | Self::FEATURE_WRITE_ZEROES;
        }
        if config.num_queues > 1 {
            features |= Self::FEATURE_MQ;
        }

        let device_id = format!(
            "arcbox-blk-{}",
            config
                .path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
        );

        Self {
            config,
            features,
            acked_features: 0,
            file: None,
            raw_fd: None,
            queue: None,
            device_id,
            last_avail_idx: 0,
        }
    }

    /// Creates a new block device from a file path.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or its size cannot be determined.
    pub fn from_path(path: impl Into<PathBuf>, read_only: bool) -> Result<Self> {
        let path = path.into();

        let file = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .open(&path)
            .map_err(|e| VirtioError::Io(format!("Failed to open {}: {}", path.display(), e)))?;

        let metadata = file
            .metadata()
            .map_err(|e| VirtioError::Io(format!("Failed to get metadata: {e}")))?;

        let capacity = metadata.len() / 512;

        let config = BlockConfig {
            capacity,
            blk_size: 512,
            path: path.clone(),
            read_only,
            num_queues: 1,
        };

        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();

        // Disable page cache on macOS for large disk images.
        #[cfg(target_os = "macos")]
        // SAFETY: F_NOCACHE on a fd we own; ignored on failure.
        unsafe {
            libc::fcntl(fd, libc::F_NOCACHE, 1);
        }

        let mut device = Self::new(config);
        device.raw_fd = Some(fd);
        device.file = Some(Arc::new(RwLock::new(file)));

        tracing::info!(
            "Created block device from {}: capacity={} sectors ({} bytes)",
            path.display(),
            capacity,
            capacity * 512
        );

        Ok(device)
    }

    /// Returns the disk capacity in bytes.
    #[must_use]
    pub fn capacity_bytes(&self) -> u64 {
        self.config.capacity * u64::from(self.config.blk_size)
    }

    /// Returns the raw fd for pread/pwrite (if activated).
    #[must_use]
    pub fn raw_fd(&self) -> Option<std::os::unix::io::RawFd> {
        self.raw_fd
    }

    /// Returns the block size in bytes.
    #[must_use]
    pub fn blk_size(&self) -> u32 {
        self.config.blk_size
    }

    /// Returns true if the device is read-only.
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        self.config.read_only
    }

    /// Returns the device ID string.
    #[must_use]
    pub fn device_id_string(&self) -> &str {
        &self.device_id
    }

    /// Returns the number of request queues.
    #[must_use]
    pub fn num_queues(&self) -> u16 {
        self.config.num_queues
    }

    /// Sets the number of request queues (must call before activate).
    pub fn set_num_queues(&mut self, n: u16) {
        self.config.num_queues = n.max(1);
        if self.config.num_queues > 1 {
            self.features |= Self::FEATURE_MQ;
        }
    }
}
