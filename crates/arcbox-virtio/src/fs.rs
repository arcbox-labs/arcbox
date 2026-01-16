//! VirtIO filesystem device (virtio-fs).
//!
//! This implements the high-performance shared filesystem using virtiofs
//! protocol for host-guest file sharing.
//!
//! # Architecture
//!
//! ```text
//! Guest Driver (virtio-fs)
//!       │
//!       ▼ (virtqueue)
//! ┌─────────────────────────┐
//! │      VirtioFs           │
//! │  ┌─────────────────┐   │
//! │  │   FuseSession   │   │
//! │  │  - INIT state   │   │
//! │  │  - features     │   │
//! │  └─────────────────┘   │
//! └───────────┬─────────────┘
//!             │ dispatch
//!             ▼
//!     FuseRequestHandler
//!       (implemented by arcbox-fs)
//! ```

use crate::error::{Result, VirtioError};
use crate::queue::VirtQueue;
use crate::{VirtioDevice, VirtioDeviceId};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

// ============================================================================
// FUSE Constants
// ============================================================================

/// FUSE kernel protocol major version.
pub const FUSE_KERNEL_VERSION: u32 = 7;

/// FUSE kernel protocol minor version.
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 38;

// FUSE init flags
pub const FUSE_ASYNC_READ: u32 = 1 << 0;
pub const FUSE_BIG_WRITES: u32 = 1 << 5;
pub const FUSE_WRITEBACK_CACHE: u32 = 1 << 16;
pub const FUSE_PARALLEL_DIROPS: u32 = 1 << 18;
pub const FUSE_CACHE_SYMLINKS: u32 = 1 << 23;

/// Default max readahead size (128 KB).
pub const DEFAULT_MAX_READAHEAD: u32 = 128 * 1024;

/// Default max write size (128 KB).
pub const DEFAULT_MAX_WRITE: u32 = 128 * 1024;

/// Default max pages per request.
pub const DEFAULT_MAX_PAGES: u16 = 32;

// ============================================================================
// Traits
// ============================================================================

/// Trait for handling FUSE requests.
///
/// This trait is implemented by `arcbox-fs::FsServer` to process FUSE
/// filesystem operations. The `VirtioFs` device dispatches requests to
/// this handler.
///
/// # Example
///
/// ```ignore
/// use arcbox_virtio::fs::{FuseRequestHandler, FuseRequest, FuseResponse};
///
/// struct MyFsHandler;
///
/// impl FuseRequestHandler for MyFsHandler {
///     fn handle_request(&self, request: &FuseRequest) -> FuseResponse {
///         // Process FUSE request and return response
///         FuseResponse::new(request.unique(), vec![])
///     }
/// }
/// ```
pub trait FuseRequestHandler: Send + Sync {
    /// Handles a FUSE request and returns the response.
    ///
    /// The request contains the raw FUSE protocol bytes from the guest.
    /// The handler should parse, process, and return the response bytes.
    fn handle_request(&self, request: &[u8]) -> Result<Vec<u8>>;

    /// Called when the FUSE session is initialized.
    ///
    /// This is invoked after the FUSE_INIT handshake completes successfully.
    fn on_init(&self, _session: &FuseSession) {}

    /// Called when the FUSE session is destroyed.
    fn on_destroy(&self) {}
}

// ============================================================================
// FUSE Request/Response Types
// ============================================================================

/// FUSE request from guest.
#[derive(Debug)]
pub struct FuseRequest<'a> {
    /// Raw request data.
    data: &'a [u8],
}

impl<'a> FuseRequest<'a> {
    /// Creates a new FUSE request from raw bytes.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Returns the raw request data.
    #[must_use]
    pub const fn data(&self) -> &[u8] {
        self.data
    }

    /// Returns the request length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the request is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Parses the opcode from the request header.
    ///
    /// Returns None if the request is too small.
    #[must_use]
    pub fn opcode(&self) -> Option<u32> {
        if self.data.len() < 8 {
            return None;
        }
        Some(u32::from_le_bytes([
            self.data[4],
            self.data[5],
            self.data[6],
            self.data[7],
        ]))
    }

    /// Parses the unique ID from the request header.
    #[must_use]
    pub fn unique(&self) -> Option<u64> {
        if self.data.len() < 16 {
            return None;
        }
        Some(u64::from_le_bytes([
            self.data[8],
            self.data[9],
            self.data[10],
            self.data[11],
            self.data[12],
            self.data[13],
            self.data[14],
            self.data[15],
        ]))
    }
}

/// FUSE response to guest.
#[derive(Debug)]
pub struct FuseResponse {
    /// Response data.
    data: Vec<u8>,
}

impl FuseResponse {
    /// Creates a new FUSE response.
    #[must_use]
    pub fn new(unique: u64, payload: Vec<u8>) -> Self {
        let len = (16 + payload.len()) as u32;
        let mut data = Vec::with_capacity(len as usize);

        // Write header
        data.extend_from_slice(&len.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes()); // error = 0
        data.extend_from_slice(&unique.to_le_bytes());

        // Write payload
        data.extend_from_slice(&payload);

        Self { data }
    }

    /// Creates an error response.
    #[must_use]
    pub fn error(unique: u64, errno: i32) -> Self {
        let len = 16u32;
        let mut data = Vec::with_capacity(len as usize);

        data.extend_from_slice(&len.to_le_bytes());
        data.extend_from_slice(&(-errno).to_le_bytes());
        data.extend_from_slice(&unique.to_le_bytes());

        Self { data }
    }

    /// Returns the response data.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Consumes the response and returns the data.
    #[must_use]
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

// ============================================================================
// FUSE Session
// ============================================================================

/// FUSE session state.
///
/// Manages the FUSE protocol session including initialization handshake
/// and feature negotiation.
#[derive(Debug)]
pub struct FuseSession {
    /// Whether FUSE_INIT has been received and processed.
    initialized: AtomicBool,
    /// Negotiated protocol major version.
    major: u32,
    /// Negotiated protocol minor version.
    minor: u32,
    /// Negotiated flags.
    flags: u32,
    /// Maximum readahead size.
    max_readahead: u32,
    /// Maximum write size.
    max_write: u32,
    /// Maximum pages per request.
    max_pages: u16,
}

impl FuseSession {
    /// Creates a new FUSE session with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            major: FUSE_KERNEL_VERSION,
            minor: FUSE_KERNEL_MINOR_VERSION,
            flags: FUSE_ASYNC_READ | FUSE_BIG_WRITES | FUSE_WRITEBACK_CACHE,
            max_readahead: DEFAULT_MAX_READAHEAD,
            max_write: DEFAULT_MAX_WRITE,
            max_pages: DEFAULT_MAX_PAGES,
        }
    }

    /// Returns whether the session is initialized.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    /// Returns the negotiated major version.
    #[must_use]
    pub const fn major(&self) -> u32 {
        self.major
    }

    /// Returns the negotiated minor version.
    #[must_use]
    pub const fn minor(&self) -> u32 {
        self.minor
    }

    /// Returns the negotiated flags.
    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns the maximum readahead size.
    #[must_use]
    pub const fn max_readahead(&self) -> u32 {
        self.max_readahead
    }

    /// Returns the maximum write size.
    #[must_use]
    pub const fn max_write(&self) -> u32 {
        self.max_write
    }

    /// Returns the maximum pages per request.
    #[must_use]
    pub const fn max_pages(&self) -> u16 {
        self.max_pages
    }

    /// Handles FUSE_INIT request and returns the response.
    ///
    /// This negotiates the protocol version and features with the guest driver.
    pub fn handle_init(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        // FUSE_INIT request body starts after 40-byte header
        // Layout: major(4) + minor(4) + max_readahead(4) + flags(4)
        if request.len() < 56 {
            return Err(VirtioError::DeviceError {
                device: "fs".to_string(),
                message: "FUSE_INIT request too small".to_string(),
            });
        }

        let body = &request[40..];
        let guest_major = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
        let guest_minor = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
        let guest_max_readahead = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
        let guest_flags = u32::from_le_bytes([body[12], body[13], body[14], body[15]]);

        tracing::debug!(
            "FUSE_INIT: guest version {}.{}, max_readahead={}, flags={:#x}",
            guest_major,
            guest_minor,
            guest_max_readahead,
            guest_flags
        );

        // Check version compatibility
        if guest_major < FUSE_KERNEL_VERSION {
            return Err(VirtioError::DeviceError {
                device: "fs".to_string(),
                message: format!(
                    "FUSE version mismatch: guest {}.{} < required {}.{}",
                    guest_major, guest_minor, FUSE_KERNEL_VERSION, FUSE_KERNEL_MINOR_VERSION
                ),
            });
        }

        // Negotiate features
        self.major = FUSE_KERNEL_VERSION;
        self.minor = FUSE_KERNEL_MINOR_VERSION;
        self.max_readahead = guest_max_readahead.min(DEFAULT_MAX_READAHEAD);
        self.flags &= guest_flags; // Only enable mutually supported flags

        // Build FUSE_INIT response
        // Layout: major(4) + minor(4) + max_readahead(4) + flags(4) +
        //         max_background(2) + congestion_threshold(2) + max_write(4) +
        //         time_gran(4) + max_pages(2) + padding(2) + unused(32)
        let mut response = Vec::with_capacity(80);

        // Response header (16 bytes)
        let unique = u64::from_le_bytes([
            request[8],
            request[9],
            request[10],
            request[11],
            request[12],
            request[13],
            request[14],
            request[15],
        ]);
        let len = 80u32;
        response.extend_from_slice(&len.to_le_bytes());
        response.extend_from_slice(&0i32.to_le_bytes()); // error = 0
        response.extend_from_slice(&unique.to_le_bytes());

        // FUSE_INIT response body (64 bytes)
        response.extend_from_slice(&self.major.to_le_bytes());
        response.extend_from_slice(&self.minor.to_le_bytes());
        response.extend_from_slice(&self.max_readahead.to_le_bytes());
        response.extend_from_slice(&self.flags.to_le_bytes());
        response.extend_from_slice(&16u16.to_le_bytes()); // max_background
        response.extend_from_slice(&12u16.to_le_bytes()); // congestion_threshold
        response.extend_from_slice(&self.max_write.to_le_bytes());
        response.extend_from_slice(&1u32.to_le_bytes()); // time_gran (1 ns)
        response.extend_from_slice(&self.max_pages.to_le_bytes());
        response.extend_from_slice(&0u16.to_le_bytes()); // padding
        response.extend_from_slice(&[0u8; 32]); // unused

        self.initialized.store(true, Ordering::Release);

        tracing::info!(
            "FUSE session initialized: version {}.{}, flags={:#x}, max_write={}",
            self.major,
            self.minor,
            self.flags,
            self.max_write
        );

        Ok(response)
    }

    /// Resets the session state.
    pub fn reset(&mut self) {
        self.initialized.store(false, Ordering::Release);
        self.major = FUSE_KERNEL_VERSION;
        self.minor = FUSE_KERNEL_MINOR_VERSION;
        self.flags = FUSE_ASYNC_READ | FUSE_BIG_WRITES | FUSE_WRITEBACK_CACHE;
        self.max_readahead = DEFAULT_MAX_READAHEAD;
        self.max_write = DEFAULT_MAX_WRITE;
        self.max_pages = DEFAULT_MAX_PAGES;
    }
}

impl Default for FuseSession {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Filesystem Configuration
// ============================================================================

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

// ============================================================================
// VirtIO Filesystem Device
// ============================================================================

/// VirtIO filesystem device.
///
/// Provides high-performance file sharing between host and guest using
/// the FUSE protocol over virtio transport.
pub struct VirtioFs {
    config: FsConfig,
    features: u64,
    acked_features: u64,
    /// FUSE session state.
    session: FuseSession,
    /// Request handler (provided by arcbox-fs).
    handler: Option<Arc<dyn FuseRequestHandler>>,
    /// Request queues for FUSE traffic.
    request_queues: Vec<VirtQueue>,
    /// Whether the device is activated.
    activated: bool,
}

impl VirtioFs {
    /// Feature: Notification.
    pub const FEATURE_NOTIFICATION: u64 = 1 << 0;

    /// FUSE opcode for INIT.
    const FUSE_INIT: u32 = 26;

    /// FUSE opcode for DESTROY.
    const FUSE_DESTROY: u32 = 38;

    /// Creates a new filesystem device.
    #[must_use]
    pub fn new(config: FsConfig) -> Self {
        Self {
            config,
            features: 0,
            acked_features: 0,
            session: FuseSession::new(),
            handler: None,
            request_queues: Vec::new(),
            activated: false,
        }
    }

    /// Creates a new filesystem device with a request handler.
    #[must_use]
    pub fn with_handler(config: FsConfig, handler: Arc<dyn FuseRequestHandler>) -> Self {
        Self {
            config,
            features: 0,
            acked_features: 0,
            session: FuseSession::new(),
            handler: Some(handler),
            request_queues: Vec::new(),
            activated: false,
        }
    }

    /// Sets the request handler.
    pub fn set_handler(&mut self, handler: Arc<dyn FuseRequestHandler>) {
        self.handler = Some(handler);
    }

    /// Returns a reference to the request handler.
    #[must_use]
    pub fn handler(&self) -> Option<&Arc<dyn FuseRequestHandler>> {
        self.handler.as_ref()
    }

    /// Returns a reference to the FUSE session.
    #[must_use]
    pub const fn session(&self) -> &FuseSession {
        &self.session
    }

    /// Returns whether the device is activated.
    #[must_use]
    pub const fn is_activated(&self) -> bool {
        self.activated
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

    /// Returns the number of queues.
    #[must_use]
    pub const fn num_queues(&self) -> u32 {
        self.config.num_queues
    }

    /// Returns the queue size.
    #[must_use]
    pub const fn queue_size(&self) -> u16 {
        self.config.queue_size
    }

    /// Processes a FUSE request and returns the response.
    ///
    /// This method is called by the VMM when a request is received from
    /// the guest via the virtqueue.
    ///
    /// # Flow
    ///
    /// 1. Parse request opcode
    /// 2. If FUSE_INIT: handle initialization handshake
    /// 3. If FUSE_DESTROY: clean up session
    /// 4. Otherwise: delegate to request handler
    ///
    /// # Errors
    ///
    /// Returns an error if the request cannot be processed.
    pub fn process_request(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        if request.len() < 40 {
            return Err(VirtioError::DeviceError {
                device: "fs".to_string(),
                message: "FUSE request too small".to_string(),
            });
        }

        // Parse opcode from header (offset 4-7)
        let opcode = u32::from_le_bytes([request[4], request[5], request[6], request[7]]);

        // Parse unique ID for error responses
        let unique = u64::from_le_bytes([
            request[8],
            request[9],
            request[10],
            request[11],
            request[12],
            request[13],
            request[14],
            request[15],
        ]);

        match opcode {
            Self::FUSE_INIT => {
                // Handle INIT locally
                let response = self.session.handle_init(request)?;

                // Notify handler of initialization
                if let Some(handler) = &self.handler {
                    handler.on_init(&self.session);
                }

                Ok(response)
            }
            Self::FUSE_DESTROY => {
                // Handle DESTROY
                self.session.reset();

                // Notify handler
                if let Some(handler) = &self.handler {
                    handler.on_destroy();
                }

                // Return empty success response
                Ok(FuseResponse::new(unique, vec![]).into_data())
            }
            _ => {
                // Check if session is initialized
                if !self.session.is_initialized() {
                    tracing::warn!("FUSE request before INIT: opcode={}", opcode);
                    return Ok(FuseResponse::error(unique, libc::EINVAL).into_data());
                }

                // Delegate to handler
                if let Some(handler) = &self.handler {
                    handler.handle_request(request)
                } else {
                    // No handler configured, return ENOSYS
                    Ok(FuseResponse::error(unique, libc::ENOSYS).into_data())
                }
            }
        }
    }

    /// Processes a single request queue and writes responses into guest memory.
    ///
    /// Returns a list of completed descriptor heads and their response lengths.
    pub fn process_queue(
        &mut self,
        queue_index: usize,
        memory: &mut [u8],
    ) -> Result<Vec<(u16, u32)>> {
        // First, collect all pending requests from the queue
        // This releases the borrow on self.request_queues
        let pending_requests = {
            let queue = self.request_queues.get_mut(queue_index).ok_or_else(|| {
                VirtioError::NotReady(format!("request queue {} not available", queue_index))
            })?;

            let mut requests = Vec::new();
            while let Some((head_idx, chain)) = queue.pop_avail() {
                let mut request_data = Vec::new();
                let mut write_buffers = Vec::new();

                for desc in chain {
                    let start = desc.addr as usize;
                    let end = start + desc.len as usize;
                    if end > memory.len() {
                        return Err(VirtioError::InvalidQueue(
                            "descriptor out of bounds".to_string(),
                        ));
                    }

                    if desc.is_write_only() {
                        write_buffers.push((start, desc.len as usize));
                    } else {
                        request_data.extend_from_slice(&memory[start..end]);
                    }
                }

                if write_buffers.is_empty() {
                    return Err(VirtioError::InvalidQueue(
                        "no writable descriptors for response".to_string(),
                    ));
                }

                requests.push((head_idx, request_data, write_buffers));
            }
            requests
        };

        // Now process all requests (self.request_queues borrow is released)
        let mut completions = Vec::new();
        for (head_idx, request_data, write_buffers) in pending_requests {
            let response = self.process_request(&request_data)?;
            let mut remaining = response.as_slice();
            let mut written = 0usize;

            for (start, len) in write_buffers {
                if remaining.is_empty() {
                    break;
                }

                let copy_len = len.min(remaining.len());
                memory[start..start + copy_len].copy_from_slice(&remaining[..copy_len]);
                remaining = &remaining[copy_len..];
                written += copy_len;
            }

            if !remaining.is_empty() {
                return Err(VirtioError::InvalidQueue(
                    "response buffer too small".to_string(),
                ));
            }

            completions.push((head_idx, written as u32));
        }

        Ok(completions)
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
        if self.activated {
            return Ok(());
        }

        // Validate configuration
        if self.config.shared_dir.is_empty() {
            return Err(VirtioError::DeviceError {
                device: "fs".to_string(),
                message: "shared_dir not configured".to_string(),
            });
        }

        if self.config.num_queues == 0 {
            return Err(VirtioError::DeviceError {
                device: "fs".to_string(),
                message: "num_queues must be greater than 0".to_string(),
            });
        }

        // Reset session state for fresh start
        self.session.reset();

        // Create request queues
        let mut queues = Vec::with_capacity(self.config.num_queues as usize);
        for _ in 0..self.config.num_queues {
            queues.push(VirtQueue::new(self.config.queue_size)?);
        }
        self.request_queues = queues;

        // Mark as activated
        // Note: The FUSE_INIT handshake will happen when the guest driver
        // sends the first request through the virtqueue.
        self.activated = true;

        tracing::info!(
            "VirtIO-FS device activated: tag='{}', shared_dir='{}', queues={}",
            self.config.tag,
            self.config.shared_dir,
            self.config.num_queues
        );

        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
        self.session.reset();
        self.activated = false;
        self.request_queues.clear();

        // Notify handler of reset
        if let Some(handler) = &self.handler {
            handler.on_destroy();
        }

        tracing::debug!("VirtIO-FS device reset: tag='{}'", self.config.tag);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::flags;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        let config = FsConfig {
            shared_dir: "/tmp".to_string(),
            ..Default::default()
        };
        let mut fs = VirtioFs::new(config);
        assert!(!fs.is_activated());

        assert!(fs.activate().is_ok());
        assert!(fs.is_activated());
        assert_eq!(fs.request_queues.len(), 1);

        // Activating again should be idempotent
        assert!(fs.activate().is_ok());
    }

    #[test]
    fn test_fs_activate_no_shared_dir() {
        let mut fs = VirtioFs::new(FsConfig::default());
        // Should fail without shared_dir
        assert!(fs.activate().is_err());
    }

    #[test]
    fn test_fs_reset() {
        let config = FsConfig {
            shared_dir: "/tmp".to_string(),
            ..Default::default()
        };
        let mut fs = VirtioFs::new(config);
        fs.acked_features = 0xFF;
        fs.activate().unwrap();

        fs.reset();

        assert_eq!(fs.acked_features, 0);
        assert!(!fs.is_activated());
        assert!(!fs.session.is_initialized());
        assert!(fs.request_queues.is_empty());
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

    // ==========================================================================
    // FuseSession Tests
    // ==========================================================================

    #[test]
    fn test_fuse_session_new() {
        let session = FuseSession::new();
        assert!(!session.is_initialized());
        assert_eq!(session.major(), FUSE_KERNEL_VERSION);
        assert_eq!(session.minor(), FUSE_KERNEL_MINOR_VERSION);
        assert_eq!(session.max_readahead(), DEFAULT_MAX_READAHEAD);
        assert_eq!(session.max_write(), DEFAULT_MAX_WRITE);
        assert_eq!(session.max_pages(), DEFAULT_MAX_PAGES);
    }

    #[test]
    fn test_fuse_session_default() {
        let session = FuseSession::default();
        assert!(!session.is_initialized());
    }

    #[test]
    fn test_fuse_session_reset() {
        let mut session = FuseSession::new();
        session.initialized.store(true, Ordering::SeqCst);

        session.reset();

        assert!(!session.is_initialized());
        assert_eq!(session.major(), FUSE_KERNEL_VERSION);
    }

    #[test]
    fn test_fuse_session_handle_init() {
        let mut session = FuseSession::new();

        // Build a valid FUSE_INIT request
        // Header (40 bytes) + Body (16 bytes minimum)
        let mut request = vec![0u8; 56];

        // Length
        request[0..4].copy_from_slice(&56u32.to_le_bytes());
        // Opcode (FUSE_INIT = 26)
        request[4..8].copy_from_slice(&26u32.to_le_bytes());
        // Unique
        request[8..16].copy_from_slice(&1u64.to_le_bytes());
        // nodeid
        request[16..24].copy_from_slice(&0u64.to_le_bytes());
        // uid
        request[24..28].copy_from_slice(&0u32.to_le_bytes());
        // gid
        request[28..32].copy_from_slice(&0u32.to_le_bytes());
        // pid
        request[32..36].copy_from_slice(&0u32.to_le_bytes());
        // padding
        request[36..40].copy_from_slice(&0u32.to_le_bytes());

        // FUSE_INIT body
        // major
        request[40..44].copy_from_slice(&FUSE_KERNEL_VERSION.to_le_bytes());
        // minor
        request[44..48].copy_from_slice(&FUSE_KERNEL_MINOR_VERSION.to_le_bytes());
        // max_readahead
        request[48..52].copy_from_slice(&(64 * 1024u32).to_le_bytes());
        // flags
        request[52..56].copy_from_slice(&(FUSE_ASYNC_READ | FUSE_BIG_WRITES).to_le_bytes());

        let response = session.handle_init(&request).unwrap();

        assert!(session.is_initialized());
        assert_eq!(response.len(), 80);

        // Check response header
        let resp_len = u32::from_le_bytes([response[0], response[1], response[2], response[3]]);
        let resp_error = i32::from_le_bytes([response[4], response[5], response[6], response[7]]);
        let resp_unique = u64::from_le_bytes([
            response[8],
            response[9],
            response[10],
            response[11],
            response[12],
            response[13],
            response[14],
            response[15],
        ]);

        assert_eq!(resp_len, 80);
        assert_eq!(resp_error, 0);
        assert_eq!(resp_unique, 1);

        // Check negotiated max_readahead (should be min of guest and host)
        assert_eq!(session.max_readahead(), 64 * 1024);
    }

    #[test]
    fn test_fuse_session_handle_init_too_small() {
        let mut session = FuseSession::new();
        let request = vec![0u8; 40]; // Too small (need 56)

        let result = session.handle_init(&request);
        assert!(result.is_err());
    }

    #[test]
    fn test_fuse_session_handle_init_old_version() {
        let mut session = FuseSession::new();

        let mut request = vec![0u8; 56];
        // Header
        request[0..4].copy_from_slice(&56u32.to_le_bytes());
        request[4..8].copy_from_slice(&26u32.to_le_bytes());
        request[8..16].copy_from_slice(&1u64.to_le_bytes());

        // FUSE_INIT body with old version
        request[40..44].copy_from_slice(&5u32.to_le_bytes()); // major = 5 (too old)
        request[44..48].copy_from_slice(&0u32.to_le_bytes());
        request[48..52].copy_from_slice(&(64 * 1024u32).to_le_bytes());
        request[52..56].copy_from_slice(&0u32.to_le_bytes());

        let result = session.handle_init(&request);
        assert!(result.is_err());
    }

    #[test]
    fn test_fs_activate_creates_multiple_queues() {
        let config = FsConfig {
            shared_dir: "/tmp".to_string(),
            num_queues: 2,
            queue_size: 16,
            ..Default::default()
        };
        let mut fs = VirtioFs::new(config);
        fs.activate().unwrap();
        assert_eq!(fs.request_queues.len(), 2);
    }

    #[test]
    fn test_fs_process_queue_roundtrip() {
        struct TestHandler {
            calls: Arc<AtomicUsize>,
        }

        impl FuseRequestHandler for TestHandler {
            fn handle_request(&self, request: &[u8]) -> Result<Vec<u8>> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let unique = u64::from_le_bytes([
                    request[8],
                    request[9],
                    request[10],
                    request[11],
                    request[12],
                    request[13],
                    request[14],
                    request[15],
                ]);
                Ok(FuseResponse::new(unique, b"ok".to_vec()).into_data())
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let handler = Arc::new(TestHandler {
            calls: Arc::clone(&calls),
        });

        let config = FsConfig {
            shared_dir: "/tmp".to_string(),
            queue_size: 16,
            ..Default::default()
        };
        let mut fs = VirtioFs::with_handler(config, handler);
        fs.activate().unwrap();

        let queue = fs.request_queues.get_mut(0).unwrap();
        let mut memory = vec![0u8; 1024];

        // Build FUSE_INIT request
        let mut init_req = vec![0u8; 56];
        init_req[0..4].copy_from_slice(&56u32.to_le_bytes());
        init_req[4..8].copy_from_slice(&VirtioFs::FUSE_INIT.to_le_bytes());
        init_req[8..16].copy_from_slice(&1u64.to_le_bytes());
        init_req[40..44].copy_from_slice(&FUSE_KERNEL_VERSION.to_le_bytes());
        init_req[44..48].copy_from_slice(&FUSE_KERNEL_MINOR_VERSION.to_le_bytes());
        init_req[48..52].copy_from_slice(&(64 * 1024u32).to_le_bytes());
        init_req[52..56].copy_from_slice(&(FUSE_ASYNC_READ | FUSE_BIG_WRITES).to_le_bytes());

        let init_req_offset = 0usize;
        let init_resp_offset = 128usize;
        memory[init_req_offset..init_req_offset + init_req.len()].copy_from_slice(&init_req);

        queue
            .set_descriptor(
                0,
                crate::queue::Descriptor {
                    addr: init_req_offset as u64,
                    len: init_req.len() as u32,
                    flags: flags::NEXT,
                    next: 1,
                },
            )
            .unwrap();
        queue
            .set_descriptor(
                1,
                crate::queue::Descriptor {
                    addr: init_resp_offset as u64,
                    len: 80,
                    flags: flags::WRITE,
                    next: 0,
                },
            )
            .unwrap();

        // Build a simple FUSE request that goes to the handler
        let mut other_req = vec![0u8; 40];
        other_req[0..4].copy_from_slice(&40u32.to_le_bytes());
        other_req[4..8].copy_from_slice(&1u32.to_le_bytes());
        other_req[8..16].copy_from_slice(&2u64.to_le_bytes());

        let other_req_offset = 256usize;
        let other_resp_offset = 512usize;
        memory[other_req_offset..other_req_offset + other_req.len()].copy_from_slice(&other_req);

        queue
            .set_descriptor(
                2,
                crate::queue::Descriptor {
                    addr: other_req_offset as u64,
                    len: other_req.len() as u32,
                    flags: flags::NEXT,
                    next: 3,
                },
            )
            .unwrap();
        queue
            .set_descriptor(
                3,
                crate::queue::Descriptor {
                    addr: other_resp_offset as u64,
                    len: 32,
                    flags: flags::WRITE,
                    next: 0,
                },
            )
            .unwrap();

        queue.add_avail(0).unwrap();
        queue.add_avail(2).unwrap();

        let completions = fs.process_queue(0, &mut memory).unwrap();
        assert_eq!(completions.len(), 2);
        assert!(fs.session.is_initialized());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let response = &memory[other_resp_offset..other_resp_offset + 18];
        assert_eq!(&response[16..18], b"ok");
    }

    // ==========================================================================
    // FuseRequest Tests
    // ==========================================================================

    #[test]
    fn test_fuse_request_new() {
        let data = vec![0u8; 64];
        let request = FuseRequest::new(&data);
        assert_eq!(request.len(), 64);
        assert!(!request.is_empty());
    }

    #[test]
    fn test_fuse_request_empty() {
        let data = vec![];
        let request = FuseRequest::new(&data);
        assert!(request.is_empty());
    }

    #[test]
    fn test_fuse_request_opcode() {
        let mut data = vec![0u8; 16];
        data[4..8].copy_from_slice(&42u32.to_le_bytes());

        let request = FuseRequest::new(&data);
        assert_eq!(request.opcode(), Some(42));
    }

    #[test]
    fn test_fuse_request_opcode_too_small() {
        let data = vec![0u8; 4];
        let request = FuseRequest::new(&data);
        assert!(request.opcode().is_none());
    }

    #[test]
    fn test_fuse_request_unique() {
        let mut data = vec![0u8; 16];
        data[8..16].copy_from_slice(&12345u64.to_le_bytes());

        let request = FuseRequest::new(&data);
        assert_eq!(request.unique(), Some(12345));
    }

    // ==========================================================================
    // FuseResponse Tests
    // ==========================================================================

    #[test]
    fn test_fuse_response_new() {
        let response = FuseResponse::new(123, vec![1, 2, 3, 4]);

        let data = response.data();
        assert_eq!(data.len(), 20); // 16 header + 4 payload

        let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let error = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let unique = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);

        assert_eq!(len, 20);
        assert_eq!(error, 0);
        assert_eq!(unique, 123);
        assert_eq!(&data[16..], &[1, 2, 3, 4]);
    }

    #[test]
    fn test_fuse_response_error() {
        let response = FuseResponse::error(456, libc::ENOENT);

        let data = response.data();
        assert_eq!(data.len(), 16);

        let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let error = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let unique = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);

        assert_eq!(len, 16);
        assert_eq!(error, -libc::ENOENT);
        assert_eq!(unique, 456);
    }

    #[test]
    fn test_fuse_response_into_data() {
        let response = FuseResponse::new(1, vec![]);
        let data = response.into_data();
        assert_eq!(data.len(), 16);
    }

    // ==========================================================================
    // VirtioFs Process Request Tests
    // ==========================================================================

    #[test]
    fn test_fs_process_request_too_small() {
        let config = FsConfig {
            shared_dir: "/tmp".to_string(),
            ..Default::default()
        };
        let mut fs = VirtioFs::new(config);
        fs.activate().unwrap();

        let result = fs.process_request(&[0u8; 20]);
        assert!(result.is_err());
    }

    #[test]
    fn test_fs_process_request_before_init() {
        let config = FsConfig {
            shared_dir: "/tmp".to_string(),
            ..Default::default()
        };
        let mut fs = VirtioFs::new(config);
        fs.activate().unwrap();

        // Send a non-INIT request before initialization
        let mut request = vec![0u8; 40];
        request[4..8].copy_from_slice(&1u32.to_le_bytes()); // LOOKUP opcode
        request[8..16].copy_from_slice(&1u64.to_le_bytes()); // unique

        let response = fs.process_request(&request).unwrap();

        // Should return EINVAL
        let error = i32::from_le_bytes([response[4], response[5], response[6], response[7]]);
        assert_eq!(error, -libc::EINVAL);
    }

    #[test]
    fn test_fs_process_request_no_handler() {
        let config = FsConfig {
            shared_dir: "/tmp".to_string(),
            ..Default::default()
        };
        let mut fs = VirtioFs::new(config);
        fs.activate().unwrap();

        // First, send FUSE_INIT
        let mut init_request = vec![0u8; 56];
        init_request[4..8].copy_from_slice(&26u32.to_le_bytes()); // INIT opcode
        init_request[8..16].copy_from_slice(&1u64.to_le_bytes());
        init_request[40..44].copy_from_slice(&FUSE_KERNEL_VERSION.to_le_bytes());
        init_request[44..48].copy_from_slice(&FUSE_KERNEL_MINOR_VERSION.to_le_bytes());
        init_request[48..52].copy_from_slice(&(64 * 1024u32).to_le_bytes());
        init_request[52..56].copy_from_slice(&0u32.to_le_bytes());

        fs.process_request(&init_request).unwrap();
        assert!(fs.session.is_initialized());

        // Now send another request - should get ENOSYS since no handler
        let mut request = vec![0u8; 40];
        request[4..8].copy_from_slice(&1u32.to_le_bytes()); // LOOKUP opcode
        request[8..16].copy_from_slice(&2u64.to_le_bytes()); // unique

        let response = fs.process_request(&request).unwrap();

        let error = i32::from_le_bytes([response[4], response[5], response[6], response[7]]);
        assert_eq!(error, -libc::ENOSYS);
    }

    #[test]
    fn test_fs_with_handler() {
        use std::sync::atomic::AtomicU32;

        struct TestHandler {
            call_count: AtomicU32,
        }

        impl FuseRequestHandler for TestHandler {
            fn handle_request(&self, _request: &[u8]) -> Result<Vec<u8>> {
                self.call_count.fetch_add(1, Ordering::SeqCst);
                Ok(FuseResponse::new(0, vec![]).into_data())
            }
        }

        let handler = Arc::new(TestHandler {
            call_count: AtomicU32::new(0),
        });

        let config = FsConfig {
            shared_dir: "/tmp".to_string(),
            ..Default::default()
        };
        let mut fs = VirtioFs::with_handler(config, handler.clone());
        fs.activate().unwrap();

        // Send FUSE_INIT
        let mut init_request = vec![0u8; 56];
        init_request[4..8].copy_from_slice(&26u32.to_le_bytes());
        init_request[8..16].copy_from_slice(&1u64.to_le_bytes());
        init_request[40..44].copy_from_slice(&FUSE_KERNEL_VERSION.to_le_bytes());
        init_request[44..48].copy_from_slice(&FUSE_KERNEL_MINOR_VERSION.to_le_bytes());
        init_request[48..52].copy_from_slice(&(64 * 1024u32).to_le_bytes());
        init_request[52..56].copy_from_slice(&0u32.to_le_bytes());

        fs.process_request(&init_request).unwrap();

        // Send a regular request
        let mut request = vec![0u8; 40];
        request[4..8].copy_from_slice(&1u32.to_le_bytes());
        request[8..16].copy_from_slice(&2u64.to_le_bytes());

        fs.process_request(&request).unwrap();

        assert_eq!(handler.call_count.load(Ordering::SeqCst), 1);
    }
}
