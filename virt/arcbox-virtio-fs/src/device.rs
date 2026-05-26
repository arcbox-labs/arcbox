//! `VirtioFs` device — config, queue dispatch, `VirtioDevice` impl.

use std::sync::Arc;

use arcbox_virtio_core::error::{Result, VirtioError};
use arcbox_virtio_core::queue::VirtQueue;
use arcbox_virtio_core::{QueueConfig, VirtioDevice, VirtioDeviceId, virtio_bindings};

use crate::handler::FuseRequestHandler;
use crate::request::FuseResponse;
use crate::session::FuseSession;

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

/// `VirtIO` filesystem device.
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
    /// Request queues for FUSE traffic (host-side, used by tests).
    request_queues: Vec<VirtQueue>,
    /// Whether the device is activated.
    activated: bool,
    /// Last processed avail index for request queue 1 (guest-memory path).
    last_avail_idx_q1: u16,
}

impl VirtioFs {
    /// Feature: Notification.
    pub const FEATURE_NOTIFICATION: u64 = 1 << 0;
    /// VirtIO version 1 compliance (required for modern MMIO transport).
    pub const FEATURE_VERSION_1: u64 = 1 << virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;

    /// FUSE opcode for INIT.
    pub(crate) const FUSE_INIT: u32 = 26;

    /// FUSE opcode for DESTROY.
    const FUSE_DESTROY: u32 = 38;

    /// Creates a new filesystem device.
    #[must_use]
    pub fn new(config: FsConfig) -> Self {
        Self {
            config,
            features: Self::FEATURE_VERSION_1,
            acked_features: 0,
            session: FuseSession::new(),
            handler: None,
            request_queues: Vec::new(),
            activated: false,
            last_avail_idx_q1: 0,
        }
    }

    /// Creates a new filesystem device with a request handler.
    #[must_use]
    pub fn with_handler(config: FsConfig, handler: Arc<dyn FuseRequestHandler>) -> Self {
        Self {
            config,
            features: Self::FEATURE_VERSION_1,
            acked_features: 0,
            session: FuseSession::new(),
            handler: Some(handler),
            request_queues: Vec::new(),
            activated: false,
            last_avail_idx_q1: 0,
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
    /// 2. If `FUSE_INIT`: handle initialization handshake
    /// 3. If `FUSE_DESTROY`: clean up session
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
                let response = self.session.handle_init(request)?;

                if let Some(handler) = &self.handler {
                    handler.on_init(&self.session);
                }

                Ok(response)
            }
            Self::FUSE_DESTROY => {
                self.session.reset();

                if let Some(handler) = &self.handler {
                    handler.on_destroy();
                }

                Ok(FuseResponse::new(unique, vec![]).into_data())
            }
            _ => {
                if !self.session.is_initialized() {
                    tracing::warn!("FUSE request before INIT: opcode={}", opcode);
                    return Ok(FuseResponse::error(unique, libc::EINVAL).into_data());
                }

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
        // First, collect all pending requests from the queue. Releases the
        // borrow on self.request_queues.
        let pending_requests = {
            let queue = self.request_queues.get_mut(queue_index).ok_or_else(|| {
                VirtioError::NotReady(format!("request queue {queue_index} not available"))
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

        // Process requests preserving avail ring order. Control requests
        // (INIT/DESTROY) must go through self.process_request() for session
        // state mutation. Normal requests can be dispatched in parallel via
        // handler when multiple are pending, but their results are collected
        // back into original order.

        type ResponseItem = (
            u16,
            std::result::Result<Vec<u8>, VirtioError>,
            Vec<(usize, usize)>,
        );

        let handler = self.handler.clone();
        let session_initialized = self.session.is_initialized();

        // Parallel dispatch is only safe when the entire batch contains
        // normal requests (no INIT/DESTROY) with valid FUSE headers (>= 40
        // bytes). If any control request is present, fall back to sequential
        // processing because pre-computing handler results for normal requests
        // around a DESTROY would violate avail ring ordering.
        let has_control = pending_requests.iter().any(|(_, data, _)| {
            if data.len() >= 8 {
                let op = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                op == Self::FUSE_INIT || op == Self::FUSE_DESTROY
            } else {
                true // malformed → force sequential for proper error handling
            }
        });
        let all_valid = pending_requests.iter().all(|(_, data, _)| data.len() >= 40);
        let can_parallel = !has_control
            && all_valid
            && pending_requests.len() > 1
            && session_initialized
            && handler.is_some();

        let responses: Vec<ResponseItem> = if can_parallel {
            // All requests are normal with valid headers — safe to parallelize.
            let handler_ref = handler.as_ref().unwrap();
            use rayon::prelude::*;
            pending_requests
                .into_par_iter()
                .map(|(head_idx, data, bufs)| {
                    let response = handler_ref.handle_request(&data);
                    (head_idx, response, bufs)
                })
                .collect()
        } else {
            // Sequential: control ops present, malformed headers, or single request.
            pending_requests
                .into_iter()
                .map(|(head_idx, request_data, write_buffers)| {
                    let response = self.process_request(&request_data);
                    (head_idx, response, write_buffers)
                })
                .collect()
        };

        // Phase 2: Write responses into guest memory (sequential)
        // TODO(ABX-208): Use push_used_batch() for single interrupt notification
        let mut completions = Vec::with_capacity(responses.len());
        for (head_idx, response_result, write_buffers) in responses {
            let response = response_result?;
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

        let tag_bytes = self.config.tag.as_bytes();
        let tag_len = tag_bytes.len().min(36);
        config_data[..tag_len].copy_from_slice(&tag_bytes[..tag_len]);

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

        self.session.reset();

        let event_idx = (self.acked_features & arcbox_virtio_core::queue::VIRTIO_F_EVENT_IDX) != 0;
        let mut queues = Vec::with_capacity(self.config.num_queues as usize);
        for _ in 0..self.config.num_queues {
            let mut q = VirtQueue::new(self.config.queue_size)?;
            q.set_event_idx(event_idx);
            queues.push(q);
        }
        self.request_queues = queues;

        // The FUSE_INIT handshake will happen when the guest driver sends the
        // first request through the virtqueue.
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

        if let Some(handler) = &self.handler {
            handler.on_destroy();
        }

        tracing::debug!("VirtIO-FS device reset: tag='{}'", self.config.tag);
    }

    fn process_queue(
        &mut self,
        queue_idx: u16,
        memory: &mut [u8],
        queue_config: &QueueConfig,
    ) -> Result<Vec<(u16, u32)>> {
        // Queue 0 is the hiprio/notification queue — nothing to do for now.
        if queue_idx == 0 {
            return Ok(Vec::new());
        }

        if !queue_config.ready || queue_config.size == 0 {
            return Ok(Vec::new());
        }

        // Read descriptors directly from guest memory (not the internal VirtQueue).
        // Translate GPAs to slice offsets by subtracting gpa_base (checked to
        // guard against a malicious guest providing a GPA below the RAM base).
        let gpa_base = queue_config.gpa_base as usize;
        let desc_addr = (queue_config.desc_addr as usize)
            .checked_sub(gpa_base)
            .ok_or_else(|| {
                tracing::warn!(
                    "invalid desc GPA {:#x} below ram base {:#x}",
                    queue_config.desc_addr,
                    gpa_base
                );
                VirtioError::InvalidQueue("desc GPA below ram base".into())
            })?;
        let avail_addr = (queue_config.avail_addr as usize)
            .checked_sub(gpa_base)
            .ok_or_else(|| {
                tracing::warn!(
                    "invalid avail GPA {:#x} below ram base {:#x}",
                    queue_config.avail_addr,
                    gpa_base
                );
                VirtioError::InvalidQueue("avail GPA below ram base".into())
            })?;
        let used_addr = (queue_config.used_addr as usize)
            .checked_sub(gpa_base)
            .ok_or_else(|| {
                tracing::warn!(
                    "invalid used GPA {:#x} below ram base {:#x}",
                    queue_config.used_addr,
                    gpa_base
                );
                VirtioError::InvalidQueue("used GPA below ram base".into())
            })?;
        let q_size = queue_config.size as usize;

        if avail_addr + 4 > memory.len() {
            return Ok(Vec::new());
        }
        let avail_idx = u16::from_le_bytes([memory[avail_addr + 2], memory[avail_addr + 3]]);

        // Track last processed index per queue. Use a simple field for queue 1.
        let mut current_avail = self.last_avail_idx_q1;
        let mut completions = Vec::new();

        while current_avail != avail_idx {
            let ring_off = avail_addr + 4 + 2 * (current_avail as usize % q_size);
            if ring_off + 2 > memory.len() {
                break;
            }
            let head_idx = u16::from_le_bytes([memory[ring_off], memory[ring_off + 1]]) as usize;

            // Walk descriptor chain: collect request data (read-only) and
            // response buffer locations (write-only).
            let mut request_data = Vec::new();
            let mut write_bufs: Vec<(usize, usize)> = Vec::new();
            let mut idx = head_idx;
            for _ in 0..q_size {
                let d_off = desc_addr + idx * 16;
                if d_off + 16 > memory.len() {
                    break;
                }
                let addr = match (u64::from_le_bytes(memory[d_off..d_off + 8].try_into().unwrap())
                    as usize)
                    .checked_sub(gpa_base)
                {
                    Some(a) => a,
                    None => continue,
                };
                let len =
                    u32::from_le_bytes(memory[d_off + 8..d_off + 12].try_into().unwrap()) as usize;
                let flags = u16::from_le_bytes(memory[d_off + 12..d_off + 14].try_into().unwrap());
                let next = u16::from_le_bytes(memory[d_off + 14..d_off + 16].try_into().unwrap());

                if flags & arcbox_virtio_core::queue::flags::WRITE != 0 {
                    write_bufs.push((addr, len));
                } else if addr + len <= memory.len() {
                    request_data.extend_from_slice(&memory[addr..addr + len]);
                }

                if flags & arcbox_virtio_core::queue::flags::NEXT == 0 {
                    break;
                }
                idx = next as usize;
            }

            let response = match self.process_request(&request_data) {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!("VirtioFS FUSE request error: {e}");
                    let unique = if request_data.len() >= 16 {
                        u64::from_le_bytes(request_data[8..16].try_into().unwrap())
                    } else {
                        0
                    };
                    FuseResponse::error(unique, libc::EIO).into_data()
                }
            };

            // Write response into the write-only descriptors.
            let mut resp_offset = 0;
            for &(buf_addr, buf_len) in &write_bufs {
                let remaining = response.len() - resp_offset;
                if remaining == 0 {
                    break;
                }
                let to_write = remaining.min(buf_len);
                if buf_addr + to_write <= memory.len() {
                    memory[buf_addr..buf_addr + to_write]
                        .copy_from_slice(&response[resp_offset..resp_offset + to_write]);
                }
                resp_offset += to_write;
            }

            // Update used ring.
            let used_idx_off = used_addr + 2;
            let used_idx = u16::from_le_bytes([memory[used_idx_off], memory[used_idx_off + 1]]);
            let used_entry = used_addr + 4 + ((used_idx as usize) % q_size) * 8;
            if used_entry + 8 <= memory.len() {
                memory[used_entry..used_entry + 4]
                    .copy_from_slice(&(head_idx as u32).to_le_bytes());
                memory[used_entry + 4..used_entry + 8]
                    .copy_from_slice(&(response.len() as u32).to_le_bytes());
                std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
                let new_used = used_idx.wrapping_add(1);
                memory[used_idx_off..used_idx_off + 2].copy_from_slice(&new_used.to_le_bytes());
            }

            // Update avail_event for EVENT_IDX notification — only when negotiated.
            if (self.acked_features & arcbox_virtio_core::queue::VIRTIO_F_EVENT_IDX) != 0 {
                let avail_event_off = used_addr + 4 + 8 * q_size;
                if avail_event_off + 2 <= memory.len() {
                    let ae = current_avail.wrapping_add(1).to_le_bytes();
                    memory[avail_event_off] = ae[0];
                    memory[avail_event_off + 1] = ae[1];
                }
            }

            completions.push((head_idx as u16, response.len() as u32));
            current_avail = current_avail.wrapping_add(1);
        }

        self.last_avail_idx_q1 = current_avail;
        Ok(completions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        FUSE_ASYNC_READ, FUSE_BIG_WRITES, FUSE_KERNEL_MINOR_VERSION, FUSE_KERNEL_VERSION,
    };
    use arcbox_virtio_core::queue::flags;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        assert_ne!(
            fs.features() & (1 << virtio_bindings::virtio_config::VIRTIO_F_VERSION_1),
            0
        );
    }

    #[test]
    fn test_fs_ack_features() {
        let mut fs = VirtioFs::new(FsConfig::default());
        fs.ack_features(VirtioFs::FEATURE_NOTIFICATION);
        assert_eq!(fs.acked_features & VirtioFs::FEATURE_NOTIFICATION, 0);
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

        assert_eq!(&data[0..6], b"testfs");
        assert!(data[6..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_fs_read_config_tag_long() {
        let config = FsConfig {
            tag: "a".repeat(50),
            ..Default::default()
        };
        let fs = VirtioFs::new(config);

        let mut data = [0u8; 36];
        fs.read_config(0, &mut data);

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
    }

    #[test]
    fn test_fs_read_config_beyond() {
        let fs = VirtioFs::new(FsConfig::default());

        let mut data = [0xFFu8; 4];
        fs.read_config(100, &mut data);
    }

    #[test]
    fn test_fs_write_config_noop() {
        let config = FsConfig {
            tag: "original".to_string(),
            ..Default::default()
        };
        let mut fs = VirtioFs::new(config);

        fs.write_config(0, b"newvalue");

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

    #[test]
    fn test_fs_feature_constants() {
        assert_eq!(VirtioFs::FEATURE_NOTIFICATION, 1 << 0);
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
                arcbox_virtio_core::queue::Descriptor {
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
                arcbox_virtio_core::queue::Descriptor {
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
                arcbox_virtio_core::queue::Descriptor {
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
                arcbox_virtio_core::queue::Descriptor {
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
