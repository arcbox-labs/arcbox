//! `VirtioFs` device — config, queue dispatch, `VirtioDevice` impl.

mod queue;
mod virtio_device;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use arcbox_virtio_core::error::{Result, VirtioError};
use arcbox_virtio_core::queue::VirtQueue;
use arcbox_virtio_core::virtio_bindings;

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
}
