//! Filesystem server implementation.
//!
//! This module provides the FUSE server that handles filesystem requests
//! from the guest VM. On Darwin, the native VZ framework handles virtio-fs,
//! so this is primarily used for Linux KVM.
//!
//! The [`FsServer`] implements [`arcbox_virtio::fs::FuseRequestHandler`] to
//! integrate with the VirtIO-FS device.

use std::sync::Arc;

use arcbox_virtio::fs::{FuseRequestHandler, FuseSession};

use crate::FsConfig;
use crate::dispatcher::{DispatcherConfig, FuseDispatcher};
use crate::error::{FsError, Result};
use crate::passthrough::PassthroughFs;

/// Filesystem server state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// Server created but not started.
    Created,
    /// Server is running.
    Running,
    /// Server is stopped.
    Stopped,
}

/// Filesystem server.
///
/// Manages the virtiofs server lifecycle and request handling.
/// Integrates `PassthroughFs` for host filesystem access and
/// `FuseDispatcher` for FUSE protocol handling.
pub struct FsServer {
    config: FsConfig,
    state: ServerState,
    /// Passthrough filesystem backend.
    fs: Option<Arc<PassthroughFs>>,
    /// FUSE request dispatcher.
    dispatcher: Option<FuseDispatcher>,
}

impl FsServer {
    /// Creates a new filesystem server.
    #[must_use]
    pub fn new(config: FsConfig) -> Self {
        Self {
            config,
            state: ServerState::Created,
            fs: None,
            dispatcher: None,
        }
    }

    /// Returns the current server state.
    #[must_use]
    pub const fn state(&self) -> ServerState {
        self.state
    }

    /// Returns the filesystem tag.
    #[must_use]
    pub fn tag(&self) -> &str {
        &self.config.tag
    }

    /// Returns the source directory path.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.config.source
    }

    /// Starts the server.
    ///
    /// Initializes the passthrough filesystem and FUSE dispatcher.
    ///
    /// # Errors
    ///
    /// Returns an error if the filesystem cannot be initialized.
    pub fn start(&mut self) -> Result<()> {
        if self.state == ServerState::Running {
            return Ok(());
        }

        // Initialize passthrough filesystem
        let fs = PassthroughFs::new(&self.config.source)
            .map_err(|e| FsError::NotFound(format!("Failed to initialize filesystem: {}", e)))?;
        let fs = Arc::new(fs);

        // Initialize dispatcher
        let dispatcher_config = DispatcherConfig {
            entry_timeout: self.config.cache_timeout,
            attr_timeout: self.config.cache_timeout,
        };
        let dispatcher = FuseDispatcher::new(Arc::clone(&fs), dispatcher_config);

        self.fs = Some(fs);
        self.dispatcher = Some(dispatcher);
        self.state = ServerState::Running;

        tracing::info!(
            "Started filesystem server: tag='{}', source='{}'",
            self.config.tag,
            self.config.source
        );

        Ok(())
    }

    /// Stops the server.
    ///
    /// Releases filesystem resources.
    ///
    /// # Errors
    ///
    /// Returns an error if cleanup fails.
    pub fn stop(&mut self) -> Result<()> {
        if self.state != ServerState::Running {
            return Ok(());
        }

        self.dispatcher = None;
        self.fs = None;
        self.state = ServerState::Stopped;

        tracing::info!("Stopped filesystem server: tag='{}'", self.config.tag);

        Ok(())
    }

    /// Handles a FUSE request and returns the response.
    ///
    /// This method is called by the virtio-fs device when it receives
    /// a request from the guest.
    ///
    /// # Errors
    ///
    /// Returns an error if the request cannot be processed.
    pub fn handle_request(&self, request: &[u8]) -> Result<Vec<u8>> {
        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| FsError::Fuse("Server not started".to_string()))?;

        dispatcher.dispatch(request)
    }

    /// Returns a reference to the passthrough filesystem.
    #[must_use]
    pub fn filesystem(&self) -> Option<&Arc<PassthroughFs>> {
        self.fs.as_ref()
    }

    /// Returns a reference to the dispatcher.
    #[must_use]
    pub fn dispatcher(&self) -> Option<&FuseDispatcher> {
        self.dispatcher.as_ref()
    }
}

// ============================================================================
// FuseRequestHandler Implementation
// ============================================================================

impl FuseRequestHandler for FsServer {
    fn handle_request(&self, request: &[u8]) -> arcbox_virtio::Result<Vec<u8>> {
        self.handle_request(request)
            .map_err(|e| arcbox_virtio::VirtioError::DeviceError {
                device: "fs".to_string(),
                message: e.to_string(),
            })
    }

    fn on_init(&self, session: &FuseSession) {
        tracing::info!(
            "FsServer received FUSE_INIT: version {}.{}, max_readahead={}, max_write={}",
            session.major(),
            session.minor(),
            session.max_readahead(),
            session.max_write()
        );
    }

    fn on_destroy(&self) {
        tracing::info!("FsServer received FUSE_DESTROY");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_server_lifecycle() {
        let temp = TempDir::new().unwrap();
        let config = FsConfig {
            tag: "test".to_string(),
            source: temp.path().to_string_lossy().to_string(),
            num_threads: 1,
            writeback_cache: false,
            cache_timeout: 1,
        };

        let mut server = FsServer::new(config);
        assert_eq!(server.state(), ServerState::Created);
        assert!(server.filesystem().is_none());

        // Start
        server.start().unwrap();
        assert_eq!(server.state(), ServerState::Running);
        assert!(server.filesystem().is_some());
        assert!(server.dispatcher().is_some());

        // Stop
        server.stop().unwrap();
        assert_eq!(server.state(), ServerState::Stopped);
        assert!(server.filesystem().is_none());
    }

    #[test]
    fn test_server_handle_request() {
        use crate::fuse::{
            FUSE_KERNEL_MINOR_VERSION, FUSE_KERNEL_VERSION, FuseInHeader, FuseInitIn, FuseOpcode,
        };
        use std::mem::size_of;

        let temp = TempDir::new().unwrap();
        let config = FsConfig {
            tag: "test".to_string(),
            source: temp.path().to_string_lossy().to_string(),
            num_threads: 1,
            writeback_cache: false,
            cache_timeout: 1,
        };

        let mut server = FsServer::new(config);
        server.start().unwrap();

        // Build INIT request
        let init_in = FuseInitIn {
            major: FUSE_KERNEL_VERSION,
            minor: FUSE_KERNEL_MINOR_VERSION,
            max_readahead: 128 * 1024,
            flags: 0,
        };

        let header = FuseInHeader {
            len: (FuseInHeader::SIZE + size_of::<FuseInitIn>()) as u32,
            opcode: FuseOpcode::Init as u32,
            unique: 1,
            nodeid: 0,
            uid: 0,
            gid: 0,
            pid: 0,
            padding: 0,
        };

        let mut request = Vec::new();
        request.extend_from_slice(unsafe {
            std::slice::from_raw_parts(&header as *const _ as *const u8, FuseInHeader::SIZE)
        });
        request.extend_from_slice(unsafe {
            std::slice::from_raw_parts(&init_in as *const _ as *const u8, size_of::<FuseInitIn>())
        });

        // Handle request
        let response = server.handle_request(&request).unwrap();
        assert!(!response.is_empty());
    }

    #[test]
    fn test_server_not_started_error() {
        let config = FsConfig {
            tag: "test".to_string(),
            source: "/tmp".to_string(),
            num_threads: 1,
            writeback_cache: false,
            cache_timeout: 1,
        };

        let server = FsServer::new(config);
        let result = server.handle_request(&[]);
        assert!(result.is_err());
    }
}
