//! Filesystem server implementation.

use crate::{error::Result, FsConfig};

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
pub struct FsServer {
    config: FsConfig,
    state: ServerState,
}

impl FsServer {
    /// Creates a new filesystem server.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // FsConfig contains String
    pub fn new(config: FsConfig) -> Self {
        Self {
            config,
            state: ServerState::Created,
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

    /// Starts the server.
    ///
    /// # Errors
    ///
    /// Currently always succeeds. Will return an error if
    /// the FUSE server cannot be initialized once implemented.
    #[allow(clippy::missing_const_for_fn)] // Will have async operations
    pub fn start(&mut self) -> Result<()> {
        // TODO: Initialize FUSE server, start worker threads
        self.state = ServerState::Running;
        Ok(())
    }

    /// Stops the server.
    ///
    /// # Errors
    ///
    /// Currently always succeeds. Will return an error if
    /// cleanup fails once implemented.
    #[allow(clippy::missing_const_for_fn)] // Will have async operations
    pub fn stop(&mut self) -> Result<()> {
        // TODO: Stop worker threads, cleanup
        self.state = ServerState::Stopped;
        Ok(())
    }
}
