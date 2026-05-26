//! Errors returned by `arcbox-vmnet`.

use thiserror::Error;

/// Result alias for vmnet operations.
pub type Result<T> = std::result::Result<T, VmnetError>;

/// Errors that can occur while configuring or driving a vmnet interface.
#[derive(Debug, Error)]
pub enum VmnetError {
    /// Configuration is invalid or vmnet rejected the start request.
    ///
    /// Typical causes: missing entitlement / not running as root, malformed
    /// MAC, missing bridge interface, vmnet returned a non-success status.
    #[error("vmnet configuration error: {0}")]
    Config(String),

    /// I/O error from `vmnet_read` / `vmnet_write` or an underlying syscall.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl VmnetError {
    /// Creates a configuration error.
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }
}
