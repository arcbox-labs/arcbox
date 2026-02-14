//! Error types for the VMM crate.

use arcbox_error::CommonError;
use arcbox_hypervisor::HypervisorError;
use thiserror::Error;

/// Result type alias for VMM operations.
pub type Result<T> = std::result::Result<T, VmmError>;

/// Errors that can occur during VMM operations.
#[derive(Debug, Error)]
pub enum VmmError {
    /// Common error from arcbox-error.
    #[error(transparent)]
    Common(#[from] CommonError),

    /// Hypervisor error.
    #[error("hypervisor error: {0}")]
    Hypervisor(#[from] HypervisorError),

    /// VMM not initialized.
    #[error("VMM not initialized")]
    NotInitialized,

    /// vCPU error.
    #[error("vCPU error: {0}")]
    Vcpu(String),

    /// Memory error.
    #[error("memory error: {0}")]
    Memory(String),

    /// Device error.
    #[error("device error: {0}")]
    Device(String),

    /// IRQ error.
    #[error("IRQ error: {0}")]
    Irq(String),

    /// Event loop error.
    #[error("event loop error: {0}")]
    EventLoop(String),
}

impl VmmError {
    /// Creates an invalid state error via CommonError.
    #[must_use]
    pub fn invalid_state(msg: impl Into<String>) -> Self {
        Self::Common(CommonError::invalid_state(msg))
    }

    /// Creates a config error via CommonError.
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Common(CommonError::config(msg))
    }
}

// Allow automatic conversion from std::io::Error to VmmError via CommonError.
impl From<std::io::Error> for VmmError {
    fn from(err: std::io::Error) -> Self {
        Self::Common(CommonError::from(err))
    }
}
