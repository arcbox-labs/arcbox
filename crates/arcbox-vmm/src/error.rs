//! Error types for the VMM crate.

use arcbox_hypervisor::HypervisorError;
use thiserror::Error;

/// Result type alias for VMM operations.
pub type Result<T> = std::result::Result<T, VmmError>;

/// Errors that can occur during VMM operations.
#[derive(Debug, Error)]
pub enum VmmError {
    /// Hypervisor error.
    #[error("hypervisor error: {0}")]
    Hypervisor(#[from] HypervisorError),

    /// VMM not initialized.
    #[error("VMM not initialized")]
    NotInitialized,

    /// Invalid VMM state.
    #[error("invalid VMM state: {0}")]
    InvalidState(String),

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

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),
}
