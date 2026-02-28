//! Error types for the hypervisor crate.

use arcbox_error::CommonError;
use thiserror::Error;

/// Result type alias for hypervisor operations.
pub type Result<T> = std::result::Result<T, HypervisorError>;

/// Errors that can occur during hypervisor operations.
#[derive(Debug, Error)]
pub enum HypervisorError {
    /// Common error from arcbox-error.
    #[error(transparent)]
    Common(#[from] CommonError),

    /// Platform not supported.
    #[error("platform not supported: {0}")]
    UnsupportedPlatform(String),

    /// Failed to initialize hypervisor.
    #[error("failed to initialize hypervisor: {0}")]
    InitializationFailed(String),

    /// Failed to create virtual machine.
    #[error("failed to create VM: {0}")]
    VmCreationFailed(String),

    /// Failed to create vCPU.
    #[error("failed to create vCPU {id}: {reason}")]
    VcpuCreationFailed { id: u32, reason: String },

    /// Memory mapping error.
    #[error("memory error: {0}")]
    MemoryError(String),

    /// VM not in expected state.
    #[error("VM state error: expected {expected}, got {actual}")]
    VmStateError { expected: String, actual: String },

    /// vCPU execution error.
    #[error("vCPU execution error: {0}")]
    VcpuRunError(String),

    /// Device error.
    #[error("device error: {0}")]
    DeviceError(String),

    /// VM runtime error.
    #[error("VM error: {0}")]
    VmError(String),

    /// Snapshot error.
    #[error("snapshot error: {0}")]
    SnapshotError(String),

    /// Feature not supported.
    #[error("not supported: {0}")]
    NotSupported(String),

    /// Platform-specific error.
    #[cfg(target_os = "macos")]
    #[error("darwin error: {0}")]
    DarwinError(String),

    /// Platform-specific error.
    #[cfg(target_os = "linux")]
    #[error("KVM error: {0}")]
    KvmError(String),
}

impl HypervisorError {
    /// Creates a timeout error via CommonError.
    #[must_use]
    pub fn timeout(msg: impl Into<String>) -> Self {
        Self::Common(CommonError::timeout(msg))
    }

    /// Creates an invalid config error via CommonError.
    #[must_use]
    pub fn invalid_config(msg: impl Into<String>) -> Self {
        Self::Common(CommonError::config(msg))
    }
}

// Allow automatic conversion from std::io::Error to HypervisorError via CommonError.
impl From<std::io::Error> for HypervisorError {
    fn from(err: std::io::Error) -> Self {
        Self::Common(CommonError::from(err))
    }
}
