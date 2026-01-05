//! Error types for the hypervisor crate.

use thiserror::Error;

/// Result type alias for hypervisor operations.
pub type Result<T> = std::result::Result<T, HypervisorError>;

/// Errors that can occur during hypervisor operations.
#[derive(Debug, Error)]
pub enum HypervisorError {
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

    /// Invalid configuration.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// VM not in expected state.
    #[error("VM state error: expected {expected}, got {actual}")]
    InvalidState { expected: String, actual: String },

    /// vCPU execution error.
    #[error("vCPU execution error: {0}")]
    VcpuRunError(String),

    /// Device error.
    #[error("device error: {0}")]
    DeviceError(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Platform-specific error.
    #[cfg(target_os = "macos")]
    #[error("darwin error: {0}")]
    DarwinError(String),

    /// Platform-specific error.
    #[cfg(target_os = "linux")]
    #[error("KVM error: {0}")]
    KvmError(String),
}
