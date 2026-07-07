//! Error types for the core layer.

use arcbox_error::CommonError;
use thiserror::Error;

/// Result type alias for core operations.
pub type Result<T> = std::result::Result<T, CoreError>;

/// Errors that can occur in core operations.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Common errors (I/O, config, not found, etc.).
    #[error(transparent)]
    Common(#[from] CommonError),

    /// VMM-layer error (hypervisor, devices, boot).
    #[error("VMM error: {0}")]
    Vmm(#[from] arcbox_vmm::VmmError),

    /// Snapshot error.
    #[error("snapshot error: {0}")]
    Snapshot(#[from] arcbox_vmm::SnapshotError),

    /// VM management error (registry, lifecycle).
    #[error("VM error: {0}")]
    Vm(String),

    /// Machine error.
    #[error("machine error: {0}")]
    Machine(String),

    /// Error reported by the guest agent over the vsock wire, carrying an
    /// HTTP-style status code (400/404/409/412/500/503) that the API layer
    /// maps onto the matching gRPC status.
    #[error("{message}")]
    Agent {
        /// HTTP-style status code from the agent's `ErrorResponse`.
        code: i32,
        /// Human-readable error message.
        message: String,
    },

    /// Persistence deserialization error.
    #[error("persistence error: {0}")]
    Persistence(#[from] toml::de::Error),

    /// An internal RwLock was poisoned by a panicking thread.
    #[error("internal lock poisoned")]
    LockPoisoned,

    /// Filesystem error.
    #[error("filesystem error: {0}")]
    Fs(#[from] arcbox_fs::FsError),

    /// Network error.
    #[error("network error: {0}")]
    Net(#[from] arcbox_net::NetError),
}

impl CoreError {
    /// Creates a new configuration error.
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Common(CommonError::config(msg))
    }

    /// Creates a new not found error.
    #[must_use]
    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::Common(CommonError::not_found(resource))
    }

    /// Creates a new already exists error.
    #[must_use]
    pub fn already_exists(resource: impl Into<String>) -> Self {
        Self::Common(CommonError::already_exists(resource))
    }

    /// Creates a new invalid state error.
    #[must_use]
    pub fn invalid_state(msg: impl Into<String>) -> Self {
        Self::Common(CommonError::invalid_state(msg))
    }
}

// Allow automatic conversion from std::io::Error to CoreError via CommonError.
impl From<std::io::Error> for CoreError {
    fn from(err: std::io::Error) -> Self {
        Self::Common(CommonError::from(err))
    }
}
