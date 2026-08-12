//! Error types for the engine layer.
//!
//! `EngineError` carries the engine-flavored subset of what used to be
//! `arcbox-core`'s `CoreError`; `CoreError` keeps those variants as the
//! app-layer contract and converts variant-for-variant via `From`, so
//! predicates like `CommonError::is_not_found` answer identically
//! through either type.

use arcbox_error::CommonError;
use thiserror::Error;

/// Result type alias for engine operations.
pub type Result<T> = std::result::Result<T, EngineError>;

/// Errors that can occur in engine operations.
#[derive(Debug, Error)]
pub enum EngineError {
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

    /// Guest-agent transport error.
    #[error("{context}: {source}")]
    Transport {
        /// Transport operation that failed.
        context: &'static str,
        /// Original transport error.
        #[source]
        source: arcbox_transport::error::TransportError,
    },

    /// Persistence deserialization error.
    #[error("persistence error: {0}")]
    Persistence(#[from] toml::de::Error),

    /// An internal RwLock was poisoned by a panicking thread.
    #[error("internal lock poisoned")]
    LockPoisoned,
}

impl EngineError {
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

// Allow automatic conversion from std::io::Error via CommonError, matching
// the CoreError convention in arcbox-core.
impl From<std::io::Error> for EngineError {
    fn from(err: std::io::Error) -> Self {
        Self::Common(CommonError::from(err))
    }
}

impl From<arcbox_transport::error::TransportError> for EngineError {
    fn from(source: arcbox_transport::error::TransportError) -> Self {
        Self::Transport {
            context: "guest-agent transport failed",
            source,
        }
    }
}
