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

    /// Filesystem error.
    #[error("filesystem error: {0}")]
    Fs(#[from] arcbox_fs::FsError),

    /// Network error.
    #[error("network error: {0}")]
    Net(#[from] arcbox_net::NetError),

    /// Published-image registry error (index/manifest fetch, reference
    /// parsing, name validation) shared by the macOS base-image and Linux
    /// machine-image flows.
    #[error("image error: {0}")]
    Image(String),

    /// macOS guest image / clone error (a message that does not originate from
    /// Virtualization.framework — e.g. a path or serialization failure).
    #[cfg(target_os = "macos")]
    #[error("macOS image error: {0}")]
    Macos(String),

    /// Virtualization.framework error from the `arcbox-vz` layer.
    #[cfg(target_os = "macos")]
    #[error("macOS virtualization error: {0}")]
    Vz(#[from] arcbox_vz::VZError),
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

    /// Creates a new published-image registry error.
    #[must_use]
    pub fn image(msg: impl Into<String>) -> Self {
        Self::Image(msg.into())
    }

    /// Creates a new macOS image error.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn macos(msg: impl Into<String>) -> Self {
        Self::Macos(msg.into())
    }
}

// Allow automatic conversion from std::io::Error to CoreError via CommonError.
impl From<std::io::Error> for CoreError {
    fn from(err: std::io::Error) -> Self {
        Self::Common(CommonError::from(err))
    }
}

impl From<arcbox_transport::error::TransportError> for CoreError {
    fn from(source: arcbox_transport::error::TransportError) -> Self {
        Self::Transport {
            context: "guest-agent transport failed",
            source,
        }
    }
}

// The engine-layer errors map variant-for-variant, so `is_not_found()` and
// friends keep answering the same through either type.
impl From<arcbox_engine::EngineError> for CoreError {
    fn from(err: arcbox_engine::EngineError) -> Self {
        use arcbox_engine::EngineError as E;
        match err {
            E::Common(c) => Self::Common(c),
            E::Vmm(e) => Self::Vmm(e),
            E::Snapshot(e) => Self::Snapshot(e),
            E::Vm(msg) => Self::Vm(msg),
            E::Machine(msg) => Self::Machine(msg),
            E::Agent { code, message } => Self::Agent { code, message },
            E::Transport { context, source } => Self::Transport { context, source },
            E::Persistence(e) => Self::Persistence(e),
            E::LockPoisoned => Self::LockPoisoned,
        }
    }
}

impl From<arcbox_image::ImageError> for CoreError {
    fn from(err: arcbox_image::ImageError) -> Self {
        match err {
            arcbox_image::ImageError::Common(c) => Self::Common(c),
            arcbox_image::ImageError::Image(msg) => Self::Image(msg),
        }
    }
}
