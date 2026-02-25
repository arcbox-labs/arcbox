use thiserror::Error;

/// Core VMM error type.
#[derive(Debug, Error)]
pub enum VmmError {
    /// The requested VM was not found.
    #[error("VM not found: {0}")]
    NotFound(String),

    /// A VM with the given name already exists.
    #[error("VM already exists: {0}")]
    AlreadyExists(String),

    /// The VM is not in a state that allows the requested operation.
    #[error("VM '{id}' is in wrong state: expected {expected}, got {actual}")]
    WrongState {
        id: String,
        expected: String,
        actual: String,
    },

    /// I/O error (file system, sockets, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialisation/deserialisation error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Error from the Firecracker SDK.
    #[error("fc-sdk error: {0}")]
    Sdk(#[from] fc_sdk::Error),

    /// Network-related error (TAP creation, IP allocation, etc.).
    #[error("network error: {0}")]
    Network(String),

    /// Snapshot catalog error.
    #[error("snapshot error: {0}")]
    Snapshot(String),

    /// Process lifecycle error.
    #[error("process error: {0}")]
    Process(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Generic catch-all error.
    #[error("{0}")]
    Other(String),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, VmmError>;
