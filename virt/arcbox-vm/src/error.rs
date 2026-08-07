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

    /// Device-mapper / dm-snapshot error.
    #[error("device-mapper error: {0}")]
    DeviceMapper(String),

    /// Process lifecycle error.
    #[error("process error: {0}")]
    Process(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Vsock / guest-agent communication error.
    #[error("vsock error: {0}")]
    Vsock(String),

    /// A retryable operation whose durable result could not be confirmed.
    #[error("service unavailable: {0}")]
    Unavailable(String),

    /// The operation's side effects committed — the sandbox exists and is
    /// running — but the acknowledging record's durability is unconfirmed.
    /// Distinct from [`VmmError::Unavailable`] so callers with a fallback
    /// (warm create) can tell "nothing happened, retry freely" from "it
    /// happened, do NOT re-execute".
    #[error("sandbox {id} committed, but ACK durability is unconfirmed: {detail}")]
    AckUnconfirmed {
        /// The sandbox whose operation committed.
        id: String,
        /// The underlying durability failure.
        detail: String,
    },

    /// A stdin write starts past the accepted byte count — the caller must
    /// resume from `accepted` (its offsets have a gap).
    #[error("stdin offset {offset} is past the {accepted} accepted bytes")]
    StdinGap {
        /// Bytes accepted so far — the offset the next write must start at.
        accepted: u64,
        /// The rejected write's offset.
        offset: u64,
    },

    /// Generic catch-all error.
    #[error("{0}")]
    Other(String),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, VmmError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_not_found_display() {
        let e = VmmError::NotFound("vm-123".into());
        assert_eq!(e.to_string(), "VM not found: vm-123");
    }

    #[test]
    fn test_already_exists_display() {
        let e = VmmError::AlreadyExists("my-vm".into());
        assert_eq!(e.to_string(), "VM already exists: my-vm");
    }

    #[test]
    fn test_wrong_state_display() {
        let e = VmmError::WrongState {
            id: "vm-1".into(),
            expected: "running".into(),
            actual: "stopped".into(),
        };
        let s = e.to_string();
        assert!(s.contains("vm-1"));
        assert!(s.contains("running"));
        assert!(s.contains("stopped"));
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let vmm_err = VmmError::from(io_err);
        assert!(matches!(vmm_err, VmmError::Io(_)));
        assert!(vmm_err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_network_error_display() {
        let e = VmmError::Network("TAP creation failed".into());
        assert_eq!(e.to_string(), "network error: TAP creation failed");
    }
}
