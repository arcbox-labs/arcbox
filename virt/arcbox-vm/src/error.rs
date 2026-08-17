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

    /// The sandbox is paused. Distinct from [`Self::WrongState`] so callers
    /// (the daemon's transparent auto-resume, CORE-21) can recognise
    /// "paused" machine-readably instead of parsing state strings.
    #[error("sandbox '{0}' is paused")]
    Paused(String),

    /// I/O error (file system, sockets, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialisation/deserialisation error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The VM driver — the port's adapter, or a capability reached through
    /// it — failed in a way that has no native shape here (an adapter
    /// fault, a foreign checkpoint). The port's `NotFound`, `WrongState`,
    /// `Io`, `Network` and `InvalidSpec` land on their native variants
    /// instead (see the `From` impl), so the guest agent's wire mapping
    /// keeps answering 404 / 412 for them rather than 500.
    #[error("driver error: {0}")]
    Driver(#[source] arcbox_vm_driver::Error),

    /// Network-related error (TAP creation, IP allocation, etc.).
    #[error("network error: {0}")]
    Network(String),

    /// Snapshot catalog error.
    #[error("snapshot error: {0}")]
    Snapshot(String),

    /// Device-mapper / dm-snapshot error.
    #[error("device-mapper error: {0}")]
    DeviceMapper(String),

    /// Building a sandbox rootfs image (OCI/overlay2 → ext4, vm-agent
    /// injection, the default busybox image) failed.
    #[error("rootfs error: {0}")]
    Rootfs(String),

    /// Process lifecycle error.
    #[error("process error: {0}")]
    Process(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Vsock / guest-agent communication error.
    #[error("vsock error: {0}")]
    Vsock(String),

    /// A path inside a sandbox does not exist. The message shape is a
    /// contract: the daemon's error classifier keys on the "path not
    /// found:" prefix to attach the `FILE_NOT_FOUND` registry code.
    #[error("path not found: {0}")]
    PathNotFound(String),

    /// A directory operation addressed a non-directory path.
    #[error("not a directory: {0}")]
    NotADirectory(String),

    /// Refused to remove a non-empty directory without `recursive`
    /// (`FAILED_PRECONDITION` per the filesystem contract).
    #[error("directory not empty: {0}")]
    DirectoryNotEmpty(String),

    /// A catalog template reference did not resolve. The message shape is a
    /// contract: the daemon's classifier keys on the "template not found:"
    /// prefix to attach the `TEMPLATE_NOT_FOUND` registry code (CORE-107).
    #[error("template not found: {0}")]
    TemplateNotFound(String),

    /// Publishing would repoint an existing immutable template version at
    /// different content (409 on the daemon surface).
    #[error("template version already exists: {0}")]
    TemplateVersionExists(String),

    /// A required precondition does not hold and retrying the same request
    /// never helps (`FAILED_PRECONDITION` on the daemon surface).
    #[error("failed precondition: {0}")]
    FailedPrecondition(String),

    /// A bounded wait elapsed before the awaited condition held
    /// (`DEADLINE_EXCEEDED` on the daemon surface).
    #[error("deadline exceeded: {0}")]
    DeadlineExceeded(String),

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

/// Variant-for-variant, so a snapshot or template failure keeps the exact
/// shape callers already match on — the daemon maps `TemplateNotFound`
/// and `TemplateVersionExists` onto their own wire codes, and folding
/// either into a generic error would change the surface.
impl From<arcbox_snapshot::SnapshotError> for VmmError {
    fn from(err: arcbox_snapshot::SnapshotError) -> Self {
        use arcbox_error::CommonError;
        use arcbox_snapshot::SnapshotError as S;
        match err {
            S::Common(CommonError::Io(io)) => Self::Io(io),
            S::Common(CommonError::Config(msg)) => Self::Config(msg),
            S::Common(CommonError::NotFound(msg)) => Self::NotFound(msg),
            S::Common(CommonError::AlreadyExists(msg)) => Self::AlreadyExists(msg),
            S::Common(other) => Self::Other(other.to_string()),
            S::Snapshot(msg) => Self::Snapshot(msg),
            S::DeviceMapper(msg) => Self::DeviceMapper(msg),
            S::TemplateNotFound(msg) => Self::TemplateNotFound(msg),
            S::TemplateVersionExists(msg) => Self::TemplateVersionExists(msg),
            S::FailedPrecondition(msg) => Self::FailedPrecondition(msg),
            S::Unavailable(msg) => Self::Unavailable(msg),
        }
    }
}

/// Variant-for-variant where a native shape exists, so a driver-reported
/// `NotFound` or `WrongState` keeps the wire code the equivalent native
/// error already has (the guest agent classifies `VmmError` by variant;
/// anything it does not know becomes a 500). What has no native shape —
/// an adapter fault, a checkpoint another driver wrote — stays
/// [`VmmError::Driver`] with the port error intact for its `source` chain.
impl From<arcbox_vm_driver::Error> for VmmError {
    fn from(err: arcbox_vm_driver::Error) -> Self {
        use arcbox_vm_driver::Error as D;
        match err {
            D::NotFound(id) => Self::NotFound(id.to_string()),
            D::WrongState {
                id,
                state,
                expected,
            } => Self::WrongState {
                id: id.to_string(),
                expected: expected.to_string(),
                actual: state.to_string(),
            },
            D::Io(io) => Self::Io(io),
            D::Network(msg) => Self::Network(msg),
            D::InvalidSpec(msg) => Self::Config(msg),
            other @ (D::Driver { .. } | D::ForeignCheckpoint(_)) => Self::Driver(other),
        }
    }
}

/// Variant-for-variant: the TAP network's `WrongState` (a cleanup token
/// naming another generation) and `Unavailable` (a closed startup gate, a
/// same-id cleanup still pending) are what the guest agent classifies as
/// 412 and 503, and folding either into `Network` would turn them into
/// 500s. `Io` and `Json` keep their native shapes for the same reason.
impl From<arcbox_tap_net::TapNetError> for VmmError {
    fn from(err: arcbox_tap_net::TapNetError) -> Self {
        use arcbox_tap_net::TapNetError as T;
        match err {
            T::Network(msg) => Self::Network(msg),
            T::Io(io) => Self::Io(io),
            T::Json(json) => Self::Json(json),
            T::WrongState {
                id,
                expected,
                actual,
            } => Self::WrongState {
                id,
                expected,
                actual,
            },
            T::Unavailable(msg) => Self::Unavailable(msg),
        }
    }
}

/// A durable write that never landed is an I/O failure; one that landed
/// without a confirmed rename is [`VmmError::Unavailable`] — the caller
/// may retry, and the retry is safe because the write is idempotent.
///
/// Callers that can do better than this (the sandbox record store keeps
/// the record and warns) match on [`AtomicWriteError`] themselves instead
/// of going through here.
impl From<arcbox_atomic_file::AtomicWriteError> for VmmError {
    fn from(err: arcbox_atomic_file::AtomicWriteError) -> Self {
        use arcbox_atomic_file::AtomicWriteError;
        match err {
            AtomicWriteError::NotCommitted { source, .. } => Self::Io(source),
            error @ AtomicWriteError::DurabilityUncertain { .. } => {
                Self::Unavailable(error.to_string())
            }
        }
    }
}

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
