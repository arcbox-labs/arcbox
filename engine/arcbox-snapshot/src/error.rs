//! Error type for the snapshot layer.

use arcbox_error::CommonError;
use thiserror::Error;

/// Result type alias for snapshot operations.
pub type Result<T> = std::result::Result<T, SnapshotError>;

/// Errors from the snapshot catalog, the copy-on-write rootfs manager,
/// and the template catalog.
///
/// The variants below `Common` are the ones callers match on rather than
/// print: the daemon maps `TemplateNotFound` and `TemplateVersionExists`
/// onto their own wire codes, so folding them into `CommonError::NotFound`
/// / `AlreadyExists` would lose the distinction at the boundary.
#[derive(Debug, Error)]
pub enum SnapshotError {
    /// Common errors (I/O, config, not found, ...).
    #[error(transparent)]
    Common(#[from] CommonError),

    /// Snapshot creation, load, or catalog bookkeeping failed.
    #[error("snapshot error: {0}")]
    Snapshot(String),

    /// A device-mapper operation (`dmsetup`, thin pool, snapshot target)
    /// failed.
    #[error("device-mapper error: {0}")]
    DeviceMapper(String),

    /// No template with that name (or name@version) is in the catalog.
    #[error("template not found: {0}")]
    TemplateNotFound(String),

    /// The requested template version is already published, and versions
    /// are immutable once built.
    #[error("template version already exists: {0}")]
    TemplateVersionExists(String),

    /// The operation's precondition does not hold (a template still has
    /// pins, a snapshot is not in a loadable state, ...).
    #[error("failed precondition: {0}")]
    FailedPrecondition(String),

    /// A retryable operation whose durable result could not be confirmed.
    #[error("service unavailable: {0}")]
    Unavailable(String),
}

impl SnapshotError {
    /// Creates a configuration error.
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Common(CommonError::config(msg))
    }

    /// Creates a not-found error for a non-template resource.
    #[must_use]
    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::Common(CommonError::not_found(resource))
    }
}

// Matches the convention in the other engine-layer crates: an io::Error
// converts through `CommonError` so `?` works on filesystem calls.
impl From<std::io::Error> for SnapshotError {
    fn from(err: std::io::Error) -> Self {
        Self::Common(CommonError::Io(err))
    }
}

impl From<serde_json::Error> for SnapshotError {
    fn from(err: serde_json::Error) -> Self {
        Self::Snapshot(format!("JSON error: {err}"))
    }
}

/// A durable write that never landed is I/O; one that landed without a
/// confirmed rename is [`SnapshotError::Unavailable`] — retryable, and the
/// retry is safe because these writes are idempotent.
impl From<arcbox_atomic_file::AtomicWriteError> for SnapshotError {
    fn from(err: arcbox_atomic_file::AtomicWriteError) -> Self {
        use arcbox_atomic_file::AtomicWriteError;
        match err {
            AtomicWriteError::NotCommitted { source, .. } => Self::Common(CommonError::Io(source)),
            error @ AtomicWriteError::DurabilityUncertain { .. } => {
                Self::Unavailable(error.to_string())
            }
        }
    }
}
