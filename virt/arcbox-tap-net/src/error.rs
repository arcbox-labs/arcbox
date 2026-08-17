//! The crate's error type.
//!
//! The variants mirror the shapes the sandbox manager already classifies
//! for its wire codes — a token mismatch is `WrongState` (412 upstream), a
//! closed startup gate or a pending same-id cleanup is `Unavailable` (503,
//! retry later) — so both `From` impls below carry them across without a
//! reclassification: whether the manager reaches this network directly or
//! through the driver port, the answer keeps its code. Everything the TAP,
//! netlink, netfilter, and eBPF plumbing can fail with is `Network` with
//! the failing step in the message.

use thiserror::Error;

/// Errors raised by the TAP network.
#[derive(Debug, Error)]
pub enum TapNetError {
    /// TAP, netlink, netfilter, or eBPF plumbing failed, or a quarantine
    /// ledger record does not fit the configured network.
    #[error("network error: {0}")]
    Network(String),

    /// Host I/O failed (`/dev/net/tun`, `/proc`, the quarantine ledger).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A quarantine ledger record could not be encoded or decoded.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// A cleanup token names another generation, or there is no pending
    /// cleanup for the id.
    #[error("'{id}' is in wrong state: expected {expected}, got {actual}")]
    WrongState {
        /// The VM, or `startup` for the process-wide startup sweep.
        id: String,
        /// The generation the operation needed.
        expected: String,
        /// What was presented instead.
        actual: String,
    },

    /// The operation cannot proceed until host-side cleanup finalizes;
    /// retrying later is the remedy.
    #[error("service unavailable: {0}")]
    Unavailable(String),
}

/// `Result` specialised to this crate's [`TapNetError`].
pub type Result<T> = std::result::Result<T, TapNetError>;

/// Into the port's error, variant for variant where a shape exists: a
/// closed gate stays retry-later and a token mismatch stays a failed
/// precondition, so the 503 / 412 a caller answers with survives the port
/// boundary. The port's `WrongState` is about VM lifecycle state and
/// cannot carry the token mismatch, so [`TapNetError::WrongState`]'s three
/// fields collapse into the precondition message. `Io` keeps its shape,
/// and a ledger decode failure is a fault like any other `Network` one.
impl From<TapNetError> for arcbox_vm_driver::Error {
    fn from(err: TapNetError) -> Self {
        match err {
            TapNetError::Io(io) => Self::Io(io),
            TapNetError::Network(msg) => Self::Network(msg),
            TapNetError::Unavailable(msg) => Self::Unavailable(msg),
            wrong @ TapNetError::WrongState { .. } => Self::PreconditionFailed(wrong.to_string()),
            json @ TapNetError::Json(_) => Self::Network(json.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use arcbox_vm_driver::Error;

    use super::TapNetError as T;

    #[test]
    fn errors_keep_io_and_the_faults_land_on_network() {
        let io = Error::from(T::Io(std::io::Error::other("disk")));
        assert!(matches!(io, Error::Io(_)), "{io}");
        // A network failure's message is already the whole story.
        let network = Error::from(T::Network("TUNSETIFF vmtap0-2: EPERM".into()));
        assert!(
            matches!(&network, Error::Network(m) if m == "TUNSETIFF vmtap0-2: EPERM"),
            "{network}"
        );
        // A ledger that will not decode is a fault, not a protocol answer.
        let json = T::Json(serde_json::from_str::<u8>("x").unwrap_err());
        let text = json.to_string();
        let mapped = Error::from(json);
        assert!(
            matches!(&mapped, Error::Network(m) if *m == text),
            "{mapped}"
        );
    }

    /// The cleanup protocol's two answers keep their classification across
    /// the port: "come back later" and "that is not the token", which the
    /// callers above turn into 503 and 412.
    #[test]
    fn the_cleanup_protocols_answers_survive_the_port() {
        let gate = Error::from(T::Unavailable("startup cleanup pending".into()));
        assert!(
            matches!(&gate, Error::Unavailable(m) if m == "startup cleanup pending"),
            "{gate}"
        );
        let mismatch = Error::from(T::WrongState {
            id: "box".into(),
            expected: "cleanup token a".into(),
            actual: "b".into(),
        });
        let Error::PreconditionFailed(message) = &mismatch else {
            panic!("a token mismatch is a failed precondition, got {mismatch}");
        };
        // The three fields the port cannot carry stay readable in the text.
        assert!(
            message.contains("box") && message.contains("cleanup token a") && message.contains('b'),
            "{message}"
        );
    }
}
