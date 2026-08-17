//! The crate's error type.
//!
//! The variants mirror the shapes the sandbox manager already classifies
//! for its wire codes — a token mismatch is `WrongState` (412 upstream), a
//! closed startup gate or a pending same-id cleanup is `Unavailable` (503,
//! retry later) — so `arcbox-vm`'s `From` impl maps them variant for
//! variant. Everything the TAP, netlink, netfilter, and eBPF plumbing can
//! fail with is `Network` with the failing step in the message.

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

/// Into the port's error. `Io` keeps its shape and a `Network` message is
/// already the whole story; a closed gate, a token mismatch, or a ledger
/// decode failure keeps its classification in the text, because the port
/// has no retry-later or token-mismatch variant to carry it (its
/// `WrongState` is about VM lifecycle state).
impl From<TapNetError> for arcbox_vm_driver::Error {
    fn from(err: TapNetError) -> Self {
        match err {
            TapNetError::Io(io) => Self::Io(io),
            TapNetError::Network(msg) => Self::Network(msg),
            other @ (TapNetError::Json(_)
            | TapNetError::WrongState { .. }
            | TapNetError::Unavailable(_)) => Self::Network(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use arcbox_vm_driver::Error;

    use super::TapNetError as T;

    #[test]
    fn errors_keep_io_and_flatten_the_rest_into_network() {
        let io = Error::from(T::Io(std::io::Error::other("disk")));
        assert!(matches!(io, Error::Io(_)), "{io}");
        // A network failure's message is already the whole story.
        let network = Error::from(T::Network("TUNSETIFF vmtap0-2: EPERM".into()));
        assert!(
            matches!(&network, Error::Network(m) if m == "TUNSETIFF vmtap0-2: EPERM"),
            "{network}"
        );
        // Everything else keeps its classification in the text, since the
        // port has no retry-later or token-mismatch shape to carry it.
        for error in [
            T::Unavailable("gate".into()),
            T::WrongState {
                id: "box".into(),
                expected: "token a".into(),
                actual: "token b".into(),
            },
            T::Json(serde_json::from_str::<u8>("x").unwrap_err()),
        ] {
            let text = error.to_string();
            let mapped = Error::from(error);
            assert!(
                matches!(&mapped, Error::Network(m) if *m == text),
                "{mapped}"
            );
        }
    }
}
