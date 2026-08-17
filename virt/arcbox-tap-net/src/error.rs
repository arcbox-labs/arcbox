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
