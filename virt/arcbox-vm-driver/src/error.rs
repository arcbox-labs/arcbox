//! The one error type every port method speaks.
//!
//! There is deliberately no `Unsupported` variant: a driver that cannot do
//! something says so through a capability accessor returning `None`, never
//! through an error at call time.

use crate::capability::CheckpointFormat;
use crate::driver::VmState;
use crate::spec::VmId;

/// Errors raised by drivers, handles, and the guest-network port.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A [`crate::VmSpec`] (or a piece of it) failed validation.
    #[error("invalid spec: {0}")]
    InvalidSpec(String),

    /// No VM with this id is known to the driver or network.
    #[error("vm {0} not found")]
    NotFound(VmId),

    /// The VM is in a state the operation cannot act on (dialing an exited
    /// VM, checkpointing one that already exited).
    #[error("vm {id} is {state}; expected {expected}")]
    WrongState {
        /// The VM.
        id: VmId,
        /// Where it actually is.
        state: VmState,
        /// What the operation needed, e.g. `"running"`.
        expected: &'static str,
    },

    /// A restore was asked of a checkpoint another driver (or another
    /// version of this one) wrote.
    #[error("checkpoint format {0} is not one this driver wrote")]
    ForeignCheckpoint(CheckpointFormat),

    /// The adapter itself failed: process spawn, API call, file staging.
    ///
    /// `driver` is the adapter's [`crate::VmDriver::name`]; `source` carries
    /// the underlying error when there is one worth chaining.
    #[error("driver `{driver}`: {message}")]
    Driver {
        /// The adapter that raised the error.
        driver: &'static str,
        /// What failed, in the adapter's words.
        message: String,
        /// The underlying error, if any.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// A host I/O failure surfaced unchanged.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The guest-network port refused or failed an operation.
    #[error("network: {0}")]
    Network(String),

    /// The operation cannot proceed yet, and retrying later is the remedy:
    /// a startup-cleanup gate still closed, a same-id cleanup the host has
    /// not finalized. Separate from [`Self::Network`] because a caller
    /// surfaces it as "unavailable, come back" rather than as a fault.
    #[error("unavailable: {0}")]
    Unavailable(String),

    /// A precondition the caller presented does not hold — a cleanup token
    /// naming another generation, or naming one that no longer exists.
    /// Retrying the same call never helps; the caller needs a current
    /// token. Separate from [`Self::WrongState`], which is about where a
    /// VM sits in its lifecycle.
    #[error("failed precondition: {0}")]
    PreconditionFailed(String),
}

/// `Result` specialised to this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
