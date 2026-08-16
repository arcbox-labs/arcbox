//! The one error type every port method speaks.
//!
//! There is deliberately no `Unsupported` variant: a driver that cannot do
//! something says so through a capability accessor returning `None`, never
//! through an error at call time.

use crate::spec::VmId;

/// Errors raised by drivers, handles, and the guest-network port.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A `VmSpec` (or a piece of it) failed validation.
    #[error("invalid spec: {0}")]
    InvalidSpec(String),

    /// No VM with this id is known to the driver or network.
    #[error("vm {0} not found")]
    NotFound(VmId),

    /// The adapter itself failed: process spawn, API call, file staging.
    ///
    /// `driver` is the adapter's `VmDriver::name`; `source` carries
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
}

/// `Result` specialised to this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
