//! What can go wrong inside the adapter, and how it reaches the port.
//!
//! The port speaks one [`Error`](arcbox_vm_driver::Error); an adapter's own
//! failures travel inside its [`Driver`](arcbox_vm_driver::Error::Driver)
//! variant. [`FcError`] is the typed vocabulary this crate uses internally
//! — spawn, API, staging, signalling — and [`From<FcError>`] is the one
//! place it is folded into the port's error, naming the driver and keeping
//! the original as the `source`.

use std::path::PathBuf;

use crate::NAME;

/// A failure inside the Firecracker adapter.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FcError {
    /// The VMM (or jailer) process could not be spawned, or its API socket
    /// did not appear within the configured wait.
    #[error("spawn firecracker: {0}")]
    Spawn(#[source] fc_sdk::Error),

    /// A Firecracker API call failed.
    #[error("firecracker api: {0}")]
    Api(#[source] fc_sdk::Error),

    /// Jailer isolation was asked for, but the driver config names no
    /// jailer binary.
    #[error("jailer isolation requested but no jailer binary is configured")]
    NoJailer,

    /// `chown` on a staged file, directory, or socket failed.
    #[error("chown {path}: {source}")]
    Chown {
        /// The path being handed to the jailed uid/gid.
        path: PathBuf,
        /// The underlying errno.
        #[source]
        source: nix::Error,
    },

    /// Signalling the VMM process failed.
    #[error("kill firecracker {pid}: {source}")]
    Kill {
        /// The VMM's pid.
        pid: u32,
        /// The underlying errno.
        #[source]
        source: nix::Error,
    },

    /// The VMM did not exit within the reap budget after `SIGKILL`.
    #[error("timed out reaping firecracker {pid}")]
    ReapTimeout {
        /// The VMM's pid.
        pid: u32,
    },
}

/// `Result` specialised to [`FcError`].
pub type Result<T> = std::result::Result<T, FcError>;

impl From<FcError> for arcbox_vm_driver::Error {
    /// Folds an adapter failure into the port's `Driver` variant: the driver
    /// name, the failure in this crate's words, and the typed error kept as
    /// the source.
    fn from(err: FcError) -> Self {
        Self::Driver {
            driver: NAME,
            message: err.to_string(),
            source: Some(Box::new(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    #[test]
    fn adapter_errors_reach_the_port_as_driver_errors_with_the_source_kept() {
        let port = arcbox_vm_driver::Error::from(FcError::ReapTimeout { pid: 42 });
        let arcbox_vm_driver::Error::Driver {
            driver,
            message,
            source,
        } = &port
        else {
            panic!("expected Error::Driver, got {port}");
        };
        assert_eq!(*driver, "firecracker");
        assert_eq!(message, "timed out reaping firecracker 42");
        let source = source.as_ref().expect("the FcError is kept as the source");
        assert!(
            source.downcast_ref::<FcError>().is_some(),
            "source is the typed FcError"
        );
        assert_eq!(
            port.to_string(),
            "driver `firecracker`: timed out reaping firecracker 42"
        );
        assert!(port.source().is_some());
    }
}
