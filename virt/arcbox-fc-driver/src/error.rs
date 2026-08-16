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

    /// A path that should name a block device could not be inspected.
    #[error("stat {path}: {source}")]
    Stat {
        /// The path.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A disk to mirror as a device node is not a block device.
    #[error("{path} is not a block device")]
    NotBlockDevice {
        /// The path.
        path: PathBuf,
    },

    /// A block device carries a major or minor number outside `u32` — a
    /// corrupt node, not something to truncate.
    #[error("{path}: {what} {value} out of range")]
    BadDeviceNumber {
        /// The device node.
        path: PathBuf,
        /// `"major"` or `"minor"`.
        what: &'static str,
        /// The offending value.
        value: u64,
    },

    /// A block-device node could not be created in the jail.
    #[error("mknod {path}: {source}")]
    Mknod {
        /// The node being created.
        path: PathBuf,
        /// The underlying errno.
        #[source]
        source: nix::Error,
    },

    /// An operation this host cannot perform: block-device nodes and the
    /// jailer exist on Linux only.
    #[error("{what}: Linux-only")]
    LinuxOnly {
        /// What was asked for.
        what: String,
    },

    /// Connecting to Firecracker's hybrid-vsock Unix socket failed — the
    /// socket is missing or the VMM is not accepting; final, unlike a guest
    /// port with no listener yet.
    #[error("connect to {uds}: {source}")]
    VsockConnect {
        /// The Unix socket.
        uds: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The `CONNECT <port>` / `OK` handshake on the vsock Unix socket
    /// failed or answered something other than `OK`.
    #[error("vsock handshake on {uds}: {detail}")]
    VsockHandshake {
        /// The Unix socket.
        uds: PathBuf,
        /// What went wrong, in the handshake's terms.
        detail: String,
        /// The underlying I/O error, when there was one.
        #[source]
        source: Option<std::io::Error>,
    },

    /// A guest-dial-out listener socket could not be bound or accepted on.
    #[error("{what} {path}: {source}")]
    VsockListen {
        /// The step that failed.
        what: &'static str,
        /// The listener socket.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
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
