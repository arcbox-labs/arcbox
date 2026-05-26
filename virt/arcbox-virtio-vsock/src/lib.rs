//! `VirtIO` socket device (virtio-vsock).
//!
//! Provides socket communication between host and guest without requiring
//! network configuration.
//!
//! On Darwin, the native VZ framework handles vsock. This implementation
//! is primarily used for the custom HV backend (Hypervisor.framework).
//!
//! ## Module layout
//!
//! - `addr`: `VsockAddr`, `VsockHostConnections` trait, well-known CIDs
//! - `protocol`: `VsockOp` enum + 44-byte `VsockHeader` wire format
//! - `connection`: `VsockConnection` + `ConnectionState` (in-process loopback)
//! - `backend`: `VsockBackend` trait + `LoopbackBackend`
//! - `tcp`: `TcpBackend`
//! - `host`: `HostVsockBackend` (Unix Hypervisor.framework path)
//! - `device`: `VsockConfig`, `VirtioVsock` device, `VirtioDevice` impl
//! - `manager`: connection manager (`VsockConnectionManager`, `RxOps`, …)

#![allow(clippy::ptr_as_ptr)]
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::useless_vec)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::missing_fields_in_debug)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::needless_collect)]
#![allow(mismatched_lifetime_syntaxes)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::too_many_arguments)]

mod addr;
mod backend;
mod connection;
mod device;
#[cfg(unix)]
mod host;
pub mod manager;
mod protocol;
mod tcp;

pub use addr::{VsockAddr, VsockHostConnections};
pub use backend::{LoopbackBackend, VsockBackend};
pub use connection::{ConnectionState, VsockConnection};
pub use device::{VirtioVsock, VsockConfig};
#[cfg(unix)]
pub use host::HostVsockBackend;
pub use protocol::{VsockHeader, VsockOp};
pub use tcp::TcpBackend;
