//! `VirtIO` network device (virtio-net).
//!
//! Implements the `VirtIO` network device for Ethernet connectivity.
//!
//! ## Module layout
//!
//! - `config`: `NetConfig`, `NetStatus`, `NetPort`
//! - `header`: `VirtioNetHeader` + `NetPacket` wire types
//! - `backend`: `NetBackend` trait + cross-platform `LoopbackBackend`
//! - `tap`: TAP backend (Linux only)
//! - `device`: `VirtioNet` device + `VirtioDevice` impl

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

mod backend;
mod config;
mod device;
mod header;
#[cfg(target_os = "linux")]
mod tap;

pub use backend::{LoopbackBackend, NetBackend};
pub use config::{NetConfig, NetPort, NetStatus};
pub use device::VirtioNet;
pub use header::{NetPacket, VirtioNetHeader};
#[cfg(target_os = "linux")]
pub use tap::TapBackend;
