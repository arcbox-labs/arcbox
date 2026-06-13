//! VirtIO-net backends bridging the ArcBox datapath to `arcbox-virtio`.
//!
//! This crate holds the only adapters that implement `arcbox-virtio`'s
//! `NetBackend` trait, keeping `arcbox-net` itself free of the device-model
//! dependency:
//!
//! - [`nat_backend`] — `NatNetBackend`: routes guest frames through the NAT
//!   engine (`arcbox-conntrack`) and a `HostNetIO` host interface.
//! - [`tso_backend`] — `TsoNetBackend`: a TSO fast path that relays large TCP
//!   segments directly to host `TcpStream`s, with a slow-path channel for
//!   everything else.

pub mod nat_backend;
pub mod tso_backend;
