//! Userspace TCP termination shim and frame plane for the ArcBox datapath.
//!
//! The pieces a frame-to-socket bridge needs, independent of any VM/VirtIO
//! device model:
//!
//! - [`classifier`] — demultiplexes inbound Ethernet frames (ARP / TCP-SYN /
//!   TCP / DHCP / DNS / UDP / ICMP). It is *fed* frames via
//!   [`FrameClassifier::classify_frame`] rather than owning an fd, so the
//!   ingest source is pluggable.
//! - [`frame_source`] — the [`FrameSource`] ingest seam (an fd to await for
//!   readiness plus a non-blocking `drain`) and [`FdFrameSource`], a raw-fd
//!   implementation used by both the VM (socketpair) and host (utun) datapaths.
//! - [`tcp_bridge`] — a hand-rolled TCP handshake synthesizer + fast-path data
//!   plane that terminates TCP without a full userspace stack.
//! - [`direct_rx`] — the [`FrameSink`](direct_rx::FrameSink) /
//!   [`ConnSink`](direct_rx::ConnSink) egress seams for host → guest injection.
//! - [`shim`] — an L3 ↔ L2 shim that wraps a host's `utun` IP packets in a
//!   synthetic Ethernet header so the L2 classifier and TCP shim run unmodified
//!   over an L3 link.
//! - [`utun`] (macOS) — a [`FrameSource`](frame_source::FrameSource) and sink
//!   over a host `utun` fd, stripping/prepending the device's 4-byte AF header.
//!
//! Extracted from `arcbox-net` so a host-level proxy can reuse the same TCP
//! termination and classification plane as the VM datapath.

pub mod classifier;
pub mod direct_rx;
pub mod egress;
mod fragment;
pub mod frame_source;
pub mod shim;
pub mod tcp_bridge;
#[cfg(target_os = "macos")]
pub mod utun;

pub use egress::{DefaultEgress, EgressConn, EgressResolver, FlowKey, FlowMeta, FlowObserver};
#[cfg(target_os = "macos")]
pub use frame_source::FdFrameSource;
pub use frame_source::FrameSource;

// `tcp_bridge` and `classifier` reference `crate::ethernet::*` pervasively;
// re-export `arcbox-packet`'s ethernet module here so those paths resolve
// unchanged within this crate (mirrors `arcbox-net`'s own re-export).
pub(crate) use arcbox_packet::ethernet;
