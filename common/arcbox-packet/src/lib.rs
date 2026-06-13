//! Zero-copy packet primitives for the ArcBox network datapath.
//!
//! Pure, transport-agnostic building blocks with no VM, VirtIO, or I/O
//! dependencies:
//!
//! - [`packet`] — zero-copy packet representation and header parsing.
//! - [`ethernet`] — Ethernet/ARP framing and TCP/UDP frame construction.
//! - [`checksum`] — Internet checksum routines (RFC 1071/1624), incremental
//!   NAT updates, and SIMD-accelerated variants.
//!
//! Extracted from `arcbox-net` so non-VM consumers (host-side proxies, packet
//! tools, tests) can reuse them without pulling in the hypervisor or device
//! stack.

pub mod checksum;
pub mod ethernet;
pub mod packet;
