//! Proxy egress and inbound relay for the ArcBox datapath.
//!
//! Transport-agnostic building blocks that turn classified guest/host frames
//! into real network I/O, with no VM/VirtIO/device dependency:
//!
//! - [`proxy_tunnel`] — establishes a TCP tunnel to a destination via an
//!   upstream SOCKS5 or HTTP-CONNECT proxy, connecting by hostname so Fake-IP
//!   destinations resolve on the proxy's side.
//! - [`socket_proxy`] — proxies guest UDP/ICMP through real host sockets
//!   (bypassing kernel routing / VPN interference) and dispatches inbound
//!   datagrams via the [`inbound_relay`].
//! - [`inbound_relay`] — host → guest port forwarding by injecting crafted L2
//!   frames, plus the listener manager and `InboundCommand` channel.
//!
//! Extracted from `arcbox-net` so a host-level proxy can reuse the same egress
//! and relay machinery as the VM datapath.

pub mod inbound_relay;
pub mod proxy_tunnel;
pub mod socket_proxy;
