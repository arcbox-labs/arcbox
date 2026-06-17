//! Proxy egress and inbound relay for the ArcBox datapath.
//!
//! Transport-agnostic building blocks that turn classified guest/host frames
//! into real network I/O, with no VM/VirtIO/device dependency:
//!
//! - [`socks5`] — all SOCKS5 (RFC 1928): the shared address codec, the CONNECT
//!   tunnel client ([`socks5::connect_via_socks5`]), and the UDP-ASSOCIATE client
//!   ([`socks5::Socks5UdpAssociation`]), connecting by hostname so Fake-IP
//!   destinations resolve on the proxy's side.
//! - [`http_connect`] — the HTTP CONNECT tunnel client.
//! - [`egress`] — proxies guest UDP/ICMP through real host sockets (bypassing
//!   kernel routing / VPN interference), optionally via the SOCKS5 proxy, and
//!   dispatches inbound datagrams through the [`inbound_relay`].
//! - [`inbound_relay`] — host → guest port forwarding by injecting crafted L2
//!   frames, plus the listener manager and `InboundCommand` channel.
//!
//! Extracted from `arcbox-net` so a host-level proxy can reuse the same egress
//! and relay machinery as the VM datapath.

pub mod egress;
pub mod http_connect;
pub mod inbound_relay;
pub mod socks5;
