//! Fake-IP plumbing for ArcBox's proxy-aware datapath.
//!
//! Two portable building blocks, free of any VM/VirtIO/device dependency:
//!
//! - [`dns_log`] — a thread-safe IP → domain resolution log. The datapath's
//!   DNS handler records `(domain, ips)` from upstream A records; the TCP shim
//!   reads it to recover the original hostname for a Fake-IP destination so it
//!   can tunnel by name (HTTP CONNECT / SOCKS5) instead of by virtual IP.
//! - [`proxy_detect`] — detection of the host's proxy/VPN environment (system
//!   proxy, Fake-IP range, bypass list). The `scutil`/`ifconfig` probes are
//!   `cfg`-gated to macOS; elsewhere `detect()` falls back to env vars so the
//!   crate stays useful (and compiles) on every target.
//!
//! Extracted from `arcbox-net` so a host-level proxy can share the same
//! Fake-IP machinery as the VM datapath.

pub mod dns_log;
pub mod proxy_detect;
