//! # arcbox-net-advanced
//!
//! Advanced networking features for ArcBox Pro.
//!
//! This crate extends arcbox-net with:
//!
//! - **VPN awareness**: Auto-detect VPN and route traffic
//! - **Advanced DNS**: Split DNS, custom resolvers
//! - **Traffic shaping**: QoS and bandwidth limits
//! - **Network policies**: Fine-grained access control
//!
//! ## License
//!
//! This crate is licensed under BSL-1.1, which converts to MIT after 2 years.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
// TODO: Remove these allows once the module is complete.
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(clippy::nursery)]

pub mod dns;
pub mod vpn;

pub use dns::{DnsRecord, DnsRecordData, DnsResolver, DnsResponse, RecordType, SplitDnsResolver};
pub use vpn::{VpnDetector, VpnInterface, VpnType};

/// Advanced network configuration.
#[derive(Debug, Clone, Default)]
pub struct AdvancedNetConfig {
    /// Enable VPN awareness.
    pub vpn_aware: bool,
    /// Custom DNS servers.
    pub dns_servers: Vec<String>,
    /// Split DNS domains.
    pub split_dns: Vec<SplitDnsRule>,
}

/// Split DNS rule.
#[derive(Debug, Clone)]
pub struct SplitDnsRule {
    /// Domain suffix.
    pub domain: String,
    /// DNS servers for this domain.
    pub servers: Vec<String>,
}
