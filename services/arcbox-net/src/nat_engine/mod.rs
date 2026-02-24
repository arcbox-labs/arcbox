//! High-performance NAT engine.
//!
//! This module provides a high-performance Network Address Translation (NAT)
//! engine optimized for low latency and high throughput.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     High-Performance NAT Engine                  │
//! │                                                                  │
//! │  ┌────────────────────────────────────────────────────────────┐ │
//! │  │                     Fast Path Cache                         │ │
//! │  │  [256 entries, direct index by flow hash]                   │ │
//! │  │  Hit rate target: >95%                                      │ │
//! │  └────────────────────────────────────────────────────────────┘ │
//! │                              │                                   │
//! │                    miss      │      hit                          │
//! │                      ↓       ↓                                   │
//! │  ┌────────────────────────────────────────────────────────────┐ │
//! │  │               Connection Tracking Table                      │ │
//! │  │  [Swiss Table HashMap, lock-free lookups]                   │ │
//! │  │  - Outbound: src_ip:src_port → nat_ip:nat_port              │ │
//! │  │  - Inbound:  nat_ip:nat_port → orig_ip:orig_port            │ │
//! │  └────────────────────────────────────────────────────────────┘ │
//! │                              │                                   │
//! │                              ↓                                   │
//! │  ┌────────────────────────────────────────────────────────────┐ │
//! │  │                  Packet Translation                          │ │
//! │  │  - Modify IP headers (zero-copy in place)                   │ │
//! │  │  - Incremental checksum update (RFC 1624)                   │ │
//! │  └────────────────────────────────────────────────────────────┘ │
//! │                                                                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Performance Targets
//!
//! - NAT throughput: >30 Mpps (million packets per second)
//! - Fast path latency: <100ns per packet
//! - Connection tracking: O(1) lookup
//! - Incremental checksum: <10ns per update

pub mod checksum;
pub mod conntrack;
pub mod translate;

pub use checksum::{checksum_fold, incremental_checksum_update};
pub use conntrack::{ConnState, ConnTrackEntry, ConnTrackKey, ConnTrackTable, FastCacheEntry};
pub use translate::{NatDirection, NatEngine, NatResult, TranslateError};

use std::net::Ipv4Addr;

/// NAT engine configuration.
#[derive(Debug, Clone)]
pub struct NatEngineConfig {
    /// External IP address for SNAT.
    pub external_ip: Ipv4Addr,
    /// Port range start for NAT ports.
    pub port_range_start: u16,
    /// Port range end for NAT ports.
    pub port_range_end: u16,
    /// Connection tracking table size.
    pub conntrack_size: usize,
    /// Connection timeout in seconds.
    pub connection_timeout_secs: u32,
    /// Enable fast path cache.
    pub enable_fast_cache: bool,
    /// Fast cache size (must be power of 2).
    pub fast_cache_size: usize,
}

impl Default for NatEngineConfig {
    fn default() -> Self {
        Self {
            external_ip: Ipv4Addr::new(192, 168, 64, 1),
            port_range_start: 49152,
            port_range_end: 65535,
            conntrack_size: 65536,
            connection_timeout_secs: 300, // 5 minutes
            enable_fast_cache: true,
            fast_cache_size: 256,
        }
    }
}

impl NatEngineConfig {
    /// Creates a new configuration with the specified external IP.
    #[must_use]
    pub fn new(external_ip: Ipv4Addr) -> Self {
        Self {
            external_ip,
            ..Default::default()
        }
    }

    /// Sets the port range.
    #[must_use]
    pub fn with_port_range(mut self, start: u16, end: u16) -> Self {
        self.port_range_start = start;
        self.port_range_end = end;
        self
    }

    /// Sets the connection timeout.
    #[must_use]
    pub fn with_timeout(mut self, secs: u32) -> Self {
        self.connection_timeout_secs = secs;
        self
    }

    /// Disables the fast path cache.
    #[must_use]
    pub fn without_fast_cache(mut self) -> Self {
        self.enable_fast_cache = false;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NatEngineConfig::default();
        assert_eq!(config.external_ip, Ipv4Addr::new(192, 168, 64, 1));
        assert_eq!(config.port_range_start, 49152);
        assert_eq!(config.port_range_end, 65535);
        assert!(config.enable_fast_cache);
    }

    #[test]
    fn test_config_builder() {
        let config = NatEngineConfig::new(Ipv4Addr::new(10, 0, 0, 1))
            .with_port_range(10000, 20000)
            .with_timeout(600)
            .without_fast_cache();

        assert_eq!(config.external_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(config.port_range_start, 10000);
        assert_eq!(config.port_range_end, 20000);
        assert_eq!(config.connection_timeout_secs, 600);
        assert!(!config.enable_fast_cache);
    }
}
