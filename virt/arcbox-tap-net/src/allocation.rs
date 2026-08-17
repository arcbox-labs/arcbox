//! The per-VM allocation record: what `reserve` hands out and what the
//! quarantine ledger and the sandbox record persist.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// Default prefix length for backwards-compatible deserialization of records
/// that predate the `prefix_len` field.
const fn default_prefix_len() -> u8 {
    16
}

/// Result of allocating network resources for a single VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAllocation {
    /// TAP interface name (e.g. `vmtap0`).
    pub tap_name: String,
    /// IP address assigned to the guest.
    pub ip_address: Ipv4Addr,
    /// Network prefix length (e.g. 16 for /16).
    #[serde(default = "default_prefix_len")]
    pub prefix_len: u8,
    /// Gateway IP.
    pub gateway: Ipv4Addr,
    /// MAC address (deterministic from VM ID).
    pub mac_address: String,
    /// DNS servers.
    pub dns_servers: Vec<String>,
    /// Opaque generation token carried through host cleanup finalization.
    #[serde(default)]
    pub cleanup_token: String,
}

impl NetworkAllocation {
    /// Return the subnet mask as an `Ipv4Addr` (e.g. prefix_len 16 → 255.255.0.0).
    ///
    /// Values above 32 are clamped to 32 to avoid shift overflow.
    pub fn netmask(&self) -> Ipv4Addr {
        let p = self.prefix_len.min(32);
        if p == 0 {
            Ipv4Addr::UNSPECIFIED
        } else {
            Ipv4Addr::from(!0u32 << (32 - p))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netmask_slash0() {
        let alloc = NetworkAllocation {
            tap_name: String::new(),
            ip_address: Ipv4Addr::UNSPECIFIED,
            prefix_len: 0,
            gateway: Ipv4Addr::UNSPECIFIED,
            mac_address: String::new(),
            dns_servers: vec![],
            cleanup_token: String::new(),
        };
        assert_eq!(alloc.netmask(), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn test_netmask_slash8() {
        let alloc = NetworkAllocation {
            tap_name: String::new(),
            ip_address: Ipv4Addr::UNSPECIFIED,
            prefix_len: 8,
            gateway: Ipv4Addr::UNSPECIFIED,
            mac_address: String::new(),
            dns_servers: vec![],
            cleanup_token: String::new(),
        };
        assert_eq!(alloc.netmask(), Ipv4Addr::new(255, 0, 0, 0));
    }

    #[test]
    fn test_netmask_slash16() {
        let alloc = NetworkAllocation {
            tap_name: String::new(),
            ip_address: Ipv4Addr::UNSPECIFIED,
            prefix_len: 16,
            gateway: Ipv4Addr::UNSPECIFIED,
            mac_address: String::new(),
            dns_servers: vec![],
            cleanup_token: String::new(),
        };
        assert_eq!(alloc.netmask(), Ipv4Addr::new(255, 255, 0, 0));
    }

    #[test]
    fn test_netmask_slash24() {
        let alloc = NetworkAllocation {
            tap_name: String::new(),
            ip_address: Ipv4Addr::UNSPECIFIED,
            prefix_len: 24,
            gateway: Ipv4Addr::UNSPECIFIED,
            mac_address: String::new(),
            dns_servers: vec![],
            cleanup_token: String::new(),
        };
        assert_eq!(alloc.netmask(), Ipv4Addr::new(255, 255, 255, 0));
    }

    #[test]
    fn test_netmask_slash30() {
        let alloc = NetworkAllocation {
            tap_name: String::new(),
            ip_address: Ipv4Addr::UNSPECIFIED,
            prefix_len: 30,
            gateway: Ipv4Addr::UNSPECIFIED,
            mac_address: String::new(),
            dns_servers: vec![],
            cleanup_token: String::new(),
        };
        assert_eq!(alloc.netmask(), Ipv4Addr::new(255, 255, 255, 252));
    }

    #[test]
    fn test_netmask_slash32() {
        let alloc = NetworkAllocation {
            tap_name: String::new(),
            ip_address: Ipv4Addr::UNSPECIFIED,
            prefix_len: 32,
            gateway: Ipv4Addr::UNSPECIFIED,
            mac_address: String::new(),
            dns_servers: vec![],
            cleanup_token: String::new(),
        };
        assert_eq!(alloc.netmask(), Ipv4Addr::BROADCAST);
    }

    #[test]
    fn test_netmask_out_of_range_clamps_to_32() {
        let alloc = NetworkAllocation {
            tap_name: String::new(),
            ip_address: Ipv4Addr::UNSPECIFIED,
            prefix_len: 33,
            gateway: Ipv4Addr::UNSPECIFIED,
            mac_address: String::new(),
            dns_servers: vec![],
            cleanup_token: String::new(),
        };
        // prefix_len 33 should clamp to /32 → 255.255.255.255
        assert_eq!(alloc.netmask(), Ipv4Addr::BROADCAST);
    }
}
