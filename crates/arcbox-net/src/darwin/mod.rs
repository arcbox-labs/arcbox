//! macOS Darwin network implementation.
//!
//! This module provides macOS-specific networking functionality using
//! Virtualization.framework and vmnet.framework.
//!
//! # Architecture
//!
//! On macOS, we leverage Apple's virtualization frameworks:
//!
//! - **Virtualization.framework**: High-level VM network attachment
//!   (VZNATNetworkDeviceAttachment, VZBridgedNetworkDeviceAttachment)
//! - **vmnet.framework**: Low-level packet I/O (for advanced use cases)
//!
//! # Network Modes
//!
//! - **NAT (Shared)**: VMs share host's network connection via NAT
//! - **Host-Only**: VMs can only communicate with host
//! - **Bridged**: VMs appear as separate devices on the network

pub mod nat;

pub use nat::DarwinNatNetwork;

use std::net::Ipv4Addr;

use crate::error::Result;
use crate::nat::NatConfig;

/// Darwin network configuration.
#[derive(Debug, Clone)]
pub struct DarwinNetConfig {
    /// Network mode.
    pub mode: DarwinNetMode,
    /// NAT configuration (for NAT mode).
    pub nat_config: Option<NatConfig>,
    /// Bridge interface (for bridged mode).
    pub bridge_interface: Option<String>,
    /// Enable high-performance datapath.
    pub high_performance: bool,
}

impl Default for DarwinNetConfig {
    fn default() -> Self {
        Self {
            mode: DarwinNetMode::Nat,
            nat_config: Some(NatConfig::default()),
            bridge_interface: None,
            high_performance: true,
        }
    }
}

/// Darwin network mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DarwinNetMode {
    /// NAT mode (shared network).
    #[default]
    Nat,
    /// Host-only mode.
    HostOnly,
    /// Bridged mode.
    Bridged,
}

/// Darwin network endpoint representing a VM's network connection.
#[derive(Debug)]
pub struct DarwinNetEndpoint {
    /// Endpoint ID.
    pub id: String,
    /// MAC address.
    pub mac: [u8; 6],
    /// Assigned IP address.
    pub ip: Option<Ipv4Addr>,
    /// Network mode.
    pub mode: DarwinNetMode,
}

impl DarwinNetEndpoint {
    /// Creates a new endpoint.
    #[must_use]
    pub fn new(id: String, mac: [u8; 6], mode: DarwinNetMode) -> Self {
        Self {
            id,
            mac,
            ip: None,
            mode,
        }
    }

    /// Sets the IP address.
    pub fn set_ip(&mut self, ip: Ipv4Addr) {
        self.ip = Some(ip);
    }
}

/// Generates a random MAC address with the locally administered bit set.
#[must_use]
pub fn generate_mac() -> [u8; 6] {
    use std::time::{SystemTime, UNIX_EPOCH};

    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    // Simple PRNG
    let mut state = seed;
    let mut mac = [0u8; 6];

    for byte in &mut mac {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *byte = (state >> 32) as u8;
    }

    // Set locally administered bit and clear multicast bit
    mac[0] = (mac[0] & 0xFC) | 0x02;

    mac
}

/// Formats a MAC address as a string.
#[must_use]
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Parses a MAC address from a string.
///
/// # Errors
///
/// Returns an error if the string is not a valid MAC address.
pub fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(crate::error::NetError::Config(
            "invalid MAC address format".to_string(),
        ));
    }

    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).map_err(|_| {
            crate::error::NetError::Config("invalid MAC address byte".to_string())
        })?;
    }

    Ok(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mac() {
        let mac1 = generate_mac();

        // Add a small delay to ensure different nanosecond timestamp
        std::thread::sleep(std::time::Duration::from_micros(1));

        let mac2 = generate_mac();

        // Should be locally administered (bit 1 of first byte set)
        assert_eq!(mac1[0] & 0x02, 0x02);
        // Should not be multicast (bit 0 of first byte clear)
        assert_eq!(mac1[0] & 0x01, 0x00);

        // Two generated MACs should be different (with high probability)
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_format_mac() {
        let mac = [0x02, 0xAB, 0xCD, 0xEF, 0x12, 0x34];
        assert_eq!(format_mac(&mac), "02:ab:cd:ef:12:34");
    }

    #[test]
    fn test_parse_mac() {
        let mac = parse_mac("02:ab:cd:ef:12:34").unwrap();
        assert_eq!(mac, [0x02, 0xAB, 0xCD, 0xEF, 0x12, 0x34]);
    }

    #[test]
    fn test_parse_mac_invalid() {
        assert!(parse_mac("invalid").is_err());
        assert!(parse_mac("02:ab:cd:ef:12").is_err()); // Too short
        assert!(parse_mac("02:ab:cd:ef:12:34:56").is_err()); // Too long
        assert!(parse_mac("02:ab:cd:ef:12:gg").is_err()); // Invalid hex
    }

    #[test]
    fn test_roundtrip_mac() {
        let original = [0x02, 0xAB, 0xCD, 0xEF, 0x12, 0x34];
        let formatted = format_mac(&original);
        let parsed = parse_mac(&formatted).unwrap();
        assert_eq!(original, parsed);
    }
}
