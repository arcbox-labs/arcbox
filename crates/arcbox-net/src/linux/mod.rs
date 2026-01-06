//! Linux-specific network infrastructure.
//!
//! This module provides Linux-specific implementations for:
//!
//! - **Bridge**: Linux bridge creation and management
//! - **TAP**: TAP device creation and management
//! - **Netlink**: Netlink socket operations for network configuration
//! - **Firewall**: iptables/nftables rule management
//!
//! All types in this module require `target_os = "linux"`.

pub mod bridge;
pub mod firewall;
pub mod netlink;
pub mod tap;

pub use bridge::{BridgeConfig, LinuxBridge};
pub use firewall::{DnatRule, FirewallBackend, LinuxFirewall, NatRule, NatType, Protocol};
pub use netlink::{LinkConfig, LinkType, NetlinkHandle, Route};
pub use tap::{LinuxTap, TapConfig};
