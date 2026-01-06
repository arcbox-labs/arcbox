//! Linux bridge management.
//!
//! This module provides functionality for creating and managing Linux bridge
//! interfaces. Bridges are used to connect multiple TAP devices together,
//! enabling VM-to-VM and VM-to-host communication.

use std::collections::HashSet;

use ipnetwork::Ipv4Network;

use super::netlink::{LinkConfig, LinkType, NetlinkHandle};
use crate::error::{NetError, Result};

/// Default bridge name for ArcBox.
pub const DEFAULT_BRIDGE_NAME: &str = "arcbox0";

/// Default MTU for bridge interfaces.
pub const DEFAULT_MTU: u16 = 1500;

/// Linux bridge configuration.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Bridge interface name (e.g., "arcbox0").
    pub name: String,
    /// IP address with prefix length (e.g., "192.168.64.1/24").
    pub ip_addr: Option<Ipv4Network>,
    /// MTU size.
    pub mtu: u16,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            name: DEFAULT_BRIDGE_NAME.to_string(),
            ip_addr: None,
            mtu: DEFAULT_MTU,
        }
    }
}

impl BridgeConfig {
    /// Creates a new bridge configuration with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    /// Sets the IP address.
    #[must_use]
    pub fn with_ip(mut self, ip: Ipv4Network) -> Self {
        self.ip_addr = Some(ip);
        self
    }

    /// Sets the MTU.
    #[must_use]
    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }
}

/// Linux bridge manager.
///
/// Manages the creation, configuration, and deletion of Linux bridge interfaces.
/// Uses netlink for configuration instead of shell commands for better
/// performance and error handling.
///
/// # Example
///
/// ```no_run
/// use arcbox_net::linux::{BridgeConfig, LinuxBridge};
/// use ipnetwork::Ipv4Network;
///
/// let config = BridgeConfig::new("arcbox0")
///     .with_ip("192.168.64.1/24".parse().unwrap())
///     .with_mtu(1500);
///
/// let mut bridge = LinuxBridge::new(config).unwrap();
/// bridge.create().unwrap();
/// bridge.bring_up().unwrap();
///
/// // Add TAP devices to the bridge
/// bridge.add_interface("tap0").unwrap();
///
/// // Cleanup
/// bridge.delete().unwrap();
/// ```
pub struct LinuxBridge {
    /// Bridge configuration.
    config: BridgeConfig,
    /// Netlink socket handle.
    netlink: NetlinkHandle,
    /// Bridge interface index (set after creation).
    ifindex: Option<u32>,
    /// Attached interfaces.
    attached_interfaces: HashSet<String>,
}

impl LinuxBridge {
    /// Creates a new Linux bridge manager.
    ///
    /// Note: This does not create the bridge interface yet. Call `create()` to
    /// actually create the interface.
    ///
    /// # Errors
    ///
    /// Returns an error if the netlink socket cannot be created.
    pub fn new(config: BridgeConfig) -> Result<Self> {
        let netlink = NetlinkHandle::new()?;
        Ok(Self {
            config,
            netlink,
            ifindex: None,
            attached_interfaces: HashSet::new(),
        })
    }

    /// Creates the bridge interface.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The bridge already exists (call `delete()` first)
    /// - Interface creation fails
    pub fn create(&mut self) -> Result<()> {
        if self.ifindex.is_some() {
            return Err(NetError::Bridge("bridge already created".to_string()));
        }

        let link_config = LinkConfig {
            name: self.config.name.clone(),
            link_type: LinkType::Bridge,
            mtu: Some(self.config.mtu),
            mac: None,
        };

        let ifindex = self.netlink.create_link(&link_config)?;
        self.ifindex = Some(ifindex);

        tracing::info!(
            "Created bridge {} with ifindex {}",
            self.config.name,
            ifindex
        );

        Ok(())
    }

    /// Deletes the bridge interface.
    ///
    /// This also detaches all attached interfaces.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The bridge was not created
    /// - Interface deletion fails
    pub fn delete(&mut self) -> Result<()> {
        let ifindex = self
            .ifindex
            .ok_or_else(|| NetError::Bridge("bridge not created".to_string()))?;

        self.netlink.delete_link(ifindex)?;
        self.ifindex = None;
        self.attached_interfaces.clear();

        tracing::info!("Deleted bridge {}", self.config.name);

        Ok(())
    }

    /// Brings the bridge interface up.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The bridge was not created
    /// - State change fails
    pub fn bring_up(&mut self) -> Result<()> {
        let ifindex = self
            .ifindex
            .ok_or_else(|| NetError::Bridge("bridge not created".to_string()))?;

        self.netlink.set_link_state(ifindex, true)?;

        tracing::debug!("Brought up bridge {}", self.config.name);

        Ok(())
    }

    /// Brings the bridge interface down.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The bridge was not created
    /// - State change fails
    pub fn bring_down(&mut self) -> Result<()> {
        let ifindex = self
            .ifindex
            .ok_or_else(|| NetError::Bridge("bridge not created".to_string()))?;

        self.netlink.set_link_state(ifindex, false)?;

        tracing::debug!("Brought down bridge {}", self.config.name);

        Ok(())
    }

    /// Sets the IP address on the bridge.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The bridge was not created
    /// - Address configuration fails
    pub fn set_ip(&mut self, addr: Ipv4Network) -> Result<()> {
        let ifindex = self
            .ifindex
            .ok_or_else(|| NetError::Bridge("bridge not created".to_string()))?;

        self.netlink
            .add_address(ifindex, ipnetwork::IpNetwork::V4(addr))?;
        self.config.ip_addr = Some(addr);

        tracing::debug!("Set IP {} on bridge {}", addr, self.config.name);

        Ok(())
    }

    /// Adds an interface to the bridge.
    ///
    /// The interface must already exist (e.g., a TAP device).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The bridge was not created
    /// - The interface does not exist
    /// - Adding the interface fails
    pub fn add_interface(&mut self, ifname: &str) -> Result<()> {
        let bridge_ifindex = self
            .ifindex
            .ok_or_else(|| NetError::Bridge("bridge not created".to_string()))?;

        let if_index = self.netlink.get_ifindex(ifname)?;
        self.netlink.set_link_master(if_index, bridge_ifindex)?;
        self.attached_interfaces.insert(ifname.to_string());

        tracing::debug!("Added {} to bridge {}", ifname, self.config.name);

        Ok(())
    }

    /// Removes an interface from the bridge.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The bridge was not created
    /// - The interface is not attached
    /// - Removing the interface fails
    pub fn remove_interface(&mut self, ifname: &str) -> Result<()> {
        if !self.attached_interfaces.contains(ifname) {
            return Err(NetError::Bridge(format!(
                "interface {} not attached to bridge",
                ifname
            )));
        }

        let if_index = self.netlink.get_ifindex(ifname)?;
        // Setting master to 0 removes from bridge
        self.netlink.set_link_master(if_index, 0)?;
        self.attached_interfaces.remove(ifname);

        tracing::debug!("Removed {} from bridge {}", ifname, self.config.name);

        Ok(())
    }

    /// Returns the bridge interface name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Returns the bridge interface index.
    #[must_use]
    pub fn ifindex(&self) -> Option<u32> {
        self.ifindex
    }

    /// Returns the configured IP address.
    #[must_use]
    pub fn ip_addr(&self) -> Option<Ipv4Network> {
        self.config.ip_addr
    }

    /// Returns the MTU.
    #[must_use]
    pub fn mtu(&self) -> u16 {
        self.config.mtu
    }

    /// Returns a list of attached interfaces.
    #[must_use]
    pub fn attached_interfaces(&self) -> Vec<&str> {
        self.attached_interfaces.iter().map(|s| s.as_str()).collect()
    }

    /// Checks if the bridge exists.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.ifindex.is_some()
    }

    /// Tries to attach to an existing bridge by name.
    ///
    /// This is useful when a bridge already exists (e.g., from a previous run).
    ///
    /// # Errors
    ///
    /// Returns an error if the bridge does not exist.
    pub fn attach_existing(&mut self) -> Result<()> {
        let ifindex = self.netlink.get_ifindex(&self.config.name)?;
        self.ifindex = Some(ifindex);

        tracing::info!(
            "Attached to existing bridge {} with ifindex {}",
            self.config.name,
            ifindex
        );

        Ok(())
    }

    /// Creates the bridge if it doesn't exist, or attaches to it if it does.
    ///
    /// # Errors
    ///
    /// Returns an error if both creation and attachment fail.
    pub fn create_or_attach(&mut self) -> Result<()> {
        match self.attach_existing() {
            Ok(()) => Ok(()),
            Err(_) => self.create(),
        }
    }
}

impl Drop for LinuxBridge {
    fn drop(&mut self) {
        // Don't delete on drop by default - explicit cleanup is preferred
        // This allows the bridge to persist across process restarts
        if self.ifindex.is_some() {
            tracing::debug!(
                "LinuxBridge dropped, bridge {} still exists",
                self.config.name
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_config_default() {
        let config = BridgeConfig::default();
        assert_eq!(config.name, DEFAULT_BRIDGE_NAME);
        assert_eq!(config.mtu, DEFAULT_MTU);
        assert!(config.ip_addr.is_none());
    }

    #[test]
    fn test_bridge_config_builder() {
        let ip: Ipv4Network = "192.168.64.1/24".parse().unwrap();
        let config = BridgeConfig::new("br-test").with_ip(ip).with_mtu(9000);

        assert_eq!(config.name, "br-test");
        assert_eq!(config.mtu, 9000);
        assert_eq!(config.ip_addr, Some(ip));
    }

    #[test]
    fn test_bridge_creation_requires_root() {
        // This test requires root privileges
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping test: requires root privileges");
            return;
        }

        let config = BridgeConfig::new("arcbox-test");
        let mut bridge = LinuxBridge::new(config).unwrap();

        // Create and verify
        assert!(bridge.create().is_ok());
        assert!(bridge.exists());
        assert!(bridge.ifindex().is_some());

        // Cleanup
        assert!(bridge.delete().is_ok());
        assert!(!bridge.exists());
    }
}
