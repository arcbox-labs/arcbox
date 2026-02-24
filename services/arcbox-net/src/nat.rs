//! NAT networking implementation.
//!
//! This module provides NAT (Network Address Translation) networking for VMs.
//! VMs connected to a NAT network can access external networks through the host,
//! but are not directly accessible from outside.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use ipnetwork::Ipv4Network;

#[cfg(target_os = "linux")]
use crate::error::Result;

/// NAT network configuration.
#[derive(Debug, Clone)]
pub struct NatConfig {
    /// Subnet (e.g., 192.168.64.0/24).
    pub subnet: Ipv4Addr,
    /// Subnet mask (e.g., 24).
    pub prefix_len: u8,
    /// Gateway address.
    pub gateway: Ipv4Addr,
    /// DHCP range start.
    pub dhcp_start: Ipv4Addr,
    /// DHCP range end.
    pub dhcp_end: Ipv4Addr,
    /// Bridge interface name.
    pub bridge_name: String,
    /// External interface for NAT.
    pub external_interface: String,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            subnet: Ipv4Addr::new(192, 168, 64, 0),
            prefix_len: 24,
            gateway: Ipv4Addr::new(192, 168, 64, 1),
            dhcp_start: Ipv4Addr::new(192, 168, 64, 2),
            dhcp_end: Ipv4Addr::new(192, 168, 64, 254),
            bridge_name: "arcbox0".to_string(),
            external_interface: "eth0".to_string(),
        }
    }
}

impl NatConfig {
    /// Creates a new NAT configuration with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the subnet.
    #[must_use]
    pub fn with_subnet(mut self, subnet: Ipv4Addr, prefix_len: u8) -> Self {
        self.subnet = subnet;
        self.prefix_len = prefix_len;
        self
    }

    /// Sets the gateway address.
    #[must_use]
    pub fn with_gateway(mut self, gateway: Ipv4Addr) -> Self {
        self.gateway = gateway;
        self
    }

    /// Sets the DHCP range.
    #[must_use]
    pub fn with_dhcp_range(mut self, start: Ipv4Addr, end: Ipv4Addr) -> Self {
        self.dhcp_start = start;
        self.dhcp_end = end;
        self
    }

    /// Sets the bridge name.
    #[must_use]
    pub fn with_bridge_name(mut self, name: impl Into<String>) -> Self {
        self.bridge_name = name.into();
        self
    }

    /// Sets the external interface.
    #[must_use]
    pub fn with_external_interface(mut self, interface: impl Into<String>) -> Self {
        self.external_interface = interface.into();
        self
    }

    /// Returns the subnet as an `Ipv4Network`.
    #[must_use]
    pub fn network(&self) -> Ipv4Network {
        Ipv4Network::new(self.subnet, self.prefix_len).expect("invalid subnet configuration")
    }

    /// Returns the gateway as an `Ipv4Network`.
    #[must_use]
    pub fn gateway_network(&self) -> Ipv4Network {
        Ipv4Network::new(self.gateway, self.prefix_len).expect("invalid gateway configuration")
    }
}

/// NAT network manager (cross-platform).
///
/// Uses `IpAllocator` for proper IP address pool management.
pub struct NatNetwork {
    config: NatConfig,
    /// IP address allocator for the DHCP range.
    allocator: std::sync::Mutex<IpAllocator>,
}

impl NatNetwork {
    /// Creates a new NAT network.
    #[must_use]
    pub fn new(config: NatConfig) -> Self {
        let allocator = IpAllocator::new(config.dhcp_start, config.dhcp_end);
        Self {
            config,
            allocator: std::sync::Mutex::new(allocator),
        }
    }

    /// Returns the gateway address.
    #[must_use]
    pub fn gateway(&self) -> Ipv4Addr {
        self.config.gateway
    }

    /// Returns the subnet network.
    #[must_use]
    pub fn subnet(&self) -> Ipv4Network {
        self.config.network()
    }

    /// Allocates an IP address from the pool.
    ///
    /// Returns `None` if no addresses are available.
    pub fn allocate_ip(&self) -> Option<Ipv4Addr> {
        self.allocator.lock().ok()?.allocate()
    }

    /// Allocates a specific IP address.
    ///
    /// Returns `true` if the address was successfully allocated,
    /// `false` if it's already allocated or out of range.
    pub fn allocate_specific(&self, ip: Ipv4Addr) -> bool {
        self.allocator
            .lock()
            .ok()
            .map(|mut a| a.allocate_specific(ip))
            .unwrap_or(false)
    }

    /// Releases an IP address back to the pool.
    pub fn release_ip(&self, ip: Ipv4Addr) {
        if let Ok(mut allocator) = self.allocator.lock() {
            allocator.release(ip);
        }
    }

    /// Checks if an IP address is available.
    #[must_use]
    pub fn is_available(&self, ip: Ipv4Addr) -> bool {
        self.allocator
            .lock()
            .ok()
            .map(|a| a.is_available(ip))
            .unwrap_or(false)
    }

    /// Returns the number of allocated addresses.
    #[must_use]
    pub fn allocated_count(&self) -> usize {
        self.allocator
            .lock()
            .ok()
            .map(|a| a.allocated_count())
            .unwrap_or(0)
    }

    /// Returns the number of available addresses.
    #[must_use]
    pub fn available_count(&self) -> usize {
        self.allocator
            .lock()
            .ok()
            .map(|a| a.available_count())
            .unwrap_or(0)
    }
}

/// Simple IP address allocator.
///
/// Manages a pool of IP addresses within a subnet, allowing allocation
/// and release of addresses.
#[derive(Debug)]
pub struct IpAllocator {
    /// Start of the allocation range.
    start: u32,
    /// End of the allocation range (inclusive).
    end: u32,
    /// Set of allocated addresses.
    allocated: HashSet<u32>,
    /// Next address to try (for sequential allocation).
    next: u32,
}

impl IpAllocator {
    /// Creates a new IP allocator for the given range.
    ///
    /// # Panics
    ///
    /// Panics if start > end.
    #[must_use]
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        let start_u32 = u32::from(start);
        let end_u32 = u32::from(end);

        assert!(start_u32 <= end_u32, "start must be <= end");

        Self {
            start: start_u32,
            end: end_u32,
            allocated: HashSet::new(),
            next: start_u32,
        }
    }

    /// Allocates the next available IP address.
    ///
    /// Returns `None` if no addresses are available.
    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        // Try sequential allocation first (faster for sparse usage)
        let range_size = self.end - self.start + 1;

        for _ in 0..range_size {
            if !self.allocated.contains(&self.next) {
                let addr = self.next;
                self.allocated.insert(addr);
                self.next = if self.next >= self.end {
                    self.start
                } else {
                    self.next + 1
                };
                return Some(Ipv4Addr::from(addr));
            }

            self.next = if self.next >= self.end {
                self.start
            } else {
                self.next + 1
            };
        }

        None // All addresses allocated
    }

    /// Allocates a specific IP address.
    ///
    /// Returns `true` if the address was successfully allocated,
    /// `false` if it's already allocated or out of range.
    pub fn allocate_specific(&mut self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);

        if ip_u32 < self.start || ip_u32 > self.end {
            return false;
        }

        if self.allocated.contains(&ip_u32) {
            return false;
        }

        self.allocated.insert(ip_u32);
        true
    }

    /// Releases an IP address back to the pool.
    pub fn release(&mut self, ip: Ipv4Addr) {
        let ip_u32 = u32::from(ip);
        self.allocated.remove(&ip_u32);
    }

    /// Checks if an IP address is available.
    #[must_use]
    pub fn is_available(&self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        ip_u32 >= self.start && ip_u32 <= self.end && !self.allocated.contains(&ip_u32)
    }

    /// Returns the number of allocated addresses.
    #[must_use]
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// Returns the number of available addresses.
    #[must_use]
    pub fn available_count(&self) -> usize {
        let total = (self.end - self.start + 1) as usize;
        total - self.allocated.len()
    }
}

/// NAT endpoint representing a connected VM or container.
#[derive(Debug, Clone)]
pub struct NatEndpoint {
    /// Endpoint name.
    pub name: String,
    /// TAP device name.
    pub tap_name: String,
    /// MAC address.
    pub mac: [u8; 6],
    /// Assigned IP address.
    pub ip: Ipv4Addr,
}

// Linux-specific NAT network implementation
#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use crate::linux::{
        BridgeConfig, LinuxBridge, LinuxFirewall, LinuxTap, NatRule as FirewallNatRule, TapConfig,
    };

    /// Linux NAT network with full infrastructure support.
    ///
    /// Provides a complete NAT networking solution including:
    /// - Linux bridge for VM connectivity
    /// - TAP devices for each endpoint
    /// - iptables/nftables NAT rules
    /// - IP address allocation
    ///
    /// # Example
    ///
    /// ```no_run
    /// use arcbox_net::nat::{LinuxNatNetwork, NatConfig};
    ///
    /// let config = NatConfig::default();
    /// let mut network = LinuxNatNetwork::new(config).unwrap();
    ///
    /// // Setup the network infrastructure
    /// network.setup().unwrap();
    ///
    /// // Create an endpoint for a VM
    /// let endpoint = network.create_endpoint("my-vm").unwrap();
    /// println!("TAP: {}, IP: {}", endpoint.tap_name, endpoint.ip);
    ///
    /// // Cleanup when done
    /// network.teardown().unwrap();
    /// ```
    pub struct LinuxNatNetwork {
        /// NAT configuration.
        config: NatConfig,
        /// Bridge manager.
        bridge: LinuxBridge,
        /// Firewall manager.
        firewall: LinuxFirewall,
        /// IP address allocator.
        allocator: IpAllocator,
        /// Connected endpoints.
        endpoints: HashMap<String, NatEndpoint>,
        /// TAP devices (kept alive).
        taps: HashMap<String, LinuxTap>,
        /// Whether the network has been set up.
        setup_complete: bool,
    }

    impl LinuxNatNetwork {
        /// Creates a new Linux NAT network.
        ///
        /// Note: This does not set up the network infrastructure yet.
        /// Call `setup()` to create the bridge, configure firewall rules, etc.
        ///
        /// # Errors
        ///
        /// Returns an error if the network components cannot be initialized.
        pub fn new(config: NatConfig) -> Result<Self> {
            let bridge_config = BridgeConfig::new(&config.bridge_name)
                .with_ip(config.gateway_network())
                .with_mtu(1500);

            let bridge = LinuxBridge::new(bridge_config)?;
            let firewall = LinuxFirewall::new()?;
            let allocator = IpAllocator::new(config.dhcp_start, config.dhcp_end);

            Ok(Self {
                config,
                bridge,
                firewall,
                allocator,
                endpoints: HashMap::new(),
                taps: HashMap::new(),
                setup_complete: false,
            })
        }

        /// Sets up the NAT network infrastructure.
        ///
        /// This creates:
        /// - The bridge interface with the gateway IP
        /// - Firewall NAT rules for external access
        /// - IP forwarding enabled
        ///
        /// # Errors
        ///
        /// Returns an error if setup fails.
        pub fn setup(&mut self) -> Result<()> {
            if self.setup_complete {
                return Ok(());
            }

            // Create or attach to existing bridge
            self.bridge.create_or_attach()?;

            // Configure IP address on bridge (may fail if already set)
            let gateway_net = self.config.gateway_network();
            let _ = self.bridge.set_ip(gateway_net);

            // Bring up the bridge
            self.bridge.bring_up()?;

            // Setup firewall
            self.firewall.enable_ip_forward()?;
            self.firewall.setup()?;

            // Add NAT rule
            let nat_rule =
                FirewallNatRule::masquerade(self.config.network(), &self.config.external_interface);
            self.firewall.add_nat_rule(&nat_rule)?;

            // Add forward rules
            self.firewall
                .add_forward_rule(&self.config.bridge_name, &self.config.external_interface)?;

            self.setup_complete = true;

            tracing::info!(
                "NAT network {} set up with gateway {}",
                self.config.bridge_name,
                self.config.gateway
            );

            Ok(())
        }

        /// Tears down the NAT network infrastructure.
        ///
        /// This removes all endpoints, firewall rules, and the bridge.
        ///
        /// # Errors
        ///
        /// Returns an error if teardown fails.
        pub fn teardown(&mut self) -> Result<()> {
            // Remove all endpoints
            let endpoint_names: Vec<String> = self.endpoints.keys().cloned().collect();
            for name in endpoint_names {
                let _ = self.remove_endpoint(&name);
            }

            // Teardown firewall
            let _ = self.firewall.teardown();

            // Delete bridge
            let _ = self.bridge.delete();

            self.setup_complete = false;

            tracing::info!("NAT network {} torn down", self.config.bridge_name);

            Ok(())
        }

        /// Creates a new endpoint (TAP device) and attaches it to the bridge.
        ///
        /// Returns the endpoint information including the TAP device name
        /// and assigned IP address.
        ///
        /// # Errors
        ///
        /// Returns an error if:
        /// - The network has not been set up
        /// - An endpoint with the same name already exists
        /// - TAP creation fails
        /// - No IP addresses are available
        pub fn create_endpoint(&mut self, name: &str) -> Result<NatEndpoint> {
            if !self.setup_complete {
                return Err(NetError::Nat("network not set up".to_string()));
            }

            if self.endpoints.contains_key(name) {
                return Err(NetError::Nat(format!("endpoint {} already exists", name)));
            }

            // Allocate IP
            let ip = self.allocator.allocate().ok_or_else(|| {
                NetError::AddressAllocation("no IP addresses available".to_string())
            })?;

            // Create TAP device
            let tap_name = format!("tap-{}", name.chars().take(10).collect::<String>());
            let tap_config = TapConfig::new().with_name(&tap_name).with_mtu(1500);

            let tap = LinuxTap::new(tap_config).map_err(|e| {
                self.allocator.release(ip);
                e
            })?;

            let mac = tap.mac();

            // Bring up TAP and add to bridge
            tap.bring_up().map_err(|e| {
                self.allocator.release(ip);
                e
            })?;

            self.bridge.add_interface(tap.name()).map_err(|e| {
                self.allocator.release(ip);
                e
            })?;

            let endpoint = NatEndpoint {
                name: name.to_string(),
                tap_name: tap.name().to_string(),
                mac,
                ip,
            };

            self.endpoints.insert(name.to_string(), endpoint.clone());
            self.taps.insert(name.to_string(), tap);

            tracing::info!(
                "Created endpoint {} with TAP {} and IP {}",
                name,
                endpoint.tap_name,
                ip
            );

            Ok(endpoint)
        }

        /// Removes an endpoint.
        ///
        /// # Errors
        ///
        /// Returns an error if the endpoint does not exist.
        pub fn remove_endpoint(&mut self, name: &str) -> Result<()> {
            let endpoint = self
                .endpoints
                .remove(name)
                .ok_or_else(|| NetError::Nat(format!("endpoint {} not found", name)))?;

            // Remove from bridge
            let _ = self.bridge.remove_interface(&endpoint.tap_name);

            // Remove TAP (will be dropped)
            self.taps.remove(name);

            // Release IP
            self.allocator.release(endpoint.ip);

            tracing::info!("Removed endpoint {}", name);

            Ok(())
        }

        /// Allocates an IP address manually (without creating an endpoint).
        pub fn allocate_ip(&mut self) -> Option<Ipv4Addr> {
            self.allocator.allocate()
        }

        /// Releases an IP address.
        pub fn release_ip(&mut self, ip: Ipv4Addr) {
            self.allocator.release(ip);
        }

        /// Returns the gateway address.
        #[must_use]
        pub fn gateway(&self) -> Ipv4Addr {
            self.config.gateway
        }

        /// Returns the DNS server address (same as gateway by default).
        #[must_use]
        pub fn dns_server(&self) -> Ipv4Addr {
            self.config.gateway
        }

        /// Returns the bridge name.
        #[must_use]
        pub fn bridge_name(&self) -> &str {
            &self.config.bridge_name
        }

        /// Returns the subnet.
        #[must_use]
        pub fn subnet(&self) -> Ipv4Network {
            self.config.network()
        }

        /// Returns all endpoints.
        #[must_use]
        pub fn endpoints(&self) -> &HashMap<String, NatEndpoint> {
            &self.endpoints
        }

        /// Gets an endpoint by name.
        #[must_use]
        pub fn get_endpoint(&self, name: &str) -> Option<&NatEndpoint> {
            self.endpoints.get(name)
        }

        /// Returns the raw TAP file descriptor for an endpoint.
        ///
        /// This can be used to pass to VirtIO network device.
        #[must_use]
        pub fn get_tap_fd(&self, name: &str) -> Option<std::os::unix::io::RawFd> {
            self.taps.get(name).map(|tap| tap.as_raw_fd())
        }

        /// Checks if the network has been set up.
        #[must_use]
        pub fn is_setup(&self) -> bool {
            self.setup_complete
        }
    }

    impl Drop for LinuxNatNetwork {
        fn drop(&mut self) {
            if self.setup_complete {
                tracing::debug!(
                    "LinuxNatNetwork dropped, network {} still active",
                    self.config.bridge_name
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux_impl::LinuxNatNetwork;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_config_default() {
        let config = NatConfig::default();
        assert_eq!(config.subnet, Ipv4Addr::new(192, 168, 64, 0));
        assert_eq!(config.prefix_len, 24);
        assert_eq!(config.gateway, Ipv4Addr::new(192, 168, 64, 1));
    }

    #[test]
    fn test_ip_allocator_basic() {
        let start = Ipv4Addr::new(192, 168, 64, 2);
        let end = Ipv4Addr::new(192, 168, 64, 5);

        let mut allocator = IpAllocator::new(start, end);

        // Should be able to allocate 4 addresses
        assert_eq!(allocator.available_count(), 4);

        let ip1 = allocator.allocate().unwrap();
        let ip2 = allocator.allocate().unwrap();
        let ip3 = allocator.allocate().unwrap();
        let ip4 = allocator.allocate().unwrap();

        assert_eq!(allocator.allocated_count(), 4);
        assert_eq!(allocator.available_count(), 0);

        // Should fail to allocate more
        assert!(allocator.allocate().is_none());

        // Release one
        allocator.release(ip2);
        assert_eq!(allocator.available_count(), 1);

        // Should be able to allocate again
        let ip5 = allocator.allocate().unwrap();
        assert_eq!(ip5, ip2);
    }

    #[test]
    fn test_ip_allocator_specific() {
        let start = Ipv4Addr::new(192, 168, 64, 2);
        let end = Ipv4Addr::new(192, 168, 64, 10);

        let mut allocator = IpAllocator::new(start, end);

        // Allocate specific IP
        let specific = Ipv4Addr::new(192, 168, 64, 5);
        assert!(allocator.allocate_specific(specific));

        // Should not be able to allocate same IP again
        assert!(!allocator.allocate_specific(specific));

        // Out of range should fail
        let out_of_range = Ipv4Addr::new(192, 168, 64, 100);
        assert!(!allocator.allocate_specific(out_of_range));
    }

    #[test]
    fn test_ip_allocator_is_available() {
        let start = Ipv4Addr::new(10, 0, 0, 1);
        let end = Ipv4Addr::new(10, 0, 0, 5);

        let mut allocator = IpAllocator::new(start, end);

        assert!(allocator.is_available(Ipv4Addr::new(10, 0, 0, 3)));
        assert!(!allocator.is_available(Ipv4Addr::new(10, 0, 0, 100)));

        allocator.allocate().unwrap();
        assert!(!allocator.is_available(start));
    }
}
