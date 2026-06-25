//! DHCP server configuration.

use std::net::Ipv4Addr;
use std::time::Duration;

/// Default DHCP lease duration (24 hours).
pub const DEFAULT_LEASE_DURATION: Duration = Duration::from_hours(24);

/// DHCP server port.
pub const DHCP_SERVER_PORT: u16 = 67;

/// DHCP client port.
pub const DHCP_CLIENT_PORT: u16 = 68;

/// DHCP configuration.
#[derive(Debug, Clone)]
pub struct DhcpConfig {
    /// Server IP address (usually the gateway).
    pub server_ip: Ipv4Addr,
    /// Subnet mask.
    pub netmask: Ipv4Addr,
    /// Gateway address (defaults to server_ip).
    pub gateway: Ipv4Addr,
    /// DNS servers.
    pub dns_servers: Vec<Ipv4Addr>,
    /// Lease duration.
    pub lease_duration: Duration,
    /// DHCP pool start.
    pub pool_start: Ipv4Addr,
    /// DHCP pool end.
    pub pool_end: Ipv4Addr,
    /// Domain name.
    pub domain_name: Option<String>,
}

impl DhcpConfig {
    /// Creates a new DHCP configuration.
    #[must_use]
    pub fn new(server_ip: Ipv4Addr, netmask: Ipv4Addr) -> Self {
        // Derive default pool range from the subnet.
        let netmask_u32 = u32::from(netmask);
        let network = u32::from(server_ip) & netmask_u32;
        let broadcast = network | !netmask_u32;

        // Host range: [network+1, broadcast-1], skipping server_ip, capped to 253.
        let server_u32 = u32::from(server_ip);
        let host_min = network.saturating_add(1);
        let host_max = broadcast.saturating_sub(1);

        // Start the pool after server_ip if it sits at host_min.
        let pool_start_u32 = if host_min == server_u32 {
            host_min.saturating_add(1)
        } else {
            host_min
        };
        let pool_end_u32 = pool_start_u32.saturating_add(252).min(host_max);

        let pool_start = Ipv4Addr::from(pool_start_u32);
        let pool_end = Ipv4Addr::from(pool_end_u32);

        Self {
            server_ip,
            netmask,
            gateway: server_ip,
            dns_servers: vec![server_ip], // Default to gateway as DNS
            lease_duration: DEFAULT_LEASE_DURATION,
            pool_start,
            pool_end,
            domain_name: None,
        }
    }

    /// Sets the gateway address.
    #[must_use]
    pub fn with_gateway(mut self, gateway: Ipv4Addr) -> Self {
        self.gateway = gateway;
        self
    }

    /// Sets the DNS servers.
    #[must_use]
    pub fn with_dns_servers(mut self, servers: Vec<Ipv4Addr>) -> Self {
        self.dns_servers = servers;
        self
    }

    /// Sets the lease duration.
    #[must_use]
    pub fn with_lease_duration(mut self, duration: Duration) -> Self {
        self.lease_duration = duration;
        self
    }

    /// Sets the address pool range.
    #[must_use]
    pub fn with_pool_range(mut self, start: Ipv4Addr, end: Ipv4Addr) -> Self {
        self.pool_start = start;
        self.pool_end = end;
        self
    }

    /// Sets the domain name.
    #[must_use]
    pub fn with_domain_name(mut self, name: impl Into<String>) -> Self {
        self.domain_name = Some(name.into());
        self
    }
}
