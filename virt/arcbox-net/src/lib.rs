//! # arcbox-net
//!
//! High-performance network stack for ArcBox.
//!
//! This crate provides networking capabilities for VMs including:
//!
//! - **NAT networking**: Default shared network with host
//! - **Bridge networking**: Direct L2 connectivity
//! - **Host-only networking**: Isolated VM networks
//! - **Port forwarding**: Expose guest services to host
//!
//! ## Performance Features
//!
//! - Zero-copy packet handling via shared memory
//! - Kernel bypass using vmnet.framework (macOS)
//! - Multi-queue virtio-net support
//! - Hardware checksum offload
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │                  arcbox-net                     │
//! │  ┌─────────────────────────────────────────┐   │
//! │  │            NetworkManager               │   │
//! │  │  - Network lifecycle                    │   │
//! │  │  - IP allocation                        │   │
//! │  └─────────────────────────────────────────┘   │
//! │  ┌──────────┐ ┌──────────┐ ┌──────────────┐   │
//! │  │  NAT     │ │  Bridge  │ │  Port Forward │   │
//! │  │ Network  │ │ Network  │ │    Service    │   │
//! │  └──────────┘ └──────────┘ └──────────────┘   │
//! │  ┌─────────────────────────────────────────┐   │
//! │  │              TAP/vmnet                   │   │
//! │  └─────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────┘
//! ```

#![allow(unused_imports, unused_variables, unused_mut)]

pub mod backend;
pub mod datapath;
pub mod dhcp;
pub mod direct_rx;
pub mod dns;
pub mod error;
pub mod ethernet;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod mdns;
pub mod mdns_protocol;
pub mod nat;
pub mod nat_backend;
pub mod nat_engine;
pub mod port_forward;
pub mod timer_wheel;

#[cfg(target_os = "macos")]
pub mod darwin;

pub use error::{NetError, Result};

/// Network mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkMode {
    /// NAT networking (default).
    #[default]
    Nat,
    /// Bridge networking.
    Bridge,
    /// Host-only networking.
    HostOnly,
    /// No networking.
    None,
}

/// Network configuration.
#[derive(Debug, Clone)]
pub struct NetConfig {
    /// Network mode.
    pub mode: NetworkMode,
    /// MAC address (auto-generated if None).
    pub mac: Option<[u8; 6]>,
    /// MTU size.
    pub mtu: u16,
    /// Bridge interface name (for bridge mode).
    pub bridge: Option<String>,
    /// Enable multiqueue.
    pub multiqueue: bool,
    /// Number of queues.
    pub num_queues: u32,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Nat,
            mac: None,
            mtu: 1500,
            bridge: None,
            multiqueue: false,
            num_queues: 1,
        }
    }
}

use std::net::IpAddr;
use std::sync::RwLock;

/// Network manager state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkState {
    /// Network manager not started.
    Stopped,
    /// Network manager is starting.
    Starting,
    /// Network manager is running.
    Running,
    /// Network manager is stopping.
    Stopping,
}

/// Network manager.
///
/// Manages the network infrastructure for VMs including:
/// - Network backends (vmnet on macOS, TAP/bridge on Linux)
/// - NAT engine for address translation
/// - Port forwarding
/// - DNS forwarding
pub struct NetworkManager {
    config: NetConfig,
    /// Current state.
    state: RwLock<NetworkState>,
    /// IP allocator for NAT.
    ip_allocator: RwLock<Option<nat::IpAllocator>>,
    /// DNS forwarder with local hostname resolution.
    dns_forwarder: RwLock<dns::DnsForwarder>,
}

impl NetworkManager {
    /// Creates a new network manager.
    #[must_use]
    pub fn new(config: NetConfig) -> Self {
        Self {
            config,
            state: RwLock::new(NetworkState::Stopped),
            ip_allocator: RwLock::new(None),
            dns_forwarder: RwLock::new(dns::DnsForwarder::new(dns::DnsConfig::default())),
        }
    }

    /// Replaces the DNS forwarder's local domain.
    ///
    /// Call this before registering any hostnames to ensure the domain suffix
    /// is consistent across all entries. Preserves the shared hosts table
    /// but removes stale FQDN entries from the old domain.
    pub fn set_dns_domain(&self, domain: &str) {
        if let Ok(mut forwarder) = self.dns_forwarder.write() {
            // Remove FQDN entries belonging to the old domain.
            if let Some(ref old_domain) = forwarder.config().local_domain {
                let suffix = format!(".{old_domain}");
                let table = forwarder.local_hosts_table();
                if let Ok(mut hosts) = table.write() {
                    hosts.retain(|k, _| !k.ends_with(&suffix) && k != old_domain);
                }
            }
            let mut cfg = forwarder.config().clone();
            cfg.local_domain = Some(domain.to_string());
            let shared_table = forwarder.local_hosts_table();
            *forwarder = dns::DnsForwarder::with_shared_hosts(cfg, shared_table);
        }
    }

    /// Returns the network configuration.
    #[must_use]
    pub fn config(&self) -> &NetConfig {
        &self.config
    }

    /// Returns the current state.
    #[must_use]
    pub fn state(&self) -> NetworkState {
        *self.state.read().unwrap_or_else(|p| p.into_inner())
    }

    /// Starts the network manager.
    ///
    /// This initializes the network backend based on the configured mode:
    /// - NAT: Creates NAT network with IP allocation and port forwarding
    /// - Bridge: Attaches to existing bridge interface
    /// - HostOnly: Creates isolated network
    /// - None: No network initialization
    ///
    /// # Errors
    ///
    /// Returns an error if the network cannot be started.
    pub fn start(&self) -> Result<()> {
        {
            let mut state = self
                .state
                .write()
                .map_err(|_| NetError::config("lock poisoned".to_string()))?;

            if *state != NetworkState::Stopped {
                return Ok(());
            }
            *state = NetworkState::Starting;
        }

        let result = self.do_start();

        {
            let mut state = self
                .state
                .write()
                .map_err(|_| NetError::config("lock poisoned".to_string()))?;
            *state = if result.is_ok() {
                NetworkState::Running
            } else {
                NetworkState::Stopped
            };
        }

        result
    }

    /// Internal start implementation.
    fn do_start(&self) -> Result<()> {
        match self.config.mode {
            NetworkMode::Nat => {
                // Initialize IP allocator for NAT mode.
                let allocator = nat::IpAllocator::new(
                    std::net::Ipv4Addr::new(192, 168, 64, 2),
                    std::net::Ipv4Addr::new(192, 168, 64, 254),
                );

                let mut ip_alloc = self
                    .ip_allocator
                    .write()
                    .map_err(|_| NetError::config("lock poisoned".to_string()))?;
                *ip_alloc = Some(allocator);

                tracing::info!("Network manager started in NAT mode");
            }
            NetworkMode::Bridge => {
                if self.config.bridge.is_none() {
                    return Err(NetError::config(
                        "bridge mode requires bridge interface name".to_string(),
                    ));
                }
                tracing::info!(
                    "Network manager started in bridge mode ({})",
                    self.config.bridge.as_deref().unwrap_or("unknown")
                );
            }
            NetworkMode::HostOnly => {
                // Initialize IP allocator for host-only mode.
                let allocator = nat::IpAllocator::new(
                    std::net::Ipv4Addr::new(10, 0, 0, 2),
                    std::net::Ipv4Addr::new(10, 0, 0, 254),
                );

                let mut ip_alloc = self
                    .ip_allocator
                    .write()
                    .map_err(|_| NetError::config("lock poisoned".to_string()))?;
                *ip_alloc = Some(allocator);

                tracing::info!("Network manager started in host-only mode");
            }
            NetworkMode::None => {
                tracing::info!("Network manager started with no networking");
            }
        }

        Ok(())
    }

    /// Stops the network manager.
    ///
    /// Current stop behavior:
    /// - Clears the in-memory IP allocator state
    /// - Transitions manager state back to `Stopped`
    ///
    /// # Errors
    ///
    /// Returns an error if the network cannot be stopped.
    pub fn stop(&self) -> Result<()> {
        {
            let mut state = self
                .state
                .write()
                .map_err(|_| NetError::config("lock poisoned".to_string()))?;

            if *state != NetworkState::Running {
                return Ok(());
            }
            *state = NetworkState::Stopping;
        }

        let result = self.do_stop();

        {
            let mut state = self
                .state
                .write()
                .map_err(|_| NetError::config("lock poisoned".to_string()))?;
            *state = NetworkState::Stopped;
        }

        result
    }

    /// Internal stop implementation.
    #[allow(clippy::unnecessary_wraps)] // Result kept for forward-compatibility (stop may fail in future)
    fn do_stop(&self) -> Result<()> {
        // Clear IP allocator.
        if let Ok(mut ip_alloc) = self.ip_allocator.write() {
            *ip_alloc = None;
        }

        tracing::info!("Network manager stopped");
        Ok(())
    }

    /// Allocates an IP address from the pool.
    ///
    /// Returns None if no addresses are available or network is not started.
    pub fn allocate_ip(&self) -> Option<std::net::Ipv4Addr> {
        let mut ip_alloc = self.ip_allocator.write().ok()?;
        ip_alloc.as_mut()?.allocate()
    }

    /// Releases an IP address back to the pool.
    pub fn release_ip(&self, ip: std::net::Ipv4Addr) {
        if let Ok(mut ip_alloc) = self.ip_allocator.write() {
            if let Some(allocator) = ip_alloc.as_mut() {
                allocator.release(ip);
            }
        }
    }

    /// Returns the number of available IP addresses.
    #[must_use]
    pub fn available_ips(&self) -> usize {
        self.ip_allocator
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().map(nat::IpAllocator::available_count))
            .unwrap_or(0)
    }

    /// Returns the shared local-hosts table for this network manager.
    ///
    /// Pass this to the VMM when constructing the datapath's `DnsForwarder`
    /// so that both the host-side `DnsService` and the VMM-side forwarder
    /// resolve from the same table.
    pub fn local_hosts_table(&self) -> std::sync::Arc<arcbox_dns::LocalHostsTable> {
        self.dns_forwarder
            .read()
            .expect("dns forwarder lock")
            .local_hosts_table()
    }

    /// Registers a local DNS hostname → IP mapping.
    pub fn register_dns(&self, hostname: &str, ip: IpAddr) {
        if let Ok(forwarder) = self.dns_forwarder.read() {
            forwarder.add_local_host(hostname, ip);
        }
    }

    /// Removes a local DNS hostname mapping.
    pub fn deregister_dns(&self, hostname: &str) {
        if let Ok(forwarder) = self.dns_forwarder.read() {
            forwarder.remove_local_host(hostname);
        }
    }

    /// Tries to resolve a DNS query locally, returning NXDOMAIN for unresolved
    /// `*.arcbox.local` queries. Returns `None` only when the query should be
    /// forwarded to upstream DNS.
    pub fn try_resolve_dns_or_nxdomain(&self, query: &[u8]) -> Option<Vec<u8>> {
        let forwarder = self.dns_forwarder.read().ok()?;
        forwarder.try_resolve_locally_or_nxdomain(query)
    }

    /// Handles a full DNS query: local resolution first, then upstream forwarding.
    /// This blocks on network I/O for upstream queries.
    pub fn handle_dns_query(&self, query: &[u8]) -> Result<Vec<u8>> {
        // handle_query needs &mut self for cache updates, so take a write lock.
        let mut forwarder = self
            .dns_forwarder
            .write()
            .map_err(|_| NetError::config("dns forwarder lock poisoned".to_string()))?;
        forwarder.handle_query(query)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_manager_lifecycle() {
        let manager = NetworkManager::new(NetConfig::default());
        assert_eq!(manager.state(), NetworkState::Stopped);

        manager.start().unwrap();
        assert_eq!(manager.state(), NetworkState::Running);

        // Can allocate IPs in NAT mode.
        let ip = manager.allocate_ip();
        assert!(ip.is_some());

        manager.stop().unwrap();
        assert_eq!(manager.state(), NetworkState::Stopped);
    }

    #[test]
    fn test_network_manager_ip_allocation() {
        let manager = NetworkManager::new(NetConfig::default());
        manager.start().unwrap();

        let ip1 = manager.allocate_ip().unwrap();
        let ip2 = manager.allocate_ip().unwrap();
        assert_ne!(ip1, ip2);

        // Release ip1 and verify it can be allocated again (eventually).
        manager.release_ip(ip1);
        // Allocator uses sequential allocation, so ip3 may not be ip1 immediately.
        // But after release, the pool should have one more available slot.
        let initial_available = manager.available_ips();
        let _ip3 = manager.allocate_ip().unwrap();
        // Available count should decrease after allocation.
        assert!(manager.available_ips() < initial_available || initial_available == 253);
    }

    #[test]
    fn test_set_dns_domain_switches_nxdomain_scope() {
        let manager = NetworkManager::new(NetConfig::default());
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(172, 17, 0, 2));
        manager.register_dns("web", ip);

        // Helper to build a minimal A-record query.
        let build_query = |name: &str| -> Vec<u8> {
            let mut pkt = vec![0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00];
            pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            for label in name.split('.') {
                pkt.push(label.len() as u8);
                pkt.extend_from_slice(label.as_bytes());
            }
            pkt.push(0x00);
            pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
            pkt
        };

        // Default domain: web.arcbox.local resolves.
        let q = build_query("web.arcbox.local");
        let resp = manager.try_resolve_dns_or_nxdomain(&q).unwrap();
        assert_eq!(resp[3] & 0x0F, 0, "should resolve under default domain");

        // Switch to custom domain — old registrations are gone (forwarder rebuilt).
        manager.set_dns_domain("custom.test");

        // Re-register under new domain.
        manager.register_dns("web", ip);
        let q = build_query("web.custom.test");
        let resp = manager.try_resolve_dns_or_nxdomain(&q).unwrap();
        assert_eq!(resp[3] & 0x0F, 0, "should resolve under custom domain");

        // Unknown under custom domain → NXDOMAIN.
        let q = build_query("nope.custom.test");
        let resp = manager.try_resolve_dns_or_nxdomain(&q).unwrap();
        assert_eq!(
            resp[3] & 0x0F,
            3,
            "NXDOMAIN for unregistered custom-domain host"
        );

        // Old default domain → forwarded (None), not NXDOMAIN.
        let q = build_query("web.arcbox.local");
        assert!(
            manager.try_resolve_dns_or_nxdomain(&q).is_none(),
            "old domain queries should not match after set_dns_domain"
        );
    }

    #[test]
    fn test_network_manager_no_network_mode() {
        let config = NetConfig {
            mode: NetworkMode::None,
            ..Default::default()
        };
        let manager = NetworkManager::new(config);
        manager.start().unwrap();

        // No IP allocation in none mode.
        assert!(manager.allocate_ip().is_none());
    }
}
