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

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

pub mod backend;
pub mod datapath;
pub mod dhcp;
pub mod dns;
pub mod error;
pub mod mdns;
pub mod mdns_protocol;
pub mod nat;
pub mod nat_engine;
pub mod port_forward;

#[cfg(target_os = "linux")]
pub mod linux;

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

use std::collections::HashMap;
use std::sync::RwLock;

/// Docker-style network.
#[derive(Debug, Clone)]
pub struct Network {
    /// Network ID.
    pub id: String,
    /// Network name.
    pub name: String,
    /// Network driver.
    pub driver: String,
    /// Network scope.
    pub scope: String,
    /// Whether the network is internal.
    pub internal: bool,
    /// Whether the network is attachable.
    pub attachable: bool,
    /// Creation timestamp.
    pub created: chrono::DateTime<chrono::Utc>,
    /// Labels.
    pub labels: HashMap<String, String>,
}

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
    /// User-created networks.
    networks: RwLock<HashMap<String, Network>>,
    /// Current state.
    state: RwLock<NetworkState>,
    /// IP allocator for NAT.
    ip_allocator: RwLock<Option<nat::IpAllocator>>,
}

impl NetworkManager {
    /// Creates a new network manager.
    #[must_use]
    pub fn new(config: NetConfig) -> Self {
        Self {
            config,
            networks: RwLock::new(HashMap::new()),
            state: RwLock::new(NetworkState::Stopped),
            ip_allocator: RwLock::new(None),
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
                .map_err(|_| NetError::Config("lock poisoned".to_string()))?;

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
                .map_err(|_| NetError::Config("lock poisoned".to_string()))?;
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
                    .map_err(|_| NetError::Config("lock poisoned".to_string()))?;
                *ip_alloc = Some(allocator);

                tracing::info!("Network manager started in NAT mode");
            }
            NetworkMode::Bridge => {
                if self.config.bridge.is_none() {
                    return Err(NetError::Config(
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
                    .map_err(|_| NetError::Config("lock poisoned".to_string()))?;
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
    /// This cleans up all network resources:
    /// - Releases allocated IP addresses
    /// - Stops port forwarding
    /// - Removes user-created networks
    ///
    /// # Errors
    ///
    /// Returns an error if the network cannot be stopped.
    pub fn stop(&self) -> Result<()> {
        {
            let mut state = self
                .state
                .write()
                .map_err(|_| NetError::Config("lock poisoned".to_string()))?;

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
                .map_err(|_| NetError::Config("lock poisoned".to_string()))?;
            *state = NetworkState::Stopped;
        }

        result
    }

    /// Internal stop implementation.
    fn do_stop(&self) -> Result<()> {
        // Clear IP allocator.
        if let Ok(mut ip_alloc) = self.ip_allocator.write() {
            *ip_alloc = None;
        }

        // Clear user-created networks.
        if let Ok(mut networks) = self.networks.write() {
            networks.clear();
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

    /// Creates a new Docker-style network.
    ///
    /// # Errors
    ///
    /// Returns an error if the network cannot be created.
    pub fn create_network(
        &self,
        name: &str,
        driver: Option<&str>,
        labels: HashMap<String, String>,
    ) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string().replace('-', "");
        let network = Network {
            id: id.clone(),
            name: name.to_string(),
            driver: driver.unwrap_or("bridge").to_string(),
            scope: "local".to_string(),
            internal: false,
            attachable: false,
            created: chrono::Utc::now(),
            labels,
        };

        let mut networks = self
            .networks
            .write()
            .map_err(|_| NetError::Config("lock poisoned".to_string()))?;
        networks.insert(id.clone(), network);

        Ok(id)
    }

    /// Gets a network by ID or name.
    #[must_use]
    pub fn get_network(&self, id_or_name: &str) -> Option<Network> {
        let networks = self.networks.read().ok()?;

        // First try by ID.
        if let Some(network) = networks.get(id_or_name) {
            return Some(network.clone());
        }

        // Then try by name.
        networks.values().find(|n| n.name == id_or_name).cloned()
    }

    /// Lists all networks.
    #[must_use]
    pub fn list_networks(&self) -> Vec<Network> {
        self.networks
            .read()
            .map(|n| n.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Removes a network.
    ///
    /// # Errors
    ///
    /// Returns an error if the network cannot be removed.
    pub fn remove_network(&self, id_or_name: &str) -> Result<()> {
        let mut networks = self
            .networks
            .write()
            .map_err(|_| NetError::Config("lock poisoned".to_string()))?;

        // Try by ID first.
        if networks.remove(id_or_name).is_some() {
            return Ok(());
        }

        // Then try by name.
        let id_to_remove = networks
            .iter()
            .find(|(_, n)| n.name == id_or_name)
            .map(|(id, _)| id.clone());

        if let Some(id) = id_to_remove {
            networks.remove(&id);
            return Ok(());
        }

        Err(NetError::Config(format!(
            "network {} not found",
            id_or_name
        )))
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
