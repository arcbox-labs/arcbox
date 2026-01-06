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

/// Network manager.
pub struct NetworkManager {
    config: NetConfig,
    /// User-created networks.
    networks: RwLock<HashMap<String, Network>>,
}

impl NetworkManager {
    /// Creates a new network manager.
    #[must_use]
    pub fn new(config: NetConfig) -> Self {
        Self {
            config,
            networks: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the network configuration.
    #[must_use]
    pub fn config(&self) -> &NetConfig {
        &self.config
    }

    /// Starts the network.
    ///
    /// # Errors
    ///
    /// Returns an error if the network cannot be started.
    pub fn start(&mut self) -> Result<()> {
        // TODO: Initialize network backend
        Ok(())
    }

    /// Stops the network.
    ///
    /// # Errors
    ///
    /// Returns an error if the network cannot be stopped.
    pub fn stop(&mut self) -> Result<()> {
        // TODO: Cleanup network
        Ok(())
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
        networks
            .values()
            .find(|n| n.name == id_or_name)
            .cloned()
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

        Err(NetError::Config(format!("network {} not found", id_or_name)))
    }
}
