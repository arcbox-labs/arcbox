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

/// Network manager.
pub struct NetworkManager {
    config: NetConfig,
}

impl NetworkManager {
    /// Creates a new network manager.
    #[must_use]
    pub fn new(config: NetConfig) -> Self {
        Self { config }
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
}
