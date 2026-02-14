//! macOS NAT network implementation.
//!
//! This module provides NAT networking for VMs on macOS using the
//! high-performance datapath components.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::datapath::{
    DEFAULT_POOL_CAPACITY, DEFAULT_RING_CAPACITY, DatapathStats, LockFreeRing, PacketPool,
};
use crate::error::{NetError, Result};
use crate::nat::{IpAllocator, NatConfig};
use crate::nat_engine::{NatDirection, NatEngine, NatEngineConfig, NatResult};

use super::{DarwinNetEndpoint, DarwinNetMode, generate_mac};

/// macOS NAT network.
///
/// Provides NAT networking for VMs using a high-performance datapath
/// with zero-copy packet handling and lock-free queues.
pub struct DarwinNatNetwork {
    /// Network configuration.
    config: NatConfig,
    /// NAT engine for packet translation.
    nat_engine: NatEngine,
    /// Packet buffer pool.
    packet_pool: Arc<PacketPool>,
    /// TX ring (Guest -> Host).
    tx_ring: Arc<LockFreeRing<u32>>,
    /// RX ring (Host -> Guest).
    rx_ring: Arc<LockFreeRing<u32>>,
    /// IP allocator.
    ip_allocator: IpAllocator,
    /// Connected endpoints.
    endpoints: HashMap<String, DarwinNetEndpoint>,
    /// Performance statistics.
    stats: DatapathStats,
    /// Running state.
    running: bool,
}

impl DarwinNatNetwork {
    /// Creates a new Darwin NAT network.
    ///
    /// # Errors
    ///
    /// Returns an error if resource allocation fails.
    pub fn new(config: NatConfig) -> Result<Self> {
        let nat_config = NatEngineConfig::new(config.gateway)
            .with_port_range(49152, 65535)
            .with_timeout(300);

        let packet_pool = Arc::new(PacketPool::new(DEFAULT_POOL_CAPACITY)?);
        let tx_ring = Arc::new(LockFreeRing::new(DEFAULT_RING_CAPACITY));
        let rx_ring = Arc::new(LockFreeRing::new(DEFAULT_RING_CAPACITY));

        // Calculate DHCP range
        let mut ip_allocator = IpAllocator::new(config.dhcp_start, config.dhcp_end);

        // Reserve gateway IP
        ip_allocator.allocate_specific(config.gateway);

        Ok(Self {
            config,
            nat_engine: NatEngine::new(&nat_config),
            packet_pool,
            tx_ring,
            rx_ring,
            ip_allocator,
            endpoints: HashMap::new(),
            stats: DatapathStats::new(),
            running: false,
        })
    }

    /// Creates a NAT network with default configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if resource allocation fails.
    pub fn with_defaults() -> Result<Self> {
        Self::new(NatConfig::default())
    }

    /// Returns the network configuration.
    #[must_use]
    pub fn config(&self) -> &NatConfig {
        &self.config
    }

    /// Returns the gateway IP address.
    #[must_use]
    pub fn gateway(&self) -> Ipv4Addr {
        self.config.gateway
    }

    /// Creates a new endpoint for a VM.
    ///
    /// # Errors
    ///
    /// Returns an error if IP allocation fails or endpoint already exists.
    pub fn create_endpoint(&mut self, id: &str) -> Result<&DarwinNetEndpoint> {
        if self.endpoints.contains_key(id) {
            return Err(NetError::config(format!(
                "endpoint '{}' already exists",
                id
            )));
        }

        let ip = self
            .ip_allocator
            .allocate()
            .ok_or_else(|| NetError::AddressAllocation("no available IP addresses".to_string()))?;

        let mac = generate_mac();
        let mut endpoint = DarwinNetEndpoint::new(id.to_string(), mac, DarwinNetMode::Nat);
        endpoint.set_ip(ip);

        self.endpoints.insert(id.to_string(), endpoint);

        Ok(self.endpoints.get(id).unwrap())
    }

    /// Removes an endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the endpoint doesn't exist.
    pub fn remove_endpoint(&mut self, id: &str) -> Result<()> {
        let endpoint = self
            .endpoints
            .remove(id)
            .ok_or_else(|| NetError::config(format!("endpoint '{}' not found", id)))?;

        if let Some(ip) = endpoint.ip {
            self.ip_allocator.release(ip);
        }

        Ok(())
    }

    /// Returns an endpoint by ID.
    #[must_use]
    pub fn get_endpoint(&self, id: &str) -> Option<&DarwinNetEndpoint> {
        self.endpoints.get(id)
    }

    /// Returns all endpoints.
    #[must_use]
    pub fn endpoints(&self) -> impl Iterator<Item = &DarwinNetEndpoint> {
        self.endpoints.values()
    }

    /// Returns the number of connected endpoints.
    #[must_use]
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    /// Starts the NAT network.
    ///
    /// # Errors
    ///
    /// Returns an error if the network is already running.
    pub fn start(&mut self) -> Result<()> {
        if self.running {
            return Err(NetError::config("network already running".to_string()));
        }

        // Set internal network in NAT engine
        self.nat_engine
            .set_internal_network(self.config.subnet, self.config.prefix_len);

        self.running = true;
        Ok(())
    }

    /// Stops the NAT network.
    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Returns true if the network is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Processes a packet from a guest (TX direction).
    ///
    /// # Safety
    ///
    /// The packet data must be valid.
    ///
    /// # Errors
    ///
    /// Returns an error if translation fails.
    pub unsafe fn process_tx_packet(&mut self, packet: &mut [u8]) -> Result<NatResult> {
        self.stats.record_tx(1, packet.len() as u64);

        // Safety: packet data is valid per function contract
        match unsafe { self.nat_engine.translate(packet, NatDirection::Outbound) } {
            Ok(result) => {
                if result == NatResult::Translated {
                    self.stats.record_nat_translation(true);
                }
                Ok(result)
            }
            Err(e) => {
                self.stats.record_tx_error();
                Err(NetError::Nat(e.to_string()))
            }
        }
    }

    /// Processes a packet to a guest (RX direction).
    ///
    /// # Safety
    ///
    /// The packet data must be valid.
    ///
    /// # Errors
    ///
    /// Returns an error if translation fails.
    pub unsafe fn process_rx_packet(&mut self, packet: &mut [u8]) -> Result<NatResult> {
        self.stats.record_rx(1, packet.len() as u64);

        // Safety: packet data is valid per function contract
        match unsafe { self.nat_engine.translate(packet, NatDirection::Inbound) } {
            Ok(result) => {
                if result == NatResult::Translated {
                    self.stats.record_nat_translation(false);
                }
                Ok(result)
            }
            Err(e) => {
                self.stats.record_rx_error();
                Err(NetError::Nat(e.to_string()))
            }
        }
    }

    /// Returns the packet pool.
    #[must_use]
    pub fn packet_pool(&self) -> &Arc<PacketPool> {
        &self.packet_pool
    }

    /// Returns the TX ring.
    #[must_use]
    pub fn tx_ring(&self) -> &Arc<LockFreeRing<u32>> {
        &self.tx_ring
    }

    /// Returns the RX ring.
    #[must_use]
    pub fn rx_ring(&self) -> &Arc<LockFreeRing<u32>> {
        &self.rx_ring
    }

    /// Returns performance statistics.
    #[must_use]
    pub fn stats(&self) -> &DatapathStats {
        &self.stats
    }

    /// Returns NAT engine statistics.
    #[must_use]
    pub fn nat_stats(&self) -> &crate::nat_engine::conntrack::ConnTrackStats {
        self.nat_engine.conntrack().stats()
    }

    /// Expires old NAT connections.
    pub fn expire_connections(&mut self) -> usize {
        let count = self.nat_engine.expire_connections();
        for _ in 0..count {
            self.stats.record_nat_connection_expired();
        }
        count
    }

    /// Returns the number of active NAT connections.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.nat_engine.connection_count()
    }

    /// Performs periodic maintenance.
    pub fn maintenance(&mut self) {
        // Expire old connections every call
        self.expire_connections();
    }
}

impl std::fmt::Debug for DarwinNatNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DarwinNatNetwork")
            .field("gateway", &self.config.gateway)
            .field("endpoints", &self.endpoints.len())
            .field("connections", &self.nat_engine.connection_count())
            .field("running", &self.running)
            .finish()
    }
}

impl Drop for DarwinNatNetwork {
    fn drop(&mut self) {
        self.stop();
    }
}

/// High-performance datapath poller.
///
/// This structure manages the polling loop for the network datapath,
/// processing packets in batches for optimal performance.
pub struct DatapathPoller {
    /// Batch size for packet processing.
    batch_size: usize,
    /// Polling strategy.
    strategy: PollingStrategy,
    /// Spin count for adaptive polling.
    spin_count: u32,
    /// Maximum spin count before yielding.
    max_spins: u32,
}

/// Polling strategy for the datapath.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PollingStrategy {
    /// Always poll (lowest latency, highest CPU).
    Busy,
    /// Poll with adaptive backoff.
    #[default]
    Adaptive,
    /// Event-driven (lowest CPU, higher latency).
    EventDriven,
}

impl Default for DatapathPoller {
    fn default() -> Self {
        Self::new()
    }
}

impl DatapathPoller {
    /// Creates a new datapath poller.
    #[must_use]
    pub fn new() -> Self {
        Self {
            batch_size: 64,
            strategy: PollingStrategy::Adaptive,
            spin_count: 0,
            max_spins: 1000,
        }
    }

    /// Sets the batch size.
    #[must_use]
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Sets the polling strategy.
    #[must_use]
    pub fn with_strategy(mut self, strategy: PollingStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Polls the datapath once.
    ///
    /// Returns true if any work was done.
    pub fn poll_once(&mut self, network: &mut DarwinNatNetwork) -> bool {
        let mut work_done = false;

        // Process TX packets (Guest -> Host)
        let mut tx_batch = [0u32; 64];
        let tx_count = network
            .tx_ring()
            .dequeue_batch(&mut tx_batch[..self.batch_size]);
        if tx_count > 0 {
            work_done = true;
            network.stats().record_batch_size(tx_count);

            for &buf_idx in &tx_batch[..tx_count] {
                // Get buffer pointer and length first to avoid borrow conflicts.
                // Safety: buf_idx comes from our ring buffer and is valid.
                let (ptr, len) = unsafe {
                    let buffer = network.packet_pool().get_mut(buf_idx);
                    (buffer.as_mut_ptr(), buffer.len())
                };

                // Process packet with raw pointer access.
                // Safety: ptr is valid and exclusively owned during this operation.
                unsafe {
                    let slice = std::slice::from_raw_parts_mut(ptr, len);
                    let _ = network.process_tx_packet(slice);
                    network.packet_pool().free_by_index(buf_idx);
                }
            }
        }

        // Process RX packets (Host -> Guest)
        let mut rx_batch = [0u32; 64];
        let rx_count = network
            .rx_ring()
            .dequeue_batch(&mut rx_batch[..self.batch_size]);
        if rx_count > 0 {
            work_done = true;
            network.stats().record_batch_size(rx_count);

            for &buf_idx in &rx_batch[..rx_count] {
                // Get buffer pointer and length first to avoid borrow conflicts.
                // Safety: buf_idx comes from our ring buffer and is valid.
                let (ptr, len) = unsafe {
                    let buffer = network.packet_pool().get_mut(buf_idx);
                    (buffer.as_mut_ptr(), buffer.len())
                };

                // Process packet with raw pointer access.
                // Safety: ptr is valid and exclusively owned during this operation.
                unsafe {
                    let slice = std::slice::from_raw_parts_mut(ptr, len);
                    let _ = network.process_rx_packet(slice);
                    network.packet_pool().free_by_index(buf_idx);
                }
            }
        }

        // Update polling state
        network.stats().record_poll(work_done);

        if work_done {
            self.spin_count = 0;
        } else {
            self.spin_count += 1;

            // Adaptive backoff
            if self.strategy == PollingStrategy::Adaptive && self.spin_count > self.max_spins {
                std::thread::yield_now();
                self.spin_count = 0;
            }
        }

        work_done
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_darwin_nat_network_creation() {
        let network = DarwinNatNetwork::with_defaults().unwrap();
        assert!(!network.is_running());
        assert_eq!(network.endpoint_count(), 0);
        assert_eq!(network.gateway(), Ipv4Addr::new(192, 168, 64, 1));
    }

    #[test]
    fn test_endpoint_lifecycle() {
        let mut network = DarwinNatNetwork::with_defaults().unwrap();

        // Create endpoint
        let endpoint = network.create_endpoint("vm1").unwrap();
        assert!(endpoint.ip.is_some());
        assert_eq!(endpoint.mode, DarwinNetMode::Nat);

        // Should have one endpoint
        assert_eq!(network.endpoint_count(), 1);

        // Create another
        let _ = network.create_endpoint("vm2").unwrap();
        assert_eq!(network.endpoint_count(), 2);

        // Remove first
        network.remove_endpoint("vm1").unwrap();
        assert_eq!(network.endpoint_count(), 1);

        // Can't remove non-existent
        assert!(network.remove_endpoint("vm1").is_err());
    }

    #[test]
    fn test_start_stop() {
        let mut network = DarwinNatNetwork::with_defaults().unwrap();

        assert!(!network.is_running());

        network.start().unwrap();
        assert!(network.is_running());

        // Can't start twice
        assert!(network.start().is_err());

        network.stop();
        assert!(!network.is_running());
    }

    #[test]
    fn test_poller_creation() {
        let poller = DatapathPoller::new()
            .with_batch_size(32)
            .with_strategy(PollingStrategy::Busy);

        assert_eq!(poller.batch_size, 32);
        assert_eq!(poller.strategy, PollingStrategy::Busy);
    }
}
