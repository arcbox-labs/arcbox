//! Port forwarding service.
//!
//! This module provides TCP and UDP port forwarding between host and guest.
//! It supports dynamic addition and removal of forwarding rules.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;

use crate::error::{NetError, Result};

/// Port forwarding rule.
#[derive(Debug, Clone)]
pub struct PortForwardRule {
    /// Host address to listen on.
    pub host_addr: SocketAddr,
    /// Guest address to forward to.
    pub guest_addr: SocketAddr,
    /// Protocol (TCP or UDP).
    pub protocol: Protocol,
}

impl PortForwardRule {
    /// Creates a new TCP port forwarding rule.
    #[must_use]
    pub fn tcp(host_addr: SocketAddr, guest_addr: SocketAddr) -> Self {
        Self {
            host_addr,
            guest_addr,
            protocol: Protocol::Tcp,
        }
    }

    /// Creates a new UDP port forwarding rule.
    #[must_use]
    pub fn udp(host_addr: SocketAddr, guest_addr: SocketAddr) -> Self {
        Self {
            host_addr,
            guest_addr,
            protocol: Protocol::Udp,
        }
    }
}

/// Network protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// TCP protocol.
    Tcp,
    /// UDP protocol.
    Udp,
}

/// Active forwarder state.
struct ActiveForwarder {
    /// Shutdown signal sender.
    shutdown_tx: mpsc::Sender<()>,
    /// Task handle.
    handle: JoinHandle<()>,
}

/// Port forwarding manager.
///
/// Manages port forwarding rules and their associated listeners.
/// Each rule creates a listener on the host that forwards connections
/// to the guest address.
pub struct PortForwarder {
    /// Configured rules.
    rules: Vec<PortForwardRule>,
    /// Active forwarders (keyed by host address string).
    active: Arc<RwLock<HashMap<String, ActiveForwarder>>>,
    /// Whether the forwarder is running.
    running: bool,
}

impl PortForwarder {
    /// Creates a new port forwarder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            active: Arc::new(RwLock::new(HashMap::new())),
            running: false,
        }
    }

    /// Adds a forwarding rule.
    pub fn add_rule(&mut self, rule: PortForwardRule) {
        self.rules.push(rule);
    }

    /// Removes a forwarding rule by host address.
    pub fn remove_rule(&mut self, host_addr: SocketAddr) {
        self.rules.retain(|r| r.host_addr != host_addr);
    }

    /// Returns all configured rules.
    #[must_use]
    pub fn rules(&self) -> &[PortForwardRule] {
        &self.rules
    }

    /// Starts port forwarding for all configured rules.
    ///
    /// # Errors
    ///
    /// Returns an error if any listener cannot be started.
    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }

        for rule in &self.rules {
            self.start_forwarder(rule.clone()).await?;
        }

        self.running = true;
        tracing::info!("Port forwarder started with {} rules", self.rules.len());
        Ok(())
    }

    /// Stops all port forwarding.
    pub async fn stop(&mut self) {
        if !self.running {
            return;
        }

        let mut active = self.active.write().await;
        for (addr, forwarder) in active.drain() {
            // Send shutdown signal (ignore if receiver dropped).
            let _ = forwarder.shutdown_tx.send(()).await;
            // Abort the task if it doesn't shutdown gracefully.
            forwarder.handle.abort();
            tracing::debug!("Stopped forwarder for {}", addr);
        }

        self.running = false;
        tracing::info!("Port forwarder stopped");
    }

    /// Starts a single forwarder for a rule.
    async fn start_forwarder(&self, rule: PortForwardRule) -> Result<()> {
        let key = rule.host_addr.to_string();

        // Check if already active.
        {
            let active = self.active.read().await;
            if active.contains_key(&key) {
                return Ok(());
            }
        }

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let active = Arc::clone(&self.active);

        let handle = match rule.protocol {
            Protocol::Tcp => {
                let listener = TcpListener::bind(rule.host_addr).await.map_err(|e| {
                    NetError::Io(std::io::Error::new(
                        e.kind(),
                        format!("failed to bind {}: {}", rule.host_addr, e),
                    ))
                })?;

                tracing::info!(
                    "TCP port forward: {} -> {}",
                    rule.host_addr,
                    rule.guest_addr
                );

                tokio::spawn(tcp_forward_loop(
                    listener,
                    rule.guest_addr,
                    shutdown_rx,
                ))
            }
            Protocol::Udp => {
                let socket = UdpSocket::bind(rule.host_addr).await.map_err(|e| {
                    NetError::Io(std::io::Error::new(
                        e.kind(),
                        format!("failed to bind {}: {}", rule.host_addr, e),
                    ))
                })?;

                tracing::info!(
                    "UDP port forward: {} -> {}",
                    rule.host_addr,
                    rule.guest_addr
                );

                tokio::spawn(udp_forward_loop(socket, rule.guest_addr, shutdown_rx))
            }
        };

        // Store active forwarder.
        let mut active_guard = active.write().await;
        active_guard.insert(
            key,
            ActiveForwarder {
                shutdown_tx,
                handle,
            },
        );

        Ok(())
    }

    /// Dynamically adds and starts a new rule.
    ///
    /// # Errors
    ///
    /// Returns an error if the forwarder cannot be started.
    pub async fn add_and_start(&mut self, rule: PortForwardRule) -> Result<()> {
        if self.running {
            self.start_forwarder(rule.clone()).await?;
        }
        self.rules.push(rule);
        Ok(())
    }

    /// Dynamically removes and stops a rule.
    pub async fn remove_and_stop(&mut self, host_addr: SocketAddr) {
        let key = host_addr.to_string();

        // Stop the forwarder.
        let mut active = self.active.write().await;
        if let Some(forwarder) = active.remove(&key) {
            let _ = forwarder.shutdown_tx.send(()).await;
            forwarder.handle.abort();
        }

        // Remove the rule.
        self.rules.retain(|r| r.host_addr != host_addr);
    }

    /// Returns the number of active forwarders.
    pub async fn active_count(&self) -> usize {
        self.active.read().await.len()
    }

    /// Returns whether the forwarder is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running
    }
}

impl Default for PortForwarder {
    fn default() -> Self {
        Self::new()
    }
}

/// TCP forwarding loop.
///
/// Accepts connections on the listener and forwards them to the guest.
async fn tcp_forward_loop(
    listener: TcpListener,
    guest_addr: SocketAddr,
    mut shutdown_rx: mpsc::Receiver<()>,
) {
    loop {
        tokio::select! {
            // Check for shutdown signal.
            _ = shutdown_rx.recv() => {
                tracing::debug!("TCP forwarder shutdown");
                break;
            }
            // Accept new connections.
            result = listener.accept() => {
                match result {
                    Ok((client, peer_addr)) => {
                        tracing::debug!("TCP connection from {} -> {}", peer_addr, guest_addr);
                        tokio::spawn(handle_tcp_connection(client, guest_addr));
                    }
                    Err(e) => {
                        tracing::warn!("TCP accept error: {}", e);
                    }
                }
            }
        }
    }
}

/// Handles a single TCP connection by forwarding data bidirectionally.
async fn handle_tcp_connection(mut client: TcpStream, guest_addr: SocketAddr) {
    // Connect to guest.
    let mut guest = match TcpStream::connect(guest_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::warn!("Failed to connect to guest {}: {}", guest_addr, e);
            return;
        }
    };

    // Split streams for bidirectional forwarding.
    let (mut client_read, mut client_write) = client.split();
    let (mut guest_read, mut guest_write) = guest.split();

    // Forward in both directions concurrently.
    let client_to_guest = async {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if guest_write.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    };

    let guest_to_client = async {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = match guest_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if client_write.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    };

    // Run both directions concurrently, complete when either finishes.
    tokio::select! {
        _ = client_to_guest => {}
        _ = guest_to_client => {}
    }
}

/// UDP forwarding loop.
///
/// Receives packets on the socket and forwards them to the guest.
/// Also forwards responses back to the original sender.
async fn udp_forward_loop(
    socket: UdpSocket,
    guest_addr: SocketAddr,
    mut shutdown_rx: mpsc::Receiver<()>,
) {
    let socket = Arc::new(socket);
    // Track client addresses for response routing (simplified: last sender).
    let client_addr: Arc<RwLock<Option<SocketAddr>>> = Arc::new(RwLock::new(None));

    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            // Check for shutdown signal.
            _ = shutdown_rx.recv() => {
                tracing::debug!("UDP forwarder shutdown");
                break;
            }
            // Receive packets.
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, peer_addr)) => {
                        // If packet is from guest, send to client.
                        if peer_addr == guest_addr {
                            let client = client_addr.read().await;
                            if let Some(addr) = *client {
                                let _ = socket.send_to(&buf[..len], addr).await;
                            }
                        } else {
                            // Packet from client, forward to guest.
                            {
                                let mut client = client_addr.write().await;
                                *client = Some(peer_addr);
                            }
                            let _ = socket.send_to(&buf[..len], guest_addr).await;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("UDP recv error: {}", e);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn test_port_forward_rule_tcp() {
        let host = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080));
        let guest = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 64, 2), 80));

        let rule = PortForwardRule::tcp(host, guest);
        assert_eq!(rule.host_addr, host);
        assert_eq!(rule.guest_addr, guest);
        assert_eq!(rule.protocol, Protocol::Tcp);
    }

    #[test]
    fn test_port_forward_rule_udp() {
        let host = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5353));
        let guest = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 64, 2), 53));

        let rule = PortForwardRule::udp(host, guest);
        assert_eq!(rule.protocol, Protocol::Udp);
    }

    #[test]
    fn test_port_forwarder_add_remove() {
        let mut forwarder = PortForwarder::new();

        let host = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080));
        let guest = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 64, 2), 80));

        forwarder.add_rule(PortForwardRule::tcp(host, guest));
        assert_eq!(forwarder.rules().len(), 1);

        forwarder.remove_rule(host);
        assert!(forwarder.rules().is_empty());
    }

    #[tokio::test]
    async fn test_port_forwarder_not_running() {
        let forwarder = PortForwarder::new();
        assert!(!forwarder.is_running());
        assert_eq!(forwarder.active_count().await, 0);
    }
}
