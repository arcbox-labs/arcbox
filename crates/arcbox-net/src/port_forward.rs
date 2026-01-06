//! Port forwarding service.

use std::net::SocketAddr;

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

/// Network protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// TCP protocol.
    Tcp,
    /// UDP protocol.
    Udp,
}

/// Port forwarding manager.
pub struct PortForwarder {
    rules: Vec<PortForwardRule>,
}

impl PortForwarder {
    /// Creates a new port forwarder.
    #[must_use]
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Adds a forwarding rule.
    pub fn add_rule(&mut self, rule: PortForwardRule) {
        self.rules.push(rule);
    }

    /// Removes a forwarding rule.
    pub fn remove_rule(&mut self, host_addr: SocketAddr) {
        self.rules.retain(|r| r.host_addr != host_addr);
    }

    /// Returns all rules.
    #[must_use]
    pub fn rules(&self) -> &[PortForwardRule] {
        &self.rules
    }

    /// Starts port forwarding.
    pub fn start(&self) {
        // TODO: Start listening on host ports and forwarding
    }

    /// Stops port forwarding.
    pub fn stop(&self) {
        // TODO: Stop forwarding
    }
}

impl Default for PortForwarder {
    fn default() -> Self {
        Self::new()
    }
}
