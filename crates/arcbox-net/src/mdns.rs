//! mDNS (Multicast DNS) responder for ArcBox.
//!
//! Provides mDNS-based hostname resolution for containers and VMs,
//! allowing them to be accessed via `<name>.arcbox.local` from the host
//! and other devices on the local network.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     mDNS Responder                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                             │
//! │  ┌──────────────┐      ┌──────────────────────────────┐   │
//! │  │  DnsForwarder │◄────│  MdnsResponder               │   │
//! │  │  (local hosts)│      │  - Multicast listener       │   │
//! │  └──────────────┘      │  - Query responder           │   │
//! │                        │  - Announcement sender       │   │
//! │                        └──────────────────────────────┘   │
//! │                                    │                        │
//! │                                    ▼                        │
//! │                        ┌──────────────────────────────┐   │
//! │                        │  UDP Multicast (224.0.0.251) │   │
//! │                        └──────────────────────────────┘   │
//! │                                                             │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use arcbox_net::mdns::{MdnsResponder, MdnsResponderConfig};
//! use arcbox_net::dns::DnsForwarder;
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let forwarder = Arc::new(RwLock::new(DnsForwarder::new(Default::default())));
//! let config = MdnsResponderConfig::default();
//! let responder = MdnsResponder::new(config, forwarder).await?;
//!
//! // Announce a new container
//! responder.announce("nginx", "192.168.64.10".parse()?).await?;
//!
//! // Run the responder (usually in a background task)
//! tokio::spawn(async move {
//!     responder.serve().await.unwrap();
//! });
//! # Ok(())
//! # }
//! ```

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::dns::DnsForwarder;
use crate::error::{NetError, Result};
use crate::mdns_protocol::{
    DNS_TYPE_A, DNS_TYPE_ANY, MDNS_MULTICAST_ADDR, MDNS_PORT, build_announcement, build_goodbye,
    build_response, parse_query,
};

/// Default mDNS TTL (2 minutes, per RFC 6762 recommendation for records that may change).
pub const DEFAULT_MDNS_TTL: u32 = 120;

/// Default domain suffix for mDNS.
pub const DEFAULT_MDNS_DOMAIN: &str = "arcbox.local";

/// mDNS responder configuration.
#[derive(Debug, Clone)]
pub struct MdnsResponderConfig {
    /// Interface address to bind to (0.0.0.0 for all interfaces).
    pub interface_addr: Ipv4Addr,

    /// Domain suffix (e.g., "arcbox.local").
    pub domain: String,

    /// Default TTL for responses.
    pub ttl: u32,

    /// Enable cache-flush bit in responses.
    pub cache_flush: bool,
}

impl Default for MdnsResponderConfig {
    fn default() -> Self {
        Self {
            interface_addr: Ipv4Addr::UNSPECIFIED,
            domain: DEFAULT_MDNS_DOMAIN.to_string(),
            ttl: DEFAULT_MDNS_TTL,
            cache_flush: true,
        }
    }
}

impl MdnsResponderConfig {
    /// Creates a new configuration with the specified interface address.
    #[must_use]
    pub fn new(interface_addr: Ipv4Addr) -> Self {
        Self {
            interface_addr,
            ..Default::default()
        }
    }

    /// Sets the domain suffix.
    #[must_use]
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = domain.into();
        self
    }

    /// Sets the TTL.
    #[must_use]
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }

    /// Sets whether to use cache-flush bit.
    #[must_use]
    pub fn with_cache_flush(mut self, cache_flush: bool) -> Self {
        self.cache_flush = cache_flush;
        self
    }
}

/// mDNS responder.
///
/// Listens for mDNS queries and responds with local hostname information.
/// Also provides methods to proactively announce hostnames.
pub struct MdnsResponder {
    /// Configuration.
    config: MdnsResponderConfig,

    /// DNS forwarder containing local host mappings.
    forwarder: Arc<RwLock<DnsForwarder>>,

    /// UDP socket for multicast communication.
    socket: UdpSocket,
}

impl MdnsResponder {
    /// Creates a new mDNS responder.
    ///
    /// Sets up a multicast UDP socket bound to 224.0.0.251:5353 with
    /// appropriate socket options for mDNS operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be created or configured.
    pub async fn new(
        config: MdnsResponderConfig,
        forwarder: Arc<RwLock<DnsForwarder>>,
    ) -> Result<Self> {
        let socket = create_mdns_socket(config.interface_addr)?;

        tracing::info!(
            interface = %config.interface_addr,
            domain = %config.domain,
            "mDNS responder created"
        );

        Ok(Self {
            config,
            forwarder,
            socket,
        })
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &MdnsResponderConfig {
        &self.config
    }

    /// Runs the mDNS responder loop.
    ///
    /// This method listens for incoming mDNS queries and responds to
    /// queries for domains we know about. It runs indefinitely until
    /// the task is cancelled.
    ///
    /// # Errors
    ///
    /// Returns an error if receiving or sending packets fails.
    pub async fn serve(&self) -> Result<()> {
        let mut buf = [0u8; 1500];
        let multicast_addr = SocketAddr::new(IpAddr::V4(MDNS_MULTICAST_ADDR), MDNS_PORT);

        tracing::info!("mDNS responder started, listening on {}", multicast_addr);

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    if let Err(e) = self.handle_packet(&buf[..len], src).await {
                        tracing::debug!(error = %e, "failed to handle mDNS packet");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "mDNS recv error");
                    // Continue running despite errors
                }
            }
        }
    }

    /// Handles an incoming mDNS packet.
    async fn handle_packet(&self, packet: &[u8], src: SocketAddr) -> Result<()> {
        // Parse the query
        let query = match parse_query(packet) {
            Ok(Some(q)) => q,
            Ok(None) => return Ok(()), // Not a query, ignore
            Err(e) => {
                tracing::trace!(error = ?e, "failed to parse mDNS packet");
                return Ok(()); // Ignore malformed packets
            }
        };

        // Check if query is for our domain
        if !self.is_our_domain(&query.domain) {
            return Ok(());
        }

        // Only respond to A or ANY queries
        if query.query_type != DNS_TYPE_A && query.query_type != DNS_TYPE_ANY {
            return Ok(());
        }

        tracing::debug!(
            domain = %query.domain,
            query_type = query.query_type,
            unicast = query.unicast_response,
            src = %src,
            "received mDNS query"
        );

        // Look up the hostname
        let forwarder = self.forwarder.read().await;
        let ip = match forwarder.resolve_local(&query.domain) {
            Some(IpAddr::V4(v4)) => v4,
            Some(IpAddr::V6(_)) => return Ok(()), // We only handle A records
            None => {
                // Try without domain suffix
                let hostname = self.strip_domain_suffix(&query.domain);
                match forwarder.resolve_local(hostname) {
                    Some(IpAddr::V4(v4)) => v4,
                    _ => return Ok(()), // Not found, don't respond
                }
            }
        };
        drop(forwarder);

        // Build and send response
        let response = build_response(&query, ip, self.config.ttl, self.config.cache_flush);

        // Determine destination: unicast if QU bit set, otherwise multicast
        let dest = if query.unicast_response {
            src
        } else {
            SocketAddr::new(IpAddr::V4(MDNS_MULTICAST_ADDR), MDNS_PORT)
        };

        self.socket.send_to(&response, dest).await?;

        tracing::debug!(
            domain = %query.domain,
            ip = %ip,
            dest = %dest,
            "sent mDNS response"
        );

        Ok(())
    }

    /// Announces a hostname via mDNS.
    ///
    /// Sends an unsolicited mDNS announcement to inform other devices
    /// on the network about a new or updated hostname.
    ///
    /// # Arguments
    ///
    /// * `hostname` - The hostname (without domain suffix)
    /// * `ip` - The IPv4 address
    ///
    /// # Errors
    ///
    /// Returns an error if the announcement cannot be sent.
    pub async fn announce(&self, hostname: &str, ip: Ipv4Addr) -> Result<()> {
        let fqdn = format!("{}.{}", hostname, self.config.domain);

        // Register in DNS forwarder
        {
            let mut forwarder = self.forwarder.write().await;
            forwarder.add_local_host(hostname, IpAddr::V4(ip));
        }

        // Build and send announcement
        let packet = build_announcement(&fqdn, ip, self.config.ttl);
        let dest = SocketAddr::new(IpAddr::V4(MDNS_MULTICAST_ADDR), MDNS_PORT);

        self.socket.send_to(&packet, dest).await?;

        tracing::info!(hostname = %fqdn, ip = %ip, "announced hostname via mDNS");

        Ok(())
    }

    /// Sends a goodbye packet for a hostname.
    ///
    /// Tells other devices on the network to remove the cached record
    /// for this hostname. This should be called when a container or VM
    /// is stopped.
    ///
    /// # Arguments
    ///
    /// * `hostname` - The hostname (without domain suffix)
    ///
    /// # Errors
    ///
    /// Returns an error if the goodbye packet cannot be sent.
    pub async fn goodbye(&self, hostname: &str) -> Result<()> {
        let fqdn = format!("{}.{}", hostname, self.config.domain);

        // Remove from DNS forwarder
        {
            let mut forwarder = self.forwarder.write().await;
            forwarder.remove_local_host(hostname);
        }

        // Build and send goodbye
        let packet = build_goodbye(&fqdn);
        let dest = SocketAddr::new(IpAddr::V4(MDNS_MULTICAST_ADDR), MDNS_PORT);

        self.socket.send_to(&packet, dest).await?;

        tracing::info!(hostname = %fqdn, "sent mDNS goodbye");

        Ok(())
    }

    /// Checks if a domain is one we should respond to.
    fn is_our_domain(&self, domain: &str) -> bool {
        let lower = domain.to_lowercase();
        lower.ends_with(&format!(".{}", self.config.domain)) || lower == self.config.domain
    }

    /// Strips the domain suffix from a hostname.
    fn strip_domain_suffix<'a>(&self, domain: &'a str) -> &'a str {
        let suffix = format!(".{}", self.config.domain);
        domain
            .strip_suffix(&suffix)
            .or_else(|| domain.strip_suffix(&suffix.to_uppercase()))
            .unwrap_or(domain)
    }
}

/// Creates an mDNS multicast socket.
///
/// The socket is configured with:
/// - SO_REUSEADDR and SO_REUSEPORT for sharing with other mDNS responders
/// - Joined to multicast group 224.0.0.251
/// - Multicast TTL set to 255 (link-local, per RFC 6762)
/// - Multicast loopback enabled
fn create_mdns_socket(interface_addr: Ipv4Addr) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| NetError::Mdns(format!("failed to create socket: {}", e)))?;

    // Allow address reuse for multiple responders
    socket
        .set_reuse_address(true)
        .map_err(|e| NetError::Mdns(format!("failed to set SO_REUSEADDR: {}", e)))?;

    // macOS and BSD require SO_REUSEPORT for multicast
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    socket
        .set_reuse_port(true)
        .map_err(|e| NetError::Mdns(format!("failed to set SO_REUSEPORT: {}", e)))?;

    // Bind to mDNS port
    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT);
    socket
        .bind(&bind_addr.into())
        .map_err(|e| NetError::Mdns(format!("failed to bind to {}: {}", bind_addr, e)))?;

    // Join multicast group
    socket
        .join_multicast_v4(&MDNS_MULTICAST_ADDR, &interface_addr)
        .map_err(|e| NetError::Mdns(format!("failed to join multicast group: {}", e)))?;

    // Set multicast TTL to 255 (required by RFC 6762)
    socket
        .set_multicast_ttl_v4(255)
        .map_err(|e| NetError::Mdns(format!("failed to set multicast TTL: {}", e)))?;

    // Enable multicast loopback (for local testing)
    socket
        .set_multicast_loop_v4(true)
        .map_err(|e| NetError::Mdns(format!("failed to set multicast loopback: {}", e)))?;

    // Set non-blocking for tokio
    socket
        .set_nonblocking(true)
        .map_err(|e| NetError::Mdns(format!("failed to set non-blocking: {}", e)))?;

    // Convert to tokio UdpSocket
    let std_socket: std::net::UdpSocket = socket.into();
    let tokio_socket = UdpSocket::from_std(std_socket)
        .map_err(|e| NetError::Mdns(format!("failed to create tokio socket: {}", e)))?;

    Ok(tokio_socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::DnsConfig;

    fn create_test_forwarder() -> Arc<RwLock<DnsForwarder>> {
        let config = DnsConfig::default().with_local_domain("arcbox.local");
        Arc::new(RwLock::new(DnsForwarder::new(config)))
    }

    #[test]
    fn test_config_default() {
        let config = MdnsResponderConfig::default();
        assert_eq!(config.interface_addr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(config.domain, "arcbox.local");
        assert_eq!(config.ttl, 120);
        assert!(config.cache_flush);
    }

    #[test]
    fn test_config_builder() {
        let config = MdnsResponderConfig::new(Ipv4Addr::new(192, 168, 1, 1))
            .with_domain("test.local")
            .with_ttl(60)
            .with_cache_flush(false);

        assert_eq!(config.interface_addr, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(config.domain, "test.local");
        assert_eq!(config.ttl, 60);
        assert!(!config.cache_flush);
    }

    #[tokio::test]
    async fn test_is_our_domain() {
        let forwarder = create_test_forwarder();
        let config = MdnsResponderConfig::default();

        // Note: We can't create a real responder in tests without binding to the port,
        // so we test the logic directly through a mock or the individual functions.
        // For now, test the config and helper logic.

        let domain = "arcbox.local";
        let test_domain = "nginx.arcbox.local";

        // Test domain suffix checking logic
        assert!(
            test_domain
                .to_lowercase()
                .ends_with(&format!(".{}", domain))
        );
        assert!(
            "NGINX.ARCBOX.LOCAL"
                .to_lowercase()
                .ends_with(&format!(".{}", domain))
        );
    }

    #[test]
    fn test_strip_domain_suffix() {
        let domain = "arcbox.local";
        let suffix = format!(".{}", domain);

        let test = "nginx.arcbox.local";
        let stripped = test.strip_suffix(&suffix).unwrap_or(test);
        assert_eq!(stripped, "nginx");

        let test_plain = "nginx";
        let stripped_plain = test_plain.strip_suffix(&suffix).unwrap_or(test_plain);
        assert_eq!(stripped_plain, "nginx");
    }

    #[tokio::test]
    async fn test_forwarder_integration() {
        let forwarder = create_test_forwarder();

        // Add a host
        {
            let mut fw = forwarder.write().await;
            fw.add_local_host("nginx", IpAddr::V4(Ipv4Addr::new(192, 168, 64, 10)));
        }

        // Verify resolution
        {
            let fw = forwarder.read().await;
            assert_eq!(
                fw.resolve_local("nginx"),
                Some(IpAddr::V4(Ipv4Addr::new(192, 168, 64, 10)))
            );
            assert_eq!(
                fw.resolve_local("nginx.arcbox.local"),
                Some(IpAddr::V4(Ipv4Addr::new(192, 168, 64, 10)))
            );
        }

        // Remove host
        {
            let mut fw = forwarder.write().await;
            fw.remove_local_host("nginx");
        }

        // Verify removal
        {
            let fw = forwarder.read().await;
            assert_eq!(fw.resolve_local("nginx"), None);
        }
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_MDNS_TTL, 120);
        assert_eq!(DEFAULT_MDNS_DOMAIN, "arcbox.local");
    }
}
