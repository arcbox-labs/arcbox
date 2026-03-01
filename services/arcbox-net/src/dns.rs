//! Built-in DNS server/forwarder.
//!
//! This module provides a simple DNS forwarder that can:
//! - Forward queries to upstream DNS servers
//! - Resolve local hostnames (VM names)
//! - Cache DNS responses
//!
//! The implementation handles basic A and AAAA record queries.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use crate::error::{NetError, Result};

/// Default DNS port.
pub const DNS_PORT: u16 = 53;

/// Default upstream DNS servers.
pub const DEFAULT_UPSTREAM: &[Ipv4Addr] = &[
    Ipv4Addr::new(8, 8, 8, 8), // Google DNS
    Ipv4Addr::new(1, 1, 1, 1), // Cloudflare DNS
];

/// Default cache TTL.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);

/// DNS configuration.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// Listen address.
    pub listen_addr: SocketAddr,
    /// Upstream DNS servers.
    pub upstream: Vec<SocketAddr>,
    /// Cache TTL.
    pub cache_ttl: Duration,
    /// Domain suffix for local names.
    pub local_domain: Option<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), DNS_PORT),
            upstream: DEFAULT_UPSTREAM
                .iter()
                .map(|ip| SocketAddr::new(IpAddr::V4(*ip), DNS_PORT))
                .collect(),
            cache_ttl: DEFAULT_CACHE_TTL,
            local_domain: Some("arcbox.local".to_string()),
        }
    }
}

impl DnsConfig {
    /// Creates a new DNS configuration.
    #[must_use]
    pub fn new(listen_addr: Ipv4Addr) -> Self {
        let mut config = Self {
            listen_addr: SocketAddr::new(IpAddr::V4(listen_addr), DNS_PORT),
            ..Default::default()
        };
        let detected = detect_system_upstream();
        if !detected.is_empty() {
            config.upstream = detected;
        }
        config
    }

    /// Sets the listen address.
    #[must_use]
    pub fn with_listen_addr(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = addr;
        self
    }

    /// Sets the upstream DNS servers.
    #[must_use]
    pub fn with_upstream(mut self, servers: Vec<SocketAddr>) -> Self {
        self.upstream = servers;
        self
    }

    /// Sets the cache TTL.
    #[must_use]
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Sets the local domain suffix.
    #[must_use]
    pub fn with_local_domain(mut self, domain: impl Into<String>) -> Self {
        self.local_domain = Some(domain.into());
        self
    }
}

/// Parses `nameserver` entries from resolv.conf text.
fn parse_resolv_conf_nameservers(contents: &str) -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        let mut parts = line.split_whitespace();
        if parts.next() != Some("nameserver") {
            continue;
        }
        let Some(raw_ip) = parts.next() else {
            continue;
        };

        let Ok(ip) = raw_ip.parse::<IpAddr>() else {
            continue;
        };
        let addr = SocketAddr::new(ip, DNS_PORT);
        if !servers.contains(&addr) {
            servers.push(addr);
        }
    }
    servers
}

/// Detects system DNS upstream servers from `/etc/resolv.conf`.
fn detect_system_upstream() -> Vec<SocketAddr> {
    let Ok(contents) = fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    parse_resolv_conf_nameservers(&contents)
}

/// DNS record type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsRecordType {
    /// A record (IPv4 address).
    A = 1,
    /// AAAA record (IPv6 address).
    Aaaa = 28,
    /// CNAME record.
    Cname = 5,
    /// PTR record (reverse lookup).
    Ptr = 12,
    /// MX record (mail exchange).
    Mx = 15,
    /// TXT record.
    Txt = 16,
    /// SRV record (service).
    Srv = 33,
}

impl TryFrom<u16> for DnsRecordType {
    type Error = ();

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::A),
            28 => Ok(Self::Aaaa),
            5 => Ok(Self::Cname),
            12 => Ok(Self::Ptr),
            15 => Ok(Self::Mx),
            16 => Ok(Self::Txt),
            33 => Ok(Self::Srv),
            _ => Err(()),
        }
    }
}

/// DNS query class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsClass {
    /// Internet class.
    In = 1,
}

/// DNS response code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DnsResponseCode {
    /// No error.
    NoError = 0,
    /// Format error.
    FormErr = 1,
    /// Server failure.
    ServFail = 2,
    /// Name error (NXDOMAIN).
    NxDomain = 3,
    /// Not implemented.
    NotImp = 4,
    /// Refused.
    Refused = 5,
}

/// DNS record data.
#[derive(Debug, Clone)]
pub enum DnsRdata {
    /// A record (IPv4).
    A(Ipv4Addr),
    /// AAAA record (IPv6).
    Aaaa(Ipv6Addr),
    /// CNAME record.
    Cname(String),
    /// Other (raw bytes).
    Raw(Vec<u8>),
}

/// DNS record.
#[derive(Debug, Clone)]
pub struct DnsRecord {
    /// Record name.
    pub name: String,
    /// Record type.
    pub rtype: DnsRecordType,
    /// Record class.
    pub class: DnsClass,
    /// TTL in seconds.
    pub ttl: u32,
    /// Record data.
    pub rdata: DnsRdata,
}

/// DNS cache entry.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Cached records.
    records: Vec<DnsRecord>,
    /// When the entry was cached.
    cached_at: Instant,
    /// TTL from the response.
    ttl: Duration,
}

impl CacheEntry {
    /// Checks if the entry is expired.
    fn is_expired(&self) -> bool {
        self.cached_at.elapsed() >= self.ttl
    }
}

/// DNS forwarder.
///
/// Forwards DNS queries to upstream servers and provides local hostname
/// resolution for VMs.
pub struct DnsForwarder {
    /// Configuration.
    config: DnsConfig,
    /// Local hostname mappings (hostname -> IP).
    local_hosts: HashMap<String, IpAddr>,
    /// DNS cache (query -> response).
    cache: HashMap<(String, DnsRecordType), CacheEntry>,
}

impl DnsForwarder {
    /// Creates a new DNS forwarder.
    #[must_use]
    pub fn new(config: DnsConfig) -> Self {
        Self {
            config,
            local_hosts: HashMap::new(),
            cache: HashMap::new(),
        }
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &DnsConfig {
        &self.config
    }

    /// Adds a local hostname mapping.
    pub fn add_local_host(&mut self, hostname: &str, ip: IpAddr) {
        let hostname = hostname.to_lowercase();
        self.local_hosts.insert(hostname.clone(), ip);

        // Also add with local domain suffix
        if let Some(ref domain) = self.config.local_domain {
            let fqdn = format!("{}.{}", hostname, domain);
            self.local_hosts.insert(fqdn, ip);
        }

        tracing::debug!("Added local host: {} -> {}", hostname, ip);
    }

    /// Removes a local hostname mapping.
    pub fn remove_local_host(&mut self, hostname: &str) {
        let hostname = hostname.to_lowercase();
        self.local_hosts.remove(&hostname);

        if let Some(ref domain) = self.config.local_domain {
            let fqdn = format!("{}.{}", hostname, domain);
            self.local_hosts.remove(&fqdn);
        }
    }

    /// Resolves a local hostname.
    #[must_use]
    pub fn resolve_local(&self, hostname: &str) -> Option<IpAddr> {
        let hostname = hostname.to_lowercase();
        self.local_hosts.get(&hostname).copied()
    }

    /// Attempts to resolve a DNS query locally without any network I/O.
    ///
    /// Returns `Ok(Some(response))` if the query was resolved from local host
    /// mappings, or `Ok(None)` if upstream forwarding is needed. Unsupported
    /// query types (e.g. HTTPS/SVCB) gracefully return `None` instead of
    /// failing, so the caller can forward the raw query.
    pub fn try_resolve_locally(&self, data: &[u8]) -> Option<Vec<u8>> {
        let query = DnsQuery::parse(data).ok()?;
        let ip = self.resolve_local(&query.name)?;
        self.build_local_response(&query, ip).ok()
    }

    /// Returns the upstream DNS server addresses.
    #[must_use]
    pub fn upstream(&self) -> &[SocketAddr] {
        &self.config.upstream
    }

    /// Handles a DNS query packet (synchronous, blocks on upstream forwarding).
    ///
    /// Returns the response packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the query cannot be processed.
    pub fn handle_query(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        // Parse the query
        let query = DnsQuery::parse(data)?;

        // Check for local resolution
        if let Some(ip) = self.resolve_local(&query.name) {
            return self.build_local_response(&query, ip);
        }

        // Check cache
        if let Some(cached) = self.check_cache(&query.name, query.qtype) {
            return self.build_cached_response(&query, &cached);
        }

        // Forward to upstream (synchronous for simplicity)
        // In production, this would be async
        self.forward_query(data)
    }

    /// Checks the cache for a query.
    fn check_cache(&mut self, name: &str, qtype: DnsRecordType) -> Option<Vec<DnsRecord>> {
        let key = (name.to_lowercase(), qtype);

        // Clean up expired entries
        self.cache.retain(|_, v| !v.is_expired());

        self.cache.get(&key).map(|e| e.records.clone())
    }

    /// Builds a response for a local hostname.
    fn build_local_response(&self, query: &DnsQuery, ip: IpAddr) -> Result<Vec<u8>> {
        let mut response = Vec::with_capacity(512);

        // Copy header from query
        response.extend_from_slice(&query.raw_header);

        // Set response flags
        response[2] = 0x81; // QR=1, Opcode=0, AA=0, TC=0, RD=1
        response[3] = 0x80; // RA=1, Z=0, RCODE=0
        response[6] = 0x00; // ANCOUNT high
        response[7] = 0x01; // ANCOUNT low

        // Copy question section
        response.extend_from_slice(&query.raw_question);

        // Build answer
        // Name pointer to question
        response.extend_from_slice(&[0xc0, 0x0c]);

        match ip {
            IpAddr::V4(v4) => {
                // Type A
                response.extend_from_slice(&[0x00, 0x01]);
                // Class IN
                response.extend_from_slice(&[0x00, 0x01]);
                // TTL (300 seconds)
                response.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]);
                // RDLENGTH
                response.extend_from_slice(&[0x00, 0x04]);
                // RDATA
                response.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                // Type AAAA
                response.extend_from_slice(&[0x00, 0x1c]);
                // Class IN
                response.extend_from_slice(&[0x00, 0x01]);
                // TTL (300 seconds)
                response.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]);
                // RDLENGTH
                response.extend_from_slice(&[0x00, 0x10]);
                // RDATA
                response.extend_from_slice(&v6.octets());
            }
        }

        Ok(response)
    }

    /// Builds a response from cached records.
    fn build_cached_response(&self, query: &DnsQuery, records: &[DnsRecord]) -> Result<Vec<u8>> {
        let mut response = Vec::with_capacity(512);

        // Copy header from query
        response.extend_from_slice(&query.raw_header);

        // Set response flags
        response[2] = 0x81;
        response[3] = 0x80;
        response[6] = 0x00;
        response[7] = records.len() as u8;

        // Copy question section
        response.extend_from_slice(&query.raw_question);

        // Build answers
        for record in records {
            // Name pointer
            response.extend_from_slice(&[0xc0, 0x0c]);

            // Type
            response.extend_from_slice(&(record.rtype as u16).to_be_bytes());

            // Class
            response.extend_from_slice(&[0x00, 0x01]);

            // TTL
            response.extend_from_slice(&record.ttl.to_be_bytes());

            // RDATA
            match &record.rdata {
                DnsRdata::A(ip) => {
                    response.extend_from_slice(&[0x00, 0x04]);
                    response.extend_from_slice(&ip.octets());
                }
                DnsRdata::Aaaa(ip) => {
                    response.extend_from_slice(&[0x00, 0x10]);
                    response.extend_from_slice(&ip.octets());
                }
                DnsRdata::Raw(data) => {
                    response.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    response.extend_from_slice(data);
                }
                DnsRdata::Cname(_) => {
                    // Skip CNAME for simplicity
                }
            }
        }

        Ok(response)
    }

    /// Forwards a query to upstream servers.
    fn forward_query(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        use std::net::UdpSocket;

        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| NetError::Dns(format!("failed to bind socket: {}", e)))?;

        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| NetError::Dns(format!("failed to set timeout: {}", e)))?;

        for upstream in &self.config.upstream {
            // Send query
            if socket.send_to(data, upstream).is_err() {
                continue;
            }

            // Receive response
            let mut buf = [0u8; 512];
            match socket.recv_from(&mut buf) {
                Ok((len, _)) => {
                    let response = buf[..len].to_vec();

                    // Cache the response (simplified)
                    if let Ok(query) = DnsQuery::parse(data) {
                        self.cache_response(&query.name, query.qtype, &response);
                    }

                    return Ok(response);
                }
                Err(_) => continue,
            }
        }

        Err(NetError::Dns("all upstream servers failed".to_string()))
    }

    /// Caches a DNS response.
    fn cache_response(&mut self, name: &str, qtype: DnsRecordType, _response: &[u8]) {
        // Simplified caching - just store the query info
        let key = (name.to_lowercase(), qtype);
        let entry = CacheEntry {
            records: Vec::new(), // Would parse from response in full implementation
            cached_at: Instant::now(),
            ttl: self.config.cache_ttl,
        };
        self.cache.insert(key, entry);
    }

    /// Clears the DNS cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

/// Parsed DNS query.
#[derive(Debug)]
struct DnsQuery {
    /// Query name.
    name: String,
    /// Query type.
    qtype: DnsRecordType,
    /// Query class.
    #[allow(dead_code)]
    qclass: DnsClass,
    /// Raw header bytes.
    raw_header: Vec<u8>,
    /// Raw question section.
    raw_question: Vec<u8>,
}

impl DnsQuery {
    /// Parses a DNS query from bytes.
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 12 {
            return Err(NetError::Dns("query too short".to_string()));
        }

        let raw_header = data[..12].to_vec();

        // Parse question section
        let mut offset = 12;
        let mut name_parts = Vec::new();

        // Read name labels
        while offset < data.len() {
            let len = data[offset] as usize;
            if len == 0 {
                offset += 1;
                break;
            }

            if offset + 1 + len > data.len() {
                return Err(NetError::Dns("invalid name".to_string()));
            }

            let label = String::from_utf8_lossy(&data[offset + 1..offset + 1 + len]);
            name_parts.push(label.to_string());
            offset += 1 + len;
        }

        if offset + 4 > data.len() {
            return Err(NetError::Dns("query truncated".to_string()));
        }

        let name = name_parts.join(".");
        let qtype_raw = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let qclass_raw = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);

        let qtype = DnsRecordType::try_from(qtype_raw)
            .map_err(|_| NetError::Dns(format!("unsupported query type: {}", qtype_raw)))?;

        let qclass = if qclass_raw == 1 {
            DnsClass::In
        } else {
            return Err(NetError::Dns(format!("unsupported class: {}", qclass_raw)));
        };

        let raw_question = data[12..offset + 4].to_vec();

        Ok(Self {
            name,
            qtype,
            qclass,
            raw_header,
            raw_question,
        })
    }
}

/// Legacy DNS server (for backwards compatibility).
pub struct DnsServer {
    /// Listen address.
    listen_addr: Ipv4Addr,
    /// Upstream DNS servers.
    #[allow(dead_code)]
    upstream: Vec<Ipv4Addr>,
    /// Internal forwarder.
    forwarder: DnsForwarder,
}

impl DnsServer {
    /// Creates a new DNS server.
    #[must_use]
    pub fn new(listen_addr: Ipv4Addr, upstream: Vec<Ipv4Addr>) -> Self {
        let config = DnsConfig::new(listen_addr).with_upstream(
            upstream
                .iter()
                .map(|ip| SocketAddr::new(IpAddr::V4(*ip), DNS_PORT))
                .collect(),
        );

        Self {
            listen_addr,
            upstream,
            forwarder: DnsForwarder::new(config),
        }
    }

    /// Returns the listen address.
    #[must_use]
    pub fn listen_addr(&self) -> Ipv4Addr {
        self.listen_addr
    }

    /// Adds a local hostname mapping.
    pub fn add_host(&mut self, hostname: &str, ip: IpAddr) {
        self.forwarder.add_local_host(hostname, ip);
    }

    /// Resolves a hostname.
    ///
    /// Returns the IP address if found locally.
    #[must_use]
    pub fn resolve(&self, hostname: &str) -> Option<Ipv4Addr> {
        match self.forwarder.resolve_local(hostname) {
            Some(IpAddr::V4(v4)) => Some(v4),
            _ => None,
        }
    }

    /// Returns a mutable reference to the forwarder.
    pub fn forwarder_mut(&mut self) -> &mut DnsForwarder {
        &mut self.forwarder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_config_default() {
        let config = DnsConfig::default();
        assert_eq!(config.listen_addr.port(), DNS_PORT);
        assert!(!config.upstream.is_empty());
    }

    #[test]
    fn test_dns_record_type_conversion() {
        assert_eq!(DnsRecordType::try_from(1), Ok(DnsRecordType::A));
        assert_eq!(DnsRecordType::try_from(28), Ok(DnsRecordType::Aaaa));
        assert!(DnsRecordType::try_from(999).is_err());
    }

    #[test]
    fn test_dns_forwarder_local_hosts() {
        let config = DnsConfig::default();
        let mut forwarder = DnsForwarder::new(config);

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 64, 10));
        forwarder.add_local_host("myvm", ip);

        assert_eq!(forwarder.resolve_local("myvm"), Some(ip));
        assert_eq!(forwarder.resolve_local("MYVM"), Some(ip)); // Case insensitive
        assert_eq!(forwarder.resolve_local("myvm.arcbox.local"), Some(ip));

        forwarder.remove_local_host("myvm");
        assert_eq!(forwarder.resolve_local("myvm"), None);
    }

    #[test]
    fn test_dns_server_legacy() {
        let server = DnsServer::new(
            Ipv4Addr::new(192, 168, 64, 1),
            vec![Ipv4Addr::new(8, 8, 8, 8)],
        );

        assert_eq!(server.listen_addr(), Ipv4Addr::new(192, 168, 64, 1));
    }

    #[test]
    fn test_parse_resolv_conf_nameservers() {
        let conf = r#"
# comment
nameserver 10.0.0.2
search local
nameserver 2001:4860:4860::8888
nameserver invalid
nameserver 10.0.0.2
"#;
        let servers = parse_resolv_conf_nameservers(conf);
        assert_eq!(
            servers,
            vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), DNS_PORT),
                SocketAddr::new(
                    IpAddr::V6("2001:4860:4860::8888".parse().unwrap()),
                    DNS_PORT
                )
            ]
        );
    }
}
