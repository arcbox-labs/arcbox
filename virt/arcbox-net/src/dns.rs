//! Built-in DNS server/forwarder.
//!
//! This module provides a simple DNS forwarder that can:
//! - Forward queries to upstream DNS servers
//! - Resolve local hostnames (VM names)
//! - Cache DNS responses
//!
//! The implementation handles basic A and AAAA record queries.

mod cache;

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arcbox_dns::LocalHostsTable;

use crate::error::{NetError, Result};

/// Default DNS port.
pub const DNS_PORT: u16 = 53;

/// Default upstream DNS servers.
pub const DEFAULT_UPSTREAM: &[Ipv4Addr] = &[
    Ipv4Addr::new(8, 8, 8, 8), // Google DNS
    Ipv4Addr::new(1, 1, 1, 1), // Cloudflare DNS
];

/// Default cache TTL.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_mins(5);

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
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DNS_PORT),
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
///
/// Filters out problematic upstreams (loopback, fake-IP VPN ranges) when
/// better alternatives are available. Falls back to loopback if it's the
/// only IPv4 option — `forward_dns_async` binds `0.0.0.0:0` so only IPv4
/// upstreams are usable today.
fn parse_resolv_conf_nameservers(contents: &str) -> Vec<SocketAddr> {
    let mut all = Vec::new();
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
        if !all.contains(&addr) {
            all.push(addr);
        }
    }

    // Prefer non-loopback, non-fake-IP IPv4 servers. Keep loopback as
    // fallback when it's the only IPv4 option (common macOS default).
    let preferred: Vec<SocketAddr> = all
        .iter()
        .copied()
        .filter(|a| {
            if a.ip().is_loopback() {
                return false;
            }
            if let IpAddr::V4(v4) = a.ip() {
                let o = v4.octets();
                if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
                    return false;
                }
            }
            // Skip IPv6-only — forward_dns_async binds 0.0.0.0:0 today.
            a.ip().is_ipv4()
        })
        .collect();

    if !preferred.is_empty() {
        return preferred;
    }

    // No preferred servers. Fall back to IPv4 entries (including loopback)
    // but still exclude fake-IP — returning empty lets DnsConfig::new keep
    // DEFAULT_UPSTREAM (8.8.8.8, 1.1.1.1).
    all.into_iter()
        .filter(|a| {
            if let IpAddr::V4(v4) = a.ip() {
                let o = v4.octets();
                !(o[0] == 198 && (o[1] == 18 || o[1] == 19))
            } else {
                false
            }
        })
        .collect()
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// DNS forwarder.
///
/// Forwards DNS queries to upstream servers and provides local hostname
/// resolution for VMs. The local hosts table is behind an `Arc<RwLock<...>>`
/// so it can be shared between the host-side DnsService and the VMM-side
/// datapath forwarder.
pub struct DnsForwarder {
    /// Configuration.
    config: DnsConfig,
    /// Shared local hostname mappings (hostname -> IP).
    local_hosts: Arc<LocalHostsTable>,
    /// Response cache. Behind a `Mutex` (interior mutability) so `handle_query`
    /// takes only `&self`; callers then hold a *read* lock on the surrounding
    /// `RwLock<DnsForwarder>`, so a slow upstream forward never blocks the fast
    /// local-resolution / cache-hit path.
    cache: std::sync::Mutex<HashMap<cache::DnsCacheKey, cache::CacheEntry>>,
}

impl DnsForwarder {
    /// Creates a new DNS forwarder with a fresh (empty) hosts table.
    #[must_use]
    pub fn new(config: DnsConfig) -> Self {
        Self {
            config,
            local_hosts: Arc::new(LocalHostsTable::new(HashMap::new())),
            cache: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Creates a DNS forwarder sharing an existing hosts table.
    ///
    /// Used to connect the VMM-side forwarder to the same table as the
    /// host-side `NetworkManager` forwarder, so `runtime.register_dns()`
    /// updates both simultaneously.
    #[must_use]
    pub fn with_shared_hosts(config: DnsConfig, local_hosts: Arc<LocalHostsTable>) -> Self {
        Self {
            config,
            local_hosts,
            cache: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Returns a clone of the shared hosts table handle.
    pub fn local_hosts_table(&self) -> Arc<LocalHostsTable> {
        Arc::clone(&self.local_hosts)
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &DnsConfig {
        &self.config
    }

    /// Adds a local hostname mapping.
    pub fn add_local_host(&self, hostname: &str, ip: IpAddr) {
        let hostname = hostname.to_lowercase();
        if let Ok(mut hosts) = self.local_hosts.write() {
            hosts.insert(hostname.clone(), ip);
            if let Some(ref domain) = self.config.local_domain {
                let fqdn = format!("{}.{}", hostname, domain);
                hosts.insert(fqdn, ip);
            }
        }
        tracing::debug!("Added local host: {} -> {}", hostname, ip);
    }

    /// Removes a local hostname mapping.
    pub fn remove_local_host(&self, hostname: &str) {
        let hostname = hostname.to_lowercase();
        if let Ok(mut hosts) = self.local_hosts.write() {
            hosts.remove(&hostname);
            if let Some(ref domain) = self.config.local_domain {
                let fqdn = format!("{}.{}", hostname, domain);
                hosts.remove(&fqdn);
            }
        }
    }

    /// Resolves a local hostname.
    #[must_use]
    pub fn resolve_local(&self, hostname: &str) -> Option<IpAddr> {
        let hostname = hostname.to_lowercase();
        self.local_hosts.read().ok()?.get(&hostname).copied()
    }

    /// Attempts to resolve a DNS query locally without any network I/O.
    ///
    /// Returns `Some(response)` if the query was resolved from local host
    /// mappings, or `None` if upstream forwarding is needed. Unsupported
    /// query types (e.g. HTTPS/SVCB) gracefully return `None` instead of
    /// failing, so the caller can forward the raw query.
    pub fn try_resolve_locally(&self, data: &[u8]) -> Option<Vec<u8>> {
        let query = DnsQuery::parse(data).ok()?;
        let ip = self.resolve_local(&query.name)?;
        self.build_local_response(&query, ip).ok()
    }

    /// Attempts local resolution, returning NXDOMAIN for unresolved local-domain queries.
    ///
    /// - Registered local host → `Some(A/AAAA response)`
    /// - Unregistered `*.arcbox.local` (or `*.<local_domain>`) → `Some(NXDOMAIN)`
    /// - Other domains → `None` (caller should forward to upstream)
    pub fn try_resolve_locally_or_nxdomain(&self, data: &[u8]) -> Option<Vec<u8>> {
        let query = DnsQuery::parse(data).ok()?;

        // Check local hosts first.
        if let Some(ip) = self.resolve_local(&query.name) {
            return self.build_local_response(&query, ip).ok();
        }

        // If the query is for our local domain, return NXDOMAIN instead of
        // forwarding to upstream (prevents leaking internal names).
        if let Some(ref domain) = self.config.local_domain {
            let name_lower = query.name.to_lowercase();
            if name_lower == *domain || name_lower.ends_with(&format!(".{domain}")) {
                return Some(Self::build_nxdomain_response(&query));
            }
        }

        // Not a local domain — caller should forward upstream.
        None
    }

    /// Builds an NXDOMAIN response for a query.
    ///
    /// Zeroes all section counts (ANCOUNT, NSCOUNT, ARCOUNT) so that EDNS(0)
    /// queries (which set ARCOUNT=1 in the header) don't produce malformed
    /// responses with advertised-but-missing additional records.
    fn build_nxdomain_response(query: &DnsQuery) -> Vec<u8> {
        let mut response = Vec::with_capacity(query.raw_header.len() + query.raw_question.len());
        response.extend_from_slice(&query.raw_header);

        // QR=1, Opcode=0, AA=1, TC=0, RD=1
        response[2] = 0x85;
        // RA=1, Z=0, RCODE=3 (NXDOMAIN)
        response[3] = 0x83;
        // ANCOUNT = 0
        response[6] = 0x00;
        response[7] = 0x00;
        // NSCOUNT = 0
        response[8] = 0x00;
        response[9] = 0x00;
        // ARCOUNT = 0 (clears EDNS OPT record count from query)
        response[10] = 0x00;
        response[11] = 0x00;

        response.extend_from_slice(&query.raw_question);
        response
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
    pub fn handle_query(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Parse the query
        let query = DnsQuery::parse(data)?;

        // Check for local resolution
        if let Some(ip) = self.resolve_local(&query.name) {
            return self.build_local_response(&query, ip);
        }

        // Check cache
        if let Some(cached) = self.check_cache(&query) {
            return Ok(cached);
        }

        // Forward to upstream (synchronous for simplicity)
        // In production, this would be async
        self.forward_query(data)
    }

    /// Builds a response for a local hostname.
    #[allow(clippy::unnecessary_wraps)] // Result kept for consistent call-site interface
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

    /// Forwards a query to upstream servers.
    ///
    /// Each upstream gets a freshly `connect`ed socket so the kernel drops any
    /// datagram not from that upstream, and the reply's transaction ID must
    /// echo the query's — together closing the off-path cache-poisoning window
    /// an unconnected `recv_from` (which accepted any sender's bytes) left open.
    fn forward_query(&self, data: &[u8]) -> Result<Vec<u8>> {
        use std::net::UdpSocket;

        // The query's transaction ID; a valid reply must echo it.
        let query_id = data.get(0..2);

        for upstream in &self.config.upstream {
            let socket = UdpSocket::bind("0.0.0.0:0")
                .map_err(|e| NetError::Dns(format!("failed to bind socket: {}", e)))?;
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .map_err(|e| NetError::Dns(format!("failed to set timeout: {}", e)))?;

            // connect() filters incoming datagrams to this upstream only.
            if socket.connect(upstream).is_err() || socket.send(data).is_err() {
                continue;
            }

            // Sized for EDNS0 replies (a 512-byte buffer silently truncated
            // them). Reject anything without a full header echoing our txid.
            let mut buf = vec![0u8; 65535];
            if let Ok(len) = socket.recv(&mut buf) {
                if len < 12 || Some(&buf[0..2]) != query_id {
                    continue;
                }
                let response = buf[..len].to_vec();

                if let Ok(query) = DnsQuery::parse(data) {
                    self.cache_response(&query, &response);
                }

                return Ok(response);
            }
        }

        Err(NetError::Dns("all upstream servers failed".to_string()))
    }

    /// Clears the DNS cache.
    pub fn clear_cache(&self) {
        self.cache.lock().expect("dns cache lock poisoned").clear();
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
            .map_err(|()| NetError::Dns(format!("unsupported query type: {}", qtype_raw)))?;

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

    /// Builds a minimal DNS query packet for testing.
    fn build_test_query(name: &str) -> Vec<u8> {
        let mut packet = Vec::with_capacity(64);
        // Header: ID=0xABCD, flags=0x0100 (RD=1), QDCOUNT=1
        packet.extend_from_slice(&[0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Question section: encode name labels
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0x00); // root label
        packet.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        packet.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
        packet
    }

    /// A one-shot fake upstream that answers a single query with a 12-byte
    /// response header, echoing the query's transaction id or corrupting it.
    fn spawn_fake_upstream(echo_txid: bool) -> (SocketAddr, std::thread::JoinHandle<()>) {
        use std::net::UdpSocket;
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (_, peer) = sock.recv_from(&mut buf).unwrap();
            let mut reply = if echo_txid {
                vec![buf[0], buf[1]]
            } else {
                vec![buf[0] ^ 0xFF, buf[1] ^ 0xFF]
            };
            reply.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0]);
            sock.send_to(&reply, peer).unwrap();
        });
        (addr, handle)
    }

    #[test]
    fn forward_query_accepts_matching_transaction_id() {
        let (upstream, handle) = spawn_fake_upstream(true);
        let config = DnsConfig {
            upstream: vec![upstream],
            ..DnsConfig::default()
        };
        let mut forwarder = DnsForwarder::new(config);

        let query = build_test_query("example.com");
        let reply = forwarder
            .forward_query(&query)
            .expect("a reply echoing the txid must be accepted");
        handle.join().unwrap();
        assert_eq!(&reply[0..2], &query[0..2], "reply carries the query's txid");
    }

    /// Regression (cache-poisoning): a reply whose transaction id does not
    /// match the query must be rejected, never returned or cached.
    #[test]
    fn forward_query_rejects_mismatched_transaction_id() {
        let (upstream, handle) = spawn_fake_upstream(false);
        let config = DnsConfig {
            upstream: vec![upstream],
            ..DnsConfig::default()
        };
        let mut forwarder = DnsForwarder::new(config);

        let query = build_test_query("example.com");
        let result = forwarder.forward_query(&query);
        handle.join().unwrap();
        assert!(
            result.is_err(),
            "a reply with the wrong transaction id must be rejected"
        );
    }

    fn build_test_response(query: &[u8], ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
        build_test_response_with_additional(query, ip, ttl, false)
    }

    fn build_test_response_with_additional(
        query: &[u8],
        ip: Ipv4Addr,
        ttl: u32,
        include_additional: bool,
    ) -> Vec<u8> {
        let mut response = Vec::with_capacity(96);
        response.extend_from_slice(&query[..12]);
        response[2] = 0x81; // QR=1, RD=1
        response[3] = 0x80; // RA=1, RCODE=0
        response[6] = 0x00;
        response[7] = 0x01; // ANCOUNT=1
        response[10] = 0x00;
        response[11] = u8::from(include_additional); // ARCOUNT
        response.extend_from_slice(&query[12..]);

        append_a_record(&mut response, ip, ttl);
        if include_additional {
            append_a_record(&mut response, Ipv4Addr::new(192, 0, 2, 53), ttl);
        }

        response
    }

    fn append_a_record(response: &mut Vec<u8>, ip: Ipv4Addr, ttl: u32) {
        response.extend_from_slice(&[0xC0, 0x0C]); // name pointer to question
        response.extend_from_slice(&[0x00, 0x01]); // TYPE=A
        response.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
        response.extend_from_slice(&ip.octets());
    }

    #[test]
    fn test_cache_hit_rewrites_transaction_id_and_preserves_response_bytes() {
        let config = DnsConfig::default();
        let mut forwarder = DnsForwarder::new(config);

        let query = build_test_query("cached.test");
        let parsed_query = DnsQuery::parse(&query).unwrap();
        let response =
            build_test_response_with_additional(&query, Ipv4Addr::new(10, 0, 0, 42), 60, true);
        forwarder.cache_response(&parsed_query, &response);

        let mut next_query = build_test_query("cached.test");
        next_query[0] = 0x12;
        next_query[1] = 0x34;
        let next_query = DnsQuery::parse(&next_query).unwrap();
        let cached = forwarder
            .check_cache(&next_query)
            .expect("response should be cached");

        assert_eq!(&cached[0..2], &[0x12, 0x34]);
        assert_eq!(&cached[2..], &response[2..]);
        assert_eq!(cached[10], 0x00, "ARCOUNT high byte is preserved");
        assert_eq!(cached[11], 0x01, "ARCOUNT low byte is preserved");
    }

    #[test]
    fn test_cache_hit_rewrites_question_case_for_current_query() {
        let config = DnsConfig::default();
        let mut forwarder = DnsForwarder::new(config);

        let query = build_test_query("cached.test");
        let parsed_query = DnsQuery::parse(&query).unwrap();
        let response = build_test_response(&query, Ipv4Addr::new(10, 0, 0, 42), 60);
        forwarder.cache_response(&parsed_query, &response);

        let next_query = build_test_query("CaChEd.TeSt");
        let next_query = DnsQuery::parse(&next_query).unwrap();
        let cached = forwarder
            .check_cache(&next_query)
            .expect("response should be cached");

        assert_eq!(
            &cached[12..12 + next_query.raw_question.len()],
            next_query.raw_question
        );
    }

    #[test]
    fn test_cache_hit_rewrites_ttl_to_remaining_lifetime() {
        let config = DnsConfig::default();
        let mut forwarder = DnsForwarder::new(config);

        let query = build_test_query("ttl.test");
        let parsed_query = DnsQuery::parse(&query).unwrap();
        let response = build_test_response(&query, Ipv4Addr::new(10, 0, 0, 43), 60);
        forwarder.cache_response(&parsed_query, &response);

        let key =
            cache::DnsCacheKey::new(&parsed_query.name, parsed_query.qtype, parsed_query.qclass);
        {
            let mut cache = forwarder.cache.lock().unwrap();
            let entry = cache.get_mut(&key).expect("response should be cached");
            entry.cached_at -= Duration::from_secs(10);
        }

        let cached = forwarder
            .check_cache(&parsed_query)
            .expect("response should be cached");
        let ttl_offset = 12 + parsed_query.raw_question.len() + 2 + 2 + 2;
        let ttl = u32::from_be_bytes([
            cached[ttl_offset],
            cached[ttl_offset + 1],
            cached[ttl_offset + 2],
            cached[ttl_offset + 3],
        ]);
        assert_eq!(ttl, 50);
    }

    #[test]
    fn test_cache_response_uses_response_ttl_capped_by_config() {
        let config = DnsConfig::default().with_cache_ttl(Duration::from_secs(30));
        let mut forwarder = DnsForwarder::new(config);

        let query = build_test_query("ttl.test");
        let parsed_query = DnsQuery::parse(&query).unwrap();
        let response = build_test_response(&query, Ipv4Addr::new(10, 0, 0, 43), 120);
        forwarder.cache_response(&parsed_query, &response);

        let key =
            cache::DnsCacheKey::new(&parsed_query.name, parsed_query.qtype, parsed_query.qclass);
        let cache = forwarder.cache.lock().unwrap();
        let entry = cache.get(&key).expect("response should be cached");
        assert_eq!(entry.ttl, Duration::from_secs(30));
    }

    #[test]
    fn test_cache_response_skips_empty_answers() {
        let config = DnsConfig::default();
        let mut forwarder = DnsForwarder::new(config);

        let query = build_test_query("empty.test");
        let parsed_query = DnsQuery::parse(&query).unwrap();
        let mut response = query;
        response[2] = 0x81;
        response[3] = 0x80;
        response[6] = 0x00;
        response[7] = 0x00; // ANCOUNT=0

        forwarder.cache_response(&parsed_query, &response);

        assert!(forwarder.check_cache(&parsed_query).is_none());
    }

    #[test]
    fn test_cache_response_skips_malformed_response() {
        let config = DnsConfig::default();
        let mut forwarder = DnsForwarder::new(config);

        let query = build_test_query("malformed.test");
        let parsed_query = DnsQuery::parse(&query).unwrap();
        forwarder.cache_response(&parsed_query, &[0x12, 0x34]);

        assert!(forwarder.check_cache(&parsed_query).is_none());
    }

    #[test]
    fn test_try_resolve_locally_or_nxdomain_returns_response_for_registered() {
        let config = DnsConfig::default();
        let mut forwarder = DnsForwarder::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(172, 17, 0, 2));
        forwarder.add_local_host("my-nginx", ip);

        let query = build_test_query("my-nginx.arcbox.local");
        let response = forwarder
            .try_resolve_locally_or_nxdomain(&query)
            .expect("should resolve registered host");

        // Verify QR=1, RCODE=0, ANCOUNT=1.
        assert_eq!(response[2] & 0x80, 0x80, "QR bit");
        assert_eq!(response[3] & 0x0F, 0, "RCODE=NoError");
        assert_eq!(response[7], 1, "ANCOUNT=1");
    }

    #[test]
    fn test_try_resolve_locally_or_nxdomain_returns_nxdomain() {
        let config = DnsConfig::default();
        let forwarder = DnsForwarder::new(config);

        let query = build_test_query("nonexistent.arcbox.local");
        let response = forwarder
            .try_resolve_locally_or_nxdomain(&query)
            .expect("should return NXDOMAIN for unregistered local host");

        // Verify QR=1, RCODE=3 (NXDOMAIN), ANCOUNT=0.
        assert_eq!(response[2] & 0x80, 0x80, "QR bit");
        assert_eq!(response[3] & 0x0F, 3, "RCODE=NXDOMAIN");
        assert_eq!(response[7], 0, "ANCOUNT=0");
    }

    #[test]
    fn test_try_resolve_locally_or_nxdomain_returns_none_for_external() {
        let config = DnsConfig::default();
        let forwarder = DnsForwarder::new(config);

        let query = build_test_query("google.com");
        let result = forwarder.try_resolve_locally_or_nxdomain(&query);

        assert!(result.is_none(), "should return None for non-local domains");
    }

    #[test]
    fn test_try_resolve_locally_or_nxdomain_bare_domain() {
        // Query for "arcbox.local" itself (no subdomain) should also NXDOMAIN
        // if not registered.
        let config = DnsConfig::default();
        let forwarder = DnsForwarder::new(config);

        let query = build_test_query("arcbox.local");
        let response = forwarder
            .try_resolve_locally_or_nxdomain(&query)
            .expect("bare domain should return NXDOMAIN");

        assert_eq!(response[3] & 0x0F, 3, "RCODE=NXDOMAIN");
    }

    #[test]
    fn test_custom_domain_nxdomain() {
        let config = DnsConfig::default().with_local_domain("myorg.test");
        let mut forwarder = DnsForwarder::new(config);

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        forwarder.add_local_host("web", ip);

        // Registered host under custom domain resolves.
        let query = build_test_query("web.myorg.test");
        let response = forwarder
            .try_resolve_locally_or_nxdomain(&query)
            .expect("should resolve registered host under custom domain");
        assert_eq!(response[3] & 0x0F, 0, "RCODE=NoError");
        assert_eq!(response[7], 1, "ANCOUNT=1");

        // Unregistered host under custom domain → NXDOMAIN.
        let query = build_test_query("unknown.myorg.test");
        let response = forwarder
            .try_resolve_locally_or_nxdomain(&query)
            .expect("should NXDOMAIN for unregistered custom-domain host");
        assert_eq!(response[3] & 0x0F, 3, "RCODE=NXDOMAIN");

        // Query under default arcbox.local → None (forwarded), not NXDOMAIN.
        let query = build_test_query("something.arcbox.local");
        assert!(
            forwarder.try_resolve_locally_or_nxdomain(&query).is_none(),
            "old default domain should not be handled after domain change"
        );
    }

    #[test]
    fn test_parse_resolv_conf_nameservers() {
        let conf = r"
# comment
nameserver 10.0.0.2
search local
nameserver 2001:4860:4860::8888
nameserver invalid
nameserver 10.0.0.2
";
        let servers = parse_resolv_conf_nameservers(conf);
        // IPv6 servers are filtered because forward_dns_async binds 0.0.0.0:0.
        // The IPv4 server is preferred; duplicates are deduplicated.
        assert_eq!(
            servers,
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                DNS_PORT
            )]
        );
    }

    #[test]
    fn test_parse_resolv_conf_loopback_fallback() {
        // When only loopback + IPv6 are available, keep loopback as fallback.
        let conf = "nameserver 127.0.0.1\nnameserver 2001:4860:4860::8888\n";
        let servers = parse_resolv_conf_nameservers(conf);
        assert_eq!(
            servers,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DNS_PORT)]
        );
    }

    #[test]
    fn test_parse_resolv_conf_filters_fake_ip() {
        let conf = "nameserver 198.18.0.2\nnameserver 8.8.8.8\n";
        let servers = parse_resolv_conf_nameservers(conf);
        assert_eq!(
            servers,
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                DNS_PORT
            )]
        );
    }

    #[test]
    fn test_parse_resolv_conf_only_fake_ip_returns_empty() {
        // Only fake-IP entries → empty list so DnsConfig::new keeps DEFAULT_UPSTREAM.
        let conf = "nameserver 198.18.0.2\nnameserver 198.19.1.1\n";
        let servers = parse_resolv_conf_nameservers(conf);
        assert!(servers.is_empty());
    }
}
