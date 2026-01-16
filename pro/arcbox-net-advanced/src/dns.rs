//! Advanced DNS features.
//!
//! Provides DNS resolution with split DNS support, custom resolvers,
//! and caching capabilities.

use crate::SplitDnsRule;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// DNS record types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    /// IPv4 address.
    A = 1,
    /// IPv6 address.
    AAAA = 28,
    /// Canonical name.
    CNAME = 5,
    /// Mail exchange.
    MX = 15,
    /// Name server.
    NS = 2,
    /// Pointer record.
    PTR = 12,
    /// Text record.
    TXT = 16,
    /// Service record.
    SRV = 33,
}

impl RecordType {
    fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::A),
            28 => Some(Self::AAAA),
            5 => Some(Self::CNAME),
            15 => Some(Self::MX),
            2 => Some(Self::NS),
            12 => Some(Self::PTR),
            16 => Some(Self::TXT),
            33 => Some(Self::SRV),
            _ => None,
        }
    }
}

/// DNS query result.
#[derive(Debug, Clone)]
pub struct DnsRecord {
    /// Record type.
    pub record_type: RecordType,
    /// TTL in seconds.
    pub ttl: u32,
    /// Record data.
    pub data: DnsRecordData,
}

/// DNS record data variants.
#[derive(Debug, Clone)]
pub enum DnsRecordData {
    /// IPv4 address.
    A(Ipv4Addr),
    /// IPv6 address.
    AAAA(Ipv6Addr),
    /// Canonical name.
    CNAME(String),
    /// Mail exchange.
    MX { priority: u16, exchange: String },
    /// Name server.
    NS(String),
    /// Pointer record.
    PTR(String),
    /// Text record.
    TXT(String),
    /// Service record.
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// Raw data for unknown types.
    Raw(Vec<u8>),
}

/// DNS query response.
#[derive(Debug, Clone)]
pub struct DnsResponse {
    /// Query ID.
    pub id: u16,
    /// Response code (0 = success).
    pub rcode: u8,
    /// Whether the response is authoritative.
    pub authoritative: bool,
    /// Answer records.
    pub answers: Vec<DnsRecord>,
    /// Authority records.
    pub authority: Vec<DnsRecord>,
    /// Additional records.
    pub additional: Vec<DnsRecord>,
}

/// Cached DNS entry.
#[derive(Debug, Clone)]
struct CacheEntry {
    response: DnsResponse,
    expires_at: Instant,
}

/// DNS resolver with caching and split DNS support.
pub struct DnsResolver {
    /// Default DNS servers.
    default_servers: Vec<SocketAddr>,
    /// Split DNS rules.
    rules: Vec<SplitDnsRule>,
    /// DNS cache.
    cache: RwLock<HashMap<(String, RecordType), CacheEntry>>,
    /// Query timeout.
    timeout: Duration,
    /// Maximum cache entries.
    max_cache_entries: usize,
}

impl DnsResolver {
    /// Creates a new DNS resolver with default system DNS servers.
    #[must_use]
    pub fn new() -> Self {
        Self::with_servers(vec![
            SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 53),
            SocketAddr::new(Ipv4Addr::new(8, 8, 4, 4).into(), 53),
        ])
    }

    /// Creates a new DNS resolver with specified servers.
    #[must_use]
    pub fn with_servers(servers: Vec<SocketAddr>) -> Self {
        Self {
            default_servers: servers,
            rules: Vec::new(),
            cache: RwLock::new(HashMap::new()),
            timeout: Duration::from_secs(5),
            max_cache_entries: 1000,
        }
    }

    /// Sets the query timeout.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Adds a split DNS rule.
    pub fn add_rule(&mut self, rule: SplitDnsRule) {
        self.rules.push(rule);
    }

    /// Resolves a hostname to IPv4 addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn resolve_a(&self, hostname: &str) -> io::Result<Vec<Ipv4Addr>> {
        let response = self.query(hostname, RecordType::A)?;

        let addrs = response
            .answers
            .iter()
            .filter_map(|r| {
                if let DnsRecordData::A(addr) = &r.data {
                    Some(*addr)
                } else {
                    None
                }
            })
            .collect();

        Ok(addrs)
    }

    /// Resolves a hostname to IPv6 addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn resolve_aaaa(&self, hostname: &str) -> io::Result<Vec<Ipv6Addr>> {
        let response = self.query(hostname, RecordType::AAAA)?;

        let addrs = response
            .answers
            .iter()
            .filter_map(|r| {
                if let DnsRecordData::AAAA(addr) = &r.data {
                    Some(*addr)
                } else {
                    None
                }
            })
            .collect();

        Ok(addrs)
    }

    /// Performs a DNS query.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn query(&self, hostname: &str, record_type: RecordType) -> io::Result<DnsResponse> {
        // Check cache first.
        if let Some(cached) = self.get_cached(hostname, record_type) {
            return Ok(cached);
        }

        // Determine which servers to use.
        let servers = self.servers_for(hostname);

        // Try each server until one succeeds.
        let mut last_error = io::Error::new(io::ErrorKind::Other, "No DNS servers available");

        for server in servers {
            match self.query_server(&server, hostname, record_type) {
                Ok(response) => {
                    // Cache the response.
                    self.cache_response(hostname, record_type, &response);
                    return Ok(response);
                }
                Err(e) => {
                    last_error = e;
                }
            }
        }

        Err(last_error)
    }

    /// Gets servers for a domain based on split DNS rules.
    fn servers_for(&self, domain: &str) -> Vec<SocketAddr> {
        for rule in &self.rules {
            if domain.ends_with(&rule.domain) {
                return rule
                    .servers
                    .iter()
                    .filter_map(|s| s.parse().ok())
                    .map(|ip: Ipv4Addr| SocketAddr::new(ip.into(), 53))
                    .collect();
            }
        }
        self.default_servers.clone()
    }

    /// Queries a specific DNS server.
    fn query_server(
        &self,
        server: &SocketAddr,
        hostname: &str,
        record_type: RecordType,
    ) -> io::Result<DnsResponse> {
        // Build DNS query packet.
        let query_id = rand_u16();
        let packet = build_dns_query(query_id, hostname, record_type);

        // Send query via UDP.
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(self.timeout))?;
        socket.send_to(&packet, server)?;

        // Receive response.
        let mut buf = [0u8; 512];
        let (len, _) = socket.recv_from(&mut buf)?;

        // Parse response.
        parse_dns_response(&buf[..len])
    }

    /// Gets a cached response if available and not expired.
    fn get_cached(&self, hostname: &str, record_type: RecordType) -> Option<DnsResponse> {
        let cache = self.cache.read().ok()?;
        let key = (hostname.to_lowercase(), record_type);

        if let Some(entry) = cache.get(&key) {
            if entry.expires_at > Instant::now() {
                return Some(entry.response.clone());
            }
        }
        None
    }

    /// Caches a DNS response.
    fn cache_response(&self, hostname: &str, record_type: RecordType, response: &DnsResponse) {
        // Determine TTL from response.
        let ttl = response.answers.first().map(|r| r.ttl).unwrap_or(300);

        let entry = CacheEntry {
            response: response.clone(),
            expires_at: Instant::now() + Duration::from_secs(u64::from(ttl)),
        };

        if let Ok(mut cache) = self.cache.write() {
            // Evict old entries if cache is full.
            if cache.len() >= self.max_cache_entries {
                let now = Instant::now();
                cache.retain(|_, v| v.expires_at > now);
            }

            cache.insert((hostname.to_lowercase(), record_type), entry);
        }
    }

    /// Clears the DNS cache.
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }

    /// Returns cache statistics.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.read().map(|c| c.len()).unwrap_or(0)
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Split DNS resolver (legacy API).
pub struct SplitDnsResolver {
    rules: Vec<SplitDnsRule>,
    default_servers: Vec<Ipv4Addr>,
}

impl SplitDnsResolver {
    /// Creates a new split DNS resolver.
    #[must_use]
    pub fn new(default_servers: Vec<Ipv4Addr>) -> Self {
        Self {
            rules: Vec::new(),
            default_servers,
        }
    }

    /// Adds a split DNS rule.
    pub fn add_rule(&mut self, rule: SplitDnsRule) {
        self.rules.push(rule);
    }

    /// Resolves which DNS servers to use for a domain.
    #[must_use]
    pub fn servers_for(&self, domain: &str) -> Vec<&str> {
        for rule in &self.rules {
            if domain.ends_with(&rule.domain) {
                return rule.servers.iter().map(String::as_str).collect();
            }
        }
        Vec::new()
    }
}

// ============================================================================
// DNS Packet Building and Parsing
// ============================================================================

/// Generates a random u16 for query ID.
fn rand_u16() -> u16 {
    use std::time::SystemTime;
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    (seed & 0xFFFF) as u16
}

/// Builds a DNS query packet.
fn build_dns_query(id: u16, hostname: &str, record_type: RecordType) -> Vec<u8> {
    let mut packet = Vec::with_capacity(512);

    // Header (12 bytes).
    packet.extend_from_slice(&id.to_be_bytes()); // ID
    packet.extend_from_slice(&[0x01, 0x00]); // Flags: standard query, recursion desired
    packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1 question
    packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT: 0 answers
    packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT: 0 authority
    packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT: 0 additional

    // Question section.
    // Encode hostname as labels.
    for label in hostname.split('.') {
        let len = label.len().min(63) as u8;
        packet.push(len);
        packet.extend_from_slice(&label.as_bytes()[..len as usize]);
    }
    packet.push(0); // End of name

    // Type and class.
    packet.extend_from_slice(&(record_type as u16).to_be_bytes()); // TYPE
    packet.extend_from_slice(&[0x00, 0x01]); // CLASS: IN (Internet)

    packet
}

/// Parses a DNS response packet.
fn parse_dns_response(data: &[u8]) -> io::Result<DnsResponse> {
    if data.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response too short",
        ));
    }

    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let rcode = (flags & 0x000F) as u8;
    let authoritative = (flags & 0x0400) != 0;

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let mut offset = 12;

    // Skip question section.
    for _ in 0..qdcount {
        offset = skip_name(data, offset)?;
        offset += 4; // TYPE + CLASS
    }

    // Parse answers.
    let mut answers = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        let (record, new_offset) = parse_resource_record(data, offset)?;
        answers.push(record);
        offset = new_offset;
    }

    // Parse authority.
    let mut authority = Vec::with_capacity(nscount);
    for _ in 0..nscount {
        let (record, new_offset) = parse_resource_record(data, offset)?;
        authority.push(record);
        offset = new_offset;
    }

    // Parse additional.
    let mut additional = Vec::with_capacity(arcount);
    for _ in 0..arcount {
        if let Ok((record, new_offset)) = parse_resource_record(data, offset) {
            additional.push(record);
            offset = new_offset;
        } else {
            break;
        }
    }

    Ok(DnsResponse {
        id,
        rcode,
        authoritative,
        answers,
        authority,
        additional,
    })
}

/// Skips a DNS name in the packet.
fn skip_name(data: &[u8], mut offset: usize) -> io::Result<usize> {
    loop {
        if offset >= data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected end of data",
            ));
        }

        let len = data[offset];

        if len == 0 {
            return Ok(offset + 1);
        }

        // Compression pointer.
        if (len & 0xC0) == 0xC0 {
            return Ok(offset + 2);
        }

        offset += 1 + len as usize;
    }
}

/// Reads a DNS name from the packet.
fn read_name(data: &[u8], mut offset: usize) -> io::Result<(String, usize)> {
    let mut name = String::new();
    let mut jumped = false;
    let original_offset = offset;
    let mut final_offset = offset;

    loop {
        if offset >= data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected end of data",
            ));
        }

        let len = data[offset];

        if len == 0 {
            if !jumped {
                final_offset = offset + 1;
            }
            break;
        }

        // Compression pointer.
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid compression pointer",
                ));
            }

            let ptr = u16::from_be_bytes([len & 0x3F, data[offset + 1]]) as usize;

            if !jumped {
                final_offset = offset + 2;
            }
            jumped = true;
            offset = ptr;
            continue;
        }

        offset += 1;
        let end = offset + len as usize;

        if end > data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Label extends past packet",
            ));
        }

        if !name.is_empty() {
            name.push('.');
        }

        name.push_str(&String::from_utf8_lossy(&data[offset..end]));
        offset = end;
    }

    Ok((name, final_offset))
}

/// Parses a resource record.
fn parse_resource_record(data: &[u8], offset: usize) -> io::Result<(DnsRecord, usize)> {
    let (_name, mut offset) = read_name(data, offset)?;

    if offset + 10 > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Resource record too short",
        ));
    }

    let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let _rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
    let ttl = u32::from_be_bytes([
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]);
    let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;

    offset += 10;

    if offset + rdlength > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "RDATA extends past packet",
        ));
    }

    let rdata = &data[offset..offset + rdlength];
    let record_type = RecordType::from_u16(rtype);

    let record_data = match record_type {
        Some(RecordType::A) if rdlength == 4 => {
            DnsRecordData::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))
        }
        Some(RecordType::AAAA) if rdlength == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            DnsRecordData::AAAA(Ipv6Addr::from(octets))
        }
        Some(RecordType::CNAME) | Some(RecordType::NS) | Some(RecordType::PTR) => {
            let (name, _) = read_name(data, offset)?;
            match record_type {
                Some(RecordType::CNAME) => DnsRecordData::CNAME(name),
                Some(RecordType::NS) => DnsRecordData::NS(name),
                Some(RecordType::PTR) => DnsRecordData::PTR(name),
                _ => DnsRecordData::Raw(rdata.to_vec()),
            }
        }
        Some(RecordType::MX) if rdlength >= 2 => {
            let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
            let (exchange, _) = read_name(data, offset + 2)?;
            DnsRecordData::MX { priority, exchange }
        }
        Some(RecordType::TXT) if !rdata.is_empty() => {
            let txt_len = rdata[0] as usize;
            let txt =
                String::from_utf8_lossy(&rdata[1..1 + txt_len.min(rdata.len() - 1)]).to_string();
            DnsRecordData::TXT(txt)
        }
        Some(RecordType::SRV) if rdlength >= 6 => {
            let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
            let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            let (target, _) = read_name(data, offset + 6)?;
            DnsRecordData::SRV {
                priority,
                weight,
                port,
                target,
            }
        }
        _ => DnsRecordData::Raw(rdata.to_vec()),
    };

    let record = DnsRecord {
        record_type: record_type.unwrap_or(RecordType::A),
        ttl,
        data: record_data,
    };

    Ok((record, offset + rdlength))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dns_query() {
        let packet = build_dns_query(0x1234, "example.com", RecordType::A);

        // Check header.
        assert_eq!(packet[0], 0x12);
        assert_eq!(packet[1], 0x34);

        // Check question count.
        assert_eq!(packet[4], 0x00);
        assert_eq!(packet[5], 0x01);

        // Check name encoding.
        assert_eq!(packet[12], 7); // "example" length
        assert_eq!(&packet[13..20], b"example");
        assert_eq!(packet[20], 3); // "com" length
        assert_eq!(&packet[21..24], b"com");
        assert_eq!(packet[24], 0); // null terminator
    }

    #[test]
    fn test_split_dns_resolver() {
        let mut resolver = SplitDnsResolver::new(vec![Ipv4Addr::new(8, 8, 8, 8)]);

        resolver.add_rule(SplitDnsRule {
            domain: ".internal.company.com".to_string(),
            servers: vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()],
        });

        // Should match rule.
        let servers = resolver.servers_for("api.internal.company.com");
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0], "10.0.0.1");

        // Should not match rule.
        let servers = resolver.servers_for("google.com");
        assert!(servers.is_empty());
    }

    #[test]
    fn test_dns_resolver_creation() {
        let resolver = DnsResolver::new();
        assert_eq!(resolver.cache_size(), 0);
    }

    #[test]
    fn test_record_type_conversion() {
        assert_eq!(RecordType::from_u16(1), Some(RecordType::A));
        assert_eq!(RecordType::from_u16(28), Some(RecordType::AAAA));
        assert_eq!(RecordType::from_u16(5), Some(RecordType::CNAME));
        assert_eq!(RecordType::from_u16(999), None);
    }
}
