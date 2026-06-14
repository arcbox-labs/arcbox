//! DNS resolution log: maps IP addresses back to domain names.
//!
//! When the DNS forwarder receives an upstream response containing A records,
//! it records (IP → domain) entries here. The TcpBridge consults this log to
//! determine the original domain name for a given destination IP, enabling
//! proxy-aware connection strategies (HTTP CONNECT / SOCKS5 use the domain
//! rather than the raw IP).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// TTL for resolution log entries. After this, entries are eligible for eviction.
const ENTRY_TTL: Duration = Duration::from_secs(300);

/// Maximum number of entries before LRU eviction kicks in.
const MAX_ENTRIES: usize = 4096;

/// A single resolution entry: domain name + timestamp.
struct Entry {
    domain: String,
    recorded_at: Instant,
}

/// Thread-safe DNS resolution log shared between the datapath DNS handler
/// and the TcpBridge.
///
/// Records are written on DNS response (datapath task) and read on TCP SYN
/// (TcpBridge). Both happen on the same tokio runtime but potentially
/// different tasks, so interior mutability via `Mutex` is required.
#[derive(Clone)]
pub struct DnsResolutionLog {
    inner: Arc<Mutex<LogInner>>,
}

struct LogInner {
    /// IP → (domain, recorded_at). Most recent resolution wins.
    entries: HashMap<Ipv4Addr, Entry>,
}

impl DnsResolutionLog {
    /// Creates a new empty resolution log.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(LogInner {
                entries: HashMap::with_capacity(256),
            })),
        }
    }

    /// Records that `domain` resolved to `ips` via DNS.
    ///
    /// Called by the datapath DNS handler after receiving an upstream response.
    /// Overwrites previous entries for the same IPs (latest resolution wins).
    pub fn record(&self, domain: &str, ips: &[Ipv4Addr]) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };

        // Evict expired entries if we're near capacity.
        if inner.entries.len() >= MAX_ENTRIES {
            let now = Instant::now();
            inner
                .entries
                .retain(|_, e| now.duration_since(e.recorded_at) < ENTRY_TTL);
        }

        let now = Instant::now();
        for &ip in ips {
            inner.entries.insert(
                ip,
                Entry {
                    domain: domain.to_string(),
                    recorded_at: now,
                },
            );
        }
    }

    /// Looks up the domain name for an IP address.
    ///
    /// Returns `None` if the IP wasn't seen in a recent DNS response or if
    /// the entry has expired.
    #[must_use]
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        let inner = self.inner.lock().ok()?;
        let entry = inner.entries.get(&ip)?;
        if entry.recorded_at.elapsed() < ENTRY_TTL {
            Some(entry.domain.clone())
        } else {
            None
        }
    }
}

impl Default for DnsResolutionLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse A record IPs and the query domain from a raw DNS response.
///
/// Returns `(domain, [ips])` or `None` if the response can't be parsed.
/// Minimal parser — only extracts the question name and A record addresses.
pub fn parse_dns_response_a_records(data: &[u8]) -> Option<(String, Vec<Ipv4Addr>)> {
    // Minimum DNS header (12 bytes) + at least 1 question.
    if data.len() < 12 {
        return None;
    }

    // Check QR bit (must be a response).
    if data[2] & 0x80 == 0 {
        return None;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    if qdcount == 0 || ancount == 0 {
        return None;
    }

    // Parse question name.
    let mut offset = 12;
    let mut name_parts: Vec<String> = Vec::new();
    while offset < data.len() {
        let len = data[offset] as usize;
        if len == 0 {
            offset += 1;
            break;
        }
        if len >= 0xC0 {
            // Compression pointer — skip for question name parsing.
            offset += 2;
            break;
        }
        if offset + 1 + len > data.len() {
            return None;
        }
        name_parts.push(String::from_utf8_lossy(&data[offset + 1..offset + 1 + len]).to_string());
        offset += 1 + len;
    }

    // Skip QTYPE + QCLASS (4 bytes).
    if offset + 4 > data.len() {
        return None;
    }
    offset += 4;

    let domain = name_parts.join(".");
    if domain.is_empty() {
        return None;
    }

    // Parse answer section for A records.
    let mut ips = Vec::new();
    for _ in 0..ancount {
        if offset + 2 > data.len() {
            break;
        }

        // Skip name (may be a compression pointer).
        if data[offset] >= 0xC0 {
            offset += 2;
        } else {
            while offset < data.len() {
                let len = data[offset] as usize;
                if len == 0 {
                    offset += 1;
                    break;
                }
                if len >= 0xC0 {
                    offset += 2;
                    break;
                }
                if offset + 1 + len > data.len() {
                    return None;
                }
                offset += 1 + len;
            }
        }

        if offset + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > data.len() {
            break;
        }

        // Type A (1) with 4-byte RDATA.
        if rtype == 1 && rdlength == 4 {
            ips.push(Ipv4Addr::new(
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ));
        }

        offset += rdlength;
    }

    if ips.is_empty() {
        None
    } else {
        Some((domain, ips))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_lookup() {
        let log = DnsResolutionLog::new();
        let ip = Ipv4Addr::new(198, 18, 2, 17);
        log.record("registry-1.docker.io", &[ip]);
        assert_eq!(log.lookup(ip).as_deref(), Some("registry-1.docker.io"));
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let log = DnsResolutionLog::new();
        assert!(log.lookup(Ipv4Addr::new(1, 2, 3, 4)).is_none());
    }

    #[test]
    fn latest_resolution_wins() {
        let log = DnsResolutionLog::new();
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        log.record("old.example.com", &[ip]);
        log.record("new.example.com", &[ip]);
        assert_eq!(log.lookup(ip).as_deref(), Some("new.example.com"));
    }

    #[test]
    fn parse_response_basic() {
        // Minimal DNS response: registry-1.docker.io → 52.7.198.84
        let mut pkt = Vec::new();
        // Header: QR=1, QDCOUNT=1, ANCOUNT=1
        pkt.extend_from_slice(&[0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Question: registry-1.docker.io
        for label in ["registry-1", "docker", "io"] {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0x00); // root
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
        // Answer: compression pointer + A record
        pkt.extend_from_slice(&[0xC0, 0x0C]); // name pointer
        pkt.extend_from_slice(&[0x00, 0x01]); // TYPE=A
        pkt.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL=300
        pkt.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
        pkt.extend_from_slice(&[52, 7, 198, 84]); // RDATA

        let (domain, ips) = parse_dns_response_a_records(&pkt).unwrap();
        assert_eq!(domain, "registry-1.docker.io");
        assert_eq!(ips, vec![Ipv4Addr::new(52, 7, 198, 84)]);
    }
}
