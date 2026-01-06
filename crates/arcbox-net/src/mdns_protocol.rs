//! mDNS protocol implementation for ArcBox.
//!
//! mDNS (Multicast DNS) is DNS over multicast UDP (RFC 6762).
//! Key differences from unicast DNS:
//! - Uses multicast address 224.0.0.251 port 5353
//! - Queries AND responses go to multicast address
//! - Cache-flush bit (0x8000) in class field
//! - TTL=0 means "goodbye" (record should be deleted)
//!
//! We only implement the subset needed for ArcBox:
//! - Responding to A record queries for *.arcbox.local
//! - Sending unsolicited announcements
//! - Sending goodbye packets

use std::net::Ipv4Addr;

/// mDNS multicast address (224.0.0.251).
pub const MDNS_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// mDNS port (5353).
pub const MDNS_PORT: u16 = 5353;

/// DNS record type: A (IPv4 address).
pub const DNS_TYPE_A: u16 = 1;

/// DNS record type: AAAA (IPv6 address).
pub const DNS_TYPE_AAAA: u16 = 28;

/// DNS record type: ANY (wildcard).
pub const DNS_TYPE_ANY: u16 = 255;

/// DNS class: IN (Internet).
pub const DNS_CLASS_IN: u16 = 1;

/// Cache-flush bit for mDNS class field.
pub const CACHE_FLUSH_BIT: u16 = 0x8000;

/// mDNS protocol error.
#[derive(Debug, Clone)]
pub enum MdnsProtocolError {
    /// Packet is too short.
    PacketTooShort {
        /// Expected minimum length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// Invalid domain name at the given offset.
    InvalidDomainName(usize),

    /// Not a query packet.
    NotAQuery,

    /// Invalid UTF-8 in domain name.
    InvalidUtf8,
}

impl std::fmt::Display for MdnsProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PacketTooShort { expected, actual } => {
                write!(
                    f,
                    "packet too short: expected at least {} bytes, got {}",
                    expected, actual
                )
            }
            Self::InvalidDomainName(offset) => {
                write!(f, "invalid domain name at offset {}", offset)
            }
            Self::NotAQuery => write!(f, "not a query packet"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 in domain name"),
        }
    }
}

impl std::error::Error for MdnsProtocolError {}

/// A parsed mDNS query.
#[derive(Debug, Clone)]
pub struct MdnsQuery {
    /// Transaction ID (often 0 for mDNS, but echo it anyway).
    pub id: u16,

    /// The queried domain name (lowercase).
    pub domain: String,

    /// Query type (1 = A, 28 = AAAA, 255 = ANY).
    pub query_type: u16,

    /// Whether unicast response is requested (QU bit).
    pub unicast_response: bool,
}

/// Parse an mDNS query packet.
///
/// mDNS queries look like regular DNS queries but:
/// - May have ID = 0
/// - May have QU bit set in class field (unicast response requested)
/// - May contain multiple questions (we only handle first)
///
/// # Returns
/// - `Ok(Some(query))` if this is a query we should respond to
/// - `Ok(None)` if this is a response or non-query packet
/// - `Err` if packet is malformed
pub fn parse_query(packet: &[u8]) -> Result<Option<MdnsQuery>, MdnsProtocolError> {
    // Minimum DNS header is 12 bytes
    if packet.len() < 12 {
        return Err(MdnsProtocolError::PacketTooShort {
            expected: 12,
            actual: packet.len(),
        });
    }

    // Check QR bit (bit 7 of byte 2): 0 = query, 1 = response
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let is_query = (flags & 0x8000) == 0;

    if !is_query {
        return Ok(None); // Ignore responses
    }

    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);

    if qdcount == 0 {
        return Ok(None); // No questions
    }

    // Parse first question
    let (domain, offset) = decode_domain_name(packet, 12)?;

    if packet.len() < offset + 4 {
        return Err(MdnsProtocolError::PacketTooShort {
            expected: offset + 4,
            actual: packet.len(),
        });
    }

    let query_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let query_class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);

    // QU bit is the top bit of class field
    let unicast_response = (query_class & 0x8000) != 0;

    Ok(Some(MdnsQuery {
        id,
        domain: domain.to_lowercase(),
        query_type,
        unicast_response,
    }))
}

/// Build an mDNS response packet.
///
/// # Arguments
/// - `query`: The query to respond to
/// - `ip`: The IPv4 address to return
/// - `ttl`: Time-to-live in seconds (use 0 for goodbye)
/// - `cache_flush`: Whether to set cache-flush bit (usually true)
///
/// # mDNS Response Format
/// - Header: ID, Flags (QR=1, AA=1), counts
/// - Answer section: NAME, TYPE=A, CLASS=IN|cache-flush, TTL, IP
#[must_use]
pub fn build_response(query: &MdnsQuery, ip: Ipv4Addr, ttl: u32, cache_flush: bool) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);

    // Header
    packet.extend_from_slice(&query.id.to_be_bytes()); // ID
    packet.extend_from_slice(&[0x84, 0x00]); // Flags: QR=1, AA=1, RCODE=0
    packet.extend_from_slice(&[0x00, 0x00]); // QDCOUNT = 0 (no question in response)
    packet.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1
    packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

    // Answer section
    packet.extend(encode_domain_name(&query.domain));
    packet.extend_from_slice(&DNS_TYPE_A.to_be_bytes()); // TYPE = A

    // CLASS = IN (1) with optional cache-flush bit
    let class: u16 = if cache_flush {
        DNS_CLASS_IN | CACHE_FLUSH_BIT
    } else {
        DNS_CLASS_IN
    };
    packet.extend_from_slice(&class.to_be_bytes());

    packet.extend_from_slice(&ttl.to_be_bytes()); // TTL
    packet.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
    packet.extend_from_slice(&ip.octets()); // RDATA = IP address

    packet
}

/// Build an unsolicited mDNS announcement.
///
/// Used to proactively inform the network about a new container.
/// Same format as response but with ID=0 and no question section.
///
/// # Arguments
/// - `domain`: The domain name to announce (e.g., "nginx.arcbox.local")
/// - `ip`: The IPv4 address
/// - `ttl`: Time-to-live (use 0 for goodbye)
#[must_use]
pub fn build_announcement(domain: &str, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);

    // Header
    packet.extend_from_slice(&[0x00, 0x00]); // ID = 0 for unsolicited
    packet.extend_from_slice(&[0x84, 0x00]); // Flags: QR=1, AA=1
    packet.extend_from_slice(&[0x00, 0x00]); // QDCOUNT = 0
    packet.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1
    packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

    // Answer section
    packet.extend(encode_domain_name(domain));
    packet.extend_from_slice(&DNS_TYPE_A.to_be_bytes()); // TYPE = A
    packet.extend_from_slice(&(DNS_CLASS_IN | CACHE_FLUSH_BIT).to_be_bytes()); // CLASS = IN + cache-flush
    packet.extend_from_slice(&ttl.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
    packet.extend_from_slice(&ip.octets());

    packet
}

/// Build a goodbye packet (TTL=0 announcement).
///
/// Tells other devices to remove the cached record.
#[must_use]
pub fn build_goodbye(domain: &str) -> Vec<u8> {
    // Goodbye is just an announcement with TTL=0 and IP=0.0.0.0
    build_announcement(domain, Ipv4Addr::UNSPECIFIED, 0)
}

/// Encode a domain name in DNS wire format.
///
/// "nginx.arcbox.local" → [5, 'n', 'g', 'i', 'n', 'x', 6, 'a', 'r', 'c', 'b', 'o', 'x', 5, 'l', 'o', 'c', 'a', 'l', 0]
#[must_use]
pub fn encode_domain_name(domain: &str) -> Vec<u8> {
    let mut result = Vec::new();

    for label in domain.split('.') {
        if label.is_empty() {
            continue;
        }
        result.push(label.len() as u8);
        result.extend(label.as_bytes());
    }
    result.push(0); // Null terminator

    result
}

/// Decode a domain name from DNS wire format.
///
/// Handles both regular labels and compressed pointers (0xC0 prefix).
/// Returns (domain_name, next_offset).
pub fn decode_domain_name(
    packet: &[u8],
    start: usize,
) -> Result<(String, usize), MdnsProtocolError> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut jumped = false;
    let mut next_offset = start;
    let mut jumps = 0;
    const MAX_JUMPS: usize = 10; // Prevent infinite loops

    loop {
        if offset >= packet.len() {
            return Err(MdnsProtocolError::InvalidDomainName(offset));
        }

        let len = packet[offset] as usize;

        if len == 0 {
            // End of domain name
            if !jumped {
                next_offset = offset + 1;
            }
            break;
        }

        // Check for compression pointer (top 2 bits = 11)
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= packet.len() {
                return Err(MdnsProtocolError::InvalidDomainName(offset));
            }

            jumps += 1;
            if jumps > MAX_JUMPS {
                return Err(MdnsProtocolError::InvalidDomainName(offset));
            }

            let pointer = ((len & 0x3F) << 8) | (packet[offset + 1] as usize);

            if !jumped {
                next_offset = offset + 2;
            }
            jumped = true;
            offset = pointer;
            continue;
        }

        // Regular label
        offset += 1;
        if offset + len > packet.len() {
            return Err(MdnsProtocolError::InvalidDomainName(offset));
        }

        let label = std::str::from_utf8(&packet[offset..offset + len])
            .map_err(|_| MdnsProtocolError::InvalidUtf8)?;
        labels.push(label.to_string());
        offset += len;
    }

    Ok((labels.join("."), next_offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_domain_name() {
        let encoded = encode_domain_name("nginx.arcbox.local");
        assert_eq!(encoded[0], 5); // "nginx" length
        assert_eq!(&encoded[1..6], b"nginx");
        assert_eq!(encoded[6], 6); // "arcbox" length
        assert_eq!(&encoded[7..13], b"arcbox");
        assert_eq!(encoded[13], 5); // "local" length
        assert_eq!(&encoded[14..19], b"local");
        assert_eq!(encoded[19], 0); // null terminator
    }

    #[test]
    fn test_encode_domain_name_empty_labels() {
        // Handle trailing dots or empty parts
        let encoded = encode_domain_name("test..arcbox.local.");
        // Should skip empty labels
        assert!(encoded.ends_with(&[0]));
    }

    #[test]
    fn test_decode_domain_name() {
        let packet = encode_domain_name("test.arcbox.local");
        let (domain, len) = decode_domain_name(&packet, 0).unwrap();
        assert_eq!(domain, "test.arcbox.local");
        assert_eq!(len, packet.len());
    }

    #[test]
    fn test_decode_domain_name_with_compression() {
        // Build a packet with compression pointer
        let mut packet = Vec::new();
        // First name at offset 0
        packet.extend(encode_domain_name("arcbox.local")); // ends at offset ~14
        let first_name_end = packet.len();

        // Second name using compression: "test" + pointer to "arcbox.local"
        packet.push(4); // "test" length
        packet.extend(b"test");
        packet.push(0xC0); // compression pointer
        packet.push(0x00); // pointer to offset 0

        let (domain, _) = decode_domain_name(&packet, first_name_end).unwrap();
        assert_eq!(domain, "test.arcbox.local");
    }

    #[test]
    fn test_build_announcement() {
        let packet = build_announcement("nginx.arcbox.local", Ipv4Addr::new(192, 168, 64, 10), 120);

        // Verify header
        assert_eq!(packet[0..2], [0x00, 0x00]); // ID = 0
        assert_eq!(packet[2] & 0x80, 0x80); // QR = 1 (response)
        assert_eq!(packet[7], 1); // ANCOUNT = 1

        // Verify IP at end
        let ip_start = packet.len() - 4;
        assert_eq!(&packet[ip_start..], &[192, 168, 64, 10]);
    }

    #[test]
    fn test_build_goodbye() {
        let packet = build_goodbye("nginx.arcbox.local");

        // TTL should be 0 (bytes before RDLENGTH)
        let rdlen_pos = packet.len() - 6; // 2 bytes RDLEN + 4 bytes IP
        let ttl_pos = rdlen_pos - 4;
        assert_eq!(&packet[ttl_pos..ttl_pos + 4], &[0, 0, 0, 0]);

        // IP should be 0.0.0.0
        assert_eq!(&packet[packet.len() - 4..], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_build_response() {
        let query = MdnsQuery {
            id: 0x1234,
            domain: "test.arcbox.local".to_string(),
            query_type: DNS_TYPE_A,
            unicast_response: false,
        };

        let packet = build_response(&query, Ipv4Addr::new(10, 0, 0, 1), 120, true);

        // Check ID is echoed
        assert_eq!(u16::from_be_bytes([packet[0], packet[1]]), 0x1234);

        // Check QR=1 (response)
        assert_eq!(packet[2] & 0x80, 0x80);

        // Check answer count = 1
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 1);
    }

    #[test]
    fn test_parse_query() {
        // Build a simple A query for test.arcbox.local
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0x00, 0x01]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags: query
        packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
        packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
        packet.extend(encode_domain_name("test.arcbox.local"));
        packet.extend_from_slice(&[0x00, 0x01]); // TYPE = A
        packet.extend_from_slice(&[0x00, 0x01]); // CLASS = IN

        let query = parse_query(&packet).unwrap().unwrap();
        assert_eq!(query.domain, "test.arcbox.local");
        assert_eq!(query.query_type, 1);
        assert!(!query.unicast_response);
    }

    #[test]
    fn test_parse_query_with_qu_bit() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags: query
        packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
        packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
        packet.extend(encode_domain_name("test.arcbox.local"));
        packet.extend_from_slice(&[0x00, 0x01]); // TYPE = A
        packet.extend_from_slice(&[0x80, 0x01]); // CLASS = IN with QU bit set

        let query = parse_query(&packet).unwrap().unwrap();
        assert!(query.unicast_response);
    }

    #[test]
    fn test_parse_response_returns_none() {
        // Response packet (QR=1)
        let packet = [
            0x00, 0x00, // ID
            0x84, 0x00, // Flags: QR=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(parse_query(&packet).unwrap().is_none());
    }

    #[test]
    fn test_parse_query_too_short() {
        let packet = [0x00, 0x01, 0x00]; // Only 3 bytes
        assert!(matches!(
            parse_query(&packet),
            Err(MdnsProtocolError::PacketTooShort { .. })
        ));
    }

    #[test]
    fn test_parse_query_no_questions() {
        let packet = [
            0x00, 0x00, // ID
            0x00, 0x00, // Flags: query
            0x00, 0x00, // QDCOUNT = 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(parse_query(&packet).unwrap().is_none());
    }

    #[test]
    fn test_constants() {
        assert_eq!(MDNS_MULTICAST_ADDR, Ipv4Addr::new(224, 0, 0, 251));
        assert_eq!(MDNS_PORT, 5353);
        assert_eq!(DNS_TYPE_A, 1);
        assert_eq!(DNS_TYPE_AAAA, 28);
        assert_eq!(DNS_TYPE_ANY, 255);
    }
}
