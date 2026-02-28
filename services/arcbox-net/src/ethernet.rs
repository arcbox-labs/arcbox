//! Ethernet frame parsing, construction, and ARP handling.
//!
//! Provides minimal L2 utilities for the custom network datapath:
//! - Ethernet header parse/construct
//! - ARP responder (gateway only)
//! - UDP/IP/Ethernet packet builder for DHCP and DNS responses

use std::net::Ipv4Addr;

/// Ethernet header size in bytes.
pub const ETH_HEADER_LEN: usize = 14;

/// Minimum frame size for an ARP packet (Ethernet + 28-byte ARP payload).
const ARP_FRAME_MIN_LEN: usize = ETH_HEADER_LEN + 28;

/// EtherType values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Arp,
    Ipv6,
    Unknown(u16),
}

impl EtherType {
    /// Parses EtherType from raw two-byte big-endian value.
    #[must_use]
    pub fn from_raw(raw: u16) -> Self {
        match raw {
            0x0800 => Self::Ipv4,
            0x0806 => Self::Arp,
            0x86DD => Self::Ipv6,
            other => Self::Unknown(other),
        }
    }

    /// Returns the raw two-byte big-endian value.
    #[must_use]
    pub fn to_raw(self) -> u16 {
        match self {
            Self::Ipv4 => 0x0800,
            Self::Arp => 0x0806,
            Self::Ipv6 => 0x86DD,
            Self::Unknown(v) => v,
        }
    }
}

/// Parsed Ethernet header fields.
#[derive(Debug, Clone, Copy)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: EtherType,
}

impl EthernetHeader {
    /// Parses an Ethernet header from the start of `data`.
    ///
    /// Returns `None` if the data is shorter than 14 bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < ETH_HEADER_LEN {
            return None;
        }
        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dst_mac.copy_from_slice(&data[0..6]);
        src_mac.copy_from_slice(&data[6..12]);
        let raw_type = u16::from_be_bytes([data[12], data[13]]);
        Some(Self {
            dst_mac,
            src_mac,
            ethertype: EtherType::from_raw(raw_type),
        })
    }

    /// Serialises the header into a 14-byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ETH_HEADER_LEN] {
        let mut buf = [0u8; ETH_HEADER_LEN];
        buf[0..6].copy_from_slice(&self.dst_mac);
        buf[6..12].copy_from_slice(&self.src_mac);
        buf[12..14].copy_from_slice(&self.ethertype.to_raw().to_be_bytes());
        buf
    }
}

/// Returns the payload slice after the 14-byte Ethernet header.
#[must_use]
pub fn strip_ethernet_header(frame: &[u8]) -> &[u8] {
    if frame.len() <= ETH_HEADER_LEN {
        return &[];
    }
    &frame[ETH_HEADER_LEN..]
}

/// Prepends a 14-byte Ethernet header (IPv4 EtherType) to an IP packet.
#[must_use]
pub fn prepend_ethernet_header(ip_packet: &[u8], dst_mac: [u8; 6], src_mac: [u8; 6]) -> Vec<u8> {
    let hdr = EthernetHeader {
        dst_mac,
        src_mac,
        ethertype: EtherType::Ipv4,
    };
    let mut frame = Vec::with_capacity(ETH_HEADER_LEN + ip_packet.len());
    frame.extend_from_slice(&hdr.to_bytes());
    frame.extend_from_slice(ip_packet);
    frame
}

// ============================================================================
// ARP Responder
// ============================================================================

/// Responds to ARP requests targeting the gateway IP.
pub struct ArpResponder {
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
}

impl ArpResponder {
    /// Creates a new ARP responder for the given gateway.
    #[must_use]
    pub fn new(gateway_ip: Ipv4Addr, gateway_mac: [u8; 6]) -> Self {
        Self {
            gateway_ip,
            gateway_mac,
        }
    }

    /// If `frame` is an ARP Request for the gateway IP, returns a complete
    /// ARP Reply Ethernet frame. Otherwise returns `None`.
    #[must_use]
    pub fn handle_arp(&self, frame: &[u8]) -> Option<Vec<u8>> {
        if frame.len() < ARP_FRAME_MIN_LEN {
            return None;
        }

        let arp = &frame[ETH_HEADER_LEN..];

        // Hardware type = Ethernet (1), Protocol type = IPv4 (0x0800)
        if u16::from_be_bytes([arp[0], arp[1]]) != 1
            || u16::from_be_bytes([arp[2], arp[3]]) != 0x0800
        {
            return None;
        }

        // HLEN = 6, PLEN = 4, Operation = Request (1)
        if arp[4] != 6 || arp[5] != 4 || u16::from_be_bytes([arp[6], arp[7]]) != 1 {
            return None;
        }

        // Target protocol address (bytes 24..28 of ARP payload)
        let target_ip = Ipv4Addr::new(arp[24], arp[25], arp[26], arp[27]);
        if target_ip != self.gateway_ip {
            return None;
        }

        // Sender hardware address (bytes 8..14) and sender IP (14..18)
        let mut sender_mac = [0u8; 6];
        sender_mac.copy_from_slice(&arp[8..14]);
        let sender_ip_bytes: [u8; 4] = [arp[14], arp[15], arp[16], arp[17]];

        // Build ARP Reply
        let mut reply = Vec::with_capacity(ARP_FRAME_MIN_LEN);

        // Ethernet header: dst=sender, src=gateway, EtherType=ARP
        reply.extend_from_slice(&sender_mac);
        reply.extend_from_slice(&self.gateway_mac);
        reply.extend_from_slice(&0x0806u16.to_be_bytes());

        // ARP payload
        reply.extend_from_slice(&1u16.to_be_bytes()); // Hardware type: Ethernet
        reply.extend_from_slice(&0x0800u16.to_be_bytes()); // Protocol type: IPv4
        reply.push(6); // HLEN
        reply.push(4); // PLEN
        reply.extend_from_slice(&2u16.to_be_bytes()); // Operation: Reply
        reply.extend_from_slice(&self.gateway_mac); // Sender hardware addr
        reply.extend_from_slice(&self.gateway_ip.octets()); // Sender protocol addr
        reply.extend_from_slice(&sender_mac); // Target hardware addr
        reply.extend_from_slice(&sender_ip_bytes); // Target protocol addr

        Some(reply)
    }
}

// ============================================================================
// UDP/IP/Ethernet packet builder
// ============================================================================

/// Builds a complete Ethernet frame containing a UDP/IPv4 packet.
///
/// Used to construct DHCP and DNS responses that are injected directly
/// into the guest FD.
#[must_use]
pub fn build_udp_ip_ethernet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let ip_total_len = 20 + udp_len;
    let frame_len = ETH_HEADER_LEN + ip_total_len;
    let mut frame = vec![0u8; frame_len];

    // -- Ethernet header --
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // -- IPv4 header (20 bytes, no options) --
    let ip = &mut frame[ETH_HEADER_LEN..];
    ip[0] = 0x45; // Version 4, IHL 5
    ip[2..4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    ip[8] = 64; // TTL
    ip[9] = 17; // Protocol: UDP
    ip[12..16].copy_from_slice(&src_ip.octets());
    ip[16..20].copy_from_slice(&dst_ip.octets());

    // IP header checksum
    let ip_cksum = ipv4_header_checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // -- UDP header --
    let udp_start = ETH_HEADER_LEN + 20;
    frame[udp_start..udp_start + 2].copy_from_slice(&src_port.to_be_bytes());
    frame[udp_start + 2..udp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
    frame[udp_start + 4..udp_start + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // UDP checksum = 0 (optional for IPv4)
    frame[udp_start + 6..udp_start + 8].copy_from_slice(&[0, 0]);

    // -- Payload --
    frame[udp_start + 8..].copy_from_slice(payload);

    // Compute UDP checksum over pseudo-header + UDP header + payload.
    let udp_cksum = udp_checksum(src_ip, dst_ip, &frame[udp_start..]);
    frame[udp_start + 6..udp_start + 8].copy_from_slice(&udp_cksum.to_be_bytes());

    frame
}

/// Computes the IPv4 header checksum (RFC 1071).
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        // Skip the checksum field at offsets 10-11
        if i != 10 {
            sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
        }
        i += 2;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Computes the UDP checksum over the pseudo-header + UDP segment.
fn udp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: src_ip(4) + dst_ip(4) + zero(1) + proto(1) + udp_len(2)
    let src = src_ip.octets();
    let dst = dst_ip.octets();
    sum += u32::from(u16::from_be_bytes([src[0], src[1]]));
    sum += u32::from(u16::from_be_bytes([src[2], src[3]]));
    sum += u32::from(u16::from_be_bytes([dst[0], dst[1]]));
    sum += u32::from(u16::from_be_bytes([dst[2], dst[3]]));
    sum += 17u32; // Protocol: UDP
    sum += udp_segment.len() as u32;

    // UDP segment (header + payload), treating checksum field as 0
    let mut i = 0;
    while i + 1 < udp_segment.len() {
        if i != 6 {
            // Skip the checksum field itself
            sum += u32::from(u16::from_be_bytes([udp_segment[i], udp_segment[i + 1]]));
        }
        i += 2;
    }
    // Handle odd trailing byte
    if i < udp_segment.len() {
        sum += u32::from(udp_segment[i]) << 8;
    }

    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let result = !sum as u16;
    // UDP uses 0xFFFF to represent a computed zero checksum
    if result == 0 { 0xFFFF } else { result }
}

// ============================================================================
// TCP flag constants
// ============================================================================

/// TCP FIN flag.
pub const TCP_FIN: u8 = 0x01;
/// TCP SYN flag.
pub const TCP_SYN: u8 = 0x02;
/// TCP RST flag.
pub const TCP_RST: u8 = 0x04;
/// TCP PSH flag.
pub const TCP_PSH: u8 = 0x08;
/// TCP ACK flag.
pub const TCP_ACK: u8 = 0x10;

// ============================================================================
// TCP/IP/Ethernet packet builder
// ============================================================================

/// Builds a complete Ethernet frame containing a TCP/IPv4 packet.
///
/// Used by the socket proxy to construct TCP segments (SYN-ACK, ACK, data,
/// FIN) that are injected directly into the guest FD.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_ip_ethernet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
) -> Vec<u8> {
    let tcp_header_len = 20; // No options
    let tcp_len = tcp_header_len + payload.len();
    let ip_total_len = 20 + tcp_len;
    let frame_len = ETH_HEADER_LEN + ip_total_len;
    let mut frame = vec![0u8; frame_len];

    // -- Ethernet header --
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // -- IPv4 header (20 bytes, no options) --
    let ip = &mut frame[ETH_HEADER_LEN..];
    ip[0] = 0x45; // Version 4, IHL 5
    ip[2..4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
    ip[8] = 64; // TTL
    ip[9] = 6; // Protocol: TCP
    ip[12..16].copy_from_slice(&src_ip.octets());
    ip[16..20].copy_from_slice(&dst_ip.octets());

    let ip_cksum = ipv4_header_checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // -- TCP header (20 bytes) --
    let tcp_start = ETH_HEADER_LEN + 20;
    frame[tcp_start..tcp_start + 2].copy_from_slice(&src_port.to_be_bytes());
    frame[tcp_start + 2..tcp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
    frame[tcp_start + 4..tcp_start + 8].copy_from_slice(&seq.to_be_bytes());
    frame[tcp_start + 8..tcp_start + 12].copy_from_slice(&ack.to_be_bytes());
    // Data offset (5 words = 20 bytes) in upper 4 bits, reserved in lower 4
    frame[tcp_start + 12] = 0x50;
    frame[tcp_start + 13] = flags;
    frame[tcp_start + 14..tcp_start + 16].copy_from_slice(&window.to_be_bytes());
    // Checksum and urgent pointer are 0 initially

    // -- Payload --
    if !payload.is_empty() {
        frame[tcp_start + tcp_header_len..].copy_from_slice(payload);
    }

    // Compute TCP checksum over pseudo-header + TCP header + payload.
    let tcp_cksum = tcp_checksum(src_ip, dst_ip, &frame[tcp_start..]);
    frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_cksum.to_be_bytes());

    frame
}

/// Computes the TCP checksum over the pseudo-header + TCP segment.
pub fn tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: src_ip(4) + dst_ip(4) + zero(1) + proto(1) + tcp_len(2)
    let src = src_ip.octets();
    let dst = dst_ip.octets();
    sum += u32::from(u16::from_be_bytes([src[0], src[1]]));
    sum += u32::from(u16::from_be_bytes([src[2], src[3]]));
    sum += u32::from(u16::from_be_bytes([dst[0], dst[1]]));
    sum += u32::from(u16::from_be_bytes([dst[2], dst[3]]));
    sum += 6u32; // Protocol: TCP
    sum += tcp_segment.len() as u32;

    // TCP segment (header + payload), treating checksum field as 0
    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        if i != 16 {
            // Skip the checksum field at offsets 16-17
            sum += u32::from(u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]));
        }
        i += 2;
    }
    // Handle odd trailing byte
    if i < tcp_segment.len() {
        sum += u32::from(tcp_segment[i]) << 8;
    }

    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let result = !sum as u16;
    if result == 0 { 0xFFFF } else { result }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethertype_roundtrip() {
        for raw in [0x0800u16, 0x0806, 0x86DD, 0x1234] {
            assert_eq!(EtherType::from_raw(raw).to_raw(), raw);
        }
    }

    #[test]
    fn test_ethernet_header_parse_roundtrip() {
        let hdr = EthernetHeader {
            dst_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            src_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            ethertype: EtherType::Ipv4,
        };
        let bytes = hdr.to_bytes();
        let parsed = EthernetHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.dst_mac, hdr.dst_mac);
        assert_eq!(parsed.src_mac, hdr.src_mac);
        assert_eq!(parsed.ethertype, hdr.ethertype);
    }

    #[test]
    fn test_parse_too_short() {
        assert!(EthernetHeader::parse(&[0; 13]).is_none());
        assert!(EthernetHeader::parse(&[]).is_none());
    }

    #[test]
    fn test_strip_ethernet_header() {
        let mut frame = vec![0u8; 20];
        frame[14] = 0xAB;
        let payload = strip_ethernet_header(&frame);
        assert_eq!(payload.len(), 6);
        assert_eq!(payload[0], 0xAB);

        // Edge case: frame shorter than header
        assert!(strip_ethernet_header(&[0; 10]).is_empty());
    }

    #[test]
    fn test_prepend_ethernet_header_roundtrip() {
        let ip_data = [0x45, 0x00, 0x00, 0x28]; // Minimal IP start
        let dst = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let src = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        let frame = prepend_ethernet_header(&ip_data, dst, src);

        assert_eq!(frame.len(), ETH_HEADER_LEN + ip_data.len());
        let hdr = EthernetHeader::parse(&frame).unwrap();
        assert_eq!(hdr.dst_mac, dst);
        assert_eq!(hdr.src_mac, src);
        assert_eq!(hdr.ethertype, EtherType::Ipv4);
        assert_eq!(strip_ethernet_header(&frame), &ip_data);
    }

    #[test]
    fn test_arp_responder_reply() {
        let gw_ip = Ipv4Addr::new(192, 168, 64, 1);
        let gw_mac = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01];
        let responder = ArpResponder::new(gw_ip, gw_mac);

        // Build an ARP Request: "Who has 192.168.64.1? Tell 192.168.64.100"
        let sender_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x99];
        let sender_ip = [192, 168, 64, 100];
        let target_ip = [192, 168, 64, 1];
        let mut frame = vec![0u8; ARP_FRAME_MIN_LEN];
        // Ethernet header
        frame[0..6].copy_from_slice(&[0xFF; 6]); // broadcast dst
        frame[6..12].copy_from_slice(&sender_mac);
        frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        // ARP payload
        let arp = &mut frame[ETH_HEADER_LEN..];
        arp[0..2].copy_from_slice(&1u16.to_be_bytes()); // HW type: Ethernet
        arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // Proto: IPv4
        arp[4] = 6; // HLEN
        arp[5] = 4; // PLEN
        arp[6..8].copy_from_slice(&1u16.to_be_bytes()); // Op: Request
        arp[8..14].copy_from_slice(&sender_mac);
        arp[14..18].copy_from_slice(&sender_ip);
        // target hw addr = zeroes (unknown)
        arp[24..28].copy_from_slice(&target_ip);

        let reply = responder.handle_arp(&frame).expect("Expected ARP reply");

        // Verify Ethernet header
        assert_eq!(&reply[0..6], &sender_mac); // dst = original sender
        assert_eq!(&reply[6..12], &gw_mac); // src = gateway
        assert_eq!(u16::from_be_bytes([reply[12], reply[13]]), 0x0806);

        // Verify ARP payload
        let rarp = &reply[ETH_HEADER_LEN..];
        assert_eq!(u16::from_be_bytes([rarp[6], rarp[7]]), 2); // Op: Reply
        assert_eq!(&rarp[8..14], &gw_mac); // Sender HW = gateway
        assert_eq!(&rarp[14..18], &target_ip); // Sender IP = gateway
        assert_eq!(&rarp[18..24], &sender_mac); // Target HW = requester
        assert_eq!(&rarp[24..28], &sender_ip); // Target IP = requester
    }

    #[test]
    fn test_arp_responder_ignores_wrong_target() {
        let gw_ip = Ipv4Addr::new(192, 168, 64, 1);
        let gw_mac = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01];
        let responder = ArpResponder::new(gw_ip, gw_mac);

        // ARP Request for a different IP
        let mut frame = vec![0u8; ARP_FRAME_MIN_LEN];
        frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        let arp = &mut frame[ETH_HEADER_LEN..];
        arp[0..2].copy_from_slice(&1u16.to_be_bytes());
        arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        arp[4] = 6;
        arp[5] = 4;
        arp[6..8].copy_from_slice(&1u16.to_be_bytes());
        arp[24..28].copy_from_slice(&[192, 168, 64, 99]); // Not the gateway

        assert!(responder.handle_arp(&frame).is_none());
    }

    #[test]
    fn test_build_udp_ip_ethernet_checksum() {
        let src_ip = Ipv4Addr::new(192, 168, 64, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 64, 2);
        let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let dst_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        let payload = b"hello";

        let frame = build_udp_ip_ethernet(src_ip, dst_ip, 1234, 5678, payload, src_mac, dst_mac);

        // Verify Ethernet header
        let hdr = EthernetHeader::parse(&frame).unwrap();
        assert_eq!(hdr.ethertype, EtherType::Ipv4);

        // Verify IP header
        let ip = &frame[ETH_HEADER_LEN..];
        assert_eq!(ip[0], 0x45);
        assert_eq!(ip[9], 17); // UDP
        let ip_total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        assert_eq!(ip_total, 20 + 8 + payload.len());

        // Verify IP checksum: recompute over the full header (including cksum field)
        // and confirm the result folds to zero.
        let mut sum: u32 = 0;
        for i in (0..20).step_by(2) {
            sum += u32::from(u16::from_be_bytes([ip[i], ip[i + 1]]));
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xFFFF, "IP header checksum verification failed");

        // Verify UDP header
        let udp = &frame[ETH_HEADER_LEN + 20..];
        assert_eq!(u16::from_be_bytes([udp[0], udp[1]]), 1234);
        assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), 5678);
        let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
        assert_eq!(udp_len, 8 + payload.len());

        // Verify UDP checksum is non-zero
        let udp_cksum = u16::from_be_bytes([udp[6], udp[7]]);
        assert_ne!(udp_cksum, 0);
    }

    #[test]
    fn test_build_tcp_ip_ethernet_syn_ack() {
        let src_ip = Ipv4Addr::new(192, 168, 64, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 64, 2);
        let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let dst_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

        let frame = build_tcp_ip_ethernet(
            src_ip, dst_ip, 80, 12345, 1000, 501, TCP_SYN | TCP_ACK, 65535,
            &[], src_mac, dst_mac,
        );

        // Verify Ethernet header
        let hdr = EthernetHeader::parse(&frame).unwrap();
        assert_eq!(hdr.ethertype, EtherType::Ipv4);

        // Verify IP header
        let ip = &frame[ETH_HEADER_LEN..];
        assert_eq!(ip[0], 0x45);
        assert_eq!(ip[9], 6); // TCP
        let ip_total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        assert_eq!(ip_total, 40); // 20 IP + 20 TCP, no payload

        // Verify IP checksum
        let mut sum: u32 = 0;
        for i in (0..20).step_by(2) {
            sum += u32::from(u16::from_be_bytes([ip[i], ip[i + 1]]));
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xFFFF, "IP header checksum verification failed");

        // Verify TCP header
        let tcp = &frame[ETH_HEADER_LEN + 20..];
        assert_eq!(u16::from_be_bytes([tcp[0], tcp[1]]), 80);
        assert_eq!(u16::from_be_bytes([tcp[2], tcp[3]]), 12345);
        assert_eq!(u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]), 1000);
        assert_eq!(u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]), 501);
        assert_eq!(tcp[12], 0x50); // Data offset = 5 words
        assert_eq!(tcp[13], TCP_SYN | TCP_ACK);
        assert_eq!(u16::from_be_bytes([tcp[14], tcp[15]]), 65535);

        // Verify TCP checksum is non-zero
        let tcp_cksum = u16::from_be_bytes([tcp[16], tcp[17]]);
        assert_ne!(tcp_cksum, 0);
    }

    #[test]
    fn test_build_tcp_ip_ethernet_with_payload() {
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(10, 0, 0, 2);
        let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let dst_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        let payload = b"HTTP/1.1 200 OK\r\n";

        let frame = build_tcp_ip_ethernet(
            src_ip, dst_ip, 80, 50000, 100, 200, TCP_ACK | TCP_PSH, 32768,
            payload, src_mac, dst_mac,
        );

        // Verify total frame length
        assert_eq!(frame.len(), ETH_HEADER_LEN + 20 + 20 + payload.len());

        // Verify payload at the end
        let payload_start = ETH_HEADER_LEN + 40;
        assert_eq!(&frame[payload_start..], payload);

        // Verify TCP checksum by recomputing from scratch
        let tcp_segment = &frame[ETH_HEADER_LEN + 20..];
        let recomputed = tcp_checksum(src_ip, dst_ip, tcp_segment);
        // When we include the original checksum in the computation, the
        // result should fold to 0xFFFF.
        let mut sum: u32 = 0;
        let src = src_ip.octets();
        let dst = dst_ip.octets();
        sum += u32::from(u16::from_be_bytes([src[0], src[1]]));
        sum += u32::from(u16::from_be_bytes([src[2], src[3]]));
        sum += u32::from(u16::from_be_bytes([dst[0], dst[1]]));
        sum += u32::from(u16::from_be_bytes([dst[2], dst[3]]));
        sum += 6u32;
        sum += tcp_segment.len() as u32;
        for i in (0..tcp_segment.len()).step_by(2) {
            if i + 1 < tcp_segment.len() {
                sum += u32::from(u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]));
            } else {
                sum += u32::from(tcp_segment[i]) << 8;
            }
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xFFFF, "TCP checksum verification failed");
        // Suppress unused variable warning for recomputed
        let _ = recomputed;
    }

    #[test]
    fn test_tcp_checksum_deterministic() {
        let src = Ipv4Addr::new(1, 2, 3, 4);
        let dst = Ipv4Addr::new(5, 6, 7, 8);
        let segment = [
            0x00, 0x50, 0xC3, 0x50, // src_port=80, dst_port=50000
            0x00, 0x00, 0x00, 0x01, // seq=1
            0x00, 0x00, 0x00, 0x00, // ack=0
            0x50, 0x02, 0xFF, 0xFF, // data_off=5, SYN, window=65535
            0x00, 0x00, 0x00, 0x00, // checksum=0, urgent=0
        ];
        let cksum1 = tcp_checksum(src, dst, &segment);
        let cksum2 = tcp_checksum(src, dst, &segment);
        assert_eq!(cksum1, cksum2);
        assert_ne!(cksum1, 0);
    }
}
