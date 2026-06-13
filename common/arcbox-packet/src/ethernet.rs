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

    // TCP segment, treating checksum field (offset 16-17) as 0.
    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        if i != 16 {
            sum += u32::from(u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]));
        }
        i += 2;
    }
    if i < tcp_segment.len() {
        sum += u32::from(tcp_segment[i]) << 8;
    }

    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Parameters for constructing TCP frames on the fast path.
#[derive(Debug, Clone, Copy)]
pub struct TcpFrameParams {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
}

/// Builds a TCP ACK frame (no payload) to acknowledge data from the guest.
///
/// Used by the TCP fast path to ACK guest data segments using the
/// hand-rolled TCP state machine in `TcpBridge`.
#[must_use]
pub fn build_tcp_ack_frame(p: &TcpFrameParams) -> Vec<u8> {
    let TcpFrameParams {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        window,
        src_mac,
        dst_mac,
    } = *p;
    // ACK frame: ETH(14) + IP(20) + TCP(20) = 54 bytes, no payload.
    let tcp_hdr_len = 20;
    let ip_total_len = 20 + tcp_hdr_len;
    let frame_len = ETH_HEADER_LEN + ip_total_len;
    let mut frame = vec![0u8; frame_len];

    // -- Ethernet header --
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // -- IPv4 header --
    let ip = ETH_HEADER_LEN;
    frame[ip] = 0x45; // Version 4, IHL 5
    frame[ip + 2..ip + 4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    frame[ip + 6..ip + 8].copy_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
    frame[ip + 8] = 64; // TTL
    frame[ip + 9] = 6; // Protocol: TCP
    frame[ip + 12..ip + 16].copy_from_slice(&src_ip.octets());
    frame[ip + 16..ip + 20].copy_from_slice(&dst_ip.octets());
    let ip_cksum = ipv4_header_checksum(&frame[ip..ip + 20]);
    frame[ip + 10..ip + 12].copy_from_slice(&ip_cksum.to_be_bytes());

    // -- TCP header (20 bytes, no options) --
    let tcp = ip + 20;
    frame[tcp..tcp + 2].copy_from_slice(&src_port.to_be_bytes());
    frame[tcp + 2..tcp + 4].copy_from_slice(&dst_port.to_be_bytes());
    frame[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
    frame[tcp + 8..tcp + 12].copy_from_slice(&ack.to_be_bytes());
    frame[tcp + 12] = 0x50; // Data offset: 5 (20 bytes), no options
    frame[tcp + 13] = 0x10; // Flags: ACK
    frame[tcp + 14..tcp + 16].copy_from_slice(&window.to_be_bytes());
    let tcp_cksum = tcp_checksum(src_ip, dst_ip, &frame[tcp..]);
    frame[tcp + 16..tcp + 18].copy_from_slice(&tcp_cksum.to_be_bytes());

    frame
}

/// Builds a TCP data frame carrying payload from the host to the guest.
///
/// Used by the TCP fast path to inject host TcpStream data into the guest
/// via `TcpBridge`'s hand-rolled TCP state machine.
#[must_use]
pub fn build_tcp_data_frame(p: &TcpFrameParams, payload: &[u8]) -> Vec<u8> {
    let TcpFrameParams {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        window,
        src_mac,
        dst_mac,
    } = *p;

    let tcp_hdr_len = 20;
    let tcp_total_len = tcp_hdr_len + payload.len();
    let ip_total_len = 20 + tcp_total_len;
    // IPv4 encodes total length in a 16-bit field; the `as u16` cast below
    // would silently truncate for oversized payloads. Assert so the failure
    // is loud if a caller ever exceeds the per-frame MTU budget.
    assert!(
        u16::try_from(ip_total_len).is_ok(),
        "build_tcp_data_frame: ip_total_len={ip_total_len} overflows u16"
    );
    let frame_len = ETH_HEADER_LEN + ip_total_len;
    let mut frame = vec![0u8; frame_len];

    // -- Ethernet header --
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // -- IPv4 header --
    let ip = ETH_HEADER_LEN;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    frame[ip + 6..ip + 8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    frame[ip + 8] = 64; // TTL
    frame[ip + 9] = 6; // TCP
    frame[ip + 12..ip + 16].copy_from_slice(&src_ip.octets());
    frame[ip + 16..ip + 20].copy_from_slice(&dst_ip.octets());
    let ip_cksum = ipv4_header_checksum(&frame[ip..ip + 20]);
    frame[ip + 10..ip + 12].copy_from_slice(&ip_cksum.to_be_bytes());

    // -- TCP header --
    let tcp = ip + 20;
    frame[tcp..tcp + 2].copy_from_slice(&src_port.to_be_bytes());
    frame[tcp + 2..tcp + 4].copy_from_slice(&dst_port.to_be_bytes());
    frame[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
    frame[tcp + 8..tcp + 12].copy_from_slice(&ack.to_be_bytes());
    frame[tcp + 12] = 0x50; // Data offset: 5
    frame[tcp + 13] = 0x18; // Flags: ACK | PSH
    frame[tcp + 14..tcp + 16].copy_from_slice(&window.to_be_bytes());

    // -- Payload --
    frame[tcp + 20..].copy_from_slice(payload);

    // TCP checksum over header + payload.
    let tcp_cksum = tcp_checksum(src_ip, dst_ip, &frame[tcp..]);
    frame[tcp + 16..tcp + 18].copy_from_slice(&tcp_cksum.to_be_bytes());

    frame
}

/// Builds a TCP data frame with only a pseudo-header checksum (for GSO).
///
/// Identical to [`build_tcp_data_frame`] except the TCP checksum field
/// contains only the pseudo-header checksum. The guest kernel completes
/// the checksum per-segment during GSO segmentation.
#[must_use]
pub fn build_tcp_data_frame_partial_csum(p: &TcpFrameParams, payload: &[u8]) -> Vec<u8> {
    let TcpFrameParams {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        window,
        src_mac,
        dst_mac,
    } = *p;

    let tcp_hdr_len = 20;
    let tcp_total_len = tcp_hdr_len + payload.len();
    let ip_total_len = 20 + tcp_total_len;
    // Same IPv4 total_length overflow guard as `build_tcp_data_frame`.
    // Callers are GSO-oriented and bounded by the RX descriptor budget,
    // but asserting here keeps us honest if that ever slips.
    assert!(
        u16::try_from(ip_total_len).is_ok(),
        "build_tcp_data_frame_partial_csum: ip_total_len={ip_total_len} overflows u16"
    );
    let frame_len = ETH_HEADER_LEN + ip_total_len;
    let mut frame = vec![0u8; frame_len];

    // -- Ethernet header --
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // -- IPv4 header --
    let ip = ETH_HEADER_LEN;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    frame[ip + 6..ip + 8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    frame[ip + 8] = 64; // TTL
    frame[ip + 9] = 6; // TCP
    frame[ip + 12..ip + 16].copy_from_slice(&src_ip.octets());
    frame[ip + 16..ip + 20].copy_from_slice(&dst_ip.octets());
    let ip_cksum = ipv4_header_checksum(&frame[ip..ip + 20]);
    frame[ip + 10..ip + 12].copy_from_slice(&ip_cksum.to_be_bytes());

    // -- TCP header --
    let tcp = ip + 20;
    frame[tcp..tcp + 2].copy_from_slice(&src_port.to_be_bytes());
    frame[tcp + 2..tcp + 4].copy_from_slice(&dst_port.to_be_bytes());
    frame[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
    frame[tcp + 8..tcp + 12].copy_from_slice(&ack.to_be_bytes());
    frame[tcp + 12] = 0x50; // Data offset: 5
    frame[tcp + 13] = 0x18; // Flags: ACK | PSH
    frame[tcp + 14..tcp + 16].copy_from_slice(&window.to_be_bytes());

    // -- Payload --
    frame[tcp + 20..].copy_from_slice(payload);

    // Pseudo-header-only TCP checksum. The guest kernel completes it
    // per-segment during GSO segmentation (VIRTIO_NET_HDR_F_NEEDS_CSUM).
    let pseudo_cksum = tcp_pseudo_header_checksum(src_ip, dst_ip, tcp_total_len);
    frame[tcp + 16..tcp + 18].copy_from_slice(&pseudo_cksum.to_be_bytes());

    frame
}

/// Computes the TCP pseudo-header checksum only (for GSO offload).
///
/// The guest kernel adds the TCP header + payload contribution per segment.
#[must_use]
pub fn tcp_pseudo_header_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_len: usize) -> u16 {
    let mut sum: u32 = 0;
    let src = src_ip.octets();
    let dst = dst_ip.octets();
    sum += u32::from(u16::from_be_bytes([src[0], src[1]]));
    sum += u32::from(u16::from_be_bytes([src[2], src[3]]));
    sum += u32::from(u16::from_be_bytes([dst[0], dst[1]]));
    sum += u32::from(u16::from_be_bytes([dst[2], dst[3]]));
    sum += 6u32; // TCP protocol
    sum += tcp_len as u32;
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Builds a TCP FIN+ACK frame for connection teardown.
#[must_use]
pub fn build_tcp_fin_frame(p: &TcpFrameParams) -> Vec<u8> {
    let mut ack_params = *p;
    ack_params.window = 65535;
    let mut frame = build_tcp_ack_frame(&ack_params);
    // Change flags from ACK to FIN|ACK.
    let tcp = ETH_HEADER_LEN + 20;
    frame[tcp + 13] = 0x11; // FIN | ACK
    // Recompute TCP checksum.
    frame[tcp + 16..tcp + 18].copy_from_slice(&[0, 0]);
    let tcp_cksum = tcp_checksum(p.src_ip, p.dst_ip, &frame[tcp..]);
    frame[tcp + 16..tcp + 18].copy_from_slice(&tcp_cksum.to_be_bytes());
    frame
}

/// Peer TCP options observed on an incoming SYN or SYN-ACK frame.
///
/// Captured so the handshake synthesizer can mirror the peer's negotiated
/// options back in its SYN-ACK response (or record them for later use).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpSynOptions {
    /// Maximum Segment Size advertised by the peer. `None` if the option
    /// was absent (RFC 9293 §3.7.1 says default 536, but we treat absence
    /// as "use our default").
    pub mss: Option<u16>,
    /// Window scale shift count (0–14). `None` if the peer did not advertise it.
    pub wscale: Option<u8>,
    /// Whether the peer included SACK-Permitted.
    pub sack_permitted: bool,
    /// Whether the peer included Timestamps. We do not echo these back —
    /// both endpoints must send TSopt in their SYN for it to be used
    /// (RFC 7323 §3.1), so not echoing disables timestamps cleanly.
    pub timestamps: bool,
}

/// Parses the TCP options field of a SYN (or SYN-ACK) segment.
///
/// `tcp_segment` is the TCP header + options + (optionally) payload. The
/// `data_offset` field (upper nibble of byte 12, in 32-bit words) determines
/// where the options end. Malformed or unknown options cause early
/// termination without returning an error — the returned struct reflects
/// only what was parsed successfully.
#[must_use]
pub fn parse_tcp_syn_options(tcp_segment: &[u8]) -> TcpSynOptions {
    let mut opts = TcpSynOptions::default();
    if tcp_segment.len() < 20 {
        return opts;
    }
    let data_offset = usize::from(tcp_segment[12] >> 4) * 4;
    if data_offset < 20 || data_offset > tcp_segment.len() {
        return opts;
    }
    let options = &tcp_segment[20..data_offset];
    let mut i = 0;
    while i < options.len() {
        let kind = options[i];
        match kind {
            0 => break, // End of option list
            1 => {
                i += 1;
            } // NOP
            2 => {
                // MSS
                if i + 4 > options.len() || options[i + 1] != 4 {
                    break;
                }
                opts.mss = Some(u16::from_be_bytes([options[i + 2], options[i + 3]]));
                i += 4;
            }
            3 => {
                // Window scale
                if i + 3 > options.len() || options[i + 1] != 3 {
                    break;
                }
                opts.wscale = Some(options[i + 2]);
                i += 3;
            }
            4 => {
                // SACK-Permitted
                if i + 2 > options.len() || options[i + 1] != 2 {
                    break;
                }
                opts.sack_permitted = true;
                i += 2;
            }
            8 => {
                // Timestamps
                if i + 10 > options.len() || options[i + 1] != 10 {
                    break;
                }
                opts.timestamps = true;
                i += 10;
            }
            _ => {
                // Skip using the Length field if present; bail if malformed.
                if i + 1 >= options.len() {
                    break;
                }
                let len = usize::from(options[i + 1]);
                if len < 2 || i + len > options.len() {
                    break;
                }
                i += len;
            }
        }
    }
    opts
}

/// Parameters for constructing a TCP SYN-ACK frame.
///
/// Used by the handshake synthesizer to respond to a guest SYN without
/// going through a userspace TCP state machine. `mss` defaults to 1460 if
/// unspecified; `wscale` and `sack_permitted` are conditionally included
/// based on what the peer advertised.
#[derive(Debug, Clone, Copy)]
pub struct SynAckParams {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    /// Our chosen ISN (appears as SEQ in the SYN-ACK).
    pub seq: u32,
    /// Peer ISN + 1 (appears as ACK in the SYN-ACK).
    pub ack: u32,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    /// MSS to advertise (typically 1460 for Ethernet with DF bit set).
    pub mss: u16,
    /// Window scale to advertise. `None` means don't include the option
    /// (peer did not send WScale in its SYN, so we must not negotiate it).
    pub wscale: Option<u8>,
    /// Whether to include SACK-Permitted.
    pub sack_permitted: bool,
}

/// Builds a TCP SYN-ACK frame that accepts a guest SYN.
///
/// Options included: MSS (always), WScale (if `Some`), SACK-Permitted (if true).
/// Timestamps are omitted — not echoing disables TSopt for the connection,
/// saving 12 bytes/segment of overhead.
#[must_use]
pub fn build_tcp_syn_ack_frame(p: &SynAckParams) -> Vec<u8> {
    // Assemble options. Pad to multiple of 4 bytes with NOPs.
    let mut options: Vec<u8> = Vec::with_capacity(16);

    // MSS (kind=2, len=4)
    options.push(2);
    options.push(4);
    options.extend_from_slice(&p.mss.to_be_bytes());

    // SACK-Permitted (kind=4, len=2) — placed before WScale so NOP padding
    // lands naturally after WScale.
    if p.sack_permitted {
        options.push(4);
        options.push(2);
    }

    // Window scale (kind=3, len=3)
    if let Some(shift) = p.wscale {
        options.push(3);
        options.push(3);
        options.push(shift);
    }

    while options.len() % 4 != 0 {
        options.push(1); // NOP padding
    }

    let tcp_hdr_len = 20 + options.len();
    let ip_total_len = 20 + tcp_hdr_len;
    let frame_len = ETH_HEADER_LEN + ip_total_len;
    let mut frame = vec![0u8; frame_len];

    // -- Ethernet header --
    frame[0..6].copy_from_slice(&p.dst_mac);
    frame[6..12].copy_from_slice(&p.src_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // -- IPv4 header --
    let ip = ETH_HEADER_LEN;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    frame[ip + 6..ip + 8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    frame[ip + 8] = 64;
    frame[ip + 9] = 6; // TCP
    frame[ip + 12..ip + 16].copy_from_slice(&p.src_ip.octets());
    frame[ip + 16..ip + 20].copy_from_slice(&p.dst_ip.octets());
    let ip_cksum = ipv4_header_checksum(&frame[ip..ip + 20]);
    frame[ip + 10..ip + 12].copy_from_slice(&ip_cksum.to_be_bytes());

    // -- TCP header --
    let tcp = ip + 20;
    frame[tcp..tcp + 2].copy_from_slice(&p.src_port.to_be_bytes());
    frame[tcp + 2..tcp + 4].copy_from_slice(&p.dst_port.to_be_bytes());
    frame[tcp + 4..tcp + 8].copy_from_slice(&p.seq.to_be_bytes());
    frame[tcp + 8..tcp + 12].copy_from_slice(&p.ack.to_be_bytes());
    frame[tcp + 12] = ((tcp_hdr_len / 4) as u8) << 4;
    frame[tcp + 13] = 0x12; // Flags: SYN | ACK
    frame[tcp + 14..tcp + 16].copy_from_slice(&65535u16.to_be_bytes());
    frame[tcp + 20..tcp + 20 + options.len()].copy_from_slice(&options);

    let tcp_cksum = tcp_checksum(p.src_ip, p.dst_ip, &frame[tcp..]);
    frame[tcp + 16..tcp + 18].copy_from_slice(&tcp_cksum.to_be_bytes());

    frame
}

/// Parameters for constructing a TCP SYN frame (active open).
///
/// Used when arcbox initiates a TCP connection toward the guest for an
/// inbound port-forward. Only the MSS option is included — WScale and
/// SACK-Permitted are negotiated by the peer echoing them in its SYN-ACK.
#[derive(Debug, Clone, Copy)]
pub struct SynParams {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub mss: u16,
    pub wscale: Option<u8>,
}

/// Builds a TCP SYN frame for active open toward the guest.
#[must_use]
pub fn build_tcp_syn_frame(p: &SynParams) -> Vec<u8> {
    let mut options: Vec<u8> = Vec::with_capacity(12);

    // MSS
    options.push(2);
    options.push(4);
    options.extend_from_slice(&p.mss.to_be_bytes());

    // SACK-Permitted — always advertise, we don't care if peer uses it.
    options.push(4);
    options.push(2);

    if let Some(shift) = p.wscale {
        options.push(3);
        options.push(3);
        options.push(shift);
    }

    while options.len() % 4 != 0 {
        options.push(1);
    }

    let tcp_hdr_len = 20 + options.len();
    let ip_total_len = 20 + tcp_hdr_len;
    let frame_len = ETH_HEADER_LEN + ip_total_len;
    let mut frame = vec![0u8; frame_len];

    frame[0..6].copy_from_slice(&p.dst_mac);
    frame[6..12].copy_from_slice(&p.src_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    let ip = ETH_HEADER_LEN;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    frame[ip + 6..ip + 8].copy_from_slice(&0x4000u16.to_be_bytes());
    frame[ip + 8] = 64;
    frame[ip + 9] = 6;
    frame[ip + 12..ip + 16].copy_from_slice(&p.src_ip.octets());
    frame[ip + 16..ip + 20].copy_from_slice(&p.dst_ip.octets());
    let ip_cksum = ipv4_header_checksum(&frame[ip..ip + 20]);
    frame[ip + 10..ip + 12].copy_from_slice(&ip_cksum.to_be_bytes());

    let tcp = ip + 20;
    frame[tcp..tcp + 2].copy_from_slice(&p.src_port.to_be_bytes());
    frame[tcp + 2..tcp + 4].copy_from_slice(&p.dst_port.to_be_bytes());
    frame[tcp + 4..tcp + 8].copy_from_slice(&p.seq.to_be_bytes());
    // ack = 0 for pure SYN
    frame[tcp + 12] = ((tcp_hdr_len / 4) as u8) << 4;
    frame[tcp + 13] = 0x02; // SYN
    frame[tcp + 14..tcp + 16].copy_from_slice(&65535u16.to_be_bytes());
    frame[tcp + 20..tcp + 20 + options.len()].copy_from_slice(&options);

    let tcp_cksum = tcp_checksum(p.src_ip, p.dst_ip, &frame[tcp..]);
    frame[tcp + 16..tcp + 18].copy_from_slice(&tcp_cksum.to_be_bytes());

    frame
}

/// Builds a TCP RST frame for connection abort.
#[must_use]
pub fn build_tcp_rst_frame(p: &TcpFrameParams) -> Vec<u8> {
    let mut rst_params = *p;
    rst_params.window = 0;
    let mut frame = build_tcp_ack_frame(&rst_params);
    // Change flags from ACK to RST|ACK.
    let tcp = ETH_HEADER_LEN + 20;
    frame[tcp + 13] = 0x14; // RST | ACK
    frame[tcp + 16..tcp + 18].copy_from_slice(&[0, 0]);
    let tcp_cksum = tcp_checksum(p.src_ip, p.dst_ip, &frame[tcp..]);
    frame[tcp + 16..tcp + 18].copy_from_slice(&tcp_cksum.to_be_bytes());
    frame
}

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

    fn make_tcp_params(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
    ) -> TcpFrameParams {
        TcpFrameParams {
            src_ip: Ipv4Addr::from(src_ip),
            dst_ip: Ipv4Addr::from(dst_ip),
            src_port,
            dst_port,
            seq,
            ack,
            window: 65535,
            src_mac: [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x01],
            dst_mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
        }
    }

    /// Verify checksum: zero the field, recompute, compare to stored.
    fn verify_tcp_checksum(frame: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) {
        let tcp = 34;
        let stored = u16::from_be_bytes([frame[tcp + 16], frame[tcp + 17]]);
        assert_ne!(stored, 0);
        let mut v = frame.to_vec();
        v[tcp + 16] = 0;
        v[tcp + 17] = 0;
        assert_eq!(tcp_checksum(src_ip, dst_ip, &v[tcp..]), stored);
    }

    #[test]
    fn test_tcp_ack_frame_structure() {
        let p = make_tcp_params([1, 1, 1, 1], [10, 0, 2, 2], 443, 12345, 1000, 2000);
        let frame = build_tcp_ack_frame(&p);

        assert_eq!(frame.len(), 54);
        assert_eq!(&frame[0..6], &p.dst_mac);
        assert_eq!(&frame[6..12], &p.src_mac);
        assert_eq!(frame[14 + 9], 6); // TCP protocol

        let tcp = 34;
        assert_eq!(u16::from_be_bytes([frame[tcp], frame[tcp + 1]]), 443);
        assert_eq!(u16::from_be_bytes([frame[tcp + 2], frame[tcp + 3]]), 12345);
        assert_eq!(frame[tcp + 13], 0x10); // ACK flag
        verify_tcp_checksum(&frame, p.src_ip, p.dst_ip);
    }

    #[test]
    fn test_tcp_data_frame_payload() {
        let p = make_tcp_params([1, 1, 1, 1], [10, 0, 2, 2], 80, 54321, 5000, 6000);
        let payload = b"Hello, world!";
        let frame = build_tcp_data_frame(&p, payload);

        assert_eq!(frame.len(), 54 + payload.len());
        assert_eq!(&frame[54..], payload.as_slice());
        assert_eq!(frame[34 + 13], 0x18); // ACK|PSH
        verify_tcp_checksum(&frame, p.src_ip, p.dst_ip);
    }

    #[test]
    fn test_tcp_fin_frame_flags() {
        let p = make_tcp_params([10, 0, 2, 1], [10, 0, 2, 2], 80, 1234, 100, 200);
        let frame = build_tcp_fin_frame(&p);
        assert_eq!(frame.len(), 54);
        assert_eq!(frame[34 + 13], 0x11); // FIN | ACK
        verify_tcp_checksum(&frame, p.src_ip, p.dst_ip);
    }

    #[test]
    fn test_tcp_rst_frame_flags() {
        let p = make_tcp_params([10, 0, 2, 1], [10, 0, 2, 2], 80, 1234, 100, 200);
        let frame = build_tcp_rst_frame(&p);
        assert_eq!(frame.len(), 54);
        assert_eq!(frame[34 + 13], 0x14); // RST | ACK
        verify_tcp_checksum(&frame, p.src_ip, p.dst_ip);
    }

    #[test]
    fn test_tcp_checksum_standalone() {
        let p = make_tcp_params([192, 168, 1, 1], [192, 168, 1, 2], 80, 443, 0, 0);
        let frame = build_tcp_ack_frame(&p);
        verify_tcp_checksum(&frame, p.src_ip, p.dst_ip);
    }

    /// Helper: build a minimal SYN frame (ETH + IP + TCP with given options).
    fn make_syn_with_options(opts: &[u8]) -> Vec<u8> {
        let tcp_hdr_len = 20 + opts.len();
        assert_eq!(tcp_hdr_len % 4, 0, "options must pad to 4");
        let ip_total = 20 + tcp_hdr_len;
        let mut frame = vec![0u8; 14 + ip_total];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let ip = 14;
        frame[ip] = 0x45;
        frame[ip + 2..ip + 4].copy_from_slice(&(ip_total as u16).to_be_bytes());
        frame[ip + 9] = 6;
        let tcp = ip + 20;
        frame[tcp + 12] = ((tcp_hdr_len / 4) as u8) << 4;
        frame[tcp + 13] = 0x02; // SYN
        frame[tcp + 20..tcp + 20 + opts.len()].copy_from_slice(opts);
        frame
    }

    #[test]
    fn test_parse_syn_options_full() {
        // MSS=1460, NOP, WScale=7, NOP, NOP, SACK-perm, NOP, NOP (8 bytes options → pad)
        // MSS(4) + WScale(3) + NOP + SACK-perm(2) = 10 bytes → pad to 12 with NOP NOP
        let opts = &[
            2, 4, 0x05, 0xB4, // MSS = 1460
            3, 3, 7, // WScale = 7
            4, 2, // SACK-Permitted
            1, 1, 1, // padding
        ];
        let frame = make_syn_with_options(opts);
        let parsed = parse_tcp_syn_options(&frame[34..]);
        assert_eq!(parsed.mss, Some(1460));
        assert_eq!(parsed.wscale, Some(7));
        assert!(parsed.sack_permitted);
        assert!(!parsed.timestamps);
    }

    #[test]
    fn test_parse_syn_options_empty() {
        // No options — tcp_hdr_len = 20.
        let opts = &[];
        let frame = make_syn_with_options(opts);
        let parsed = parse_tcp_syn_options(&frame[34..]);
        assert_eq!(parsed.mss, None);
        assert_eq!(parsed.wscale, None);
        assert!(!parsed.sack_permitted);
    }

    #[test]
    fn test_parse_syn_options_unknown_skipped() {
        // Unknown kind=99, length=4, data=0xAA 0xBB. Followed by MSS=1460.
        let opts = &[
            99, 4, 0xAA, 0xBB, // unknown
            2, 4, 0x05, 0xB4, // MSS = 1460
        ];
        let frame = make_syn_with_options(opts);
        let parsed = parse_tcp_syn_options(&frame[34..]);
        assert_eq!(parsed.mss, Some(1460));
    }

    #[test]
    fn test_parse_syn_options_malformed_length() {
        // Kind=2 (MSS) with bogus length=3 (should be 4). Parser must bail.
        let opts = &[2, 3, 0x05, 0xB4];
        let frame = make_syn_with_options(opts);
        let parsed = parse_tcp_syn_options(&frame[34..]);
        assert_eq!(parsed.mss, None);
    }

    #[test]
    fn test_build_syn_ack_frame_flags_and_seq() {
        let p = SynAckParams {
            src_ip: Ipv4Addr::new(10, 0, 2, 1),
            dst_ip: Ipv4Addr::new(10, 0, 2, 2),
            src_port: 443,
            dst_port: 54321,
            seq: 0xDEAD_BEEF,
            ack: 0xCAFE_BABE,
            src_mac: [0x02, 0xAB, 0xCD, 0, 0, 1],
            dst_mac: [0x52, 0x54, 0, 0x12, 0x34, 0x56],
            mss: 1460,
            wscale: Some(7),
            sack_permitted: true,
        };
        let frame = build_tcp_syn_ack_frame(&p);

        // TCP header starts at offset 34.
        let tcp = 34;
        assert_eq!(frame[tcp + 13], 0x12, "flags must be SYN|ACK");

        let seq = u32::from_be_bytes([
            frame[tcp + 4],
            frame[tcp + 5],
            frame[tcp + 6],
            frame[tcp + 7],
        ]);
        assert_eq!(seq, p.seq);
        let ack = u32::from_be_bytes([
            frame[tcp + 8],
            frame[tcp + 9],
            frame[tcp + 10],
            frame[tcp + 11],
        ]);
        assert_eq!(ack, p.ack);

        // Data offset must fit header + options.
        let doff = usize::from(frame[tcp + 12] >> 4) * 4;
        assert!(doff >= 24, "SYN-ACK must include at least MSS option");

        // Parse the options back and verify round-trip.
        let parsed = parse_tcp_syn_options(&frame[tcp..]);
        assert_eq!(parsed.mss, Some(1460));
        assert_eq!(parsed.wscale, Some(7));
        assert!(parsed.sack_permitted);

        // Checksum must verify.
        verify_tcp_checksum(&frame, p.src_ip, p.dst_ip);
    }

    #[test]
    fn test_build_syn_ack_frame_without_wscale() {
        let p = SynAckParams {
            src_ip: Ipv4Addr::new(1, 1, 1, 1),
            dst_ip: Ipv4Addr::new(10, 0, 2, 2),
            src_port: 80,
            dst_port: 12345,
            seq: 1000,
            ack: 2000,
            src_mac: [0x02, 0xAB, 0xCD, 0, 0, 1],
            dst_mac: [0x52, 0x54, 0, 0x12, 0x34, 0x56],
            mss: 1460,
            wscale: None,
            sack_permitted: false,
        };
        let frame = build_tcp_syn_ack_frame(&p);
        let parsed = parse_tcp_syn_options(&frame[34..]);
        assert_eq!(parsed.mss, Some(1460));
        assert_eq!(parsed.wscale, None);
        assert!(!parsed.sack_permitted);
        verify_tcp_checksum(&frame, p.src_ip, p.dst_ip);
    }

    #[test]
    fn test_build_syn_frame_active_open() {
        let p = SynParams {
            src_ip: Ipv4Addr::new(10, 0, 2, 1),
            dst_ip: Ipv4Addr::new(10, 0, 2, 2),
            src_port: 61000,
            dst_port: 15201,
            seq: 0x1234_5678,
            src_mac: [0x02, 0xAB, 0xCD, 0, 0, 1],
            dst_mac: [0x52, 0x54, 0, 0x12, 0x34, 0x56],
            mss: 1460,
            wscale: Some(7),
        };
        let frame = build_tcp_syn_frame(&p);
        let tcp = 34;
        assert_eq!(frame[tcp + 13], 0x02, "flags must be SYN only");
        let seq = u32::from_be_bytes([
            frame[tcp + 4],
            frame[tcp + 5],
            frame[tcp + 6],
            frame[tcp + 7],
        ]);
        assert_eq!(seq, p.seq);
        let parsed = parse_tcp_syn_options(&frame[tcp..]);
        assert_eq!(parsed.mss, Some(1460));
        assert_eq!(parsed.wscale, Some(7));
        verify_tcp_checksum(&frame, p.src_ip, p.dst_ip);
    }
}
