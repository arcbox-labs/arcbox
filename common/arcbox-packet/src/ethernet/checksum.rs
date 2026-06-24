use std::net::Ipv4Addr;

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
pub(super) fn udp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_segment: &[u8]) -> u16 {
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
