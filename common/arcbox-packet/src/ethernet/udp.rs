use std::net::Ipv4Addr;

use super::{
    ETH_HEADER_LEN,
    checksum::{ipv4_header_checksum, udp_checksum},
};

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
