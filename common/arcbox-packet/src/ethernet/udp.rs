use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU16, Ordering};

use super::{
    ETH_HEADER_LEN,
    checksum::{ipv4_header_checksum, udp_checksum},
};

/// Largest UDP payload an IPv4 datagram can carry: the 16-bit IP total-length
/// field (65535) minus the IPv4 header (20) and the UDP header (8).
pub const MAX_UDP_PAYLOAD: usize = 65_507;

/// IP identification counter shared by every frame built here, so the
/// fragments of one datagram carry one ID while consecutive datagrams differ.
static NEXT_IP_ID: AtomicU16 = AtomicU16::new(1);

/// Builds a guest-bound UDP/IPv4 datagram as one or more Ethernet frames.
///
/// A datagram that fits `mtu` yields exactly one frame. A larger one is split
/// into standard IPv4 fragments (offsets in 8-byte units, MF set on all but
/// the last) for the receiver to reassemble — the link never sees a frame
/// above `mtu` + 14 bytes. Returns no frames for a payload above
/// [`MAX_UDP_PAYLOAD`], which cannot be expressed in the UDP length field.
///
/// `mtu` is the link MTU excluding the Ethernet header.
///
/// Used to construct DHCP / DNS responses and relayed UDP datagrams that are
/// injected directly into the guest FD.
///
/// # Panics
///
/// Panics if `mtu < 36` (an IPv4 header plus one 8-byte fragment unit) —
/// a host misconfiguration, not a runtime input.
#[must_use]
#[allow(clippy::too_many_arguments)] // all parameters are required header fields
pub fn build_udp_ip_ethernet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    mtu: usize,
) -> Vec<Vec<u8>> {
    assert!(mtu >= 36, "mtu {mtu} cannot carry an IPv4 fragment");
    if payload.len() > MAX_UDP_PAYLOAD {
        return Vec::new();
    }

    // The IP payload: UDP header + payload, checksummed as one datagram
    // (the checksum lands in the first fragment with the UDP header).
    let udp_len = 8 + payload.len();
    let mut datagram = vec![0u8; udp_len];
    datagram[0..2].copy_from_slice(&src_port.to_be_bytes());
    datagram[2..4].copy_from_slice(&dst_port.to_be_bytes());
    datagram[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // Checksum field stays 0 while the checksum is computed.
    datagram[8..].copy_from_slice(payload);
    let udp_cksum = udp_checksum(src_ip, dst_ip, &datagram);
    datagram[6..8].copy_from_slice(&udp_cksum.to_be_bytes());

    let ip_id = NEXT_IP_ID.fetch_add(1, Ordering::Relaxed);

    if 20 + udp_len <= mtu {
        return vec![build_frame(
            src_ip, dst_ip, ip_id, 0, false, &datagram, src_mac, dst_mac,
        )];
    }

    // Per-fragment IP payload: what fits under the MTU, rounded down to the
    // 8-byte fragment-offset unit.
    let chunk = (mtu - 20) & !7;
    datagram
        .chunks(chunk)
        .enumerate()
        .map(|(i, part)| {
            let offset = i * chunk;
            let more = offset + part.len() < udp_len;
            build_frame(src_ip, dst_ip, ip_id, offset, more, part, src_mac, dst_mac)
        })
        .collect()
}

/// Builds one Ethernet + IPv4 frame carrying `ip_payload` at
/// `frag_offset_bytes` of the enclosing datagram.
#[allow(clippy::too_many_arguments)] // all parameters are required header fields
fn build_frame(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    ip_id: u16,
    frag_offset_bytes: usize,
    more_fragments: bool,
    ip_payload: &[u8],
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
) -> Vec<u8> {
    let ip_total_len = 20 + ip_payload.len();
    let mut frame = vec![0u8; ETH_HEADER_LEN + ip_total_len];

    // -- Ethernet header --
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // -- IPv4 header (20 bytes, no options) --
    let ip = &mut frame[ETH_HEADER_LEN..];
    ip[0] = 0x45; // Version 4, IHL 5
    ip[2..4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&ip_id.to_be_bytes());
    // Flags (bit 13 = MF) + fragment offset in 8-byte units.
    let flags_frag = (u16::from(more_fragments) << 13) | ((frag_offset_bytes / 8) as u16);
    ip[6..8].copy_from_slice(&flags_frag.to_be_bytes());
    ip[8] = 64; // TTL
    ip[9] = 17; // Protocol: UDP
    ip[12..16].copy_from_slice(&src_ip.octets());
    ip[16..20].copy_from_slice(&dst_ip.octets());

    let ip_cksum = ipv4_header_checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    frame[ETH_HEADER_LEN + 20..].copy_from_slice(ip_payload);
    frame
}
