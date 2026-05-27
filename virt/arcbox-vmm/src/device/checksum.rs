//! virtio-net guest checksum offload finalization.
//!
//! When the guest sets `VIRTIO_NET_HDR_F_NEEDS_CSUM`, it means the TCP/UDP
//! checksum field inside the frame is uninitialized and the host must
//! compute it before forwarding. This is the standard offload arrangement
//! — it lets the guest skip per-packet checksum computation.

use arcbox_net::nat_engine::checksum::{tcp_checksum, udp_checksum};
use arcbox_virtio::net::VirtioNetHeader;

const ETH_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;

/// Completes guest-requested checksum offload before forwarding the frame.
pub(super) fn finalize_virtio_net_checksum(packet_data: &mut [u8]) {
    if packet_data.len() <= VirtioNetHeader::SIZE {
        return;
    }

    let Some(header) = VirtioNetHeader::from_bytes(&packet_data[..VirtioNetHeader::SIZE]) else {
        return;
    };
    if header.flags & VirtioNetHeader::FLAG_NEEDS_CSUM == 0 {
        return;
    }

    let frame = &mut packet_data[VirtioNetHeader::SIZE..];
    if frame.len() < ETH_HEADER_LEN + 20 || frame[12..14] != ETHERTYPE_IPV4 {
        return;
    }

    let ip_start = ETH_HEADER_LEN;
    let version = frame[ip_start] >> 4;
    let ihl = usize::from(frame[ip_start] & 0x0F) * 4;
    if version != 4 || ihl < 20 || frame.len() < ip_start + ihl {
        return;
    }

    let total_len = usize::from(u16::from_be_bytes([
        frame[ip_start + 2],
        frame[ip_start + 3],
    ]));
    if total_len < ihl || frame.len() < ip_start + total_len {
        return;
    }

    let checksum_start = usize::from(header.csum_start);
    let checksum_offset = usize::from(header.csum_offset);
    let payload_end = ip_start + total_len;
    let checksum_end = checksum_start
        .checked_add(checksum_offset)
        .and_then(|offset| offset.checked_add(2));
    if checksum_start < ip_start + ihl || checksum_end.is_none_or(|end| end > payload_end) {
        return;
    }

    let protocol = frame[ip_start + 9];
    let src_ip = [
        frame[ip_start + 12],
        frame[ip_start + 13],
        frame[ip_start + 14],
        frame[ip_start + 15],
    ];
    let dst_ip = [
        frame[ip_start + 16],
        frame[ip_start + 17],
        frame[ip_start + 18],
        frame[ip_start + 19],
    ];

    let Some(checksum_start_offset) = checksum_start.checked_add(checksum_offset) else {
        return;
    };
    frame[checksum_start_offset..checksum_start_offset + 2].fill(0);

    let checksum = match protocol {
        PROTOCOL_TCP => tcp_checksum(src_ip, dst_ip, &frame[checksum_start..payload_end]),
        PROTOCOL_UDP => udp_checksum(src_ip, dst_ip, &frame[checksum_start..payload_end]),
        _ => return,
    };
    frame[checksum_start_offset..checksum_start_offset + 2]
        .copy_from_slice(&checksum.to_be_bytes());
}
