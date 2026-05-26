//! Inline (vhost-style) fast-path connections.
//!
//! When a TCP connection is promoted to the fast path, its socket is moved
//! here. The inject thread reads directly from the host TCP socket into
//! guest descriptor buffers — **zero intermediate copies**.
//!
//! Data flow:
//! ```text
//! host socket → read() into guest_buf[66..] → 1 syscall, 1 copy
//! write 12-byte virtio-net header + 54-byte Eth/IP/TCP header inline
//! update used ring + batch interrupt
//! ```

use std::io::Read;
use std::net::{Ipv4Addr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// Ethernet (14) + IPv4 (20) + TCP (20) = 54 bytes of L2/L3/L4 headers.
const ETH_IP_TCP_HDR_LEN: usize = 54;

/// Virtio-net header (12 bytes) + Ethernet+IP+TCP headers (54 bytes).
pub const TOTAL_HDR_LEN: usize = 12 + ETH_IP_TCP_HDR_LEN;

/// A promoted fast-path TCP connection owned by the inject thread.
/// The socket lives here — reads go directly to guest memory.
pub struct InlineConn {
    /// Host-side TCP stream (non-blocking).
    pub stream: TcpStream,
    /// Remote IP as seen by the guest.
    pub remote_ip: Ipv4Addr,
    /// Guest IP.
    pub guest_ip: Ipv4Addr,
    /// Remote TCP port.
    pub remote_port: u16,
    /// Guest TCP port.
    pub guest_port: u16,
    /// Our SEQ number for frames sent TO guest (shared with the datapath
    /// loop via atomic so ACKs emitted by try_fast_path_intercept carry
    /// the up-to-date seq after the inline thread advances it).
    pub our_seq: Arc<AtomicU32>,
    /// Last ACK from guest (shared with datapath loop via atomic).
    pub last_ack: Arc<AtomicU32>,
    /// Gateway MAC for Ethernet source.
    pub gw_mac: [u8; 6],
    /// Guest MAC for Ethernet destination.
    pub guest_mac: [u8; 6],
    /// Whether host stream has reached EOF.
    pub host_eof: bool,
}

// SAFETY: TcpStream is Send, all other fields are Send+Sync.
unsafe impl Send for InlineConn {}

/// Writes 66 bytes of headers (12 virtio-net + 54 Eth/IP/TCP) directly
/// into a guest descriptor buffer. Returns the number of header bytes
/// written, or 0 if the buffer is too small.
///
/// The TCP checksum field is filled with the pseudo-header checksum only —
/// the guest kernel completes it per-segment during GSO (NEEDS_CSUM).
///
/// `num_buffers` is stamped into the virtio-net header's `num_buffers`
/// field (bytes 10..12). For single-descriptor frames pass `1`; for
/// MRG_RXBUF multi-descriptor delivery pass the count of descriptors
/// this frame spans.
pub fn write_inline_headers(
    buf: &mut [u8],
    conn: &InlineConn,
    payload_len: usize,
    num_buffers: u16,
) -> usize {
    if buf.len() < TOTAL_HDR_LEN {
        return 0;
    }

    let last_ack = conn.last_ack.load(Ordering::Relaxed);
    let tcp_total_len = 20 + payload_len;
    let ip_total_len = 20 + tcp_total_len;
    let eth_total_len = 14 + ip_total_len;

    // -- Virtio-net header (12 bytes) --
    buf[0..12].fill(0);
    // Always set NEEDS_CSUM so the guest kernel completes the TCP
    // checksum from the pseudo-header-only value below. This covers
    // both short (<= MSS) and large (> MSS) segments uniformly and
    // avoids computing the full checksum in userspace.
    buf[0] = 1; // flags = VIRTIO_NET_HDR_F_NEEDS_CSUM
    // GSO: for frames bigger than a classic Ethernet MTU, advertise
    // GSO_TCPV4 so the guest kernel segments at 1460-byte MSS boundaries.
    // Without this, guests that stick to MTU=1500 (default when
    // VIRTIO_NET_F_MTU isn't negotiated) drop oversized frames silently.
    if eth_total_len > 1500 {
        buf[1] = 1; // gso_type = VIRTIO_NET_HDR_GSO_TCPV4
        // hdr_len = Eth14 + IP20 + TCP20 = 54 (total L2+L3+L4 header size;
        // this is where the payload starts, per virtio-net spec).
        buf[2..4].copy_from_slice(&54u16.to_le_bytes());
        buf[4..6].copy_from_slice(&1460u16.to_le_bytes()); // gso_size
    }
    buf[6..8].copy_from_slice(&34u16.to_le_bytes()); // csum_start (Eth14+IP20)
    buf[8..10].copy_from_slice(&16u16.to_le_bytes()); // csum_offset (TCP csum field)
    // num_buffers: 1 for single-descriptor frames, N for MRG_RXBUF.
    buf[10..12].copy_from_slice(&num_buffers.to_le_bytes());

    // -- Ethernet header (14 bytes at offset 12) --
    let eth = 12;
    buf[eth..eth + 6].copy_from_slice(&conn.guest_mac);
    buf[eth + 6..eth + 12].copy_from_slice(&conn.gw_mac);
    buf[eth + 12..eth + 14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4

    // -- IPv4 header (20 bytes at offset 26) --
    let ip = eth + 14;
    buf[ip] = 0x45; // Version 4, IHL 5
    buf[ip + 1] = 0;
    buf[ip + 2..ip + 4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    buf[ip + 4..ip + 6].fill(0); // ID
    buf[ip + 6..ip + 8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    buf[ip + 8] = 64; // TTL
    buf[ip + 9] = 6; // TCP
    buf[ip + 10..ip + 12].fill(0); // Checksum (computed below)
    buf[ip + 12..ip + 16].copy_from_slice(&conn.remote_ip.octets());
    buf[ip + 16..ip + 20].copy_from_slice(&conn.guest_ip.octets());
    // IPv4 header checksum.
    let ip_cksum = ipv4_header_checksum(&buf[ip..ip + 20]);
    buf[ip + 10..ip + 12].copy_from_slice(&ip_cksum.to_be_bytes());

    // -- TCP header (20 bytes at offset 46) --
    let tcp = ip + 20;
    let our_seq = conn.our_seq.load(Ordering::Relaxed);
    buf[tcp..tcp + 2].copy_from_slice(&conn.remote_port.to_be_bytes());
    buf[tcp + 2..tcp + 4].copy_from_slice(&conn.guest_port.to_be_bytes());
    buf[tcp + 4..tcp + 8].copy_from_slice(&our_seq.to_be_bytes());
    buf[tcp + 8..tcp + 12].copy_from_slice(&last_ack.to_be_bytes());
    buf[tcp + 12] = 0x50; // Data offset: 5 (20 bytes)
    buf[tcp + 13] = 0x18; // Flags: ACK | PSH
    buf[tcp + 14..tcp + 16].copy_from_slice(&65535u16.to_be_bytes()); // Window
    buf[tcp + 16..tcp + 18].fill(0); // Checksum (filled below)
    buf[tcp + 18..tcp + 20].fill(0); // Urgent pointer

    // TCP pseudo-header checksum (guest completes per-segment for GSO).
    let pseudo_cksum = tcp_pseudo_header_checksum(conn.remote_ip, conn.guest_ip, tcp_total_len);
    buf[tcp + 16..tcp + 18].copy_from_slice(&pseudo_cksum.to_be_bytes());

    TOTAL_HDR_LEN
}

/// Reads from the connection's socket directly into a guest descriptor
/// buffer (after the header region). Returns the number of payload bytes
/// read, or 0 on WouldBlock/EOF.
///
/// `buf` must start at the payload offset (after 66 header bytes).
pub fn read_payload_to_guest(conn: &mut InlineConn, buf: &mut [u8]) -> std::io::Result<usize> {
    conn.stream.read(buf)
}

/// Writes a FIN+ACK control frame (66 header bytes, no payload).
///
/// Used when the host stream has reached EOF so the guest closes
/// gracefully instead of RST-ing on the next outbound write. Caller
/// must increment `conn.our_seq` by 1 after injection (FIN consumes
/// one sequence number, per RFC 793).
pub fn write_fin_headers(buf: &mut [u8], conn: &InlineConn) -> usize {
    if buf.len() < TOTAL_HDR_LEN {
        return 0;
    }

    let last_ack = conn.last_ack.load(Ordering::Relaxed);
    let tcp_total_len = 20; // TCP header only, no payload.
    let ip_total_len = 20 + tcp_total_len;

    // -- Virtio-net header (12 bytes) --
    buf[0..12].fill(0);
    buf[0] = 1; // VIRTIO_NET_HDR_F_NEEDS_CSUM
    buf[6..8].copy_from_slice(&34u16.to_le_bytes()); // csum_start
    buf[8..10].copy_from_slice(&16u16.to_le_bytes()); // csum_offset
    buf[10..12].copy_from_slice(&1u16.to_le_bytes()); // num_buffers

    // -- Ethernet --
    let eth = 12;
    buf[eth..eth + 6].copy_from_slice(&conn.guest_mac);
    buf[eth + 6..eth + 12].copy_from_slice(&conn.gw_mac);
    buf[eth + 12..eth + 14].copy_from_slice(&0x0800u16.to_be_bytes());

    // -- IPv4 --
    let ip = eth + 14;
    buf[ip] = 0x45;
    buf[ip + 1] = 0;
    buf[ip + 2..ip + 4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    buf[ip + 4..ip + 6].fill(0);
    buf[ip + 6..ip + 8].copy_from_slice(&0x4000u16.to_be_bytes());
    buf[ip + 8] = 64;
    buf[ip + 9] = 6;
    buf[ip + 10..ip + 12].fill(0);
    buf[ip + 12..ip + 16].copy_from_slice(&conn.remote_ip.octets());
    buf[ip + 16..ip + 20].copy_from_slice(&conn.guest_ip.octets());
    let ip_cksum = ipv4_header_checksum(&buf[ip..ip + 20]);
    buf[ip + 10..ip + 12].copy_from_slice(&ip_cksum.to_be_bytes());

    // -- TCP: FIN+ACK --
    let tcp = ip + 20;
    let our_seq = conn.our_seq.load(Ordering::Relaxed);
    buf[tcp..tcp + 2].copy_from_slice(&conn.remote_port.to_be_bytes());
    buf[tcp + 2..tcp + 4].copy_from_slice(&conn.guest_port.to_be_bytes());
    buf[tcp + 4..tcp + 8].copy_from_slice(&our_seq.to_be_bytes());
    buf[tcp + 8..tcp + 12].copy_from_slice(&last_ack.to_be_bytes());
    buf[tcp + 12] = 0x50; // data offset = 5 (20 bytes)
    buf[tcp + 13] = 0x11; // FIN | ACK
    buf[tcp + 14..tcp + 16].copy_from_slice(&65535u16.to_be_bytes());
    buf[tcp + 16..tcp + 18].fill(0);
    buf[tcp + 18..tcp + 20].fill(0);
    let pseudo_cksum = tcp_pseudo_header_checksum(conn.remote_ip, conn.guest_ip, tcp_total_len);
    buf[tcp + 16..tcp + 18].copy_from_slice(&pseudo_cksum.to_be_bytes());

    TOTAL_HDR_LEN
}

// -- Inline helper functions (no allocation) --

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        if i != 10 {
            // Skip checksum field.
            sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
        }
        i += 2;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

fn tcp_pseudo_header_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_len: usize) -> u16 {
    let mut sum: u32 = 0;
    let src = src_ip.octets();
    let dst = dst_ip.octets();
    sum += u32::from(u16::from_be_bytes([src[0], src[1]]));
    sum += u32::from(u16::from_be_bytes([src[2], src[3]]));
    sum += u32::from(u16::from_be_bytes([dst[0], dst[1]]));
    sum += u32::from(u16::from_be_bytes([dst[2], dst[3]]));
    sum += 6u32; // TCP
    sum += tcp_len as u32;
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}
