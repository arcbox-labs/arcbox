use std::net::Ipv4Addr;

use super::{
    ETH_HEADER_LEN,
    checksum::{ipv4_header_checksum, tcp_checksum},
};

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

    while !options.len().is_multiple_of(4) {
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

    while !options.len().is_multiple_of(4) {
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
