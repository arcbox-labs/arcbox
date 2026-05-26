//! Ethernet frame builders and parsers for network datapath tests.
//!
//! Constructs well-formed L2 Ethernet frames that can be injected into the
//! mock guest NIC socketpair. Also provides minimal parsers for validating
//! response frames.

// Builders/parsers are used across different test files; not all are
// exercised yet but will be as more datapath tests are added.
#![allow(dead_code)]

use std::net::Ipv4Addr;

/// Ethernet header length.
const ETH_HDR: usize = 14;

// ---------------------------------------------------------------------------
// Frame builders
// ---------------------------------------------------------------------------

/// Builds an ARP request frame.
///
/// Standard 42-byte Ethernet + ARP for IPv4 over Ethernet.
pub fn build_arp_request(src_mac: [u8; 6], src_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut frame = vec![0u8; 42];
    // Ethernet: dst = broadcast, src = sender, type = ARP (0x0806)
    frame[0..6].copy_from_slice(&[0xFF; 6]);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x06]);
    // ARP payload
    frame[14..16].copy_from_slice(&[0x00, 0x01]); // HW type: Ethernet
    frame[16..18].copy_from_slice(&[0x08, 0x00]); // Protocol: IPv4
    frame[18] = 6; // HW addr len
    frame[19] = 4; // Proto addr len
    frame[20..22].copy_from_slice(&[0x00, 0x01]); // Op: Request
    frame[22..28].copy_from_slice(&src_mac); // Sender HW addr
    frame[28..32].copy_from_slice(&src_ip.octets()); // Sender proto addr
    frame[32..38].copy_from_slice(&[0x00; 6]); // Target HW addr (unknown)
    frame[38..42].copy_from_slice(&target_ip.octets()); // Target proto addr
    frame
}

/// Builds a DHCP DISCOVER frame (full L2/IP/UDP/DHCP stack).
///
/// The returned frame is a broadcast Ethernet frame with:
/// - IP: 0.0.0.0 -> 255.255.255.255
/// - UDP: src=68, dst=67
/// - DHCP DISCOVER payload with the given client MAC and transaction ID.
pub fn build_dhcp_discover(client_mac: [u8; 6], xid: u32) -> Vec<u8> {
    let dhcp_payload = build_dhcp_discover_payload(client_mac, xid);
    build_udp_frame(
        client_mac,
        [0xFF; 6], // broadcast
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
        68,
        67,
        &dhcp_payload,
    )
}

/// Builds a DHCP REQUEST frame (full L2/IP/UDP/DHCP stack).
///
/// Requests the IP `requested_ip` from the server at `server_ip`.
pub fn build_dhcp_request(
    client_mac: [u8; 6],
    xid: u32,
    requested_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
) -> Vec<u8> {
    let dhcp_payload = build_dhcp_request_payload(client_mac, xid, requested_ip, server_ip);
    build_udp_frame(
        client_mac,
        [0xFF; 6], // broadcast
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
        68,
        67,
        &dhcp_payload,
    )
}

/// Builds a TCP SYN frame.
pub fn build_tcp_syn(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> Vec<u8> {
    let tcp_hdr_len = 20;
    let ip_total = 20 + tcp_hdr_len;
    let frame_len = ETH_HDR + ip_total;
    let mut frame = vec![0u8; frame_len];

    // Ethernet header
    write_eth_header(&mut frame, src_mac, dst_mac, 0x0800);

    // IPv4 header
    let ip = ETH_HDR;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&(ip_total as u16).to_be_bytes());
    frame[ip + 8] = 64; // TTL
    frame[ip + 9] = 6; // TCP
    frame[ip + 12..ip + 16].copy_from_slice(&src_ip.octets());
    frame[ip + 16..ip + 20].copy_from_slice(&dst_ip.octets());
    write_ipv4_checksum(&mut frame[ip..ip + 20]);

    // TCP header
    let l4 = ip + 20;
    frame[l4..l4 + 2].copy_from_slice(&src_port.to_be_bytes());
    frame[l4 + 2..l4 + 4].copy_from_slice(&dst_port.to_be_bytes());
    frame[l4 + 4..l4 + 8].copy_from_slice(&1000u32.to_be_bytes()); // seq
    frame[l4 + 12] = 0x50; // data offset = 5 words
    frame[l4 + 13] = 0x02; // SYN flag

    frame
}

/// Builds a DNS query frame (L2/IP/UDP/DNS).
pub fn build_dns_query(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
    domain: &str,
) -> Vec<u8> {
    let dns_payload = build_dns_query_payload(domain);
    build_udp_frame(
        src_mac,
        dst_mac,
        src_ip,
        gateway_ip,
        12345, // ephemeral src port
        53,
        &dns_payload,
    )
}

/// Builds a UDP frame with arbitrary payload.
pub fn build_udp_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let ip_total = 20 + udp_len;
    let frame_len = ETH_HDR + ip_total;
    let mut frame = vec![0u8; frame_len];

    // Ethernet header
    write_eth_header(&mut frame, src_mac, dst_mac, 0x0800);

    // IPv4 header
    let ip = ETH_HDR;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&(ip_total as u16).to_be_bytes());
    frame[ip + 8] = 64; // TTL
    frame[ip + 9] = 17; // UDP
    frame[ip + 12..ip + 16].copy_from_slice(&src_ip.octets());
    frame[ip + 16..ip + 20].copy_from_slice(&dst_ip.octets());
    write_ipv4_checksum(&mut frame[ip..ip + 20]);

    // UDP header
    let udp = ip + 20;
    frame[udp..udp + 2].copy_from_slice(&src_port.to_be_bytes());
    frame[udp + 2..udp + 4].copy_from_slice(&dst_port.to_be_bytes());
    frame[udp + 4..udp + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // UDP checksum = 0 (optional for IPv4)

    // Payload
    frame[udp + 8..].copy_from_slice(payload);

    frame
}

/// Builds an ICMP Echo Request frame.
pub fn build_icmp_echo(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    id: u16,
    seq: u16,
) -> Vec<u8> {
    let icmp_len = 8; // type(1) + code(1) + checksum(2) + id(2) + seq(2)
    let ip_total = 20 + icmp_len;
    let frame_len = ETH_HDR + ip_total;
    let mut frame = vec![0u8; frame_len];

    // Ethernet header
    write_eth_header(&mut frame, src_mac, dst_mac, 0x0800);

    // IPv4 header
    let ip = ETH_HDR;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&(ip_total as u16).to_be_bytes());
    frame[ip + 8] = 64; // TTL
    frame[ip + 9] = 1; // ICMP
    frame[ip + 12..ip + 16].copy_from_slice(&src_ip.octets());
    frame[ip + 16..ip + 20].copy_from_slice(&dst_ip.octets());
    write_ipv4_checksum(&mut frame[ip..ip + 20]);

    // ICMP Echo Request
    let icmp = ip + 20;
    frame[icmp] = 8; // Type: Echo Request
    frame[icmp + 1] = 0; // Code
    frame[icmp + 4..icmp + 6].copy_from_slice(&id.to_be_bytes());
    frame[icmp + 6..icmp + 8].copy_from_slice(&seq.to_be_bytes());
    // ICMP checksum
    let cksum = internet_checksum(&frame[icmp..icmp + icmp_len]);
    frame[icmp + 2..icmp + 4].copy_from_slice(&cksum.to_be_bytes());

    frame
}

// ---------------------------------------------------------------------------
// Frame parsers
// ---------------------------------------------------------------------------

/// Parsed Ethernet frame header.
#[derive(Debug)]
pub struct ParsedEthFrame<'a> {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
    pub payload: &'a [u8],
}

/// Parses an Ethernet frame header.
pub fn parse_eth_frame(frame: &[u8]) -> Option<ParsedEthFrame<'_>> {
    if frame.len() < ETH_HDR {
        return None;
    }
    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    dst_mac.copy_from_slice(&frame[0..6]);
    src_mac.copy_from_slice(&frame[6..12]);
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    Some(ParsedEthFrame {
        dst_mac,
        src_mac,
        ethertype,
        payload: &frame[ETH_HDR..],
    })
}

/// Extracts the DHCP payload from a UDP/IP/Ethernet frame.
///
/// Returns the raw DHCP bytes (starting after the UDP header), or `None`
/// if the frame is too short or not a UDP packet.
pub fn extract_dhcp_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < ETH_HDR + 28 {
        return None;
    }
    let ip_start = ETH_HDR;
    let ihl = ((frame[ip_start] & 0x0F) as usize) * 4;
    let l4 = ip_start + ihl;
    let dhcp = l4 + 8;
    if dhcp >= frame.len() {
        return None;
    }
    Some(&frame[dhcp..])
}

/// Parsed DHCP response fields (minimal for test validation).
#[derive(Debug)]
pub struct ParsedDhcp {
    pub op: u8,
    pub xid: u32,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub message_type: Option<u8>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub router: Option<Ipv4Addr>,
    pub lease_time: Option<u32>,
    pub server_id: Option<Ipv4Addr>,
}

/// Parses a DHCP payload (raw bytes after UDP header).
pub fn parse_dhcp(data: &[u8]) -> Option<ParsedDhcp> {
    if data.len() < 240 {
        return None;
    }
    let op = data[0];
    let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let yiaddr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let siaddr = Ipv4Addr::new(data[20], data[21], data[22], data[23]);

    // Parse options (after magic cookie at offset 236).
    let mut message_type = None;
    let mut subnet_mask = None;
    let mut router = None;
    let mut lease_time = None;
    let mut server_id = None;

    if data.len() > 240 && data[236..240] == [99, 130, 83, 99] {
        let mut i = 240;
        while i < data.len() {
            let code = data[i];
            if code == 255 {
                break;
            }
            if code == 0 {
                i += 1;
                continue;
            }
            if i + 1 >= data.len() {
                break;
            }
            let len = data[i + 1] as usize;
            if i + 2 + len > data.len() {
                break;
            }
            let val = &data[i + 2..i + 2 + len];
            match code {
                53 if len == 1 => message_type = Some(val[0]),
                1 if len == 4 => {
                    subnet_mask = Some(Ipv4Addr::new(val[0], val[1], val[2], val[3]));
                }
                3 if len >= 4 => {
                    router = Some(Ipv4Addr::new(val[0], val[1], val[2], val[3]));
                }
                51 if len == 4 => {
                    lease_time = Some(u32::from_be_bytes([val[0], val[1], val[2], val[3]]));
                }
                54 if len == 4 => {
                    server_id = Some(Ipv4Addr::new(val[0], val[1], val[2], val[3]));
                }
                _ => {}
            }
            i += 2 + len;
        }
    }

    Some(ParsedDhcp {
        op,
        xid,
        yiaddr,
        siaddr,
        message_type,
        subnet_mask,
        router,
        lease_time,
        server_id,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Writes the Ethernet header at the start of `frame`.
fn write_eth_header(frame: &mut [u8], src_mac: [u8; 6], dst_mac: [u8; 6], ethertype: u16) {
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
}

/// Computes and writes the IPv4 header checksum in-place.
fn write_ipv4_checksum(header: &mut [u8]) {
    // Clear existing checksum field.
    header[10] = 0;
    header[11] = 0;
    let cksum = internet_checksum(header);
    header[10..12].copy_from_slice(&cksum.to_be_bytes());
}

/// RFC 1071 internet checksum.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Builds a DHCP DISCOVER payload (just the BOOTP/DHCP portion).
fn build_dhcp_discover_payload(client_mac: [u8; 6], xid: u32) -> Vec<u8> {
    let mut data = vec![0u8; 300]; // Enough for header + magic + options

    data[0] = 1; // BOOTREQUEST
    data[1] = 1; // HW type: Ethernet
    data[2] = 6; // HW addr len
    data[4..8].copy_from_slice(&xid.to_be_bytes());
    data[28..34].copy_from_slice(&client_mac);

    // Magic cookie at offset 236
    data[236..240].copy_from_slice(&[99, 130, 83, 99]);

    // Options
    let mut opt = 240;
    // Option 53: DHCP Message Type = DISCOVER (1)
    data[opt] = 53;
    data[opt + 1] = 1;
    data[opt + 2] = 1;
    opt += 3;
    // Option 255: End
    data[opt] = 255;

    data
}

/// Builds a DHCP REQUEST payload.
fn build_dhcp_request_payload(
    client_mac: [u8; 6],
    xid: u32,
    requested_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut data = vec![0u8; 300];

    data[0] = 1; // BOOTREQUEST
    data[1] = 1; // HW type: Ethernet
    data[2] = 6; // HW addr len
    data[4..8].copy_from_slice(&xid.to_be_bytes());
    data[28..34].copy_from_slice(&client_mac);

    // Magic cookie
    data[236..240].copy_from_slice(&[99, 130, 83, 99]);

    // Options
    let mut opt = 240;
    // Option 53: DHCP Message Type = REQUEST (3)
    data[opt] = 53;
    data[opt + 1] = 1;
    data[opt + 2] = 3;
    opt += 3;
    // Option 50: Requested IP Address
    data[opt] = 50;
    data[opt + 1] = 4;
    data[opt + 2..opt + 6].copy_from_slice(&requested_ip.octets());
    opt += 6;
    // Option 54: Server Identifier
    data[opt] = 54;
    data[opt + 1] = 4;
    data[opt + 2..opt + 6].copy_from_slice(&server_ip.octets());
    opt += 6;
    // Option 255: End
    data[opt] = 255;

    data
}

/// Builds a minimal DNS A query payload for `domain`.
fn build_dns_query_payload(domain: &str) -> Vec<u8> {
    let mut pkt = Vec::new();
    // Header: ID=0xABCD, flags=standard query, QDCOUNT=1
    pkt.extend_from_slice(&[0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // Question: encode domain labels
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00); // root label
    pkt.extend_from_slice(&[0x00, 0x01]); // QTYPE: A
    pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN
    pkt
}
