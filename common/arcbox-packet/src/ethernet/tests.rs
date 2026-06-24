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
