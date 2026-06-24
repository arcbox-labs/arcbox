use super::*;
use crate::ethernet::ETH_HEADER_LEN;

const GW_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 64, 1);
const GW_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const GUEST_MAC: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
const GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 64, 2);

// -------- Handshake synthesizer tests --------

#[test]
fn test_next_isn_distinct_values() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..1000 {
        let isn = next_isn();
        assert!(seen.insert(isn), "next_isn produced duplicate {isn:08x}");
    }
}

/// Builds a synthetic guest SYN frame with the given options.
fn make_guest_syn_frame(
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    seq: u32,
    options: &[u8],
) -> Vec<u8> {
    assert_eq!(options.len() % 4, 0);
    let tcp_hdr_len = 20 + options.len();
    let ip_total = 20 + tcp_hdr_len;
    let mut frame = vec![0u8; ETH_HEADER_LEN + ip_total];
    // Eth: dst=GW_MAC, src=GUEST_MAC, IPv4.
    frame[0..6].copy_from_slice(&GW_MAC);
    frame[6..12].copy_from_slice(&GUEST_MAC);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    // IPv4.
    let ip = 14;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&(ip_total as u16).to_be_bytes());
    frame[ip + 8] = 64;
    frame[ip + 9] = 6;
    frame[ip + 12..ip + 16].copy_from_slice(&GUEST_IP.octets());
    frame[ip + 16..ip + 20].copy_from_slice(&dst_ip.octets());
    // TCP.
    let tcp = 34;
    frame[tcp..tcp + 2].copy_from_slice(&src_port.to_be_bytes());
    frame[tcp + 2..tcp + 4].copy_from_slice(&dst_port.to_be_bytes());
    frame[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
    frame[tcp + 12] = ((tcp_hdr_len / 4) as u8) << 4;
    frame[tcp + 13] = 0x02; // SYN
    frame[tcp + 14..tcp + 16].copy_from_slice(&65535u16.to_be_bytes());
    frame[tcp + 20..tcp + 20 + options.len()].copy_from_slice(options);
    frame
}

/// Builds a guest ACK frame (pure ACK, no payload).
fn make_guest_ack_frame(
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    seq: u32,
    ack: u32,
) -> Vec<u8> {
    let mut frame = vec![0u8; ETH_HEADER_LEN + 40];
    frame[0..6].copy_from_slice(&GW_MAC);
    frame[6..12].copy_from_slice(&GUEST_MAC);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip = 14;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&40u16.to_be_bytes());
    frame[ip + 9] = 6;
    frame[ip + 12..ip + 16].copy_from_slice(&GUEST_IP.octets());
    frame[ip + 16..ip + 20].copy_from_slice(&dst_ip.octets());
    let tcp = 34;
    frame[tcp..tcp + 2].copy_from_slice(&src_port.to_be_bytes());
    frame[tcp + 2..tcp + 4].copy_from_slice(&dst_port.to_be_bytes());
    frame[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
    frame[tcp + 8..tcp + 12].copy_from_slice(&ack.to_be_bytes());
    frame[tcp + 12] = 0x50;
    frame[tcp + 13] = 0x10; // ACK
    frame
}

/// Builds a guest SYN-ACK frame (for ActiveOpen completion tests).
fn make_guest_syn_ack_frame(
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    seq: u32,
    ack: u32,
) -> Vec<u8> {
    let mut frame = make_guest_ack_frame(src_port, dst_ip, dst_port, seq, ack);
    let tcp = 34;
    frame[tcp + 13] = 0x12; // SYN | ACK
    frame
}

#[tokio::test]
async fn handshake_passive_open_registers_and_emits_syn_ack() {
    // Spin up a local listener so the host connect succeeds.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_port = addr.port();

    let mut bridge = TcpBridge::new(GW_IP);
    bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);

    // Build a guest SYN with MSS + WScale + SACK-Permitted (12-byte options).
    let opts = &[
        2, 4, 0x05, 0xB4, // MSS = 1460
        3, 3, 8, // WScale = 8 (peer)
        4, 2, // SACK-Permitted
        1, 1, 1, // NOP padding to 12 bytes (4-aligned)
    ];
    // Target 127.0.0.1 directly via the non-gateway path.
    let syn = make_guest_syn_frame(40001, Ipv4Addr::LOCALHOST, server_port, 0xAAAA_AAAA, opts);

    // handle_outbound_syn returns None on success, Some(RST) on reject.
    let rst = bridge.handle_outbound_syn(&syn, GW_MAC, GUEST_MAC);
    assert!(rst.is_none());
    assert_eq!(bridge.handshake_count(), 1);

    // Accept the server-side connection so our tokio connect resolves.
    let (_accepted, _) = listener.accept().await.unwrap();
    // Give the tokio task time to deliver the stream.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Poll — should emit SYN-ACK.
    let out = bridge.poll_handshakes();
    assert_eq!(out.len(), 1, "expected one SYN-ACK frame");
    let syn_ack = &out[0];

    // Verify: flags=SYN|ACK, ack=guest_isn+1, correct options.
    let tcp = 34;
    assert_eq!(syn_ack[tcp + 13], 0x12);
    let ack = u32::from_be_bytes([
        syn_ack[tcp + 8],
        syn_ack[tcp + 9],
        syn_ack[tcp + 10],
        syn_ack[tcp + 11],
    ]);
    assert_eq!(ack, 0xAAAA_AAAAu32.wrapping_add(1));
    let parsed = crate::ethernet::parse_tcp_syn_options(&syn_ack[tcp..]);
    assert_eq!(parsed.mss, Some(SHIM_MSS));
    assert_eq!(parsed.wscale, Some(SHIM_WSCALE));
    assert!(parsed.sack_permitted);
}

#[tokio::test]
async fn handshake_passive_open_completes_on_guest_ack() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_port = addr.port();

    let mut bridge = TcpBridge::new(GW_IP);
    bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);

    let guest_isn = 0x1234_5678u32;
    let syn = make_guest_syn_frame(
        40002,
        Ipv4Addr::LOCALHOST,
        server_port,
        guest_isn,
        &[2, 4, 0x05, 0xB4],
    );
    assert!(
        bridge
            .handle_outbound_syn(&syn, GW_MAC, GUEST_MAC)
            .is_none()
    );

    let (_accepted, _) = listener.accept().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let syn_ack = bridge.poll_handshakes();
    assert_eq!(syn_ack.len(), 1);
    let tcp = 34;
    let our_isn = u32::from_be_bytes([
        syn_ack[0][tcp + 4],
        syn_ack[0][tcp + 5],
        syn_ack[0][tcp + 6],
        syn_ack[0][tcp + 7],
    ]);

    // Guest completes the handshake.
    let guest_ack = make_guest_ack_frame(
        40002,
        Ipv4Addr::LOCALHOST,
        server_port,
        guest_isn.wrapping_add(1),
        our_isn.wrapping_add(1),
    );
    let result = bridge.try_complete_handshake(&guest_ack);
    assert!(result.is_some());

    // Now promoted to fast path; handshake entry gone.
    assert_eq!(bridge.handshake_count(), 0);
    assert_eq!(bridge.fast_path_count(), 1);
}

#[tokio::test]
async fn handshake_active_open_emits_syn_and_completes() {
    // Pretend the host accepted a connection; wire up two loopback
    // streams so `initiate_active_handshake` has a valid stream.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (_server, _) = listener.accept().await.unwrap();
    let host_stream = client.into_std().unwrap();

    let mut bridge = TcpBridge::new(GW_IP);
    bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);

    let flow_key = SynFlowKey {
        src_ip: GUEST_IP,
        src_port: 8080,
        dst_ip: GW_IP,
        dst_port: 61500,
    };
    bridge.initiate_active_handshake(flow_key, host_stream, GW_MAC, GUEST_MAC);
    assert_eq!(bridge.handshake_count(), 1);

    // Poll emits our SYN toward the guest.
    let out = bridge.poll_handshakes();
    assert_eq!(out.len(), 1);
    let tcp = 34;
    assert_eq!(out[0][tcp + 13], 0x02, "expected pure SYN");
    let our_isn = u32::from_be_bytes([
        out[0][tcp + 4],
        out[0][tcp + 5],
        out[0][tcp + 6],
        out[0][tcp + 7],
    ]);

    // Guest responds with SYN-ACK.
    let guest_isn = 0xDEAD_BEEFu32;
    let syn_ack = make_guest_syn_ack_frame(8080, GW_IP, 61500, guest_isn, our_isn.wrapping_add(1));
    let reply = bridge.try_complete_handshake(&syn_ack);
    let reply = reply.expect("shim should accept SYN-ACK");
    assert_eq!(reply.len(), 1, "expected final ACK frame");
    assert_eq!(reply[0][tcp + 13], 0x10, "flags=ACK");

    assert_eq!(bridge.handshake_count(), 0);
    assert_eq!(bridge.fast_path_count(), 1);
}

#[tokio::test]
async fn handshake_rejects_mismatched_ack() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut bridge = TcpBridge::new(GW_IP);
    bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);

    let guest_isn = 7777;
    let syn = make_guest_syn_frame(
        40003,
        Ipv4Addr::LOCALHOST,
        addr.port(),
        guest_isn,
        &[2, 4, 0x05, 0xB4],
    );
    bridge.handle_outbound_syn(&syn, GW_MAC, GUEST_MAC);
    let (_accepted, _) = listener.accept().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let _ = bridge.poll_handshakes();

    // ACK with wrong ack number — shim must reject (return None) and
    // leave the handshake entry intact.
    let bad_ack = make_guest_ack_frame(
        40003,
        Ipv4Addr::LOCALHOST,
        addr.port(),
        guest_isn.wrapping_add(1),
        0xBAD_BAD,
    );
    let result = bridge.try_complete_handshake(&bad_ack);
    assert!(result.is_none());
    assert_eq!(bridge.handshake_count(), 1);
    assert_eq!(bridge.fast_path_count(), 0);
}

#[test]
fn handshake_capacity_sends_rst() {
    let mut bridge = TcpBridge::new(GW_IP);
    // Fill to capacity with fake entries.
    for i in 0..MAX_PENDING_SYNS {
        let k = SynFlowKey {
            src_ip: GUEST_IP,
            src_port: 10000 + i as u16,
            dst_ip: Ipv4Addr::new(203, 0, 113, 1),
            dst_port: 80,
        };
        bridge.handshake_conns.insert(
            k,
            HandshakeConn {
                flow_key: k,
                role: HandshakeRole::PassiveOpen,
                our_isn: 0,
                peer_isn: 0,
                host_stream: None,
                connect_rx: None,
                peer_wscale: None,
                peer_sack: false,
                peer_mss: 1460,
                gw_mac: GW_MAC,
                guest_mac: GUEST_MAC,
                retransmit_count: 0,
                last_sent: None,
                saved_frame: None,
                created: StdInstant::now(),
            },
        );
    }
    let syn = make_guest_syn_frame(
        9999,
        Ipv4Addr::new(203, 0, 113, 1),
        80,
        0,
        &[2, 4, 0x05, 0xB4],
    );
    let rst = bridge.handle_outbound_syn(&syn, GW_MAC, GUEST_MAC);
    assert!(rst.is_some(), "capacity-exceeded must return RST");
    let rst = rst.unwrap();
    assert_eq!(rst[34 + 13], 0x14, "RST|ACK flags expected");
}

#[tokio::test]
async fn poll_fast_path_segments_frames_for_unix_dgram_limit() {
    use tokio::io::AsyncWriteExt;

    let mut bridge = TcpBridge::new(GW_IP);
    bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::net::TcpStream::connect(addr);
    let (client, accepted) = tokio::join!(connect, listener.accept());
    let client = client.unwrap();
    let (mut accepted, _) = accepted.unwrap();

    let key = SynFlowKey {
        src_ip: GUEST_IP,
        src_port: 12345,
        dst_ip: Ipv4Addr::new(198, 18, 30, 95),
        dst_port: 443,
    };
    bridge.promote_to_fast_path(key, client.into_std().unwrap(), 1, 1);

    let payload = vec![0xAB; FAST_PATH_GUEST_MSS * 2 + 128];
    accepted.write_all(&payload).await.unwrap();

    // Loopback TCP delivery from `write_all` to the peer's recv buffer
    // is asynchronous at the kernel level. On a slow/busy CI runner a
    // single immediate `poll_fast_path` can race the delivery and
    // observe zero bytes (non-blocking read returns WouldBlock). Poll
    // with a small backoff until we accumulate the full payload or
    // time out.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut frames: Vec<Vec<u8>> = Vec::new();
    loop {
        let batch = bridge.poll_fast_path();
        let had_new = !batch.is_empty();
        frames.extend(batch);
        let received: usize = frames
            .iter()
            .map(|f| f.len().saturating_sub(ETH_HEADER_LEN + 40))
            .sum();
        if received >= payload.len() || std::time::Instant::now() >= deadline {
            break;
        }
        if !had_new {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    assert!(
        frames.len() >= 3,
        "large host payload should be segmented into multiple guest frames (got {})",
        frames.len(),
    );
    assert!(
        frames
            .iter()
            .all(|frame| frame.len() <= UNIX_DGRAM_MAX_FRAME_LEN),
        "fast-path frames must respect the AF_UNIX/SOCK_DGRAM datagram limit"
    );
}

#[tokio::test]
async fn poll_fast_path_segments_frames_for_configured_mtu() {
    use tokio::io::AsyncWriteExt;

    let mut bridge = TcpBridge::new(GW_IP);
    bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);
    bridge.set_fast_path_mtu(4000);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::net::TcpStream::connect(addr);
    let (client, accepted) = tokio::join!(connect, listener.accept());
    let client = client.unwrap();
    let (mut accepted, _) = accepted.unwrap();

    let key = SynFlowKey {
        src_ip: GUEST_IP,
        src_port: 12345,
        dst_ip: Ipv4Addr::new(198, 18, 30, 95),
        dst_port: 443,
    };
    bridge.promote_to_fast_path(key, client.into_std().unwrap(), 1, 1);

    let payload = vec![0xAB; 5000];
    accepted.write_all(&payload).await.unwrap();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut frames: Vec<Vec<u8>> = Vec::new();
    loop {
        let batch = bridge.poll_fast_path();
        let had_new = !batch.is_empty();
        frames.extend(batch);
        let received: usize = frames
            .iter()
            .map(|frame| frame.len().saturating_sub(ETH_HEADER_LEN + 40))
            .sum();
        if received >= payload.len() || std::time::Instant::now() >= deadline {
            break;
        }
        if !had_new {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    assert_eq!(frames.len(), 2);

    let first_ip_len =
        u16::from_be_bytes([frames[0][ETH_HEADER_LEN + 2], frames[0][ETH_HEADER_LEN + 3]]);
    let second_ip_len =
        u16::from_be_bytes([frames[1][ETH_HEADER_LEN + 2], frames[1][ETH_HEADER_LEN + 3]]);
    assert_eq!(first_ip_len, 4000);
    assert_eq!(second_ip_len, 1080);
}
