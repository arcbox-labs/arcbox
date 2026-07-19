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
    // Jumbo peer MSS so the dgram limit — not the peer bound — drives sizing.
    bridge.promote_to_fast_path(key, client.into_std().unwrap(), 1, 1, 9000, None);

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
    // Jumbo peer MSS so the configured MTU — not the peer bound — drives sizing.
    bridge.promote_to_fast_path(key, client.into_std().unwrap(), 1, 1, 9000, None);

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

/// Regression: even with a jumbo configured MTU, host→guest segments must be
/// bounded by the peer's advertised MSS. A container behind a 1500-MTU docker
/// bridge advertises MSS 1460; without this clamp the shim emits ~4000-byte
/// frames the guest cannot forward onto the bridge and Host→VM stalls.
#[tokio::test]
async fn poll_fast_path_clamps_segments_to_peer_mss() {
    use tokio::io::AsyncWriteExt;

    let mut bridge = TcpBridge::new(GW_IP);
    bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);
    bridge.set_fast_path_mtu(4000); // jumbo host-side budget…

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
    // …but the peer (a 1500-MTU bridged container) advertised MSS 1460.
    bridge.promote_to_fast_path(key, client.into_std().unwrap(), 1, 1, 1460, None);

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

    // Every emitted IP packet must fit a 1500-MTU link (20 IP + 20 TCP + ≤1460).
    assert!(
        frames.iter().all(|frame| {
            let ip_len = u16::from_be_bytes([frame[ETH_HEADER_LEN + 2], frame[ETH_HEADER_LEN + 3]]);
            ip_len <= 1500
        }),
        "peer MSS 1460 must bound every host→guest frame to ≤1500 bytes",
    );
    // 5000 bytes at ≤1460 payload each ⇒ at least 4 segments (not the 2 the
    // jumbo budget alone would produce).
    assert!(
        frames.len() >= 4,
        "expected ≥4 segments, got {}",
        frames.len()
    );
}

/// Regression: the GSO/large-frame path (HV) is gated on the peer accepting the
/// fixed 1460-byte GSO segments. A peer that advertised a smaller MSS (e.g. a
/// sub-1500 overlay bridge) must fall back to the clamped polling path instead
/// of a single super-frame the guest would re-segment at 1460 and drop.
#[tokio::test]
async fn large_frames_below_gso_mss_falls_back_to_clamped_segmentation() {
    use tokio::io::AsyncWriteExt;

    let mut bridge = TcpBridge::new(GW_IP);
    bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);
    bridge.enable_large_frames(); // HV-style large-frame mode…

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
    // …but the peer advertised MSS 1400, below the 1460 GSO segment size.
    bridge.promote_to_fast_path(key, client.into_std().unwrap(), 1, 1, 1400, None);

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

    // Not a single 5000-byte super-frame: clamped to the 1400 peer MSS.
    assert!(
        frames.iter().all(|frame| {
            let ip_len = u16::from_be_bytes([frame[ETH_HEADER_LEN + 2], frame[ETH_HEADER_LEN + 3]]);
            ip_len <= 1440 // 1400 payload + 20 IP + 20 TCP
        }),
        "sub-GSO-MSS peer must stay on the clamped path, not emit a super-frame",
    );
    assert!(
        frames.len() >= 4,
        "expected ≥4 clamped segments, got {}",
        frames.len()
    );
}

/// Upstream mid-stream death (reset, proxy-killed tunnel) must reach the
/// guest as a RST and reap the flow — silence leaves the guest socket
/// ESTABLISHED forever (ABX-431).
#[tokio::test]
async fn poll_fast_path_read_error_emits_rst_and_removes_flow() {
    let mut bridge = TcpBridge::new(GW_IP);
    bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::net::TcpStream::connect(addr);
    let (client, accepted) = tokio::join!(connect, listener.accept());
    let client = client.unwrap();
    let (accepted, _) = accepted.unwrap();

    let key = SynFlowKey {
        src_ip: GUEST_IP,
        src_port: 12345,
        dst_ip: Ipv4Addr::new(198, 18, 30, 95),
        dst_port: 443,
    };
    bridge.promote_to_fast_path(key, client.into_std().unwrap(), 1000, 2000, 1460, None);
    assert_eq!(bridge.fast_path_count(), 1);

    // Abortive close: SO_LINGER(0) turns the peer's close into a RST, so
    // the bridge's next read fails with ECONNRESET instead of a clean EOF.
    let accepted = accepted.into_std().unwrap();
    socket2::SockRef::from(&accepted)
        .set_linger(Some(std::time::Duration::ZERO))
        .unwrap();
    drop(accepted);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut frames: Vec<Vec<u8>> = Vec::new();
    while frames.is_empty() && std::time::Instant::now() < deadline {
        frames = bridge.poll_fast_path();
        if frames.is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    assert_eq!(
        frames.len(),
        1,
        "upstream reset must produce one guest frame"
    );
    let flags = frames[0][ETH_HEADER_LEN + 20 + 13];
    assert_ne!(flags & 0x04, 0, "frame must be a RST (flags {flags:#04x})");
    assert_eq!(bridge.fast_path_count(), 0, "flow must be reaped");
}

/// The inline inject thread owns a promoted socket's teardown; when it
/// marks the shared `dead` flag, `poll_fast_path` must reap the bridge's
/// inline-owned entry — nothing else removes it (ABX-431).
#[tokio::test]
async fn inline_dead_flag_reaps_bridge_entry() {
    struct CaptureSink(std::sync::Mutex<Option<crate::direct_rx::PromotedConn>>);
    impl crate::direct_rx::ConnSink for CaptureSink {
        fn send_conn(&self, conn: crate::direct_rx::PromotedConn) -> bool {
            *self.0.lock().unwrap() = Some(conn);
            true
        }
    }

    let sink = std::sync::Arc::new(CaptureSink(std::sync::Mutex::new(None)));
    let mut bridge = TcpBridge::new(GW_IP);
    bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);
    bridge.set_conn_sink(std::sync::Arc::clone(&sink) as _);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::net::TcpStream::connect(addr);
    let (client, accepted) = tokio::join!(connect, listener.accept());
    let client = client.unwrap();
    let _accepted = accepted.unwrap();

    let key = SynFlowKey {
        src_ip: GUEST_IP,
        src_port: 23456,
        dst_ip: Ipv4Addr::new(198, 18, 30, 96),
        dst_port: 443,
    };
    // peer_mss ≥ GSO_SEGMENT_MSS → inline-eligible, handed to the sink.
    bridge.promote_to_fast_path(key, client.into_std().unwrap(), 1000, 2000, 9000, None);
    assert_eq!(bridge.fast_path_count(), 1);
    let promoted = sink
        .0
        .lock()
        .unwrap()
        .take()
        .expect("conn handed to the sink");

    // Alive: the inline-owned entry stays.
    assert!(bridge.poll_fast_path().is_empty());
    assert_eq!(bridge.fast_path_count(), 1);

    // Sink owner marks the flow dead (it already emitted the FIN/RST).
    promoted
        .dead
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(bridge.poll_fast_path().is_empty());
    assert_eq!(
        bridge.fast_path_count(),
        0,
        "dead inline flow must be reaped"
    );
}

/// A handshake abort (TTL expiry) must RST the guest so its socket dies
/// immediately instead of retrying SYNs against a flow the bridge already
/// gave up on (ABX-431).
#[tokio::test]
async fn handshake_ttl_abort_emits_rst() {
    let mut bridge = TcpBridge::new(GW_IP);
    // TEST-NET-3 destination: the spawned connect never resolves quickly,
    // and the entry is expired manually below.
    let syn = make_guest_syn_frame(40000, Ipv4Addr::new(203, 0, 113, 1), 443, 7777, &[]);
    assert!(
        bridge
            .handle_outbound_syn(&syn, GW_MAC, GUEST_MAC)
            .is_none()
    );
    assert_eq!(bridge.handshake_count(), 1);

    for conn in bridge.handshake_conns.values_mut() {
        conn.created = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(30))
            .unwrap();
    }

    let out = bridge.poll_handshakes();
    assert_eq!(
        bridge.handshake_count(),
        0,
        "expired handshake must be evicted"
    );
    let rst = out
        .iter()
        .find(|f| f[ETH_HEADER_LEN + 20 + 13] & 0x04 != 0)
        .expect("TTL abort must emit a RST toward the guest");
    // ACKing the guest ISN + 1 keeps the RST acceptable in SYN-SENT.
    let ack = u32::from_be_bytes([
        rst[ETH_HEADER_LEN + 20 + 8],
        rst[ETH_HEADER_LEN + 20 + 9],
        rst[ETH_HEADER_LEN + 20 + 10],
        rst[ETH_HEADER_LEN + 20 + 11],
    ]);
    assert_eq!(ack, 7778);
}

// -------- Upload in-order ACK discipline / download window tests --------
// Regression net for the 2026-07-19 findings: uploads ACKed across
// WouldBlock holes and short writes (silent data loss), downloads overran
// the guest's receive window with no retransmission to repair the gap.

/// Builds a guest TCP segment with explicit flags, window, and payload.
/// `flow` is the guest-side (src_port, dst_ip, dst_port) tuple.
fn make_guest_segment(
    flow: (u16, Ipv4Addr, u16),
    seq: u32,
    ack: u32,
    window: u16,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let (src_port, dst_ip, dst_port) = flow;
    let ip_total = 40 + payload.len();
    let mut frame = vec![0u8; ETH_HEADER_LEN + ip_total];
    frame[0..6].copy_from_slice(&GW_MAC);
    frame[6..12].copy_from_slice(&GUEST_MAC);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip = 14;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&(ip_total as u16).to_be_bytes());
    frame[ip + 8] = 64;
    frame[ip + 9] = 6;
    frame[ip + 12..ip + 16].copy_from_slice(&GUEST_IP.octets());
    frame[ip + 16..ip + 20].copy_from_slice(&dst_ip.octets());
    let tcp = 34;
    frame[tcp..tcp + 2].copy_from_slice(&src_port.to_be_bytes());
    frame[tcp + 2..tcp + 4].copy_from_slice(&dst_port.to_be_bytes());
    frame[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
    frame[tcp + 8..tcp + 12].copy_from_slice(&ack.to_be_bytes());
    frame[tcp + 12] = 0x50;
    frame[tcp + 13] = flags;
    frame[tcp + 14..tcp + 16].copy_from_slice(&window.to_be_bytes());
    frame[tcp + 20..].copy_from_slice(payload);
    frame
}

fn tcp_flags_of(frame: &[u8]) -> u8 {
    frame[ETH_HEADER_LEN + 20 + 13]
}

fn tcp_ack_of(frame: &[u8]) -> u32 {
    let tcp = ETH_HEADER_LEN + 20;
    u32::from_be_bytes([
        frame[tcp + 8],
        frame[tcp + 9],
        frame[tcp + 10],
        frame[tcp + 11],
    ])
}

/// A segment arriving beyond the contiguous cursor (a hole precedes it)
/// must not be written to the host socket and must not advance the ACK —
/// the reply is a dup-ACK at the cursor. Filling the hole in order then
/// delivers everything, bytes in the right order.
#[tokio::test]
async fn upload_hole_is_never_acked_or_written() {
    use std::io::Read;

    let mut bridge = TcpBridge::new(GW_IP);
    bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::net::TcpStream::connect(addr);
    let (client, accepted) = tokio::join!(connect, listener.accept());
    let client = client.unwrap();
    let (accepted, _) = accepted.unwrap();

    let dst_ip = Ipv4Addr::new(198, 18, 30, 96);
    let key = SynFlowKey {
        src_ip: GUEST_IP,
        src_port: 40021,
        dst_ip,
        dst_port: 443,
    };
    bridge.promote_to_fast_path(key, client.into_std().unwrap(), 1000, 2000, 1460, None);

    // Out-of-order segment: 2000..2100 is missing.
    let ooo = make_guest_segment((40021, dst_ip, 443), 2100, 1000, 65535, 0x18, &[0xBB; 50]);
    let reply = bridge.try_fast_path_intercept(&ooo).expect("intercepted");
    assert_eq!(
        tcp_ack_of(&reply),
        2000,
        "hole ahead of the segment: reply must be a dup-ACK at the cursor"
    );

    // Fill the hole in order, then retransmit the tail.
    let fill = make_guest_segment((40021, dst_ip, 443), 2000, 1000, 65535, 0x18, &[0xAA; 100]);
    let reply = bridge.try_fast_path_intercept(&fill).expect("intercepted");
    assert_eq!(tcp_ack_of(&reply), 2100);
    let tail = make_guest_segment((40021, dst_ip, 443), 2100, 1000, 65535, 0x18, &[0xBB; 50]);
    let reply = bridge.try_fast_path_intercept(&tail).expect("intercepted");
    assert_eq!(tcp_ack_of(&reply), 2150);

    // The host socket saw the contiguous stream in order — no 0xBB bytes
    // written ahead of the hole.
    let mut server = accepted.into_std().unwrap();
    server.set_nonblocking(false).unwrap();
    server
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    let mut got = [0u8; 150];
    server.read_exact(&mut got).unwrap();
    assert!(got[..100].iter().all(|&b| b == 0xAA));
    assert!(got[100..].iter().all(|&b| b == 0xBB));
}

/// A FIN whose sequence position lies beyond the cursor (its stream still
/// has a gap) must not tear the flow down — teardown would cut off the
/// retransmissions that repair the gap (the silent-truncation bug). Once
/// the gap is filled, the retransmitted FIN completes the close.
#[tokio::test]
async fn upload_fin_with_gap_defers_teardown() {
    let mut bridge = TcpBridge::new(GW_IP);
    bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::net::TcpStream::connect(addr);
    let (client, accepted) = tokio::join!(connect, listener.accept());
    let client = client.unwrap();
    let (_accepted, _) = accepted.unwrap();

    let dst_ip = Ipv4Addr::new(198, 18, 30, 97);
    let key = SynFlowKey {
        src_ip: GUEST_IP,
        src_port: 40022,
        dst_ip,
        dst_port: 443,
    };
    bridge.promote_to_fast_path(key, client.into_std().unwrap(), 1000, 2000, 1460, None);

    // FIN at 2100 while the cursor is still 2000: 100 bytes are missing.
    let early_fin = make_guest_segment((40022, dst_ip, 443), 2100, 1000, 65535, 0x11, &[]);
    let reply = bridge
        .try_fast_path_intercept(&early_fin)
        .expect("intercepted");
    assert_eq!(
        tcp_flags_of(&reply) & 0x01,
        0,
        "deferred FIN must be answered with a plain dup-ACK, not FIN-ACK"
    );
    assert_eq!(tcp_ack_of(&reply), 2000);
    assert_eq!(
        bridge.fast_path_count(),
        1,
        "flow must survive a FIN that precedes its missing data"
    );

    // Gap filled, FIN retransmitted → normal close.
    let fill = make_guest_segment((40022, dst_ip, 443), 2000, 1000, 65535, 0x18, &[0xAA; 100]);
    let reply = bridge.try_fast_path_intercept(&fill).expect("intercepted");
    assert_eq!(tcp_ack_of(&reply), 2100);
    let fin = make_guest_segment((40022, dst_ip, 443), 2100, 1000, 65535, 0x11, &[]);
    let reply = bridge.try_fast_path_intercept(&fin).expect("intercepted");
    assert_ne!(tcp_flags_of(&reply) & 0x01, 0, "in-order FIN gets FIN-ACK");
    assert_eq!(tcp_ack_of(&reply), 2101, "FIN consumes one sequence number");
    assert_eq!(bridge.fast_path_count(), 0);
}

/// Property: the ACK returned for a data segment never covers bytes the
/// host socket did not take. Driven by writing far more than a shrunken
/// send buffer accepts, then retransmitting from the ACK cursor until the
/// whole payload lands — every byte must reach the server exactly once.
#[tokio::test]
async fn upload_ack_never_exceeds_host_writable() {
    use std::io::Read;

    let mut bridge = TcpBridge::new(GW_IP);
    bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::net::TcpStream::connect(addr);
    let (client, accepted) = tokio::join!(connect, listener.accept());
    let std_client = client.unwrap().into_std().unwrap();
    // Shrink both socket buffers so segments outrun what the kernel will
    // take and the write path must report partial/zero takes.
    socket2::SockRef::from(&std_client)
        .set_send_buffer_size(4096)
        .unwrap();
    let (accepted, _) = accepted.unwrap();
    socket2::SockRef::from(&accepted)
        .set_recv_buffer_size(4096)
        .unwrap();

    let dst_ip = Ipv4Addr::new(198, 18, 30, 98);
    let key = SynFlowKey {
        src_ip: GUEST_IP,
        src_port: 40023,
        dst_ip,
        dst_port: 443,
    };
    bridge.promote_to_fast_path(key, std_client, 1000, 2000, 1460, None);

    let mut server = accepted.into_std().unwrap();
    server.set_nonblocking(false).unwrap();
    server
        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .unwrap();

    // Segments stay MTU-plausible (an IP packet's total length is u16);
    // the volume, not the segment size, is what outruns the buffers.
    const SEGMENT: usize = 8 * 1024;
    let payload = vec![0xCC; 256 * 1024];
    let base: u32 = 2000;
    let mut cursor: u32 = base;
    let mut server_received = 0usize;
    let mut short_takes = 0usize;
    let mut read_buf = vec![0u8; 64 * 1024];

    for _ in 0..2000 {
        let offset = cursor.wrapping_sub(base) as usize;
        if offset >= payload.len() {
            break;
        }
        let chunk = &payload[offset..(offset + SEGMENT).min(payload.len())];
        let segment = make_guest_segment((40023, dst_ip, 443), cursor, 1000, 65535, 0x18, chunk);
        let reply = bridge
            .try_fast_path_intercept(&segment)
            .expect("intercepted");
        let acked = tcp_ack_of(&reply);
        let advance = acked.wrapping_sub(cursor) as usize;
        assert!(advance <= chunk.len(), "ACK beyond the offered bytes");
        if advance < chunk.len() {
            short_takes += 1;
        }
        cursor = acked;

        // Drain whatever reached the server; every ACKed byte must
        // eventually be readable.
        while server_received < cursor.wrapping_sub(base) as usize {
            match server.read(&mut read_buf) {
                Ok(0) => panic!("server EOF mid-transfer"),
                Ok(n) => {
                    assert!(read_buf[..n].iter().all(|&b| b == 0xCC));
                    server_received += n;
                }
                Err(e) => panic!("ACKed bytes never reached the server: {e}"),
            }
        }
    }

    assert_eq!(
        cursor.wrapping_sub(base) as usize,
        payload.len(),
        "retransmit-from-cursor must eventually deliver the whole payload"
    );
    assert_eq!(server_received, payload.len());
    assert!(
        short_takes > 0,
        "test must actually exercise the partial-take path (send buffer 4 KiB, payload 64 KiB)"
    );
}

/// The download side must never send beyond the guest's advertised receive
/// window: with no ACKs after promotion at most one unscaled window goes
/// out; a window-opening ACK releases the next tranche.
#[tokio::test]
async fn poll_fast_path_respects_guest_window() {
    use tokio::io::AsyncWriteExt;

    let mut bridge = TcpBridge::new(GW_IP);
    bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::net::TcpStream::connect(addr);
    let (client, accepted) = tokio::join!(connect, listener.accept());
    let client = client.unwrap();
    let (mut accepted, _) = accepted.unwrap();

    let dst_ip = Ipv4Addr::new(198, 18, 30, 99);
    let key = SynFlowKey {
        src_ip: GUEST_IP,
        src_port: 40024,
        dst_ip,
        dst_port: 443,
    };
    bridge.promote_to_fast_path(key, client.into_std().unwrap(), 1, 1, 1460, None);

    accepted.write_all(&vec![0xDD; 100_000]).await.unwrap();

    async fn drain(bridge: &mut TcpBridge) -> usize {
        let mut sent = 0usize;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut idle = 0;
        while std::time::Instant::now() < deadline && idle < 10 {
            let batch = bridge.poll_fast_path();
            if batch.is_empty() {
                idle += 1;
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            } else {
                idle = 0;
                sent += batch
                    .iter()
                    .map(|f| f.len().saturating_sub(ETH_HEADER_LEN + 40))
                    .sum::<usize>();
            }
        }
        sent
    }

    let first = drain(&mut bridge).await;
    assert!(
        first <= 65535,
        "no guest ACK yet: at most one unscaled window may be sent, got {first}"
    );
    assert!(
        first >= 65535 - 1460,
        "the initial window should be filled, got {first}"
    );

    // Guest ACKs everything and re-opens a 65535 window.
    let ack = make_guest_segment((40024, dst_ip, 443), 1, 1 + first as u32, 65535, 0x10, &[]);
    bridge.try_fast_path_intercept(&ack).expect("intercepted");

    let second = drain(&mut bridge).await;
    assert!(second > 0, "an opening ACK must release more data");
    assert!(
        second <= 65535,
        "second tranche must respect the re-advertised window, got {second}"
    );
}

/// In-flight download bytes that never get ACKed must be retransmitted
/// after the RTO — the path beyond guest eth0 drops under burst, and
/// without sender-side retransmission one dropped frame wedges the flow.
#[tokio::test]
async fn poll_retransmits_unacked_data_after_rto() {
    use tokio::io::AsyncWriteExt;

    let mut bridge = TcpBridge::new(GW_IP);
    bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::net::TcpStream::connect(addr);
    let (client, accepted) = tokio::join!(connect, listener.accept());
    let client = client.unwrap();
    let (mut accepted, _) = accepted.unwrap();

    let dst_ip = Ipv4Addr::new(198, 18, 30, 100);
    let key = SynFlowKey {
        src_ip: GUEST_IP,
        src_port: 40025,
        dst_ip,
        dst_port: 443,
    };
    bridge.promote_to_fast_path(key, client.into_std().unwrap(), 1, 1, 1460, None);

    accepted.write_all(&[0xEE; 4096]).await.unwrap();

    // First transmission (pretend every frame is lost — we just drop them).
    let mut sent = 0usize;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while sent < 4096 && std::time::Instant::now() < deadline {
        sent += bridge
            .poll_fast_path()
            .iter()
            .map(|f| f.len().saturating_sub(ETH_HEADER_LEN + 40))
            .sum::<usize>();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(sent, 4096, "initial transmission");

    // No guest ACK ever arrives. After the RTO the same sequence space
    // must be re-emitted, starting at the un-ACKed cursor (seq=1).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut retransmitted = Vec::new();
    while retransmitted.is_empty() && std::time::Instant::now() < deadline {
        retransmitted = bridge.poll_fast_path();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        !retransmitted.is_empty(),
        "RTO must re-emit un-ACKed data with no guest ACKs at all"
    );
    let tcp = ETH_HEADER_LEN + 20;
    let first_seq = u32::from_be_bytes([
        retransmitted[0][tcp + 4],
        retransmitted[0][tcp + 5],
        retransmitted[0][tcp + 6],
        retransmitted[0][tcp + 7],
    ]);
    assert_eq!(first_seq, 1, "retransmission restarts at the ack cursor");
}

/// Three duplicate ACKs (same ack, same window, no payload, data in
/// flight) must trigger an immediate fast retransmit from the ack point.
#[tokio::test]
async fn triple_dup_ack_triggers_fast_retransmit() {
    use tokio::io::AsyncWriteExt;

    let mut bridge = TcpBridge::new(GW_IP);
    bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::net::TcpStream::connect(addr);
    let (client, accepted) = tokio::join!(connect, listener.accept());
    let client = client.unwrap();
    let (mut accepted, _) = accepted.unwrap();

    let dst_ip = Ipv4Addr::new(198, 18, 30, 101);
    let key = SynFlowKey {
        src_ip: GUEST_IP,
        src_port: 40026,
        dst_ip,
        dst_port: 443,
    };
    bridge.promote_to_fast_path(key, client.into_std().unwrap(), 1, 1, 1460, None);

    accepted.write_all(&[0xEF; 2920]).await.unwrap();
    let mut sent = 0usize;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while sent < 2920 && std::time::Instant::now() < deadline {
        sent += bridge
            .poll_fast_path()
            .iter()
            .map(|f| f.len().saturating_sub(ETH_HEADER_LEN + 40))
            .sum::<usize>();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(sent, 2920, "initial transmission");

    // Guest signals a gap: three dup-ACKs at the initial cursor with the
    // (unchanged) initial window.
    for _ in 0..3 {
        let dup = make_guest_segment((40026, dst_ip, 443), 1, 1, 65535, 0x10, &[]);
        bridge.try_fast_path_intercept(&dup).expect("intercepted");
    }
    let retransmitted = bridge.poll_fast_path();
    assert!(
        !retransmitted.is_empty(),
        "three dup-ACKs must fast-retransmit without waiting for the RTO"
    );
    let tcp = ETH_HEADER_LEN + 20;
    let first_seq = u32::from_be_bytes([
        retransmitted[0][tcp + 4],
        retransmitted[0][tcp + 5],
        retransmitted[0][tcp + 6],
        retransmitted[0][tcp + 7],
    ]);
    assert_eq!(first_seq, 1, "fast retransmit restarts at the ack cursor");
}
