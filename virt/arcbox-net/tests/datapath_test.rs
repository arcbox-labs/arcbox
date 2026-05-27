//! Network datapath integration tests using mock guest NIC.
//!
//! These tests exercise the full `NetworkDatapath` event loop by creating a
//! socketpair mock in place of the real VZ framework guest FD. L2 Ethernet
//! frames are injected through the "guest" end and responses are read back,
//! verifying DHCP, DNS, frame classification, and TCP SYN gating without
//! requiring a VM, root privileges, or code signing.

#![cfg(target_os = "macos")]

mod helpers;

use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use arcbox_dhcp::DhcpConfig;
use arcbox_net::darwin::datapath_loop::NetworkDatapath;
use arcbox_net::darwin::socket_proxy::SocketProxy;
use arcbox_net::dns::{DnsConfig, DnsForwarder};

use helpers::frames::{
    build_arp_request, build_dhcp_discover, build_dhcp_request, build_icmp_echo, build_tcp_syn,
    extract_dhcp_payload, parse_dhcp,
};
use helpers::mock_nic::{fd_write, mock_guest_nic, recv_frames_timeout, set_nonblocking};

/// Test network configuration constants.
const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 64, 1);
const GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 64, 2);
const GATEWAY_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const CLIENT_MAC: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

/// Creates a `NetworkDatapath` wired to a mock socketpair.
///
/// Returns `(datapath, guest_fd, cancel_token)` where `guest_fd` is the
/// test-side end of the socketpair for injecting/reading L2 frames.
fn create_test_datapath() -> (NetworkDatapath, std::os::fd::OwnedFd, CancellationToken) {
    let (host_fd, guest_fd) = mock_guest_nic();
    set_nonblocking(guest_fd.as_raw_fd());

    let cancel = CancellationToken::new();

    let (reply_tx, reply_rx) = mpsc::channel(256);
    let (_cmd_tx, cmd_rx) = mpsc::channel(64);

    let socket_proxy =
        SocketProxy::new(GATEWAY_IP, GATEWAY_MAC, GUEST_IP, reply_tx, cancel.clone());

    let dhcp_config = DhcpConfig::new(GATEWAY_IP, Ipv4Addr::new(255, 255, 255, 0));
    let dhcp_server = arcbox_dhcp::DhcpServer::new(dhcp_config);

    let dns_config = DnsConfig::new(GATEWAY_IP);
    let dns_forwarder = DnsForwarder::new(dns_config);

    let datapath = NetworkDatapath::new(
        host_fd,
        socket_proxy,
        reply_rx,
        cmd_rx,
        dhcp_server,
        dns_forwarder,
        GATEWAY_IP,
        GUEST_IP,
        GATEWAY_MAC,
        cancel.clone(),
        1500, // mtu
    );

    (datapath, guest_fd, cancel)
}

/// Spawns the datapath event loop as a background tokio task and returns
/// the join handle. The caller should cancel via the `CancellationToken`
/// when the test is done.
fn spawn_datapath(datapath: NetworkDatapath) -> tokio::task::JoinHandle<std::io::Result<()>> {
    tokio::spawn(async move { datapath.run().await })
}

// ---------------------------------------------------------------------------
// DHCP tests
// ---------------------------------------------------------------------------

/// Full DHCP cycle: DISCOVER -> OFFER -> REQUEST -> ACK.
///
/// Verifies that the datapath's integrated DHCP server responds correctly
/// to a complete lease acquisition sequence.
#[tokio::test]
async fn test_dhcp_full_cycle() {
    let (datapath, guest_fd, cancel) = create_test_datapath();
    let handle = spawn_datapath(datapath);
    let guest_raw = guest_fd.as_raw_fd();

    // Allow the datapath event loop to start.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let xid: u32 = 0xDEAD_BEEF;

    // --- Step 1: Send DHCP DISCOVER ---
    let discover = build_dhcp_discover(CLIENT_MAC, xid);
    fd_write(guest_raw, &discover).expect("failed to write DISCOVER");

    // --- Step 2: Read DHCP OFFER ---
    let frames = recv_frames_timeout(guest_raw, Duration::from_secs(2)).await;
    assert!(!frames.is_empty(), "expected DHCP OFFER, got no frames");

    // Find the DHCP response among returned frames.
    let offer_frame = frames
        .iter()
        .find(|f| {
            extract_dhcp_payload(f)
                .and_then(parse_dhcp)
                .is_some_and(|p| p.message_type == Some(2)) // OFFER
        })
        .expect("no DHCP OFFER frame found");

    let offer = parse_dhcp(extract_dhcp_payload(offer_frame).unwrap()).unwrap();
    assert_eq!(offer.op, 2, "OFFER op should be BOOTREPLY");
    assert_eq!(offer.xid, xid, "OFFER xid should match");
    assert_eq!(offer.message_type, Some(2), "should be OFFER (type 2)");
    assert!(
        !offer.yiaddr.is_unspecified(),
        "OFFER should assign an IP address"
    );
    let offered_ip = offer.yiaddr;

    // Verify the offered IP is in the expected subnet.
    let offered_octets = offered_ip.octets();
    assert_eq!(
        &offered_octets[..3],
        &[192, 168, 64],
        "offered IP should be in 192.168.64.0/24"
    );

    // --- Step 3: Send DHCP REQUEST for the offered IP ---
    let request = build_dhcp_request(CLIENT_MAC, xid, offered_ip, GATEWAY_IP);
    fd_write(guest_raw, &request).expect("failed to write REQUEST");

    // --- Step 4: Read DHCP ACK ---
    let frames = recv_frames_timeout(guest_raw, Duration::from_secs(2)).await;
    assert!(!frames.is_empty(), "expected DHCP ACK, got no frames");

    let ack_frame = frames
        .iter()
        .find(|f| {
            extract_dhcp_payload(f)
                .and_then(parse_dhcp)
                .is_some_and(|p| p.message_type == Some(5)) // ACK
        })
        .expect("no DHCP ACK frame found");

    let ack = parse_dhcp(extract_dhcp_payload(ack_frame).unwrap()).unwrap();
    assert_eq!(ack.op, 2, "ACK op should be BOOTREPLY");
    assert_eq!(ack.xid, xid, "ACK xid should match");
    assert_eq!(ack.message_type, Some(5), "should be ACK (type 5)");
    assert_eq!(ack.yiaddr, offered_ip, "ACK should confirm the offered IP");

    // Verify lease parameters are present.
    assert!(ack.lease_time.is_some(), "ACK should include lease time");
    assert!(ack.subnet_mask.is_some(), "ACK should include subnet mask");

    // Cleanup: cancel the datapath and wait for it to finish.
    cancel.cancel();
    handle.await.unwrap().unwrap();
}

// ---------------------------------------------------------------------------
// Frame classification tests (via FrameClassifier directly)
// ---------------------------------------------------------------------------

/// Verifies that an ARP request injected through the socketpair is handled
/// inline by the classifier: an ARP reply is generated, the guest MAC is
/// learned, and the frame is not queued for the slow intercept path.
#[tokio::test]
async fn test_frame_classification_arp() {
    use arcbox_net::darwin::classifier::FrameClassifier;

    let (host_fd, guest_fd) = mock_guest_nic();
    set_nonblocking(host_fd.as_raw_fd());

    let mut device = FrameClassifier::new(host_fd.as_raw_fd(), GATEWAY_IP, 1500);
    // Inline ARP responder needs the gateway MAC to synthesize a reply;
    // without it the request is silently dropped.
    device.set_gateway_mac(GATEWAY_MAC);
    let mut guest_mac = None;

    // Write an ARP request from the guest side.
    let arp = build_arp_request(CLIENT_MAC, GUEST_IP, GATEWAY_IP);
    fd_write(guest_fd.as_raw_fd(), &arp).expect("write ARP");

    device.drain_guest_fd(&mut guest_mac);

    // ARP is handled inline — not queued as an intercepted frame.
    let intercepted = device.take_intercepted();
    assert!(intercepted.is_empty(), "ARP should not be intercepted");
    assert_eq!(
        guest_mac,
        Some(CLIENT_MAC),
        "guest MAC should be learned from ARP"
    );

    // An ARP reply should have been generated for the gateway.
    let replies = device.take_arp_replies();
    assert_eq!(replies.len(), 1, "expected exactly one ARP reply");
    let reply = &replies[0];
    assert!(
        reply.len() >= 42,
        "ARP reply must be at least 42 bytes (Ethernet + ARP header), got {}",
        reply.len()
    );
    // Ethernet dst: requester's MAC.
    assert_eq!(
        &reply[0..6],
        &CLIENT_MAC,
        "reply dst MAC should be the requester"
    );
    // Ethernet src: gateway's MAC.
    assert_eq!(
        &reply[6..12],
        &GATEWAY_MAC,
        "reply src MAC should be the gateway"
    );
    // EtherType: 0x0806 (ARP).
    assert_eq!(
        &reply[12..14],
        &[0x08, 0x06],
        "reply EtherType should be 0x0806"
    );
    // ARP opcode at offset 20..22: 2 (reply).
    assert_eq!(
        &reply[20..22],
        &[0x00, 0x02],
        "ARP opcode should be 2 (reply)"
    );
}

/// Verifies that a TCP SYN injected through the socketpair is gated
/// (held back for host connect).
#[tokio::test]
async fn test_frame_classification_tcp_syn() {
    use arcbox_net::darwin::classifier::FrameClassifier;

    let (host_fd, guest_fd) = mock_guest_nic();
    set_nonblocking(host_fd.as_raw_fd());

    let mut device = FrameClassifier::new(host_fd.as_raw_fd(), GATEWAY_IP, 1500);
    let mut guest_mac = None;

    let syn = build_tcp_syn(
        CLIENT_MAC,
        GATEWAY_MAC,
        GUEST_IP,
        12345,
        Ipv4Addr::new(1, 1, 1, 1),
        443,
    );
    fd_write(guest_fd.as_raw_fd(), &syn).expect("write SYN");

    device.drain_guest_fd(&mut guest_mac);

    let gated = device.take_gated_syns();
    assert_eq!(gated.len(), 1, "TCP SYN should be gated");
    assert_eq!(gated[0].dst_port, 443);
    assert_eq!(gated[0].src_port, 12345);
    assert_eq!(gated[0].dst_ip, Ipv4Addr::new(1, 1, 1, 1));
}

/// Verifies that ICMP frames are classified as intercepted.
#[tokio::test]
async fn test_frame_classification_icmp() {
    use arcbox_net::darwin::classifier::{FrameClassifier, InterceptedKind};

    let (host_fd, guest_fd) = mock_guest_nic();
    set_nonblocking(host_fd.as_raw_fd());

    let mut device = FrameClassifier::new(host_fd.as_raw_fd(), GATEWAY_IP, 1500);
    let mut guest_mac = None;

    let icmp = build_icmp_echo(
        CLIENT_MAC,
        GATEWAY_MAC,
        GUEST_IP,
        Ipv4Addr::new(8, 8, 8, 8),
        1,
        1,
    );
    fd_write(guest_fd.as_raw_fd(), &icmp).expect("write ICMP");

    device.drain_guest_fd(&mut guest_mac);

    let intercepted = device.take_intercepted();
    assert_eq!(intercepted.len(), 1);
    assert_eq!(intercepted[0].kind, InterceptedKind::Icmp);
}

/// Verifies that a DHCP (UDP dst port 67) frame is classified as intercepted
/// with kind `Dhcp`.
#[tokio::test]
async fn test_frame_classification_dhcp() {
    use arcbox_net::darwin::classifier::{FrameClassifier, InterceptedKind};

    let (host_fd, guest_fd) = mock_guest_nic();
    set_nonblocking(host_fd.as_raw_fd());

    let mut device = FrameClassifier::new(host_fd.as_raw_fd(), GATEWAY_IP, 1500);
    let mut guest_mac = None;

    let discover = build_dhcp_discover(CLIENT_MAC, 0x1234);
    fd_write(guest_fd.as_raw_fd(), &discover).expect("write DHCP DISCOVER");

    device.drain_guest_fd(&mut guest_mac);

    let intercepted = device.take_intercepted();
    assert_eq!(intercepted.len(), 1);
    assert_eq!(intercepted[0].kind, InterceptedKind::Dhcp);
}
