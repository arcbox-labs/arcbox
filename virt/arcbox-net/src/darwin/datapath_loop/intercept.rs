use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::RawFd;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::darwin::classifier::InterceptedKind;
use crate::darwin::egress::HostEgress;
use crate::darwin::inbound_relay::InboundCommand;
use crate::darwin::tcp_bridge::TcpBridge;
use crate::dhcp::DhcpServer;
use crate::dns::DnsForwarder;
use crate::ethernet::{ETH_HEADER_LEN, build_udp_ip_ethernet};

use super::guest_tx::{DeliveryClass, GuestTx};

/// Dispatches an intercepted frame to the appropriate handler.
#[allow(clippy::too_many_arguments)]
pub(super) fn handle_intercepted_frame(
    intercepted: &crate::darwin::classifier::InterceptedFrame,
    guest_tx: &mut GuestTx,
    guest_fd: RawFd,
    egress: &mut HostEgress,
    dhcp_server: &mut DhcpServer,
    dns_forwarder: &DnsForwarder,
    dns_reply_tx: &mpsc::Sender<Vec<u8>>,
    dns_log: &crate::darwin::dns_log::DnsResolutionLog,
    cancel: &CancellationToken,
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
    mtu: usize,
) {
    let frame = &intercepted.frame;
    match intercepted.kind {
        InterceptedKind::Dhcp => {
            handle_dhcp(
                frame,
                guest_tx,
                guest_fd,
                dhcp_server,
                gateway_ip,
                gateway_mac,
                guest_mac,
                mtu,
            );
        }
        InterceptedKind::Dns => {
            handle_dns(
                frame,
                dns_forwarder,
                dns_reply_tx,
                dns_log,
                cancel,
                gateway_ip,
                gateway_mac,
                guest_mac,
                mtu,
            );
        }
        InterceptedKind::Udp | InterceptedKind::Icmp => {
            egress.handle_outbound(frame, guest_mac);
        }
    }
}

/// Processes one inbound command from `InboundListenerManager`.
///
/// TCP accepted streams are registered with the handshake synthesizer; UDP
/// datagrams are routed through the socket proxy inbound path.
pub(super) fn process_inbound_cmd(
    cmd: InboundCommand,
    tcp_bridge: &mut TcpBridge,
    egress: &mut HostEgress,
    guest_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
    guest_mac: Option<[u8; 6]>,
) {
    match cmd {
        InboundCommand::TcpAccepted {
            host_port, stream, ..
        } => {
            tracing::debug!(
                "Inbound TCP accepted: guest_port={} peer={:?}",
                host_port,
                stream.peer_addr().ok(),
            );
            tcp_bridge.initiate_inbound(host_port, stream, guest_ip, gateway_ip);
        }
        cmd @ InboundCommand::UdpReceived { .. } => {
            let mac = guest_mac.unwrap_or([0xFF; 6]);
            egress.handle_inbound_command(cmd, mac);
        }
    }
}

/// Handles a DHCP packet from the guest.
#[allow(clippy::too_many_arguments)] // all parameters are required context for DHCP frame handling
fn handle_dhcp(
    frame: &[u8],
    guest_tx: &mut GuestTx,
    guest_fd: RawFd,
    dhcp_server: &mut DhcpServer,
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
    mtu: usize,
) {
    let ip_start = ETH_HEADER_LEN;
    let ihl = ((frame[ip_start] & 0x0F) as usize) * 4;
    let l4_start = ip_start + ihl;
    let dhcp_start = l4_start + 8;
    if dhcp_start >= frame.len() {
        return;
    }

    let dhcp_data = &frame[dhcp_start..];
    tracing::info!("DHCP packet from guest ({} bytes)", dhcp_data.len());

    match dhcp_server.handle_packet(dhcp_data) {
        Ok(Some(response)) => {
            let reply_frames = build_udp_ip_ethernet(
                gateway_ip,
                Ipv4Addr::BROADCAST,
                67,
                68,
                &response,
                gateway_mac,
                guest_mac,
                mtu,
            );
            for reply_frame in reply_frames {
                tracing::info!("Sending DHCP reply frame: {} bytes", reply_frame.len());
                guest_tx.send(guest_fd, &reply_frame, DeliveryClass::Lossy);
            }
        }
        Ok(None) => {
            tracing::info!("DHCP: no response needed");
        }
        Err(e) => tracing::warn!("DHCP handling error: {}", e),
    }
}

/// Handles a DNS query from the guest.
///
/// Local host mappings are resolved synchronously (no I/O). All other
/// queries are forwarded to upstream servers asynchronously via a spawned
/// tokio task, keeping the datapath event loop unblocked.
///
/// When an upstream response is received, A record IPs are recorded in
/// the [`DnsResolutionLog`] so that [`TcpBridge`] can map destination IPs
/// back to domain names for proxy-aware connections.
#[allow(clippy::too_many_arguments)] // all parameters are required context for DNS frame handling
fn handle_dns(
    frame: &[u8],
    dns_forwarder: &DnsForwarder,
    dns_reply_tx: &mpsc::Sender<Vec<u8>>,
    dns_log: &crate::darwin::dns_log::DnsResolutionLog,
    cancel: &CancellationToken,
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
    mtu: usize,
) {
    let ip_start = ETH_HEADER_LEN;
    let ihl = ((frame[ip_start] & 0x0F) as usize) * 4;
    let l4_start = ip_start + ihl;
    let dns_start = l4_start + 8;
    if dns_start >= frame.len() {
        return;
    }

    let src_ip = Ipv4Addr::new(
        frame[ip_start + 12],
        frame[ip_start + 13],
        frame[ip_start + 14],
        frame[ip_start + 15],
    );
    let src_port = u16::from_be_bytes([frame[l4_start], frame[l4_start + 1]]);
    let dns_data = &frame[dns_start..];

    // Fast path: resolve from local host mappings (no I/O).
    if let Some(response) = dns_forwarder.try_resolve_locally(dns_data) {
        let reply_frames = build_udp_ip_ethernet(
            gateway_ip,
            src_ip,
            53,
            src_port,
            &response,
            gateway_mac,
            guest_mac,
            mtu,
        );
        let tx = dns_reply_tx.clone();
        tokio::spawn(async move {
            for reply_frame in reply_frames {
                if tx.send(reply_frame).await.is_err() {
                    tracing::debug!("DNS reply channel closed");
                    return;
                }
            }
        });
        tracing::debug!("Queued local DNS response to guest");
        return;
    }

    // Slow path: forward to upstream asynchronously.
    let upstream = dns_forwarder.upstream().to_vec();
    let data = dns_data.to_vec();
    let tx = dns_reply_tx.clone();
    let log = dns_log.clone();
    let cancel = cancel.clone();

    tokio::spawn(async move {
        // Cancel promptly on shutdown instead of waiting for upstream
        // DNS timeouts (up to 2 s × number of upstream servers).
        let result = tokio::select! {
            r = forward_dns_async(&data, &upstream) => r,
            () = cancel.cancelled() => return,
        };
        match result {
            Ok(response) => {
                // Record IP → domain mapping for proxy-aware TCP connections.
                if let Some((domain, ips)) =
                    crate::darwin::dns_log::parse_dns_response_a_records(&response)
                {
                    tracing::debug!(
                        domain = %domain,
                        ips = ?ips,
                        "DNS resolution logged"
                    );
                    log.record(&domain, &ips);
                }

                let reply_frames = build_udp_ip_ethernet(
                    gateway_ip,
                    src_ip,
                    53,
                    src_port,
                    &response,
                    gateway_mac,
                    guest_mac,
                    mtu,
                );
                for reply_frame in reply_frames {
                    if tx.send(reply_frame).await.is_err() {
                        tracing::debug!("DNS reply channel closed");
                        return;
                    }
                }
                tracing::debug!("Sent forwarded DNS response to guest");
            }
            Err(e) => {
                tracing::warn!("DNS forwarding failed: {e}");
                if let Some(servfail) = build_dns_servfail_response(&data) {
                    let reply_frames = build_udp_ip_ethernet(
                        gateway_ip,
                        src_ip,
                        53,
                        src_port,
                        &servfail,
                        gateway_mac,
                        guest_mac,
                        mtu,
                    );
                    for reply_frame in reply_frames {
                        if tx.send(reply_frame).await.is_err() {
                            tracing::debug!("DNS reply channel closed");
                            return;
                        }
                    }
                }
            }
        }
    });
}

/// Forwards a raw DNS query to upstream servers using async I/O.
async fn forward_dns_async(data: &[u8], upstream: &[SocketAddr]) -> Result<Vec<u8>, String> {
    if data.len() < 2 {
        return Err("query too short".to_string());
    }
    let query_id = [data[0], data[1]];

    for addr in upstream {
        // A connected socket makes the kernel drop datagrams from anyone but
        // this upstream — a 16-bit txid alone is guessable by an off-path
        // attacker flooding the ephemeral port, so the source filter matters.
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("bind failed: {e}"))?;
        if socket.connect(addr).await.is_err() || socket.send(data).await.is_err() {
            continue;
        }

        let mut buf = [0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buf)).await {
            Ok(Ok(len)) if len >= 2 && buf[0] == query_id[0] && buf[1] == query_id[1] => {
                return Ok(buf[..len].to_vec());
            }
            _ => {}
        }
    }

    Err("all upstream DNS servers failed".to_string())
}

/// Builds a minimal DNS SERVFAIL response from the raw query.
pub(super) fn build_dns_servfail_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }

    // Parse first question section: QNAME + QTYPE + QCLASS.
    let mut offset = 12;
    while offset < query.len() {
        let label_len = query[offset] as usize;
        offset += 1;
        if label_len == 0 {
            break;
        }
        if offset + label_len > query.len() {
            return None;
        }
        offset += label_len;
    }
    if offset + 4 > query.len() {
        return None;
    }
    let question_end = offset + 4;

    let mut response = Vec::with_capacity(question_end);
    response.extend_from_slice(&query[..12]);

    // Preserve opcode + RD, set QR=1.
    response[2] = 0x80 | (query[2] & 0x79);
    // RA=1, RCODE=2(SERVFAIL).
    response[3] = 0x80 | 0x02;

    // Single-question response with no answers/authority/additional.
    response[4..6].copy_from_slice(&1u16.to_be_bytes());
    response[6..8].copy_from_slice(&0u16.to_be_bytes());
    response[8..10].copy_from_slice(&0u16.to_be_bytes());
    response[10..12].copy_from_slice(&0u16.to_be_bytes());

    response.extend_from_slice(&query[12..question_end]);
    Some(response)
}
