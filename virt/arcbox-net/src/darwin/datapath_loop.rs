//! Async event loop bridging the guest VM network FD to the host network stack.
//!
//! # Datapath
//!
//! ```text
//! Guest VM
//!     ↕ VirtIO (VZ framework)
//! VZFileHandleNetworkDeviceAttachment
//!     ↕ socketpair FD (L2 Ethernet frames)
//! FrameClassifier (demultiplexes by protocol)
//!     ├─ ARP            → ArpResponder
//!     ├─ TCP SYN        → TcpBridge::handle_outbound_syn
//!     ├─ TCP (live)     → TcpBridge fast path / handshake-complete
//!     ├─ UDP:67 (DHCP)  → DhcpServer → reply to guest
//!     ├─ UDP:53 to gw   → DnsForwarder → reply to guest
//!     ├─ UDP (other)    → UdpProxy → reply to guest
//!     └─ ICMP           → IcmpProxy → reply to guest
//! ```
//!
//! There is no userspace TCP state machine. All TCP handshake work is done
//! by the in-shim `TcpBridge`; data frames flow via the fast path or the
//! zero-copy inline inject thread.

use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::Duration;

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::darwin::classifier::{FrameClassifier, InterceptedKind};
use crate::darwin::inbound_relay::InboundCommand;
use crate::darwin::socket_proxy::SocketProxy;
use crate::darwin::tcp_bridge::TcpBridge;
use crate::datapath::FrameBuf;
use crate::dhcp::DhcpServer;
use crate::dns::DnsForwarder;
use crate::ethernet::{ETH_HEADER_LEN, build_udp_ip_ethernet};

/// Hard cap on write_queue depth. Frames beyond this are dropped to prevent
/// unbounded memory growth when the guest FD is blocked (VM paused, VZ socket
/// buffer full). Increased from 2048 to 8192 to match 8 MB socket buffers.
const WRITE_QUEUE_HARD_CAP: usize = 8192;

/// Wraps an `OwnedFd` so it can be registered with `AsyncFd`.
struct FdWrapper(OwnedFd);

impl AsRawFd for FdWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// Async network datapath bridging guest ↔ host via `FrameClassifier`
/// demultiplexing and socket proxying.
///
/// `FrameClassifier` routes ARP (inline reply) and TCP (fast-path /
/// handshake drains). DHCP, DNS, UDP, and ICMP are intercepted and handled
/// by the corresponding proxy modules.
pub struct NetworkDatapath {
    /// Host end of the socketpair (guest L2 Ethernet frames).
    pub guest_fd: OwnedFd,
    /// Socket proxy for ICMP/UDP/TCP traffic.
    pub socket_proxy: SocketProxy,
    /// Channel receiving L2 reply frames from the socket proxy.
    pub reply_rx: mpsc::Receiver<Vec<u8>>,
    /// Channel receiving inbound commands from `InboundListenerManager`.
    pub cmd_rx: mpsc::Receiver<InboundCommand>,
    /// DHCP server.
    pub dhcp_server: DhcpServer,
    /// DNS forwarder.
    pub dns_forwarder: DnsForwarder,
    /// DNS resolution log: maps IPs back to domain names for proxy-aware TCP.
    pub dns_log: super::dns_log::DnsResolutionLog,
    /// Gateway MAC address used in L2 headers sent to the guest.
    pub gateway_mac: [u8; 6],
    /// Gateway IP address.
    pub gateway_ip: Ipv4Addr,
    /// Guest IP address (for inbound TCP connections).
    pub guest_ip: Ipv4Addr,
    /// Cancellation token for graceful shutdown.
    pub cancel: CancellationToken,
    /// Negotiated MTU (from VZ `setMaximumTransmissionUnit:` result).
    pub mtu: usize,
    /// Frame sink for host-to-guest RX injection. When set, all frames
    /// destined for the guest go through this sink (to the inject thread)
    /// instead of the socketpair write_queue.
    pub frame_sink: Option<std::sync::Arc<dyn crate::direct_rx::FrameSink>>,
    /// Connection sink for promoted fast-path TCP connections. When set,
    /// `TcpBridge` can send promoted connections to the RX inject thread
    /// for inline (zero-copy) host→guest data transfer.
    pub conn_sink: Option<std::sync::Arc<dyn crate::direct_rx::ConnSink>>,
}

impl NetworkDatapath {
    /// Creates a new datapath.
    ///
    /// `guest_fd` is the host side of the socketpair passed to VZ.
    /// `socket_proxy` and `reply_rx` are created via `SocketProxy::new()`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        guest_fd: OwnedFd,
        socket_proxy: SocketProxy,
        reply_rx: mpsc::Receiver<Vec<u8>>,
        cmd_rx: mpsc::Receiver<InboundCommand>,
        dhcp_server: DhcpServer,
        dns_forwarder: DnsForwarder,
        gateway_ip: Ipv4Addr,
        guest_ip: Ipv4Addr,
        gateway_mac: [u8; 6],
        cancel: CancellationToken,
        mtu: usize,
    ) -> Self {
        Self {
            guest_fd,
            socket_proxy,
            reply_rx,
            cmd_rx,
            dhcp_server,
            dns_forwarder,
            dns_log: super::dns_log::DnsResolutionLog::new(),
            gateway_mac,
            gateway_ip,
            guest_ip,
            cancel,
            mtu,
            frame_sink: None,
            conn_sink: None,
        }
    }

    /// Attaches a frame sink for host-to-guest RX injection.
    ///
    /// When set, frames are delivered through the sink (typically a crossbeam
    /// channel to the RX inject thread) instead of the socketpair write path.
    pub fn set_frame_sink(&mut self, sink: std::sync::Arc<dyn crate::direct_rx::FrameSink>) {
        self.frame_sink = Some(sink);
    }

    /// Attaches a connection sink for promoted fast-path TCP connections.
    ///
    /// When set, `TcpBridge` can send promoted connections to the RX inject
    /// thread for inline (zero-copy) host-to-guest data transfer.
    pub fn set_conn_sink(&mut self, sink: std::sync::Arc<dyn crate::direct_rx::ConnSink>) {
        self.conn_sink = Some(sink);
    }

    /// Runs the event loop until the cancellation token fires.
    ///
    /// Consumes `self` and destructures to avoid borrow conflicts between
    /// the AsyncFd wrappers and the mutable network processing state.
    ///
    /// # Errors
    ///
    /// Returns an error if the AsyncFd registration fails.
    pub async fn run(self) -> io::Result<()> {
        let Self {
            guest_fd,
            mut socket_proxy,
            mut reply_rx,
            mut cmd_rx,
            mut dhcp_server,
            dns_forwarder,
            dns_log,
            gateway_mac,
            gateway_ip,
            guest_ip,
            cancel,
            mtu,
            frame_sink,
            conn_sink,
        } = self;

        // Set guest_fd to non-blocking for AsyncFd.
        set_nonblocking(guest_fd.as_raw_fd())?;

        // Create the frame classifier wrapping the guest socketpair FD.
        let mut device = FrameClassifier::new(guest_fd.as_raw_fd(), gateway_ip, mtu);
        device.set_gateway_mac(gateway_mac);

        // TCP shim: handshake synthesizer + fast-path data plane.
        let mut tcp_bridge = TcpBridge::new(gateway_ip);

        // Enable large frame mode when using the channel-based FrameSink
        // (no socketpair 2048-byte datagram limit). This sends entire
        // read buffers (up to 32KB) as single frames, reducing per-frame
        // overhead by 10-30x.
        if frame_sink.is_some() {
            tcp_bridge.enable_large_frames();
        }

        // Attach connection sink so promoted fast-path connections can be
        // forwarded to the RX inject thread for inline transfer.
        if let Some(ref sink) = conn_sink {
            tcp_bridge.set_conn_sink(sink.clone());
        }

        // Enable proxy-aware connections: detect host VPN/proxy environment
        // and share the DNS resolution log so TcpBridge can map IPs to domains.
        let proxy_env = super::proxy_detect::ProxyEnvironment::detect();
        tcp_bridge.set_proxy_awareness(dns_log.clone(), proxy_env);

        let guest_async = AsyncFd::new(FdWrapper(guest_fd))?;

        // Clone the reply sender for async DNS forwarding tasks.
        let dns_reply_tx = socket_proxy.reply_sender();

        let mut guest_mac: Option<[u8; 6]> = None;

        // Write queue: buffers frames that couldn't be written to the guest FD
        // due to EWOULDBLOCK. Drained when the FD becomes writable again.
        let mut write_queue: VecDeque<FrameBuf> = VecDeque::new();

        // Unified timer wheel for flow timeout management (1s tick).
        // Replaces per-flow tokio::time::timeout() objects with a single
        // shared timer, reducing wakeup count from O(active_flows) to O(1).
        let mut timer_wheel =
            crate::timer_wheel::TimerWheel::<std::net::SocketAddr>::new(Duration::from_secs(1));
        let mut timer_wheel_tick = tokio::time::interval(Duration::from_secs(1));
        timer_wheel_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Periodic maintenance interval for cleaning up stale flows.
        let mut maintenance = tokio::time::interval(Duration::from_secs(30));
        maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        tracing::info!("Network datapath started (TCP shim + socket proxy mode)");

        loop {
            let has_pending = !write_queue.is_empty();

            tokio::select! {
                biased;

                () = cancel.cancelled() => {
                    tracing::info!("Network datapath shutting down");
                    break;
                }

                // Drain pending writes when the guest FD becomes writable.
                writable = guest_async.writable(), if has_pending => {
                    let mut guard = writable?;
                    while let Some(frame) = write_queue.front() {
                        match guard.try_io(|inner| fd_write(inner.get_ref().as_raw_fd(), frame)) {
                            Ok(Ok(n)) if n >= frame.len() => { write_queue.pop_front(); }
                            Ok(Ok(n)) => {
                                // SOCK_DGRAM delivers whole frames or fails — a short
                                // write should never happen and indicates a broken
                                // invariant. Drop the frame to avoid corrupting L2
                                // boundaries.
                                tracing::error!(
                                    "Guest write: short datagram ({n}/{} bytes), dropping frame",
                                    frame.len(),
                                );
                                write_queue.pop_front();
                            }
                            Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Ok(Err(e)) => {
                                tracing::warn!("Guest write error: {}", e);
                                write_queue.pop_front();
                            }
                            Err(_) => break,
                        }
                    }
                }

                // Guest → Host: read frames, classify, and dispatch.
                readable = guest_async.readable() => {
                    let mut guard = readable?;
                    let prev_mac = guest_mac;
                    // Drain all available frames from the FD, classifying each.
                    device.drain_guest_fd(&mut guest_mac);
                    // We drained until WouldBlock; clear readiness to avoid
                    // spinning on the biased readable arm.
                    guard.clear_ready();

                    // Record guest MAC the first time we see it so outbound
                    // shim-built frames carry the correct Ethernet destination.
                    if prev_mac.is_none() {
                        if let Some(gmac) = guest_mac {
                            tcp_bridge.set_fast_path_macs(gateway_mac, gmac);
                        }
                    }

                    // Fast-path intercept: extract TCP data frames for established
                    // fast-path connections and synthesize ACKs inline.
                    let fast_acks = device.drain_fast_path(|frame_data| {
                        tcp_bridge.try_fast_path_intercept(frame_data)
                    });
                    for ack in fast_acks {
                        send_to_guest(frame_sink.as_ref(), &guest_async, &ack, &mut write_queue);
                    }

                    // Handshake intercept: complete in-progress shim handshakes
                    // (guest ACK → PassiveOpen promotion, guest SYN-ACK →
                    // ActiveOpen promotion). Frames that match are consumed
                    // here.
                    let hs_replies = device.drain_handshake(|frame_data| {
                        tcp_bridge.try_complete_handshake(frame_data)
                    });
                    for reply in hs_replies {
                        send_to_guest(frame_sink.as_ref(), &guest_async, &reply, &mut write_queue);
                    }

                    // Flush ARP replies produced inline by the classifier.
                    for reply in device.take_arp_replies() {
                        send_to_guest(frame_sink.as_ref(), &guest_async, &reply, &mut write_queue);
                    }

                    // Discard any TCP frames left in the rx queue that didn't
                    // match a fast-path or handshake entry — there is no
                    // userspace TCP stack to consume them.
                    device.clear_unmatched_rx();

                    // Process intercepted frames (DHCP, DNS, UDP, ICMP).
                    let intercepted = device.take_intercepted();
                    for intercepted_frame in &intercepted {
                        handle_intercepted_frame(
                            intercepted_frame,
                            frame_sink.as_ref(),
                            &guest_async,
                            &mut write_queue,
                            &mut socket_proxy,
                            &mut dhcp_server,
                            &dns_forwarder,
                            &dns_reply_tx,
                            &dns_log,
                            &cancel,
                            gateway_ip,
                            gateway_mac,
                            guest_mac.unwrap_or([0xFF; 6]),
                        );
                    }

                    // New outbound SYNs: route to the hand-rolled handshake
                    // synthesizer. The shim owns this path end-to-end and
                    // emits the SYN-ACK via poll_handshakes once the async
                    // host connect resolves.
                    let gated_syns = device.take_gated_syns();
                    let gmac = guest_mac.unwrap_or([0xFF; 6]);
                    for syn in &gated_syns {
                        if let Some(rst) = tcp_bridge.handle_outbound_syn(&syn.frame, gateway_mac, gmac) {
                            send_to_guest(frame_sink.as_ref(), &guest_async, &rst, &mut write_queue);
                        }
                    }

                }

                // Proxy → Guest: relay reply frames from socket proxy.
                // Always poll — the bounded channel (256) provides natural backpressure
                // to spawned tasks. Gating on write_queue depth starved DNS replies.
                Some(reply_frame) = reply_rx.recv() => {
                    send_to_guest(frame_sink.as_ref(), &guest_async, &reply_frame, &mut write_queue);
                }

                // Inbound commands from InboundListenerManager.
                Some(cmd) = cmd_rx.recv() => {
                    process_inbound_cmd(
                        cmd,
                        &mut tcp_bridge,
                        &mut socket_proxy,
                        guest_ip,
                        gateway_ip,
                        guest_mac,
                    );
                }

                // Periodic maintenance.
                _ = timer_wheel_tick.tick() => {
                    // Advance the timer wheel and handle expired flow timers.
                    // TODO: Migrate tcp_bridge SYN gate and socket_proxy UDP/ICMP
                    // per-flow timeouts to use timer_wheel.register() instead of
                    // spawning independent tokio::time::timeout() tasks. For now
                    // the wheel is wired but consumers are not yet migrated.
                    let expired = timer_wheel.advance();
                    for entry in &expired {
                        tracing::trace!(
                            "Timer wheel expired: {:?} action={:?}",
                            entry.key,
                            entry.action
                        );
                    }
                    // Feed expired entries back to socket_proxy for cleanup
                    for entry in expired {
                        use crate::timer_wheel::TimerAction;
                        match entry.action {
                            TimerAction::UdpFlowExpiry | TimerAction::IcmpTimeout => {
                                socket_proxy.expire_flow(entry.key);
                            }
                            _ => {}
                        }
                    }
                }

                _ = maintenance.tick() => {
                    socket_proxy.maintenance();
                }
            }

            // ── Common tail: run on every iteration regardless of which
            //    branch fired. This ensures handshake retransmissions,
            //    tcp_bridge relay, and frame flushing are never starved.

            // 1. Drive the hand-rolled handshake synthesizer. Emits SYN-ACKs
            //    when host connects complete (PassiveOpen), SYNs for
            //    active-open (ActiveOpen), and retransmits under loss.
            let hs_frames = tcp_bridge.poll_handshakes();
            for frame in hs_frames {
                send_to_guest(frame_sink.as_ref(), &guest_async, &frame, &mut write_queue);
            }

            // 1.5. Drain inbound listener commands so `cmd_rx.recv()` cannot be
            //      starved by the biased readable branch under sustained traffic.
            drain_cmd_rx(
                &mut cmd_rx,
                &mut tcp_bridge,
                &mut socket_proxy,
                guest_ip,
                gateway_ip,
                guest_mac,
            );

            // 2. Poll fast-path host streams for inbound data and inject
            //    constructed frames directly to guest.
            for frame in tcp_bridge.poll_fast_path() {
                send_to_guest(frame_sink.as_ref(), &guest_async, &frame, &mut write_queue);
            }

            drain_reply_rx(
                &mut reply_rx,
                frame_sink.as_ref(),
                &guest_async,
                &mut write_queue,
            );

            // Yield to the tokio runtime so spawned tasks (e.g. host relay
            // read/write) get a chance to run on this worker thread. Without
            // this, the tight synchronous common-tail loop can starve spawned
            // tasks for seconds.
            tokio::task::yield_now().await;
        }

        Ok(())
    }
}

// ============================================================================
// Intercepted frame handling
// ============================================================================

/// Dispatches an intercepted frame to the appropriate handler.
#[allow(clippy::too_many_arguments)]
fn handle_intercepted_frame(
    intercepted: &crate::darwin::classifier::InterceptedFrame,
    frame_sink: Option<&std::sync::Arc<dyn crate::direct_rx::FrameSink>>,
    guest_async: &AsyncFd<FdWrapper>,
    write_queue: &mut VecDeque<FrameBuf>,
    socket_proxy: &mut SocketProxy,
    dhcp_server: &mut DhcpServer,
    dns_forwarder: &DnsForwarder,
    dns_reply_tx: &mpsc::Sender<Vec<u8>>,
    dns_log: &super::dns_log::DnsResolutionLog,
    cancel: &CancellationToken,
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
) {
    let frame = &intercepted.frame;
    match intercepted.kind {
        InterceptedKind::Dhcp => {
            handle_dhcp(
                frame,
                frame_sink,
                guest_async,
                write_queue,
                dhcp_server,
                gateway_ip,
                gateway_mac,
                guest_mac,
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
            );
        }
        InterceptedKind::Udp | InterceptedKind::Icmp => {
            // Route through socket proxy (UDP/ICMP).
            socket_proxy.handle_outbound(frame, guest_mac);
        }
    }
}

/// Processes one inbound command from `InboundListenerManager`.
///
/// TCP accepted streams are registered with the handshake synthesizer; UDP
/// datagrams are routed through the socket proxy inbound path.
fn process_inbound_cmd(
    cmd: InboundCommand,
    tcp_bridge: &mut TcpBridge,
    socket_proxy: &mut SocketProxy,
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
            socket_proxy.handle_inbound_command(cmd, mac);
        }
    }
}

/// Handles a DHCP packet from the guest.
#[allow(clippy::too_many_arguments)]
fn handle_dhcp(
    frame: &[u8],
    frame_sink: Option<&std::sync::Arc<dyn crate::direct_rx::FrameSink>>,
    guest_async: &AsyncFd<FdWrapper>,
    write_queue: &mut VecDeque<FrameBuf>,
    dhcp_server: &mut DhcpServer,
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
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
            let reply_frame = build_udp_ip_ethernet(
                gateway_ip,
                Ipv4Addr::BROADCAST,
                67,
                68,
                &response,
                gateway_mac,
                guest_mac,
            );
            tracing::info!("Sending DHCP reply frame: {} bytes", reply_frame.len());
            send_to_guest(frame_sink, guest_async, &reply_frame, write_queue);
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
    dns_log: &super::dns_log::DnsResolutionLog,
    cancel: &CancellationToken,
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
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
        let reply_frame = build_udp_ip_ethernet(
            gateway_ip,
            src_ip,
            53,
            src_port,
            &response,
            gateway_mac,
            guest_mac,
        );
        let tx = dns_reply_tx.clone();
        tokio::spawn(async move {
            if tx.send(reply_frame).await.is_err() {
                tracing::debug!("DNS reply channel closed");
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
                if let Some((domain, ips)) = super::dns_log::parse_dns_response_a_records(&response)
                {
                    tracing::debug!(
                        domain = %domain,
                        ips = ?ips,
                        "DNS resolution logged"
                    );
                    log.record(&domain, &ips);
                }

                let reply_frame = build_udp_ip_ethernet(
                    gateway_ip,
                    src_ip,
                    53,
                    src_port,
                    &response,
                    gateway_mac,
                    guest_mac,
                );
                if tx.send(reply_frame).await.is_err() {
                    tracing::debug!("DNS reply channel closed");
                }
                tracing::debug!("Sent forwarded DNS response to guest");
            }
            Err(e) => {
                tracing::warn!("DNS forwarding failed: {e}");
                if let Some(servfail) = build_dns_servfail_response(&data) {
                    let reply_frame = build_udp_ip_ethernet(
                        gateway_ip,
                        src_ip,
                        53,
                        src_port,
                        &servfail,
                        gateway_mac,
                        guest_mac,
                    );
                    if tx.send(reply_frame).await.is_err() {
                        tracing::debug!("DNS reply channel closed");
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

    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("bind failed: {e}"))?;

    for addr in upstream {
        if socket.send_to(data, addr).await.is_err() {
            continue;
        }

        let mut buf = [0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) if len >= 2 && buf[0] == query_id[0] && buf[1] == query_id[1] => {
                return Ok(buf[..len].to_vec());
            }
            _ => {}
        }
    }

    Err("all upstream DNS servers failed".to_string())
}

/// Builds a minimal DNS SERVFAIL response from the raw query.
fn build_dns_servfail_response(query: &[u8]) -> Option<Vec<u8>> {
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

// ============================================================================
// Helpers
// ============================================================================

/// Maximum number of reply frames to drain per call, preventing a single
/// drain from starving other `select!` branches under high traffic.
const DRAIN_REPLY_BATCH: usize = 64;

/// Maximum number of inbound listener commands to drain per common-tail pass.
///
/// Batching prevents command draining from monopolizing the event loop while
/// still guaranteeing forward progress when `cmd_rx.recv()` is starved.
const DRAIN_CMD_BATCH: usize = 64;

/// Non-blocking drain of the reply channel. Delivers pending proxy
/// responses (DNS, UDP, ICMP) to the guest without blocking the event loop.
///
/// Limits each call to `DRAIN_REPLY_BATCH` frames to avoid starving other
/// `select!` branches.
fn drain_reply_rx(
    reply_rx: &mut mpsc::Receiver<Vec<u8>>,
    frame_sink: Option<&std::sync::Arc<dyn crate::direct_rx::FrameSink>>,
    guest_async: &AsyncFd<FdWrapper>,
    write_queue: &mut VecDeque<FrameBuf>,
) {
    for _ in 0..DRAIN_REPLY_BATCH {
        match reply_rx.try_recv() {
            Ok(reply_frame) => {
                send_to_guest(frame_sink, guest_async, &reply_frame, write_queue);
            }
            Err(_) => break,
        }
    }
}

/// Non-blocking drain of inbound listener commands.
///
/// Prevents starvation of `cmd_rx.recv()` in the biased `select!` loop when
/// the guest FD readable branch is continuously ready.
fn drain_cmd_rx(
    cmd_rx: &mut mpsc::Receiver<InboundCommand>,
    tcp_bridge: &mut TcpBridge,
    socket_proxy: &mut SocketProxy,
    guest_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
    guest_mac: Option<[u8; 6]>,
) {
    for _ in 0..DRAIN_CMD_BATCH {
        match cmd_rx.try_recv() {
            Ok(cmd) => process_inbound_cmd(
                cmd,
                tcp_bridge,
                socket_proxy,
                guest_ip,
                gateway_ip,
                guest_mac,
            ),
            Err(_) => break,
        }
    }
}

/// Sends a frame to the guest via the frame sink (if present) or falls
/// back to the socketpair write path.
///
/// When `frame_sink` is `Some`, the frame is sent through the crossbeam
/// channel to the RX injection thread, bypassing the socketpair entirely.
/// When `None`, falls back to `enqueue_or_write` for VZ-backend or
/// early-boot compatibility.
fn send_to_guest(
    frame_sink: Option<&std::sync::Arc<dyn crate::direct_rx::FrameSink>>,
    guest_async: &AsyncFd<FdWrapper>,
    frame_data: &[u8],
    write_queue: &mut VecDeque<FrameBuf>,
) {
    if let Some(sink) = frame_sink {
        let _ = sink.send(frame_data.to_vec());
        return;
    }
    // Fallback: socketpair (VZ backend or during early boot).
    enqueue_or_write(
        guest_async,
        FrameBuf::from(frame_data.to_vec()),
        write_queue,
    );
}

/// Attempts a direct non-blocking write; queues the frame on `WouldBlock`.
///
/// If the write queue is non-empty, the frame is appended directly to
/// preserve ordering.
fn enqueue_or_write(
    guest_async: &AsyncFd<FdWrapper>,
    frame: FrameBuf,
    write_queue: &mut VecDeque<FrameBuf>,
) {
    if !write_queue.is_empty() {
        if write_queue.len() < WRITE_QUEUE_HARD_CAP {
            write_queue.push_back(frame);
        } else {
            tracing::debug!("Write queue full ({WRITE_QUEUE_HARD_CAP}), dropping frame");
        }
        return;
    }
    let fd = guest_async.get_ref().as_raw_fd();
    match fd_write(fd, &frame) {
        Ok(n) if n >= frame.len() => {}
        Ok(n) => {
            // SOCK_DGRAM: short write should never happen — invariant violation.
            tracing::error!(
                "Guest write: short datagram ({n}/{} bytes), dropping frame",
                frame.len(),
            );
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            write_queue.push_back(frame);
        }
        Err(e) => {
            tracing::warn!("Guest write error: {}", e);
        }
    }
}

/// Writes data to a raw file descriptor, returning bytes written or an error.
fn fd_write(fd: RawFd, data: &[u8]) -> io::Result<usize> {
    // SAFETY: writing from our buffer to a valid socketpair fd.
    let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        #[allow(clippy::cast_sign_loss)]
        Ok(n as usize)
    }
}

/// Writes a frame to the guest FD (best-effort, non-blocking).
///
/// Used in tests for direct FD write verification.
#[cfg(test)]
fn write_to_guest(guest_async: &AsyncFd<FdWrapper>, data: &[u8]) {
    let fd = guest_async.get_ref().as_raw_fd();
    // SAFETY: writing from our buffer to a valid socketpair fd.
    let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
    if n < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            tracing::warn!("Guest write WouldBlock: {} bytes dropped", data.len());
        } else {
            tracing::warn!("Guest write error: {}", err);
        }
    } else {
        tracing::debug!("Guest write OK: {}/{} bytes", n, data.len());
    }
}

/// Reads from a file descriptor into `buf`, returning number of bytes read.
#[allow(dead_code)]
fn fd_read(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: reading into our buffer from a valid fd.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        #[allow(clippy::cast_sign_loss)]
        Ok(n as usize)
    }
}

/// Sets a file descriptor to non-blocking mode.
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a valid fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;

    /// Creates a SOCK_DGRAM socketpair, returning (fd_a, fd_b) as OwnedFds.
    fn socketpair() -> (OwnedFd, OwnedFd) {
        let mut fds: [i32; 2] = [0; 2];
        // SAFETY: valid pointer to 2-element array.
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "socketpair() failed");
        // SAFETY: fds are valid file descriptors from socketpair.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    #[test]
    fn test_set_nonblocking() {
        let (a, _b) = socketpair();
        set_nonblocking(a.as_raw_fd()).unwrap();

        // SAFETY: fcntl on a valid fd.
        let flags = unsafe { libc::fcntl(a.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::O_NONBLOCK, 0, "O_NONBLOCK should be set");
    }

    #[test]
    fn test_fd_read_write_roundtrip() {
        let (a, b) = socketpair();
        let data = b"hello network";

        // SAFETY: writing from valid buffer to valid fd.
        let n = unsafe { libc::write(b.as_raw_fd(), data.as_ptr().cast(), data.len()) };
        assert_eq!(n as usize, data.len());

        let mut buf = [0u8; 64];
        let n = fd_read(a.as_raw_fd(), &mut buf).unwrap();
        assert_eq!(n, data.len());
        assert_eq!(&buf[..n], data);
    }

    #[tokio::test]
    async fn test_write_to_guest_roundtrip() {
        let (a, b) = socketpair();

        set_nonblocking(a.as_raw_fd()).unwrap();
        let guest_async = AsyncFd::new(FdWrapper(a)).unwrap();

        let frame = b"test ethernet frame data";
        write_to_guest(&guest_async, frame);

        let mut buf = [0u8; 128];
        let n = fd_read(b.as_raw_fd(), &mut buf).unwrap();
        assert_eq!(n, frame.len());
        assert_eq!(&buf[..n], frame.as_slice());
    }

    #[test]
    fn test_fd_write_roundtrip() {
        let (a, b) = socketpair();
        let data = b"fd_write test data";
        let n = fd_write(b.as_raw_fd(), data).unwrap();
        assert_eq!(n, data.len());

        let mut buf = [0u8; 64];
        let n = fd_read(a.as_raw_fd(), &mut buf).unwrap();
        assert_eq!(&buf[..n], data);
    }

    #[tokio::test]
    async fn test_enqueue_or_write_direct() {
        let (a, b) = socketpair();
        set_nonblocking(a.as_raw_fd()).unwrap();
        let guest_async = AsyncFd::new(FdWrapper(a)).unwrap();

        let mut queue = VecDeque::new();
        let frame_data = b"direct write frame";
        enqueue_or_write(
            &guest_async,
            FrameBuf::from(frame_data.to_vec()),
            &mut queue,
        );

        assert!(queue.is_empty(), "Queue should be empty after direct write");

        let mut buf = [0u8; 128];
        let n = fd_read(b.as_raw_fd(), &mut buf).unwrap();
        assert_eq!(&buf[..n], frame_data.as_slice());
    }

    #[tokio::test]
    async fn test_enqueue_or_write_queues_when_nonempty() {
        let (a, _b) = socketpair();
        set_nonblocking(a.as_raw_fd()).unwrap();
        let guest_async = AsyncFd::new(FdWrapper(a)).unwrap();

        let mut queue: VecDeque<FrameBuf> = VecDeque::new();
        queue.push_back(FrameBuf::from(b"already queued".to_vec()));

        enqueue_or_write(
            &guest_async,
            FrameBuf::from(b"new frame".to_vec()),
            &mut queue,
        );

        assert_eq!(queue.len(), 2);
        assert_eq!(&queue[1][..], b"new frame");
    }

    #[test]
    fn test_build_dns_servfail_response() {
        let query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags (RD)
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            0x01, b'a', // QNAME label "a"
            0x00, // root
            0x00, 0x01, // QTYPE A
            0x00, 0x01, // QCLASS IN
        ];

        let response = build_dns_servfail_response(&query).expect("should build servfail");
        assert_eq!(response[0..2], query[0..2]); // ID preserved
        assert_eq!(response[2] & 0x80, 0x80); // QR=1
        assert_eq!(response[3] & 0x0F, 0x02); // RCODE=SERVFAIL
        assert_eq!(&response[4..6], &1u16.to_be_bytes()); // QDCOUNT=1
        assert_eq!(&response[6..8], &0u16.to_be_bytes()); // ANCOUNT=0
        assert_eq!(&response[8..10], &0u16.to_be_bytes()); // NSCOUNT=0
        assert_eq!(&response[10..12], &0u16.to_be_bytes()); // ARCOUNT=0
        assert_eq!(&response[12..], &query[12..]); // Question echoed
    }
}
