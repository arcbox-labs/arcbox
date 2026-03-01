//! Async event loop bridging the guest VM network FD to the host network stack.
//!
//! # Datapath
//!
//! ```text
//! Guest VM
//!     ↕ VirtIO (VZ framework)
//! VZFileHandleNetworkDeviceAttachment
//!     ↕ socketpair FD (L2 Ethernet frames)
//! SmoltcpDevice (frame classification)
//!     ├─ ARP           → smoltcp Interface (automatic handling)
//!     ├─ TCP           → smoltcp Interface → tcp::Socket pool (Phase 2)
//!     ├─ UDP:67 (DHCP) → DhcpServer → reply to guest
//!     ├─ UDP:53 to gw  → DnsForwarder → reply to guest
//!     ├─ UDP (other)   → UdpProxy → reply to guest
//!     └─ ICMP          → IcmpProxy → reply to guest
//! ```
//!
//! The smoltcp `Interface` handles ARP automatically and will manage TCP
//! connections via its socket pool (Phase 2). DHCP, DNS, UDP, and ICMP are
//! intercepted at the `SmoltcpDevice` layer before reaching smoltcp and
//! handled by the existing proxy modules.

use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::wire::{EthernetAddress, IpCidr};

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::darwin::inbound_relay::InboundCommand;
use crate::darwin::smoltcp_device::{InterceptedKind, SmoltcpDevice};
use crate::darwin::socket_proxy::SocketProxy;
use crate::darwin::tcp_bridge::TcpBridge;
use crate::dhcp::DhcpServer;
use crate::dns::DnsForwarder;
use crate::ethernet::{ETH_HEADER_LEN, build_udp_ip_ethernet};

/// Stop consuming reply_rx when write queue exceeds this depth, propagating
/// backpressure through the reply channel to upstream TCP/UDP proxies.
const WRITE_QUEUE_HIGH: usize = 512;

/// Wraps an `OwnedFd` so it can be registered with `AsyncFd`.
struct FdWrapper(OwnedFd);

impl AsRawFd for FdWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// Async network datapath bridging guest ↔ host through smoltcp + socket proxying.
///
/// smoltcp handles ARP and TCP (Phase 2). DHCP, DNS, UDP, and ICMP are
/// intercepted before reaching smoltcp and handled by existing proxy modules.
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
    /// Gateway MAC address used in L2 headers sent to the guest.
    pub gateway_mac: [u8; 6],
    /// Gateway IP address.
    pub gateway_ip: Ipv4Addr,
    /// Guest IP address (for inbound TCP connections via smoltcp).
    pub guest_ip: Ipv4Addr,
    /// Cancellation token for graceful shutdown.
    pub cancel: CancellationToken,
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
    ) -> Self {
        Self {
            guest_fd,
            socket_proxy,
            reply_rx,
            cmd_rx,
            dhcp_server,
            dns_forwarder,
            gateway_mac,
            gateway_ip,
            guest_ip,
            cancel,
        }
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
        let NetworkDatapath {
            guest_fd,
            mut socket_proxy,
            mut reply_rx,
            mut cmd_rx,
            mut dhcp_server,
            dns_forwarder,
            gateway_mac,
            gateway_ip,
            guest_ip,
            cancel,
        } = self;

        // Set guest_fd to non-blocking for AsyncFd.
        set_nonblocking(guest_fd.as_raw_fd())?;

        // Create the smoltcp device wrapping the guest socketpair FD.
        let mut device = SmoltcpDevice::new(guest_fd.as_raw_fd(), gateway_ip);

        // Create the smoltcp Interface with the gateway's MAC and IP.
        let hw_addr = EthernetAddress(gateway_mac);
        let config = Config::new(hw_addr.into());
        let mut iface = Interface::new(config, &mut device, smoltcp::time::Instant::now());

        // Configure the interface with the gateway IP address.
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(gateway_ip.into(), 24))
                .expect("failed to add gateway IP to smoltcp interface");
        });

        // Enable any_ip so smoltcp accepts packets to any destination IP,
        // which is required for the TCP listen pool.
        iface.set_any_ip(true);

        // Add a default route so smoltcp can send TCP replies (SYN-ACK, etc.)
        // to the guest for connections to arbitrary external IPs.
        iface
            .routes_mut()
            .add_default_ipv4_route(gateway_ip)
            .expect("failed to add default route to smoltcp interface");

        // Create socket set (TCP sockets added dynamically by TcpBridge).
        let mut sockets = SocketSet::new(vec![]);

        // TCP bridge: manages smoltcp TCP socket pool and host connections.
        let mut tcp_bridge = TcpBridge::new();

        let guest_async = AsyncFd::new(FdWrapper(guest_fd))?;

        // Clone the reply sender for async DNS forwarding tasks.
        let dns_reply_tx = socket_proxy.reply_sender();

        let mut guest_mac: Option<[u8; 6]> = None;

        // Write queue: buffers frames that couldn't be written to the guest FD
        // due to EWOULDBLOCK. Drained when the FD becomes writable again.
        let mut write_queue: VecDeque<Vec<u8>> = VecDeque::new();

        // Periodic maintenance interval for cleaning up stale flows.
        let mut maintenance = tokio::time::interval(Duration::from_secs(30));
        maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // smoltcp poll timer: drives retransmissions and ARP cache expiry.
        let mut smoltcp_timer = tokio::time::interval(Duration::from_millis(100));
        smoltcp_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        tracing::info!("Network datapath started (smoltcp + socket proxy mode)");

        loop {
            let has_pending = !write_queue.is_empty();
            let accept_replies = write_queue.len() < WRITE_QUEUE_HIGH;

            tokio::select! {
                biased;

                _ = cancel.cancelled() => {
                    tracing::info!("Network datapath shutting down");
                    break;
                }

                // Drain pending writes when the guest FD becomes writable.
                writable = guest_async.writable(), if has_pending => {
                    let mut guard = writable?;
                    while let Some(frame) = write_queue.front() {
                        match guard.try_io(|inner| fd_write(inner.get_ref().as_raw_fd(), frame)) {
                            Ok(Ok(_)) => { write_queue.pop_front(); }
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
                    // Clear the readiness so we don't spin if no data available.
                    match guard.try_io(|_| Ok::<(), io::Error>(())) {
                        Ok(_) => {}
                        Err(_) => continue,
                    }

                    // Drain all available frames from the FD, classifying each.
                    device.drain_guest_fd(&mut guest_mac);

                    // Process intercepted frames (DHCP, DNS, UDP, ICMP).
                    let intercepted = device.take_intercepted();
                    for intercepted_frame in &intercepted {
                        handle_intercepted_frame(
                            intercepted_frame,
                            &guest_async,
                            &mut write_queue,
                            &mut socket_proxy,
                            &mut dhcp_server,
                            &dns_forwarder,
                            &dns_reply_tx,
                            gateway_ip,
                            gateway_mac,
                            guest_mac.unwrap_or([0xFF; 6]),
                        );
                    }

                    // Gate TCP SYN frames: start host connect, hold SYN
                    // until connect completes.
                    let gated_syns = device.take_gated_syns();
                    if !gated_syns.is_empty() {
                        let rst_frames = tcp_bridge.gate_syns(&gated_syns, gateway_mac);
                        for rst in rst_frames {
                            enqueue_or_write(&guest_async, rst, &mut write_queue);
                        }
                    }
                }

                // Proxy → Guest: relay reply frames from socket proxy.
                Some(reply_frame) = reply_rx.recv(), if accept_replies => {
                    enqueue_or_write(&guest_async, reply_frame, &mut write_queue);
                }

                // Inbound commands from InboundListenerManager.
                Some(cmd) = cmd_rx.recv() => {
                    use crate::darwin::inbound_relay::InboundCommand;
                    match cmd {
                        InboundCommand::TcpAccepted { container_port, stream, .. } => {
                            tcp_bridge.initiate_inbound(
                                container_port,
                                stream,
                                guest_ip,
                                gateway_ip,
                                &mut iface,
                                &mut sockets,
                            );
                        }
                        cmd @ InboundCommand::UdpReceived { .. } => {
                            let mac = guest_mac.unwrap_or([0xFF; 6]);
                            socket_proxy.handle_inbound_command(cmd, mac);
                        }
                    }
                }

                // Wakeup when no other events: drives retransmissions during
                // idle periods. Under load, the readable arm triggers smoltcp
                // poll via the common tail below.
                _ = smoltcp_timer.tick() => {}

                // Periodic maintenance.
                _ = maintenance.tick() => {
                    socket_proxy.maintenance();
                }
            }

            // ── Common tail: run on every iteration regardless of which
            //    branch fired. This ensures smoltcp retransmissions,
            //    tcp_bridge relay, and frame flushing are never starved.

            // 1. Poll pending SYN gate entries — may inject SYN frames into
            //    device rx_queue and create listen sockets, or produce RST frames.
            let rst_frames = tcp_bridge.poll_pending_syns(&mut device, &mut sockets, gateway_mac);
            for rst in rst_frames {
                enqueue_or_write(&guest_async, rst, &mut write_queue);
            }

            // 2. smoltcp poll: processes injected SYN frames (from gate) +
            //    retransmissions + ACKs.
            let ts = smoltcp::time::Instant::now();
            iface.poll(ts, &mut device, &mut sockets);

            // 3. tcp_bridge relay: detect new connections, relay data,
            //    cleanup closed.
            tcp_bridge.poll(&mut sockets);

            // 4. Re-poll to flush data pushed by tcp_bridge into TCP segments.
            let ts = smoltcp::time::Instant::now();
            iface.poll(ts, &mut device, &mut sockets);

            // 5. Flush TX frames to guest.
            for frame in device.take_tx_pending() {
                enqueue_or_write(&guest_async, frame, &mut write_queue);
            }

            drain_reply_rx(&mut reply_rx, &guest_async, &mut write_queue);

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
    intercepted: &crate::darwin::smoltcp_device::InterceptedFrame,
    guest_async: &AsyncFd<FdWrapper>,
    write_queue: &mut VecDeque<Vec<u8>>,
    socket_proxy: &mut SocketProxy,
    dhcp_server: &mut DhcpServer,
    dns_forwarder: &DnsForwarder,
    dns_reply_tx: &mpsc::Sender<Vec<u8>>,
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
) {
    let frame = &intercepted.frame;
    match intercepted.kind {
        InterceptedKind::Dhcp => {
            handle_dhcp(
                frame,
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

/// Handles a DHCP packet from the guest.
fn handle_dhcp(
    frame: &[u8],
    guest_async: &AsyncFd<FdWrapper>,
    write_queue: &mut VecDeque<Vec<u8>>,
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
            enqueue_or_write(guest_async, reply_frame, write_queue);
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
fn handle_dns(
    frame: &[u8],
    dns_forwarder: &DnsForwarder,
    dns_reply_tx: &mpsc::Sender<Vec<u8>>,
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

    tokio::spawn(async move {
        match forward_dns_async(&data, &upstream).await {
            Ok(response) => {
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
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("bind failed: {e}"))?;

    for addr in upstream {
        if socket.send_to(data, addr).await.is_err() {
            continue;
        }

        let mut buf = [0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => return Ok(buf[..len].to_vec()),
            _ => continue,
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

/// Non-blocking drain of the reply channel. Delivers pending proxy
/// responses (DNS, UDP, ICMP) to the guest without blocking the event loop.
///
/// Respects `WRITE_QUEUE_HIGH` backpressure and limits each call to
/// `DRAIN_REPLY_BATCH` frames to avoid starving other `select!` branches.
fn drain_reply_rx(
    reply_rx: &mut mpsc::Receiver<Vec<u8>>,
    guest_async: &AsyncFd<FdWrapper>,
    write_queue: &mut VecDeque<Vec<u8>>,
) {
    for _ in 0..DRAIN_REPLY_BATCH {
        if write_queue.len() >= WRITE_QUEUE_HIGH {
            break;
        }
        match reply_rx.try_recv() {
            Ok(reply_frame) => enqueue_or_write(guest_async, reply_frame, write_queue),
            Err(_) => break,
        }
    }
}

/// Attempts a direct non-blocking write; queues the frame on `WouldBlock`.
///
/// If the write queue is non-empty, the frame is appended directly to
/// preserve ordering.
fn enqueue_or_write(
    guest_async: &AsyncFd<FdWrapper>,
    frame: Vec<u8>,
    write_queue: &mut VecDeque<Vec<u8>>,
) {
    if !write_queue.is_empty() {
        write_queue.push_back(frame);
        return;
    }
    let fd = guest_async.get_ref().as_raw_fd();
    match fd_write(fd, &frame) {
        Ok(_) => {}
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
        let frame = b"direct write frame".to_vec();
        enqueue_or_write(&guest_async, frame.clone(), &mut queue);

        assert!(queue.is_empty(), "Queue should be empty after direct write");

        let mut buf = [0u8; 128];
        let n = fd_read(b.as_raw_fd(), &mut buf).unwrap();
        assert_eq!(&buf[..n], frame.as_slice());
    }

    #[tokio::test]
    async fn test_enqueue_or_write_queues_when_nonempty() {
        let (a, _b) = socketpair();
        set_nonblocking(a.as_raw_fd()).unwrap();
        let guest_async = AsyncFd::new(FdWrapper(a)).unwrap();

        let mut queue = VecDeque::new();
        queue.push_back(b"already queued".to_vec());

        let frame = b"new frame".to_vec();
        enqueue_or_write(&guest_async, frame.clone(), &mut queue);

        assert_eq!(queue.len(), 2);
        assert_eq!(queue[1], frame);
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

    #[test]
    fn test_smoltcp_arp_response() {
        let (host_fd, guest_fd) = socketpair();
        set_nonblocking(host_fd.as_raw_fd()).unwrap();

        let gateway_ip = Ipv4Addr::new(192, 168, 64, 1);
        let gateway_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let guest_mac_addr = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

        // Create smoltcp device and interface.
        let mut device = SmoltcpDevice::new(host_fd.as_raw_fd(), gateway_ip);
        let hw_addr = EthernetAddress(gateway_mac);
        let config = Config::new(hw_addr.into());
        let mut iface = Interface::new(config, &mut device, smoltcp::time::Instant::now());
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(gateway_ip.into(), 24)).unwrap();
        });
        let mut sockets = SocketSet::new(vec![]);

        // Build an ARP request: "Who has 192.168.64.1? Tell 192.168.64.2"
        let mut arp_request = Vec::with_capacity(42);
        arp_request.extend_from_slice(&[0xFF; 6]); // dst=broadcast
        arp_request.extend_from_slice(&guest_mac_addr); // src=guest
        arp_request.extend_from_slice(&[0x08, 0x06]); // ARP
        arp_request.extend_from_slice(&[0x00, 0x01]); // HW: Ethernet
        arp_request.extend_from_slice(&[0x08, 0x00]); // Proto: IPv4
        arp_request.push(6); // HLEN
        arp_request.push(4); // PLEN
        arp_request.extend_from_slice(&[0x00, 0x01]); // Op: Request
        arp_request.extend_from_slice(&guest_mac_addr); // Sender MAC
        arp_request.extend_from_slice(&[192, 168, 64, 2]); // Sender IP
        arp_request.extend_from_slice(&[0x00; 6]); // Target MAC
        arp_request.extend_from_slice(&[192, 168, 64, 1]); // Target IP

        // Inject the ARP request directly into the device's rx_queue
        // (bypassing the FD, which is tested separately in smoltcp_device tests).
        device.inject_rx(arp_request);

        let ts = smoltcp::time::Instant::now();
        iface.poll(ts, &mut device, &mut sockets);

        // smoltcp should generate an ARP reply.
        let tx_frames = device.take_tx_pending();
        assert!(
            !tx_frames.is_empty(),
            "smoltcp should generate an ARP reply"
        );

        let reply = &tx_frames[0];
        assert!(reply.len() >= 42, "ARP reply should be at least 42 bytes");
        assert_eq!(&reply[12..14], &[0x08, 0x06], "EtherType should be ARP");
        assert_eq!(&reply[20..22], &[0x00, 0x02], "ARP opcode should be Reply");
        assert_eq!(&reply[22..28], &gateway_mac, "Sender MAC should be gateway");
        assert_eq!(
            &reply[28..32],
            &[192, 168, 64, 1],
            "Sender IP should be gateway"
        );
    }
}
