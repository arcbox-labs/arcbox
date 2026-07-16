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

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use splicetcp::{FdFrameSource, FrameSource};

use crate::darwin::classifier::FrameClassifier;
use crate::darwin::egress::HostEgress;
use crate::darwin::inbound_relay::InboundCommand;
use crate::darwin::tcp_bridge::TcpBridge;
use crate::dhcp::DhcpServer;
use crate::dns::DnsForwarder;

mod fd;
mod guest_tx;
mod intercept;
#[cfg(test)]
mod tests;

use fd::{FdWrapper, set_nonblocking};
use guest_tx::{DeliveryClass, GuestTx, NOBUFS_RETRY_DELAY, drain_cmd_rx, drain_reply_rx};
use intercept::{handle_intercepted_frame, process_inbound_cmd};

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
    pub egress: HostEgress,
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
    /// `egress` and `reply_rx` are created via `HostEgress::new()`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        guest_fd: OwnedFd,
        egress: HostEgress,
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
            egress,
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
            mut egress,
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
        let guest_raw_fd = guest_fd.as_raw_fd();
        set_nonblocking(guest_raw_fd)?;

        // Ingest seam: an FdFrameSource over the (now non-blocking) socketpair
        // feeds raw frames to the classifier. The same fd is owned by the
        // AsyncFd below for readiness; FdFrameSource holds it non-owning.
        let mut source = FdFrameSource::new(guest_raw_fd);

        // Frame classifier — fed frames via the source; it owns no fd.
        let mut device = FrameClassifier::new(gateway_ip, mtu);
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
        // Give guest UDP the same proxy enforcement as TCP: share the fake-IP log
        // + proxy env so the UDP path reverses fake-IPs and honours the SOCKS
        // proxy + bypass list, mirroring the TCP bridge below. (HTTP proxies can't
        // carry UDP, so only a SOCKS proxy actually routes UDP.)
        egress.set_proxy_awareness(dns_log.clone(), proxy_env.clone());
        tcp_bridge.set_proxy_awareness(dns_log.clone(), proxy_env);

        let guest_async = AsyncFd::new(FdWrapper(guest_fd))?;

        // Clone the reply sender for async DNS forwarding tasks.
        let dns_reply_tx = egress.reply_sender();

        let mut guest_mac: Option<[u8; 6]> = None;

        // Guest-bound frame sink: owns the pending queue and the lossless
        // backpressure state machine (see the guest_tx module docs).
        let mut guest_tx = GuestTx::new(frame_sink);

        // Retry driver for an ENOBUFS-blocked backlog. A persistent interval
        // (rather than a per-iteration `sleep`) survives other select! arms
        // firing more often than the retry period — a fresh sleep would be
        // reset every iteration and never complete under load.
        let mut nobufs_retry = tokio::time::interval(NOBUFS_RETRY_DELAY);
        nobufs_retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

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
            let awaits_writable = guest_tx.awaits_writable();
            let awaits_retry = guest_tx.awaits_retry();

            tokio::select! {
                biased;

                () = cancel.cancelled() => {
                    tracing::info!("Network datapath shutting down");
                    break;
                }

                // Drain an EAGAIN-blocked backlog when the guest FD becomes
                // writable. An ENOBUFS-blocked backlog is timer-driven below:
                // write-readiness is not a reliable signal for a full peer
                // receive buffer on a macOS AF_UNIX datagram socket.
                writable = guest_async.writable(), if awaits_writable => {
                    let mut guard = writable?;
                    guest_tx.drain(guest_raw_fd);
                    if guest_tx.awaits_writable() {
                        // Still blocked: clear readiness so the next poll
                        // waits for a fresh writability edge.
                        guard.clear_ready();
                    }
                }

                // Retry an ENOBUFS-blocked backlog after a short delay.
                _ = nobufs_retry.tick(), if awaits_retry => {
                    guest_tx.drain(guest_raw_fd);
                }

                // Guest → Host: read frames, classify, and dispatch.
                readable = guest_async.readable() => {
                    let mut guard = readable?;
                    let prev_mac = guest_mac;
                    // Drain all available frames from the source, classifying each.
                    // This is the FdFrameSource + classify_frame composition that
                    // replaced the classifier's old fd-owning drain_guest_fd.
                    source.drain(|frame| device.classify_frame(frame, &mut guest_mac));
                    // We drained until WouldBlock; clear readiness to avoid
                    // spinning on the biased readable arm.
                    guard.clear_ready();

                    // Record guest MAC the first time we see it so outbound
                    // shim-built frames carry the correct Ethernet destination.
                    if prev_mac.is_none()
                        && let Some(gmac) = guest_mac
                    {
                        tcp_bridge.set_fast_path_macs(gateway_mac, gmac);
                    }

                    // Fast-path intercept: extract TCP data frames for established
                    // fast-path connections and synthesize ACKs inline.
                    let fast_acks = device.drain_fast_path(|frame_data| {
                        tcp_bridge.try_fast_path_intercept(frame_data)
                    });
                    for ack in fast_acks {
                        guest_tx.send(guest_raw_fd, &ack, DeliveryClass::Reliable);
                    }

                    // Handshake intercept: complete in-progress shim handshakes
                    // (guest ACK → PassiveOpen promotion, guest SYN-ACK →
                    // ActiveOpen promotion). Frames that match are consumed
                    // here.
                    let hs_replies = device.drain_handshake(|frame_data| {
                        tcp_bridge.try_complete_handshake(frame_data)
                    });
                    for reply in hs_replies {
                        guest_tx.send(guest_raw_fd, &reply, DeliveryClass::Reliable);
                    }

                    // Flush ARP replies produced inline by the classifier.
                    for reply in device.take_arp_replies() {
                        guest_tx.send(guest_raw_fd, &reply, DeliveryClass::Lossy);
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
                            &mut guest_tx,
                            guest_raw_fd,
                            &mut egress,
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
                            guest_tx.send(guest_raw_fd, &rst, DeliveryClass::Reliable);
                        }
                    }

                }

                // Proxy → Guest: relay reply frames from socket proxy.
                // Always poll — the bounded channel (256) provides natural backpressure
                // to spawned tasks. Gating on backlog depth starved DNS replies.
                Some(reply_frame) = reply_rx.recv() => {
                    guest_tx.send(guest_raw_fd, &reply_frame, DeliveryClass::Lossy);
                }

                // Inbound commands from InboundListenerManager.
                Some(cmd) = cmd_rx.recv() => {
                    process_inbound_cmd(
                        cmd,
                        &mut tcp_bridge,
                        &mut egress,
                        guest_ip,
                        gateway_ip,
                        guest_mac,
                    );
                }

                // Periodic maintenance.
                _ = timer_wheel_tick.tick() => {
                    // Advance the timer wheel and handle expired flow timers.
                    // TODO: Migrate tcp_bridge SYN gate and egress UDP/ICMP
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
                    // Feed expired entries back to egress for cleanup
                    for entry in expired {
                        use crate::timer_wheel::TimerAction;
                        match entry.action {
                            TimerAction::UdpFlowExpiry | TimerAction::IcmpTimeout => {
                                egress.expire_flow(entry.key);
                            }
                            _ => {}
                        }
                    }
                }

                _ = maintenance.tick() => {
                    egress.maintenance();
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
                guest_tx.send(guest_raw_fd, &frame, DeliveryClass::Reliable);
            }

            // 1.5. Drain inbound listener commands so `cmd_rx.recv()` cannot be
            //      starved by the biased readable branch under sustained traffic.
            drain_cmd_rx(
                &mut cmd_rx,
                &mut tcp_bridge,
                &mut egress,
                guest_ip,
                gateway_ip,
                guest_mac,
            );

            // 2. Poll fast-path host streams for inbound data and inject
            //    constructed frames directly to guest — but only when no
            //    backlog is pending. Skipping the poll leaves host-socket
            //    data in the host kernel's receive buffer, closing the
            //    host-side TCP window so the remote sender throttles instead
            //    of the datapath dropping frames (lossless backpressure; the
            //    shim has no retransmission, so a dropped data frame would
            //    stall the connection permanently).
            if guest_tx.has_backlog() {
                guest_tx.stats.gated_polls += 1;
            } else {
                for frame in tcp_bridge.poll_fast_path() {
                    guest_tx.send(guest_raw_fd, &frame, DeliveryClass::Reliable);
                }
            }

            drain_reply_rx(&mut reply_rx, &mut guest_tx, guest_raw_fd);

            // Yield to the tokio runtime so spawned tasks (e.g. host relay
            // read/write) get a chance to run on this worker thread. Without
            // this, the tight synchronous common-tail loop can starve spawned
            // tasks for seconds.
            tokio::task::yield_now().await;
        }

        Ok(())
    }
}
