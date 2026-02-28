//! Async event loop bridging the guest VM network FD to the host network stack.
//!
//! # Datapath
//!
//! ```text
//! Guest VM
//!     ↕ VirtIO (VZ framework)
//! VZFileHandleNetworkDeviceAttachment
//!     ↕ socketpair FD (L2 Ethernet frames)
//! NetworkDatapath (this module)
//!     ├─ ARP 0x0806 → ArpResponder → reply to guest
//!     ├─ IPv4 0x0800
//!     │   ├─ UDP:67 (DHCP) → DhcpServer → reply to guest
//!     │   ├─ UDP:53 to gateway (DNS) → DnsForwarder → reply to guest
//!     │   └─ other → NatEngine outbound → strip L2 → DarwinTun (L3)
//!     └─ other EtherType → drop
//! DarwinTun recv → prepend L2 header → NatEngine inbound → guest FD
//! ```

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use tokio::io::unix::AsyncFd;
use tokio_util::sync::CancellationToken;

use crate::darwin::tun::DarwinTun;
use crate::dhcp::DhcpServer;
use crate::dns::DnsForwarder;
use crate::ethernet::{
    ArpResponder, EtherType, EthernetHeader, build_udp_ip_ethernet, prepend_ethernet_header,
    strip_ethernet_header, ETH_HEADER_LEN,
};
use crate::nat_engine::{NatDirection, NatEngine, NatResult};

/// Maximum Ethernet frame size we handle (jumbo-safe).
const MAX_FRAME_SIZE: usize = 65535;

/// Wraps an `OwnedFd` so it can be registered with `AsyncFd`.
struct FdWrapper(OwnedFd);

impl AsRawFd for FdWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// Async network datapath bridging guest ↔ host through the custom stack.
pub struct NetworkDatapath {
    /// Host end of the socketpair (guest L2 Ethernet frames).
    pub guest_fd: OwnedFd,
    /// Host utun device for L3 I/O to the Internet.
    pub tun: DarwinTun,
    /// NAT engine (operates on full Ethernet frames).
    pub nat_engine: NatEngine,
    /// DHCP server.
    pub dhcp_server: DhcpServer,
    /// DNS forwarder.
    pub dns_forwarder: DnsForwarder,
    /// Gateway MAC address used in L2 headers sent to the guest.
    pub gateway_mac: [u8; 6],
    /// Gateway IP address.
    pub gateway_ip: Ipv4Addr,
    /// ARP responder for the gateway IP.
    pub arp_responder: ArpResponder,
    /// Cancellation token for graceful shutdown.
    pub cancel: CancellationToken,
}

impl NetworkDatapath {
    /// Creates a new datapath.
    ///
    /// `guest_fd` is the host side of the socketpair passed to VZ.
    /// `tun` must already be configured and in non-blocking mode.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        guest_fd: OwnedFd,
        tun: DarwinTun,
        nat_engine: NatEngine,
        dhcp_server: DhcpServer,
        dns_forwarder: DnsForwarder,
        gateway_ip: Ipv4Addr,
        gateway_mac: [u8; 6],
        cancel: CancellationToken,
    ) -> Self {
        let arp_responder = ArpResponder::new(gateway_ip, gateway_mac);
        Self {
            guest_fd,
            tun,
            nat_engine,
            dhcp_server,
            dns_forwarder,
            gateway_mac,
            gateway_ip,
            arp_responder,
            cancel,
        }
    }

    /// Runs the event loop until the cancellation token fires.
    ///
    /// Consumes `self` and destructures to avoid borrow conflicts between
    /// the AsyncFd wrappers (which borrow guest_fd/tun) and the mutable
    /// network processing state (nat_engine, dhcp_server, dns_forwarder).
    ///
    /// # Errors
    ///
    /// Returns an error if the AsyncFd registration fails.
    pub async fn run(self) -> io::Result<()> {
        let NetworkDatapath {
            guest_fd,
            tun,
            mut nat_engine,
            mut dhcp_server,
            mut dns_forwarder,
            gateway_mac,
            gateway_ip,
            arp_responder,
            cancel,
        } = self;

        // Set guest_fd to non-blocking for AsyncFd.
        set_nonblocking(guest_fd.as_raw_fd())?;
        let guest_async = AsyncFd::new(FdWrapper(guest_fd))?;

        // DarwinTun is already non-blocking (set by caller).
        let tun_async = AsyncFd::new(TunWrapper(&tun))?;

        let mut guest_buf = vec![0u8; MAX_FRAME_SIZE];
        let mut tun_buf = vec![0u8; MAX_FRAME_SIZE];
        let mut guest_mac: Option<[u8; 6]> = None;

        tracing::info!("Network datapath started");

        loop {
            tokio::select! {
                biased;

                _ = cancel.cancelled() => {
                    tracing::info!("Network datapath shutting down");
                    break;
                }

                // Guest → Host: read an Ethernet frame from the guest FD.
                readable = guest_async.readable() => {
                    let mut guard = readable?;
                    match guard.try_io(|inner| {
                        fd_read(inner.get_ref().as_raw_fd(), &mut guest_buf)
                    }) {
                        Ok(Ok(n)) if n > 0 => {
                            dispatch_guest_frame(
                                &guest_buf[..n],
                                &guest_async,
                                &tun,
                                &mut nat_engine,
                                &mut dhcp_server,
                                &mut dns_forwarder,
                                &arp_responder,
                                gateway_ip,
                                gateway_mac,
                                &mut guest_mac,
                            );
                        }
                        Ok(Err(e)) if e.kind() != io::ErrorKind::Interrupted => {
                            tracing::warn!("Guest FD read error: {}", e);
                        }
                        _ => {} // WouldBlock, Interrupted, or zero-length read
                    }
                }

                // Host → Guest: read an IP packet from the tun device.
                readable = tun_async.readable() => {
                    let mut guard = readable?;
                    match guard.try_io(|_| {
                        tun.recv_packet(&mut tun_buf)
                    }) {
                        Ok(Ok(n)) if n > 0 => {
                            handle_host_packet(
                                &tun_buf[..n],
                                &guest_async,
                                &mut nat_engine,
                                gateway_mac,
                                guest_mac.unwrap_or([0xFF; 6]),
                            );
                        }
                        Ok(Err(e))
                            if e.kind() != io::ErrorKind::Interrupted
                                && e.kind() != io::ErrorKind::WouldBlock =>
                        {
                            tracing::warn!("Tun read error: {}", e);
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(())
    }
}

// ============================================================================
// Free functions — operate on borrowed fields to avoid borrow conflicts
// ============================================================================

/// Dispatches an Ethernet frame received from the guest.
#[allow(clippy::too_many_arguments)]
fn dispatch_guest_frame(
    frame: &[u8],
    guest_async: &AsyncFd<FdWrapper>,
    tun: &DarwinTun,
    nat_engine: &mut NatEngine,
    dhcp_server: &mut DhcpServer,
    dns_forwarder: &mut DnsForwarder,
    arp_responder: &ArpResponder,
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
    guest_mac: &mut Option<[u8; 6]>,
) {
    let hdr = match EthernetHeader::parse(frame) {
        Some(h) => h,
        None => return,
    };

    // Learn the guest MAC from the source address.
    learn_guest_mac(hdr.src_mac, guest_mac);

    match hdr.ethertype {
        EtherType::Arp => {
            if let Some(reply) = arp_responder.handle_arp(frame) {
                write_to_guest(guest_async, &reply);
            }
        }
        EtherType::Ipv4 => {
            handle_ipv4_from_guest(
                frame,
                guest_async,
                tun,
                nat_engine,
                dhcp_server,
                dns_forwarder,
                gateway_ip,
                gateway_mac,
                guest_mac.unwrap_or([0xFF; 6]),
            );
        }
        _ => {
            tracing::trace!("Dropping frame with EtherType {:?}", hdr.ethertype);
        }
    }
}

/// Handles an IPv4 frame from the guest. Intercepts DHCP and DNS;
/// everything else goes through NAT to the tun.
#[allow(clippy::too_many_arguments)]
fn handle_ipv4_from_guest(
    frame: &[u8],
    guest_async: &AsyncFd<FdWrapper>,
    tun: &DarwinTun,
    nat_engine: &mut NatEngine,
    dhcp_server: &mut DhcpServer,
    dns_forwarder: &mut DnsForwarder,
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
) {
    // Need at least Ethernet(14) + IP(20) + UDP/TCP(8) = 42 bytes.
    if frame.len() < 42 {
        return;
    }

    let ip_start = ETH_HEADER_LEN;
    let protocol = frame[ip_start + 9];
    let ihl = ((frame[ip_start] & 0x0F) as usize) * 4;
    let l4_start = ip_start + ihl;

    // Only intercept UDP (protocol 17) for DHCP and DNS.
    if protocol == 17 && l4_start + 8 <= frame.len() {
        let dst_port = u16::from_be_bytes([frame[l4_start + 2], frame[l4_start + 3]]);
        let dst_ip = Ipv4Addr::new(
            frame[ip_start + 16],
            frame[ip_start + 17],
            frame[ip_start + 18],
            frame[ip_start + 19],
        );

        // DHCP: client sends to server port 67.
        if dst_port == 67 {
            handle_dhcp(
                frame,
                l4_start,
                guest_async,
                dhcp_server,
                gateway_ip,
                gateway_mac,
                guest_mac,
            );
            return;
        }

        // DNS: guest sends to gateway IP on port 53.
        if dst_port == 53 && dst_ip == gateway_ip {
            handle_dns(
                frame,
                l4_start,
                guest_async,
                dns_forwarder,
                gateway_ip,
                gateway_mac,
                guest_mac,
            );
            return;
        }
    }

    // General traffic: NAT outbound then send to tun.
    nat_and_send_to_tun(frame, tun, nat_engine);
}

/// Handles a DHCP packet from the guest.
fn handle_dhcp(
    frame: &[u8],
    l4_start: usize,
    guest_async: &AsyncFd<FdWrapper>,
    dhcp_server: &mut DhcpServer,
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
) {
    let dhcp_start = l4_start + 8; // Skip UDP header
    if dhcp_start >= frame.len() {
        return;
    }

    let dhcp_data = &frame[dhcp_start..];
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
            write_to_guest(guest_async, &reply_frame);
            tracing::debug!("Sent DHCP response to guest");
        }
        Ok(None) => {} // No response needed (e.g. RELEASE)
        Err(e) => tracing::warn!("DHCP handling error: {}", e),
    }
}

/// Handles a DNS query from the guest.
fn handle_dns(
    frame: &[u8],
    l4_start: usize,
    guest_async: &AsyncFd<FdWrapper>,
    dns_forwarder: &mut DnsForwarder,
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
) {
    let dns_start = l4_start + 8; // Skip UDP header
    if dns_start >= frame.len() {
        return;
    }

    let src_ip = Ipv4Addr::new(
        frame[ETH_HEADER_LEN + 12],
        frame[ETH_HEADER_LEN + 13],
        frame[ETH_HEADER_LEN + 14],
        frame[ETH_HEADER_LEN + 15],
    );
    let src_port = u16::from_be_bytes([frame[l4_start], frame[l4_start + 1]]);

    let dns_data = &frame[dns_start..];
    match dns_forwarder.handle_query(dns_data) {
        Ok(response) => {
            let reply_frame = build_udp_ip_ethernet(
                gateway_ip, src_ip, 53, src_port, &response, gateway_mac, guest_mac,
            );
            write_to_guest(guest_async, &reply_frame);
            tracing::debug!("Sent DNS response to guest");
        }
        Err(e) => tracing::warn!("DNS handling error: {}", e),
    }
}

/// NAT-translates an outbound frame and sends the L3 packet through the tun.
fn nat_and_send_to_tun(frame: &[u8], tun: &DarwinTun, nat_engine: &mut NatEngine) {
    let mut frame_buf = frame.to_vec();

    // SAFETY: frame_buf contains a valid Ethernet + IPv4 header (validated by caller).
    let result = unsafe { nat_engine.translate(&mut frame_buf, NatDirection::Outbound) };

    match result {
        Ok(NatResult::Translated | NatResult::PassThrough) => {
            let ip_packet = strip_ethernet_header(&frame_buf);
            if !ip_packet.is_empty() {
                if let Err(e) = tun.send_packet(ip_packet) {
                    if e.kind() != io::ErrorKind::WouldBlock {
                        tracing::warn!("Tun send error: {}", e);
                    }
                }
            }
        }
        Ok(NatResult::Dropped) => {
            tracing::trace!("NAT outbound: packet dropped");
        }
        Err(e) => {
            tracing::trace!("NAT outbound error: {}", e);
        }
    }
}

/// Handles an IP packet received from the tun (host network stack).
fn handle_host_packet(
    ip_packet: &[u8],
    guest_async: &AsyncFd<FdWrapper>,
    nat_engine: &mut NatEngine,
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
) {
    let mut frame = prepend_ethernet_header(ip_packet, guest_mac, gateway_mac);

    // SAFETY: the frame was just constructed with a valid Ethernet + IP header.
    let result = unsafe { nat_engine.translate(&mut frame, NatDirection::Inbound) };

    match result {
        Ok(NatResult::Translated | NatResult::PassThrough) => {
            write_to_guest(guest_async, &frame);
        }
        Ok(NatResult::Dropped) => {
            tracing::trace!("NAT inbound: packet dropped (no connection)");
        }
        Err(e) => {
            tracing::trace!("NAT inbound error: {}", e);
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Writes a frame to the guest FD (best-effort, non-blocking).
fn write_to_guest(guest_async: &AsyncFd<FdWrapper>, data: &[u8]) {
    let fd = guest_async.get_ref().as_raw_fd();
    // SAFETY: writing from our buffer to a valid socketpair fd.
    let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
    if n < 0 {
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::WouldBlock {
            tracing::warn!("Guest write error: {}", err);
        }
    }
}

/// Learns the guest MAC from a frame's source address.
fn learn_guest_mac(mac: [u8; 6], guest_mac: &mut Option<[u8; 6]>) {
    // Skip broadcast/multicast
    if mac[0] & 0x01 != 0 || mac == [0; 6] {
        return;
    }
    if guest_mac.is_none() {
        tracing::info!(
            "Learned guest MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        );
    }
    *guest_mac = Some(mac);
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

/// Wrapper to make `DarwinTun` usable with `AsyncFd` (borrows the tun).
struct TunWrapper<'a>(&'a DarwinTun);

impl AsRawFd for TunWrapper<'_> {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
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
