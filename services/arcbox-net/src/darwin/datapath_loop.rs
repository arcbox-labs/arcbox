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
//!     │   ├─ ICMP → IcmpProxy (raw socket) → reply to guest
//!     │   ├─ UDP → UdpProxy (host UdpSocket per flow) → reply to guest
//!     │   └─ TCP → TcpProxy (host TcpStream + TCP state) → reply to guest
//!     └─ other EtherType → drop
//! ```
//!
//! Outbound traffic is proxied through host OS sockets instead of a utun +
//! pf NAT. This bypasses kernel routing, VPN interference, and pf issues.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::darwin::socket_proxy::SocketProxy;
use crate::dhcp::DhcpServer;
use crate::dns::DnsForwarder;
use crate::ethernet::{
    ArpResponder, ETH_HEADER_LEN, EtherType, EthernetHeader, build_udp_ip_ethernet,
};

/// Maximum Ethernet frame size we handle (jumbo-safe).
const MAX_FRAME_SIZE: usize = 65535;

/// Wraps an `OwnedFd` so it can be registered with `AsyncFd`.
struct FdWrapper(OwnedFd);

impl AsRawFd for FdWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// Async network datapath bridging guest ↔ host through socket proxying.
///
/// Outbound traffic is dispatched to protocol-specific host sockets (ICMP,
/// UDP, TCP) instead of being forwarded through a utun device. Replies
/// arrive on the `reply_rx` channel as complete L2 Ethernet frames.
pub struct NetworkDatapath {
    /// Host end of the socketpair (guest L2 Ethernet frames).
    pub guest_fd: OwnedFd,
    /// Socket proxy for ICMP/UDP/TCP traffic.
    pub socket_proxy: SocketProxy,
    /// Channel receiving L2 reply frames from the socket proxy.
    pub reply_rx: mpsc::Receiver<Vec<u8>>,
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
    /// `socket_proxy` and `reply_rx` are created via `SocketProxy::new()`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        guest_fd: OwnedFd,
        socket_proxy: SocketProxy,
        reply_rx: mpsc::Receiver<Vec<u8>>,
        dhcp_server: DhcpServer,
        dns_forwarder: DnsForwarder,
        gateway_ip: Ipv4Addr,
        gateway_mac: [u8; 6],
        cancel: CancellationToken,
    ) -> Self {
        let arp_responder = ArpResponder::new(gateway_ip, gateway_mac);
        Self {
            guest_fd,
            socket_proxy,
            reply_rx,
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

        let mut guest_buf = vec![0u8; MAX_FRAME_SIZE];
        let mut guest_mac: Option<[u8; 6]> = None;

        // Periodic maintenance interval for cleaning up stale flows.
        let mut maintenance = tokio::time::interval(std::time::Duration::from_secs(30));
        maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        tracing::info!("Network datapath started (socket proxy mode)");

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
                                &mut socket_proxy,
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

                // Proxy → Guest: relay reply frames from socket proxy.
                Some(reply_frame) = reply_rx.recv() => {
                    write_to_guest(&guest_async, &reply_frame);
                }

                // Periodic maintenance.
                _ = maintenance.tick() => {
                    socket_proxy.maintenance();
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
    socket_proxy: &mut SocketProxy,
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

    tracing::info!(
        "Guest frame: ethertype={:?} len={} src={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        hdr.ethertype,
        frame.len(),
        hdr.src_mac[0],
        hdr.src_mac[1],
        hdr.src_mac[2],
        hdr.src_mac[3],
        hdr.src_mac[4],
        hdr.src_mac[5],
    );

    match hdr.ethertype {
        EtherType::Arp => {
            if let Some(reply) = arp_responder.handle_arp(frame) {
                tracing::info!("Sending ARP reply ({} bytes)", reply.len());
                write_to_guest(guest_async, &reply);
            }
        }
        EtherType::Ipv4 => {
            handle_ipv4_from_guest(
                frame,
                guest_async,
                socket_proxy,
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
/// everything else goes through the socket proxy.
#[allow(clippy::too_many_arguments)]
fn handle_ipv4_from_guest(
    frame: &[u8],
    guest_async: &AsyncFd<FdWrapper>,
    socket_proxy: &mut SocketProxy,
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
            tracing::info!("DHCP packet from guest ({} bytes)", frame.len());
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

    // All other traffic: proxy through host sockets.
    tracing::info!(
        "Socket proxy: protocol={} dst_port={}",
        protocol,
        if (protocol == 17 || protocol == 6) && l4_start + 4 <= frame.len() {
            u16::from_be_bytes([frame[l4_start + 2], frame[l4_start + 3]])
        } else {
            0
        }
    );
    socket_proxy.handle_outbound(frame, guest_mac);
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
    tracing::info!(
        "DHCP payload: {} bytes starting at offset {}",
        dhcp_data.len(),
        dhcp_start
    );
    match dhcp_server.handle_packet(dhcp_data) {
        Ok(Some(response)) => {
            tracing::info!("DHCP response generated: {} bytes", response.len());
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
            write_to_guest(guest_async, &reply_frame);
        }
        Ok(None) => {
            tracing::info!("DHCP: no response needed");
        }
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
                gateway_ip,
                src_ip,
                53,
                src_port,
                &response,
                gateway_mac,
                guest_mac,
            );
            write_to_guest(guest_async, &reply_frame);
            tracing::debug!("Sent DNS response to guest");
        }
        Err(e) => tracing::warn!("DNS handling error: {}", e),
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
        if err.kind() == io::ErrorKind::WouldBlock {
            tracing::warn!("Guest write WouldBlock: {} bytes dropped", data.len());
        } else {
            tracing::warn!("Guest write error: {}", err);
        }
    } else {
        tracing::debug!("Guest write OK: {}/{} bytes", n, data.len());
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
    fn test_learn_guest_mac_unicast() {
        let mut mac = None;
        learn_guest_mac([0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE], &mut mac);
        assert_eq!(mac, Some([0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]));
    }

    #[test]
    fn test_learn_guest_mac_ignores_broadcast() {
        let mut mac = None;
        // Multicast bit set (LSB of first octet = 1)
        learn_guest_mac([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], &mut mac);
        assert!(mac.is_none(), "Should ignore broadcast MAC");
    }

    #[test]
    fn test_learn_guest_mac_ignores_multicast() {
        let mut mac = None;
        learn_guest_mac([0x01, 0x00, 0x5E, 0x00, 0x00, 0x01], &mut mac);
        assert!(mac.is_none(), "Should ignore multicast MAC");
    }

    #[test]
    fn test_learn_guest_mac_ignores_zero() {
        let mut mac = None;
        learn_guest_mac([0; 6], &mut mac);
        assert!(mac.is_none(), "Should ignore all-zero MAC");
    }

    #[test]
    fn test_learn_guest_mac_updates() {
        let mut mac = None;
        learn_guest_mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], &mut mac);
        learn_guest_mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x02], &mut mac);
        assert_eq!(mac, Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]));
    }

    #[test]
    fn test_set_nonblocking() {
        let (a, _b) = socketpair();
        set_nonblocking(a.as_raw_fd()).unwrap();

        // Verify O_NONBLOCK is set.
        // SAFETY: fcntl on a valid fd.
        let flags = unsafe { libc::fcntl(a.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::O_NONBLOCK, 0, "O_NONBLOCK should be set");
    }

    #[test]
    fn test_fd_read_write_roundtrip() {
        let (a, b) = socketpair();
        let data = b"hello network";

        // Write to one end.
        // SAFETY: writing from valid buffer to valid fd.
        let n = unsafe { libc::write(b.as_raw_fd(), data.as_ptr().cast(), data.len()) };
        assert_eq!(n as usize, data.len());

        // Read from the other end.
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

        // Read from the other end (blocking is fine, data was just written).
        let mut buf = [0u8; 128];
        let n = fd_read(b.as_raw_fd(), &mut buf).unwrap();
        assert_eq!(n, frame.len());
        assert_eq!(&buf[..n], frame.as_slice());
    }

    #[tokio::test]
    async fn test_arp_response_via_socketpair() {
        let (host_fd, guest_fd) = socketpair();
        set_nonblocking(host_fd.as_raw_fd()).unwrap();
        let host_async = AsyncFd::new(FdWrapper(host_fd)).unwrap();

        let gateway_ip = Ipv4Addr::new(192, 168, 64, 1);
        let gateway_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let guest_mac_addr = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

        let arp_responder = ArpResponder::new(gateway_ip, gateway_mac);

        // Build an ARP request: "Who has 192.168.64.1? Tell 192.168.64.2"
        let mut arp_request = Vec::with_capacity(42);
        // Ethernet header: dst=broadcast, src=guest, type=ARP
        arp_request.extend_from_slice(&[0xFF; 6]); // dst
        arp_request.extend_from_slice(&guest_mac_addr); // src
        arp_request.extend_from_slice(&[0x08, 0x06]); // ARP
        // ARP payload
        arp_request.extend_from_slice(&[0x00, 0x01]); // Hardware: Ethernet
        arp_request.extend_from_slice(&[0x08, 0x00]); // Protocol: IPv4
        arp_request.push(6); // Hardware addr len
        arp_request.push(4); // Protocol addr len
        arp_request.extend_from_slice(&[0x00, 0x01]); // Opcode: Request
        arp_request.extend_from_slice(&guest_mac_addr); // Sender MAC
        arp_request.extend_from_slice(&[192, 168, 64, 2]); // Sender IP
        arp_request.extend_from_slice(&[0x00; 6]); // Target MAC (unknown)
        arp_request.extend_from_slice(&[192, 168, 64, 1]); // Target IP (gateway)

        // The ARP responder should generate a reply.
        let reply = arp_responder.handle_arp(&arp_request);
        assert!(reply.is_some(), "ARP responder should reply for gateway IP");

        let reply = reply.unwrap();
        write_to_guest(&host_async, &reply);

        // Read the reply from the guest side.
        let mut buf = [0u8; 256];
        let n = fd_read(guest_fd.as_raw_fd(), &mut buf).unwrap();
        assert!(n >= 42, "ARP reply should be at least 42 bytes");

        // Verify it's an ARP reply (opcode 2).
        assert_eq!(&buf[12..14], &[0x08, 0x06], "EtherType should be ARP");
        assert_eq!(&buf[20..22], &[0x00, 0x02], "ARP opcode should be Reply");

        // Verify the sender MAC in the reply is our gateway MAC.
        assert_eq!(&buf[22..28], &gateway_mac);
        // Verify the sender IP is the gateway IP.
        assert_eq!(&buf[28..32], &[192, 168, 64, 1]);
    }
}
