//! ICMP egress: one host ICMP datagram socket per echo.
//!
//! macOS allows unprivileged `SOCK_DGRAM` + `IPPROTO_ICMP`; if even that is
//! denied the proxy disables ICMP (once, with a warning). The kernel rewrites the
//! ICMP identifier on DGRAM sockets, so the guest's original id is restored on
//! Echo Reply before the reply frame is built.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use socket2::{Domain, Protocol, Type};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use arcbox_packet::ethernet::ETH_HEADER_LEN;

/// ICMP proxy: ICMP socket per echo.
pub(super) struct IcmpProxy {
    reply_tx: mpsc::Sender<Vec<u8>>,
    gateway_mac: [u8; 6],
    /// When true, ICMP proxying is disabled due to persistent permission errors.
    disabled: Arc<AtomicBool>,
    /// Ensures permission-denied warning is emitted only once.
    permission_warned: Arc<AtomicBool>,
}

impl IcmpProxy {
    pub(super) fn new(reply_tx: mpsc::Sender<Vec<u8>>, gateway_mac: [u8; 6]) -> Self {
        Self {
            reply_tx,
            gateway_mac,
            disabled: Arc::new(AtomicBool::new(false)),
            permission_warned: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Proxies an ICMP packet from the guest to the host.
    pub(super) fn proxy_icmp(&self, frame: &[u8], guest_mac: [u8; 6], cancel: CancellationToken) {
        if self.disabled.load(Ordering::Relaxed) {
            tracing::trace!("ICMP proxy: disabled, dropping frame");
            return;
        }
        tracing::trace!("ICMP proxy: received frame ({} bytes)", frame.len());

        let ip_start = ETH_HEADER_LEN;
        let ihl = ((frame[ip_start] & 0x0F) as usize) * 4;
        let icmp_start = ip_start + ihl;

        if frame.len() < icmp_start + 8 {
            return;
        }

        let src_ip = Ipv4Addr::new(
            frame[ip_start + 12],
            frame[ip_start + 13],
            frame[ip_start + 14],
            frame[ip_start + 15],
        );
        let dst_ip = Ipv4Addr::new(
            frame[ip_start + 16],
            frame[ip_start + 17],
            frame[ip_start + 18],
            frame[ip_start + 19],
        );

        let icmp_payload = frame[icmp_start..].to_vec();
        // Save the guest's original ICMP identifier (bytes 4-5). macOS DGRAM
        // ICMP sockets rewrite this with a kernel-internal socket ID, so the
        // reply will carry the wrong value. We patch it back before forwarding.
        let orig_icmp_id: [u8; 2] = if icmp_payload.len() >= 6 {
            [icmp_payload[4], icmp_payload[5]]
        } else {
            [0, 0]
        };
        let reply_tx = self.reply_tx.clone();
        let gateway_mac = self.gateway_mac;
        let disabled = Arc::clone(&self.disabled);
        let permission_warned = Arc::clone(&self.permission_warned);

        tokio::spawn(async move {
            // On modern macOS, SOCK_RAW for ICMP requires elevated privileges.
            // Prefer SOCK_DGRAM + IPPROTO_ICMP to support unprivileged daemon.
            let icmp_socket = match socket2::Socket::new(
                Domain::IPV4,
                Type::DGRAM,
                Some(Protocol::ICMPV4),
            ) {
                Ok(s) => s,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::PermissionDenied {
                        disabled.store(true, Ordering::Relaxed);
                        if !permission_warned.swap(true, Ordering::Relaxed) {
                            tracing::warn!(
                                "ICMP proxy disabled: failed to create ICMP datagram socket: {}",
                                e
                            );
                        }
                    } else {
                        tracing::debug!(
                            "ICMP proxy: failed to create ICMP datagram socket (will retry): {}",
                            e
                        );
                    }
                    return;
                }
            };

            icmp_socket.set_nonblocking(true).ok();
            let dst_addr: SocketAddr = SocketAddrV4::new(dst_ip, 0).into();

            match icmp_socket.send_to(&icmp_payload, &dst_addr.into()) {
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("ICMP proxy: sendto {} -> {} failed: {}", src_ip, dst_ip, e);
                    return;
                }
            }

            // Wait for reply using AsyncFd on the ICMP socket.
            let async_fd = match AsyncFd::new(RawSocketWrapper(icmp_socket)) {
                Ok(fd) => fd,
                Err(e) => {
                    tracing::warn!("ICMP proxy: AsyncFd failed: {}", e);
                    return;
                }
            };

            let mut buf = vec![0u8; 65535];
            let recv_fut = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    let readable = async_fd.readable().await;
                    match readable {
                        Ok(mut guard) => {
                            match guard.try_io(|inner| {
                                // SAFETY: reading into valid buffer from a raw socket fd.
                                let n = unsafe {
                                    libc::recv(
                                        inner.get_ref().as_raw_fd(),
                                        buf.as_mut_ptr().cast(),
                                        buf.len(),
                                        0,
                                    )
                                };
                                if n < 0 {
                                    Err(std::io::Error::last_os_error())
                                } else {
                                    Ok(n as usize)
                                }
                            }) {
                                Ok(Ok(n)) if n > 0 => return Ok(n),
                                Ok(Err(e)) => return Err(e),
                                _ => {} // WouldBlock, retry
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
            });

            // Cancel promptly on datapath shutdown instead of waiting the
            // full 10 s recv timeout.
            let recv = tokio::select! {
                r = recv_fut => r,
                () = cancel.cancelled() => return,
            };

            match recv {
                Ok(Ok(n)) if n > 0 => {
                    let reply_packet = &buf[..n];
                    // Extract the ICMP payload from the reply. macOS DGRAM
                    // ICMP sockets return the full IPv4 packet whose dst IP
                    // is the *host's* real address — not the guest's. Always
                    // rebuild the frame with the correct src/dst so the guest
                    // network stack accepts it.
                    let mut icmp_data = if looks_like_ipv4_icmp(reply_packet) {
                        let ihl = ((reply_packet[0] & 0x0F) as usize) * 4;
                        reply_packet[ihl..].to_vec()
                    } else {
                        reply_packet.to_vec()
                    };
                    // Restore the guest's original ICMP identifier that macOS
                    // replaced with its kernel-internal socket ID. Only patch
                    // Echo Reply (type 0) — bytes 4-5 are the identifier field
                    // only for Echo; other ICMP types use them for different
                    // purposes (e.g., redirect gateway address).
                    if icmp_data.len() >= 6 && icmp_data[0] == 0 {
                        icmp_data[4] = orig_icmp_id[0];
                        icmp_data[5] = orig_icmp_id[1];
                    }
                    let reply_frame = build_icmp_ipv4_ethernet(
                        dst_ip, // original dst becomes reply src
                        src_ip, // original src (guest) becomes reply dst
                        &icmp_data,
                        gateway_mac,
                        guest_mac,
                    );
                    if reply_tx.send(reply_frame).await.is_err() {
                        tracing::warn!("ICMP proxy: reply_tx channel closed");
                    }
                }
                _ => {
                    tracing::trace!(
                        "ICMP proxy: no reply (timeout/error) for {} -> {}",
                        src_ip,
                        dst_ip
                    );
                }
            }
        });
    }
}

/// Wrapper to make `socket2::Socket` usable with `AsyncFd`.
struct RawSocketWrapper(socket2::Socket);

impl AsRawFd for RawSocketWrapper {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
}

/// Returns true when the payload appears to be a complete IPv4 ICMP packet.
fn looks_like_ipv4_icmp(packet: &[u8]) -> bool {
    if packet.len() < 20 {
        return false;
    }
    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0F) as usize * 4;
    version == 4 && ihl >= 20 && packet.len() >= ihl && packet[9] == 1
}

/// Builds an Ethernet frame containing an IPv4 ICMP packet.
fn build_icmp_ipv4_ethernet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    icmp_payload: &[u8],
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
) -> Vec<u8> {
    let ip_total_len = 20 + icmp_payload.len();
    let frame_len = ETH_HEADER_LEN + ip_total_len;
    let mut frame = vec![0u8; frame_len];

    // Ethernet header
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // IPv4 header (20 bytes, no options)
    let ip_start = ETH_HEADER_LEN;
    let ip = &mut frame[ip_start..ip_start + 20];
    ip[0] = 0x45; // Version 4, IHL 5
    ip[2..4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    ip[8] = 64; // TTL
    ip[9] = 1; // Protocol: ICMP
    ip[12..16].copy_from_slice(&src_ip.octets());
    ip[16..20].copy_from_slice(&dst_ip.octets());
    let ip_cksum = ipv4_checksum(ip);
    ip[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // ICMP payload
    let icmp_start = ETH_HEADER_LEN + 20;
    frame[icmp_start..].copy_from_slice(icmp_payload);

    // Recompute ICMP checksum when header is present.
    if icmp_payload.len() >= 4 {
        frame[icmp_start + 2] = 0;
        frame[icmp_start + 3] = 0;
        let icmp_cksum = internet_checksum(&frame[icmp_start..]);
        frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_cksum.to_be_bytes());
    }

    frame
}

/// Computes RFC 1071 checksum over bytes.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Computes IPv4 header checksum while skipping the checksum field itself.
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        if i != 10 {
            sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
        }
        i += 2;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use super::IcmpProxy;
    use crate::egress::ETH_HEADER_LEN;

    const GW_MAC: [u8; 6] = [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x01];
    const GUEST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x99];
    const GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 64, 2);
    /// Distinctive so a reply carrying the kernel's rewritten value is
    /// unmistakable rather than coincidentally equal.
    const ECHO_ID: [u8; 2] = [0x5A, 0xC3];
    const ECHO_SEQ: [u8; 2] = [0x00, 0x07];

    /// Ethernet + IPv4 + ICMP echo request addressed to `dst`.
    fn echo_request_frame(dst: Ipv4Addr) -> Vec<u8> {
        let mut icmp = vec![
            8,
            0, // type 8 (echo request), code 0
            0,
            0, // checksum, filled in below
            ECHO_ID[0],
            ECHO_ID[1],
            ECHO_SEQ[0],
            ECHO_SEQ[1],
        ];
        icmp.extend_from_slice(b"arcbox-icmp-probe");
        let checksum = super::internet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

        let total_len = (20 + icmp.len()) as u16;
        let mut frame = Vec::with_capacity(ETH_HEADER_LEN + total_len as usize);
        frame.extend_from_slice(&GW_MAC); // dst MAC (the gateway)
        frame.extend_from_slice(&GUEST_MAC); // src MAC
        frame.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4

        frame.extend_from_slice(&[0x45, 0x00]); // v4, IHL 5, DSCP 0
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]); // id, flags/frag
        frame.extend_from_slice(&[64, 1]); // TTL, protocol ICMP
        frame.extend_from_slice(&[0x00, 0x00]); // header checksum (unchecked here)
        frame.extend_from_slice(&GUEST_IP.octets());
        frame.extend_from_slice(&dst.octets());
        frame.extend_from_slice(&icmp);
        frame
    }

    /// An echo request proxied to loopback comes back as an echo reply that
    /// still carries the guest's own identifier and sequence.
    ///
    /// `test_icmp_identifier_restore` covers the patch arithmetic on a
    /// hand-built packet; nothing exercised the socket path that makes the
    /// patch necessary in the first place. macOS `SOCK_DGRAM`+`IPPROTO_ICMP`
    /// rewrites the identifier with a kernel-internal socket id, so a reply
    /// arriving with `ECHO_ID` intact is the whole point.
    ///
    /// Ignored because it needs an ICMP datagram socket. That is unprivileged
    /// on macOS but commonly unavailable in container-based CI, where the
    /// proxy disables itself on `PermissionDenied` and this would time out —
    /// a sandbox artifact, not a defect worth failing a build over.
    #[tokio::test]
    #[ignore = "needs an unprivileged ICMP datagram socket; run locally or on the e2e runner"]
    async fn echo_request_round_trips_with_the_guest_identifier() {
        let (tx, mut rx) = mpsc::channel(8);
        let proxy = IcmpProxy::new(tx, GW_MAC);

        let frame = echo_request_frame(Ipv4Addr::LOCALHOST);
        proxy.proxy_icmp(&frame, GUEST_MAC, CancellationToken::new());

        let reply = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("an echo reply should arrive within 10s")
            .expect("reply channel stayed open");

        let ip_start = ETH_HEADER_LEN;
        let ihl = ((reply[ip_start] & 0x0F) as usize) * 4;
        let icmp = &reply[ip_start + ihl..];

        assert_eq!(icmp[0], 0, "reply must be ICMP type 0 (echo reply)");
        assert_eq!(
            &icmp[4..6],
            &ECHO_ID,
            "the guest's identifier must be restored, not the kernel's rewritten one"
        );
        assert_eq!(
            &icmp[6..8],
            &ECHO_SEQ,
            "the sequence number must survive the round trip"
        );
        assert_eq!(
            &reply[..6],
            &GUEST_MAC,
            "the reply frame must be addressed back to the guest"
        );
    }

    /// Verifies that the ICMP identifier restoration logic patches Echo Reply
    /// (type 0) packets but leaves other ICMP types untouched.
    #[test]
    fn test_icmp_identifier_restore() {
        // Build a minimal ICMP Echo Reply (type=0, code=0) with a "wrong"
        // identifier that simulates what macOS DGRAM ICMP sockets return.
        let orig_icmp_id: [u8; 2] = [0xAA, 0xBB];
        let wrong_id: [u8; 2] = [0x00, 0x42]; // kernel-rewritten value

        // ICMP Echo Reply: [type, code, checksum(2), id(2), seq(2), ...]
        let mut icmp_data: Vec<u8> = vec![
            0x00, // type: Echo Reply
            0x00, // code: 0
            0x00,
            0x00, // checksum (placeholder)
            wrong_id[0],
            wrong_id[1], // identifier (wrong)
            0x00,
            0x01, // sequence number
        ];

        // Apply the same patching logic used in proxy_icmp.
        if icmp_data.len() >= 6 && icmp_data[0] == 0 {
            icmp_data[4] = orig_icmp_id[0];
            icmp_data[5] = orig_icmp_id[1];
        }

        assert_eq!(
            [icmp_data[4], icmp_data[5]],
            orig_icmp_id,
            "Echo Reply identifier should be restored to the original guest value"
        );

        // Build an ICMP Destination Unreachable (type=3, code=1) — should NOT
        // be patched because bytes 4-5 have a different meaning.
        let mut icmp_unreach: Vec<u8> = vec![
            0x03, // type: Destination Unreachable
            0x01, // code: Host Unreachable
            0x00, 0x00, // checksum (placeholder)
            0x00, 0x00, // unused (bytes 4-5)
            0x00, 0x00, // next-hop MTU (bytes 6-7)
        ];

        let before = [icmp_unreach[4], icmp_unreach[5]];

        // Same patching logic — should be a no-op for type != 0.
        if icmp_unreach.len() >= 6 && icmp_unreach[0] == 0 {
            icmp_unreach[4] = orig_icmp_id[0];
            icmp_unreach[5] = orig_icmp_id[1];
        }

        assert_eq!(
            [icmp_unreach[4], icmp_unreach[5]],
            before,
            "Non-Echo ICMP types must not have their identifier bytes patched"
        );
    }
}
