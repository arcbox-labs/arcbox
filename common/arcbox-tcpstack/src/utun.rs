//! macOS `utun` endpoint: a [`FrameSource`] and sink over a host `utun` fd.
//!
//! macOS frames each `utun` packet with a 4-byte address-family header (the
//! `AF_INET`/`AF_INET6` value in host byte order). [`UtunFrameSource`] strips
//! it on read; [`UtunSink`] prepends it on write. Both operate on a raw,
//! non-owning fd — open and configure the device with
//! `arcbox_net::darwin::DarwinTun` (which requires no root to create, but root
//! to assign addresses / install a route), then hand its fd here.
//!
//! [`UtunFrameSource`] yields bare IP packets (L3); wrap it with
//! [`L3ToL2Source`](crate::shim::L3ToL2Source) to feed the L2 classifier.

use std::io;
use std::os::fd::RawFd;

use crate::frame_source::FrameSource;
use crate::shim::l2_to_l3;

/// The 4-byte address-family header macOS prepends to each `utun` packet.
const AF_HEADER_SIZE: usize = 4;

/// Largest IP packet we read from the device in one shot.
const MAX_IP_PACKET: usize = 65535;

/// A [`FrameSource`] over a macOS `utun` fd, yielding bare IP packets.
///
/// The 4-byte AF header is stripped on each read via `readv`. The fd is not
/// owned (keep the owning [`DarwinTun`](arcbox_net) alive) and must be
/// non-blocking.
pub struct UtunFrameSource {
    fd: RawFd,
    ip_buf: Vec<u8>,
}

impl UtunFrameSource {
    /// Wraps a (non-blocking) `utun` fd.
    #[must_use]
    pub fn new(fd: RawFd) -> Self {
        Self {
            fd,
            ip_buf: vec![0u8; MAX_IP_PACKET],
        }
    }
}

impl FrameSource for UtunFrameSource {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    fn drain(&mut self, mut f: impl FnMut(&[u8])) {
        loop {
            match utun_read(self.fd, &mut self.ip_buf) {
                Ok(n) if n > 0 => f(&self.ip_buf[..n]),
                Ok(_) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    tracing::warn!("utun read error: {e}");
                    break;
                }
            }
        }
    }
}

/// Writes L2 frames destined for the "guest" back to the `utun` as IP packets.
///
/// The synthetic Ethernet header is stripped via [`l2_to_l3`] (ARP / non-IPv4
/// frames have no L3 meaning and are dropped); the 4-byte AF header is then
/// prepended.
pub struct UtunSink {
    fd: RawFd,
}

impl UtunSink {
    /// Wraps a `utun` fd for egress.
    #[must_use]
    pub fn new(fd: RawFd) -> Self {
        Self { fd }
    }

    /// Writes one L2 frame to the `utun`. Returns `Ok(false)` if the frame had
    /// no L3 representation (ARP / non-IPv4) and was dropped.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying `writev` fails.
    pub fn send_l2_frame(&self, frame: &[u8]) -> io::Result<bool> {
        let Some(ip) = l2_to_l3(frame) else {
            return Ok(false);
        };
        utun_write(self.fd, ip)?;
        Ok(true)
    }
}

/// `readv` `[AF(4) | IP]` from the device, returning the IP byte count.
fn utun_read(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let mut af = [0u8; AF_HEADER_SIZE];
    let mut iov = [
        libc::iovec {
            iov_base: af.as_mut_ptr().cast(),
            iov_len: AF_HEADER_SIZE,
        },
        libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        },
    ];
    // SAFETY: readv scatters into our own buffers from a valid fd.
    let n = unsafe { libc::readv(fd, iov.as_mut_ptr(), 2) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::cast_sign_loss)]
    Ok((n as usize).saturating_sub(AF_HEADER_SIZE))
}

/// `writev` `[AF(4) | IP]` to the device, returning the IP byte count.
fn utun_write(fd: RawFd, ip_packet: &[u8]) -> io::Result<usize> {
    if ip_packet.is_empty() {
        return Ok(0);
    }
    let af: u32 = match ip_packet[0] >> 4 {
        4 => libc::AF_INET as u32,
        6 => libc::AF_INET6 as u32,
        v => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("not an IP packet (version nibble {v})"),
            ));
        }
    };
    // macOS reads the utun protocol-family header with ntohl(), so it must be
    // network (big-endian) byte order. (Writing host order makes the kernel see
    // an unknown family, e.g. 0x02000000 on little-endian, and silently drop the
    // injected packet — ingress is unaffected since the read path strips these 4
    // bytes without parsing them.)
    let mut af_bytes = af.to_be_bytes();
    let iov = [
        libc::iovec {
            iov_base: af_bytes.as_mut_ptr().cast(),
            iov_len: AF_HEADER_SIZE,
        },
        libc::iovec {
            // writev treats the buffer as read-only despite the *mut pointer.
            iov_base: ip_packet.as_ptr().cast_mut().cast(),
            iov_len: ip_packet.len(),
        },
    ];
    // SAFETY: writev gathers from our own buffers to a valid fd.
    let n = unsafe { libc::writev(fd, iov.as_ptr(), 2) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::cast_sign_loss)]
    Ok((n as usize).saturating_sub(AF_HEADER_SIZE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use arcbox_packet::ethernet::ETH_HEADER_LEN;

    /// A `SOCK_DGRAM` socketpair stands in for the `utun` fd: each `write` is a
    /// datagram, and `readv` splits it across the AF-header / payload iovecs
    /// exactly as the real device does.
    fn dgram_pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [0i32; 2];
        // SAFETY: valid pointer to a 2-element array.
        let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(r, 0, "socketpair failed");
        // SAFETY: fds are valid descriptors from socketpair.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn set_nonblocking(fd: RawFd) {
        // SAFETY: fcntl on a valid fd.
        unsafe {
            let f = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, f | libc::O_NONBLOCK);
        }
    }

    fn write_raw(fd: RawFd, data: &[u8]) {
        // SAFETY: writing our buffer to a valid fd.
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        assert!(n > 0);
    }

    #[test]
    fn frame_source_strips_af_header() {
        let (a, b) = dgram_pair();
        set_nonblocking(a.as_raw_fd());

        // A utun-style datagram: [AF_INET (host order) | IPv4 packet].
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = 6; // TCP
        let mut datagram = (libc::AF_INET as u32).to_be_bytes().to_vec();
        datagram.extend_from_slice(&ip);
        write_raw(b.as_raw_fd(), &datagram);

        let mut src = UtunFrameSource::new(a.as_raw_fd());
        let mut got: Vec<Vec<u8>> = Vec::new();
        src.drain(|p| got.push(p.to_vec()));

        assert_eq!(got.len(), 1);
        assert_eq!(got[0], ip, "AF header stripped, IP packet intact");
    }

    #[test]
    fn sink_prepends_af_and_strips_ethernet() {
        let (a, b) = dgram_pair();
        set_nonblocking(b.as_raw_fd());

        // L2 frame: Ethernet header (IPv4 ethertype) + IP packet.
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        let mut frame = vec![0u8; ETH_HEADER_LEN];
        frame[12] = 0x08;
        frame[13] = 0x00; // IPv4
        frame.extend_from_slice(&ip);

        let sink = UtunSink::new(a.as_raw_fd());
        assert!(sink.send_l2_frame(&frame).unwrap(), "IPv4 frame is written");

        let mut buf = [0u8; 64];
        // SAFETY: reading into our buffer from a valid fd.
        let n = unsafe { libc::read(b.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        assert!(n > 0);
        let n = n as usize;
        // macOS utun protocol family is network byte order.
        assert_eq!(&buf[..4], &(libc::AF_INET as u32).to_be_bytes());
        assert_eq!(
            &buf[4..n],
            &ip[..],
            "IP packet round-trips after the AF header"
        );
    }

    #[test]
    fn sink_drops_arp() {
        let (a, _b) = dgram_pair();
        let sink = UtunSink::new(a.as_raw_fd());
        let mut frame = vec![0u8; ETH_HEADER_LEN];
        frame[12] = 0x08;
        frame[13] = 0x06; // ARP
        assert!(
            !sink.send_l2_frame(&frame).unwrap(),
            "ARP has no L3 form and must be dropped, not written"
        );
    }
}
