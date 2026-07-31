//! Routing socket message construction and I/O.
//!
//! Builds `rt_msghdr` + variable-length sockaddr payloads for PF_ROUTE
//! operations (RTM_ADD, RTM_DELETE, RTM_GET).
//!
//! # I/O model
//!
//! - **Mutations** (add/delete): `write()` only. Success/failure is
//!   determined entirely by the `write()` return value and `errno`. No reply
//!   is read — this avoids alignment UB on reply buffers, seq/pid matching
//!   complexity, and `SO_USELOOPBACK` contradictions.
//!
//! - **Queries** (get): `write()` + `read()` with `rtm_pid`/`rtm_seq`
//!   matching, since the kernel fills interface/flags info in the reply.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering};

/// Sequence counter for correlating routing socket request/reply pairs.
static SEQ: AtomicI32 = AtomicI32::new(1);

/// BSD routing socket sockaddr alignment.
///
/// Rounds `sa_len` up to a 4-byte boundary with a minimum of 4 bytes.
/// Mirrors XNU's internal `SA_SIZE` / `ROUNDUP` macro.
pub const fn sa_rlen(sa_len: usize) -> usize {
    if sa_len == 0 { 4 } else { (sa_len + 3) & !3 }
}

/// Maximum routing message buffer size (header + up to 8 sockaddrs).
const MAX_MSG_SIZE: usize = 512;

/// Maximum number of read attempts when waiting for a matching RTM_GET reply.
const MAX_READ_ATTEMPTS: usize = 50;

/// Routing message type for [`build_msg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    Add,
    Delete,
    Get,
}

impl MsgType {
    const fn as_rtm(self) -> i32 {
        match self {
            Self::Add => libc::RTM_ADD,
            Self::Delete => libc::RTM_DELETE,
            Self::Get => libc::RTM_GET,
        }
    }
}

/// Builds a routing socket message with the given sockaddrs.
///
/// # Layout
///
/// ```text
/// [rt_msghdr][DST sockaddr_in][GATEWAY sockaddr_dl (optional)][NETMASK sockaddr_in]
/// ```
///
/// `gateway_dl` is omitted for `Delete` and `Get` without interface context.
/// Each sockaddr is padded to 4-byte alignment per BSD convention.
pub fn build_msg(
    msg_type: MsgType,
    dst: &libc::sockaddr_in,
    gateway: Option<&libc::sockaddr_dl>,
    netmask: &libc::sockaddr_in,
) -> io::Result<Vec<u8>> {
    let hdr_len = std::mem::size_of::<libc::rt_msghdr>();
    let dst_len = sa_rlen(dst.sin_len as usize);
    let gw_len = gateway.map_or(0, |g| sa_rlen(g.sdl_len as usize));
    let mask_len = sa_rlen(netmask.sin_len as usize);
    let total = hdr_len + dst_len + gw_len + mask_len;

    if total > MAX_MSG_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "routing message exceeds maximum size",
        ));
    }

    let mut buf = vec![0u8; total];

    // Build rt_msghdr on the stack (properly aligned), then copy into buf.
    let mut hdr: libc::rt_msghdr = unsafe { std::mem::zeroed() };
    hdr.rtm_msglen = total as u16;
    hdr.rtm_version = libc::RTM_VERSION as u8;
    hdr.rtm_type = msg_type.as_rtm() as u8;
    hdr.rtm_seq = SEQ.fetch_add(1, Ordering::Relaxed);
    // Safety: getpid is always safe.
    hdr.rtm_pid = unsafe { libc::getpid() };

    let mut addrs = libc::RTA_DST | libc::RTA_NETMASK;
    if gateway.is_some() {
        addrs |= libc::RTA_GATEWAY;
    }
    hdr.rtm_addrs = addrs;
    // Interface-based route: RTF_UP | RTF_STATIC, no RTF_GATEWAY.
    hdr.rtm_flags = libc::RTF_UP | libc::RTF_STATIC;

    // Safety: hdr is a valid rt_msghdr; hdr_len fits in buf.
    unsafe {
        std::ptr::copy_nonoverlapping(
            std::ptr::from_ref(&hdr).cast::<u8>(),
            buf.as_mut_ptr(),
            hdr_len,
        );
    }

    // Append sockaddrs in RTA bit order: DST, GATEWAY, NETMASK.
    let mut offset = hdr_len;

    // DST (sockaddr_in).
    unsafe {
        std::ptr::copy_nonoverlapping(
            std::ptr::from_ref(dst).cast::<u8>(),
            buf.as_mut_ptr().add(offset),
            std::mem::size_of::<libc::sockaddr_in>(),
        );
    }
    offset += dst_len;

    // GATEWAY (sockaddr_dl, optional).
    if let Some(gw) = gateway {
        unsafe {
            std::ptr::copy_nonoverlapping(
                std::ptr::from_ref(gw).cast::<u8>(),
                buf.as_mut_ptr().add(offset),
                std::mem::size_of::<libc::sockaddr_dl>(),
            );
        }
        offset += gw_len;
    }

    // NETMASK (sockaddr_in).
    unsafe {
        std::ptr::copy_nonoverlapping(
            std::ptr::from_ref(netmask).cast::<u8>(),
            buf.as_mut_ptr().add(offset),
            std::mem::size_of::<libc::sockaddr_in>(),
        );
    }

    Ok(buf)
}

/// Opens a PF_ROUTE socket, writes `msg`. Success/failure is determined
/// by `write()` return value and `errno` — no reply is read.
///
/// This is the correct approach for mutations (add/delete/change) per
/// the BSD routing socket API: "the values for rtm_errno are available
/// through the normal errno mechanism, even if the routing reply message
/// is lost." (route(4))
pub fn route_write(msg: &[u8]) -> io::Result<()> {
    let fd = open_route_socket()?;

    // Safety: write with valid fd and buffer from build_msg.
    let n = unsafe { libc::write(fd.as_raw_fd(), msg.as_ptr().cast(), msg.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Reply from an RTM_GET query.
#[derive(Debug)]
pub struct GetReply {
    /// The interface index from the reply (`rtm_index`).
    pub ifindex: u16,
    /// The flags from the reply (`rtm_flags`).
    pub flags: i32,
    /// Destination network address selected by the kernel.
    pub destination: Ipv4Addr,
    /// Netmask of the route selected by the kernel.
    pub netmask: Ipv4Addr,
}

/// Opens a PF_ROUTE socket, writes an RTM_GET message, and reads back the
/// kernel reply matching our `rtm_pid` and `rtm_seq`.
///
/// Unlike mutations, RTM_GET requires reading the reply because the kernel
/// fills in interface/gateway information.
pub fn route_query(msg: &[u8]) -> io::Result<GetReply> {
    let fd = open_route_socket()?;

    // Extract our seq/pid from the message for matching.
    if msg.len() < std::mem::size_of::<libc::rt_msghdr>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message too short for rt_msghdr",
        ));
    }
    // Safety: msg is at least rt_msghdr bytes; read_unaligned avoids UB.
    let sent_hdr: libc::rt_msghdr =
        unsafe { std::ptr::read_unaligned(msg.as_ptr().cast::<libc::rt_msghdr>()) };
    let our_seq = sent_hdr.rtm_seq;
    let our_pid = sent_hdr.rtm_pid;

    // Safety: write with valid fd and buffer.
    let n = unsafe { libc::write(fd.as_raw_fd(), msg.as_ptr().cast(), msg.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    // Read replies until we find one matching our seq and pid.
    // Other messages (interface changes, other processes' routes) are skipped.
    let hdr_size = std::mem::size_of::<libc::rt_msghdr>();
    let mut buf = [0u8; MAX_MSG_SIZE];

    for _ in 0..MAX_READ_ATTEMPTS {
        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if (n as usize) < hdr_size {
            continue;
        }

        // Safety: n >= hdr_size; read_unaligned avoids alignment UB.
        let reply_hdr: libc::rt_msghdr =
            unsafe { std::ptr::read_unaligned(buf.as_ptr().cast::<libc::rt_msghdr>()) };

        if reply_hdr.rtm_seq == our_seq && reply_hdr.rtm_pid == our_pid {
            if reply_hdr.rtm_errno != 0 {
                return Err(io::Error::from_raw_os_error(reply_hdr.rtm_errno));
            }
            let (destination, netmask) = parse_ipv4_route(&buf[..n as usize], &reply_hdr)?;
            return Ok(GetReply {
                ifindex: reply_hdr.rtm_index,
                flags: reply_hdr.rtm_flags,
                destination,
                netmask,
            });
        }
    }

    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "no matching RTM_GET reply after maximum read attempts",
    ))
}

pub(crate) fn parse_ipv4_route(
    message: &[u8],
    header: &libc::rt_msghdr,
) -> io::Result<(Ipv4Addr, Ipv4Addr)> {
    let message_len = usize::from(header.rtm_msglen).min(message.len());
    let mut offset = std::mem::size_of::<libc::rt_msghdr>();
    let mut destination = None;
    let mut netmask = None;

    for index in 0..libc::RTAX_MAX {
        if header.rtm_addrs & (1 << index) == 0 {
            continue;
        }
        if offset + 2 > message_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "routing message sockaddr header is truncated",
            ));
        }

        let sockaddr_len = usize::from(message[offset]);
        let padded_len = sa_rlen(sockaddr_len);
        if offset + padded_len > message_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "routing message sockaddr is truncated",
            ));
        }

        if index == libc::RTAX_DST {
            destination = Some(parse_sockaddr_ipv4(
                &message[offset..offset + sockaddr_len],
            )?);
        } else if index == libc::RTAX_NETMASK {
            netmask = Some(parse_sockaddr_netmask(
                &message[offset..offset + sockaddr_len],
            ));
        }
        offset += padded_len;
    }

    match destination {
        Some(destination) => Ok((destination, netmask.unwrap_or(Ipv4Addr::BROADCAST))),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "routing reply omitted destination",
        )),
    }
}

fn parse_sockaddr_ipv4(sockaddr: &[u8]) -> io::Result<Ipv4Addr> {
    if sockaddr.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "IPv4 sockaddr is too short",
        ));
    }
    let family = i32::from(sockaddr[1]);
    if family != libc::AF_INET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "routing message sockaddr is not IPv4",
        ));
    }
    let mut octets = [0u8; 4];
    let available = sockaddr.len().saturating_sub(4).min(octets.len());
    octets[..available].copy_from_slice(&sockaddr[4..4 + available]);
    Ok(Ipv4Addr::from(octets))
}

/// Parses XNU's radix-tree netmask representation.
///
/// Kernel replies do not contain a regular `sockaddr_in`: the family byte can
/// hold mask data, trailing zero octets are omitted, and the default route is
/// represented by `sa_len == 0`. IPv4 mask bytes still begin at the
/// `sockaddr_in.sin_addr` offset.
fn parse_sockaddr_netmask(sockaddr: &[u8]) -> Ipv4Addr {
    let mut octets = [0u8; 4];
    let available = sockaddr.len().saturating_sub(4).min(octets.len());
    if available > 0 {
        octets[..available].copy_from_slice(&sockaddr[4..4 + available]);
    }
    Ipv4Addr::from(octets)
}

/// Opens a fresh `PF_ROUTE` socket.
pub(crate) fn open_route_socket() -> io::Result<OwnedFd> {
    // Safety: socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC) is always safe.
    let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Safety: fd is valid from socket() above.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ipv4Net;
    use crate::sockaddr;

    #[test]
    fn sa_rlen_alignment() {
        assert_eq!(sa_rlen(0), 4);
        assert_eq!(sa_rlen(1), 4);
        assert_eq!(sa_rlen(4), 4);
        assert_eq!(sa_rlen(5), 8);
        assert_eq!(sa_rlen(16), 16);
        assert_eq!(sa_rlen(20), 20);
        assert_eq!(sa_rlen(21), 24);
    }

    /// Reads an rt_msghdr from a byte buffer safely using read_unaligned.
    fn read_hdr(buf: &[u8]) -> libc::rt_msghdr {
        assert!(buf.len() >= std::mem::size_of::<libc::rt_msghdr>());
        // Safety: buf is large enough; read_unaligned handles alignment.
        unsafe { std::ptr::read_unaligned(buf.as_ptr().cast::<libc::rt_msghdr>()) }
    }

    fn write_hdr(buf: &mut [u8], header: libc::rt_msghdr) {
        assert!(buf.len() >= std::mem::size_of::<libc::rt_msghdr>());
        // Safety: buf is large enough; write_unaligned handles alignment.
        unsafe { std::ptr::write_unaligned(buf.as_mut_ptr().cast(), header) };
    }

    fn netmask_offset(message: &[u8]) -> usize {
        let destination_offset = std::mem::size_of::<libc::rt_msghdr>();
        destination_offset + sa_rlen(usize::from(message[destination_offset]))
    }

    #[test]
    fn build_msg_add_with_gateway() {
        let net: Ipv4Net = "172.16.0.0/12".parse().unwrap();
        let dst = sockaddr::make_dst(net);
        let gw = sockaddr::make_gateway_dl_with_index("bridge100", 42);
        let mask = sockaddr::make_netmask(net);

        let buf = build_msg(MsgType::Add, &dst, Some(&gw), &mask).unwrap();
        let hdr = read_hdr(&buf);

        assert_eq!(hdr.rtm_version, libc::RTM_VERSION as u8);
        assert_eq!(hdr.rtm_type, libc::RTM_ADD as u8);
        assert_eq!(
            hdr.rtm_addrs,
            libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK
        );
        assert_ne!(hdr.rtm_flags & libc::RTF_UP, 0);
        assert_ne!(hdr.rtm_flags & libc::RTF_STATIC, 0);
        assert_eq!(hdr.rtm_flags & libc::RTF_GATEWAY, 0);
        assert_eq!(hdr.rtm_msglen as usize, buf.len());
    }

    #[test]
    fn build_msg_delete_no_gateway() {
        let net: Ipv4Net = "10.0.0.0/8".parse().unwrap();
        let dst = sockaddr::make_dst(net);
        let mask = sockaddr::make_netmask(net);

        let buf = build_msg(MsgType::Delete, &dst, None, &mask).unwrap();
        let hdr = read_hdr(&buf);

        assert_eq!(hdr.rtm_type, libc::RTM_DELETE as u8);
        assert_eq!(hdr.rtm_addrs, libc::RTA_DST | libc::RTA_NETMASK);

        let expected = std::mem::size_of::<libc::rt_msghdr>()
            + sa_rlen(std::mem::size_of::<libc::sockaddr_in>())
            + sa_rlen(std::mem::size_of::<libc::sockaddr_in>());
        assert_eq!(buf.len(), expected);
    }

    #[test]
    fn build_msg_sockaddr_order() {
        let net: Ipv4Net = "192.168.0.0/16".parse().unwrap();
        let dst = sockaddr::make_dst(net);
        let gw = sockaddr::make_gateway_dl_with_index("bridge100", 5);
        let mask = sockaddr::make_netmask(net);

        let buf = build_msg(MsgType::Add, &dst, Some(&gw), &mask).unwrap();
        let hdr_len = std::mem::size_of::<libc::rt_msghdr>();

        // DST → AF_INET
        assert_eq!(buf[hdr_len + 1], libc::AF_INET as u8);
        // GATEWAY → AF_LINK
        let gw_offset = hdr_len + sa_rlen(std::mem::size_of::<libc::sockaddr_in>());
        assert_eq!(buf[gw_offset + 1], libc::AF_LINK as u8);
        // NETMASK → AF_INET
        let mask_offset = gw_offset + sa_rlen(std::mem::size_of::<libc::sockaddr_dl>());
        assert_eq!(buf[mask_offset + 1], libc::AF_INET as u8);
    }

    #[test]
    fn build_msg_seq_increments() {
        let net: Ipv4Net = "10.0.0.0/8".parse().unwrap();
        let dst = sockaddr::make_dst(net);
        let mask = sockaddr::make_netmask(net);

        let buf1 = build_msg(MsgType::Delete, &dst, None, &mask).unwrap();
        let buf2 = build_msg(MsgType::Delete, &dst, None, &mask).unwrap();
        let hdr1 = read_hdr(&buf1);
        let hdr2 = read_hdr(&buf2);

        assert_ne!(hdr1.rtm_seq, hdr2.rtm_seq);
    }

    #[test]
    fn parses_compact_ipv4_netmask_from_route_reply() {
        let net: Ipv4Net = "172.16.0.0/12".parse().unwrap();
        let dst = sockaddr::make_dst(net);
        let mask = sockaddr::make_netmask(net);
        let message = build_msg(MsgType::Get, &dst, None, &mask).unwrap();
        let header = read_hdr(&message);

        let (destination, netmask) = parse_ipv4_route(&message, &header).unwrap();

        assert_eq!(destination, Ipv4Addr::new(172, 16, 0, 0));
        assert_eq!(netmask, Ipv4Addr::new(255, 240, 0, 0));
    }

    #[test]
    fn parses_kernel_shaped_trimmed_netmask() {
        let net: Ipv4Net = "172.16.0.0/12".parse().unwrap();
        let dst = sockaddr::make_dst(net);
        let mask = sockaddr::make_netmask(net);
        let mut message = build_msg(MsgType::Get, &dst, None, &mask).unwrap();
        let offset = netmask_offset(&message);
        message[offset..offset + 6].copy_from_slice(&[6, 0xff, 0xff, 0xff, 0xff, 0xf0]);
        let header = read_hdr(&message);

        let (_, netmask) = parse_ipv4_route(&message, &header).unwrap();

        assert_eq!(netmask, Ipv4Addr::new(255, 240, 0, 0));
    }

    #[test]
    fn zero_length_netmask_represents_default_route() {
        let net: Ipv4Net = "172.16.0.0/12".parse().unwrap();
        let dst = sockaddr::make_dst(net);
        let mask = sockaddr::make_netmask(net);
        let mut message = build_msg(MsgType::Get, &dst, None, &mask).unwrap();
        let offset = netmask_offset(&message);
        message[offset] = 0;
        let header = read_hdr(&message);

        let (_, netmask) = parse_ipv4_route(&message, &header).unwrap();

        assert_eq!(netmask, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn omitted_netmask_represents_host_route() {
        let net: Ipv4Net = "172.16.0.0/12".parse().unwrap();
        let dst = sockaddr::make_dst(net);
        let mask = sockaddr::make_netmask(net);
        let mut message = build_msg(MsgType::Get, &dst, None, &mask).unwrap();
        let mut header = read_hdr(&message);
        header.rtm_addrs &= !libc::RTA_NETMASK;
        write_hdr(&mut message, header);

        let (_, netmask) = parse_ipv4_route(&message, &header).unwrap();

        assert_eq!(netmask, Ipv4Addr::BROADCAST);
    }

    #[test]
    fn rejects_truncated_route_sockaddr() {
        let net: Ipv4Net = "172.16.0.0/12".parse().unwrap();
        let dst = sockaddr::make_dst(net);
        let mask = sockaddr::make_netmask(net);
        let message = build_msg(MsgType::Get, &dst, None, &mask).unwrap();
        let header = read_hdr(&message);

        let error = parse_ipv4_route(&message[..message.len() - 1], &header).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_non_ipv4_route_destination() {
        let net: Ipv4Net = "172.16.0.0/12".parse().unwrap();
        let dst = sockaddr::make_dst(net);
        let mask = sockaddr::make_netmask(net);
        let mut message = build_msg(MsgType::Get, &dst, None, &mask).unwrap();
        let header = read_hdr(&message);
        message[std::mem::size_of::<libc::rt_msghdr>() + 1] = libc::AF_INET6 as u8;

        let error = parse_ipv4_route(&message, &header).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
