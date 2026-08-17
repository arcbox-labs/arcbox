//! Minimal rtnetlink encoding for the invariant-addressing plumbing.
//!
//! The System VM rootfs ships busybox `ip`, whose support for fwmark policy
//! rules and >255 routing-table ids is build-dependent, so the two netlink
//! operations the invariant scheme needs — a fwmark fib rule and a
//! per-sandbox table route — are encoded and sent directly. rtnetlink is a
//! stable kernel ABI; the encoders are pure and unit-tested, only the socket
//! send is Linux-gated.

use std::net::Ipv4Addr;

// Message types.
const NLMSG_ERROR: u16 = 2;
const RTM_NEWROUTE: u16 = 24;
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;

// nlmsghdr flags.
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;

// rtmsg / fib_rule_hdr field values.
const AF_INET: u8 = 2;
const RT_TABLE_UNSPEC: u8 = 0;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RTN_UNICAST: u8 = 1;
const FR_ACT_TO_TBL: u8 = 1;
const RTNH_F_ONLINK: u32 = 4;

// Route attributes.
const RTA_DST: u16 = 1;
const RTA_GATEWAY: u16 = 5;
const RTA_OIF: u16 = 4;
const RTA_TABLE: u16 = 15;

// Fib-rule attributes.
const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_TABLE: u16 = 15;

const NLMSG_HDR_LEN: usize = 16;

/// Incrementally builds one netlink request message.
struct MessageBuilder {
    buf: Vec<u8>,
}

impl MessageBuilder {
    /// Start a message with the given type, flags, and 12-byte payload header
    /// (`rtmsg` and `fib_rule_hdr` share that size).
    fn new(msg_type: u16, flags: u16, header: [u8; 12]) -> Self {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&0u32.to_ne_bytes()); // len — patched in finish()
        buf.extend_from_slice(&msg_type.to_ne_bytes());
        buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK | flags).to_ne_bytes());
        buf.extend_from_slice(&1u32.to_ne_bytes()); // seq
        buf.extend_from_slice(&0u32.to_ne_bytes()); // pid (kernel fills)
        buf.extend_from_slice(&header);
        Self { buf }
    }

    fn attr(&mut self, attr_type: u16, payload: &[u8]) {
        let len = 4 + payload.len();
        self.buf
            .extend_from_slice(&u16::try_from(len).expect("attr fits u16").to_ne_bytes());
        self.buf.extend_from_slice(&attr_type.to_ne_bytes());
        self.buf.extend_from_slice(payload);
        // Pad to 4-byte alignment.
        self.buf.resize(self.buf.len().next_multiple_of(4), 0);
    }

    fn attr_u32(&mut self, attr_type: u16, value: u32) {
        self.attr(attr_type, &value.to_ne_bytes());
    }

    fn finish(mut self) -> Vec<u8> {
        let len = u32::try_from(self.buf.len()).expect("message fits u32");
        self.buf[..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

fn fib_rule_header(table: u8, action: u8) -> [u8; 12] {
    let mut header = [0u8; 12];
    header[0] = AF_INET;
    header[4] = table;
    header[7] = action;
    header
}

fn fwmark_rule(msg_type: u16, flags: u16, mark: u32, table: u32, priority: u32) -> Vec<u8> {
    let mut msg = MessageBuilder::new(
        msg_type,
        flags,
        fib_rule_header(RT_TABLE_UNSPEC, FR_ACT_TO_TBL),
    );
    msg.attr_u32(FRA_PRIORITY, priority);
    msg.attr_u32(FRA_FWMARK, mark);
    msg.attr_u32(FRA_TABLE, table);
    msg.finish()
}

/// `ip rule add fwmark <mark> lookup <table> pref <priority>`.
///
/// `NLM_F_EXCL` makes a repeated add fail with `EEXIST` instead of stacking a
/// duplicate rule; callers tolerate that errno for idempotency.
pub fn new_fwmark_rule(mark: u32, table: u32, priority: u32) -> Vec<u8> {
    fwmark_rule(
        RTM_NEWRULE,
        NLM_F_CREATE | NLM_F_EXCL,
        mark,
        table,
        priority,
    )
}

/// `ip rule del fwmark <mark> lookup <table> pref <priority>`.
pub fn del_fwmark_rule(mark: u32, table: u32, priority: u32) -> Vec<u8> {
    fwmark_rule(RTM_DELRULE, 0, mark, table, priority)
}

/// `ip route replace <dst>/32 dev <oif> table <table>` (onlink device route).
pub fn replace_link_route(dst: Ipv4Addr, oif: u32, table: u32) -> Vec<u8> {
    let mut header = [0u8; 12];
    header[0] = AF_INET;
    header[1] = 32; // dst_len
    header[4] = RT_TABLE_UNSPEC;
    header[5] = RTPROT_BOOT;
    header[6] = RT_SCOPE_LINK;
    header[7] = RTN_UNICAST;
    let mut msg = MessageBuilder::new(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE, header);
    msg.attr_u32(RTA_TABLE, table);
    msg.attr(RTA_DST, &dst.octets());
    msg.attr_u32(RTA_OIF, oif);
    msg.finish()
}

/// `ip route replace <dst>/32 via <gateway> dev <oif> onlink` (main table).
///
/// The eBPF datapath's only routing need (CORE-83): it replaces the kernel's
/// address-derived peer route (`dst dev oif`, next hop = `dst`), whose ARP
/// for the pool IP no invariant guest would ever answer, with a route whose
/// neighbor-resolution target is the fixed guest IP — which every invariant
/// guest owns. `onlink` (`RTNH_F_ONLINK`) is required because no route covers
/// the link-local gateway on the main table.
pub fn replace_gateway_route(dst: Ipv4Addr, gateway: Ipv4Addr, oif: u32) -> Vec<u8> {
    let mut header = [0u8; 12];
    header[0] = AF_INET;
    header[1] = 32; // dst_len
    header[4] = RT_TABLE_MAIN;
    header[5] = RTPROT_BOOT;
    header[6] = RT_SCOPE_UNIVERSE;
    header[7] = RTN_UNICAST;
    header[8..12].copy_from_slice(&RTNH_F_ONLINK.to_ne_bytes());
    let mut msg = MessageBuilder::new(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE, header);
    msg.attr(RTA_DST, &dst.octets());
    msg.attr(RTA_GATEWAY, &gateway.octets());
    msg.attr_u32(RTA_OIF, oif);
    msg.finish()
}

/// Send one request and wait for its ACK, tolerating the listed errnos.
#[cfg(target_os = "linux")]
pub fn execute(message: &[u8], tolerated_errnos: &[i32]) -> crate::error::Result<()> {
    use crate::error::TapNetError;

    // SAFETY: plain socket(2) call; result checked below.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(TapNetError::Network(format!(
            "netlink socket: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: fd is a freshly opened, owned socket.
    let fd = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    let raw = std::os::fd::AsRawFd::as_raw_fd(&fd);

    // SAFETY: message is a valid buffer; fd is a connected-less netlink socket
    // (destination defaults to the kernel, pid 0).
    let sent = unsafe { libc::send(raw, message.as_ptr().cast(), message.len(), 0) };
    if sent != message.len().cast_signed() {
        return Err(TapNetError::Network(format!(
            "netlink send: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut reply = [0u8; 4096];
    // SAFETY: reply is a valid mutable buffer owned by this frame.
    let received = unsafe { libc::recv(raw, reply.as_mut_ptr().cast(), reply.len(), 0) };
    if received < 0 {
        return Err(TapNetError::Network(format!(
            "netlink recv: {}",
            std::io::Error::last_os_error()
        )));
    }
    match ack_errno(&reply[..received as usize]) {
        Ok(0) => Ok(()),
        Ok(errno) if tolerated_errnos.contains(&errno) => Ok(()),
        Ok(errno) => Err(TapNetError::Network(format!(
            "netlink request failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ))),
        Err(reason) => Err(TapNetError::Network(format!("netlink reply: {reason}"))),
    }
}

/// Extract the errno from an `NLMSG_ERROR` ack (0 = success).
fn ack_errno(reply: &[u8]) -> std::result::Result<i32, String> {
    if reply.len() < NLMSG_HDR_LEN + 4 {
        return Err(format!("truncated reply ({} bytes)", reply.len()));
    }
    let msg_type = u16::from_ne_bytes(reply[4..6].try_into().expect("length checked"));
    if msg_type != NLMSG_ERROR {
        return Err(format!("unexpected reply type {msg_type}"));
    }
    let negative_errno = i32::from_ne_bytes(
        reply[NLMSG_HDR_LEN..NLMSG_HDR_LEN + 4]
            .try_into()
            .expect("length checked"),
    );
    Ok(-negative_errno)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse attributes out of a built message for shape assertions.
    fn attrs(message: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let total = u32::from_ne_bytes(message[..4].try_into().unwrap()) as usize;
        assert_eq!(total, message.len(), "nlmsghdr len must cover the message");
        let mut offset = NLMSG_HDR_LEN + 12;
        let mut parsed = vec![];
        while offset < total {
            let len = u16::from_ne_bytes(message[offset..offset + 2].try_into().unwrap()) as usize;
            let ty = u16::from_ne_bytes(message[offset + 2..offset + 4].try_into().unwrap());
            parsed.push((ty, message[offset + 4..offset + len].to_vec()));
            offset += len.next_multiple_of(4);
        }
        parsed
    }

    fn msg_type_and_flags(message: &[u8]) -> (u16, u16) {
        (
            u16::from_ne_bytes(message[4..6].try_into().unwrap()),
            u16::from_ne_bytes(message[6..8].try_into().unwrap()),
        )
    }

    #[test]
    fn fwmark_rule_carries_mark_table_and_priority() {
        let msg = new_fwmark_rule(0xAC14_0002, 0xAC14_0002, 8000);
        let (ty, flags) = msg_type_and_flags(&msg);
        assert_eq!(ty, RTM_NEWRULE);
        assert_eq!(
            flags,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            "adds must be EXCL so retries surface EEXIST instead of stacking rules"
        );
        // fib_rule_hdr: family AF_INET, action FR_ACT_TO_TBL.
        assert_eq!(msg[NLMSG_HDR_LEN], AF_INET);
        assert_eq!(msg[NLMSG_HDR_LEN + 7], FR_ACT_TO_TBL);
        assert_eq!(
            attrs(&msg),
            vec![
                (FRA_PRIORITY, 8000u32.to_ne_bytes().to_vec()),
                (FRA_FWMARK, 0xAC14_0002u32.to_ne_bytes().to_vec()),
                (FRA_TABLE, 0xAC14_0002u32.to_ne_bytes().to_vec()),
            ]
        );
    }

    #[test]
    fn rule_delete_mirrors_the_add() {
        let add = new_fwmark_rule(7, 7, 8000);
        let del = del_fwmark_rule(7, 7, 8000);
        assert_eq!(msg_type_and_flags(&del).0, RTM_DELRULE);
        assert_eq!(attrs(&add), attrs(&del), "delete must match the added rule");
    }

    #[test]
    fn link_route_targets_the_device_in_the_sandbox_table() {
        let msg = replace_link_route(Ipv4Addr::new(169, 254, 100, 2), 42, 0xAC14_0002);
        let (ty, flags) = msg_type_and_flags(&msg);
        assert_eq!(ty, RTM_NEWROUTE);
        assert_eq!(
            flags,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE
        );
        // rtmsg: family, /32 dst, link scope, unicast.
        assert_eq!(msg[NLMSG_HDR_LEN], AF_INET);
        assert_eq!(msg[NLMSG_HDR_LEN + 1], 32);
        assert_eq!(msg[NLMSG_HDR_LEN + 6], RT_SCOPE_LINK);
        assert_eq!(msg[NLMSG_HDR_LEN + 7], RTN_UNICAST);
        assert_eq!(
            attrs(&msg),
            vec![
                (RTA_TABLE, 0xAC14_0002u32.to_ne_bytes().to_vec()),
                (RTA_DST, vec![169, 254, 100, 2]),
                (RTA_OIF, 42u32.to_ne_bytes().to_vec()),
            ]
        );
    }

    #[test]
    fn gateway_route_is_an_onlink_main_table_replace() {
        let msg = replace_gateway_route(
            Ipv4Addr::new(172, 20, 0, 2),
            Ipv4Addr::new(169, 254, 100, 2),
            42,
        );
        let (ty, flags) = msg_type_and_flags(&msg);
        assert_eq!(ty, RTM_NEWROUTE);
        assert_eq!(
            flags,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            "must replace the kernel's peer route for the same /32"
        );
        // rtmsg: /32 dst in the main table, universe scope (gateway route),
        // and the onlink flag — the link-local gateway has no covering route.
        assert_eq!(msg[NLMSG_HDR_LEN], AF_INET);
        assert_eq!(msg[NLMSG_HDR_LEN + 1], 32);
        assert_eq!(msg[NLMSG_HDR_LEN + 4], RT_TABLE_MAIN);
        assert_eq!(msg[NLMSG_HDR_LEN + 6], RT_SCOPE_UNIVERSE);
        assert_eq!(msg[NLMSG_HDR_LEN + 7], RTN_UNICAST);
        assert_eq!(
            msg[NLMSG_HDR_LEN + 8..NLMSG_HDR_LEN + 12],
            RTNH_F_ONLINK.to_ne_bytes()
        );
        assert_eq!(
            attrs(&msg),
            vec![
                (RTA_DST, vec![172, 20, 0, 2]),
                (RTA_GATEWAY, vec![169, 254, 100, 2]),
                (RTA_OIF, 42u32.to_ne_bytes().to_vec()),
            ]
        );
    }

    #[test]
    fn ack_errno_decodes_success_and_failure() {
        // 20-byte NLMSG_ERROR: header + i32 negative errno.
        let mut ok = vec![0u8; 20];
        ok[..4].copy_from_slice(&20u32.to_ne_bytes());
        ok[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        assert_eq!(ack_errno(&ok), Ok(0));

        let mut eexist = ok.clone();
        eexist[NLMSG_HDR_LEN..NLMSG_HDR_LEN + 4].copy_from_slice(&(-17i32).to_ne_bytes());
        assert_eq!(ack_errno(&eexist), Ok(17));

        assert!(ack_errno(&[0u8; 4]).is_err());
    }
}
