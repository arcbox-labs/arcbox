//! Netlink socket operations for network configuration.
//!
//! This module provides a low-level interface to the Linux netlink subsystem
//! for creating and configuring network interfaces, addresses, and routes.
//!
//! Uses rtnetlink protocol for network configuration operations.

use std::ffi::CString;
use std::io::{self, Read, Write};
use std::mem;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use ipnetwork::IpNetwork;

use crate::error::{NetError, Result};

// Netlink constants
const NETLINK_ROUTE: i32 = 0;

// Netlink message types
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;

// Netlink flags
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_CREATE: u16 = 0x0400;
const NLM_F_EXCL: u16 = 0x0200;

// Interface flags
const IFF_UP: u32 = 0x1;

// Attribute types for RTM_NEWLINK
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINK: u16 = 5;
const IFLA_MASTER: u16 = 10;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_ADDRESS: u16 = 1;

// Attribute types for RTM_NEWADDR
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

// Attribute types for RTM_NEWROUTE
const RTA_DST: u16 = 1;
const RTA_GATEWAY: u16 = 5;
const RTA_OIF: u16 = 4;
const RTA_PRIORITY: u16 = 6;

// Route table and protocol constants
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;

/// Netlink message header.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

/// Interface info message.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct IfInfoMsg {
    ifi_family: u8,
    _pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

/// Interface address message.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct IfAddrMsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

/// Route message.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct RtMsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

/// Netlink attribute header.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct NlAttr {
    nla_len: u16,
    nla_type: u16,
}

/// Network interface type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// Linux bridge interface.
    Bridge,
    /// TAP device.
    Tap,
    /// Virtual ethernet pair.
    Veth,
    /// Dummy interface.
    Dummy,
}

impl LinkType {
    /// Returns the kernel name for this link type.
    fn kind(&self) -> &'static str {
        match self {
            Self::Bridge => "bridge",
            Self::Tap => "tun",
            Self::Veth => "veth",
            Self::Dummy => "dummy",
        }
    }
}

/// Link configuration for creating network interfaces.
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// Interface name.
    pub name: String,
    /// Interface type.
    pub link_type: LinkType,
    /// MTU (optional).
    pub mtu: Option<u16>,
    /// MAC address (optional).
    pub mac: Option<[u8; 6]>,
}

/// Route configuration.
#[derive(Debug, Clone)]
pub struct Route {
    /// Destination network.
    pub destination: IpNetwork,
    /// Gateway address (optional for directly connected routes).
    pub gateway: Option<IpAddr>,
    /// Output interface index.
    pub ifindex: u32,
    /// Route metric/priority (optional).
    pub metric: Option<u32>,
}

/// Netlink socket handle for network configuration.
///
/// Provides methods for creating and configuring network interfaces,
/// addresses, and routes using the netlink protocol.
pub struct NetlinkHandle {
    /// Netlink socket file descriptor.
    fd: OwnedFd,
    /// Sequence number for netlink messages.
    seq: u32,
}

impl NetlinkHandle {
    /// Creates a new netlink socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be created.
    pub fn new() -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_ROUTE,
            )
        };

        if fd < 0 {
            return Err(NetError::Netlink(format!(
                "failed to create netlink socket: {}",
                io::Error::last_os_error()
            )));
        }

        // Bind to the netlink socket
        let addr = libc::sockaddr_nl {
            nl_family: libc::AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0, // Let kernel assign
            nl_groups: 0,
        };

        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };

        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(NetError::Netlink(format!(
                "failed to bind netlink socket: {}",
                io::Error::last_os_error()
            )));
        }

        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        Ok(Self { fd, seq: 0 })
    }

    /// Gets the next sequence number.
    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    /// Sends a netlink message and waits for acknowledgement.
    fn send_and_ack(&mut self, msg: &[u8]) -> Result<()> {
        // Send message
        let ret = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
                0,
            )
        };

        if ret < 0 {
            return Err(NetError::Netlink(format!(
                "failed to send netlink message: {}",
                io::Error::last_os_error()
            )));
        }

        // Receive response
        let mut buf = [0u8; 4096];
        let len = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };

        if len < 0 {
            return Err(NetError::Netlink(format!(
                "failed to receive netlink response: {}",
                io::Error::last_os_error()
            )));
        }

        // Check for error response
        if len >= mem::size_of::<NlMsgHdr>() as isize {
            let hdr = unsafe { &*(buf.as_ptr() as *const NlMsgHdr) };
            if hdr.nlmsg_type == libc::NLMSG_ERROR as u16 {
                // Error message format: nlmsghdr + nlmsgerr
                if len >= (mem::size_of::<NlMsgHdr>() + 4) as isize {
                    let error_code =
                        unsafe { *(buf.as_ptr().add(mem::size_of::<NlMsgHdr>()) as *const i32) };
                    if error_code != 0 {
                        return Err(NetError::Netlink(format!(
                            "netlink error: {}",
                            io::Error::from_raw_os_error(-error_code)
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Creates a network interface.
    ///
    /// # Errors
    ///
    /// Returns an error if the interface cannot be created.
    pub fn create_link(&mut self, config: &LinkConfig) -> Result<u32> {
        let seq = self.next_seq();

        // Build the netlink message
        let mut msg = Vec::with_capacity(256);

        // Reserve space for header
        msg.extend_from_slice(&[0u8; mem::size_of::<NlMsgHdr>()]);

        // Add ifinfomsg
        let ifinfo = IfInfoMsg {
            ifi_family: libc::AF_UNSPEC as u8,
            _pad: 0,
            ifi_type: 0,
            ifi_index: 0,
            ifi_flags: 0,
            ifi_change: 0,
        };
        msg.extend_from_slice(unsafe {
            std::slice::from_raw_parts(
                &ifinfo as *const _ as *const u8,
                mem::size_of::<IfInfoMsg>(),
            )
        });

        // Add IFLA_IFNAME attribute
        self.add_attr_string(&mut msg, IFLA_IFNAME, &config.name);

        // Add IFLA_LINKINFO with nested IFLA_INFO_KIND
        let linkinfo_start = msg.len();
        msg.extend_from_slice(&[0u8; mem::size_of::<NlAttr>()]); // Placeholder
        self.add_attr_string(&mut msg, IFLA_INFO_KIND, config.link_type.kind());

        // Update linkinfo length
        let linkinfo_len = (msg.len() - linkinfo_start) as u16;
        let linkinfo_attr = NlAttr {
            nla_len: linkinfo_len,
            nla_type: IFLA_LINKINFO | (1 << 15), // NLA_F_NESTED
        };
        msg[linkinfo_start..linkinfo_start + mem::size_of::<NlAttr>()].copy_from_slice(unsafe {
            std::slice::from_raw_parts(
                &linkinfo_attr as *const _ as *const u8,
                mem::size_of::<NlAttr>(),
            )
        });

        // Add MTU if specified
        if let Some(mtu) = config.mtu {
            self.add_attr_u32(&mut msg, IFLA_MTU, u32::from(mtu));
        }

        // Add MAC address if specified
        if let Some(mac) = config.mac {
            self.add_attr_bytes(&mut msg, IFLA_ADDRESS, &mac);
        }

        // Update header
        let hdr = NlMsgHdr {
            nlmsg_len: msg.len() as u32,
            nlmsg_type: RTM_NEWLINK,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        msg[..mem::size_of::<NlMsgHdr>()].copy_from_slice(unsafe {
            std::slice::from_raw_parts(&hdr as *const _ as *const u8, mem::size_of::<NlMsgHdr>())
        });

        self.send_and_ack(&msg)?;

        // Get the interface index
        self.get_ifindex(&config.name)
    }

    /// Deletes a network interface.
    ///
    /// # Errors
    ///
    /// Returns an error if the interface cannot be deleted.
    pub fn delete_link(&mut self, ifindex: u32) -> Result<()> {
        let seq = self.next_seq();

        let mut msg = Vec::with_capacity(64);

        // Reserve space for header
        msg.extend_from_slice(&[0u8; mem::size_of::<NlMsgHdr>()]);

        // Add ifinfomsg
        let ifinfo = IfInfoMsg {
            ifi_family: libc::AF_UNSPEC as u8,
            _pad: 0,
            ifi_type: 0,
            ifi_index: ifindex as i32,
            ifi_flags: 0,
            ifi_change: 0,
        };
        msg.extend_from_slice(unsafe {
            std::slice::from_raw_parts(
                &ifinfo as *const _ as *const u8,
                mem::size_of::<IfInfoMsg>(),
            )
        });

        // Update header
        let hdr = NlMsgHdr {
            nlmsg_len: msg.len() as u32,
            nlmsg_type: RTM_DELLINK,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        msg[..mem::size_of::<NlMsgHdr>()].copy_from_slice(unsafe {
            std::slice::from_raw_parts(&hdr as *const _ as *const u8, mem::size_of::<NlMsgHdr>())
        });

        self.send_and_ack(&msg)
    }

    /// Sets interface state (up/down).
    ///
    /// # Errors
    ///
    /// Returns an error if the state cannot be changed.
    pub fn set_link_state(&mut self, ifindex: u32, up: bool) -> Result<()> {
        let seq = self.next_seq();

        let mut msg = Vec::with_capacity(64);

        // Reserve space for header
        msg.extend_from_slice(&[0u8; mem::size_of::<NlMsgHdr>()]);

        // Add ifinfomsg
        let flags = if up { IFF_UP } else { 0 };
        let ifinfo = IfInfoMsg {
            ifi_family: libc::AF_UNSPEC as u8,
            _pad: 0,
            ifi_type: 0,
            ifi_index: ifindex as i32,
            ifi_flags: flags,
            ifi_change: IFF_UP,
        };
        msg.extend_from_slice(unsafe {
            std::slice::from_raw_parts(
                &ifinfo as *const _ as *const u8,
                mem::size_of::<IfInfoMsg>(),
            )
        });

        // Update header
        let hdr = NlMsgHdr {
            nlmsg_len: msg.len() as u32,
            nlmsg_type: RTM_NEWLINK,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        msg[..mem::size_of::<NlMsgHdr>()].copy_from_slice(unsafe {
            std::slice::from_raw_parts(&hdr as *const _ as *const u8, mem::size_of::<NlMsgHdr>())
        });

        self.send_and_ack(&msg)
    }

    /// Sets the master (bridge) for an interface.
    ///
    /// # Errors
    ///
    /// Returns an error if the master cannot be set.
    pub fn set_link_master(&mut self, ifindex: u32, master_ifindex: u32) -> Result<()> {
        let seq = self.next_seq();

        let mut msg = Vec::with_capacity(64);

        // Reserve space for header
        msg.extend_from_slice(&[0u8; mem::size_of::<NlMsgHdr>()]);

        // Add ifinfomsg
        let ifinfo = IfInfoMsg {
            ifi_family: libc::AF_UNSPEC as u8,
            _pad: 0,
            ifi_type: 0,
            ifi_index: ifindex as i32,
            ifi_flags: 0,
            ifi_change: 0,
        };
        msg.extend_from_slice(unsafe {
            std::slice::from_raw_parts(
                &ifinfo as *const _ as *const u8,
                mem::size_of::<IfInfoMsg>(),
            )
        });

        // Add IFLA_MASTER attribute
        self.add_attr_u32(&mut msg, IFLA_MASTER, master_ifindex);

        // Update header
        let hdr = NlMsgHdr {
            nlmsg_len: msg.len() as u32,
            nlmsg_type: RTM_NEWLINK,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        msg[..mem::size_of::<NlMsgHdr>()].copy_from_slice(unsafe {
            std::slice::from_raw_parts(&hdr as *const _ as *const u8, mem::size_of::<NlMsgHdr>())
        });

        self.send_and_ack(&msg)
    }

    /// Adds an IP address to an interface.
    ///
    /// # Errors
    ///
    /// Returns an error if the address cannot be added.
    pub fn add_address(&mut self, ifindex: u32, addr: IpNetwork) -> Result<()> {
        let seq = self.next_seq();

        let mut msg = Vec::with_capacity(64);

        // Reserve space for header
        msg.extend_from_slice(&[0u8; mem::size_of::<NlMsgHdr>()]);

        // Determine address family
        let family = match addr {
            IpNetwork::V4(_) => libc::AF_INET as u8,
            IpNetwork::V6(_) => libc::AF_INET6 as u8,
        };

        // Add ifaddrmsg
        let ifaddr = IfAddrMsg {
            ifa_family: family,
            ifa_prefixlen: addr.prefix(),
            ifa_flags: 0,
            ifa_scope: 0,
            ifa_index: ifindex,
        };
        msg.extend_from_slice(unsafe {
            std::slice::from_raw_parts(
                &ifaddr as *const _ as *const u8,
                mem::size_of::<IfAddrMsg>(),
            )
        });

        // Add address attributes
        match addr {
            IpNetwork::V4(v4) => {
                let ip_bytes = v4.ip().octets();
                self.add_attr_bytes(&mut msg, IFA_LOCAL, &ip_bytes);
                self.add_attr_bytes(&mut msg, IFA_ADDRESS, &ip_bytes);
            }
            IpNetwork::V6(v6) => {
                let ip_bytes = v6.ip().octets();
                self.add_attr_bytes(&mut msg, IFA_LOCAL, &ip_bytes);
                self.add_attr_bytes(&mut msg, IFA_ADDRESS, &ip_bytes);
            }
        }

        // Update header
        let hdr = NlMsgHdr {
            nlmsg_len: msg.len() as u32,
            nlmsg_type: RTM_NEWADDR,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        msg[..mem::size_of::<NlMsgHdr>()].copy_from_slice(unsafe {
            std::slice::from_raw_parts(&hdr as *const _ as *const u8, mem::size_of::<NlMsgHdr>())
        });

        self.send_and_ack(&msg)
    }

    /// Deletes an IP address from an interface.
    ///
    /// # Errors
    ///
    /// Returns an error if the address cannot be deleted.
    pub fn delete_address(&mut self, ifindex: u32, addr: IpNetwork) -> Result<()> {
        let seq = self.next_seq();

        let mut msg = Vec::with_capacity(64);

        // Reserve space for header
        msg.extend_from_slice(&[0u8; mem::size_of::<NlMsgHdr>()]);

        // Determine address family
        let family = match addr {
            IpNetwork::V4(_) => libc::AF_INET as u8,
            IpNetwork::V6(_) => libc::AF_INET6 as u8,
        };

        // Add ifaddrmsg
        let ifaddr = IfAddrMsg {
            ifa_family: family,
            ifa_prefixlen: addr.prefix(),
            ifa_flags: 0,
            ifa_scope: 0,
            ifa_index: ifindex,
        };
        msg.extend_from_slice(unsafe {
            std::slice::from_raw_parts(
                &ifaddr as *const _ as *const u8,
                mem::size_of::<IfAddrMsg>(),
            )
        });

        // Add address attribute
        match addr {
            IpNetwork::V4(v4) => {
                let ip_bytes = v4.ip().octets();
                self.add_attr_bytes(&mut msg, IFA_LOCAL, &ip_bytes);
            }
            IpNetwork::V6(v6) => {
                let ip_bytes = v6.ip().octets();
                self.add_attr_bytes(&mut msg, IFA_LOCAL, &ip_bytes);
            }
        }

        // Update header
        let hdr = NlMsgHdr {
            nlmsg_len: msg.len() as u32,
            nlmsg_type: RTM_DELADDR,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        msg[..mem::size_of::<NlMsgHdr>()].copy_from_slice(unsafe {
            std::slice::from_raw_parts(&hdr as *const _ as *const u8, mem::size_of::<NlMsgHdr>())
        });

        self.send_and_ack(&msg)
    }

    /// Adds a route.
    ///
    /// # Errors
    ///
    /// Returns an error if the route cannot be added.
    pub fn add_route(&mut self, route: &Route) -> Result<()> {
        let seq = self.next_seq();

        let mut msg = Vec::with_capacity(128);

        // Reserve space for header
        msg.extend_from_slice(&[0u8; mem::size_of::<NlMsgHdr>()]);

        // Determine address family
        let family = match route.destination {
            IpNetwork::V4(_) => libc::AF_INET as u8,
            IpNetwork::V6(_) => libc::AF_INET6 as u8,
        };

        // Add rtmsg
        let rtmsg = RtMsg {
            rtm_family: family,
            rtm_dst_len: route.destination.prefix(),
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: RT_TABLE_MAIN,
            rtm_protocol: RTPROT_BOOT,
            rtm_scope: RT_SCOPE_UNIVERSE,
            rtm_type: RTN_UNICAST,
            rtm_flags: 0,
        };
        msg.extend_from_slice(unsafe {
            std::slice::from_raw_parts(&rtmsg as *const _ as *const u8, mem::size_of::<RtMsg>())
        });

        // Add destination
        match route.destination {
            IpNetwork::V4(v4) => {
                if route.destination.prefix() > 0 {
                    let ip_bytes = v4.ip().octets();
                    self.add_attr_bytes(&mut msg, RTA_DST, &ip_bytes);
                }
            }
            IpNetwork::V6(v6) => {
                if route.destination.prefix() > 0 {
                    let ip_bytes = v6.ip().octets();
                    self.add_attr_bytes(&mut msg, RTA_DST, &ip_bytes);
                }
            }
        }

        // Add gateway if specified
        if let Some(gateway) = route.gateway {
            match gateway {
                IpAddr::V4(v4) => {
                    self.add_attr_bytes(&mut msg, RTA_GATEWAY, &v4.octets());
                }
                IpAddr::V6(v6) => {
                    self.add_attr_bytes(&mut msg, RTA_GATEWAY, &v6.octets());
                }
            }
        }

        // Add output interface
        self.add_attr_u32(&mut msg, RTA_OIF, route.ifindex);

        // Add metric if specified
        if let Some(metric) = route.metric {
            self.add_attr_u32(&mut msg, RTA_PRIORITY, metric);
        }

        // Update header
        let hdr = NlMsgHdr {
            nlmsg_len: msg.len() as u32,
            nlmsg_type: RTM_NEWROUTE,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        msg[..mem::size_of::<NlMsgHdr>()].copy_from_slice(unsafe {
            std::slice::from_raw_parts(&hdr as *const _ as *const u8, mem::size_of::<NlMsgHdr>())
        });

        self.send_and_ack(&msg)
    }

    /// Deletes a route.
    ///
    /// # Errors
    ///
    /// Returns an error if the route cannot be deleted.
    pub fn delete_route(&mut self, route: &Route) -> Result<()> {
        let seq = self.next_seq();

        let mut msg = Vec::with_capacity(128);

        // Reserve space for header
        msg.extend_from_slice(&[0u8; mem::size_of::<NlMsgHdr>()]);

        // Determine address family
        let family = match route.destination {
            IpNetwork::V4(_) => libc::AF_INET as u8,
            IpNetwork::V6(_) => libc::AF_INET6 as u8,
        };

        // Add rtmsg
        let rtmsg = RtMsg {
            rtm_family: family,
            rtm_dst_len: route.destination.prefix(),
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: RT_TABLE_MAIN,
            rtm_protocol: RTPROT_BOOT,
            rtm_scope: RT_SCOPE_UNIVERSE,
            rtm_type: RTN_UNICAST,
            rtm_flags: 0,
        };
        msg.extend_from_slice(unsafe {
            std::slice::from_raw_parts(&rtmsg as *const _ as *const u8, mem::size_of::<RtMsg>())
        });

        // Add destination
        match route.destination {
            IpNetwork::V4(v4) => {
                if route.destination.prefix() > 0 {
                    self.add_attr_bytes(&mut msg, RTA_DST, &v4.ip().octets());
                }
            }
            IpNetwork::V6(v6) => {
                if route.destination.prefix() > 0 {
                    self.add_attr_bytes(&mut msg, RTA_DST, &v6.ip().octets());
                }
            }
        }

        // Update header
        let hdr = NlMsgHdr {
            nlmsg_len: msg.len() as u32,
            nlmsg_type: RTM_DELROUTE,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        msg[..mem::size_of::<NlMsgHdr>()].copy_from_slice(unsafe {
            std::slice::from_raw_parts(&hdr as *const _ as *const u8, mem::size_of::<NlMsgHdr>())
        });

        self.send_and_ack(&msg)
    }

    /// Gets interface index by name.
    ///
    /// # Errors
    ///
    /// Returns an error if the interface is not found.
    pub fn get_ifindex(&self, name: &str) -> Result<u32> {
        let c_name = CString::new(name).map_err(|e| NetError::Netlink(e.to_string()))?;
        let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if ifindex == 0 {
            return Err(NetError::Netlink(format!("interface not found: {name}")));
        }
        Ok(ifindex)
    }

    /// Gets interface name by index.
    ///
    /// # Errors
    ///
    /// Returns an error if the interface is not found.
    pub fn get_ifname(&self, ifindex: u32) -> Result<String> {
        let mut buf = [0i8; libc::IF_NAMESIZE];
        let ret = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr()) };
        if ret.is_null() {
            return Err(NetError::Netlink(format!(
                "interface index not found: {ifindex}"
            )));
        }

        let len = buf.iter().position(|&c| c == 0).unwrap_or(libc::IF_NAMESIZE);
        let name_bytes: Vec<u8> = buf[..len].iter().map(|&c| c as u8).collect();
        String::from_utf8(name_bytes).map_err(|e| NetError::Netlink(e.to_string()))
    }

    /// Adds a string attribute to the message.
    fn add_attr_string(&self, msg: &mut Vec<u8>, attr_type: u16, value: &str) {
        let value_bytes = value.as_bytes();
        let attr_len = mem::size_of::<NlAttr>() + value_bytes.len() + 1; // +1 for null terminator
        let padded_len = (attr_len + 3) & !3; // Align to 4 bytes

        let attr = NlAttr {
            nla_len: attr_len as u16,
            nla_type: attr_type,
        };
        msg.extend_from_slice(unsafe {
            std::slice::from_raw_parts(&attr as *const _ as *const u8, mem::size_of::<NlAttr>())
        });
        msg.extend_from_slice(value_bytes);
        msg.push(0); // Null terminator

        // Padding
        let padding = padded_len - attr_len;
        msg.extend(std::iter::repeat(0).take(padding));
    }

    /// Adds a u32 attribute to the message.
    fn add_attr_u32(&self, msg: &mut Vec<u8>, attr_type: u16, value: u32) {
        let attr_len = mem::size_of::<NlAttr>() + mem::size_of::<u32>();

        let attr = NlAttr {
            nla_len: attr_len as u16,
            nla_type: attr_type,
        };
        msg.extend_from_slice(unsafe {
            std::slice::from_raw_parts(&attr as *const _ as *const u8, mem::size_of::<NlAttr>())
        });
        msg.extend_from_slice(&value.to_ne_bytes());
    }

    /// Adds a bytes attribute to the message.
    fn add_attr_bytes(&self, msg: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
        let attr_len = mem::size_of::<NlAttr>() + value.len();
        let padded_len = (attr_len + 3) & !3; // Align to 4 bytes

        let attr = NlAttr {
            nla_len: attr_len as u16,
            nla_type: attr_type,
        };
        msg.extend_from_slice(unsafe {
            std::slice::from_raw_parts(&attr as *const _ as *const u8, mem::size_of::<NlAttr>())
        });
        msg.extend_from_slice(value);

        // Padding
        let padding = padded_len - attr_len;
        msg.extend(std::iter::repeat(0).take(padding));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netlink_handle_creation() {
        // This test requires root privileges
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping test: requires root privileges");
            return;
        }

        let handle = NetlinkHandle::new();
        assert!(handle.is_ok());
    }

    #[test]
    fn test_get_ifindex_loopback() {
        // This test requires root privileges
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping test: requires root privileges");
            return;
        }

        let handle = NetlinkHandle::new().unwrap();
        let ifindex = handle.get_ifindex("lo");
        assert!(ifindex.is_ok());
        assert!(ifindex.unwrap() > 0);
    }
}
