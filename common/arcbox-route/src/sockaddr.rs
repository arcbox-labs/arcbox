//! Sockaddr builders for routing socket messages.
//!
//! Constructs `sockaddr_in` (IPv4 destination/netmask) and `sockaddr_dl`
//! (link-layer interface gateway) for use in PF_ROUTE messages.

use std::net::Ipv4Addr;

use crate::Ipv4Net;

/// Constructs a `sockaddr_in` for a destination network address.
pub fn make_dst(net: Ipv4Net) -> libc::sockaddr_in {
    make_sin(net.addr())
}

/// Constructs a `sockaddr_in` for a netmask from an [`Ipv4Net`].
pub fn make_netmask(net: Ipv4Net) -> libc::sockaddr_in {
    make_sin(net.mask())
}

/// Constructs a `sockaddr_in` from a raw IPv4 address.
fn make_sin(addr: Ipv4Addr) -> libc::sockaddr_in {
    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sin.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
    sin.sin_family = libc::AF_INET as u8;
    sin.sin_addr.s_addr = u32::from(addr).to_be();
    sin
}

/// Constructs a `sockaddr_dl` with an explicit interface index.
pub fn make_gateway_dl(iface: &str, index: u16) -> libc::sockaddr_dl {
    let mut sdl: libc::sockaddr_dl = unsafe { std::mem::zeroed() };
    sdl.sdl_len = std::mem::size_of::<libc::sockaddr_dl>() as u8;
    sdl.sdl_family = libc::AF_LINK as u8;
    sdl.sdl_index = index;

    let name_bytes = iface.as_bytes();
    let copy_len = name_bytes.len().min(sdl.sdl_data.len());
    sdl.sdl_nlen = copy_len as u8;
    // Safety: copy_len is bounded by sdl_data length (12 bytes).
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            sdl.sdl_data.as_mut_ptr().cast::<u8>(),
            copy_len,
        );
    }

    sdl
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dst_has_correct_family_and_len() {
        let net: Ipv4Net = "10.0.0.0/8".parse().unwrap();
        let sin = make_dst(net);
        assert_eq!(sin.sin_family, libc::AF_INET as u8);
        assert_eq!(sin.sin_len, std::mem::size_of::<libc::sockaddr_in>() as u8);
        assert_eq!(
            sin.sin_addr.s_addr,
            u32::from(Ipv4Addr::new(10, 0, 0, 0)).to_be()
        );
    }

    #[test]
    fn netmask_prefix_8() {
        let net: Ipv4Net = "10.0.0.0/8".parse().unwrap();
        let sin = make_netmask(net);
        assert_eq!(
            sin.sin_addr.s_addr,
            u32::from(Ipv4Addr::new(255, 0, 0, 0)).to_be()
        );
    }

    #[test]
    fn netmask_prefix_12() {
        let net: Ipv4Net = "172.16.0.0/12".parse().unwrap();
        let sin = make_netmask(net);
        assert_eq!(
            sin.sin_addr.s_addr,
            u32::from(Ipv4Addr::new(255, 240, 0, 0)).to_be()
        );
    }

    #[test]
    fn netmask_prefix_16() {
        let net: Ipv4Net = "192.168.0.0/16".parse().unwrap();
        let sin = make_netmask(net);
        assert_eq!(
            sin.sin_addr.s_addr,
            u32::from(Ipv4Addr::new(255, 255, 0, 0)).to_be()
        );
    }

    #[test]
    fn netmask_prefix_24() {
        let net: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let sin = make_netmask(net);
        assert_eq!(
            sin.sin_addr.s_addr,
            u32::from(Ipv4Addr::new(255, 255, 255, 0)).to_be()
        );
    }

    #[test]
    fn netmask_prefix_0() {
        let net: Ipv4Net = "0.0.0.0/0".parse().unwrap();
        let sin = make_netmask(net);
        assert_eq!(sin.sin_addr.s_addr, 0);
    }

    #[test]
    fn netmask_prefix_32() {
        let net: Ipv4Net = "10.0.0.1/32".parse().unwrap();
        let sin = make_netmask(net);
        assert_eq!(sin.sin_addr.s_addr, u32::from(Ipv4Addr::BROADCAST).to_be());
    }

    #[test]
    fn gateway_dl_with_index_sets_fields() {
        let sdl = make_gateway_dl("bridge100", 42);
        assert_eq!(sdl.sdl_family, libc::AF_LINK as u8);
        assert_eq!(sdl.sdl_index, 42);
        assert_eq!(sdl.sdl_nlen, 9); // "bridge100".len()
        assert_eq!(sdl.sdl_len, std::mem::size_of::<libc::sockaddr_dl>() as u8);
    }
}
