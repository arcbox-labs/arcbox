//! PF_ROUTE routing socket API for macOS.
//!
//! Provides a safe Rust interface for manipulating the macOS routing table
//! via the BSD routing socket (`PF_ROUTE`). This replaces shelling out to
//! `/sbin/route` with direct kernel syscalls, consistent with how the rest
//! of the ArcBox codebase handles low-level Darwin APIs.
//!
//! # Types
//!
//! - [`Ipv4Net`] — Validated IPv4 network (address + prefix). Guarantees
//!   `prefix ≤ 32` and host bits are zero. This is the single source of
//!   truth for "a valid subnet" across the codebase.
//!
//! # Operations
//!
//! - [`add`] — Add a subnet route via an interface. Replaces an existing
//!   route when necessary.
//! - [`remove`] — Delete a subnet route. Idempotent (missing route = Ok).
//! - [`get`] — Query the current route for a subnet.
//!
//! # Example
//!
//! ```no_run
//! use arcbox_route::{add, remove, Ipv4Net};
//!
//! let net: Ipv4Net = "172.16.0.0/12".parse().unwrap();
//! add(net, "bridge100").unwrap();
//! remove(net).unwrap();
//! ```

#![cfg(target_os = "macos")]

pub mod msg;
pub(crate) mod sockaddr;

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

// ── Ipv4Net: validated network type ────────────────────────────────────

/// A validated IPv4 network address with prefix length.
///
/// Guarantees:
/// - `prefix` ≤ 32
/// - No non-zero host bits (e.g. `10.0.0.1/8` is rejected)
///
/// This is the canonical representation of "a subnet" used by all route
/// operations. Higher-level crates (arcbox-helper) may impose additional
/// policy constraints (e.g. private-range-only) on top of this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Net {
    addr: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Net {
    /// Creates a new `Ipv4Net` after validating prefix length and host bits.
    ///
    /// # Errors
    ///
    /// Returns an error if `prefix > 32` or the address has non-zero host bits.
    pub fn new(addr: Ipv4Addr, prefix: u8) -> Result<Self, Ipv4NetError> {
        if prefix > 32 {
            return Err(Ipv4NetError::PrefixTooLong(prefix));
        }
        let mask = Self::prefix_to_mask(prefix);
        let addr_u32 = u32::from(addr);
        if addr_u32 & !mask != 0 {
            let corrected = Ipv4Addr::from(addr_u32 & mask);
            return Err(Ipv4NetError::HostBitsSet {
                given: addr,
                corrected,
                prefix,
            });
        }
        Ok(Self { addr, prefix })
    }

    /// Returns the network address.
    #[inline]
    pub const fn addr(self) -> Ipv4Addr {
        self.addr
    }

    /// Returns the prefix length (0..=32).
    #[inline]
    pub const fn prefix(self) -> u8 {
        self.prefix
    }

    /// Returns the subnet mask as an `Ipv4Addr`.
    #[inline]
    pub fn mask(self) -> Ipv4Addr {
        Ipv4Addr::from(Self::prefix_to_mask(self.prefix))
    }

    /// Converts a prefix length to a `u32` mask in host byte order.
    const fn prefix_to_mask(prefix: u8) -> u32 {
        if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        }
    }
}

/// Errors when constructing an [`Ipv4Net`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv4NetError {
    /// Prefix length exceeds 32.
    PrefixTooLong(u8),
    /// Address has non-zero host bits.
    HostBitsSet {
        given: Ipv4Addr,
        corrected: Ipv4Addr,
        prefix: u8,
    },
    /// Failed to parse CIDR string.
    Parse(String),
}

impl fmt::Display for Ipv4NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrefixTooLong(p) => write!(f, "prefix length {p} exceeds 32"),
            Self::HostBitsSet {
                given,
                corrected,
                prefix,
            } => write!(
                f,
                "{given}/{prefix} has non-zero host bits (did you mean {corrected}/{prefix}?)"
            ),
            Self::Parse(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for Ipv4NetError {}

impl FromStr for Ipv4Net {
    type Err = Ipv4NetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_str, prefix_str) = s
            .split_once('/')
            .ok_or_else(|| Ipv4NetError::Parse(format!("missing '/' in '{s}'")))?;

        let addr: Ipv4Addr = addr_str
            .parse()
            .map_err(|e| Ipv4NetError::Parse(format!("invalid address '{addr_str}': {e}")))?;

        let prefix: u8 = prefix_str
            .parse()
            .map_err(|e| Ipv4NetError::Parse(format!("invalid prefix '{prefix_str}': {e}")))?;

        Self::new(addr, prefix)
    }
}

impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

// ── RouteInfo ──────────────────────────────────────────────────────────

/// Information about an existing route, returned by [`get`].
#[derive(Debug, Clone)]
pub struct RouteInfo {
    /// Kernel interface index the route points to.
    pub ifindex: u16,
    /// Route flags (`RTF_*`).
    pub flags: i32,
}

// ── Public API ─────────────────────────────────────────────────────────

/// Adds a subnet route via the specified interface.
///
/// Equivalent to: `route -n add -net <net> -interface <iface>`
///
/// If the route already exists (`EEXIST`), deletes it before adding the
/// interface route. XNU's `RTM_CHANGE` cannot clear `RTF_GATEWAY`, so it
/// cannot safely convert a conflicting VPN gateway route.
///
/// # Errors
///
/// Returns an error string if the kernel rejects the route operation.
pub fn add(net: Ipv4Net, iface: &str) -> Result<(), String> {
    let dst = sockaddr::make_dst(net);
    let mask = sockaddr::make_netmask(net);
    let gw = sockaddr::make_gateway_dl(iface)
        .map_err(|e| format!("RTM_ADD {net} via {iface}: failed to resolve interface: {e}"))?;

    let add_msg = msg::build_msg(msg::MsgType::Add, &dst, Some(&gw), &mask)
        .map_err(|e| format!("RTM_ADD {net} via {iface}: failed to build message: {e}"))?;

    match msg::route_write(&add_msg) {
        Ok(()) => {
            tracing::debug!(iface, net = %net, "route added");
            Ok(())
        }
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
            tracing::debug!(iface, net = %net, "route exists, replacing via delete and add");
            remove(net)?;
            msg::route_write(&add_msg)
                .map_err(|e| format!("RTM_ADD {net} via {iface} after delete: {e}"))?;
            tracing::debug!(iface, net = %net, "route replaced");
            Ok(())
        }
        Err(e) => Err(format!("RTM_ADD {net} via {iface}: {e}")),
    }
}

/// Removes a subnet route.
///
/// Equivalent to: `route -n delete -net <net>`
///
/// Idempotent: returns `Ok(())` if the route is already absent (`ESRCH`).
///
/// # Errors
///
/// Returns an error string if the kernel rejects the delete.
pub fn remove(net: Ipv4Net) -> Result<(), String> {
    let dst = sockaddr::make_dst(net);
    let mask = sockaddr::make_netmask(net);

    let del_msg = msg::build_msg(msg::MsgType::Delete, &dst, None, &mask)
        .map_err(|e| format!("RTM_DELETE {net}: failed to build message: {e}"))?;

    match msg::route_write(&del_msg) {
        Ok(()) => {
            tracing::debug!(net = %net, "route removed");
            Ok(())
        }
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {
            tracing::debug!(net = %net, "route already absent");
            Ok(())
        }
        Err(e) => Err(format!("RTM_DELETE {net}: {e}")),
    }
}

/// Queries the routing table for a subnet route.
///
/// Returns `Some(RouteInfo)` if a matching route exists, `None` if absent.
///
/// Unlike mutations, this reads the kernel reply (matched by seq/pid)
/// to extract interface index and flags.
///
/// # Errors
///
/// Returns an error string if the query fails for reasons other than
/// route-not-found.
pub fn get(net: Ipv4Net) -> Result<Option<RouteInfo>, String> {
    let dst = sockaddr::make_dst(net);
    let mask = sockaddr::make_netmask(net);

    let get_msg = msg::build_msg(msg::MsgType::Get, &dst, None, &mask)
        .map_err(|e| format!("RTM_GET {net}: failed to build message: {e}"))?;

    match msg::route_query(&get_msg) {
        Ok(reply) => Ok(Some(RouteInfo {
            ifindex: reply.ifindex,
            flags: reply.flags,
        })),
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(None),
        Err(e) => Err(format!("RTM_GET {net}: {e}")),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    struct RouteCleanup(Ipv4Net);

    impl Drop for RouteCleanup {
        fn drop(&mut self) {
            let _ = remove(self.0);
        }
    }

    #[test]
    fn ipv4net_valid() {
        let net = Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap();
        assert_eq!(net.addr(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(net.prefix(), 8);
        assert_eq!(net.mask(), Ipv4Addr::new(255, 0, 0, 0));
    }

    #[test]
    fn ipv4net_prefix_0_and_32() {
        Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap();
        Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 1), 32).unwrap();
    }

    #[test]
    fn ipv4net_rejects_prefix_33() {
        let err = Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 33).unwrap_err();
        assert!(matches!(err, Ipv4NetError::PrefixTooLong(33)));
    }

    #[test]
    fn ipv4net_rejects_host_bits() {
        let err = Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 1), 8).unwrap_err();
        assert!(matches!(
            err,
            Ipv4NetError::HostBitsSet {
                corrected,
                prefix: 8,
                ..
            } if corrected == Ipv4Addr::new(10, 0, 0, 0)
        ));
    }

    #[test]
    fn ipv4net_parse_roundtrip() {
        let net: Ipv4Net = "172.16.0.0/12".parse().unwrap();
        assert_eq!(net.to_string(), "172.16.0.0/12");
    }

    #[test]
    fn ipv4net_parse_rejects_missing_slash() {
        assert!("10.0.0.0".parse::<Ipv4Net>().is_err());
    }

    #[test]
    fn ipv4net_parse_rejects_bad_prefix() {
        assert!("10.0.0.0/33".parse::<Ipv4Net>().is_err());
    }

    #[test]
    fn ipv4net_parse_rejects_host_bits() {
        assert!("10.0.0.1/8".parse::<Ipv4Net>().is_err());
    }

    #[test]
    fn ipv4net_display() {
        let net = Ipv4Net::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap();
        assert_eq!(format!("{net}"), "192.168.0.0/16");
    }

    #[test]
    fn ipv4net_mask_values() {
        assert_eq!(
            "10.0.0.0/8".parse::<Ipv4Net>().unwrap().mask(),
            Ipv4Addr::new(255, 0, 0, 0)
        );
        assert_eq!(
            "172.16.0.0/12".parse::<Ipv4Net>().unwrap().mask(),
            Ipv4Addr::new(255, 240, 0, 0)
        );
        assert_eq!(
            "0.0.0.0/0".parse::<Ipv4Net>().unwrap().mask(),
            Ipv4Addr::UNSPECIFIED
        );
    }

    #[test]
    #[ignore = "requires root to mutate the macOS routing table"]
    fn gateway_route_is_replaced_with_interface_route() {
        use std::process::Command;

        let net: Ipv4Net = "198.51.100.0/24".parse().unwrap();
        remove(net).unwrap();
        let _cleanup = RouteCleanup(net);

        let output = Command::new("/sbin/route")
            .args(["-n", "add", "-net", &net.to_string(), "127.0.0.1"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "failed to install gateway-route fixture: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        add(net, "lo0").unwrap();
        let route = get(net).unwrap().expect("replacement route should exist");

        assert_eq!(route.flags & libc::RTF_GATEWAY, 0);
        let lo0 = std::ffi::CString::new("lo0").unwrap();
        // Safety: `lo0` is a valid NUL-terminated interface name.
        let lo0_index = unsafe { libc::if_nametoindex(lo0.as_ptr()) };
        assert_ne!(lo0_index, 0);
        assert_eq!(u32::from(route.ifindex), lo0_index);
    }
}
