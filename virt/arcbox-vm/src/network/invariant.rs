//! Network-identity-invariant sandbox addressing (CORE-81).
//!
//! Every sandbox guest sees the identical network configuration — eth0 on
//! [`GUEST_IP`] with gateway [`GUEST_GATEWAY`] — baked into the kernel `ip=`
//! boot parameter. Snapshots therefore carry no per-sandbox network identity
//! and a `network_override` restore needs zero guest-side work: no reconfig
//! RPC, no resolv.conf rewrite (the nameserver is the fixed gateway
//! everywhere). This mirrors E2B's architecture and is a design prerequisite
//! for the pre-warm pool (CORE-78).
//!
//! The sandbox's external identity — the pool IP the rest of the system
//! (DNS registry, expose DNAT, `CreateSandboxResponse.ip_address`) keeps
//! using — is applied host-side, per TAP, inside the System VM:
//!
//! - Traffic addressed to the pool IP is DNAT'd to [`GUEST_IP`]
//!   (`nat PREROUTING` for forwarded, `nat OUTPUT` for locally originated
//!   packets), and traffic from the TAP toward local services is SNAT'd to
//!   the pool IP in `nat INPUT` so DNS and relays keep seeing the pool
//!   identity.
//! - Sandbox-originated forwarded traffic is SNAT'd to the pool IP in
//!   `nat POSTROUTING`, selected by a per-sandbox packet mark because
//!   POSTROUTING cannot match the input interface.
//! - Because the guest address is identical on every TAP, the post-DNAT
//!   routing decision cannot use the main table. Each to-sandbox packet is
//!   marked from its **pre-NAT** destination (`mangle` runs before `nat` in
//!   the same hook), and a per-sandbox fwmark fib rule routes the rewritten
//!   destination through a per-sandbox table holding `GUEST_IP dev <tap>`.
//!
//! The rule set above is the contract; how it is expressed in the host's
//! netfilter framework is the [`PacketFilter`](super::packet_filter::PacketFilter)
//! seam. The reference implementation is iptables-legacy, because that is
//! what the System VM ships (2026-08, boot-assets rootfs + arcbox kernel
//! config): no nftables userland, no `tc`, and a kernel without
//! `NET_ACT_NAT` / `NETMAP` / `CONNMARK` — what it does enable (`IP_NF_NAT`,
//! `IP_NF_MANGLE`, `NETFILTER_XT_MARK`, `IP_MULTIPLE_TABLES`) is exactly
//! that rule set. The sysctls, the fwmark fib rule, and the per-sandbox
//! table route are framework-independent and installed here.
//!
//! The TAP itself keeps today's point-to-point shape with one change: its
//! local address is the fixed [`GUEST_GATEWAY`] instead of the pool gateway.
//! The peer (`SIOCSIFDSTADDR`) stays the pool IP, which keeps a unique
//! main-table host route per sandbox — that route's only jobs are to let the
//! initial route lookup of locally-originated traffic succeed (the rewrite +
//! fwmark reroute happens in the OUTPUT hooks) and to select the fixed
//! gateway as source address; no packet egresses with the pool destination
//! because every to-sandbox flow is DNAT'd first. ARP toward the guest
//! resolves [`GUEST_IP`] (the table route's on-link next hop), which the
//! guest answers regardless of which snapshot it was restored from.
//!
//! Rules are installed at TAP activation and removed with the TAP. Removal
//! is tolerant of absence so the same teardown serves legacy TAPs, partial
//! activations, and crash-recovery replays; rule specs derive entirely from
//! the allocation, so cleanup needs no extra state.
//!
//! Since CORE-83 this rule set is the `SandboxDatapath::Iptables` mechanism
//! and the automatic fallback; the default datapath applies the same
//! translation with two TCX programs per TAP instead (`super::ebpf`),
//! needing none of the mark/fwmark machinery.

use std::net::Ipv4Addr;

#[cfg(target_os = "linux")]
use super::packet_filter::PacketFilter;
#[cfg(target_os = "linux")]
use super::rtnetlink;
#[cfg(target_os = "linux")]
use crate::error::Result;

/// Fixed guest-side eth0 address every sandbox boots with.
///
/// Link-local space cannot collide with the 172.20.0.0/16 pool or user
/// traffic, and each TAP is an isolated point-to-point link, so identical
/// guest addresses never conflict with each other.
pub const GUEST_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 100, 2);

/// Fixed gateway (the System VM side of every sandbox TAP). Also the guest's
/// DNS nameserver, which is what makes the snapshot's resolv.conf valid on
/// any restore.
pub const GUEST_GATEWAY: Ipv4Addr = Ipv4Addr::new(169, 254, 100, 1);

/// Netmask of the guest link: 169.254.100.0/30 holds exactly the gateway and
/// the guest.
pub const GUEST_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 252);

/// Priority of the per-sandbox fwmark fib rules (before `main`, 32766).
const FIB_RULE_PRIORITY: u32 = 8000;

/// Per-sandbox packet mark and policy-routing table id: the pool IP itself.
///
/// Unique per active sandbox and derivable from the allocation alone, so
/// teardown and crash-recovery replays need no extra state. Caveat: kube-proxy
/// matches marks with masks 0x4000/0x8000; those bits sit in the third pool
/// octet, so the first 16 382 addresses of a /16 pool are conflict-free.
///
/// INVARIANT consumers rely on: the table this mark selects holds exactly
/// one route (`GUEST_IP/32` via the sandbox's TAP). Expose's mangle
/// companions mark every packet on a relay port regardless of destination
/// (`port_forward.rs`) — safe only while any other destination misses this
/// table and falls through to `main`. Never add a second route.
pub fn fwmark(pool_ip: Ipv4Addr) -> u32 {
    u32::from(pool_ip)
}

/// Install the per-TAP translation: sysctls, the packet-filter rules, the
/// fwmark fib rule, and the per-sandbox table route. The TAP must already
/// exist.
#[cfg(target_os = "linux")]
pub(crate) fn install(filter: &dyn PacketFilter, tap: &str, pool_ip: Ipv4Addr) -> Result<()> {
    // rp_filter: the reverse lookup for the fixed guest source only resolves
    // through the fwmark table, which strict mode consults solely when
    // src_valid_mark is set. Write both so the invariant link stays up
    // whatever the global rp_filter policy is.
    write_tap_sysctl(tap, "rp_filter", "0")?;
    write_tap_sysctl(tap, "src_valid_mark", "1")?;

    filter.install_translation(tap, pool_ip)?;

    let mark = fwmark(pool_ip);
    // EEXIST tolerated: an identical rule surviving a crash is exactly what
    // this add would create (specs derive from the allocation alone).
    rtnetlink::execute(
        &rtnetlink::new_fwmark_rule(mark, mark, FIB_RULE_PRIORITY),
        &[libc::EEXIST],
    )?;
    rtnetlink::execute(
        &rtnetlink::replace_link_route(GUEST_IP, tap_ifindex(tap)?, mark),
        &[],
    )?;
    Ok(())
}

/// Remove the per-TAP translation, tolerating absence.
///
/// Also runs for legacy TAPs (which never had these rules) and for partially
/// activated ones, so every miss is a no-op, not an error. The table route
/// and sysctls die with the TAP device and need no explicit removal.
#[cfg(target_os = "linux")]
pub(crate) fn remove(filter: &dyn PacketFilter, tap: &str, pool_ip: Ipv4Addr) -> Result<()> {
    let mut failures = Vec::new();
    if let Err(error) = filter.remove_translation(tap, pool_ip) {
        failures.push(error.to_string());
    }
    let mark = fwmark(pool_ip);
    if let Err(error) = rtnetlink::execute(
        &rtnetlink::del_fwmark_rule(mark, mark, FIB_RULE_PRIORITY),
        &[libc::ENOENT],
    ) {
        failures.push(error.to_string());
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(crate::error::VmmError::Network(format!(
            "sandbox NAT teardown incomplete for {tap}: {}",
            failures.join("; ")
        )))
    }
}

#[cfg(target_os = "linux")]
fn write_tap_sysctl(tap: &str, key: &str, value: &str) -> Result<()> {
    let path = format!("/proc/sys/net/ipv4/conf/{tap}/{key}");
    std::fs::write(&path, value)
        .map_err(|e| crate::error::VmmError::Network(format!("write {path}: {e}")))
}

/// Resolve a TAP's interface index (also the eBPF datapath's map key).
#[cfg(target_os = "linux")]
pub(super) fn tap_ifindex(tap: &str) -> Result<u32> {
    let name = std::ffi::CString::new(tap)
        .map_err(|_| crate::error::VmmError::Network(format!("TAP name {tap:?} contains NUL")))?;
    // SAFETY: name is a valid NUL-terminated string.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(crate::error::VmmError::Network(format!(
            "if_nametoindex {tap}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_form_one_point_to_point_link() {
        // /30: gateway and guest are the only hosts, in the same subnet.
        let mask = u32::from(GUEST_NETMASK);
        assert_eq!(mask.count_ones(), 30);
        assert_eq!(
            u32::from(GUEST_IP) & mask,
            u32::from(GUEST_GATEWAY) & mask,
            "guest and gateway must share the invariant subnet"
        );
        assert!(GUEST_IP.is_link_local());
    }

    #[test]
    fn fwmark_is_unique_per_pool_ip() {
        let a = fwmark("172.20.0.2".parse().unwrap());
        let b = fwmark("172.20.0.3".parse().unwrap());
        assert_ne!(a, b);
        assert_ne!(a, 0, "a zero mark would match unmarked packets");
    }
}
