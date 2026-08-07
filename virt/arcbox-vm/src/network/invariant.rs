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
//! Mechanism choice is grounded in what the System VM actually ships
//! (2026-08, boot-assets rootfs + arcbox kernel config): static
//! iptables-legacy and busybox only — no nftables userland, no `tc`, and the
//! kernel enables neither `NET_ACT_NAT` nor `NETMAP` nor conntrack marks
//! (`CONNMARK`). What it does enable — `IP_NF_NAT`, `IP_NF_MANGLE`,
//! `NETFILTER_XT_MARK`, `IP_MULTIPLE_TABLES` — is exactly the rule set below.
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

/// Comment tag on every translation rule, marking them as arcbox-owned for
/// forensics (`iptables -S`). Deletion goes by exact rule spec, not the tag.
const RULE_COMMENT: &str = "arcbox-nat";

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

/// One iptables rule of the per-TAP translation set.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct XtRule {
    pub table: &'static str,
    pub chain: &'static str,
    pub spec: Vec<String>,
}

/// The complete per-TAP translation rule set, in install order.
pub(crate) fn translation_rules(tap: &str, pool_ip: Ipv4Addr) -> Vec<XtRule> {
    let mark = format!("{:#x}", fwmark(pool_ip));
    let pool = format!("{pool_ip}/32");
    let comment = |spec: &mut Vec<String>| {
        spec.extend(["-m", "comment", "--comment", RULE_COMMENT].map(String::from));
    };
    let mut rules = Vec::new();
    let mut rule = |table, chain, head: &[&str], tail: &[&str]| {
        let mut spec: Vec<String> = head.iter().map(|s| (*s).to_owned()).collect();
        comment(&mut spec);
        spec.extend(tail.iter().map(|s| (*s).to_owned()));
        rules.push(XtRule { table, chain, spec });
    };

    // Mark sandbox-originated packets so POSTROUTING (which cannot match the
    // input interface) can select the right source identity.
    rule(
        "mangle",
        "PREROUTING",
        &["-i", tap],
        &["-j", "MARK", "--set-mark", &mark],
    );
    // Mark to-sandbox packets from their pre-NAT destination; the fwmark fib
    // rule then routes the DNAT'd destination out this TAP.
    rule(
        "mangle",
        "PREROUTING",
        &["-d", &pool],
        &["-j", "MARK", "--set-mark", &mark],
    );
    rule(
        "mangle",
        "OUTPUT",
        &["-d", &pool],
        &["-j", "MARK", "--set-mark", &mark],
    );
    // External identity → fixed guest identity, both directions.
    let guest_ip = GUEST_IP.to_string();
    rule(
        "nat",
        "PREROUTING",
        &["-d", &pool],
        &["-j", "DNAT", "--to-destination", &guest_ip],
    );
    rule(
        "nat",
        "OUTPUT",
        &["-d", &pool],
        &["-j", "DNAT", "--to-destination", &guest_ip],
    );
    // Local services (DNS, relays) see the pool identity, and their replies
    // are addressed to it — which is what makes them routable back out the
    // right TAP (dst-based mark + fwmark table).
    rule(
        "nat",
        "INPUT",
        &["-i", tap],
        &["-j", "SNAT", "--to-source", &pool_ip.to_string()],
    );
    // Forwarded sandbox-originated traffic. The source match is the
    // definitive sandbox-origin signature at POSTROUTING (only pre-SNAT
    // sandbox packets carry the fixed guest source); the mark picks which
    // sandbox, keeping to-sandbox packets (marked with the same value but
    // carrying a client source) out of this rewrite.
    rule(
        "nat",
        "POSTROUTING",
        &[
            "-s",
            &format!("{GUEST_IP}/32"),
            "-m",
            "mark",
            "--mark",
            &mark,
        ],
        &["-j", "SNAT", "--to-source", &pool_ip.to_string()],
    );
    rules
}

/// Install the per-TAP translation: sysctls, iptables rules, fwmark fib rule,
/// and the per-sandbox table route. The TAP must already exist.
#[cfg(target_os = "linux")]
pub(crate) fn install(tap: &str, pool_ip: Ipv4Addr) -> Result<()> {
    // rp_filter: the reverse lookup for the fixed guest source only resolves
    // through the fwmark table, which strict mode consults solely when
    // src_valid_mark is set. Write both so the invariant link stays up
    // whatever the global rp_filter policy is.
    write_tap_sysctl(tap, "rp_filter", "0")?;
    write_tap_sysctl(tap, "src_valid_mark", "1")?;

    for rule in translation_rules(tap, pool_ip) {
        run_iptables(&rule, "-A", false)?;
    }

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
pub(crate) fn remove(tap: &str, pool_ip: Ipv4Addr) -> Result<()> {
    let mut failures = Vec::new();
    for rule in translation_rules(tap, pool_ip) {
        if let Err(error) = run_iptables(&rule, "-D", true) {
            failures.push(error.to_string());
        }
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

/// Run one iptables verb on a rule. `tolerate_missing` treats exit status 1 —
/// iptables-legacy's "no matching rule" — as success so teardown is
/// idempotent; other failures (usage errors, the xtables lock timing out)
/// still propagate.
#[cfg(target_os = "linux")]
fn run_iptables(rule: &XtRule, verb: &str, tolerate_missing: bool) -> Result<()> {
    let output = std::process::Command::new("/sbin/iptables")
        .args(["-w", "2", "-t", rule.table, verb, rule.chain])
        .args(&rule.spec)
        .output()
        .map_err(|e| crate::error::VmmError::Network(format!("run iptables: {e}")))?;
    if output.status.success() || (tolerate_missing && output.status.code() == Some(1)) {
        return Ok(());
    }
    Err(crate::error::VmmError::Network(format!(
        "iptables -t {} {verb} {} {}: {}",
        rule.table,
        rule.chain,
        rule.spec.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    )))
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

    /// The rule specs are the NAT contract; pin them exactly so drift is loud.
    #[test]
    fn translation_rules_pin_the_nat_contract() {
        let pool: Ipv4Addr = "172.20.0.2".parse().unwrap();
        let rules = translation_rules("vmtap0-2", pool);
        let rendered: Vec<String> = rules
            .iter()
            .map(|r| format!("-t {} {} {}", r.table, r.chain, r.spec.join(" ")))
            .collect();
        assert_eq!(
            rendered,
            [
                "-t mangle PREROUTING -i vmtap0-2 -m comment --comment arcbox-nat -j MARK --set-mark 0xac140002",
                "-t mangle PREROUTING -d 172.20.0.2/32 -m comment --comment arcbox-nat -j MARK --set-mark 0xac140002",
                "-t mangle OUTPUT -d 172.20.0.2/32 -m comment --comment arcbox-nat -j MARK --set-mark 0xac140002",
                "-t nat PREROUTING -d 172.20.0.2/32 -m comment --comment arcbox-nat -j DNAT --to-destination 169.254.100.2",
                "-t nat OUTPUT -d 172.20.0.2/32 -m comment --comment arcbox-nat -j DNAT --to-destination 169.254.100.2",
                "-t nat INPUT -i vmtap0-2 -m comment --comment arcbox-nat -j SNAT --to-source 172.20.0.2",
                "-t nat POSTROUTING -s 169.254.100.2/32 -m mark --mark 0xac140002 -m comment --comment arcbox-nat -j SNAT --to-source 172.20.0.2",
            ]
        );
    }

    #[test]
    fn snat_selection_never_rewrites_client_sources() {
        // The POSTROUTING SNAT must be gated on the fixed guest source, not
        // the mark alone: to-sandbox packets carry the same mark but a client
        // source, and rewriting those would hide real client IPs from guests.
        let rules = translation_rules("vmtap0-2", "172.20.0.2".parse().unwrap());
        let postrouting = rules
            .iter()
            .find(|r| r.chain == "POSTROUTING")
            .expect("POSTROUTING SNAT rule");
        assert_eq!(postrouting.spec[0], "-s");
        assert_eq!(postrouting.spec[1], format!("{GUEST_IP}/32"));
    }
}
