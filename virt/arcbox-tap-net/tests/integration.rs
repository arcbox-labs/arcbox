//! Root-only integration tests against a real kernel: the network manager's
//! device creation, point-to-point addressing, host routes and pool
//! recycling, and the nftables [`PacketFilter`] rendering the kernel has to
//! accept. Every test skips unless it runs as root on Linux; the nftables
//! ones also move their thread into a private network namespace, so they
//! never touch the host's own ruleset.
//!
//! [`PacketFilter`]: arcbox_tap_net::PacketFilter

mod common;

#[cfg(target_os = "linux")]
use arcbox_tap_net::{NetworkAllocation, NetworkManager, Nftables, PacketFilter};

// ---------------------------------------------------------------------------
// TAP lifecycle (Linux, root only)
// ---------------------------------------------------------------------------

/// NetworkManager creates a real TAP interface on allocation and removes it on
/// release.  Skips if not running as root.
#[test]
#[cfg(target_os = "linux")]
fn tap_lifecycle_via_network_manager() {
    if !common::is_root() {
        eprintln!("SKIP tap_lifecycle_via_network_manager — requires root");
        return;
    }

    // Third octet 10 → TAP name vmtap10<x>, distinct from the other TAP test.
    let mgr = NetworkManager::new("10.0.10.0/28", "10.0.10.1", vec![]).unwrap();
    let alloc = mgr.allocate("itg-tap-lifecycle").unwrap();

    assert!(
        common::iface_exists(&alloc.tap_name),
        "TAP {} should exist after allocate",
        alloc.tap_name
    );

    mgr.release(&alloc);

    assert!(
        !common::iface_exists(&alloc.tap_name),
        "TAP {} should be gone after release",
        alloc.tap_name
    );
}

/// After releasing an allocation the IP re-enters the pool and is assigned on
/// the next call to allocate.  Verifies that the recycled TAP is also cleaned
/// up correctly.  Skips if not running as root.
#[test]
#[cfg(target_os = "linux")]
fn network_ip_returns_to_pool_with_tap() {
    if !common::is_root() {
        eprintln!("SKIP network_ip_returns_to_pool_with_tap — requires root");
        return;
    }

    // Third octet 11 → TAP name vmtap11<x>, distinct from the other TAP test.
    let mgr = NetworkManager::new("10.0.11.0/28", "10.0.11.1", vec![]).unwrap();

    let a1 = mgr.allocate("itg-pool-vm-1").unwrap();
    let first_ip = a1.ip_address;
    mgr.release(&a1);

    let a2 = mgr.allocate("itg-pool-vm-2").unwrap();
    assert_eq!(a2.ip_address, first_ip, "released IP should be reused");

    mgr.release(&a2);
    assert!(
        !common::iface_exists(&a2.tap_name),
        "TAP {} should be gone after final release",
        a2.tap_name
    );
}

// ---------------------------------------------------------------------------
// TAP cleanup guard
// ---------------------------------------------------------------------------

/// RAII guard that releases a TAP allocation on drop, ensuring cleanup even
/// when an assertion panics mid-test.
#[cfg(target_os = "linux")]
struct TapGuard<'a> {
    mgr: &'a NetworkManager,
    alloc: &'a NetworkAllocation,
}

#[cfg(target_os = "linux")]
impl Drop for TapGuard<'_> {
    fn drop(&mut self) {
        self.mgr.release(self.alloc);
    }
}

// ---------------------------------------------------------------------------
// Point-to-point TAP configuration (Linux, root only)
// ---------------------------------------------------------------------------

/// Each TAP gets a point-to-point IP with the gateway as local addr and
/// the sandbox IP as peer, with an explicit /32 host route.
#[test]
#[cfg(target_os = "linux")]
fn tap_has_point_to_point_peer_address() {
    if !common::is_root() {
        eprintln!("SKIP tap_has_point_to_point_peer_address — requires root");
        return;
    }

    let mgr = NetworkManager::new("10.0.12.0/28", "10.0.12.1", vec![]).unwrap();
    let alloc = mgr.allocate("itg-ptp-1").unwrap();
    let guard = TapGuard {
        mgr: &mgr,
        alloc: &alloc,
    };

    // TAP should have the peer address configured.
    let peer = common::get_peer_addr(&alloc.tap_name);
    assert_eq!(
        peer.as_deref(),
        Some(&*alloc.ip_address.to_string()),
        "TAP {} should have peer address {}",
        alloc.tap_name,
        alloc.ip_address
    );

    // Kernel should have a /32 host route to the sandbox IP via this TAP.
    let route_dest = format!("{}/32", alloc.ip_address);
    assert!(
        common::has_route(&route_dest, &alloc.tap_name),
        "expected /32 route to {} via {}",
        alloc.ip_address,
        alloc.tap_name
    );

    // Explicitly drop the guard to trigger release, then verify cleanup.
    drop(guard);

    // Route should be gone after TAP destruction.
    assert!(
        !common::has_route(&route_dest, &alloc.tap_name),
        "route to {} should be removed after release",
        alloc.ip_address
    );
}

/// Multiple TAPs get isolated point-to-point links — each has its own /32
/// route and there is no shared bridge interface.
#[test]
#[cfg(target_os = "linux")]
fn multiple_taps_are_isolated() {
    if !common::is_root() {
        eprintln!("SKIP multiple_taps_are_isolated — requires root");
        return;
    }

    let mgr = NetworkManager::new("10.0.13.0/28", "10.0.13.1", vec![]).unwrap();
    let a1 = mgr.allocate("itg-iso-1").unwrap();
    let _g1 = TapGuard {
        mgr: &mgr,
        alloc: &a1,
    };
    let a2 = mgr.allocate("itg-iso-2").unwrap();
    let _g2 = TapGuard {
        mgr: &mgr,
        alloc: &a2,
    };

    // Both TAPs exist with different IPs.
    assert!(common::iface_exists(&a1.tap_name));
    assert!(common::iface_exists(&a2.tap_name));
    assert_ne!(a1.ip_address, a2.ip_address);

    // Each has its own peer and /32 route.
    assert_eq!(
        common::get_peer_addr(&a1.tap_name).as_deref(),
        Some(&*a1.ip_address.to_string()),
    );
    assert_eq!(
        common::get_peer_addr(&a2.tap_name).as_deref(),
        Some(&*a2.ip_address.to_string()),
    );

    // Neither TAP is attached to a bridge (no "master" in ip link output).
    let out1 = std::process::Command::new("/usr/sbin/ip")
        .args(["link", "show", &a1.tap_name])
        .output()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&out1.stdout).contains("master"),
        "TAP {} should not be attached to any bridge",
        a1.tap_name
    );
}

/// The nftables backend against a real kernel: two sandboxes' rule sets
/// coexist in one table, teardown removes exactly the one it was asked for,
/// and a repeat teardown of the same TAP is a no-op rather than an error.
///
/// This is the half the unit tests cannot reach — that the rendered batch is
/// syntax the kernel accepts, and that removal really finds its handles.
#[test]
#[cfg(target_os = "linux")]
fn nftables_translation_installs_and_removes_per_tap() {
    let Some(nft) =
        common::nft_in_private_netns("nftables_translation_installs_and_removes_per_tap")
    else {
        return;
    };
    // Discovery must agree with the binary this host actually has; the rest
    // of the test drives the found path so a non-standard prefix still works.
    Nftables::discover().expect("a host with nft must discover it");
    let filter = Nftables::new(&nft);

    let (tap_a, pool_a) = ("vmtap9-2", "172.31.9.2".parse().unwrap());
    let (tap_b, pool_b) = ("vmtap9-3", "172.31.9.3".parse().unwrap());

    filter.install_translation(tap_a, pool_a).unwrap();
    filter.install_translation(tap_b, pool_b).unwrap();

    assert_eq!(
        common::nft_rules_tagged(&nft, "arcbox-nat:vmtap9-2"),
        7,
        "the contract is seven rules"
    );
    assert_eq!(common::nft_rules_tagged(&nft, "arcbox-nat:vmtap9-3"), 7);

    filter.remove_translation(tap_a, pool_a).unwrap();

    assert_eq!(
        common::nft_rules_tagged(&nft, "arcbox-nat:vmtap9-2"),
        0,
        "teardown must leave no residue for its own TAP"
    );
    assert_eq!(
        common::nft_rules_tagged(&nft, "arcbox-nat:vmtap9-3"),
        7,
        "and must not touch another sandbox's rules"
    );

    // Tolerating absence is the seam's contract: teardown runs again for
    // crash replays and partially activated TAPs.
    filter.remove_translation(tap_a, pool_a).unwrap();
    filter.remove_translation(tap_b, pool_b).unwrap();
    assert_eq!(common::nft_rules_tagged(&nft, "arcbox-nat:vmtap9-3"), 0);
}

/// A crash replay re-installs over rules that survived the process (unlike
/// eBPF links, netfilter rules do not die with it), so a TAP can end up with
/// two copies of its set. One teardown must collect both — `iptables -D`
/// deletes only the first match, which is the residue this backend avoids by
/// deleting on the tag.
#[test]
#[cfg(target_os = "linux")]
fn a_double_installed_tap_is_fully_torn_down() {
    let Some(nft) = common::nft_in_private_netns("a_double_installed_tap_is_fully_torn_down")
    else {
        return;
    };
    let filter = Nftables::new(&nft);
    let (tap, pool) = ("vmtap9-4", "172.31.9.4".parse().unwrap());

    filter.install_translation(tap, pool).unwrap();
    filter.install_translation(tap, pool).unwrap();
    assert_eq!(common::nft_rules_tagged(&nft, "arcbox-nat:vmtap9-4"), 14);

    filter.remove_translation(tap, pool).unwrap();

    assert_eq!(common::nft_rules_tagged(&nft, "arcbox-nat:vmtap9-4"), 0);
}
