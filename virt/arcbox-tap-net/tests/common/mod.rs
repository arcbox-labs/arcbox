/// Returns true if the process is running with effective UID 0 (root).
#[cfg(target_os = "linux")]
pub fn is_root() -> bool {
    // /proc/self/status Uid line: real  effective  saved  filesystem
    std::fs::read_to_string("/proc/self/status").is_ok_and(|s| {
        s.lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2))
            .is_some_and(|uid| uid == "0")
    })
}

/// Returns true if a network interface named `iface` is registered in the kernel.
#[cfg(target_os = "linux")]
pub fn iface_exists(iface: &str) -> bool {
    // /proc/net/dev lists one interface per line as "  <name>: ..."
    let needle = format!("{iface}:");
    std::fs::read_to_string("/proc/net/dev")
        .is_ok_and(|s| s.lines().any(|line| line.trim_start().starts_with(&needle)))
}

/// Returns true if the kernel routing table has a route for `ip` via `dev`.
#[cfg(target_os = "linux")]
pub fn has_route(ip: &str, dev: &str) -> bool {
    std::process::Command::new("/usr/sbin/ip")
        .args(["route", "show", ip])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains(dev))
}

/// Returns the point-to-point peer address configured on `iface`, if any.
#[cfg(target_os = "linux")]
pub fn get_peer_addr(iface: &str) -> Option<String> {
    let output = std::process::Command::new("/usr/sbin/ip")
        .args(["addr", "show", "dev", iface])
        .output()
        .ok()?;
    let out = String::from_utf8_lossy(&output.stdout);
    // Look for "peer <ip>/32" in the output.
    for line in out.lines() {
        if let Some(idx) = line.find("peer ") {
            let rest = &line[idx + 5..];
            return rest.split('/').next().map(String::from);
        }
    }
    None
}

/// Where a stock distro installs `nft`, in the order [`Nftables::discover`]
/// searches — kept here so a test can also *read* the ruleset it installed.
#[cfg(target_os = "linux")]
const NFT_CANDIDATES: &[&str] = &["/usr/sbin/nft", "/sbin/nft"];

/// The `nft` binary to drive, having moved this thread into a private
/// network namespace — or `None`, with the reason printed.
///
/// The namespace is what makes this test safe to run on a workstation:
/// nftables rulesets are per-netns, so `table ip arcbox` is created,
/// inspected, and discarded without the host's own ruleset ever seeing it.
/// It is per-*thread*, so sibling tests keep the netns they started in.
///
/// `ARCBOX_REQUIRE_NFT=1` turns a skip into a failure, for hosts known to
/// have nft (CI) — otherwise the coverage evaporates the day the package
/// stops being installed.
#[cfg(target_os = "linux")]
pub fn nft_in_private_netns(test: &str) -> Option<std::path::PathBuf> {
    let require = std::env::var("ARCBOX_REQUIRE_NFT").is_ok_and(|v| v == "1");
    let skip = |reason: String| -> Option<std::path::PathBuf> {
        assert!(
            !require,
            "ARCBOX_REQUIRE_NFT=1 but {test} would skip: {reason}"
        );
        eprintln!("SKIP {test} — {reason}");
        None
    };

    if !is_root() {
        return skip("requires root (netfilter, and unshare(CLONE_NEWNET))".into());
    }
    let Some(nft) = NFT_CANDIDATES
        .iter()
        .map(std::path::PathBuf::from)
        .find(|bin| bin.exists())
    else {
        return skip(format!("no nft among {}", NFT_CANDIDATES.join(", ")));
    };
    // SAFETY: `unshare` is a plain syscall with no memory operands; it moves
    // this thread into a fresh network namespace and reports failure through
    // errno, which the caller turns into a skip.
    if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
        let errno = std::io::Error::last_os_error();
        return skip(format!("unshare(CLONE_NEWNET): {errno}"));
    }
    Some(nft)
}

/// How many rules in `table ip arcbox` carry `tag`. Every rule of one TAP's
/// translation carries exactly one, so this is that TAP's rule count.
///
/// Matches the comment for equality, the way the production reader in
/// `packet_filter::nftables` does: a substring count would fold
/// `arcbox-nat:vmtap9-20` into a query for `arcbox-nat:vmtap9-2`. A failed
/// listing panics rather than counting zero — "the table is gone" and "nft
/// could not be asked" are opposite answers, and the assertions that expect
/// `0` must not accept the second.
#[cfg(target_os = "linux")]
pub fn nft_rules_tagged(nft: &std::path::Path, tag: &str) -> usize {
    let output = std::process::Command::new(nft)
        .args(["-j", "-a", "list", "table", "ip", "arcbox"])
        .output()
        .expect("run nft");
    assert!(
        output.status.success(),
        "nft list table ip arcbox: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let listing: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse nft listing");
    listing["nftables"]
        .as_array()
        .expect("nftables listing array")
        .iter()
        .filter(|item| item["rule"]["comment"] == serde_json::json!(tag))
        .count()
}
