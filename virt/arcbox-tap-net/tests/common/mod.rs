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
