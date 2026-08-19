//! Helpers shared by the `sandbox_manager_e2e` test binary.

/// Returns true if the process is running with effective UID 0 (root).
pub fn is_root() -> bool {
    // /proc/self/status Uid line: real  effective  saved  filesystem
    std::fs::read_to_string("/proc/self/status").is_ok_and(|status| {
        status
            .lines()
            .find(|line| line.starts_with("Uid:"))
            .and_then(|line| line.split_whitespace().nth(2))
            == Some("0")
    })
}

/// Returns true if a network interface named `iface` is registered in the kernel.
pub fn iface_exists(iface: &str) -> bool {
    // /proc/net/dev lists one interface per line as "  <name>: ..."
    let needle = format!("{iface}:");
    std::fs::read_to_string("/proc/net/dev").is_ok_and(|dev| {
        dev.lines()
            .any(|line| line.trim_start().starts_with(&needle))
    })
}
