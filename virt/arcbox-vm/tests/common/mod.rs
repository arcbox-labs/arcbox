/// Returns true if the process is running with effective UID 0 (root).
#[cfg(target_os = "linux")]
pub fn is_root() -> bool {
    // /proc/self/status Uid line: real  effective  saved  filesystem
    std::fs::read_to_string("/proc/self/status")
        .map(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(2))
                .map(|uid| uid == "0")
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Returns true if a network interface named `iface` is registered in the kernel.
#[cfg(target_os = "linux")]
pub fn iface_exists(iface: &str) -> bool {
    // /proc/net/dev lists one interface per line as "  <name>: ..."
    let needle = format!("{iface}:");
    std::fs::read_to_string("/proc/net/dev")
        .map(|s| s.lines().any(|line| line.trim_start().starts_with(&needle)))
        .unwrap_or(false)
}
