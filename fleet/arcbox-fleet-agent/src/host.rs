//! Host facts reported to the gateway at enrollment and in heartbeats.

use arcbox_fleet_proto::v1::RuntimeCapacity;

/// Map Rust's `target_os` to the gateway's lowercase `RunnerOs` naming.
pub fn map_os(os: &str) -> &str {
    match os {
        "macos" => "darwin",
        other => other, // linux, windows
    }
}

/// Map Rust's `target_arch` to the gateway's lowercase `RunnerArch` naming.
pub fn map_arch(arch: &str) -> &str {
    match arch {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => other,
    }
}

/// Gateway OS string for this host (e.g. `darwin`).
pub fn host_os() -> String {
    map_os(std::env::consts::OS).to_string()
}

/// Gateway arch string for this host (e.g. `arm64`).
pub fn host_arch() -> String {
    map_arch(std::env::consts::ARCH).to_string()
}

/// Best-effort host name; falls back to `"unknown"`.
pub fn machine_name() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Logical CPU count, at least 1.
pub fn cpu_cores() -> u32 {
    std::thread::available_parallelism().map_or(1, |n| n.get() as u32)
}

/// Total physical memory in MiB.
pub fn mem_mib() -> u64 {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    sys.total_memory() / 1024 / 1024
}

/// Free-form host facts as a JSON string (OS version, kernel, arch).
pub fn host_info_json() -> String {
    let info = serde_json::json!({
        "os": sysinfo::System::name(),
        "os_version": sysinfo::System::long_os_version(),
        "kernel": sysinfo::System::kernel_version(),
        "arch": std::env::consts::ARCH,
    });
    info.to_string()
}

/// The single capacity pool this host serves. With no isolation in v1, the
/// host advertises its own `(os, arch)` with the configured concurrency.
pub fn capacities(max_concurrent: usize) -> Vec<RuntimeCapacity> {
    vec![RuntimeCapacity {
        os: host_os(),
        arch: host_arch(),
        max_concurrent: i32::try_from(max_concurrent).unwrap_or(i32::MAX),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_os_and_arch_to_gateway_naming() {
        assert_eq!(map_os("macos"), "darwin");
        assert_eq!(map_os("linux"), "linux");
        assert_eq!(map_arch("aarch64"), "arm64");
        assert_eq!(map_arch("x86_64"), "amd64");
    }
}
