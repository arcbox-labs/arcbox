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

/// Build the capacity pools to advertise: the host's native pool plus any
/// Linux pools Docker can serve.
///
/// `docker_arches` lists the Linux architectures Docker can run (e.g.
/// `["arm64", "amd64"]` on Apple Silicon macOS). Empty when Docker adds no
/// pools (disabled, unavailable, or on Linux where the host pool covers it).
pub fn capacities(max_concurrent: usize, docker_arches: &[String]) -> Vec<RuntimeCapacity> {
    let cap = i32::try_from(max_concurrent).unwrap_or(i32::MAX);
    let mut pools = vec![RuntimeCapacity {
        os: host_os(),
        arch: host_arch(),
        max_concurrent: cap,
    }];

    for arch in docker_arches {
        pools.push(RuntimeCapacity {
            os: "linux".to_owned(),
            arch: arch.clone(),
            max_concurrent: cap,
        });
    }

    pools
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

    #[test]
    fn capacities_without_docker_returns_host_pool_only() {
        let pools = capacities(4, &[]);
        assert_eq!(pools.len(), 1);
        assert_eq!(pools[0].max_concurrent, 4);
    }

    #[test]
    fn capacities_with_docker_adds_linux_pools() {
        let arches = vec!["arm64".to_owned(), "amd64".to_owned()];
        let pools = capacities(3, &arches);
        assert_eq!(pools.len(), 3);
        assert_eq!(pools[1].os, "linux");
        assert_eq!(pools[1].arch, "arm64");
        assert_eq!(pools[1].max_concurrent, 3);
        assert_eq!(pools[2].os, "linux");
        assert_eq!(pools[2].arch, "amd64");
        assert_eq!(pools[2].max_concurrent, 3);
    }

    #[test]
    fn capacities_with_single_docker_arch() {
        let arches = vec!["amd64".to_owned()];
        let pools = capacities(2, &arches);
        assert_eq!(pools.len(), 2);
        assert_eq!(pools[1].os, "linux");
        assert_eq!(pools[1].arch, "amd64");
    }
}
