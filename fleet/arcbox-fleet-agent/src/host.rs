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

/// Number of containers the host can run concurrently, derived from memory:
/// one slot per 4 GiB of RAM, at least one. Docker-served Linux pools share
/// this budget (see [`capacities`]).
pub fn docker_budget() -> usize {
    const MIB_PER_SLOT: u64 = 4096;
    (mem_mib() / MIB_PER_SLOT).max(1) as usize
}

/// Build the capacity pools to advertise. The gateway reserves each
/// `(os, arch)` pool independently, so this list is also the agent's admission
/// contract: every advertised pool must be one the agent can actually serve, at
/// a cap it will actually honor.
///
/// - **Docker-served Linux pools.** `docker_arches` is the set of Linux arches
///   Docker can run (empty when Docker is absent). Each is advertised at the
///   full `docker_budget`. On Apple Silicon the arm64 (native) and amd64
///   (Rosetta-emulated) pools are alternative execution modes on one Docker
///   host, so each may use the whole budget when the other is idle.
/// - **Host-runner pool.** The native `(os, arch)` served by the pre-installed
///   runner, capped at `host_max_concurrent`. Omitted when no runner directory
///   is configured (nothing to run it), or when Linux jobs are already
///   Docker-served on this host (a Linux host with Docker).
pub fn capacities(
    host_max_concurrent: usize,
    runner_dir_present: bool,
    docker_arches: &[String],
    docker_budget: usize,
) -> Vec<RuntimeCapacity> {
    build_pools(
        &host_os(),
        &host_arch(),
        host_max_concurrent,
        runner_dir_present,
        docker_arches,
        docker_budget,
    )
}

/// Platform-independent core of [`capacities`], taking the native `(os, arch)`
/// explicitly so it can be exercised for every platform in tests.
fn build_pools(
    native_os: &str,
    native_arch: &str,
    host_max_concurrent: usize,
    runner_dir_present: bool,
    docker_arches: &[String],
    docker_budget: usize,
) -> Vec<RuntimeCapacity> {
    let mut pools = Vec::new();

    let docker_cap = i32::try_from(docker_budget).unwrap_or(i32::MAX);
    for arch in docker_arches {
        pools.push(RuntimeCapacity {
            os: "linux".to_owned(),
            arch: arch.clone(),
            max_concurrent: docker_cap,
        });
    }

    let host_pool_is_docker_served = native_os == "linux" && !docker_arches.is_empty();
    if runner_dir_present && !host_pool_is_docker_served {
        pools.push(RuntimeCapacity {
            os: native_os.to_owned(),
            arch: native_arch.to_owned(),
            max_concurrent: i32::try_from(host_max_concurrent).unwrap_or(i32::MAX),
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

    fn triple(c: &RuntimeCapacity) -> (&str, &str, i32) {
        (c.os.as_str(), c.arch.as_str(), c.max_concurrent)
    }

    #[test]
    fn build_pools_host_only_without_docker() {
        let pools = build_pools("darwin", "arm64", 4, true, &[], 0);
        assert_eq!(pools.len(), 1);
        assert_eq!(triple(&pools[0]), ("darwin", "arm64", 4));
    }

    #[test]
    fn build_pools_macos_adds_docker_linux_pools_at_full_budget() {
        let arches = vec!["arm64".to_owned(), "amd64".to_owned()];
        let pools = build_pools("darwin", "arm64", 2, true, &arches, 4);
        // Each docker linux pool gets the full budget, plus the darwin host pool.
        assert_eq!(pools.len(), 3);
        assert_eq!(triple(&pools[0]), ("linux", "arm64", 4));
        assert_eq!(triple(&pools[1]), ("linux", "amd64", 4));
        assert_eq!(triple(&pools[2]), ("darwin", "arm64", 2));
    }

    #[test]
    fn build_pools_linux_host_pool_is_docker_served() {
        // On a Linux host with Docker the native pool IS the docker linux pool,
        // capped by the docker budget — no separate host-runner pool is added.
        let pools = build_pools("linux", "amd64", 2, true, &["amd64".to_owned()], 4);
        assert_eq!(pools.len(), 1);
        assert_eq!(triple(&pools[0]), ("linux", "amd64", 4));
    }

    #[test]
    fn build_pools_omits_host_pool_without_runner_dir() {
        // Docker-only macOS: no runner dir means no darwin pool is advertised.
        let pools = build_pools("darwin", "arm64", 2, false, &["arm64".to_owned()], 3);
        assert_eq!(pools.len(), 1);
        assert_eq!(triple(&pools[0]), ("linux", "arm64", 3));
    }
}
