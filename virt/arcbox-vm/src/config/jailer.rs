use serde::{Deserialize, Serialize};

/// Configuration for running Firecracker under the Jailer sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JailerConfig {
    /// Path to the `jailer` binary.
    pub binary: String,
    /// UID the Firecracker process runs as inside the jail.
    pub uid: u32,
    /// GID the Firecracker process runs as inside the jail.
    pub gid: u32,
    /// Base chroot directory (default: `/srv/jailer`).
    pub chroot_base_dir: Option<String>,
    /// Network namespace path (e.g., `/var/run/netns/myns`).
    pub netns: Option<String>,
    /// Create a new PID namespace.
    #[serde(default)]
    pub new_pid_ns: bool,
    /// cgroup version (`"1"` or `"2"`).
    pub cgroup_version: Option<String>,
    /// Parent cgroup path.
    pub parent_cgroup: Option<String>,
    /// Resource limits in `rlimit` format (e.g., `"fsize=2048"`).
    #[serde(default)]
    pub resource_limits: Vec<String>,
}
