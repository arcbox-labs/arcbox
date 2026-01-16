//! OCI runtime-spec configuration parsing.
//!
//! This module implements the OCI Runtime Specification config.json format.
//! Reference: <https://github.com/opencontainers/runtime-spec/blob/main/config.md>

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::error::{OciError, Result};
use crate::hooks::Hooks;

/// OCI specification version supported by this implementation.
pub const OCI_VERSION: &str = "1.2.0";

/// OCI runtime configuration (config.json).
///
/// This is the main configuration structure that defines how a container
/// should be created and run according to the OCI runtime specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Spec {
    /// OCI specification version (`SemVer` 2.0.0 format).
    /// REQUIRED field.
    pub oci_version: String,

    /// Container's root filesystem.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<Root>,

    /// Container process to run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<Process>,

    /// Container hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// Container domain name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domainname: Option<String>,

    /// Additional mounts beyond the root filesystem.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<Mount>,

    /// Lifecycle hooks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hooks: Option<Hooks>,

    /// Arbitrary metadata annotations.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,

    /// Linux-specific configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux: Option<Linux>,
}

impl Spec {
    /// Load OCI spec from a config.json file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())?;
        Self::from_json(&content)
    }

    /// Parse OCI spec from JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        let spec: Self = serde_json::from_str(json)?;
        spec.validate()?;
        Ok(spec)
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Serialize to JSON and write to file.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = self.to_json()?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Validate the specification.
    pub fn validate(&self) -> Result<()> {
        // Validate OCI version format (must be valid SemVer).
        if self.oci_version.is_empty() {
            return Err(OciError::MissingField("ociVersion"));
        }

        // Validate version is parseable as semver.
        if self.oci_version.split('.').count() < 2 {
            return Err(OciError::InvalidVersion(self.oci_version.clone()));
        }

        // Validate root if present.
        if let Some(ref root) = self.root {
            if root.path.is_empty() {
                return Err(OciError::InvalidConfig(
                    "root.path cannot be empty".to_string(),
                ));
            }
        }

        // Validate process if present.
        if let Some(ref process) = self.process {
            if process.cwd.is_empty() {
                return Err(OciError::MissingField("process.cwd"));
            }
            if !process.cwd.starts_with('/') {
                return Err(OciError::InvalidConfig(
                    "process.cwd must be an absolute path".to_string(),
                ));
            }
        }

        // Validate mounts.
        for (i, mount) in self.mounts.iter().enumerate() {
            if mount.destination.is_empty() {
                return Err(OciError::InvalidConfig(format!(
                    "mounts[{i}].destination cannot be empty"
                )));
            }
            if !mount.destination.starts_with('/') {
                return Err(OciError::InvalidConfig(format!(
                    "mounts[{i}].destination must be an absolute path"
                )));
            }
        }

        Ok(())
    }

    /// Create a default spec for Linux containers.
    #[must_use]
    pub fn default_linux() -> Self {
        Self {
            oci_version: OCI_VERSION.to_string(),
            root: Some(Root {
                path: "rootfs".to_string(),
                readonly: false,
            }),
            process: Some(Process::default()),
            hostname: None,
            domainname: None,
            mounts: Self::default_mounts(),
            hooks: None,
            annotations: HashMap::new(),
            linux: Some(Linux::default()),
        }
    }

    /// Returns the default mounts for a Linux container.
    fn default_mounts() -> Vec<Mount> {
        vec![
            Mount {
                destination: "/proc".to_string(),
                source: Some("proc".to_string()),
                mount_type: Some("proc".to_string()),
                options: Some(vec![
                    "nosuid".to_string(),
                    "noexec".to_string(),
                    "nodev".to_string(),
                ]),
                ..Default::default()
            },
            Mount {
                destination: "/dev".to_string(),
                source: Some("tmpfs".to_string()),
                mount_type: Some("tmpfs".to_string()),
                options: Some(vec![
                    "nosuid".to_string(),
                    "strictatime".to_string(),
                    "mode=755".to_string(),
                    "size=65536k".to_string(),
                ]),
                ..Default::default()
            },
            Mount {
                destination: "/dev/pts".to_string(),
                source: Some("devpts".to_string()),
                mount_type: Some("devpts".to_string()),
                options: Some(vec![
                    "nosuid".to_string(),
                    "noexec".to_string(),
                    "newinstance".to_string(),
                    "ptmxmode=0666".to_string(),
                    "mode=0620".to_string(),
                ]),
                ..Default::default()
            },
            Mount {
                destination: "/dev/shm".to_string(),
                source: Some("shm".to_string()),
                mount_type: Some("tmpfs".to_string()),
                options: Some(vec![
                    "nosuid".to_string(),
                    "noexec".to_string(),
                    "nodev".to_string(),
                    "mode=1777".to_string(),
                    "size=65536k".to_string(),
                ]),
                ..Default::default()
            },
            Mount {
                destination: "/sys".to_string(),
                source: Some("sysfs".to_string()),
                mount_type: Some("sysfs".to_string()),
                options: Some(vec![
                    "nosuid".to_string(),
                    "noexec".to_string(),
                    "nodev".to_string(),
                    "ro".to_string(),
                ]),
                ..Default::default()
            },
        ]
    }
}

/// Root filesystem configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Root {
    /// Path to the root filesystem (relative to bundle path).
    /// REQUIRED field.
    pub path: String,

    /// Whether the root filesystem is read-only.
    #[serde(default)]
    pub readonly: bool,
}

/// Container process configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Process {
    /// Whether to allocate a terminal.
    #[serde(default)]
    pub terminal: bool,

    /// Console size (only used if terminal is true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console_size: Option<ConsoleSize>,

    /// Current working directory (must be absolute path).
    /// REQUIRED field.
    pub cwd: String,

    /// Environment variables.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,

    /// Command arguments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,

    /// Resource limits (rlimits).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rlimits: Vec<Rlimit>,

    /// `AppArmor` profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apparmor_profile: Option<String>,

    /// Linux capabilities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Capabilities>,

    /// Prevent gaining new privileges.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_new_privileges: bool,

    /// OOM score adjustment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oom_score_adj: Option<i32>,

    /// `SELinux` label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selinux_label: Option<String>,

    /// User specification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,

    /// I/O priority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_priority: Option<IoPriority>,

    /// Scheduler settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduler: Option<Scheduler>,

    /// CPU affinity for exec.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec_cpu_affinity: Option<ExecCpuAffinity>,
}

impl Default for Process {
    fn default() -> Self {
        Self {
            terminal: false,
            console_size: None,
            cwd: "/".to_string(),
            env: vec![
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
                "TERM=xterm".to_string(),
            ],
            args: vec!["sh".to_string()],
            rlimits: vec![Rlimit {
                rlimit_type: "RLIMIT_NOFILE".to_string(),
                soft: 1024,
                hard: 1024,
            }],
            apparmor_profile: None,
            capabilities: Some(Capabilities::default()),
            no_new_privileges: false,
            oom_score_adj: None,
            selinux_label: None,
            user: Some(User::default()),
            io_priority: None,
            scheduler: None,
            exec_cpu_affinity: None,
        }
    }
}

/// Console size configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleSize {
    /// Height in characters.
    pub height: u32,
    /// Width in characters.
    pub width: u32,
}

/// Resource limit (rlimit) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rlimit {
    /// Limit type (e.g., `RLIMIT_NOFILE`).
    #[serde(rename = "type")]
    pub rlimit_type: String,
    /// Soft limit.
    pub soft: u64,
    /// Hard limit.
    pub hard: u64,
}

/// Linux capabilities configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    /// Effective capabilities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective: Vec<String>,
    /// Bounding capabilities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bounding: Vec<String>,
    /// Inheritable capabilities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inheritable: Vec<String>,
    /// Permitted capabilities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permitted: Vec<String>,
    /// Ambient capabilities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ambient: Vec<String>,
}

/// User identity configuration (POSIX).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    /// User ID.
    #[serde(default)]
    pub uid: u32,
    /// Group ID.
    #[serde(default)]
    pub gid: u32,
    /// File creation mask.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub umask: Option<u32>,
    /// Additional group IDs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_gids: Vec<u32>,
}

/// I/O priority configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoPriority {
    /// I/O scheduling class.
    pub class: String,
    /// Priority within class.
    pub priority: i32,
}

/// Process scheduler configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scheduler {
    /// Scheduling policy.
    pub policy: String,
    /// Nice value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nice: Option<i32>,
    /// Priority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    /// Scheduler flags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
    /// Runtime (for deadline scheduler).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<u64>,
    /// Deadline (for deadline scheduler).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline: Option<u64>,
    /// Period (for deadline scheduler).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<u64>,
}

/// CPU affinity for exec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecCpuAffinity {
    /// Initial CPU affinity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial: Option<String>,
    /// Final CPU affinity.
    #[serde(rename = "final", skip_serializing_if = "Option::is_none")]
    pub final_affinity: Option<String>,
}

/// Mount configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mount {
    /// Mount destination (absolute path in container).
    /// REQUIRED field.
    pub destination: String,

    /// Mount source (path or device).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Filesystem type.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub mount_type: Option<String>,

    /// Mount options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,

    /// UID mappings for idmapped mounts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uid_mappings: Vec<IdMapping>,

    /// GID mappings for idmapped mounts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gid_mappings: Vec<IdMapping>,
}

/// ID mapping for user namespace or idmapped mounts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdMapping {
    /// Starting ID in container.
    pub container_id: u32,
    /// Starting ID on host.
    pub host_id: u32,
    /// Number of IDs to map.
    pub size: u32,
}

/// Linux-specific container configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Linux {
    /// Devices to create in container.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<Device>,

    /// UID mappings for user namespace.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uid_mappings: Vec<IdMapping>,

    /// GID mappings for user namespace.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gid_mappings: Vec<IdMapping>,

    /// Kernel parameters (sysctl).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub sysctl: HashMap<String, String>,

    /// Cgroups path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroups_path: Option<String>,

    /// Resource limits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Resources>,

    /// Root filesystem propagation mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rootfs_propagation: Option<String>,

    /// Seccomp configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seccomp: Option<Seccomp>,

    /// Namespaces to join or create.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespaces: Vec<Namespace>,

    /// Paths to mask (make inaccessible).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub masked_paths: Vec<String>,

    /// Paths to make read-only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub readonly_paths: Vec<String>,

    /// `SELinux` mount label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mount_label: Option<String>,

    /// Time offsets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_offsets: Option<TimeOffsets>,
}

/// Device configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    /// Device type (c, b, p, u).
    #[serde(rename = "type")]
    pub device_type: String,
    /// Device path in container.
    pub path: String,
    /// Major device number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub major: Option<i64>,
    /// Minor device number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minor: Option<i64>,
    /// File mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_mode: Option<u32>,
    /// Owner UID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Owner GID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
}

/// Linux namespace configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Namespace {
    /// Namespace type.
    #[serde(rename = "type")]
    pub ns_type: NamespaceType,
    /// Path to join existing namespace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Linux namespace types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NamespaceType {
    /// PID namespace.
    Pid,
    /// Network namespace.
    Network,
    /// Mount namespace.
    Mount,
    /// IPC namespace.
    Ipc,
    /// UTS namespace.
    Uts,
    /// User namespace.
    User,
    /// Cgroup namespace.
    Cgroup,
    /// Time namespace.
    Time,
}

/// Linux cgroup resource limits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resources {
    /// Device access rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<DeviceCgroup>,

    /// Memory limits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryResources>,

    /// CPU limits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<CpuResources>,

    /// Block I/O limits.
    #[serde(rename = "blockIO", skip_serializing_if = "Option::is_none")]
    pub block_io: Option<BlockIoResources>,

    /// PIDs limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pids: Option<PidsResources>,

    /// Huge pages limits.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hugepage_limits: Vec<HugepageLimit>,

    /// Network priorities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkResources>,

    /// RDMA resources.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub rdma: HashMap<String, RdmaResource>,
}

/// Device cgroup rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCgroup {
    /// Allow or deny.
    pub allow: bool,
    /// Device type (a, c, b).
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    /// Major number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub major: Option<i64>,
    /// Minor number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minor: Option<i64>,
    /// Access rights (r, w, m).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
}

/// Memory resource limits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryResources {
    /// Memory limit in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    /// Memory reservation in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reservation: Option<i64>,
    /// Memory + swap limit in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap: Option<i64>,
    /// Kernel memory limit in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<i64>,
    /// Kernel TCP memory limit in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_tcp: Option<i64>,
    /// Swappiness (0-100).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swappiness: Option<u64>,
    /// Disable OOM killer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_oom_killer: Option<bool>,
    /// Use hierarchy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_hierarchy: Option<bool>,
    /// Check before update.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_before_update: Option<bool>,
}

/// CPU resource limits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CpuResources {
    /// CPU shares.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shares: Option<u64>,
    /// CPU quota.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota: Option<i64>,
    /// CPU burst.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burst: Option<u64>,
    /// CPU period.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<u64>,
    /// Realtime runtime.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realtime_runtime: Option<i64>,
    /// Realtime period.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realtime_period: Option<u64>,
    /// CPU set (cores).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpus: Option<String>,
    /// Memory node set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mems: Option<String>,
    /// Idle setting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle: Option<i64>,
}

/// Block I/O resource limits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockIoResources {
    /// Block I/O weight.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u16>,
    /// Leaf weight.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_weight: Option<u16>,
    /// Per-device weight.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub weight_device: Vec<WeightDevice>,
    /// Throttle read bps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub throttle_read_bps_device: Vec<ThrottleDevice>,
    /// Throttle write bps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub throttle_write_bps_device: Vec<ThrottleDevice>,
    /// Throttle read iops.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub throttle_read_iops_device: Vec<ThrottleDevice>,
    /// Throttle write iops.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub throttle_write_iops_device: Vec<ThrottleDevice>,
}

/// Block I/O weight per device.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WeightDevice {
    /// Major device number.
    pub major: i64,
    /// Minor device number.
    pub minor: i64,
    /// Weight.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u16>,
    /// Leaf weight.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_weight: Option<u16>,
}

/// Block I/O throttle per device.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThrottleDevice {
    /// Major device number.
    pub major: i64,
    /// Minor device number.
    pub minor: i64,
    /// Rate limit.
    pub rate: u64,
}

/// PIDs resource limits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PidsResources {
    /// Maximum number of PIDs.
    pub limit: i64,
}

/// Hugepage limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HugepageLimit {
    /// Page size (e.g., "2MB", "1GB").
    pub page_size: String,
    /// Limit in bytes.
    pub limit: u64,
}

/// Network resource limits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkResources {
    /// Class ID for network traffic.
    #[serde(rename = "classID", skip_serializing_if = "Option::is_none")]
    pub class_id: Option<u32>,
    /// Network priorities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub priorities: Vec<NetworkPriority>,
}

/// Network priority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPriority {
    /// Interface name.
    pub name: String,
    /// Priority.
    pub priority: u32,
}

/// RDMA resource limits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RdmaResource {
    /// HCA handles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hca_handles: Option<u32>,
    /// HCA objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hca_objects: Option<u32>,
}

/// Seccomp configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Seccomp {
    /// Default action.
    pub default_action: String,
    /// Default errno return value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_errno_ret: Option<u32>,
    /// Architectures.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub architectures: Vec<String>,
    /// Flags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
    /// Listener path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listener_path: Option<String>,
    /// Listener metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listener_metadata: Option<String>,
    /// Syscall rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub syscalls: Vec<SyscallRule>,
}

/// Seccomp syscall rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyscallRule {
    /// Syscall names.
    pub names: Vec<String>,
    /// Action to take.
    pub action: String,
    /// Errno return value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errno_ret: Option<u32>,
    /// Arguments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<SyscallArg>,
}

/// Seccomp syscall argument filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyscallArg {
    /// Argument index.
    pub index: u32,
    /// Value to compare.
    pub value: u64,
    /// Secondary value (for masked equality).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_two: Option<u64>,
    /// Comparison operator.
    pub op: String,
}

/// Time offsets configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimeOffsets {
    /// Monotonic clock offset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monotonic: Option<TimeOffset>,
    /// Boottime clock offset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boottime: Option<TimeOffset>,
}

/// Time offset value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeOffset {
    /// Seconds offset.
    pub secs: i64,
    /// Nanoseconds offset.
    pub nanosecs: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_spec() {
        let json = r#"{
            "ociVersion": "1.2.0"
        }"#;

        let spec = Spec::from_json(json).unwrap();
        assert_eq!(spec.oci_version, "1.2.0");
        assert!(spec.root.is_none());
        assert!(spec.process.is_none());
    }

    #[test]
    fn test_parse_spec_with_root() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "root": {
                "path": "rootfs",
                "readonly": true
            }
        }"#;

        let spec = Spec::from_json(json).unwrap();
        let root = spec.root.unwrap();
        assert_eq!(root.path, "rootfs");
        assert!(root.readonly);
    }

    #[test]
    fn test_parse_spec_with_process() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "process": {
                "terminal": true,
                "cwd": "/app",
                "args": ["./start.sh"],
                "env": ["PATH=/usr/bin", "HOME=/root"]
            }
        }"#;

        let spec = Spec::from_json(json).unwrap();
        let process = spec.process.unwrap();
        assert!(process.terminal);
        assert_eq!(process.cwd, "/app");
        assert_eq!(process.args, vec!["./start.sh"]);
        assert_eq!(process.env.len(), 2);
    }

    #[test]
    fn test_invalid_cwd() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "process": {
                "cwd": "relative/path"
            }
        }"#;

        let result = Spec::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_default_linux_spec() {
        let spec = Spec::default_linux();
        assert_eq!(spec.oci_version, OCI_VERSION);
        assert!(spec.root.is_some());
        assert!(spec.process.is_some());
        assert!(!spec.mounts.is_empty());
        assert!(spec.linux.is_some());
    }

    #[test]
    fn test_serialize_roundtrip() {
        let spec = Spec::default_linux();
        let json = spec.to_json().unwrap();
        let parsed = Spec::from_json(&json).unwrap();
        assert_eq!(spec.oci_version, parsed.oci_version);
    }

    #[test]
    fn test_invalid_oci_version_empty() {
        let json = r#"{
            "ociVersion": ""
        }"#;
        let result = Spec::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_oci_version_format() {
        let json = r#"{
            "ociVersion": "invalid"
        }"#;
        let result = Spec::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_root_path() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "root": {
                "path": ""
            }
        }"#;
        let result = Spec::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_process_cwd() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "process": {
                "cwd": ""
            }
        }"#;
        let result = Spec::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_mount_destination_relative() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "mounts": [
                {
                    "destination": "relative/path",
                    "source": "/source"
                }
            ]
        }"#;
        let result = Spec::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_mount_destination_empty() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "mounts": [
                {
                    "destination": "",
                    "source": "/source"
                }
            ]
        }"#;
        let result = Spec::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_mounts() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "mounts": [
                {
                    "destination": "/proc",
                    "type": "proc",
                    "source": "proc",
                    "options": ["nosuid", "noexec", "nodev"]
                },
                {
                    "destination": "/dev",
                    "type": "tmpfs",
                    "source": "tmpfs",
                    "options": ["nosuid", "strictatime", "mode=755"]
                }
            ]
        }"#;

        let spec = Spec::from_json(json).unwrap();
        assert_eq!(spec.mounts.len(), 2);
        assert_eq!(spec.mounts[0].destination, "/proc");
        assert_eq!(spec.mounts[0].mount_type, Some("proc".to_string()));
        assert_eq!(spec.mounts[0].options.as_ref().unwrap().len(), 3);
    }

    #[test]
    fn test_parse_linux_namespaces() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "linux": {
                "namespaces": [
                    {"type": "pid"},
                    {"type": "network"},
                    {"type": "mount"},
                    {"type": "ipc"},
                    {"type": "uts"},
                    {"type": "user"},
                    {"type": "cgroup"}
                ]
            }
        }"#;

        let spec = Spec::from_json(json).unwrap();
        let linux = spec.linux.unwrap();
        assert_eq!(linux.namespaces.len(), 7);
        assert_eq!(linux.namespaces[0].ns_type, NamespaceType::Pid);
        assert_eq!(linux.namespaces[1].ns_type, NamespaceType::Network);
    }

    #[test]
    fn test_parse_linux_resources_memory() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "linux": {
                "resources": {
                    "memory": {
                        "limit": 536870912,
                        "reservation": 268435456,
                        "swap": 1073741824,
                        "swappiness": 60
                    }
                }
            }
        }"#;

        let spec = Spec::from_json(json).unwrap();
        let resources = spec.linux.unwrap().resources.unwrap();
        let memory = resources.memory.unwrap();
        assert_eq!(memory.limit, Some(536_870_912));
        assert_eq!(memory.reservation, Some(268_435_456));
        assert_eq!(memory.swap, Some(1_073_741_824));
        assert_eq!(memory.swappiness, Some(60));
    }

    #[test]
    fn test_parse_linux_resources_cpu() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "linux": {
                "resources": {
                    "cpu": {
                        "shares": 1024,
                        "quota": 100000,
                        "period": 100000,
                        "cpus": "0-3",
                        "mems": "0"
                    }
                }
            }
        }"#;

        let spec = Spec::from_json(json).unwrap();
        let resources = spec.linux.unwrap().resources.unwrap();
        let cpu = resources.cpu.unwrap();
        assert_eq!(cpu.shares, Some(1024));
        assert_eq!(cpu.quota, Some(100_000));
        assert_eq!(cpu.period, Some(100_000));
        assert_eq!(cpu.cpus, Some("0-3".to_string()));
        assert_eq!(cpu.mems, Some("0".to_string()));
    }

    #[test]
    fn test_parse_linux_resources_pids() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "linux": {
                "resources": {
                    "pids": {
                        "limit": 1024
                    }
                }
            }
        }"#;

        let spec = Spec::from_json(json).unwrap();
        let resources = spec.linux.unwrap().resources.unwrap();
        let pids = resources.pids.unwrap();
        assert_eq!(pids.limit, 1024);
    }

    #[test]
    fn test_parse_linux_devices() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "linux": {
                "devices": [
                    {
                        "type": "c",
                        "path": "/dev/null",
                        "major": 1,
                        "minor": 3,
                        "fileMode": 438,
                        "uid": 0,
                        "gid": 0
                    }
                ]
            }
        }"#;

        let spec = Spec::from_json(json).unwrap();
        let linux = spec.linux.unwrap();
        assert_eq!(linux.devices.len(), 1);
        assert_eq!(linux.devices[0].device_type, "c");
        assert_eq!(linux.devices[0].path, "/dev/null");
        assert_eq!(linux.devices[0].major, Some(1));
        assert_eq!(linux.devices[0].minor, Some(3));
    }

    #[test]
    fn test_parse_capabilities() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "process": {
                "cwd": "/",
                "capabilities": {
                    "bounding": ["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"],
                    "effective": ["CAP_AUDIT_WRITE", "CAP_KILL"],
                    "inheritable": ["CAP_AUDIT_WRITE", "CAP_KILL"],
                    "permitted": ["CAP_AUDIT_WRITE", "CAP_KILL"],
                    "ambient": ["CAP_AUDIT_WRITE"]
                }
            }
        }"#;

        let spec = Spec::from_json(json).unwrap();
        let caps = spec.process.unwrap().capabilities.unwrap();
        assert_eq!(caps.bounding.len(), 3);
        assert_eq!(caps.effective.len(), 2);
        assert_eq!(caps.inheritable.len(), 2);
        assert_eq!(caps.permitted.len(), 2);
        assert_eq!(caps.ambient.len(), 1);
    }

    #[test]
    fn test_parse_user() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "process": {
                "cwd": "/",
                "user": {
                    "uid": 1000,
                    "gid": 1000,
                    "umask": 18,
                    "additionalGids": [100, 200, 300]
                }
            }
        }"#;

        let spec = Spec::from_json(json).unwrap();
        let user = spec.process.unwrap().user.unwrap();
        assert_eq!(user.uid, 1000);
        assert_eq!(user.gid, 1000);
        assert_eq!(user.umask, Some(18));
        assert_eq!(user.additional_gids, vec![100, 200, 300]);
    }

    #[test]
    fn test_parse_rlimits() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "process": {
                "cwd": "/",
                "rlimits": [
                    {
                        "type": "RLIMIT_NOFILE",
                        "soft": 1024,
                        "hard": 4096
                    },
                    {
                        "type": "RLIMIT_NPROC",
                        "soft": 512,
                        "hard": 1024
                    }
                ]
            }
        }"#;

        let spec = Spec::from_json(json).unwrap();
        let rlimits = spec.process.unwrap().rlimits;
        assert_eq!(rlimits.len(), 2);
        assert_eq!(rlimits[0].rlimit_type, "RLIMIT_NOFILE");
        assert_eq!(rlimits[0].soft, 1024);
        assert_eq!(rlimits[0].hard, 4096);
    }

    #[test]
    fn test_parse_seccomp() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "linux": {
                "seccomp": {
                    "defaultAction": "SCMP_ACT_ERRNO",
                    "defaultErrnoRet": 1,
                    "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86"],
                    "syscalls": [
                        {
                            "names": ["read", "write", "exit"],
                            "action": "SCMP_ACT_ALLOW"
                        }
                    ]
                }
            }
        }"#;

        let spec = Spec::from_json(json).unwrap();
        let seccomp = spec.linux.unwrap().seccomp.unwrap();
        assert_eq!(seccomp.default_action, "SCMP_ACT_ERRNO");
        assert_eq!(seccomp.default_errno_ret, Some(1));
        assert_eq!(seccomp.architectures.len(), 2);
        assert_eq!(seccomp.syscalls.len(), 1);
        assert_eq!(seccomp.syscalls[0].names, vec!["read", "write", "exit"]);
    }

    #[test]
    fn test_parse_annotations() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "annotations": {
                "org.opencontainers.image.os": "linux",
                "org.opencontainers.image.architecture": "amd64",
                "custom.key": "custom.value"
            }
        }"#;

        let spec = Spec::from_json(json).unwrap();
        assert_eq!(spec.annotations.len(), 3);
        assert_eq!(
            spec.annotations.get("org.opencontainers.image.os"),
            Some(&"linux".to_string())
        );
    }

    #[test]
    fn test_parse_hostname_and_domainname() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "hostname": "test-container",
            "domainname": "example.com"
        }"#;

        let spec = Spec::from_json(json).unwrap();
        assert_eq!(spec.hostname, Some("test-container".to_string()));
        assert_eq!(spec.domainname, Some("example.com".to_string()));
    }

    #[test]
    fn test_parse_console_size() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "process": {
                "cwd": "/",
                "terminal": true,
                "consoleSize": {
                    "height": 24,
                    "width": 80
                }
            }
        }"#;

        let spec = Spec::from_json(json).unwrap();
        let process = spec.process.unwrap();
        assert!(process.terminal);
        let size = process.console_size.unwrap();
        assert_eq!(size.height, 24);
        assert_eq!(size.width, 80);
    }

    #[test]
    fn test_parse_linux_masked_and_readonly_paths() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "linux": {
                "maskedPaths": ["/proc/kcore", "/proc/latency_stats"],
                "readonlyPaths": ["/proc/sys", "/proc/sysrq-trigger"]
            }
        }"#;

        let spec = Spec::from_json(json).unwrap();
        let linux = spec.linux.unwrap();
        assert_eq!(linux.masked_paths.len(), 2);
        assert_eq!(linux.readonly_paths.len(), 2);
        assert!(linux.masked_paths.contains(&"/proc/kcore".to_string()));
    }

    #[test]
    fn test_parse_linux_sysctl() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "linux": {
                "sysctl": {
                    "net.ipv4.ip_forward": "1",
                    "net.core.somaxconn": "1024"
                }
            }
        }"#;

        let spec = Spec::from_json(json).unwrap();
        let linux = spec.linux.unwrap();
        assert_eq!(linux.sysctl.len(), 2);
        assert_eq!(
            linux.sysctl.get("net.ipv4.ip_forward"),
            Some(&"1".to_string())
        );
    }

    #[test]
    fn test_parse_uid_gid_mappings() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "linux": {
                "uidMappings": [
                    {"containerId": 0, "hostId": 1000, "size": 1000}
                ],
                "gidMappings": [
                    {"containerId": 0, "hostId": 1000, "size": 1000}
                ]
            }
        }"#;

        let spec = Spec::from_json(json).unwrap();
        let linux = spec.linux.unwrap();
        assert_eq!(linux.uid_mappings.len(), 1);
        assert_eq!(linux.uid_mappings[0].container_id, 0);
        assert_eq!(linux.uid_mappings[0].host_id, 1000);
        assert_eq!(linux.uid_mappings[0].size, 1000);
    }

    #[test]
    fn test_parse_block_io() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "linux": {
                "resources": {
                    "blockIO": {
                        "weight": 500,
                        "leafWeight": 300,
                        "throttleReadBpsDevice": [
                            {"major": 8, "minor": 0, "rate": 104857600}
                        ],
                        "throttleWriteBpsDevice": [
                            {"major": 8, "minor": 0, "rate": 52428800}
                        ]
                    }
                }
            }
        }"#;

        let spec = Spec::from_json(json).unwrap();
        let block_io = spec.linux.unwrap().resources.unwrap().block_io.unwrap();
        assert_eq!(block_io.weight, Some(500));
        assert_eq!(block_io.leaf_weight, Some(300));
        assert_eq!(block_io.throttle_read_bps_device.len(), 1);
        assert_eq!(block_io.throttle_read_bps_device[0].rate, 104_857_600);
    }

    #[test]
    fn test_parse_hugepage_limits() {
        let json = r#"{
            "ociVersion": "1.2.0",
            "linux": {
                "resources": {
                    "hugepageLimits": [
                        {"pageSize": "2MB", "limit": 209715200},
                        {"pageSize": "1GB", "limit": 1073741824}
                    ]
                }
            }
        }"#;

        let spec = Spec::from_json(json).unwrap();
        let limits = spec.linux.unwrap().resources.unwrap().hugepage_limits;
        assert_eq!(limits.len(), 2);
        assert_eq!(limits[0].page_size, "2MB");
        assert_eq!(limits[0].limit, 209_715_200);
    }

    #[test]
    fn test_default_process() {
        let process = Process::default();
        assert!(!process.terminal);
        assert_eq!(process.cwd, "/");
        assert!(!process.args.is_empty());
        assert!(!process.env.is_empty());
    }

    #[test]
    fn test_namespace_type_serialization() {
        let ns = Namespace {
            ns_type: NamespaceType::Network,
            path: Some("/var/run/netns/custom".to_string()),
        };
        let json = serde_json::to_string(&ns).unwrap();
        assert!(json.contains("\"type\":\"network\""));
        assert!(json.contains("/var/run/netns/custom"));
    }

    #[test]
    fn test_valid_oci_versions() {
        // Valid semver versions should pass.
        for version in ["1.0.0", "1.2.0", "2.0.0-rc1", "1.0.0-alpha+build"] {
            let json = format!(r#"{{"ociVersion": "{}"}}"#, version);
            assert!(
                Spec::from_json(&json).is_ok(),
                "Version {} should be valid",
                version
            );
        }
    }
}
