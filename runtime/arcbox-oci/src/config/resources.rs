//! Linux cgroup resource configuration types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
