//! Linux-specific OCI configuration types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{IdMapping, Resources, Seccomp, TimeOffsets};

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
