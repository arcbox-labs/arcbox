//! Root filesystem and mount configuration types.

use serde::{Deserialize, Serialize};

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
