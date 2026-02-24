//! OCI image manifest types.

use serde::{Deserialize, Serialize};

// Well-known media types.
pub const MEDIA_TYPE_MANIFEST_V2: &str = "application/vnd.docker.distribution.manifest.v2+json";
pub const MEDIA_TYPE_MANIFEST_LIST: &str =
    "application/vnd.docker.distribution.manifest.list.v2+json";
pub const MEDIA_TYPE_OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const MEDIA_TYPE_OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";

/// OCI image manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageManifest {
    /// Schema version (should be 2).
    pub schema_version: u32,
    /// Media type.
    #[serde(default)]
    pub media_type: String,
    /// Config descriptor.
    pub config: Descriptor,
    /// Layer descriptors.
    pub layers: Vec<Descriptor>,
}

/// Multi-architecture manifest list (fat manifest).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestList {
    /// Schema version (should be 2).
    pub schema_version: u32,
    /// Media type.
    pub media_type: String,
    /// Platform-specific manifests.
    pub manifests: Vec<PlatformManifest>,
}

/// Platform-specific manifest entry in a manifest list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformManifest {
    /// Media type of the referenced manifest.
    pub media_type: String,
    /// Content digest.
    pub digest: String,
    /// Content size.
    pub size: u64,
    /// Platform specification.
    pub platform: Platform,
}

/// Platform specification for multi-arch images.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Platform {
    /// CPU architecture.
    pub architecture: String,
    /// Operating system.
    pub os: String,
    /// OS version (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}

/// Content descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    /// Media type.
    pub media_type: String,
    /// Content digest.
    pub digest: String,
    /// Content size.
    pub size: u64,
}

/// Image configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageConfig {
    /// Architecture.
    pub architecture: String,
    /// OS.
    pub os: String,
    /// Config.
    pub config: ContainerConfigSpec,
    /// Root filesystem.
    pub rootfs: RootFs,
    /// History.
    pub history: Vec<History>,
}

/// Container configuration from image.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerConfigSpec {
    /// User to run as.
    pub user: Option<String>,
    /// Exposed ports.
    pub exposed_ports: Option<std::collections::HashMap<String, serde_json::Value>>,
    /// Environment variables.
    pub env: Option<Vec<String>>,
    /// Entrypoint.
    pub entrypoint: Option<Vec<String>>,
    /// Command.
    pub cmd: Option<Vec<String>>,
    /// Volumes.
    pub volumes: Option<std::collections::HashMap<String, serde_json::Value>>,
    /// Working directory.
    pub working_dir: Option<String>,
    /// Labels.
    pub labels: Option<std::collections::HashMap<String, String>>,
}

/// Root filesystem specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootFs {
    /// Type (should be "layers").
    #[serde(rename = "type")]
    pub fs_type: String,
    /// Layer diff IDs.
    pub diff_ids: Vec<String>,
}

/// Image history entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct History {
    /// Creation timestamp.
    pub created: Option<String>,
    /// Created by (command).
    pub created_by: Option<String>,
    /// Whether this is an empty layer.
    pub empty_layer: Option<bool>,
    /// Comment.
    pub comment: Option<String>,
}
