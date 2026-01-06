//! Container configuration.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Container configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerConfig {
    /// Container name.
    pub name: Option<String>,
    /// Image name.
    pub image: String,
    /// Command to run.
    pub cmd: Vec<String>,
    /// Entrypoint.
    pub entrypoint: Vec<String>,
    /// Environment variables.
    pub env: HashMap<String, String>,
    /// Working directory.
    pub working_dir: Option<String>,
    /// User to run as.
    pub user: Option<String>,
    /// Exposed ports.
    pub exposed_ports: Vec<String>,
    /// Volume mounts.
    pub volumes: Vec<VolumeMount>,
    /// Resource limits.
    pub resources: ResourceLimits,
    /// Labels.
    pub labels: HashMap<String, String>,
    /// Restart policy.
    pub restart_policy: RestartPolicy,
}

/// Volume mount configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMount {
    /// Host path or volume name.
    pub source: String,
    /// Container path.
    pub target: String,
    /// Read-only mount.
    pub read_only: bool,
}

/// Resource limits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// CPU limit (in millicores, e.g., 1000 = 1 CPU).
    pub cpu_limit: Option<u64>,
    /// Memory limit in bytes.
    pub memory_limit: Option<u64>,
    /// Memory reservation in bytes.
    pub memory_reservation: Option<u64>,
}

/// Restart policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    /// Never restart.
    #[default]
    No,
    /// Always restart.
    Always,
    /// Restart on failure.
    OnFailure,
    /// Restart unless stopped.
    UnlessStopped,
}
