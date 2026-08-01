//! Docker CLI JSON DTOs used by migration planning.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Docker daemon info needed by migration.
#[derive(Debug, Clone, Deserialize)]
pub struct DockerInfo {
    /// Daemon name.
    #[serde(rename = "Name")]
    pub name: String,
    /// Server version.
    #[serde(rename = "ServerVersion")]
    pub server_version: String,
    /// Operating system.
    #[serde(rename = "OperatingSystem")]
    pub operating_system: String,
    /// Architecture.
    #[serde(rename = "Architecture")]
    pub architecture: String,
}

/// Image inspect response subset.
#[derive(Debug, Clone, Deserialize)]
pub struct ImageInspect {
    /// Image identifier.
    #[serde(rename = "Id")]
    pub id: String,
    /// Repo tags.
    #[serde(rename = "RepoTags", default)]
    pub repo_tags: Vec<String>,
    /// Repo digests.
    #[serde(rename = "RepoDigests", default)]
    pub repo_digests: Vec<String>,
}

/// Volume inspect response subset.
#[derive(Debug, Clone, Deserialize)]
pub struct VolumeInspect {
    /// Volume name.
    #[serde(rename = "Name")]
    pub name: String,
    /// Driver name.
    #[serde(rename = "Driver")]
    pub driver: String,
    /// Labels.
    #[serde(rename = "Labels", default)]
    pub labels: Option<HashMap<String, String>>,
    /// Driver options.
    #[serde(rename = "Options", default)]
    pub options: Option<HashMap<String, String>>,
}

/// Network inspect response subset.
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkInspect {
    /// Network name.
    #[serde(rename = "Name")]
    pub name: String,
    /// Network identifier.
    #[serde(rename = "Id")]
    pub id: String,
    /// Driver.
    #[serde(rename = "Driver")]
    pub driver: String,
    /// Whether the network is internal.
    #[serde(rename = "Internal", default)]
    pub internal: bool,
    /// Whether IPv6 is enabled.
    #[serde(rename = "EnableIPv6", default)]
    pub enable_ipv6: bool,
    /// Whether the network is attachable.
    #[serde(rename = "Attachable", default)]
    pub attachable: bool,
    /// Labels.
    #[serde(rename = "Labels", default)]
    pub labels: Option<HashMap<String, String>>,
    /// Driver options.
    #[serde(rename = "Options", default)]
    pub options: Option<HashMap<String, String>>,
    /// IPAM settings.
    #[serde(rename = "IPAM", default)]
    pub ipam: NetworkIpam,
}

/// Network IPAM settings.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct NetworkIpam {
    /// IPAM driver.
    #[serde(rename = "Driver", default)]
    pub driver: String,
    /// IPAM config entries.
    #[serde(rename = "Config", default)]
    pub config: Vec<NetworkIpamConfig>,
}

/// Network IPAM config entry.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct NetworkIpamConfig {
    /// Subnet CIDR.
    #[serde(rename = "Subnet", default)]
    pub subnet: String,
    /// Gateway address.
    #[serde(rename = "Gateway", default)]
    pub gateway: String,
    /// IP range.
    #[serde(rename = "IPRange", default)]
    pub ip_range: String,
}

/// Container inspect response subset.
#[derive(Debug, Clone, Deserialize)]
pub struct ContainerInspect {
    /// Container identifier.
    #[serde(rename = "Id")]
    pub id: String,
    /// Container name (leading slash included).
    #[serde(rename = "Name")]
    pub name: String,
    /// Image ID.
    #[serde(rename = "Image")]
    pub image: String,
    /// Container state.
    #[serde(rename = "State")]
    pub state: ContainerState,
    /// Container config.
    #[serde(rename = "Config")]
    pub config: ContainerConfig,
    /// Host config.
    #[serde(rename = "HostConfig")]
    pub host_config: HostConfig,
    /// Network settings.
    #[serde(rename = "NetworkSettings")]
    pub network_settings: NetworkSettings,
    /// Mounts.
    #[serde(rename = "Mounts", default)]
    pub mounts: Vec<MountPoint>,
}

/// Container state subset.
#[derive(Debug, Clone, Deserialize)]
pub struct ContainerState {
    /// Status string.
    #[serde(rename = "Status")]
    pub status: String,
    /// Whether the container is running.
    #[serde(rename = "Running", default)]
    pub running: bool,
}

/// Container config subset.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ContainerConfig {
    /// Hostname.
    #[serde(rename = "Hostname", default)]
    pub hostname: String,
    /// Domain name.
    #[serde(rename = "Domainname", default)]
    pub domainname: String,
    /// User.
    #[serde(rename = "User", default)]
    pub user: String,
    /// Environment variables.
    #[serde(rename = "Env", default)]
    pub env: Option<Vec<String>>,
    /// Command.
    #[serde(rename = "Cmd", default)]
    pub cmd: Option<Vec<String>>,
    /// Image reference string.
    #[serde(rename = "Image", default)]
    pub image: String,
    /// Working directory.
    #[serde(rename = "WorkingDir", default)]
    pub working_dir: String,
    /// Entrypoint.
    #[serde(rename = "Entrypoint", default)]
    pub entrypoint: Option<Vec<String>>,
    /// Labels.
    #[serde(rename = "Labels", default)]
    pub labels: Option<HashMap<String, String>>,
    /// TTY mode.
    #[serde(rename = "Tty", default)]
    pub tty: bool,
    /// Open stdin.
    #[serde(rename = "OpenStdin", default)]
    pub open_stdin: bool,
    /// Exposed ports.
    #[serde(rename = "ExposedPorts", default)]
    pub exposed_ports: Option<HashMap<String, serde_json::Value>>,
}

/// Host config subset.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HostConfig {
    /// Network mode: `bridge`, `host`, `none`, `container:<name|id>`, or the
    /// name of a user-defined network.
    #[serde(rename = "NetworkMode", default)]
    pub network_mode: String,
    /// Port bindings.
    #[serde(rename = "PortBindings", default)]
    pub port_bindings: Option<HashMap<String, Option<Vec<PortBinding>>>>,
    /// Restart policy.
    #[serde(rename = "RestartPolicy", default)]
    pub restart_policy: Option<RestartPolicy>,
    /// Privileged mode.
    #[serde(rename = "Privileged", default)]
    pub privileged: bool,
    /// Read-only root filesystem.
    #[serde(rename = "ReadonlyRootfs", default)]
    pub readonly_rootfs: bool,
    /// Extra hosts.
    #[serde(rename = "ExtraHosts", default)]
    pub extra_hosts: Option<Vec<String>>,
    /// Auto remove.
    #[serde(rename = "AutoRemove", default)]
    pub auto_remove: bool,
}

/// Restart policy subset.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RestartPolicy {
    /// Policy name.
    #[serde(rename = "Name", default)]
    pub name: String,
    /// Maximum retry count.
    #[serde(rename = "MaximumRetryCount", default)]
    pub maximum_retry_count: i64,
}

/// Network settings subset.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct NetworkSettings {
    /// Networks keyed by name.
    #[serde(rename = "Networks", default)]
    pub networks: HashMap<String, EndpointSettings>,
}

/// Endpoint settings subset.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EndpointSettings {
    /// Aliases.
    #[serde(rename = "Aliases", default)]
    pub aliases: Option<Vec<String>>,
}

/// Mount description subset.
#[derive(Debug, Clone, Deserialize)]
pub struct MountPoint {
    /// Mount type.
    #[serde(rename = "Type")]
    pub mount_type: String,
    /// Volume name when applicable.
    #[serde(rename = "Name", default)]
    pub name: String,
    /// Source path or volume mountpoint.
    #[serde(rename = "Source", default)]
    pub source: String,
    /// Destination path inside the container.
    #[serde(rename = "Destination")]
    pub destination: String,
    /// Mount mode.
    #[serde(rename = "Mode", default)]
    pub mode: String,
    /// Whether the mount is writable.
    #[serde(rename = "RW", default)]
    pub rw: bool,
}

/// Port binding subset.
#[derive(Debug, Clone, Deserialize)]
pub struct PortBinding {
    /// Host IP.
    #[serde(rename = "HostIp", default)]
    pub host_ip: String,
    /// Host port.
    #[serde(rename = "HostPort", default)]
    pub host_port: String,
}
