//! Docker API types.
//!
//! Types defined according to Docker Engine API v1.43 specification.
//! See: <https://docs.docker.com/engine/api/v1.43>/

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Container Types
// ============================================================================

/// Container summary (for list).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerSummary {
    /// Container ID.
    pub id: String,
    /// Container names.
    pub names: Vec<String>,
    /// Image name.
    pub image: String,
    /// Image ID.
    pub image_id: String,
    /// Command.
    pub command: String,
    /// Created timestamp.
    pub created: i64,
    /// State.
    pub state: String,
    /// Status string.
    pub status: String,
    /// Ports.
    pub ports: Vec<Port>,
    /// Labels.
    pub labels: HashMap<String, String>,
    /// Size of files written (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_rw: Option<i64>,
    /// Size of root filesystem (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_root_fs: Option<i64>,
    /// Network settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_settings: Option<SummaryNetworkSettings>,
    /// Mounts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mounts: Option<Vec<MountPoint>>,
}

/// Port mapping.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Port {
    /// Private port.
    pub private_port: u16,
    /// Public port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_port: Option<u16>,
    /// Type (tcp/udp).
    #[serde(rename = "Type")]
    pub port_type: String,
    /// IP address (optional).
    #[serde(rename = "IP", skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

/// Network settings summary.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SummaryNetworkSettings {
    /// Networks.
    pub networks: HashMap<String, EndpointSettings>,
}

/// Endpoint settings.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EndpointSettings {
    /// Network ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    /// Endpoint ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<String>,
    /// Gateway.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// IP address.
    #[serde(rename = "IPAddress", skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    /// IP prefix length.
    #[serde(rename = "IPPrefixLen", skip_serializing_if = "Option::is_none")]
    pub ip_prefix_len: Option<i32>,
    /// MAC address.
    #[serde(rename = "MacAddress", skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
}

/// Mount point.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MountPoint {
    /// Mount type.
    #[serde(rename = "Type")]
    pub mount_type: String,
    /// Source.
    pub source: String,
    /// Destination.
    pub destination: String,
    /// Mode.
    pub mode: String,
    /// Read-write.
    #[serde(rename = "RW")]
    pub rw: bool,
    /// Propagation.
    pub propagation: String,
}

/// Container create request.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerCreateRequest {
    /// Hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Domain name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domainname: Option<String>,
    /// User.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Attach stdin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach_stdin: Option<bool>,
    /// Attach stdout.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach_stdout: Option<bool>,
    /// Attach stderr.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach_stderr: Option<bool>,
    /// Exposed ports.
    #[allow(clippy::zero_sized_map_values)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposed_ports: Option<HashMap<String, HashMap<(), ()>>>,
    /// TTY allocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tty: Option<bool>,
    /// Open stdin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_stdin: Option<bool>,
    /// Stdin once.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdin_once: Option<bool>,
    /// Environment variables.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
    /// Command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,
    /// Image name.
    pub image: String,
    /// Volumes.
    #[allow(clippy::zero_sized_map_values)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volumes: Option<HashMap<String, HashMap<(), ()>>>,
    /// Working directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    /// Entrypoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    /// Labels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,
    /// Stop signal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_signal: Option<String>,
    /// Stop timeout.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_timeout: Option<i32>,
    /// Host config.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_config: Option<HostConfig>,
    /// Networking config.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub networking_config: Option<NetworkingConfig>,
}

/// Host configuration.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HostConfig {
    /// Port bindings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_bindings: Option<HashMap<String, Vec<PortBinding>>>,
    /// Binds (volume mounts).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binds: Option<Vec<String>>,
    /// Auto remove container when it exits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_remove: Option<bool>,
    /// Network mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_mode: Option<String>,
    /// Memory limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<i64>,
    /// Memory swap limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_swap: Option<i64>,
    /// CPU shares.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_shares: Option<i64>,
    /// CPU period.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_period: Option<i64>,
    /// CPU quota.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_quota: Option<i64>,
    /// Restart policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_policy: Option<RestartPolicy>,
    /// Privileged mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
    /// PID mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid_mode: Option<String>,
    /// IPC mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipc_mode: Option<String>,
    /// Read-only root filesystem.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readonly_rootfs: Option<bool>,
    /// Extra hosts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_hosts: Option<Vec<String>>,
}

/// Networking configuration.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkingConfig {
    /// Endpoints config.
    pub endpoints_config: HashMap<String, EndpointSettings>,
}

/// Port binding.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PortBinding {
    /// Host IP.
    #[serde(rename = "HostIp", skip_serializing_if = "Option::is_none")]
    pub host_ip: Option<String>,
    /// Host port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_port: Option<String>,
}

/// Restart policy.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RestartPolicy {
    /// Policy name.
    pub name: String,
    /// Maximum retry count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_retry_count: Option<i32>,
}

/// Container create response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerCreateResponse {
    /// Container ID.
    pub id: String,
    /// Warnings.
    pub warnings: Vec<String>,
}

/// Container inspect response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerInspectResponse {
    /// Container ID.
    pub id: String,
    /// Creation time.
    pub created: String,
    /// Path to command.
    pub path: String,
    /// Command arguments.
    pub args: Vec<String>,
    /// Container state.
    pub state: ContainerState,
    /// Image.
    pub image: String,
    /// Name.
    pub name: String,
    /// Restart count.
    pub restart_count: i32,
    /// Container config.
    pub config: ContainerConfig,
    /// Host config.
    pub host_config: HostConfig,
    /// Network settings.
    pub network_settings: NetworkSettings,
    /// Mounts.
    pub mounts: Vec<MountPoint>,
}

/// Container state.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerState {
    /// Status (created, running, paused, restarting, removing, exited, dead).
    pub status: String,
    /// Running.
    pub running: bool,
    /// Paused.
    pub paused: bool,
    /// Restarting.
    pub restarting: bool,
    /// OOM killed.
    #[serde(rename = "OOMKilled")]
    pub oom_killed: bool,
    /// Dead.
    pub dead: bool,
    /// PID.
    pub pid: i32,
    /// Exit code.
    pub exit_code: i32,
    /// Error.
    pub error: String,
    /// Started at.
    pub started_at: String,
    /// Finished at.
    pub finished_at: String,
}

/// Container config.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerConfig {
    /// Hostname.
    pub hostname: String,
    /// User.
    pub user: String,
    /// Environment.
    pub env: Vec<String>,
    /// Command.
    pub cmd: Vec<String>,
    /// Image.
    pub image: String,
    /// Working directory.
    pub working_dir: String,
    /// Entrypoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    /// Labels.
    pub labels: HashMap<String, String>,
    /// TTY.
    pub tty: bool,
    /// Open stdin.
    pub open_stdin: bool,
}

/// Network settings.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkSettings {
    /// Bridge.
    pub bridge: String,
    /// Gateway.
    pub gateway: String,
    /// IP address.
    #[serde(rename = "IPAddress")]
    pub ip_address: String,
    /// IP prefix length.
    #[serde(rename = "IPPrefixLen")]
    pub ip_prefix_len: i32,
    /// MAC address.
    pub mac_address: String,
    /// Ports.
    pub ports: HashMap<String, Option<Vec<PortBinding>>>,
    /// Networks.
    pub networks: HashMap<String, EndpointSettings>,
}

/// Wait response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WaitResponse {
    /// Exit code.
    pub status_code: i64,
    /// Error (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<WaitError>,
}

/// Wait error.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WaitError {
    /// Error message.
    pub message: String,
}

// ============================================================================
// Exec Types
// ============================================================================

/// Exec create request.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExecCreateRequest {
    /// Attach stdin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach_stdin: Option<bool>,
    /// Attach stdout.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach_stdout: Option<bool>,
    /// Attach stderr.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach_stderr: Option<bool>,
    /// Console size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console_size: Option<Vec<u32>>,
    /// Detach keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detach_keys: Option<String>,
    /// TTY allocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tty: Option<bool>,
    /// Environment variables.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
    /// Command to run.
    pub cmd: Vec<String>,
    /// Privileged mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
    /// User.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Working directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

/// Exec create response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExecCreateResponse {
    /// Exec ID.
    pub id: String,
}

/// Exec start request.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExecStartRequest {
    /// Detach.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detach: Option<bool>,
    /// TTY.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tty: Option<bool>,
    /// Console size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console_size: Option<Vec<u32>>,
}

/// Exec inspect response.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExecInspectResponse {
    /// Can remove.
    pub can_remove: bool,
    /// Container ID.
    #[serde(rename = "ContainerID")]
    pub container_id: String,
    /// Detach keys.
    pub detach_keys: String,
    /// Exit code.
    pub exit_code: i32,
    /// Exec ID.
    #[serde(rename = "ID")]
    pub id: String,
    /// Open stderr.
    pub open_stderr: bool,
    /// Open stdin.
    pub open_stdin: bool,
    /// Open stdout.
    pub open_stdout: bool,
    /// Running.
    pub running: bool,
    /// PID.
    pub pid: i32,
}

// ============================================================================
// Image Types
// ============================================================================

/// Image summary.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ImageSummary {
    /// Image ID.
    pub id: String,
    /// Parent ID.
    pub parent_id: String,
    /// Repo tags.
    pub repo_tags: Vec<String>,
    /// Repo digests.
    pub repo_digests: Vec<String>,
    /// Created timestamp.
    pub created: i64,
    /// Size.
    pub size: i64,
    /// Virtual size.
    pub virtual_size: i64,
    /// Shared size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_size: Option<i64>,
    /// Labels.
    pub labels: HashMap<String, String>,
    /// Number of containers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containers: Option<i64>,
}

/// Image inspect response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ImageInspectResponse {
    /// Image ID.
    pub id: String,
    /// Repo tags.
    pub repo_tags: Vec<String>,
    /// Repo digests.
    pub repo_digests: Vec<String>,
    /// Parent.
    pub parent: String,
    /// Comment.
    pub comment: String,
    /// Created.
    pub created: String,
    /// Author.
    pub author: String,
    /// Architecture.
    pub architecture: String,
    /// OS.
    pub os: String,
    /// Size.
    pub size: i64,
    /// Virtual size.
    pub virtual_size: i64,
    /// Config.
    pub config: ContainerConfig,
    /// Root FS.
    pub root_fs: RootFS,
}

/// Root filesystem info.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RootFS {
    /// Type (usually "layers").
    #[serde(rename = "Type")]
    pub root_type: String,
    /// Layer digests.
    pub layers: Vec<String>,
}

/// Image delete response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ImageDeleteResponse {
    /// Deleted image ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted: Option<String>,
    /// Untagged reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub untagged: Option<String>,
}

// ============================================================================
// Network Types
// ============================================================================

/// Network summary.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkSummary {
    /// Name.
    pub name: String,
    /// ID.
    pub id: String,
    /// Created.
    pub created: String,
    /// Scope.
    pub scope: String,
    /// Driver.
    pub driver: String,
    /// Enable IPv6.
    #[serde(rename = "EnableIPv6")]
    pub enable_ipv6: bool,
    /// Internal.
    pub internal: bool,
    /// Attachable.
    pub attachable: bool,
    /// Ingress.
    pub ingress: bool,
    /// Labels.
    pub labels: HashMap<String, String>,
}

/// Network create request.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkCreateRequest {
    /// Name.
    pub name: String,
    /// Driver.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    /// Internal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal: Option<bool>,
    /// Attachable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachable: Option<bool>,
    /// Labels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,
}

/// Network create response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkCreateResponse {
    /// Network ID.
    pub id: String,
    /// Warning.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

// ============================================================================
// Volume Types
// ============================================================================

/// Volume summary.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VolumeSummary {
    /// Name.
    pub name: String,
    /// Driver.
    pub driver: String,
    /// Mountpoint.
    pub mountpoint: String,
    /// Created at.
    pub created_at: String,
    /// Labels.
    pub labels: HashMap<String, String>,
    /// Scope.
    pub scope: String,
    /// Options.
    pub options: HashMap<String, String>,
}

/// Volume list response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VolumeListResponse {
    /// Volumes.
    pub volumes: Vec<VolumeSummary>,
    /// Warnings.
    pub warnings: Vec<String>,
}

/// Volume create request.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VolumeCreateRequest {
    /// Name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Driver.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    /// Driver options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver_opts: Option<HashMap<String, String>>,
    /// Labels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,
}

/// Volume prune response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VolumePruneResponse {
    /// Volumes deleted.
    pub volumes_deleted: Vec<String>,
    /// Space reclaimed in bytes.
    pub space_reclaimed: u64,
}

// ============================================================================
// System Types
// ============================================================================

/// Version response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VersionResponse {
    /// Version.
    pub version: String,
    /// API version.
    pub api_version: String,
    /// Minimum API version.
    pub min_api_version: String,
    /// Git commit.
    pub git_commit: String,
    /// Go version.
    pub go_version: String,
    /// OS.
    pub os: String,
    /// Architecture.
    pub arch: String,
    /// Kernel version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,
    /// Build time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_time: Option<String>,
}

/// System info response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SystemInfoResponse {
    /// Containers count.
    pub containers: i64,
    /// Running containers.
    pub containers_running: i64,
    /// Paused containers.
    pub containers_paused: i64,
    /// Stopped containers.
    pub containers_stopped: i64,
    /// Images count.
    pub images: i64,
    /// Server version.
    pub server_version: String,
    /// Operating system.
    pub operating_system: String,
    /// OS type.
    #[serde(rename = "OSType")]
    pub os_type: String,
    /// Architecture.
    pub architecture: String,
    /// Number of CPUs.
    #[serde(rename = "NCPU")]
    pub ncpu: i64,
    /// Total memory.
    pub mem_total: i64,
    /// Name.
    pub name: String,
    /// ID.
    #[serde(rename = "ID")]
    pub id: String,
    /// Docker root directory.
    pub docker_root_dir: String,
    /// Debug mode.
    pub debug: bool,
    /// Kernel version.
    pub kernel_version: String,
}

/// Prune response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PruneResponse {
    /// Containers deleted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containers_deleted: Option<Vec<String>>,
    /// Space reclaimed.
    pub space_reclaimed: u64,
}
