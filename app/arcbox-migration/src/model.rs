//! Normalized migration model types.

use crate::docker_types::NetworkIpamConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Supported migration source runtimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    /// Docker Desktop on macOS.
    DockerDesktop,
    /// OrbStack on macOS.
    OrbStack,
}

impl SourceKind {
    /// Returns the stable CLI/protocol identifier for the source kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DockerDesktop => "docker-desktop",
            Self::OrbStack => "orbstack",
        }
    }
}

/// Source configuration used by the planner and executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceConfig {
    /// Selected source runtime.
    pub kind: SourceKind,
    /// Source Docker Engine socket path.
    pub socket_path: PathBuf,
}

/// Minimal source identity discovered during preflight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceInfo {
    /// Selected source runtime.
    pub kind: SourceKind,
    /// Source Docker Engine socket path.
    pub socket_path: PathBuf,
    /// Docker daemon name.
    pub daemon_name: String,
    /// Reported server version.
    pub server_version: String,
    /// Reported operating system.
    pub operating_system: String,
    /// Reported architecture.
    pub architecture: String,
}

/// A fully normalized migration plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationPlan {
    /// Source identity.
    pub source: SourceInfo,
    /// Helper image reference used for temporary volume-mount containers.
    pub helper_image: String,
    /// Images that will be imported into ArcBox.
    pub images: Vec<ImagePlan>,
    /// Volumes that will be imported into ArcBox.
    pub volumes: Vec<VolumePlan>,
    /// Networks that will be recreated in ArcBox.
    pub networks: Vec<NetworkPlan>,
    /// Containers that will be recreated in ArcBox.
    pub containers: Vec<ContainerPlan>,
    /// Resources that are out of scope for v1. Blocking: execution refuses to
    /// start while any are present.
    pub unsupported_resources: Vec<String>,
    /// Advisory problems that do not block execution but will likely surprise
    /// the user (for example, a bind mount whose source is missing).
    pub warnings: Vec<String>,
    /// Replace actions that require confirmation.
    pub replacements: ReplacementSummary,
    /// Source volume blockers caused by running containers.
    pub blockers: Vec<RunningVolumeBlocker>,
}

/// Source image transfer description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImagePlan {
    /// Source image identifier.
    pub image_id: String,
    /// Every reference passed to `docker save`. Listing all tags is what keeps
    /// them: `docker save` preserves an image's other tags only when the
    /// argument omits a tag, so exporting one `repo:tag` drops the rest.
    pub export_references: Vec<String>,
    /// Repo tags preserved by the source daemon.
    pub repo_tags: Vec<String>,
    /// Repo tags that will overwrite an existing ArcBox tag.
    pub replace_tags: Vec<String>,
}

impl ImagePlan {
    /// Returns the reference used when a container refers to this image.
    #[must_use]
    pub fn primary_reference(&self) -> &str {
        self.export_references
            .first()
            .map_or(self.image_id.as_str(), String::as_str)
    }
}

/// Source volume transfer description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumePlan {
    /// Source volume name.
    pub name: String,
    /// Volume driver.
    pub driver: String,
    /// Volume labels preserved during recreate.
    pub labels: HashMap<String, String>,
    /// Driver options preserved during recreate.
    pub options: HashMap<String, String>,
    /// Whether the target volume will be replaced.
    pub replace_existing: bool,
    /// Source containers referencing the volume.
    pub attached_containers: Vec<String>,
}

/// Source network transfer description.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkPlan {
    /// Source network name.
    pub name: String,
    /// Source network identifier.
    pub id: String,
    /// Docker network driver.
    pub driver: String,
    /// Whether the network is internal.
    pub internal: bool,
    /// Whether IPv6 is enabled.
    pub enable_ipv6: bool,
    /// Whether the network is attachable.
    pub attachable: bool,
    /// Network labels preserved during recreate.
    pub labels: HashMap<String, String>,
    /// Network options preserved during recreate.
    pub options: HashMap<String, String>,
    /// IPAM subnet configuration preserved during recreate.
    pub ipam: Vec<NetworkIpamConfig>,
    /// Whether the target network will be replaced.
    pub replace_existing: bool,
}

/// A recreated container definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainerPlan {
    /// Source container name without the leading slash.
    pub name: String,
    /// Source container identifier.
    pub id: String,
    /// Image reference used when recreating the container.
    pub image_reference: String,
    /// Normalized container creation spec.
    pub spec: ContainerSpec,
    /// Additional network attachments after create.
    pub extra_networks: Vec<ContainerNetworkAttachment>,
    /// Whether the target container will be replaced.
    pub replace_existing: bool,
}

/// Container creation spec translated from inspect output.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerSpec {
    /// Hostname.
    pub hostname: Option<String>,
    /// Domain name.
    pub domainname: Option<String>,
    /// User.
    pub user: Option<String>,
    /// Environment variables.
    pub env: Vec<String>,
    /// Labels.
    pub labels: HashMap<String, String>,
    /// Exposed ports.
    pub exposed_ports: Vec<String>,
    /// Whether tty mode is enabled.
    pub tty: bool,
    /// Whether stdin should stay open.
    pub open_stdin: bool,
    /// Working directory.
    pub working_dir: Option<String>,
    /// Entrypoint argv.
    pub entrypoint: Vec<String>,
    /// Command argv.
    pub cmd: Vec<String>,
    /// Mount definitions.
    pub mounts: Vec<ContainerMount>,
    /// Port publish rules.
    pub publishes: Vec<PortPublish>,
    /// Restart policy.
    pub restart_policy: Option<RestartPolicySpec>,
    /// Privileged mode.
    pub privileged: bool,
    /// Read-only root filesystem.
    pub read_only_rootfs: bool,
    /// Extra hosts.
    pub extra_hosts: Vec<String>,
    /// Auto-remove on exit.
    pub auto_remove: bool,
    /// Network the container joins at create time.
    pub network_mode: NetworkModeSpec,
}

/// The network a container joins at create time, from `HostConfig.NetworkMode`.
///
/// `container:<name|id>` is deliberately absent: it is rejected during planning
/// rather than modelled, because reproducing it would require resolving the
/// peer container and ordering creation around it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkModeSpec {
    /// The default bridge network; no `--network` flag is emitted.
    #[default]
    Default,
    /// Host networking.
    Host,
    /// No networking.
    None,
    /// A user-defined network that is part of this migration.
    Named(ContainerNetworkAttachment),
}

impl NetworkModeSpec {
    /// Returns whether this mode shares another namespace, which bars the
    /// container from joining any further network.
    ///
    /// Docker rejects that combination outright ("container sharing network
    /// namespace with another container or host cannot be connected to any
    /// other network"), so additional attachments must be skipped.
    #[must_use]
    pub const fn forbids_extra_networks(&self) -> bool {
        matches!(self, Self::Host)
    }
}

/// Supported mount definitions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ContainerMount {
    /// Named volume mount.
    Volume {
        /// Volume name.
        source: String,
        /// Container destination path.
        target: String,
        /// Whether the mount is writable.
        rw: bool,
    },
    /// Bind mount.
    Bind {
        /// Host path.
        source: String,
        /// Container destination path.
        target: String,
        /// Whether the mount is writable.
        rw: bool,
    },
    /// Tmpfs mount.
    Tmpfs {
        /// Container destination path.
        target: String,
        /// Mount options string.
        options: Option<String>,
    },
}

/// Host port publish rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortPublish {
    /// Port and protocol inside the container.
    pub container_port: String,
    /// Host IP, if present.
    pub host_ip: Option<String>,
    /// Host port.
    pub host_port: Option<String>,
}

/// Restart policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestartPolicySpec {
    /// Policy name.
    pub name: String,
    /// Maximum retry count.
    pub maximum_retry_count: Option<i64>,
}

/// Container network attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerNetworkAttachment {
    /// Network name.
    pub network: String,
    /// Network-scoped aliases.
    pub aliases: Vec<String>,
}

/// Aggregate replacement summary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplacementSummary {
    /// Container names that will be replaced.
    pub containers: Vec<String>,
    /// Volume names that will be replaced.
    pub volumes: Vec<String>,
    /// Network names that will be replaced.
    pub networks: Vec<String>,
    /// Image tags that will be overwritten.
    pub image_tags: Vec<String>,
}

impl ReplacementSummary {
    /// Returns true when no replace action is required.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.containers.is_empty()
            && self.volumes.is_empty()
            && self.networks.is_empty()
            && self.image_tags.is_empty()
    }
}

/// A source volume blocked by running containers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunningVolumeBlocker {
    /// Volume name.
    pub volume_name: String,
    /// Running source containers using the volume.
    pub containers: Vec<String>,
}
