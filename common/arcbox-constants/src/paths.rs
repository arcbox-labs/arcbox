/// Guest mount point for dockerd persistent state (`/var/lib/docker`).
///
/// Backed by the Btrfs `@docker` subvolume on `/dev/vdb`.
pub const DOCKER_DATA_MOUNT_POINT: &str = "/var/lib/docker";

/// Guest mount point for containerd persistent state (`/var/lib/containerd`).
///
/// Backed by the Btrfs `@containerd` subvolume on `/dev/vdb`.
pub const CONTAINERD_DATA_MOUNT_POINT: &str = "/var/lib/containerd";

/// Guest mount point for K3s persistent state (`/var/lib/rancher/k3s`).
pub const K3S_DATA_MOUNT_POINT: &str = "/var/lib/rancher/k3s";

/// Guest mount point for kubelet persistent state (`/var/lib/kubelet`).
pub const KUBELET_DATA_MOUNT_POINT: &str = "/var/lib/kubelet";

/// Guest mount point for CNI persistent state (`/var/lib/cni`).
pub const CNI_DATA_MOUNT_POINT: &str = "/var/lib/cni";

/// Docker Engine API Unix socket path in guest.
pub const DOCKER_API_UNIX_SOCKET: &str = "/var/run/docker.sock";

/// containerd gRPC socket path in guest.
pub const CONTAINERD_SOCKET: &str = "/run/containerd/containerd.sock";

/// K3s-generated kubeconfig path inside the guest.
pub const K3S_KUBECONFIG_PATH: &str = "/var/lib/rancher/k3s/k3s.yaml";

/// K3s-managed CNI config directory for the kubelet/containerd stack.
pub const K3S_CNI_CONF_DIR: &str = "/var/lib/rancher/k3s/agent/etc/cni/net.d";

/// K3s-managed CNI plugin directory used by current releases.
pub const K3S_CNI_BIN_DIR: &str = "/var/lib/rancher/k3s/data/cni";

/// Directory where runtime binaries (containerd, dockerd, runc, …) are
/// accessed via VirtioFS live execution.
pub const ARCBOX_RUNTIME_BIN_DIR: &str = "/arcbox/runtime/bin";

/// Host-side privileged paths (require root to write).
pub mod privileged {
    /// Installed helper binary path.
    pub const HELPER_BINARY: &str = "/usr/local/libexec/arcbox-helper";
    /// Helper launchd plist path.
    pub const HELPER_PLIST: &str = "/Library/LaunchDaemons/com.arcboxlabs.desktop.helper.plist";
    /// Helper socket-activation socket path.
    pub const HELPER_SOCKET: &str = "/var/run/arcbox-helper.sock";
    /// Docker socket symlink path.
    pub const DOCKER_SOCKET: &str = "/var/run/docker.sock";
}

/// launchd service labels.
pub mod labels {
    /// Daemon (user-level LaunchAgent).
    pub const DAEMON: &str = "com.arcboxlabs.desktop.daemon";
    /// Development daemon (user-level LaunchAgent).
    pub const DEVELOPMENT_DAEMON: &str = "com.arcboxlabs.desktop.dev.daemon";
    /// Helper (system-level LaunchDaemon).
    pub const HELPER: &str = "com.arcboxlabs.desktop.helper";
}

/// Runtime profile names and derived host identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ArcboxProfile {
    /// Production profile using `~/.arcbox` and the `arcbox` Docker context.
    #[default]
    Production,
    /// Development profile using `~/.arcbox-dev` and the `arcbox-dev` Docker context.
    Development,
}

impl ArcboxProfile {
    /// Returns the canonical profile name used in environment variables and CLIs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Development => "development",
        }
    }

    /// Returns the Docker context name for this profile.
    #[must_use]
    pub const fn docker_context_name(self) -> &'static str {
        match self {
            Self::Production => "arcbox",
            Self::Development => "arcbox-dev",
        }
    }

    /// Returns the launchd daemon label for this profile.
    #[must_use]
    pub const fn daemon_label(self) -> &'static str {
        match self {
            Self::Production => labels::DAEMON,
            Self::Development => labels::DEVELOPMENT_DAEMON,
        }
    }

    /// Returns the profile selected by `ARCBOX_PROFILE`, defaulting to production.
    #[cfg(feature = "std")]
    #[must_use]
    pub fn from_env_or_default() -> Self {
        std::env::var(crate::env::PROFILE)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_default()
    }

    /// Returns this profile's default data directory.
    #[cfg(feature = "std")]
    #[must_use]
    pub fn default_data_dir(self) -> std::path::PathBuf {
        dirs::home_dir().map_or_else(
            || std::path::PathBuf::from("/var/lib/arcbox"),
            |home| match self {
                Self::Production => home.join(".arcbox"),
                Self::Development => home.join(".arcbox-dev"),
            },
        )
    }
}

impl core::fmt::Display for ArcboxProfile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Gated on the `std` feature: the error message is an allocated `String`,
/// which `no_std` builds of this crate don't have.
#[cfg(feature = "std")]
impl core::str::FromStr for ArcboxProfile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "production" | "prod" => Ok(Self::Production),
            "development" | "dev" => Ok(Self::Development),
            other => Err(format!(
                "unknown ArcBox profile '{other}' (expected production or development)"
            )),
        }
    }
}

/// Docker CLI tool names managed by the helper's cli_link.
pub const DOCKER_CLI_TOOLS: &[&str] = &[
    "docker",
    "docker-buildx",
    "docker-compose",
    "docker-credential-osxkeychain",
];

/// Subset of `DOCKER_CLI_TOOLS` that are Docker CLI plugins — binaries that
/// upstream `docker` discovers via its plugin mechanism and invokes as
/// `docker <name>` (e.g. `docker compose`, `docker buildx`).
///
/// Upstream Docker CLI searches these paths in order for plugin binaries:
///   1. entries listed in `cliPluginsExtraDirs` in `~/.docker/config.json`
///   2. `~/.docker/cli-plugins/`
///   3. `/usr/local/lib/docker/cli-plugins/`
///   4. `/usr/lib/docker/cli-plugins/`
///
/// Putting a plugin only in `$PATH` (as a standalone `docker-compose` binary)
/// is *not* enough — `docker compose` (with a space) will fail to find it.
/// Excludes the `docker` host binary itself and credential helpers (which
/// are discovered via a different, credsStore-based mechanism).
pub const DOCKER_CLI_PLUGINS: &[&str] = &["docker-buildx", "docker-compose"];

/// Returns true if a symlink target looks like it belongs to an ArcBox app bundle.
///
/// Used by multiple subsystems (privileged helper, brew hooks, setup install)
/// to decide whether an existing `/usr/local/bin/` symlink can be safely replaced.
///
/// Gated on the `std` feature: it takes a `std::path::Path`, so it is
/// unavailable (and unusable) in `no_std` builds.
#[cfg(feature = "std")]
pub fn is_arcbox_owned(target: &std::path::Path) -> bool {
    target
        .to_string_lossy()
        .contains(".app/Contents/MacOS/xbin/")
}

/// Host-side subdirectory names within the profile data directory.
pub mod host {
    /// Runtime state (sockets, PID files, ephemeral markers).
    pub const RUN: &str = "run";
    /// Centralized log directory.
    pub const LOG: &str = "log";
    /// Persistent data aggregation (images, containers, volumes, …).
    pub const DATA: &str = "data";

    /// Log file names (written by each component's tracing-appender).
    pub const DAEMON_LOG: &str = "daemon.log";
    pub const AGENT_LOG: &str = "agent.log";

    /// Default daemon lock file name (inside `RUN`).
    pub const DAEMON_LOCK: &str = "daemon.lock";
    /// Default Docker API socket name (inside `RUN`).
    pub const DOCKER_SOCKET: &str = "docker.sock";
    /// Default gRPC API socket name (inside `RUN`).
    pub const GRPC_SOCKET: &str = "arcbox.sock";
}

/// Resolved host-side directory layout.
///
/// Single source of truth for every path derived from the ArcBox data
/// directory (`~/.arcbox` by default). Both the daemon and CLI should
/// construct a `HostLayout` once and pass it around instead of
/// recalculating paths independently.
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct HostLayout {
    /// Root data directory (e.g. `~/.arcbox`).
    pub data_dir: std::path::PathBuf,
    /// `<data_dir>/run` — sockets, PID file, lock.
    pub run_dir: std::path::PathBuf,
    /// `<data_dir>/log` — daemon and agent logs.
    pub log_dir: std::path::PathBuf,
    /// `<data_dir>/data` — persistent VM/container data.
    pub data_subdir: std::path::PathBuf,
    /// `<run_dir>/docker.sock`
    pub docker_socket: std::path::PathBuf,
    /// `<run_dir>/arcbox.sock`
    pub grpc_socket: std::path::PathBuf,
    /// `<run_dir>/daemon.lock`
    pub lock_file: std::path::PathBuf,
    /// `<log_dir>/daemon.log`
    pub daemon_log: std::path::PathBuf,
}

#[cfg(feature = "std")]
impl HostLayout {
    /// Build a layout from an explicit data directory.
    #[must_use]
    pub fn new(data_dir: std::path::PathBuf) -> Self {
        let run_dir = data_dir.join(host::RUN);
        let log_dir = data_dir.join(host::LOG);
        let data_subdir = data_dir.join(host::DATA);
        let docker_socket = run_dir.join(host::DOCKER_SOCKET);
        let grpc_socket = run_dir.join(host::GRPC_SOCKET);
        let lock_file = run_dir.join(host::DAEMON_LOCK);
        let daemon_log = log_dir.join(host::DAEMON_LOG);
        Self {
            data_dir,
            run_dir,
            log_dir,
            data_subdir,
            docker_socket,
            grpc_socket,
            lock_file,
            daemon_log,
        }
    }

    /// Build a layout from a runtime profile.
    #[must_use]
    pub fn for_profile(profile: ArcboxProfile) -> Self {
        Self::new(profile.default_data_dir())
    }

    /// Resolve the data directory from an optional override, falling
    /// back to the production profile directory.
    #[must_use]
    pub fn resolve(data_dir: Option<&std::path::Path>) -> Self {
        Self::resolve_for_profile(ArcboxProfile::Production, data_dir)
    }

    /// Resolve the data directory from an optional override, falling back to
    /// the selected profile's default directory.
    #[must_use]
    pub fn resolve_for_profile(profile: ArcboxProfile, data_dir: Option<&std::path::Path>) -> Self {
        match data_dir {
            Some(d) => Self::new(d.to_path_buf()),
            None => Self::for_profile(profile),
        }
    }

    /// Resolve the data directory from an optional override, then
    /// `ARCBOX_DATA_DIR`, then the selected profile's default directory.
    #[must_use]
    pub fn resolve_for_profile_from_env(
        profile: ArcboxProfile,
        data_dir: Option<&std::path::Path>,
    ) -> Self {
        if let Some(data_dir) = data_dir {
            return Self::new(data_dir.to_path_buf());
        }

        if let Ok(data_dir) = std::env::var(crate::env::DATA_DIR) {
            if !data_dir.is_empty() {
                return Self::new(std::path::PathBuf::from(data_dir));
            }
        }

        Self::for_profile(profile)
    }

    /// Resolve the layout from environment (`ARCBOX_DATA_DIR`, then
    /// `ARCBOX_PROFILE`) or the production defaults.
    #[must_use]
    pub fn from_env_or_default() -> Self {
        Self::resolve_for_profile_from_env(ArcboxProfile::from_env_or_default(), None)
    }
}

/// Default data directory: `~/.arcbox`, falling back to `/var/lib/arcbox`
/// when the home directory cannot be resolved.
///
/// Uses `dirs::home_dir()` which handles edge cases (launchd, sudo,
/// non-interactive shells) that raw `$HOME` does not.
#[cfg(feature = "std")]
#[must_use]
pub fn default_data_dir() -> std::path::PathBuf {
    ArcboxProfile::Production.default_data_dir()
}

/// Privileged log directory (root-owned, for arcbox-helper).
pub mod privileged_log {
    /// Directory for helper logs (root-writable).
    pub const HELPER_LOG_DIR: &str = "/var/log/arcbox";
    /// Helper log file name.
    pub const HELPER_LOG: &str = "helper.log";
}

/// Guest-side subdirectory names within `/arcbox/`.
pub mod guest {
    /// Log directory inside the VirtioFS mount.
    pub const LOG: &str = "log";
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn host_layout_new_derives_all_paths() {
        let layout = HostLayout::new(PathBuf::from("/tmp/arcbox"));
        assert_eq!(layout.run_dir, PathBuf::from("/tmp/arcbox/run"));
        assert_eq!(layout.log_dir, PathBuf::from("/tmp/arcbox/log"));
        assert_eq!(layout.data_subdir, PathBuf::from("/tmp/arcbox/data"));
        assert_eq!(
            layout.docker_socket,
            PathBuf::from("/tmp/arcbox/run/docker.sock")
        );
        assert_eq!(
            layout.grpc_socket,
            PathBuf::from("/tmp/arcbox/run/arcbox.sock")
        );
        assert_eq!(
            layout.lock_file,
            PathBuf::from("/tmp/arcbox/run/daemon.lock")
        );
        assert_eq!(
            layout.daemon_log,
            PathBuf::from("/tmp/arcbox/log/daemon.log")
        );
    }

    #[test]
    fn host_layout_resolve_uses_explicit_dir() {
        let dir = PathBuf::from("/custom/dir");
        let layout = HostLayout::resolve(Some(&dir));
        assert_eq!(layout.data_dir, dir);
    }

    #[test]
    fn host_layout_resolve_uses_default_when_none() {
        let layout = HostLayout::resolve(None);
        assert_eq!(layout.data_dir, default_data_dir());
    }

    #[test]
    fn host_layout_resolve_for_profile_uses_explicit_dir() {
        let dir = PathBuf::from("/custom/dev");
        let layout = HostLayout::resolve_for_profile_from_env(
            ArcboxProfile::Development,
            Some(dir.as_path()),
        );
        assert_eq!(layout.data_dir, dir);
    }

    #[test]
    fn development_profile_uses_dev_data_dir_and_context() {
        let layout = HostLayout::for_profile(ArcboxProfile::Development);
        assert!(layout.data_dir.ends_with(".arcbox-dev"));
        assert_eq!(
            ArcboxProfile::Development.docker_context_name(),
            "arcbox-dev"
        );
        assert_eq!(
            ArcboxProfile::Development.daemon_label(),
            labels::DEVELOPMENT_DAEMON
        );
    }

    #[test]
    fn parses_profile_names_and_aliases() {
        assert_eq!(
            "production".parse::<ArcboxProfile>().unwrap(),
            ArcboxProfile::Production
        );
        assert_eq!(
            "dev".parse::<ArcboxProfile>().unwrap(),
            ArcboxProfile::Development
        );
    }

    #[test]
    fn default_data_dir_returns_home_based_path() {
        // When HOME is set (normal dev environment), the path should
        // end with ".arcbox" under the home directory.
        if dirs::home_dir().is_some() {
            let dir = default_data_dir();
            assert!(dir.ends_with(".arcbox"));
        }
    }
}
