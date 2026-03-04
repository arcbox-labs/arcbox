/// Guest mount point for dockerd persistent state (`/var/lib/docker`).
///
/// Backed by the Btrfs `@docker` subvolume on `/dev/vdb`.
pub const DOCKER_DATA_MOUNT_POINT: &str = "/var/lib/docker";

/// Docker Engine API Unix socket path in guest.
pub const DOCKER_API_UNIX_SOCKET: &str = "/var/run/docker.sock";

/// containerd persistent root directory.
///
/// Colocated under the Docker data mount so it lives on the Btrfs `@docker`
/// subvolume alongside dockerd state.
pub const CONTAINERD_ROOT_DIR: &str = "/var/lib/docker/containerd";

/// containerd gRPC socket path in guest.
pub const CONTAINERD_SOCKET: &str = "/run/containerd/containerd.sock";

/// Directory where runtime binaries (containerd, dockerd, runc, …) are
/// accessed via VirtioFS live execution.
pub const ARCBOX_RUNTIME_BIN_DIR: &str = "/arcbox/runtime/bin";

/// ArcBox log directory in guest.
///
/// Backed by the Btrfs `@logs` subvolume on `/dev/vdb`.
pub const ARCBOX_LOG_DIR: &str = "/var/log/arcbox";
