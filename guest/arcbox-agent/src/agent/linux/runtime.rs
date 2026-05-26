//! Container runtime lifecycle: bring up containerd + dockerd, surface readiness,
//! and serve the EnsureRuntime/RuntimeStatus RPC handlers.
//!
//! Spawns the bundled `containerd` and `dockerd` from the EROFS rootfs, verifies
//! kernel/filesystem prerequisites (cgroup2, overlayfs, devpts, …), and polls
//! socket readiness with both connect-level and HTTP-level probes.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::process::Command;
use tokio::sync::Mutex;

use arcbox_constants::paths::{
    ARCBOX_RUNTIME_BIN_DIR, CONTAINERD_SOCKET, DOCKER_API_UNIX_SOCKET, DOCKER_DATA_MOUNT_POINT,
    K3S_CNI_BIN_DIR, K3S_CNI_CONF_DIR,
};
use arcbox_constants::status::{SERVICE_ERROR, SERVICE_NOT_READY, SERVICE_READY};
use arcbox_protocol::agent::{
    RuntimeEnsureRequest, RuntimeEnsureResponse, RuntimeStatusRequest, RuntimeStatusResponse,
};

use super::btrfs::ensure_data_mount;
use super::cmdline::docker_api_vsock_port;
use super::probe::{probe_docker_api_ready, probe_first_ready_socket, probe_unix_socket};
use super::rpc::sync_clock_from_host;
use crate::agent::ensure_runtime;
use crate::rpc::RpcResponse;

/// Containerd socket candidates (primary + legacy fallback).
pub(super) const CONTAINERD_SOCKET_CANDIDATES: [&str; 2] =
    [CONTAINERD_SOCKET, "/var/run/containerd/containerd.sock"];

const REQUIRED_RUNTIME_BINARIES: &[&str] =
    &["dockerd", "containerd", "containerd-shim-runc-v2", "runc"];

/// Minimum "sane" UNIX timestamp for TLS certificate validation.
///
/// Chosen to be old enough that it's always in the past, but recent
/// enough that TLS certificates issued after 2020 pass validation.
/// 2020-01-01T00:00:00Z
const MIN_SANE_EPOCH: u64 = 1_577_836_800;

/// Idempotent, non-blocking EnsureRuntime handler.
///
/// The first driver spawns [`do_ensure_runtime_start`] as a background
/// task and returns `STATUS_STARTING` immediately; subsequent callers see
/// the in-progress state and also return `STATUS_STARTING`. The daemon
/// polls until the state settles into `Ready`/`Failed`. See
/// [`ensure_runtime::ensure_runtime`] for the rationale.
pub(super) async fn handle_ensure_runtime(req: RuntimeEnsureRequest) -> RpcResponse {
    let guard = ensure_runtime::runtime_guard();

    let response = ensure_runtime::ensure_runtime(
        guard,
        req.start_if_needed,
        || do_ensure_runtime_start(),
        || do_ensure_runtime_probe(),
    )
    .await;

    RpcResponse::RuntimeEnsure(response)
}

/// Performs the actual runtime start sequence (called only by the driver).
async fn do_ensure_runtime_start() -> RuntimeEnsureResponse {
    let mut notes = Vec::new();
    let note = try_start_bundled_runtime().await;
    if !note.is_empty() {
        notes.push(note);
    }

    // Poll until docker socket is ready (up to ~90 seconds).
    // On large data volumes with VirtIO block I/O, containerd may need
    // up to 30s to scan its content store, and dockerd may need additional
    // time to load containers from Btrfs.
    let mut status = collect_runtime_status().await;
    for _ in 0..180 {
        if status.docker_ready {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        status = collect_runtime_status().await;
    }

    let mut message = status.detail.clone();
    if !notes.is_empty() {
        message = format!("{}; {}", notes.join("; "), status.detail);
    }

    let result_status = if status.docker_ready {
        ensure_runtime::STATUS_STARTED.to_string()
    } else {
        ensure_runtime::STATUS_FAILED.to_string()
    };

    RuntimeEnsureResponse {
        ready: status.docker_ready,
        endpoint: status.endpoint,
        message,
        status: result_status,
    }
}

/// Probes runtime status without attempting to start (for start_if_needed=false).
async fn do_ensure_runtime_probe() -> RuntimeEnsureResponse {
    let status = collect_runtime_status().await;
    RuntimeEnsureResponse {
        ready: status.docker_ready,
        endpoint: status.endpoint,
        message: status.detail,
        status: if status.docker_ready {
            ensure_runtime::STATUS_REUSED.to_string()
        } else {
            ensure_runtime::STATUS_FAILED.to_string()
        },
    }
}

pub(super) async fn handle_runtime_status(_req: RuntimeStatusRequest) -> RpcResponse {
    RpcResponse::RuntimeStatus(collect_runtime_status().await)
}

pub(super) fn runtime_path_env(runtime_bin_dir: &Path) -> String {
    let standard = "/usr/sbin:/usr/bin:/sbin:/bin";
    match std::env::var("PATH") {
        Ok(existing) if !existing.is_empty() => {
            format!("{}:{}:{}", runtime_bin_dir.display(), existing, standard)
        }
        _ => format!("{}:{}", runtime_bin_dir.display(), standard),
    }
}

pub(super) fn ensure_shared_runtime_dirs(notes: &mut Vec<String>) {
    for dir in [
        "/run/containerd",
        "/var/run/docker",
        "/etc/docker",
        "/etc/containerd",
        "/run/arcbox",
        K3S_CNI_CONF_DIR,
        K3S_CNI_BIN_DIR,
    ] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            notes.push(format!("mkdir {} failed({})", dir, e));
        }
    }
}

pub(super) fn shared_containerd_config() -> String {
    format!(
        "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".cni]\n  bin_dir = \"{K3S_CNI_BIN_DIR}\"\n  conf_dir = \"{K3S_CNI_CONF_DIR}\"\n  max_conf_num = 1\n"
    )
}

pub(super) async fn ensure_containerd_ready(
    runtime_bin_dir: &Path,
    notes: &mut Vec<String>,
) -> bool {
    if probe_first_ready_socket(&CONTAINERD_SOCKET_CANDIDATES).await {
        return true;
    }

    let containerd_config = "/etc/containerd/config.toml";
    let config_toml = shared_containerd_config();
    if let Err(e) = std::fs::write(containerd_config, config_toml) {
        notes.push(format!("write containerd config failed({})", e));
    }

    let path_env = runtime_path_env(runtime_bin_dir);
    let containerd_bin = runtime_bin_dir.join("containerd");
    let mut cmd = Command::new(&containerd_bin);
    cmd.args([
        "--config",
        containerd_config,
        "--address",
        CONTAINERD_SOCKET,
        "--state",
        "/run/containerd",
    ])
    .env("PATH", &path_env)
    .stdin(Stdio::null())
    .stdout(daemon_log_file("containerd"))
    .stderr(daemon_log_file("containerd"));

    match cmd.spawn() {
        Ok(child) => {
            let pid = child.id().unwrap_or_default();
            tracing::info!(pid, "spawned bundled containerd");
            notes.push(format!("spawned bundled containerd (pid={})", pid));
        }
        Err(e) => {
            notes.push(format!("failed to spawn bundled containerd: {}", e));
            return false;
        }
    }

    // On large data volumes (Btrfs with many layers/snapshots), containerd
    // may need significant time to scan its content store on first boot.
    // VirtIO block I/O is slower than VZ native disk, so allow up to 30s.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let start = tokio::time::Instant::now();
    while tokio::time::Instant::now() < deadline {
        if probe_first_ready_socket(&CONTAINERD_SOCKET_CANDIDATES).await {
            let elapsed = start.elapsed();
            tracing::info!(
                elapsed_ms = elapsed.as_millis() as u64,
                "containerd socket poll complete containerd_ready=true"
            );
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    notes.push("containerd socket not ready after 30s".to_string());
    false
}

async fn ensure_dockerd_ready(runtime_bin_dir: &Path, notes: &mut Vec<String>) {
    if probe_unix_socket(DOCKER_API_UNIX_SOCKET).await {
        return;
    }

    let path_env = runtime_path_env(runtime_bin_dir);
    let dockerd_bin = runtime_bin_dir.join("dockerd");
    let mut cmd = Command::new(&dockerd_bin);
    cmd.arg(format!("--host=unix://{DOCKER_API_UNIX_SOCKET}"))
        .arg(format!("--containerd={CONTAINERD_SOCKET}"))
        .arg("--exec-root=/var/run/docker")
        .arg(format!("--data-root={DOCKER_DATA_MOUNT_POINT}"))
        .arg("--userland-proxy=false")
        .env("PATH", &path_env)
        .stdin(Stdio::null())
        .stdout(daemon_log_file("dockerd"))
        .stderr(daemon_log_file("dockerd"));

    match cmd.spawn() {
        Ok(child) => {
            let pid = child.id().unwrap_or_default();
            tracing::info!(pid, "spawned bundled dockerd");
            notes.push(format!("spawned bundled dockerd (pid={})", pid));
        }
        Err(e) => {
            notes.push(format!("failed to spawn bundled dockerd: {}", e));
        }
    }
}

async fn collect_runtime_status() -> RuntimeStatusResponse {
    use arcbox_protocol::agent::ServiceStatus;

    let containerd_ready = probe_first_ready_socket(&CONTAINERD_SOCKET_CANDIDATES).await;
    // Two-level check: socket connectable (fast) + HTTP API probe (strong).
    // Use socket connectable as the ready gate so the daemon doesn't stall
    // when dockerd takes >30s to fully initialize (Loading containers on
    // large data volumes). The HTTP probe result is included in the detail.
    let docker_socket_ok = probe_unix_socket(DOCKER_API_UNIX_SOCKET).await;
    let docker_api_ok = if docker_socket_ok {
        probe_docker_api_ready(DOCKER_API_UNIX_SOCKET).await
    } else {
        false
    };
    let docker_ready = docker_socket_ok;
    let runtime_dir = PathBuf::from(ARCBOX_RUNTIME_BIN_DIR);
    let missing_runtime_binaries = missing_runtime_binaries_at(&runtime_dir);

    // Build per-service status entries.
    let mut services = Vec::new();

    // containerd status
    services.push(if containerd_ready {
        ServiceStatus {
            name: "containerd".to_string(),
            status: SERVICE_READY.to_string(),
            detail: format!(
                "socket reachable: {}",
                CONTAINERD_SOCKET_CANDIDATES
                    .iter()
                    .find(|p| Path::new(p).exists())
                    .unwrap_or(&CONTAINERD_SOCKET_CANDIDATES[0])
            ),
        }
    } else {
        let socket_paths = CONTAINERD_SOCKET_CANDIDATES
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        ServiceStatus {
            name: "containerd".to_string(),
            status: SERVICE_NOT_READY.to_string(),
            detail: format!("no reachable socket found; checked: {}", socket_paths),
        }
    });

    // dockerd status — distinguish socket-connectable vs API-ready.
    let docker_detail = if docker_api_ok {
        format!("API /_ping OK: {}", DOCKER_API_UNIX_SOCKET)
    } else if docker_socket_ok {
        format!(
            "socket connectable, API initializing: {}",
            DOCKER_API_UNIX_SOCKET
        )
    } else if Path::new(DOCKER_API_UNIX_SOCKET).exists() {
        format!(
            "socket exists but not connectable: {}",
            DOCKER_API_UNIX_SOCKET
        )
    } else {
        format!("socket missing: {}", DOCKER_API_UNIX_SOCKET)
    };

    services.push(ServiceStatus {
        name: "dockerd".to_string(),
        status: if docker_ready {
            SERVICE_READY.to_string()
        } else if Path::new(DOCKER_API_UNIX_SOCKET).exists() {
            SERVICE_ERROR.to_string()
        } else {
            SERVICE_NOT_READY.to_string()
        },
        detail: docker_detail,
    });

    // Build the summary detail string.
    let detail = if docker_ready {
        "docker socket ready".to_string()
    } else if Path::new(DOCKER_API_UNIX_SOCKET).exists() {
        format!(
            "docker socket exists but not reachable: {}",
            DOCKER_API_UNIX_SOCKET
        )
    } else if !missing_runtime_binaries.is_empty() {
        format!(
            "docker socket missing: {}; {}",
            DOCKER_API_UNIX_SOCKET,
            runtime_missing_detail_from(&missing_runtime_binaries)
        )
    } else {
        format!("docker socket missing: {}", DOCKER_API_UNIX_SOCKET)
    };

    RuntimeStatusResponse {
        containerd_ready,
        docker_ready,
        endpoint: format!("vsock:{}", docker_api_vsock_port()),
        detail,
        services,
    }
}

fn runtime_start_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn detect_runtime_bin_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(ARCBOX_RUNTIME_BIN_DIR);
    if missing_runtime_binaries_at(&dir).is_empty() {
        Some(dir)
    } else {
        None
    }
}

fn runtime_missing_detail() -> String {
    let dir = PathBuf::from(ARCBOX_RUNTIME_BIN_DIR);
    let missing = missing_runtime_binaries_at(&dir);
    runtime_missing_detail_from(&missing)
}

fn runtime_missing_detail_from(missing: &[&'static str]) -> String {
    if missing.is_empty() {
        format!("all runtime binaries present under {ARCBOX_RUNTIME_BIN_DIR}")
    } else {
        format!(
            "missing runtime binaries under {}: {}",
            ARCBOX_RUNTIME_BIN_DIR,
            missing.join(", ")
        )
    }
}

fn missing_runtime_binaries_at(dir: &Path) -> Vec<&'static str> {
    missing_binaries_at(dir, REQUIRED_RUNTIME_BINARIES)
}

pub(super) fn missing_binaries_at(dir: &Path, required: &[&'static str]) -> Vec<&'static str> {
    required
        .iter()
        .copied()
        .filter(|name| !dir.join(name).exists())
        .collect()
}

/// Ensures the guest environment has the prerequisites that dockerd/containerd
/// need: cgroup2, overlayfs, devpts, /dev/shm, /tmp, /run.
pub(super) fn ensure_runtime_prerequisites() -> Vec<String> {
    let mut notes = Vec::new();

    // Use /bin/busybox <applet> directly — always present on EROFS rootfs.
    let busybox = "/bin/busybox";

    // Mount cgroup2 unified hierarchy (required by dockerd).
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        if let Err(e) = std::fs::create_dir_all("/sys/fs/cgroup") {
            notes.push(format!("mkdir /sys/fs/cgroup failed({})", e));
        } else {
            let rc = std::process::Command::new(busybox)
                .args(["mount", "-t", "cgroup2", "cgroup2", "/sys/fs/cgroup"])
                .status();
            match rc {
                Ok(s) if s.success() => notes.push("mounted cgroup2".to_string()),
                Ok(s) => notes.push(format!("mount cgroup2 exit={}", s.code().unwrap_or(-1))),
                Err(e) => notes.push(format!("mount cgroup2 failed({})", e)),
            }
        }
    }

    // Mount devpts if missing (needed for PTY allocation).
    if !Path::new("/dev/pts/ptmx").exists() {
        let _ = std::fs::create_dir_all("/dev/pts");
        let _ = std::process::Command::new(busybox)
            .args([
                "mount",
                "-t",
                "devpts",
                "-o",
                "gid=5,mode=0620,noexec,nosuid",
                "devpts",
                "/dev/pts",
            ])
            .status();
    }

    // Mount /dev/shm if missing.
    if !Path::new("/dev/shm").exists() {
        let _ = std::fs::create_dir_all("/dev/shm");
        let _ = std::process::Command::new(busybox)
            .args([
                "mount",
                "-t",
                "tmpfs",
                "-o",
                "nodev,nosuid,noexec",
                "shm",
                "/dev/shm",
            ])
            .status();
    }

    // Ensure /tmp and /run exist as writable tmpfs.
    for dir in ["/tmp", "/run"] {
        if !Path::new(dir).exists()
            || std::fs::metadata(dir).is_ok_and(|m| m.permissions().readonly())
        {
            let _ = std::fs::create_dir_all(dir);
            let _ = std::process::Command::new(busybox)
                .args(["mount", "-t", "tmpfs", "tmpfs", dir])
                .status();
        }
    }

    // Enable IPv4 forwarding so Docker can route traffic between docker0 and eth0.
    // VZ framework NAT masquerades all VM traffic, so no guest-side masquerade rule needed.
    if let Err(e) = std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1\n") {
        notes.push(format!("ip_forward failed({})", e));
    } else {
        notes.push("enabled ip_forward".to_string());
    }

    // Load overlay module (needed for Docker's overlay2 storage driver).
    if !Path::new("/sys/module/overlay").exists() {
        let rc = std::process::Command::new("/sbin/modprobe")
            .arg("overlay")
            .status();
        match rc {
            Ok(s) if s.success() => notes.push("loaded overlay module".to_string()),
            _ => {
                // Fallback: try insmod with kernel version path.
                if let Ok(uname) = std::process::Command::new(busybox)
                    .arg("uname")
                    .arg("-r")
                    .output()
                {
                    let kver = String::from_utf8_lossy(&uname.stdout).trim().to_string();
                    let ko = format!("/lib/modules/{}/kernel/fs/overlayfs/overlay.ko", kver);
                    if Path::new(&ko).exists() {
                        let _ = std::process::Command::new(busybox)
                            .args(["insmod", &ko])
                            .status();
                        notes.push(format!("insmod overlay from {}", ko));
                    } else {
                        notes.push("overlay module not found".to_string());
                    }
                }
            }
        }
    }

    // Clock guard: if the wall clock is still near epoch, the host Ping
    // (which carries the real timestamp) hasn't arrived yet. Set it to a
    // known-safe minimum so TLS validation in dockerd/containerd doesn't
    // fail with "certificate is not yet valid". The next Ping overwrites
    // this with the real host time.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let min_epoch = option_env!("SOURCE_DATE_EPOCH")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
        .max(MIN_SANE_EPOCH);
    if now_secs < min_epoch {
        if sync_clock_from_host(min_epoch as i64) {
            notes.push("clock guard: set to minimum sane time (pre-ping fallback)".to_string());
        } else {
            notes.push("clock guard: failed to set clock (pre-ping fallback)".to_string());
        }
    }

    notes
}

/// Redirects daemon stdout/stderr to a log file so crashes are diagnosable.
///
/// Prefers `/arcbox/log/` (VirtioFS mount, visible from host as `~/.arcbox/log/`)
/// so that logs survive guest restarts and are accessible without exec.
/// Falls back to `/tmp/` (guest tmpfs) if VirtioFS is not mounted.
pub(super) fn daemon_log_file(name: &str) -> Stdio {
    let log_dir = format!("/arcbox/{}", arcbox_constants::paths::guest::LOG);
    let arcbox_path = format!("{}/{}.log", log_dir, name);
    let tmp_log_path = format!("/tmp/{}.log", name);

    // Ensure the log directory exists inside the VirtioFS share.
    if Path::new("/arcbox").exists() {
        let _ = std::fs::create_dir_all(&log_dir);
    }

    let log_path = if Path::new("/arcbox").exists() {
        &arcbox_path
    } else {
        &tmp_log_path
    };

    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        Ok(f) => f.into(),
        Err(_) => {
            // Fallback to /tmp/ if /arcbox/log/ write fails.
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&tmp_log_path)
            {
                Ok(f) => f.into(),
                Err(_) => Stdio::null(),
            }
        }
    }
}

async fn try_start_bundled_runtime() -> String {
    let _guard = runtime_start_lock().lock().await;

    if probe_unix_socket(DOCKER_API_UNIX_SOCKET).await {
        return "docker socket already ready".to_string();
    }

    let Some(runtime_bin_dir) = detect_runtime_bin_dir() else {
        return runtime_missing_detail();
    };

    tracing::info!(
        runtime_bin_dir = %runtime_bin_dir.display(),
        "starting bundled runtime"
    );

    let mut notes = Vec::new();

    // Ensure kernel/filesystem prerequisites before spawning daemons.
    let prereq_notes = ensure_runtime_prerequisites();
    if !prereq_notes.is_empty() {
        tracing::info!(prerequisites = %prereq_notes.join("; "), "runtime prerequisites");
    }
    notes.extend(prereq_notes);
    match ensure_data_mount() {
        Ok(note) => notes.push(note),
        Err(e) => return format!("data volume setup failed: {}", e),
    }

    ensure_shared_runtime_dirs(&mut notes);

    if !ensure_containerd_ready(&runtime_bin_dir, &mut notes).await {
        return notes.join("; ");
    }

    ensure_dockerd_ready(&runtime_bin_dir, &mut notes).await;

    notes.join("; ")
}

#[cfg(test)]
mod tests {
    use super::shared_containerd_config;

    #[test]
    fn shared_containerd_config_uses_k3s_cni_paths() {
        let config = shared_containerd_config();
        assert!(config.contains("bin_dir = \"/var/lib/rancher/k3s/data/cni\""));
        assert!(config.contains("conf_dir = \"/var/lib/rancher/k3s/agent/etc/cni/net.d\""));
        assert!(config.contains("max_conf_num = 1"));
    }
}
