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

use anyhow::{Context, Result, bail};
use tokio::process::Command;
use tokio::sync::Mutex;

use arcbox_connect::v1::{
    RuntimeEnsureRequest, RuntimeEnsureResponse, RuntimeStatusRequest, RuntimeStatusResponse,
};
use arcbox_constants::paths::{
    ARCBOX_RUNTIME_BIN_DIR, CONTAINERD_SOCKET, DOCKER_API_UNIX_SOCKET, DOCKER_DATA_MOUNT_POINT,
    K3S_CNI_BIN_DIR, K3S_CNI_CONF_DIR,
};
use arcbox_constants::status::{SERVICE_ERROR, SERVICE_NOT_READY, SERVICE_READY};

use super::btrfs::ensure_data_mount;
use super::cmdline::{declared_runtime_image_device, docker_api_vsock_port};
use super::probe::{probe_docker_api_ready, probe_first_ready_socket, probe_unix_socket};
use super::rpc::sync_clock_from_host;
use crate::agent::ensure_runtime;
use crate::rpc::RpcResponse;

/// Containerd socket candidates (primary + legacy fallback).
pub(super) const CONTAINERD_SOCKET_CANDIDATES: [&str; 2] =
    [CONTAINERD_SOCKET, "/var/run/containerd/containerd.sock"];

const REQUIRED_RUNTIME_BINARIES: &[&str] = &[
    "dockerd",
    "containerd",
    "containerd-shim-runc-v2",
    "runc",
    "docker-init",
];

/// Minimum "sane" UNIX timestamp for TLS certificate validation.
///
/// Chosen to be old enough that it's always in the past, but recent
/// enough that TLS certificates issued after 2020 pass validation.
/// 2020-01-01T00:00:00Z
const MIN_SANE_EPOCH: u64 = 1_577_836_800;

/// All Docker bridge subnets routed from macOS through the bridge NIC.
const CONTAINER_SUBNET: &str = "172.16.0.0/12";

/// Polling fallback for firewall managers that recreate `DOCKER-USER`.
const DIRECT_ROUTING_RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

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
        do_ensure_runtime_start,
        do_ensure_runtime_probe,
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

    // Poll until the docker API answers /_ping (up to ~90 seconds).
    // On large data volumes with VirtIO block I/O, containerd may need
    // up to 30s to scan its content store, and dockerd may need additional
    // time to load containers from Btrfs before it starts serving.
    let mut status = collect_runtime_status().await;
    for _ in 0..180 {
        if status.docker_ready {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        status = collect_runtime_status().await;
    }

    let routing_error = if status.docker_ready {
        ensure_direct_container_routing().await.err()
    } else {
        None
    };

    let mut message = if notes.is_empty() {
        status.detail.clone()
    } else {
        format!("{}; {}", notes.join("; "), status.detail)
    };
    if let Some(error) = &routing_error {
        message = format!("{message}; direct container routing setup failed: {error:#}");
    }

    let ready = status.docker_ready && routing_error.is_none();
    let result_status = if ready {
        ensure_runtime::STATUS_STARTED.to_string()
    } else {
        ensure_runtime::STATUS_FAILED.to_string()
    };

    RuntimeEnsureResponse {
        ready,
        endpoint: status.endpoint,
        message,
        status: result_status,
        ..Default::default()
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
        ..Default::default()
    }
}

pub(super) async fn handle_runtime_status(_req: RuntimeStatusRequest) -> RpcResponse {
    RpcResponse::RuntimeStatus(collect_runtime_status().await)
}

/// Allows traffic arriving on the vmnet bridge NIC to reach Docker bridge
/// subnets routed from macOS.
///
/// Docker creates `DOCKER-USER` only after it starts. Installing this rule
/// before dockerd is ineffective, and inserting directly into `FORWARD` is
/// unstable because Docker prepends its own chains on startup. The matching
/// daemon option `allow-direct-routing` removes Docker's earlier raw-table
/// per-container drops; this rule then bypasses its unpublished-port drop.
async fn ensure_direct_container_routing() -> Result<()> {
    let _guard = direct_routing_lock().lock().await;
    let Some(bridge_iface) = crate::init::detect_bridge_interface() else {
        tracing::debug!("no bridge NIC found; skipping direct container routing rule");
        return Ok(());
    };

    let rule = [
        "DOCKER-USER",
        "-i",
        bridge_iface.as_str(),
        "-d",
        CONTAINER_SUBNET,
        "-j",
        "ACCEPT",
    ];
    let check = Command::new("/sbin/iptables")
        .args(["-w", "2", "-C"])
        .args(rule)
        .output()
        .await
        .context("checking DOCKER-USER rule")?;
    if check.status.success() {
        return Ok(());
    }
    if check.status.code() != Some(1) {
        bail!(
            "iptables check failed: {}",
            String::from_utf8_lossy(&check.stderr).trim()
        );
    }

    let install = Command::new("/sbin/iptables")
        .args(["-w", "2", "-I"])
        .args(rule)
        .output()
        .await
        .context("installing DOCKER-USER rule")?;
    if !install.status.success() {
        bail!(
            "iptables failed: {}",
            String::from_utf8_lossy(&install.stderr).trim()
        );
    }

    tracing::info!(
        interface = bridge_iface,
        subnet = CONTAINER_SUBNET,
        "direct container routing rule installed"
    );
    Ok(())
}

fn direct_routing_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Restores the direct-routing firewall rule if Docker recreates its chains.
pub(super) async fn direct_container_routing_loop() {
    let mut ticker = tokio::time::interval(DIRECT_ROUTING_RECONCILE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Initial runtime setup owns the readiness gate and first installation.
    // Delay this fallback's first check to avoid duplicating startup probes.
    ticker.tick().await;

    loop {
        ticker.tick().await;
        if !probe_docker_api_ready(DOCKER_API_UNIX_SOCKET).await {
            continue;
        }
        if let Err(error) = ensure_direct_container_routing().await {
            tracing::warn!(%error, "failed to reconcile direct container routing rule");
        }
    }
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
    let init_bin = runtime_bin_dir.join("docker-init");
    let mut cmd = Command::new(&dockerd_bin);
    cmd.arg(format!("--host=unix://{DOCKER_API_UNIX_SOCKET}"))
        .arg(format!("--containerd={CONTAINERD_SOCKET}"))
        .arg("--exec-root=/var/run/docker")
        .arg(format!("--data-root={DOCKER_DATA_MOUNT_POINT}"))
        .arg("--userland-proxy=false")
        .arg(format!("--init-path={}", init_bin.display()))
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
    use arcbox_connect::v1::ServiceStatus;

    let containerd_ready = probe_first_ready_socket(&CONTAINERD_SOCKET_CANDIDATES).await;
    // Two-level check: socket connectable (fast) + HTTP API probe (strong).
    // The API probe is the ready gate: dockerd binds its socket before it
    // finishes initializing (Loading containers…), so a socket-only gate
    // reports ready while the first API calls still fail. Slow dockerd
    // starts are covered by budget, not by weakening the gate — the
    // ensure-runtime driver polls ~90s and the host startup timeout
    // exceeds it (`ContainerRuntimeConfig::startup_timeout_ms`).
    let docker_socket_ok = probe_unix_socket(DOCKER_API_UNIX_SOCKET).await;
    let docker_api_ok = if docker_socket_ok {
        probe_docker_api_ready(DOCKER_API_UNIX_SOCKET).await
    } else {
        false
    };
    let docker_probe = DockerProbe {
        socket_exists: Path::new(DOCKER_API_UNIX_SOCKET).exists(),
        socket_ok: docker_socket_ok,
        api_ok: docker_api_ok,
    };
    let docker_ready = docker_probe.ready();
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
            ..Default::default()
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
            ..Default::default()
        }
    });

    services.push(docker_probe.service_status());

    let detail = docker_probe.summary_detail(&missing_runtime_binaries);

    RuntimeStatusResponse {
        containerd_ready,
        docker_ready,
        endpoint: format!("vsock:{}", docker_api_vsock_port()),
        detail,
        services,
        ..Default::default()
    }
}

/// Observed dockerd probe results, classified into status/detail strings.
///
/// Ready means the API answered `/_ping` — a bound-but-initializing socket
/// (dockerd loading containers) is explicitly *not ready*, only reported
/// in the detail so operators can tell "starting up" from "broken".
struct DockerProbe {
    socket_exists: bool,
    socket_ok: bool,
    api_ok: bool,
}

impl DockerProbe {
    fn ready(&self) -> bool {
        self.api_ok
    }

    fn service_status(&self) -> arcbox_connect::v1::ServiceStatus {
        let status = if self.ready() {
            SERVICE_READY
        } else if self.socket_ok {
            // Bound socket, API still initializing — progress, not an error.
            SERVICE_NOT_READY
        } else if self.socket_exists {
            // Socket file present but connections fail: dockerd died.
            SERVICE_ERROR
        } else {
            SERVICE_NOT_READY
        };

        let detail = if self.ready() {
            format!("API /_ping OK: {}", DOCKER_API_UNIX_SOCKET)
        } else if self.socket_ok {
            format!(
                "socket connectable, API initializing: {}",
                DOCKER_API_UNIX_SOCKET
            )
        } else if self.socket_exists {
            format!(
                "socket exists but not connectable: {}",
                DOCKER_API_UNIX_SOCKET
            )
        } else {
            format!("socket missing: {}", DOCKER_API_UNIX_SOCKET)
        };

        arcbox_connect::v1::ServiceStatus {
            name: "dockerd".to_string(),
            status: status.to_string(),
            detail,
            ..Default::default()
        }
    }

    fn summary_detail(&self, missing_runtime_binaries: &[&'static str]) -> String {
        if self.ready() {
            "docker engine ready (API /_ping OK)".to_string()
        } else if self.socket_ok {
            format!(
                "docker API initializing (socket connectable): {}",
                DOCKER_API_UNIX_SOCKET
            )
        } else if self.socket_exists {
            format!(
                "docker socket exists but not reachable: {}",
                DOCKER_API_UNIX_SOCKET
            )
        } else if !missing_runtime_binaries.is_empty() {
            format!(
                "docker socket missing: {}; {}",
                DOCKER_API_UNIX_SOCKET,
                runtime_missing_detail_from(missing_runtime_binaries)
            )
        } else {
            format!("docker socket missing: {}", DOCKER_API_UNIX_SOCKET)
        }
    }
}

fn runtime_start_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Read-only mount point of the block-backed runtime image.
///
/// The runtime binaries otherwise live on the host-backed `arcbox` VirtioFS
/// share, where every exec costs a FUSE round-trip — measured 7-10x more than
/// exec'ing the same binary from block-backed storage, and paid on *every*
/// container start (so on every `docker build` step). When the boot release
/// ships a runtime image the host attaches it as a read-only disk and the
/// guest execs from here instead (ABX-498).
const RUNTIME_IMAGE_MOUNT: &str = "/run/arcbox/runtime";

/// Mounts the read-only runtime image the host declared on the cmdline.
/// Returns whether the mount is available afterward.
///
/// Best-effort by design: the VirtioFS copies stay as the fallback, so a
/// release without an image, or a failed mount, costs exec speed but never
/// correctness.
fn mount_runtime_image(notes: &mut Vec<String>) -> bool {
    if crate::mount::is_mounted(RUNTIME_IMAGE_MOUNT) {
        return true;
    }
    let Some(device) = declared_runtime_image_device() else {
        return false;
    };
    // The node can lag guest boot; wait briefly rather than silently taking
    // the slow path for the rest of this boot.
    if !wait_for_runtime_image_device(&device) {
        notes.push(format!("runtime image device {device} never appeared"));
        return false;
    }
    if let Err(e) = std::fs::create_dir_all(RUNTIME_IMAGE_MOUNT) {
        notes.push(format!("runtime image mkdir failed({e})"));
        return false;
    }
    match std::process::Command::new("/bin/busybox")
        .args([
            "mount",
            "-t",
            "erofs",
            "-o",
            "ro",
            &device,
            RUNTIME_IMAGE_MOUNT,
        ])
        .status()
    {
        Ok(status) if status.success() => {
            notes.push(format!("mounted runtime image from {device}"));
            true
        }
        _ => {
            notes.push(format!(
                "runtime image mount failed ({device}); using VirtioFS"
            ));
            false
        }
    }
}

/// Waits up to 5 s for the declared device node (same budget and rationale as
/// the data-device wait in `btrfs.rs`).
fn wait_for_runtime_image_device(device: &str) -> bool {
    for attempt in 0..50 {
        if Path::new(device).exists() {
            if attempt > 0 {
                tracing::info!(device, attempt, "waited for runtime image device");
            }
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

fn detect_runtime_bin_dir() -> Option<PathBuf> {
    // Prefer the block-backed runtime image when it is mounted — exec from
    // it is 7-10x cheaper than over VirtioFS. Everything downstream (the
    // containerd/dockerd spawns and the PATH they inherit) follows this one
    // directory, so preferring it here is the whole switch.
    let image = PathBuf::from(RUNTIME_IMAGE_MOUNT);
    if missing_runtime_binaries_at(&image).is_empty() {
        return Some(image);
    }
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

    // Expedite RCU grace periods. Every container start's `runc create`
    // (and network-namespace teardown) calls synchronize_rcu; on the
    // non-expedited guest kernel each grace period parks runc ~70 ms in
    // uninterruptible sleep (`__wait_rcu_gp`), which is the dominant
    // runc-create cost — profiled at ~88 ms → ~10 ms with this set, an 8x
    // cut (ABX-496). Expedited grace periods use IPIs (µs, not ms); the
    // trade is more IPIs under RCU load, the right call for a
    // container/build runtime with heavy netns churn.
    if let Err(e) = std::fs::write("/sys/kernel/rcu_expedited", b"1\n") {
        notes.push(format!("rcu_expedited failed({e})"));
    } else {
        notes.push("enabled rcu_expedited".to_string());
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

    let open_append = |path: &str| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    };

    // Prefer the VirtioFS share so the host can read the log; warn loudly on each
    // degradation so a virtiofs failure doesn't silently hide service logs.
    if Path::new("/arcbox").exists() {
        let _ = std::fs::create_dir_all(&log_dir);
        match open_append(&arcbox_path) {
            Ok(f) => return f.into(),
            Err(e) => {
                tracing::warn!(
                    service = name,
                    error = %e,
                    "failed to open {arcbox_path} for {name} logs; falling back to {tmp_log_path}"
                );
            }
        }
    } else {
        tracing::warn!(
            service = name,
            "/arcbox VirtioFS share not mounted; {name} logs go to {tmp_log_path} (guest-local, not visible from the host)"
        );
    }

    match open_append(&tmp_log_path) {
        Ok(f) => f.into(),
        Err(e) => {
            tracing::error!(
                service = name,
                error = %e,
                "failed to open {tmp_log_path} for {name} logs; discarding to /dev/null"
            );
            Stdio::null()
        }
    }
}

async fn try_start_bundled_runtime() -> String {
    let _guard = runtime_start_lock().lock().await;

    if probe_unix_socket(DOCKER_API_UNIX_SOCKET).await {
        return "docker socket already ready".to_string();
    }

    let mut notes = Vec::new();

    // Ensure kernel/filesystem prerequisites before spawning daemons — and
    // before mounting the runtime image below, since that mounts under /run
    // and the prerequisites are what guarantee /run is a writable tmpfs.
    let prereq_notes = ensure_runtime_prerequisites();
    if !prereq_notes.is_empty() {
        tracing::info!(prerequisites = %prereq_notes.join("; "), "runtime prerequisites");
    }
    notes.extend(prereq_notes);

    // Mount the runtime image (when this release ships one) before probing
    // for the runtime binaries, so the probe can prefer it.
    mount_runtime_image(&mut notes);

    let Some(runtime_bin_dir) = detect_runtime_bin_dir() else {
        return runtime_missing_detail();
    };

    tracing::info!(
        runtime_bin_dir = %runtime_bin_dir.display(),
        "starting bundled runtime"
    );
    match ensure_data_mount() {
        Ok(note) => notes.push(note),
        Err(e) => return format!("data volume setup failed: {}", e),
    }

    // Bind the fsync-hot metadata dirs onto the ext4 volume before the
    // daemons open their boltdb files. A hard error means the volume exists
    // but is unusable — starting dockerd against the stale shadowed btrfs
    // state would fork it, so abort instead.
    match super::metadata_volume::ensure_metadata_mount() {
        Ok(note) => notes.push(note),
        Err(e) => return format!("metadata volume setup failed: {}", e),
    }

    ensure_shared_runtime_dirs(&mut notes);

    if !ensure_containerd_ready(&runtime_bin_dir, &mut notes).await {
        return notes.join("; ");
    }

    ensure_dockerd_ready(&runtime_bin_dir, &mut notes).await;

    notes.join("; ")
}

/// Brings up the read-only NFS export of the docker data mount so the host
/// can browse it at `~/ArcBox`.
///
/// Called on demand by the host daemon (`EnsureNfsExportRequest`), which only
/// sends it when the mount is enabled — so a `--no-mount-nfs` daemon leaves
/// the guest with no nfsd at all. Ensures the docker data mount exists first
/// (idempotent), so it is safe to call at any point after the agent is up;
/// the runtime-start lock serializes it against the startup path's own
/// data-mount setup.
pub(super) async fn ensure_nfs_export() -> Result<Vec<String>, String> {
    let _guard = runtime_start_lock().lock().await;

    let mut notes = vec![ensure_data_mount()?];
    notes.extend(crate::nfs::ensure_docker_export()?);
    Ok(notes)
}

#[cfg(test)]
mod tests {
    use arcbox_constants::status::{SERVICE_ERROR, SERVICE_NOT_READY, SERVICE_READY};

    use super::{DockerProbe, shared_containerd_config};

    #[test]
    fn shared_containerd_config_uses_k3s_cni_paths() {
        let config = shared_containerd_config();
        assert!(config.contains("bin_dir = \"/var/lib/rancher/k3s/data/cni\""));
        assert!(config.contains("conf_dir = \"/var/lib/rancher/k3s/agent/etc/cni/net.d\""));
        assert!(config.contains("max_conf_num = 1"));
    }

    fn probe(socket_exists: bool, socket_ok: bool, api_ok: bool) -> DockerProbe {
        DockerProbe {
            socket_exists,
            socket_ok,
            api_ok,
        }
    }

    #[test]
    fn docker_ready_requires_api_ping_not_just_socket() {
        // Bound-but-initializing socket (dockerd loading containers) must
        // not report ready — the regression behind the "500s right after
        // engine ready" flake.
        assert!(!probe(true, true, false).ready());
        assert!(probe(true, true, true).ready());
    }

    #[test]
    fn initializing_socket_is_not_ready_but_also_not_an_error() {
        let status = probe(true, true, false).service_status();
        assert_eq!(status.status, SERVICE_NOT_READY);
        assert!(status.detail.contains("API initializing"));
    }

    #[test]
    fn dead_socket_file_is_an_error() {
        let status = probe(true, false, false).service_status();
        assert_eq!(status.status, SERVICE_ERROR);
        assert!(status.detail.contains("not connectable"));
    }

    #[test]
    fn ready_probe_reports_ready_service() {
        let status = probe(true, true, true).service_status();
        assert_eq!(status.status, SERVICE_READY);
        assert!(status.detail.contains("/_ping OK"));
    }

    #[test]
    fn summary_mentions_missing_binaries_when_socket_absent() {
        let summary = probe(false, false, false).summary_detail(&["dockerd", "runc"]);
        assert!(summary.contains("socket missing"));
        assert!(summary.contains("dockerd, runc"));

        let initializing = probe(true, true, false).summary_detail(&[]);
        assert!(initializing.contains("initializing"));
    }
}
