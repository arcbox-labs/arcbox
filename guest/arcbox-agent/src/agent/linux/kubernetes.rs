//! Kubernetes (k3s) lifecycle and RPC handlers.
//!
//! Provisions a single-node cluster via the bundled `k3s` binary, sharing
//! the containerd socket and Btrfs data volume with the Docker runtime.
//! Serves Start/Stop/Delete/Status/Kubeconfig requests and tracks the
//! k3s pid via a flat `/run/arcbox/k3s.pid` file.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::Result;
use tokio::process::Command;
use tokio::sync::Mutex;

use arcbox_constants::paths::{
    ARCBOX_RUNTIME_BIN_DIR, CNI_DATA_MOUNT_POINT, CONTAINERD_SOCKET, K3S_DATA_MOUNT_POINT,
    K3S_KUBECONFIG_PATH, KUBELET_DATA_MOUNT_POINT,
};
use arcbox_constants::ports::KUBERNETES_API_GUEST_PORT;
use arcbox_constants::status::{SERVICE_ERROR, SERVICE_NOT_READY, SERVICE_READY};
use arcbox_protocol::agent::{
    KubernetesDeleteRequest, KubernetesDeleteResponse, KubernetesKubeconfigRequest,
    KubernetesKubeconfigResponse, KubernetesStartRequest, KubernetesStartResponse,
    KubernetesStatusRequest, KubernetesStatusResponse, KubernetesStopRequest,
    KubernetesStopResponse,
};

use super::btrfs::ensure_data_mount;
use super::probe::{probe_first_ready_socket, probe_tcp};
use super::runtime::{
    CONTAINERD_SOCKET_CANDIDATES, daemon_log_file, ensure_containerd_ready,
    ensure_runtime_prerequisites, ensure_shared_runtime_dirs, missing_binaries_at,
    runtime_path_env,
};
use crate::rpc::{ErrorResponse, RpcResponse};

const K3S_PID_FILE: &str = "/run/arcbox/k3s.pid";
const K3S_NAMESPACE: &str = "k8s.io";
const KUBERNETES_HOST_ENDPOINT: &str = "https://127.0.0.1:16443";

const REQUIRED_KUBERNETES_BINARIES: &[&str] =
    &["containerd", "containerd-shim-runc-v2", "runc", "k3s"];

fn kubernetes_control_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn read_pid_file(path: &str) -> Option<i32> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<i32>()
        .ok()
}

fn write_pid_file(path: &str, pid: u32) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{pid}\n"))?;
    Ok(())
}

fn remove_pid_file(path: &str) {
    let _ = std::fs::remove_file(path);
}

fn process_alive(pid: i32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn k3s_pid() -> Option<i32> {
    let pid = read_pid_file(K3S_PID_FILE)?;
    if process_alive(pid) {
        Some(pid)
    } else {
        remove_pid_file(K3S_PID_FILE);
        None
    }
}

async fn k3s_api_ready() -> bool {
    probe_tcp(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        KUBERNETES_API_GUEST_PORT,
    ))
    .await
}

pub(super) async fn handle_start_kubernetes(_req: KubernetesStartRequest) -> RpcResponse {
    RpcResponse::KubernetesStart(do_start_kubernetes().await)
}

pub(super) async fn handle_stop_kubernetes(_req: KubernetesStopRequest) -> RpcResponse {
    RpcResponse::KubernetesStop(do_stop_kubernetes().await)
}

pub(super) async fn handle_delete_kubernetes(_req: KubernetesDeleteRequest) -> RpcResponse {
    RpcResponse::KubernetesDelete(do_delete_kubernetes().await)
}

pub(super) async fn handle_kubernetes_status(_req: KubernetesStatusRequest) -> RpcResponse {
    let _guard = kubernetes_control_lock().lock().await;
    RpcResponse::KubernetesStatus(collect_kubernetes_status().await)
}

pub(super) async fn handle_kubernetes_kubeconfig(_req: KubernetesKubeconfigRequest) -> RpcResponse {
    match std::fs::read_to_string(K3S_KUBECONFIG_PATH) {
        Ok(kubeconfig) => RpcResponse::KubernetesKubeconfig(KubernetesKubeconfigResponse {
            kubeconfig,
            context_name: "arcbox".to_string(),
            endpoint: KUBERNETES_HOST_ENDPOINT.to_string(),
        }),
        Err(e) => RpcResponse::Error(ErrorResponse::new(
            404,
            format!("kubeconfig unavailable: {e}"),
        )),
    }
}

async fn do_start_kubernetes() -> KubernetesStartResponse {
    let _guard = kubernetes_control_lock().lock().await;
    let runtime_bin_dir = PathBuf::from(ARCBOX_RUNTIME_BIN_DIR);
    let missing = missing_kubernetes_binaries_at(&runtime_bin_dir);
    if !missing.is_empty() {
        return KubernetesStartResponse {
            running: false,
            api_ready: false,
            endpoint: KUBERNETES_HOST_ENDPOINT.to_string(),
            detail: format!(
                "missing kubernetes binaries under {}: {}",
                ARCBOX_RUNTIME_BIN_DIR,
                missing.join(", ")
            ),
        };
    }

    let mut notes = ensure_runtime_prerequisites();
    match ensure_data_mount() {
        Ok(note) => notes.push(note),
        Err(e) => {
            return KubernetesStartResponse {
                running: false,
                api_ready: false,
                endpoint: KUBERNETES_HOST_ENDPOINT.to_string(),
                detail: format!("data volume setup failed: {e}"),
            };
        }
    }
    ensure_shared_runtime_dirs(&mut notes);

    if !ensure_containerd_ready(&runtime_bin_dir, &mut notes).await {
        return KubernetesStartResponse {
            running: false,
            api_ready: false,
            endpoint: KUBERNETES_HOST_ENDPOINT.to_string(),
            detail: notes.join("; "),
        };
    }

    if k3s_pid().is_none() {
        let k3s_bin = runtime_bin_dir.join("k3s");
        let mut cmd = Command::new(&k3s_bin);
        cmd.arg("server")
            .arg(format!("--container-runtime-endpoint={CONTAINERD_SOCKET}"))
            .arg(format!("--data-dir={K3S_DATA_MOUNT_POINT}"))
            .arg(format!("--write-kubeconfig={K3S_KUBECONFIG_PATH}"))
            .arg("--write-kubeconfig-mode=0600")
            .arg("--disable=traefik")
            .arg("--disable=servicelb")
            .env("PATH", runtime_path_env(&runtime_bin_dir))
            .stdin(Stdio::null())
            .stdout(daemon_log_file("k3s"))
            .stderr(daemon_log_file("k3s"));

        match cmd.spawn() {
            Ok(child) => {
                let pid = child.id().unwrap_or_default();
                if let Err(e) = write_pid_file(K3S_PID_FILE, pid) {
                    notes.push(format!("write k3s pid file failed({})", e));
                }
                notes.push(format!("spawned k3s (pid={pid})"));
            }
            Err(e) => {
                notes.push(format!("failed to spawn k3s: {}", e));
            }
        }
    } else {
        notes.push("k3s already running".to_string());
    }

    let mut status = collect_kubernetes_status().await;
    for _ in 0..60 {
        if status.api_ready {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        status = collect_kubernetes_status().await;
    }

    if !notes.is_empty() {
        status.detail = format!("{}; {}", notes.join("; "), status.detail);
    }
    KubernetesStartResponse {
        running: status.running,
        api_ready: status.api_ready,
        endpoint: status.endpoint,
        detail: status.detail,
    }
}

async fn do_stop_kubernetes() -> KubernetesStopResponse {
    let _guard = kubernetes_control_lock().lock().await;
    do_stop_kubernetes_locked().await
}

async fn do_stop_kubernetes_locked() -> KubernetesStopResponse {
    let Some(pid) = k3s_pid() else {
        return KubernetesStopResponse {
            stopped: true,
            detail: "k3s already stopped".to_string(),
        };
    };

    let pid = nix::unistd::Pid::from_raw(pid);
    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM);
    for _ in 0..20 {
        if !process_alive(pid.as_raw()) {
            remove_pid_file(K3S_PID_FILE);
            return KubernetesStopResponse {
                stopped: true,
                detail: "k3s stopped".to_string(),
            };
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
    remove_pid_file(K3S_PID_FILE);
    KubernetesStopResponse {
        stopped: true,
        detail: "k3s force-stopped".to_string(),
    }
}

async fn do_delete_kubernetes() -> KubernetesDeleteResponse {
    let _guard = kubernetes_control_lock().lock().await;
    let stop = do_stop_kubernetes_locked().await;
    let mut notes = vec![stop.detail];
    clear_kubernetes_namespace(&mut notes).await;

    for path in [
        K3S_DATA_MOUNT_POINT,
        KUBELET_DATA_MOUNT_POINT,
        CNI_DATA_MOUNT_POINT,
    ] {
        if let Err(e) = clear_directory_contents(Path::new(path)) {
            notes.push(format!("clear {} failed({})", path, e));
        }
    }

    KubernetesDeleteResponse {
        detail: notes.join("; "),
    }
}

async fn clear_kubernetes_namespace(notes: &mut Vec<String>) {
    let k3s_bin = PathBuf::from(ARCBOX_RUNTIME_BIN_DIR).join("k3s");
    if !k3s_bin.exists() {
        return;
    }

    match Command::new(&k3s_bin)
        .arg("ctr")
        .arg("--address")
        .arg(CONTAINERD_SOCKET)
        .arg("namespaces")
        .arg("remove")
        .arg(K3S_NAMESPACE)
        .status()
        .await
    {
        Ok(status) if status.success() => {
            notes.push("removed containerd namespace k8s.io".to_string());
        }
        Ok(status) => {
            notes.push(format!(
                "remove containerd namespace k8s.io exit={}",
                status.code().unwrap_or(-1)
            ));
        }
        Err(e) => {
            notes.push(format!("remove containerd namespace k8s.io failed({})", e));
        }
    }
}

fn clear_directory_contents(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            std::fs::remove_dir_all(&entry_path)?;
        } else {
            std::fs::remove_file(&entry_path)?;
        }
    }

    Ok(())
}

async fn collect_kubernetes_status() -> KubernetesStatusResponse {
    use arcbox_protocol::agent::ServiceStatus;

    let containerd_ready = probe_first_ready_socket(&CONTAINERD_SOCKET_CANDIDATES).await;
    let running = k3s_pid().is_some();
    let api_ready = k3s_api_ready().await;

    let mut services = Vec::new();
    services.push(ServiceStatus {
        name: "containerd".to_string(),
        status: if containerd_ready {
            SERVICE_READY.to_string()
        } else {
            SERVICE_NOT_READY.to_string()
        },
        detail: if containerd_ready {
            CONTAINERD_SOCKET.to_string()
        } else {
            "containerd socket not reachable".to_string()
        },
    });
    services.push(ServiceStatus {
        name: "k3s".to_string(),
        status: if api_ready {
            SERVICE_READY.to_string()
        } else if running {
            SERVICE_ERROR.to_string()
        } else {
            SERVICE_NOT_READY.to_string()
        },
        detail: if api_ready {
            format!("api reachable on 127.0.0.1:{KUBERNETES_API_GUEST_PORT}")
        } else if running {
            "k3s process running but api not ready".to_string()
        } else {
            "k3s process not running".to_string()
        },
    });

    let detail = if api_ready {
        "kubernetes api ready".to_string()
    } else if running {
        "k3s running but kubernetes api not ready".to_string()
    } else {
        "k3s not running".to_string()
    };

    KubernetesStatusResponse {
        running,
        api_ready,
        endpoint: KUBERNETES_HOST_ENDPOINT.to_string(),
        detail,
        services,
    }
}

fn missing_kubernetes_binaries_at(dir: &Path) -> Vec<&'static str> {
    missing_binaries_at(dir, REQUIRED_KUBERNETES_BINARIES)
}
