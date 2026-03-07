//! k3s lightweight Kubernetes server management.
//!
//! Spawns `k3s server` from the VirtioFS runtime directory if the binary is
//! present, with persistent state on the Btrfs `@k3s` subvolume. Degrades
//! gracefully if the k3s binary is missing.

use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use arcbox_constants::paths::{K3S_DATA_MOUNT_POINT, K3S_KUBECONFIG_GUEST};
use arcbox_constants::ports::K3S_API_PORT;
use arcbox_protocol::agent::{K3sEnsureRequest, K3sEnsureResponse, RuntimeEnsureResponse};

use crate::agent::ensure_runtime::{self, RuntimeGuard, STATUS_FAILED, STATUS_STARTED};
use crate::rpc::RpcResponse;

const K3S_BIN: &str = "/arcbox/runtime/bin/k3s";

/// Returns the global k3s `RuntimeGuard` singleton.
fn k3s_guard() -> &'static RuntimeGuard {
    static GUARD: OnceLock<RuntimeGuard> = OnceLock::new();
    GUARD.get_or_init(RuntimeGuard::new)
}

/// Maps `RuntimeEnsureResponse` (used by the generic state machine) into
/// the k3s-specific protobuf response.
fn map_response(r: &RuntimeEnsureResponse) -> K3sEnsureResponse {
    K3sEnsureResponse {
        ready: r.ready,
        endpoint: r.endpoint.clone(),
        kubeconfig_path: if r.ready {
            "~/.arcbox/k3s/kubeconfig.yaml".to_string()
        } else {
            String::new()
        },
        message: r.message.clone(),
        status: r.status.clone(),
    }
}

/// Idempotent, concurrency-safe EnsureK3s handler.
pub async fn handle_ensure_k3s(req: K3sEnsureRequest) -> RpcResponse {
    let resp = ensure_runtime::ensure_runtime(
        k3s_guard(),
        req.start_if_needed,
        do_k3s_start(),
        do_k3s_probe(),
    )
    .await;

    RpcResponse::K3sEnsure(map_response(&resp))
}

/// Performs the actual k3s start sequence (called only by the driver).
async fn do_k3s_start() -> RuntimeEnsureResponse {
    // Ensure the data drive is mounted (idempotent).
    if let Err(e) = super::agent::ensure_data_mount() {
        return failed(&format!("data mount failed: {e}"));
    }

    // Ensure the @k3s subvolume bind-mount target exists.
    if !crate::mount::is_mounted(K3S_DATA_MOUNT_POINT) {
        // The subvolume and bind-mount are set up by ensure_data_mount().
        // If we get here, it means the mount didn't include @k3s. This
        // should not happen with the updated ensure_data_mount(), but
        // handle it gracefully.
        if let Err(e) = std::fs::create_dir_all(K3S_DATA_MOUNT_POINT) {
            return failed(&format!("mkdir {} failed: {e}", K3S_DATA_MOUNT_POINT));
        }
        // Try creating the subvolume + bind-mount manually.
        let btrfs_temp = "/run/arcbox/data";
        let subvol_path = format!("{btrfs_temp}/@k3s");
        if !Path::new(&subvol_path).exists() {
            if let Err(e) = super::agent::btrfs_create_subvolume(&subvol_path) {
                return failed(&format!("failed to create @k3s subvolume: {e}"));
            }
        }
    }

    // Verify k3s binary exists.
    if !Path::new(K3S_BIN).exists() {
        return failed(&format!("k3s binary not found at {K3S_BIN}"));
    }

    // Create kubeconfig output directory.
    if let Some(parent) = Path::new(K3S_KUBECONFIG_GUEST).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Spawn k3s server.
    let log_out = super::agent::daemon_log_file("k3s");
    let log_err = super::agent::daemon_log_file("k3s");

    match tokio::process::Command::new(K3S_BIN)
        .args([
            "server",
            "--data-dir",
            K3S_DATA_MOUNT_POINT,
            "--write-kubeconfig",
            K3S_KUBECONFIG_GUEST,
            "--disable",
            "traefik",
            "--disable",
            "servicelb",
            "--flannel-backend=host-gw",
        ])
        .stdout(log_out)
        .stderr(log_err)
        .spawn()
    {
        Ok(_child) => {
            tracing::info!("k3s server spawned");
        }
        Err(e) => {
            return failed(&format!("failed to spawn k3s: {e}"));
        }
    }

    // Poll TCP 127.0.0.1:6443 up to 60 seconds (k3s first boot takes 15-30s).
    for _ in 0..600 {
        if probe_k3s_tcp().await {
            // Patch kubeconfig server field so it works over port forwarding.
            patch_kubeconfig();
            return RuntimeEnsureResponse {
                ready: true,
                endpoint: format!("https://localhost:{K3S_API_PORT}"),
                message: "k3s started".to_string(),
                status: STATUS_STARTED.to_string(),
            };
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    failed("k3s spawned but API port 6443 not reachable within 60s")
}

/// Probes k3s status without attempting to start.
async fn do_k3s_probe() -> RuntimeEnsureResponse {
    if probe_k3s_tcp().await {
        RuntimeEnsureResponse {
            ready: true,
            endpoint: format!("https://localhost:{K3S_API_PORT}"),
            message: "k3s running".to_string(),
            status: ensure_runtime::STATUS_REUSED.to_string(),
        }
    } else {
        failed("k3s not running (TCP port 6443 not reachable)")
    }
}

/// TCP connect probe to 127.0.0.1:6443.
async fn probe_k3s_tcp() -> bool {
    tokio::time::timeout(
        Duration::from_millis(300),
        tokio::net::TcpStream::connect(("127.0.0.1", K3S_API_PORT)),
    )
    .await
    .is_ok_and(|r| r.is_ok())
}

/// Patches the kubeconfig `server:` field to use `localhost:6443` so it works
/// over host port forwarding.
fn patch_kubeconfig() {
    let Ok(contents) = std::fs::read_to_string(K3S_KUBECONFIG_GUEST) else {
        tracing::warn!("k3s kubeconfig not found at {}", K3S_KUBECONFIG_GUEST);
        return;
    };

    // k3s writes `server: https://127.0.0.1:6443` by default. Replace any
    // loopback address variant with `localhost` for host-side compatibility.
    let patched = contents.replace(
        "https://127.0.0.1:6443",
        &format!("https://localhost:{K3S_API_PORT}"),
    );

    if patched != contents {
        if let Err(e) = std::fs::write(K3S_KUBECONFIG_GUEST, &patched) {
            tracing::warn!("failed to patch kubeconfig: {e}");
        }
    }
}

fn failed(message: &str) -> RuntimeEnsureResponse {
    tracing::warn!("k3s: {}", message);
    RuntimeEnsureResponse {
        ready: false,
        endpoint: String::new(),
        message: message.to_string(),
        status: STATUS_FAILED.to_string(),
    }
}
