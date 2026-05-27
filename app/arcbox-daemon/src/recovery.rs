//! Post-startup recovery: re-establish networking for surviving containers
//! and reconcile host routes.

use std::path::Path;
use std::sync::Arc;

use arcbox_core::Runtime;
use tracing::info;

use crate::context::DaemonContext;
use crate::self_setup;
use crate::self_setup::SetupTask as _;

/// Runs all recovery and best-effort setup tasks.
///
/// - Recovers DNS and port forwarding for containers that survived a daemon restart
/// - Re-installs the container subnet route (cold-start reconcile)
/// - Installs DNS resolver and Docker socket via helper (best-effort)
pub async fn run(ctx: &DaemonContext, runtime: &Arc<Runtime>) {
    recover_container_networking(runtime, &ctx.setup_state).await;

    // Cold-start route reconcile (non-blocking).
    #[cfg(target_os = "macos")]
    {
        use arcbox_core::DEFAULT_MACHINE_NAME;
        if let Some(mac) = runtime.machine_manager().bridge_mac(DEFAULT_MACHINE_NAME) {
            let setup_state = Arc::clone(&ctx.setup_state);
            drop(tokio::spawn(async move {
                match arcbox_core::route_reconciler::ensure_route_with_retry(&mac).await {
                    Ok(()) => setup_state.set_route_installed(true),
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to install container route on cold start");
                    }
                }
            }));
        }
    }

    // Best-effort self-setup (non-blocking).
    let dns_task = self_setup::DnsResolver {
        domain: ctx.dns_domain.clone(),
        port: ctx.dns_port,
    };
    let socket_task = self_setup::DockerSocket {
        target: ctx.layout.docker_socket.clone(),
    };

    // Create /usr/local/bin/ symlinks for Docker CLI tools if running from
    // bundle with docker integration enabled.
    let cli_tasks: Vec<Box<dyn self_setup::SetupTask>> = if ctx.docker_integration {
        if let Some(contents) = crate::startup::find_bundle_contents() {
            let xbin = contents.join("MacOS/xbin");
            if xbin.is_dir() {
                vec![Box::new(self_setup::CliTools { xbin_dir: xbin })]
            } else {
                vec![]
            }
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    let setup_state_self = Arc::clone(&ctx.setup_state);
    tokio::spawn(async move {
        let mut tasks: Vec<&dyn self_setup::SetupTask> = vec![&dns_task, &socket_task];
        for t in &cli_tasks {
            tasks.push(t.as_ref());
        }
        self_setup::run(&tasks).await;
        setup_state_self.set_dns_installed(dns_task.is_satisfied());
        setup_state_self.set_docker_socket_linked(socket_task.is_satisfied());
    });

    // Docker CLI tools installation (non-blocking, best-effort).
    if ctx.docker_integration {
        let data_dir = ctx.layout.data_dir.clone();
        let setup_state = Arc::clone(&ctx.setup_state);
        tokio::spawn(async move {
            match ensure_docker_tools(&data_dir).await {
                Ok(()) => setup_state.set_docker_tools_installed(true),
                Err(e) => {
                    tracing::warn!(error = %e, "Docker tools setup failed");
                }
            }
        });
    }
}

// =============================================================================
// Docker CLI tools
// =============================================================================

/// Embedded lockfile (same one used by arcbox-core for boot assets).
const LOCK_TOML: &str = include_str!("../../../assets.lock");

/// Installs Docker CLI tools (docker, buildx, compose, credential helper)
/// if not already present. Tries the app bundle first, then CDN.
async fn ensure_docker_tools(data_dir: &Path) -> anyhow::Result<()> {
    let tools = arcbox_docker_tools::parse_tools_for_group(
        LOCK_TOML,
        arcbox_docker_tools::ToolGroup::Docker,
    )
    .map_err(|e| anyhow::anyhow!("failed to parse tools from assets.lock: {e}"))?;

    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x86_64"
    };

    let install_dir = data_dir.join("runtime/bin");
    let mgr = arcbox_docker_tools::HostToolManager::new(tools, arch, install_dir);

    // Docker tools are already seeded from the app bundle by
    // seed_from_bundle() (via Resources/runtime/bin/). This check
    // is a fast no-op when they're present and checksums match.
    if mgr.validate_all().await.is_ok() {
        tracing::debug!("Docker CLI tools already installed and valid");
        return Ok(());
    }

    mgr.install_all(None)
        .await
        .map_err(|e| anyhow::anyhow!("docker tools install failed: {e}"))?;

    info!("Docker CLI tools installed");
    Ok(())
}

// =============================================================================
// Container networking recovery
// =============================================================================

/// Re-registers DNS entries and port forwarding for all running containers.
///
/// If the guest VM responds (even with an empty container list), the
/// `vm_running` flag on `setup_state` is set to `true`.
async fn recover_container_networking(
    runtime: &Arc<Runtime>,
    setup_state: &Arc<arcbox_api::SetupState>,
) {
    use arcbox_docker::proxy::VsockConnector;
    use axum::http::{HeaderMap, Method};
    use bytes::Bytes;

    let connector = VsockConnector::new(Arc::clone(runtime));
    let resp = match arcbox_docker::proxy::proxy_to_guest(
        &connector,
        Method::GET,
        "/containers/json",
        &HeaderMap::new(),
        Bytes::new(),
    )
    .await
    {
        Ok(resp) if resp.status().is_success() => resp,
        Ok(resp) => {
            tracing::debug!("Container list returned status {}", resp.status());
            return;
        }
        Err(e) => {
            tracing::debug!("Failed to list containers for networking recovery: {}", e);
            return;
        }
    };

    // Successfully queried the guest VM — it is running.
    setup_state.set_vm_running(true);

    let body_bytes = match http_body_util::BodyExt::collect(resp.into_body()).await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::debug!("Failed to read container list body: {}", e);
            return;
        }
    };

    let containers: Vec<serde_json::Value> = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!("Failed to parse container list JSON: {}", e);
            return;
        }
    };

    let mut recovered_dns = 0u32;
    let mut recovered_ports = 0u32;
    for container in &containers {
        let Some(id) = container.get("Id").and_then(|v| v.as_str()) else {
            continue;
        };

        let inspect_path = format!("/containers/{id}/json");
        let inspect_resp = match arcbox_docker::proxy::proxy_to_guest(
            &connector,
            Method::GET,
            &inspect_path,
            &HeaderMap::new(),
            Bytes::new(),
        )
        .await
        {
            Ok(resp) if resp.status().is_success() => resp,
            _ => continue,
        };

        let inspect_body = match http_body_util::BodyExt::collect(inspect_resp.into_body()).await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => continue,
        };

        if let Some((aliases, ip)) =
            arcbox_docker::handlers::extract_container_dns_info(&inspect_body)
        {
            runtime.register_dns(id, &aliases, ip).await;
            recovered_dns += 1;
        }

        let bindings = arcbox_docker::proxy::parse_port_bindings(&inspect_body);
        if !bindings.is_empty() {
            let rules: Vec<_> = bindings
                .iter()
                .map(|b| {
                    (
                        b.host_ip.clone(),
                        b.host_port,
                        b.container_port,
                        b.protocol.clone(),
                    )
                })
                .collect();
            match runtime
                .start_port_forwarding_for(runtime.default_machine_name(), id, &rules)
                .await
            {
                Ok(()) => recovered_ports += 1,
                Err(e) => tracing::warn!("Failed to recover port forwarding for {id}: {e}"),
            }
        }
    }

    if recovered_dns > 0 || recovered_ports > 0 {
        info!(
            dns = recovered_dns,
            ports = recovered_ports,
            "Recovered networking for running containers"
        );
    }
}
