//! Post-startup recovery: re-establish networking for surviving containers
//! and reconcile host routes.

use std::path::Path;
use std::sync::Arc;

use arcbox_constants::paths::HostLayout;
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
    // Every recovery task here reconciles Linux-VM container networking or
    // Docker integration; none apply in VM-host-only mode.
    if !runtime.config().vm.autostart {
        return;
    }

    recover_container_networking(runtime).await;

    // Cold-start route reconcile (non-blocking). This is load-bearing after
    // app updates or daemon restarts where the VM survives but the host route
    // may have been removed or stolen by another network service.
    #[cfg(all(target_os = "macos", feature = "vmnet"))]
    {
        use arcbox_core::DEFAULT_MACHINE_NAME;
        use arcbox_core::bridge_discovery::MachineBridgeExt as _;
        if let Some(ColdStartRoutePlan::VmnetBridge(bridge)) = cold_start_route_plan(
            runtime
                .machine_manager()
                .vmnet_bridge_name(DEFAULT_MACHINE_NAME),
            None,
        ) {
            spawn_vmnet_route_reconcile(Arc::clone(&ctx.setup_state), bridge);
        }
    }

    #[cfg(all(target_os = "macos", not(feature = "vmnet")))]
    {
        use arcbox_core::DEFAULT_MACHINE_NAME;
        if let Some(ColdStartRoutePlan::BridgeMac(mac)) = cold_start_route_plan(
            None,
            runtime.machine_manager().bridge_mac(DEFAULT_MACHINE_NAME),
        ) {
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
    //
    // The `/etc/resolver/<domain>` entry belongs to the daemon serving the
    // canonical DNS port. A daemon on any other port (an e2e harness daemon
    // with an ephemeral port, an ad-hoc dev run) must never rewrite the
    // host-global resolver away from the installed daemon — after it exits,
    // host DNS would point at a dead port.
    let dns_task =
        (ctx.dns_port == crate::startup::DEFAULT_DNS_PORT).then(|| self_setup::DnsResolver {
            domain: ctx.dns_domain.clone(),
            port: ctx.dns_port,
        });
    if dns_task.is_none() {
        tracing::debug!(
            port = ctx.dns_port,
            "non-default DNS port; skipping /etc/resolver self-setup"
        );
    }
    // The `/var/run/docker.sock` symlink likewise belongs to the daemon
    // running its profile's canonical data dir: the link target embeds the
    // data dir, so a daemon on an overridden one (an e2e harness daemon on
    // a temp dir, an ad-hoc dev run) would re-point the host-global Docker
    // socket at a path that dies with it. `ARCBOX_DATA_DIR` counts as
    // canonical — it relocates the machine-wide installation, not one
    // daemon instance; the installer persists it into the launchd plist's
    // EnvironmentVariables so a relocated install still satisfies this
    // check (its plist also passes the same path as `--data-dir`).
    let default_data_dir = HostLayout::resolve_for_profile_from_env(ctx.profile, None).data_dir;
    let socket_task = (ctx.layout.data_dir == default_data_dir).then(|| self_setup::DockerSocket {
        target: ctx.layout.docker_socket.clone(),
    });
    if socket_task.is_none() {
        tracing::debug!(
            data_dir = %ctx.layout.data_dir.display(),
            "non-default data dir; skipping /var/run/docker.sock self-setup"
        );
    }

    // The `/etc/hosts` ArcBox alias is host-global like the docker socket:
    // only the daemon on its profile's canonical data dir installs it. It
    // exists so the ~/ArcBox NFS mount can use `ArcBox:/` as its source
    // (Finder shows the source host name); daemons without it simply mount
    // from `127.0.0.1:/`.
    let hosts_task = (ctx.mount_nfs && ctx.layout.data_dir == default_data_dir)
        .then_some(self_setup::HostsAlias);

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
        let mut tasks: Vec<&dyn self_setup::SetupTask> = Vec::new();
        if let Some(dns) = &dns_task {
            tasks.push(dns);
        }
        if let Some(socket) = &socket_task {
            tasks.push(socket);
        }
        if let Some(hosts) = &hosts_task {
            tasks.push(hosts);
        }
        for t in &cli_tasks {
            tasks.push(t.as_ref());
        }
        if tasks.is_empty() {
            // Nothing to configure — don't launchd-activate the helper
            // just to hang up (the common case for harness daemons).
            return;
        }
        self_setup::run(&tasks).await;
        if let Some(dns) = &dns_task {
            setup_state_self.set_dns_installed(dns.is_satisfied());
        }
        if let Some(socket) = &socket_task {
            setup_state_self.set_docker_socket_linked(socket.is_satisfied());
        }
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

#[cfg(target_os = "macos")]
#[derive(Debug, PartialEq, Eq)]
enum ColdStartRoutePlan {
    #[cfg(feature = "vmnet")]
    VmnetBridge(String),
    #[cfg(not(feature = "vmnet"))]
    BridgeMac(String),
}

#[cfg(all(target_os = "macos", feature = "vmnet"))]
fn cold_start_route_plan(
    vmnet_bridge: Option<String>,
    _bridge_mac: Option<String>,
) -> Option<ColdStartRoutePlan> {
    vmnet_bridge.map(ColdStartRoutePlan::VmnetBridge)
}

#[cfg(all(target_os = "macos", not(feature = "vmnet")))]
fn cold_start_route_plan(
    _vmnet_bridge: Option<String>,
    bridge_mac: Option<String>,
) -> Option<ColdStartRoutePlan> {
    bridge_mac.map(ColdStartRoutePlan::BridgeMac)
}

#[cfg(all(target_os = "macos", feature = "vmnet"))]
fn spawn_vmnet_route_reconcile(setup_state: Arc<arcbox_api::SetupState>, bridge: String) {
    drop(tokio::spawn(async move {
        match arcbox_core::route_reconciler::ensure_route_for_bridge(&bridge).await {
            Ok(()) => setup_state.set_route_installed(true),
            Err(e) => {
                tracing::warn!(error = %e, "failed to install container route on cold start (vmnet)");
            }
        }
    }));
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
/// Reports nothing about VM liveness: `services::vm_running_loop` owns
/// `SetupStatus.vm_running` and follows the lifecycle across restarts, which
/// a one-shot observation made here could not.
async fn recover_container_networking(runtime: &Arc<Runtime>) {
    use arcbox_docker::guest_query;
    use arcbox_docker::proxy::{GuestHttpClient, VsockConnector};

    let client = GuestHttpClient::new(Arc::new(VsockConnector::new(Arc::clone(runtime))));
    let running = match guest_query::list_running_container_ids(&client).await {
        Ok(ids) => ids,
        Err(e) => {
            tracing::debug!("Failed to list containers for networking recovery: {}", e);
            return;
        }
    };

    let mut recovered_dns = 0u32;
    let mut recovered_ports = 0u32;
    for id in &running {
        let Some(inspect_body) = guest_query::inspect_container(&client, id).await else {
            continue;
        };

        // Re-register the name alias so lifecycle calls by name resolve
        // without a guest round-trip (mirrors handler-side registration).
        if let Some(name) = arcbox_docker::handlers::extract_container_name(&inspect_body) {
            runtime.register_container_alias(&name, id).await;
        }

        if let Some((aliases, ip)) =
            arcbox_docker::handlers::extract_container_dns_info(&inspect_body)
        {
            runtime.register_dns(id, &aliases, ip).await;
            recovered_dns += 1;
        }

        let bindings = arcbox_docker::port_bindings::parse_port_bindings(&inspect_body);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(target_os = "macos", feature = "vmnet"))]
    #[test]
    fn cold_start_route_plan_uses_vmnet_bridge() {
        let plan = cold_start_route_plan(Some("bridge100".to_string()), None);

        assert_eq!(
            plan,
            Some(ColdStartRoutePlan::VmnetBridge("bridge100".to_string()))
        );
    }

    #[cfg(all(target_os = "macos", feature = "vmnet"))]
    #[test]
    fn cold_start_route_plan_skips_when_vmnet_bridge_is_unknown() {
        let plan = cold_start_route_plan(None, Some("fe:b2:14:4d:a4:64".to_string()));

        assert_eq!(plan, None);
    }

    #[cfg(all(target_os = "macos", not(feature = "vmnet")))]
    #[test]
    fn cold_start_route_plan_uses_bridge_mac_without_vmnet() {
        let plan = cold_start_route_plan(Some("bridge100".to_string()), Some("mac".to_string()));

        assert_eq!(plan, Some(ColdStartRoutePlan::BridgeMac("mac".to_string())));
    }
}
