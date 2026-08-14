//! Post-startup recovery: re-establish networking for surviving containers
//! and reconcile host routes.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
#[cfg(target_os = "macos")]
use arcbox_constants::container_network::ContainerNetwork;
use arcbox_constants::paths::HostLayout;
use arcbox_core::Runtime;
use tracing::info;

use crate::context::DaemonContext;
use crate::self_setup;
use crate::self_setup::SetupTask as _;

/// Runs recovery and host setup tasks.
///
/// - Recovers DNS and port forwarding for containers that survived a daemon restart
/// - Re-installs the container subnet route (cold-start reconcile)
/// - Installs DNS resolver and Docker socket via helper
///
/// An explicitly requested DNS resolver is startup-critical. Canonical
/// production setup and all other host integrations remain best-effort.
pub async fn run(ctx: &DaemonContext, runtime: &Arc<Runtime>, dns_port: u16) -> Result<()> {
    let linux_vm = runtime.config().vm.autostart;
    if linux_vm {
        recover_container_networking(runtime).await;
    }

    // Cold-start route reconcile (non-blocking). This is load-bearing after
    // app updates or daemon restarts where the VM survives but the host route
    // may have been removed or stolen by another network service.
    #[cfg(target_os = "macos")]
    if linux_vm {
        use arcbox_core::DEFAULT_MACHINE_NAME;
        #[cfg(feature = "vmnet")]
        use arcbox_core::bridge_discovery::MachineBridgeExt as _;
        #[cfg(feature = "vmnet")]
        let vmnet_bridge = runtime
            .machine_manager()
            .vmnet_bridge_name(DEFAULT_MACHINE_NAME);
        #[cfg(not(feature = "vmnet"))]
        let vmnet_bridge = None;
        let bridge_mac = runtime.machine_manager().bridge_mac(DEFAULT_MACHINE_NAME);
        match cold_start_route_plan(vmnet_bridge, bridge_mac) {
            #[cfg(feature = "vmnet")]
            Some(ColdStartRoutePlan::VmnetBridge(bridge)) => spawn_vmnet_route_reconcile(
                Arc::clone(&ctx.setup_state),
                bridge,
                runtime.config().container.cidr,
            ),
            Some(ColdStartRoutePlan::BridgeMac(mac)) => spawn_bridge_mac_route_reconcile(
                Arc::clone(&ctx.setup_state),
                mac,
                runtime.config().container.cidr,
            ),
            None => {}
        }
    }

    // Best-effort self-setup (non-blocking).
    //
    let default_data_dir = HostLayout::resolve_for_profile_from_env(ctx.profile, None).data_dir;

    // Host resolver files are a privileged global mutation. Canonical
    // production DNS is implicit; any isolated domain requires the launch
    // contract to authorize it explicitly rather than inferring ownership
    // from caller-controlled text.
    let owns_dns = owns_dns_resolver(
        ctx.profile,
        ctx.install_dns_resolver,
        &ctx.dns_domain,
        &ctx.layout.data_dir,
        &default_data_dir,
    );
    if ctx.install_dns_resolver {
        let dns = self_setup::DnsResolver {
            domain: ctx.dns_domain.clone(),
            port: dns_port,
        };
        self_setup::run_required(&dns)
            .await
            .context("explicit DNS resolver setup failed")?;
        ctx.setup_state.set_dns_installed(true);
    }
    let dns_task = (owns_dns && !ctx.install_dns_resolver).then(|| self_setup::DnsResolver {
        domain: ctx.dns_domain.clone(),
        port: dns_port,
    });
    if !owns_dns {
        tracing::debug!(
            domain = ctx.dns_domain,
            data_dir = %ctx.layout.data_dir.display(),
            "non-canonical DNS owner; skipping /etc/resolver self-setup"
        );
    }
    // The `/var/run/docker.sock` symlink belongs to the production daemon
    // running its canonical data dir: the link target embeds the
    // data dir, so a daemon on an overridden one (an e2e harness daemon on
    // a temp dir, an ad-hoc dev run) would re-point the host-global Docker
    // socket at a path that dies with it. `ARCBOX_DATA_DIR` counts as
    // canonical — it relocates the machine-wide installation, not one
    // daemon instance; the installer persists it into the launchd plist's
    // EnvironmentVariables so a relocated install still satisfies this
    // check (its plist also passes the same path as `--data-dir`).
    let owns_global_host_setup =
        owns_implicit_host_setup(ctx.profile, &ctx.layout.data_dir, &default_data_dir);
    let socket_task = (linux_vm && owns_global_host_setup).then(|| self_setup::DockerSocket {
        target: ctx.layout.docker_socket.clone(),
    });
    if socket_task.is_none() {
        tracing::debug!(
            data_dir = %ctx.layout.data_dir.display(),
            "non-default data dir; skipping /var/run/docker.sock self-setup"
        );
    }

    // The `/etc/hosts` ArcBox alias is host-global like the docker socket:
    // only the production daemon on its canonical data dir installs it. It
    // exists so the ~/ArcBox NFS mount can use `ArcBox:/` as its source
    // (Finder shows the source host name); daemons without it simply mount
    // from `127.0.0.1:/`.
    let hosts_task =
        (linux_vm && ctx.mount_nfs && owns_global_host_setup).then_some(self_setup::HostsAlias);

    // Create /usr/local/bin/ symlinks for Docker CLI tools if running from
    // bundle with docker integration enabled.
    let cli_tasks: Vec<Box<dyn self_setup::SetupTask>> = if linux_vm && ctx.docker_integration {
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
    if linux_vm && ctx.docker_integration {
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
    Ok(())
}

fn owns_dns_resolver(
    profile: arcbox_constants::paths::ArcboxProfile,
    explicitly_enabled: bool,
    domain: &str,
    data_dir: &Path,
    canonical_data_dir: &Path,
) -> bool {
    explicitly_enabled
        || (profile == arcbox_constants::paths::ArcboxProfile::Production
            && domain == crate::startup::DEFAULT_DNS_DOMAIN
            && data_dir == canonical_data_dir)
}

fn owns_implicit_host_setup(
    profile: arcbox_constants::paths::ArcboxProfile,
    data_dir: &Path,
    canonical_data_dir: &Path,
) -> bool {
    profile == arcbox_constants::paths::ArcboxProfile::Production && data_dir == canonical_data_dir
}

#[cfg(target_os = "macos")]
#[derive(Debug, PartialEq, Eq)]
enum ColdStartRoutePlan {
    #[cfg(feature = "vmnet")]
    VmnetBridge(String),
    BridgeMac(String),
}

#[cfg(target_os = "macos")]
fn cold_start_route_plan(
    vmnet_bridge: Option<String>,
    bridge_mac: Option<String>,
) -> Option<ColdStartRoutePlan> {
    #[cfg(feature = "vmnet")]
    if let Some(bridge) = vmnet_bridge {
        return Some(ColdStartRoutePlan::VmnetBridge(bridge));
    }
    #[cfg(not(feature = "vmnet"))]
    let _ = vmnet_bridge;
    bridge_mac.map(ColdStartRoutePlan::BridgeMac)
}

#[cfg(all(target_os = "macos", feature = "vmnet"))]
fn spawn_vmnet_route_reconcile(
    setup_state: Arc<arcbox_api::SetupState>,
    bridge: String,
    container_network: ContainerNetwork,
) {
    drop(tokio::spawn(async move {
        match arcbox_core::route_reconciler::ensure_route_for_bridge_with_network(
            &bridge,
            container_network,
        )
        .await
        {
            Ok(()) => setup_state.set_route_installed(true),
            Err(e) => {
                tracing::warn!(error = %e, "failed to install container route on cold start (vmnet)");
            }
        }
    }));
}

#[cfg(target_os = "macos")]
fn spawn_bridge_mac_route_reconcile(
    setup_state: Arc<arcbox_api::SetupState>,
    mac: String,
    container_network: ContainerNetwork,
) {
    drop(tokio::spawn(async move {
        match arcbox_core::route_reconciler::ensure_route_with_retry_for_network(
            &mac,
            container_network,
        )
        .await
        {
            Ok(()) => setup_state.set_route_installed(true),
            Err(e) => {
                tracing::warn!(error = %e, "failed to install container route on cold start");
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

    #[test]
    fn dns_resolver_owner_isolated_by_domain_or_canonical_data_dir() {
        let canonical = Path::new("/canonical");

        assert!(owns_dns_resolver(
            arcbox_constants::paths::ArcboxProfile::Production,
            false,
            crate::startup::DEFAULT_DNS_DOMAIN,
            canonical,
            canonical
        ));
        assert!(!owns_dns_resolver(
            arcbox_constants::paths::ArcboxProfile::Production,
            false,
            crate::startup::DEFAULT_DNS_DOMAIN,
            Path::new("/isolated-test"),
            canonical
        ));
        assert!(!owns_dns_resolver(
            arcbox_constants::paths::ArcboxProfile::Production,
            false,
            "ad-hoc.dev.arcbox.local",
            Path::new("/isolated-test"),
            canonical
        ));
        assert!(owns_dns_resolver(
            arcbox_constants::paths::ArcboxProfile::Development,
            true,
            "dev-id.dev.arcbox.local",
            Path::new("/isolated-dev"),
            canonical
        ));
        assert!(!owns_dns_resolver(
            arcbox_constants::paths::ArcboxProfile::Development,
            false,
            crate::startup::DEFAULT_DNS_DOMAIN,
            canonical,
            canonical
        ));
    }

    #[test]
    fn implicit_host_setup_belongs_only_to_canonical_production() {
        let canonical = Path::new("/canonical");

        assert!(owns_implicit_host_setup(
            arcbox_constants::paths::ArcboxProfile::Production,
            canonical,
            canonical,
        ));
        assert!(!owns_implicit_host_setup(
            arcbox_constants::paths::ArcboxProfile::Production,
            Path::new("/isolated"),
            canonical,
        ));
        assert!(!owns_implicit_host_setup(
            arcbox_constants::paths::ArcboxProfile::Development,
            canonical,
            canonical,
        ));
    }

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
    fn cold_start_route_plan_falls_back_to_bridge_mac() {
        let plan = cold_start_route_plan(None, Some("fe:b2:14:4d:a4:64".to_string()));

        assert_eq!(
            plan,
            Some(ColdStartRoutePlan::BridgeMac(
                "fe:b2:14:4d:a4:64".to_string()
            ))
        );
    }

    #[cfg(all(target_os = "macos", not(feature = "vmnet")))]
    #[test]
    fn cold_start_route_plan_uses_bridge_mac_without_vmnet() {
        let plan = cold_start_route_plan(Some("bridge100".to_string()), Some("mac".to_string()));

        assert_eq!(plan, Some(ColdStartRoutePlan::BridgeMac("mac".to_string())));
    }
}
