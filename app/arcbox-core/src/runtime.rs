//! `ArcBox` runtime.

mod assets;
mod kubeconfig;

#[cfg(test)]
mod tests;

use crate::config::Config;
use crate::container_backend::{DynContainerBackend, create_backend};
use crate::error::{CoreError, Result};
use crate::event::EventBus;
use crate::machine::{MachineManager, MachineState};
use crate::migration::MigrationManager;
use crate::vm::VmManager;
use crate::vm_lifecycle::{DEFAULT_MACHINE_NAME, VmLifecycleConfig, VmLifecycleManager};
use arcbox_net::NetworkManager;
#[cfg(target_os = "macos")]
use arcbox_net::darwin::inbound_relay::{InboundListenerManager, InboundProtocol};
#[cfg(not(target_os = "macos"))]
use arcbox_net::port_forward::{PortForwardRule, PortForwarder};
use arcbox_protocol::agent::{
    KubernetesDeleteResponse, KubernetesKubeconfigResponse, KubernetesStartResponse,
    KubernetesStatusResponse, KubernetesStopResponse, ServiceStatus,
};
use assets::ensure_guest_binaries;
use kubeconfig::{KUBERNETES_HOST_ENDPOINT, rewrite_kubeconfig_server};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
#[cfg(not(target_os = "macos"))]
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock as TokioRwLock;

/// Default guest VM IP address in NAT network (used by PortForwarder fallback).
#[cfg(not(target_os = "macos"))]
const DEFAULT_GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 64, 2);

/// Inbound port-forwarding rules per container.
///
/// Maps the canonical container ID to the machine that holds the rules and
/// the list of `(host_ip, host_port, protocol)` tuples registered on that
/// machine. The machine name is needed so teardown reaches the right
/// inbound listener when both utility VMs are active concurrently.
#[cfg(target_os = "macos")]
type InboundRulesMap =
    Arc<TokioRwLock<HashMap<String, (String, Vec<(Ipv4Addr, u16, InboundProtocol)>)>>>;
/// Per-machine inbound listener managers, keyed by machine name.
#[cfg(target_os = "macos")]
type InboundListenerMap = Arc<TokioRwLock<HashMap<String, InboundListenerManager>>>;

pub struct Runtime {
    /// Configuration.
    config: Config,
    /// Event bus.
    event_bus: EventBus,
    /// VM manager.
    vm_manager: Arc<VmManager>,
    /// Machine manager.
    machine_manager: Arc<MachineManager>,
    /// Lifecycle manager for the single System VM. amd64 runs inside it via the
    /// active backend's translator (VZ→Rosetta, HV→FEX) rather than on a
    /// separate VM.
    vm_lifecycle: Arc<VmLifecycleManager>,
    /// Container backend that drives ensure-ready / dockerd plumbing for the
    /// System VM.
    container_backend: DynContainerBackend,
    /// Network manager.
    network_manager: Arc<NetworkManager>,
    /// Host-side runtime migration manager.
    migration_manager: Arc<MigrationManager>,
    /// Inbound listener managers keyed by machine name, for port
    /// forwarding via L2 frame injection (macOS). Each utility VM owns its
    /// own bridge interface and therefore its own listener.
    #[cfg(target_os = "macos")]
    inbound_listeners: InboundListenerMap,
    /// Tracks which inbound rules belong to each container, plus the
    /// machine those rules live on, so teardown reaches the right
    /// listener (macOS).
    #[cfg(target_os = "macos")]
    inbound_rules: InboundRulesMap,
    /// Port forwarders for each container (non-macOS fallback).
    #[cfg(not(target_os = "macos"))]
    port_forwarders: Arc<TokioRwLock<HashMap<String, PortForwarder>>>,
    /// Tracks DNS registrations: canonical container ID → hostnames.
    dns_entries: Arc<TokioRwLock<HashMap<String, Vec<String>>>>,
}

impl Runtime {
    /// Creates a new runtime with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub fn new(config: Config) -> Result<Self> {
        let mut vm_lifecycle_config = VmLifecycleConfig::default();

        // Propagate config.vm defaults into VM lifecycle so every entry
        // point (daemon, machine, diagnose, API server) uses the same values.
        vm_lifecycle_config.default_vm.cpus = config.vm.effective_cpus();
        vm_lifecycle_config.default_vm.memory_mb = config.vm.memory_mb;
        if let Some(ref kernel) = config.vm.kernel_path {
            vm_lifecycle_config.default_vm.kernel = Some(kernel.clone());
        }

        Self::with_vm_lifecycle_config(config, vm_lifecycle_config)
    }

    /// Creates a new runtime with custom VM lifecycle configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub fn with_vm_lifecycle_config(
        config: Config,
        mut vm_lifecycle_config: VmLifecycleConfig,
    ) -> Result<Self> {
        vm_lifecycle_config.guest_docker_vsock_port =
            Some(config.container.guest_docker_vsock_port);

        let event_bus = EventBus::new();
        let snapshot_dir = config.data_dir.join("snapshots");
        let vm_manager = Arc::new(VmManager::new(snapshot_dir));
        let network_manager = Arc::new(NetworkManager::new(arcbox_net::NetConfig::default()));

        // Share the host-side DNS hosts table with the VMM so both
        // the host DnsService and the VMM-side datapath DnsForwarder
        // resolve from the same table.
        let shared_dns_table = Some(network_manager.local_hosts_table());

        let machine_manager = Arc::new(MachineManager::new(
            Arc::clone(&vm_manager),
            config.data_dir.clone(),
            shared_dns_table,
        ));

        // Build the single System VM. The daemon runs one utility VM (default
        // backend VZ); amd64 workloads run inside it via the active backend's
        // x86 translator (VZ→Rosetta, HV→FEX), so there is no separate VM.
        let system_lifecycle = Arc::new(VmLifecycleManager::new(
            machine_manager.clone(),
            event_bus.clone(),
            config.data_dir.clone(),
            vm_lifecycle_config,
        )?);
        let system_backend = create_backend(
            &config.container,
            Arc::clone(&system_lifecycle),
            Arc::clone(&machine_manager),
            DEFAULT_MACHINE_NAME,
        );

        let migration_manager = Arc::new(MigrationManager::new(config.docker.socket_path.clone()));

        Ok(Self {
            config,
            event_bus,
            vm_manager,
            machine_manager,
            vm_lifecycle: system_lifecycle,
            container_backend: system_backend,
            network_manager,
            migration_manager,
            #[cfg(target_os = "macos")]
            inbound_listeners: Arc::new(TokioRwLock::new(HashMap::new())),
            #[cfg(target_os = "macos")]
            inbound_rules: Arc::new(TokioRwLock::new(HashMap::new())),
            #[cfg(not(target_os = "macos"))]
            port_forwarders: Arc::new(TokioRwLock::new(HashMap::new())),
            dns_entries: Arc::new(TokioRwLock::new(HashMap::new())),
        })
    }

    /// Returns the configuration.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Returns the event bus.
    #[must_use]
    pub const fn event_bus(&self) -> &EventBus {
        &self.event_bus
    }

    /// Returns the VM manager.
    #[must_use]
    pub const fn vm_manager(&self) -> &Arc<VmManager> {
        &self.vm_manager
    }

    /// Returns the machine manager.
    #[must_use]
    pub const fn machine_manager(&self) -> &Arc<MachineManager> {
        &self.machine_manager
    }

    /// Returns the network manager.
    #[must_use]
    pub const fn network_manager(&self) -> &Arc<NetworkManager> {
        &self.network_manager
    }

    /// Returns the host-side migration manager.
    #[must_use]
    pub const fn migration_manager(&self) -> &Arc<MigrationManager> {
        &self.migration_manager
    }

    /// Returns the VM lifecycle manager.
    #[must_use]
    pub const fn vm_lifecycle(&self) -> &Arc<VmLifecycleManager> {
        &self.vm_lifecycle
    }

    /// Returns the selected container backend implementation.
    #[must_use]
    pub fn container_backend(&self) -> &DynContainerBackend {
        &self.container_backend
    }

    /// Returns the configured guest Docker vsock port.
    #[must_use]
    pub const fn guest_docker_vsock_port(&self) -> u32 {
        self.config.container.guest_docker_vsock_port
    }

    /// Ensures the default VM is running and ready for container operations.
    ///
    /// This is the main entry point for automatic VM lifecycle management.
    /// If the VM is not running, it will be created and started automatically.
    /// This method is idempotent and safe to call multiple times.
    ///
    /// Returns the vsock CID of the running VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be started or becomes unhealthy.
    pub async fn ensure_vm_ready(&self) -> Result<u32> {
        self.container_backend.ensure_ready().await
    }

    /// Ensures the System VM is running and ready, returning its guest CID.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying VM cannot be started or becomes
    /// unhealthy.
    pub async fn ensure_system_vm_ready(&self) -> Result<u32> {
        self.container_backend.ensure_ready().await
    }

    /// Returns the System VM's current hypervisor backend.
    #[must_use]
    pub fn system_vm_backend(&self) -> arcbox_vmm::VmBackend {
        self.vm_lifecycle.backend()
    }

    /// Switches the System VM's hypervisor backend (HV <-> VZ) and restarts the
    /// VM so it takes effect.
    ///
    /// No-op when the backend is unchanged. Otherwise the System VM is
    /// gracefully stopped, its backend updated **in place** — the machine
    /// record, SSH keys and the persistent dockerd data image are all kept,
    /// only the lazily-built `Vmm` is rebuilt — and rebooted on the new backend.
    /// The choice is persisted in the machine config so it survives daemon
    /// restarts. Running containers are stopped by the restart.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot be applied or the VM cannot be
    /// restarted on the new backend.
    pub async fn switch_system_vm_backend(&self, backend: arcbox_vmm::VmBackend) -> Result<()> {
        let lifecycle = &self.vm_lifecycle;
        if lifecycle.backend() == backend {
            return Ok(());
        }

        let machine_name = lifecycle.machine_name().to_string();
        tracing::info!(
            from = lifecycle.backend().as_str(),
            to = backend.as_str(),
            "switching System VM backend; restarting the System VM"
        );

        // Stop first — if the VM genuinely cannot be stopped, abort rather than
        // record a new backend the still-running VM is not actually on.
        // `shutdown` is a no-op when not running and force-stops as a fallback,
        // so it only errors when the VM truly could not be torn down.
        lifecycle.shutdown().await?;
        // Apply the backend in place. The persisted machine (if it exists yet)
        // is updated so the choice survives a restart; the lifecycle's own
        // backend governs the next create on first boot.
        if self.machine_manager.exists(&machine_name) {
            self.machine_manager.set_backend(&machine_name, backend)?;
        }
        lifecycle.set_backend(backend);
        lifecycle.ensure_ready().await?;

        tracing::info!(backend = backend.as_str(), "System VM backend switched");
        Ok(())
    }

    /// Returns the default machine name used for automatic VM lifecycle.
    #[must_use]
    pub const fn default_machine_name(&self) -> &'static str {
        DEFAULT_MACHINE_NAME
    }

    /// Returns the guest dockerd vsock port for the System VM.
    #[must_use]
    pub const fn system_vm_docker_vsock_port(&self) -> u32 {
        self.config.container.guest_docker_vsock_port
    }

    /// Returns whether the System VM can run `linux/amd64` workloads.
    ///
    /// The x86_64 translator follows the System VM's backend:
    /// - **VZ** uses Apple Rosetta — requires Apple Silicon *and* the System
    ///   VM actually wiring the Rosetta share (`default_vm.rosetta`). If Rosetta
    ///   is disabled the VZ guest has no x86 `binfmt` handler.
    /// - **HV** uses FEX, which requires the interpreter provisioned as a
    ///   runtime binary at `<data_dir>/runtime/bin/FEX` (the same `runtime/bin`
    ///   set as `dockerd`/`containerd`, surfaced to the guest over the `arcbox`
    ///   VirtioFS share). The guest rootfs init registers the `binfmt_misc`
    ///   handler iff that binary is present.
    ///
    /// Fail-closed (ABX-375): when the active backend's translator is
    /// unavailable, amd64 requests must return a clear error rather than
    /// silently falling back.
    #[must_use]
    pub fn amd64_runtime_supported(&self) -> bool {
        match self.system_vm_backend() {
            arcbox_vmm::VmBackend::Vz => {
                cfg!(all(target_os = "macos", target_arch = "aarch64"))
                    && self.vm_lifecycle.config().default_vm.rosetta
            }
            arcbox_vmm::VmBackend::Hv => self
                .config
                .data_dir
                .join("runtime")
                .join("bin")
                .join("FEX")
                .is_file(),
        }
    }

    /// Gets an agent client for a machine.
    ///
    /// On macOS, this uses the hypervisor layer to establish vsock connections.
    /// On Linux, it creates a direct `AF_VSOCK` connection.
    ///
    /// # Errors
    /// Returns an error if the machine is not found or connection fails.
    #[cfg(target_os = "macos")]
    pub fn get_agent(&self, machine_name: &str) -> Result<crate::agent_client::AgentClient> {
        self.machine_manager.connect_agent(machine_name)
    }

    /// Gets an agent client for a machine (Linux version).
    #[cfg(target_os = "linux")]
    pub fn get_agent(&self, machine_name: &str) -> Result<crate::agent_client::AgentClient> {
        self.machine_manager.connect_agent(machine_name)
    }

    /// Connects to a machine's guest service via vsock port.
    ///
    /// # Errors
    ///
    /// Returns an error if the machine is not running or the vsock port is not reachable.
    pub fn connect_vsock_port(&self, machine_name: &str, port: u32) -> Result<std::os::fd::RawFd> {
        self.machine_manager.connect_vsock_port(machine_name, port)
    }

    /// Starts the native Kubernetes cluster in the default VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be started or the guest request fails.
    pub async fn start_kubernetes(&self) -> Result<KubernetesStartResponse> {
        self.vm_lifecycle.ensure_ready().await?;
        let mut agent = self.get_agent(DEFAULT_MACHINE_NAME)?;
        let response = agent.start_kubernetes().await?;
        self.vm_lifecycle
            .set_kubernetes_hold(response.running)
            .await;
        Ok(response)
    }

    /// Stops the native Kubernetes cluster in the default VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the guest request fails.
    pub async fn stop_kubernetes(&self) -> Result<KubernetesStopResponse> {
        if !self.vm_lifecycle.is_running().await {
            self.vm_lifecycle.set_kubernetes_hold(false).await;
            return Ok(KubernetesStopResponse {
                stopped: true,
                detail: "k3s already stopped".to_string(),
            });
        }

        let mut agent = self.get_agent(DEFAULT_MACHINE_NAME)?;
        let response = agent.stop_kubernetes().await?;
        self.vm_lifecycle.set_kubernetes_hold(false).await;
        Ok(response)
    }

    /// Deletes the native Kubernetes cluster state in the default VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the guest request fails.
    pub async fn delete_kubernetes(&self) -> Result<KubernetesDeleteResponse> {
        self.vm_lifecycle.ensure_ready().await?;
        let mut agent = self.get_agent(DEFAULT_MACHINE_NAME)?;
        let response = agent.delete_kubernetes().await?;
        self.vm_lifecycle.set_kubernetes_hold(false).await;
        Ok(response)
    }

    /// Returns Kubernetes cluster status for the default VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the guest request fails while the VM is running.
    pub async fn kubernetes_status(&self) -> Result<KubernetesStatusResponse> {
        if !self.vm_lifecycle.is_running().await {
            return Ok(KubernetesStatusResponse {
                running: false,
                api_ready: false,
                endpoint: KUBERNETES_HOST_ENDPOINT.to_string(),
                detail: "default vm not running".to_string(),
                services: vec![ServiceStatus {
                    name: "k3s".to_string(),
                    status: "not_ready".to_string(),
                    detail: "default vm not running".to_string(),
                }],
            });
        }

        let mut agent = self.get_agent(DEFAULT_MACHINE_NAME)?;
        let response = agent.get_kubernetes_status().await?;
        self.vm_lifecycle
            .set_kubernetes_hold(response.running)
            .await;
        Ok(response)
    }

    /// Returns the ArcBox-managed kubeconfig payload for the default VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the guest request fails.
    pub async fn kubernetes_kubeconfig(&self) -> Result<KubernetesKubeconfigResponse> {
        self.vm_lifecycle.ensure_ready().await?;
        let mut agent = self.get_agent(DEFAULT_MACHINE_NAME)?;
        let mut response = agent.get_kubeconfig().await?;
        response.kubeconfig = rewrite_kubeconfig_server(&response.kubeconfig);
        response.context_name = "arcbox".to_string();
        response.endpoint = KUBERNETES_HOST_ENDPOINT.to_string();
        Ok(response)
    }

    /// Initializes the runtime and eagerly starts the default VM.
    ///
    /// Validates that all guest binaries (agent + runtime) are present and
    /// executable before starting the VM. This is a boot-blocking check.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails or guest binaries are missing.
    pub async fn init(&self) -> Result<()> {
        // Create data directories.
        tokio::fs::create_dir_all(&self.config.data_dir).await?;
        tokio::fs::create_dir_all(self.config.data_dir.join("vms")).await?;
        tokio::fs::create_dir_all(self.config.data_dir.join("machines")).await?;

        // Download every runtime binary in the boot manifest if not cached:
        // dockerd, containerd, containerd-shim-runc-v2, runc, docker-init, k3s,
        // and the optional FEX x86_64 interpreter for linux/amd64. ArcBox's
        // FEX carries a small patch making it binfmt-only — no FEXServer.
        let runtime_bin_dir = self.config.data_dir.join("runtime/bin");
        tokio::fs::create_dir_all(&runtime_bin_dir).await?;
        self.vm_lifecycle
            .boot_assets()
            .prepare_binaries(&runtime_bin_dir, None)
            .await?;

        // Validate all guest binaries are present and executable (boot-blocking).
        ensure_guest_binaries(&self.config.data_dir)?;

        self.ensure_vm_ready().await?;

        tracing::info!(
            backend = self.container_backend.name(),
            "ArcBox runtime initialized"
        );
        Ok(())
    }

    /// Shuts down the runtime gracefully.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown fails.
    pub async fn shutdown(&self) -> Result<()> {
        tracing::info!("ArcBox runtime shutting down");

        // 1. Stop all active host port forwarders.
        self.stop_port_forwarding_all().await;

        // 2. Shutdown VM lifecycle manager (gracefully stops default VM).
        if let Err(e) = self.vm_lifecycle.shutdown().await {
            tracing::warn!("Failed to shutdown VM lifecycle manager: {}", e);
        }

        // 3. Stop any remaining machines/VMs (non-default VMs).
        let machines = self.machine_manager.list();
        for machine in machines {
            if machine.state == MachineState::Running && machine.name != DEFAULT_MACHINE_NAME {
                tracing::debug!("Stopping machine {}", machine.name);
                let stopped_gracefully = match self.machine_manager.graceful_stop(
                    &machine.name,
                    Duration::from_secs(arcbox_constants::timeouts::HOST_SHUTDOWN_TIMEOUT_SECS),
                ) {
                    Ok(true) => true,
                    Ok(false) => {
                        tracing::warn!(
                            "Graceful stop timed out for machine {}, forcing stop",
                            machine.name
                        );
                        false
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Graceful stop failed for machine {}: {}, forcing stop",
                            machine.name,
                            e
                        );
                        false
                    }
                };

                let stop_result = if stopped_gracefully {
                    Ok(())
                } else {
                    self.machine_manager.stop(&machine.name)
                };

                match stop_result {
                    Ok(()) => {
                        tracing::info!("Machine {} stopped", machine.name);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to stop machine {}: {}", machine.name, e);
                    }
                }
            }
        }

        // 4. Stop network manager.
        if let Err(e) = self.network_manager.stop() {
            tracing::warn!("Failed to stop network manager: {}", e);
        }

        tracing::info!("ArcBox runtime shutdown complete");
        Ok(())
    }

    /// Shuts down the runtime forcefully.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown fails.
    pub async fn shutdown_force(&self) -> Result<()> {
        tracing::warn!("ArcBox runtime force shutdown");

        self.stop_port_forwarding_all().await;

        // Force stop VM lifecycle manager (immediate VM termination).
        if let Err(e) = self.vm_lifecycle.force_stop().await {
            tracing::warn!("Failed to force stop VM lifecycle manager: {}", e);
        }

        // Force stop any remaining machines (non-default VMs).
        let machines = self.machine_manager.list();
        for machine in machines {
            if machine.state == MachineState::Running && machine.name != DEFAULT_MACHINE_NAME {
                tracing::debug!("Force stopping machine {}", machine.name);
                let _ = self.machine_manager.stop(&machine.name);
            }
        }

        // Stop network manager.
        let _ = self.network_manager.stop();

        tracing::info!("ArcBox runtime force shutdown complete");
        Ok(())
    }

    /// Gets the VM's IP address from machine state, falling back to the
    /// default NAT IP when the address is not known yet.
    #[cfg(not(target_os = "macos"))]
    fn guest_ip_for_machine(&self, machine_name: &str) -> Ipv4Addr {
        let ip = self
            .machine_manager
            .get(machine_name)
            .and_then(|m| m.ip_address)
            .and_then(|raw| raw.parse::<Ipv4Addr>().ok());

        if let Some(ip) = ip {
            return ip;
        }

        tracing::debug!(
            machine = machine_name,
            fallback = %DEFAULT_GUEST_IP,
            "machine IP unavailable, using default guest NAT IP"
        );
        DEFAULT_GUEST_IP
    }

    /// Starts port forwarding for a container from externally-provided bindings.
    ///
    /// On macOS, uses `InboundListenerManager` with L2 frame injection through
    /// the socketpair. On other platforms, falls back to `PortForwarder`.
    ///
    /// # Errors
    ///
    /// Returns an error if listeners fail to bind.
    pub async fn start_port_forwarding_for(
        &self,
        machine_name: &str,
        container_id: &str,
        bindings: &[(String, u16, u16, String)], // (host_ip, host_port, container_port, protocol)
    ) -> Result<()> {
        if bindings.is_empty() {
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            self.start_port_forwarding_macos(machine_name, container_id, bindings)
                .await
        }

        #[cfg(not(target_os = "macos"))]
        {
            self.start_port_forwarding_fallback(machine_name, container_id, bindings)
                .await
        }
    }

    /// macOS: add inbound rules via the machine's `InboundListenerManager`.
    #[cfg(target_os = "macos")]
    async fn start_port_forwarding_macos(
        &self,
        machine_name: &str,
        container_id: &str,
        bindings: &[(String, u16, u16, String)],
    ) -> Result<()> {
        // Keep the cached manager for this machine fresh across VM restarts.
        {
            let mut guard = self.inbound_listeners.write().await;
            if let Some(manager) = self
                .machine_manager
                .take_inbound_listener_manager(machine_name)
            {
                guard.insert(machine_name.to_string(), manager);
            }
            if !guard.contains_key(machine_name) {
                return Err(CoreError::Machine(format!(
                    "inbound listener manager not available for machine '{machine_name}'",
                )));
            }
        }

        // Remove previously tracked listeners for this container before
        // applying new bindings, so stale ports do not leak. Cleanup
        // routes to the machine the rules were originally bound to —
        // which may differ from the requested machine if the container
        // was previously on a different role.
        let previous = {
            let mut rules = self.inbound_rules.write().await;
            rules.remove(container_id)
        };
        if let Some((prev_machine, previous_rules)) = previous {
            let mut guard = self.inbound_listeners.write().await;
            if let Some(manager) = guard.get_mut(&prev_machine) {
                for (host_ip, host_port, proto) in previous_rules {
                    manager.remove_rule(host_ip, host_port, proto);
                }
            }
        }

        let mut added_rules = Vec::new();

        for (host_ip_str, host_port, container_port, protocol) in bindings {
            let proto = match protocol.to_lowercase().as_str() {
                "udp" => InboundProtocol::Udp,
                _ => InboundProtocol::Tcp,
            };

            let host_ip: Ipv4Addr = if host_ip_str.is_empty() || host_ip_str == "0.0.0.0" {
                Ipv4Addr::UNSPECIFIED
            } else if let Ok(ip) = host_ip_str.parse() {
                ip
            } else {
                tracing::warn!(
                    "Skipping inbound rule: invalid HostIp '{}' for port {}:{}",
                    host_ip_str,
                    host_port,
                    protocol,
                );
                continue;
            };

            let mut guard = self.inbound_listeners.write().await;
            let manager = guard
                .get_mut(machine_name)
                .expect("checked machine_name presence above");
            if let Err(e) = manager
                .add_rule(host_ip, *host_port, *container_port, proto)
                .await
            {
                tracing::warn!(
                    "Failed to bind inbound port {}:{}:{}: {}",
                    host_ip_str,
                    host_port,
                    protocol,
                    e,
                );
                continue;
            }
            added_rules.push((host_ip, *host_port, proto));
        }

        if !added_rules.is_empty() {
            let mut rules = self.inbound_rules.write().await;
            rules.insert(
                container_id.to_string(),
                (machine_name.to_string(), added_rules),
            );
        }

        Ok(())
    }

    /// Non-macOS fallback: use PortForwarder with direct TCP/UDP connect.
    #[cfg(not(target_os = "macos"))]
    async fn start_port_forwarding_fallback(
        &self,
        machine_name: &str,
        container_id: &str,
        bindings: &[(String, u16, u16, String)],
    ) -> Result<()> {
        let guest_ip = self.guest_ip_for_machine(machine_name);
        let mut forwarder = PortForwarder::new();

        for (host_ip_str, host_port, container_port, protocol) in bindings {
            let host_ip: Ipv4Addr = if host_ip_str.is_empty() || host_ip_str == "0.0.0.0" {
                Ipv4Addr::UNSPECIFIED
            } else {
                match host_ip_str.parse() {
                    Ok(ip) => ip,
                    Err(_) => {
                        tracing::warn!(
                            "Skipping port forward rule: invalid HostIp '{}' for port {}:{}",
                            host_ip_str,
                            host_port,
                            protocol,
                        );
                        continue;
                    }
                }
            };

            let host_addr = SocketAddr::V4(SocketAddrV4::new(host_ip, *host_port));
            let guest_addr = SocketAddr::V4(SocketAddrV4::new(guest_ip, *container_port));

            let rule = match protocol.to_lowercase().as_str() {
                "udp" => PortForwardRule::udp(host_addr, guest_addr),
                _ => PortForwardRule::tcp(host_addr, guest_addr),
            };

            forwarder.add_rule(rule);
            tracing::info!(
                "Port forward rule added: {} -> {} ({})",
                host_addr,
                guest_addr,
                protocol
            );
        }

        forwarder.start().await?;

        let mut forwarders = self.port_forwarders.write().await;
        forwarders.insert(container_id.to_string(), forwarder);

        Ok(())
    }

    /// Stops port forwarding for a container by its string ID.
    pub async fn stop_port_forwarding_by_id(&self, container_id: &str) {
        #[cfg(target_os = "macos")]
        {
            let rules = {
                let mut guard = self.inbound_rules.write().await;
                guard.remove(container_id)
            };
            if let Some((machine_name, rules)) = rules {
                let mut guard = self.inbound_listeners.write().await;
                if let Some(manager) = guard.get_mut(&machine_name) {
                    for (host_ip, host_port, proto) in rules {
                        manager.remove_rule(host_ip, host_port, proto);
                    }
                }
                tracing::debug!(
                    machine = %machine_name,
                    container_id,
                    "Stopped port forwarding for container",
                );
            }
        }

        #[cfg(not(target_os = "macos"))]
        {
            let mut forwarders = self.port_forwarders.write().await;
            if let Some(mut forwarder) = forwarders.remove(container_id) {
                forwarder.stop().await;
                tracing::debug!("Stopped port forwarding for container {}", container_id);
            }
        }
    }

    /// Registers DNS entries for a container.
    ///
    /// Maps each hostname in `hostnames` to `ip` so the host can reach the
    /// container by name. Also tracks the `container_id → hostnames` mapping
    /// for cleanup.
    pub async fn register_dns(&self, container_id: &str, hostnames: &[String], ip: IpAddr) {
        for hostname in hostnames {
            self.network_manager.register_dns(hostname, ip);
        }
        self.dns_entries
            .write()
            .await
            .insert(container_id.to_string(), hostnames.to_vec());
        tracing::info!(
            container_id,
            ?hostnames,
            %ip,
            "DNS entries registered",
        );
    }

    /// Removes DNS entries for a container by its canonical ID.
    ///
    /// Shared aliases (e.g. compose service-level names used by multiple
    /// replicas) are only removed from the network manager when no other
    /// container still references them.
    pub async fn deregister_dns_by_id(&self, container_id: &str) {
        let mut entries = self.dns_entries.write().await;
        let Some(hostnames) = entries.remove(container_id) else {
            return;
        };

        // Only deregister hostnames not referenced by any remaining container.
        for hostname in &hostnames {
            let still_in_use = entries.values().any(|names| names.contains(hostname));
            if !still_in_use {
                self.network_manager.deregister_dns(hostname);
            }
        }
        drop(entries);
        tracing::info!(container_id, ?hostnames, "DNS entries deregistered");
    }

    /// Stops all active port forwarders across every machine.
    pub async fn stop_port_forwarding_all(&self) {
        #[cfg(target_os = "macos")]
        {
            let mut guard = self.inbound_listeners.write().await;
            // Drain so the next start_port_forwarding_macos() call fetches
            // fresh managers from the VMM (with live cmd_tx values).
            for (_, mut manager) in guard.drain() {
                manager.stop_all();
            }
            self.inbound_rules.write().await.clear();
        }

        #[cfg(not(target_os = "macos"))]
        {
            let mut forwarders = self.port_forwarders.write().await;
            for (container_id, mut forwarder) in forwarders.drain() {
                tracing::debug!("Stopping port forwarder for container {}", container_id);
                forwarder.stop().await;
            }
        }
    }
}
