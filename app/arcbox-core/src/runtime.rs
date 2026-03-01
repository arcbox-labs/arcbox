//! ArcBox runtime.

use crate::boot_assets::BootAssetManifest;
use crate::config::Config;
use crate::container_backend::{DynContainerBackend, create_backend};
use crate::error::{CoreError, Result};
use crate::event::EventBus;
use crate::machine::{MachineManager, MachineState};
use crate::vm::VmManager;
use crate::vm_lifecycle::{DEFAULT_MACHINE_NAME, VmLifecycleConfig, VmLifecycleManager};
use arcbox_net::NetworkManager;
#[cfg(target_os = "macos")]
use arcbox_net::darwin::inbound_relay::{InboundListenerManager, InboundProtocol};
#[cfg(not(target_os = "macos"))]
use arcbox_net::port_forward::{PortForwardRule, PortForwarder};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
#[cfg(not(target_os = "macos"))]
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Component, Path};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock as TokioRwLock;

/// Default guest VM IP address in NAT network (used by PortForwarder fallback).
#[cfg(not(target_os = "macos"))]
const DEFAULT_GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 64, 2);
const REQUIRED_RUNTIME_ASSETS: [&str; 3] = ["dockerd", "containerd", "youki"];

fn validate_bundled_runtime_manifest(manifest: &BootAssetManifest, cache_dir: &Path) -> Result<()> {
    let mut missing = Vec::new();

    for required in REQUIRED_RUNTIME_ASSETS {
        let Some(entry) = manifest
            .runtime_assets
            .iter()
            .find(|item| item.name == required)
        else {
            missing.push(required);
            continue;
        };

        if entry
            .version
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
        {
            return Err(CoreError::config(format!(
                "boot manifest runtime asset '{}' is missing version",
                required
            )));
        }
        let expected_sha = entry.sha256.as_deref().unwrap_or_default().trim();
        if expected_sha.is_empty() {
            return Err(CoreError::config(format!(
                "boot manifest runtime asset '{}' is missing sha256",
                required
            )));
        }

        let relative_path = Path::new(&entry.path);
        if relative_path.as_os_str().is_empty()
            || relative_path.is_absolute()
            || relative_path
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(CoreError::config(format!(
                "boot manifest runtime asset '{}' has invalid path '{}'",
                required, entry.path
            )));
        }

        let runtime_path = cache_dir.join(relative_path);
        if !runtime_path.exists() {
            return Err(CoreError::config(format!(
                "boot runtime asset '{}' missing from cache: {}",
                required,
                runtime_path.display()
            )));
        }

        let bytes = std::fs::read(&runtime_path).map_err(|e| {
            CoreError::config(format!(
                "failed to read boot runtime asset '{}': {}",
                runtime_path.display(),
                e
            ))
        })?;
        let actual_sha = format!("{:x}", Sha256::digest(&bytes));
        if actual_sha != expected_sha {
            return Err(CoreError::config(format!(
                "boot runtime asset '{}' checksum mismatch: expected {}, got {}",
                required, expected_sha, actual_sha
            )));
        }
    }

    if !missing.is_empty() {
        return Err(CoreError::config(format!(
            "boot manifest runtime_assets missing required entries: {}",
            missing.join(", ")
        )));
    }

    Ok(())
}

pub struct Runtime {
    /// Configuration.
    config: Config,
    /// Event bus.
    event_bus: EventBus,
    /// VM manager.
    vm_manager: Arc<VmManager>,
    /// Machine manager.
    machine_manager: Arc<MachineManager>,
    /// VM lifecycle manager (automatic VM management).
    vm_lifecycle: Arc<VmLifecycleManager>,
    /// Selected container backend implementation.
    container_backend: DynContainerBackend,
    /// Network manager.
    network_manager: Arc<NetworkManager>,
    /// Inbound listener manager for port forwarding via L2 frame injection (macOS).
    #[cfg(target_os = "macos")]
    inbound_listener: Arc<TokioRwLock<Option<InboundListenerManager>>>,
    /// Tracks which inbound rules belong to each container for cleanup (macOS).
    #[cfg(target_os = "macos")]
    inbound_rules: Arc<TokioRwLock<HashMap<String, Vec<(u16, InboundProtocol)>>>>,
    /// Port forwarders for each container (non-macOS fallback).
    #[cfg(not(target_os = "macos"))]
    port_forwarders: Arc<TokioRwLock<HashMap<String, PortForwarder>>>,
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
        vm_lifecycle_config.default_vm.cpus = config.vm.cpus;
        vm_lifecycle_config.default_vm.memory_mb = config.vm.memory_mb;
        if let Some(ref kernel) = config.vm.kernel_path {
            vm_lifecycle_config.default_vm.kernel = Some(kernel.clone());
        }
        if let Some(ref initrd) = config.vm.initrd_path {
            vm_lifecycle_config.default_vm.initramfs = Some(initrd.clone());
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
        let vm_manager = Arc::new(VmManager::new());
        let machine_manager = Arc::new(MachineManager::new(
            VmManager::new(),
            config.data_dir.clone(),
        ));

        // Create VM lifecycle manager with the machine manager.
        let vm_lifecycle = Arc::new(VmLifecycleManager::new(
            machine_manager.clone(),
            event_bus.clone(),
            config.data_dir.clone(),
            vm_lifecycle_config,
        ));
        let container_backend = create_backend(
            &config.container,
            Arc::clone(&vm_lifecycle),
            Arc::clone(&machine_manager),
            DEFAULT_MACHINE_NAME,
        );

        let network_manager = Arc::new(NetworkManager::new(arcbox_net::NetConfig::default()));

        Ok(Self {
            config,
            event_bus,
            vm_manager,
            machine_manager,
            vm_lifecycle,
            container_backend,
            network_manager,
            #[cfg(target_os = "macos")]
            inbound_listener: Arc::new(TokioRwLock::new(None)),
            #[cfg(target_os = "macos")]
            inbound_rules: Arc::new(TokioRwLock::new(HashMap::new())),
            #[cfg(not(target_os = "macos"))]
            port_forwarders: Arc::new(TokioRwLock::new(HashMap::new())),
        })
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Returns the event bus.
    #[must_use]
    pub fn event_bus(&self) -> &EventBus {
        &self.event_bus
    }

    /// Returns the VM manager.
    #[must_use]
    pub fn vm_manager(&self) -> &Arc<VmManager> {
        &self.vm_manager
    }

    /// Returns the machine manager.
    #[must_use]
    pub fn machine_manager(&self) -> &Arc<MachineManager> {
        &self.machine_manager
    }

    /// Returns the network manager.
    #[must_use]
    pub fn network_manager(&self) -> &Arc<NetworkManager> {
        &self.network_manager
    }

    /// Returns the VM lifecycle manager.
    #[must_use]
    pub fn vm_lifecycle(&self) -> &Arc<VmLifecycleManager> {
        &self.vm_lifecycle
    }

    /// Returns the selected container backend implementation.
    #[must_use]
    pub fn container_backend(&self) -> &DynContainerBackend {
        &self.container_backend
    }

    /// Returns the configured guest Docker vsock port.
    #[must_use]
    pub fn guest_docker_vsock_port(&self) -> u32 {
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

    /// Returns the default machine name used for automatic VM lifecycle.
    #[must_use]
    pub fn default_machine_name(&self) -> &'static str {
        DEFAULT_MACHINE_NAME
    }

    /// Gets an agent client for a machine.
    ///
    /// On macOS, this uses the hypervisor layer to establish vsock connections.
    /// On Linux, it creates a direct AF_VSOCK connection.
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

    /// Initializes the runtime and eagerly starts the default VM.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub async fn init(&self) -> Result<()> {
        // Create data directories.
        tokio::fs::create_dir_all(&self.config.data_dir).await?;
        tokio::fs::create_dir_all(self.config.data_dir.join("vms")).await?;
        tokio::fs::create_dir_all(self.config.data_dir.join("machines")).await?;

        if matches!(
            self.config.container.provision,
            crate::config::ContainerProvisionMode::BundledAssets
        ) {
            let boot_assets = self.vm_lifecycle.boot_assets().get_assets().await?;
            let manifest = boot_assets.manifest.as_ref().ok_or_else(|| {
                CoreError::config(
                    "guest_docker + bundled_assets requires boot manifest with runtime_assets",
                )
            })?;
            let cache_dir = self.vm_lifecycle.boot_assets().config().version_cache_dir();
            validate_bundled_runtime_manifest(manifest, &cache_dir)?;

            // Ensure the guest agent binary is available at data_dir/bin/arcbox-agent.
            // The OpenRC service inside the guest mounts data_dir via VirtioFS at /arcbox
            // and expects the agent at /arcbox/bin/arcbox-agent.
            let agent_src = cache_dir.join("bin/arcbox-agent");
            if agent_src.exists() {
                let bin_dir = self.config.data_dir.join("bin");
                tokio::fs::create_dir_all(&bin_dir).await?;
                let agent_dst = bin_dir.join("arcbox-agent");
                let needs_copy = if agent_dst.exists() {
                    let src_meta = tokio::fs::metadata(&agent_src).await?;
                    let dst_meta = tokio::fs::metadata(&agent_dst).await?;
                    src_meta.len() != dst_meta.len()
                } else {
                    true
                };
                if needs_copy {
                    tokio::fs::copy(&agent_src, &agent_dst).await.map_err(|e| {
                        CoreError::config(format!(
                            "failed to install agent binary to {}: {}",
                            agent_dst.display(),
                            e
                        ))
                    })?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        tokio::fs::set_permissions(
                            &agent_dst,
                            std::fs::Permissions::from_mode(0o755),
                        )
                        .await?;
                    }
                    tracing::info!(
                        src = %agent_src.display(),
                        dst = %agent_dst.display(),
                        "Installed guest agent binary"
                    );
                }
            }
        }

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
                let stopped_gracefully = match self
                    .machine_manager
                    .graceful_stop(&machine.name, Duration::from_secs(30))
                {
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

    /// macOS: add inbound rules via InboundListenerManager.
    #[cfg(target_os = "macos")]
    async fn start_port_forwarding_macos(
        &self,
        machine_name: &str,
        container_id: &str,
        bindings: &[(String, u16, u16, String)],
    ) -> Result<()> {
        // Lazily take the manager from the VMM on first use.
        {
            let mut guard = self.inbound_listener.write().await;
            if guard.is_none() {
                *guard = self
                    .machine_manager
                    .take_inbound_listener_manager(machine_name);
                if guard.is_none() {
                    return Err(CoreError::Machine(
                        "inbound listener manager not available".to_string(),
                    ));
                }
            }
        }

        let mut added_rules = Vec::new();

        for (_host_ip_str, host_port, container_port, protocol) in bindings {
            let proto = match protocol.to_lowercase().as_str() {
                "udp" => InboundProtocol::Udp,
                _ => InboundProtocol::Tcp,
            };

            let mut guard = self.inbound_listener.write().await;
            let manager = guard.as_mut().expect("checked above");
            if let Err(e) = manager.add_rule(*host_port, *container_port, proto).await {
                tracing::warn!(
                    "Failed to bind inbound port {}:{}: {}",
                    host_port,
                    protocol,
                    e,
                );
                continue;
            }
            added_rules.push((*host_port, proto));
        }

        if !added_rules.is_empty() {
            let mut rules = self.inbound_rules.write().await;
            rules.insert(container_id.to_string(), added_rules);
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
                host_ip_str.parse().unwrap_or(Ipv4Addr::UNSPECIFIED)
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
            if let Some(rules) = rules {
                let mut guard = self.inbound_listener.write().await;
                if let Some(manager) = guard.as_mut() {
                    for (host_port, proto) in rules {
                        manager.remove_rule(host_port, proto);
                    }
                }
                tracing::debug!("Stopped port forwarding for container {}", container_id);
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

    /// Stops all active port forwarders.
    pub async fn stop_port_forwarding_all(&self) {
        #[cfg(target_os = "macos")]
        {
            let mut guard = self.inbound_listener.write().await;
            if let Some(manager) = guard.as_mut() {
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

#[cfg(test)]
mod tests {
    use super::{Runtime, validate_bundled_runtime_manifest};
    use crate::boot_assets::{BootAssetManifest, RuntimeAssetManifestEntry};
    use crate::config::Config;
    use bytes::Bytes;
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;

    fn runtime_entry(name: &str, content: &[u8]) -> RuntimeAssetManifestEntry {
        RuntimeAssetManifestEntry {
            name: name.to_string(),
            path: format!("runtime/bin/{}", name),
            version: Some("test-version".to_string()),
            sha256: Some(format!("{:x}", Sha256::digest(content))),
        }
    }

    #[test]
    fn test_validate_bundled_runtime_manifest_ok() {
        let temp_dir = tempfile::tempdir().unwrap();
        let runtime_dir = temp_dir.path().join("runtime/bin");
        std::fs::create_dir_all(&runtime_dir).unwrap();

        std::fs::write(runtime_dir.join("dockerd"), b"dockerd-bin").unwrap();
        std::fs::write(runtime_dir.join("containerd"), b"containerd-bin").unwrap();
        std::fs::write(runtime_dir.join("youki"), b"youki-bin").unwrap();

        let manifest = BootAssetManifest {
            schema_version: 1,
            asset_version: "test".to_string(),
            arch: "arm64".to_string(),
            kernel_commit: None,
            agent_commit: None,
            built_at: None,
            kernel_cmdline: None,
            runtime_assets: vec![
                runtime_entry("dockerd", b"dockerd-bin"),
                runtime_entry("containerd", b"containerd-bin"),
                runtime_entry("youki", b"youki-bin"),
            ],
            rootfs_squashfs_sha256: None,
            modloop_sha256: None,
            rootfs_ext4_sha256: None,
        };

        let result = validate_bundled_runtime_manifest(&manifest, temp_dir.path());
        assert!(
            result.is_ok(),
            "expected validation success, got {:?}",
            result
        );
    }

    #[test]
    fn test_validate_bundled_runtime_manifest_missing_entry() {
        let temp_dir = tempfile::tempdir().unwrap();
        let runtime_dir = temp_dir.path().join("runtime/bin");
        std::fs::create_dir_all(&runtime_dir).unwrap();
        std::fs::write(runtime_dir.join("dockerd"), b"dockerd-bin").unwrap();
        std::fs::write(runtime_dir.join("containerd"), b"containerd-bin").unwrap();

        let manifest = BootAssetManifest {
            schema_version: 1,
            asset_version: "test".to_string(),
            arch: "arm64".to_string(),
            kernel_commit: None,
            agent_commit: None,
            built_at: None,
            kernel_cmdline: None,
            runtime_assets: vec![
                runtime_entry("dockerd", b"dockerd-bin"),
                runtime_entry("containerd", b"containerd-bin"),
            ],
            rootfs_squashfs_sha256: None,
            modloop_sha256: None,
            rootfs_ext4_sha256: None,
        };

        let err = validate_bundled_runtime_manifest(&manifest, temp_dir.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("runtime_assets missing required entries"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_runtime_new_propagates_config_vm_defaults() {
        let temp_dir = tempfile::tempdir().unwrap();

        let mut config = Config::default();
        config.data_dir = temp_dir.path().to_path_buf();
        config.vm.cpus = 6;
        config.vm.memory_mb = 3072;
        config.vm.kernel_path = Some(PathBuf::from("/tmp/arcbox-test-kernel"));
        config.vm.initrd_path = Some(PathBuf::from("/tmp/arcbox-test-initramfs"));

        let runtime = Runtime::new(config).expect("runtime init should succeed");
        let default_vm = runtime.vm_lifecycle().default_vm_config();

        assert_eq!(default_vm.cpus, 6);
        assert_eq!(default_vm.memory_mb, 3072);
        assert_eq!(
            default_vm.kernel,
            Some(PathBuf::from("/tmp/arcbox-test-kernel"))
        );
        assert_eq!(
            default_vm.initramfs,
            Some(PathBuf::from("/tmp/arcbox-test-initramfs"))
        );
    }
}
