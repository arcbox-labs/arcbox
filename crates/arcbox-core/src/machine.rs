//! Linux machine management.
//!
//! A "machine" is a high-level abstraction over a VM that provides
//! a Linux environment for running containers.

use crate::boot_assets::BootAssetProvider;
use crate::disk::{self, DiskManager};
use crate::distro::DistroRegistry;
use crate::error::{CoreError, Result};
use crate::persistence::MachinePersistence;
use crate::ssh::SshKeyManager;
use crate::vm::{BlockDeviceConfig, SharedDirConfig, VmConfig, VmId, VmManager};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

/// Machine state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineState {
    /// Machine created but not started.
    Created,
    /// Machine is starting.
    Starting,
    /// Machine is running.
    Running,
    /// Machine is stopping.
    Stopping,
    /// Machine is stopped.
    Stopped,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot_assets::{BootAssetConfig, BootAssetProvider};
    use tempfile::tempdir;

    /// Creates a test MachineManager with a mock boot asset provider.
    fn test_machine_manager(data_dir: &std::path::Path) -> MachineManager {
        let vm_manager = VmManager::new();
        let boot_config = BootAssetConfig::with_cache_dir(data_dir.join("boot"));
        let boot_assets = Arc::new(BootAssetProvider::with_config(boot_config));
        MachineManager::new(vm_manager, data_dir.to_path_buf(), boot_assets)
    }

    #[tokio::test]
    async fn test_assign_cid_propagates_to_vm_config() {
        let temp_dir = tempdir().unwrap();
        let machine_manager = test_machine_manager(temp_dir.path());

        let name = machine_manager
            .create(MachineConfig {
                name: "cid-test".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();

        let (vm_id, cid) = machine_manager.assign_cid_for_start(&name).unwrap();
        assert_eq!(cid, 3);
        assert_eq!(
            machine_manager.vm_manager.guest_cid_for_test(&vm_id),
            Some(cid)
        );
    }

    #[test]
    fn test_register_mock_machine() {
        let temp_dir = tempdir().unwrap();
        let machine_manager = test_machine_manager(temp_dir.path());

        // Register a mock machine.
        machine_manager
            .register_mock_machine("test-mock", 42)
            .unwrap();

        // Verify the machine exists.
        let machine = machine_manager
            .get("test-mock")
            .expect("machine should exist");
        assert_eq!(machine.name, "test-mock");
        assert_eq!(machine.cid, Some(42));
        assert_eq!(machine.state, MachineState::Running);
    }

    #[test]
    fn test_register_mock_machine_idempotent() {
        let temp_dir = tempdir().unwrap();
        let machine_manager = test_machine_manager(temp_dir.path());

        // Register twice should succeed (idempotent).
        machine_manager
            .register_mock_machine("test-idempotent", 10)
            .unwrap();
        machine_manager
            .register_mock_machine("test-idempotent", 20)
            .unwrap();

        // Should still have the first CID (not overwritten).
        let machine = machine_manager.get("test-idempotent").unwrap();
        assert_eq!(machine.cid, Some(10));
    }
}

/// Machine information.
#[derive(Debug, Clone)]
pub struct MachineInfo {
    /// Machine name.
    pub name: String,
    /// Machine state.
    pub state: MachineState,
    /// Underlying VM ID.
    pub vm_id: VmId,
    /// vsock CID for agent communication (assigned when VM starts).
    pub cid: Option<u32>,
    /// Number of CPUs.
    pub cpus: u32,
    /// Memory in MB.
    pub memory_mb: u64,
    /// Disk size in GB.
    pub disk_gb: u64,
    /// Kernel path.
    pub kernel: Option<String>,
    /// Initrd path.
    pub initrd: Option<String>,
    /// Kernel command line.
    pub cmdline: Option<String>,
    /// Distribution name (e.g., "alpine", "ubuntu").
    pub distro: Option<String>,
    /// Distribution version (e.g., "3.21", "24.04").
    pub distro_version: Option<String>,
    /// Path to the disk image.
    pub disk_path: Option<PathBuf>,
    /// Path to the SSH private key.
    pub ssh_key_path: Option<PathBuf>,
    /// Guest IP address (reported by machine init via vsock).
    pub ip_address: Option<String>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

/// Machine configuration.
#[derive(Debug, Clone)]
pub struct MachineConfig {
    /// Machine name.
    pub name: String,
    /// Number of CPUs.
    pub cpus: u32,
    /// Memory in MB.
    pub memory_mb: u64,
    /// Disk size in GB.
    pub disk_gb: u64,
    /// Kernel path.
    pub kernel: Option<String>,
    /// Initrd path.
    pub initrd: Option<String>,
    /// Kernel command line.
    pub cmdline: Option<String>,
    /// Distribution name (e.g., "alpine", "ubuntu").
    pub distro: Option<String>,
    /// Distribution version (e.g., "3.21", "24.04").
    pub distro_version: Option<String>,
}

impl Default for MachineConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            cpus: 4,
            memory_mb: 4096,
            disk_gb: 50,
            kernel: None,
            initrd: None,
            cmdline: None,
            distro: None,
            distro_version: None,
        }
    }
}

/// Machine manager.
pub struct MachineManager {
    machines: RwLock<HashMap<String, MachineInfo>>,
    vm_manager: VmManager,
    persistence: MachinePersistence,
    /// Data directory for VirtioFS sharing.
    data_dir: PathBuf,
    /// Machine-specific directory (data_dir/machines/).
    machines_dir: PathBuf,
    /// Distribution rootfs registry.
    distro_registry: DistroRegistry,
    /// Boot asset provider (shared kernel/initramfs).
    boot_assets: Arc<BootAssetProvider>,
}

impl MachineManager {
    /// Creates a new machine manager.
    #[must_use]
    pub fn new(
        vm_manager: VmManager,
        data_dir: PathBuf,
        boot_assets: Arc<BootAssetProvider>,
    ) -> Self {
        let machines_dir = data_dir.join("machines");
        let persistence = MachinePersistence::new(&machines_dir);
        let distro_registry = DistroRegistry::new(data_dir.join("distros"));

        // Create the default shared directory config for VirtioFS
        // This shares the data_dir (e.g., ~/.arcbox) with the guest at /arcbox
        let shared_dirs = vec![SharedDirConfig::new(
            data_dir.to_string_lossy().to_string(),
            "arcbox",
        )];

        // Load persisted machines
        let mut machines = HashMap::new();
        for persisted in persistence.load_all() {
            // Reconstruct VmConfig from persisted data.
            // For machine VMs with a distro, set up block devices and shared dirs.
            let (block_devices, vm_shared_dirs) = if persisted.distro.is_some() {
                let machine_dir = machines_dir.join(&persisted.name);
                let mut bds = Vec::new();
                if let Some(ref dp) = persisted.disk_path {
                    bds.push(BlockDeviceConfig {
                        path: dp.clone(),
                        read_only: false,
                    });
                }
                let sds = vec![SharedDirConfig::new(
                    machine_dir.to_string_lossy().to_string(),
                    "arcbox-setup",
                )];
                (bds, sds)
            } else {
                (Vec::new(), shared_dirs.clone())
            };

            let vm_config = VmConfig {
                cpus: persisted.cpus,
                memory_mb: persisted.memory_mb,
                kernel: persisted.kernel.clone(),
                initrd: persisted.initrd.clone(),
                cmdline: persisted.cmdline.clone(),
                shared_dirs: vm_shared_dirs,
                block_devices,
                ..Default::default()
            };

            // Try to create the underlying VM
            if let Ok(vm_id) = vm_manager.create(vm_config) {
                let info = MachineInfo {
                    name: persisted.name.clone(),
                    state: persisted.state.into(),
                    vm_id,
                    cid: None, // Will be assigned when VM starts
                    cpus: persisted.cpus,
                    memory_mb: persisted.memory_mb,
                    disk_gb: persisted.disk_gb,
                    kernel: persisted.kernel.clone(),
                    initrd: persisted.initrd.clone(),
                    cmdline: persisted.cmdline,
                    distro: persisted.distro.clone(),
                    distro_version: persisted.distro_version.clone(),
                    disk_path: persisted.disk_path.clone().map(PathBuf::from),
                    ssh_key_path: persisted.ssh_key_path.clone().map(PathBuf::from),
                    ip_address: persisted.ip_address.clone(),
                    created_at: persisted.created_at,
                };
                machines.insert(persisted.name, info);
            }
        }

        tracing::info!("Loaded {} persisted machines", machines.len());

        Self {
            machines: RwLock::new(machines),
            vm_manager,
            persistence,
            data_dir,
            machines_dir,
            distro_registry,
            boot_assets,
        }
    }

    /// Creates a new machine.
    ///
    /// When `config.distro` is set, this performs full machine VM setup:
    /// 1. Resolve and download distro rootfs tarball
    /// 2. Generate SSH key pair
    /// 3. Create ext4 disk image
    /// 4. Write setup.json for first-boot provisioning
    /// 5. Configure block device + VirtioFS sharing
    ///
    /// When `config.distro` is None, creates a lightweight container VM
    /// (existing behavior).
    ///
    /// # Errors
    ///
    /// Returns an error if the machine cannot be created.
    pub async fn create(&self, config: MachineConfig) -> Result<String> {
        // Check if machine already exists
        if self
            .machines
            .read()
            .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?
            .contains_key(&config.name)
        {
            return Err(CoreError::already_exists(config.name));
        }

        let machine_dir = self.machines_dir.join(&config.name);
        std::fs::create_dir_all(&machine_dir)?;

        // Set up machine based on whether distro is specified.
        let (disk_path, ssh_key_path, kernel, initrd, cmdline, block_devices, shared_dirs) =
            if let Some(ref distro_name) = config.distro {
                // Full machine VM with distro rootfs.
                self.setup_machine_vm(&config, &machine_dir, distro_name)
                    .await?
            } else {
                // Lightweight container VM (existing behavior).
                let mut shared_dirs = vec![SharedDirConfig::new(
                    self.data_dir.to_string_lossy().to_string(),
                    "arcbox",
                )];
                if let Some(home_dir) = dirs::home_dir() {
                    shared_dirs.push(SharedDirConfig::new(
                        home_dir.to_string_lossy().to_string(),
                        "home",
                    ));
                }
                (
                    None,
                    None,
                    config.kernel.clone(),
                    config.initrd.clone(),
                    config.cmdline.clone(),
                    Vec::new(),
                    shared_dirs,
                )
            };

        // Create underlying VM
        let vm_config = VmConfig {
            cpus: config.cpus,
            memory_mb: config.memory_mb,
            kernel,
            initrd,
            cmdline,
            shared_dirs,
            block_devices,
            ..Default::default()
        };
        let vm_id = self.vm_manager.create(vm_config)?;

        let info = MachineInfo {
            name: config.name.clone(),
            state: MachineState::Created,
            vm_id,
            cid: None,
            cpus: config.cpus,
            memory_mb: config.memory_mb,
            disk_gb: config.disk_gb,
            kernel: config.kernel,
            initrd: config.initrd,
            cmdline: config.cmdline,
            distro: config.distro,
            distro_version: config.distro_version,
            disk_path,
            ssh_key_path,
            ip_address: None,
            created_at: Utc::now(),
        };

        // Persist the machine config
        self.persistence.save(&info)?;

        self.machines
            .write()
            .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?
            .insert(config.name.clone(), info);

        Ok(config.name)
    }

    /// Sets up a full machine VM with distro rootfs, disk image, and SSH keys.
    async fn setup_machine_vm(
        &self,
        config: &MachineConfig,
        machine_dir: &std::path::Path,
        distro_name: &str,
    ) -> Result<(
        Option<PathBuf>,
        Option<PathBuf>,
        Option<String>,
        Option<String>,
        Option<String>,
        Vec<BlockDeviceConfig>,
        Vec<SharedDirConfig>,
    )> {
        // 1. Resolve distro info.
        let distro_info = self
            .distro_registry
            .resolve(distro_name, config.distro_version.as_deref())?;

        tracing::info!(
            "Setting up machine VM: distro={} {}, disk={}GB",
            distro_info.distro,
            distro_info.version,
            config.disk_gb
        );

        // 2. Download rootfs tarball (cached).
        let tarball_path = self.distro_registry.ensure_rootfs(&distro_info).await?;

        // 3. Generate SSH key pair.
        let (private_key_path, public_key) = SshKeyManager::generate(machine_dir).await?;

        // 4. Create ext4 disk image.
        let disk_path = machine_dir.join(disk::DISK_IMAGE_FILENAME);
        DiskManager::create_image(&disk_path, config.disk_gb).await?;

        // 5. Create setup.json for first-boot provisioning.
        let setup_data = serde_json::json!({
            "hostname": config.name,
            "ssh_pubkey": public_key,
            "distro": distro_name,
            "distro_version": distro_info.version,
        });
        std::fs::write(
            machine_dir.join("setup.json"),
            serde_json::to_string_pretty(&setup_data)
                .map_err(|e| CoreError::Machine(format!("Failed to serialize setup.json: {}", e)))?,
        )?;

        // 6. Symlink rootfs tarball into machine dir for VirtioFS access.
        let local_tarball = machine_dir.join("rootfs.tar.gz");
        if !local_tarball.exists() {
            #[cfg(unix)]
            std::os::unix::fs::symlink(&tarball_path, &local_tarball)?;
            #[cfg(not(unix))]
            std::fs::copy(&tarball_path, &local_tarball)?;
        }

        // 7. Get shared boot assets (kernel + initramfs).
        let assets = self.boot_assets.get_assets().await?;

        let kernel = Some(assets.kernel.to_string_lossy().to_string());
        let initrd = Some(assets.initramfs.to_string_lossy().to_string());
        let base_cmdline = assets
            .manifest
            .as_ref()
            .and_then(|m| m.kernel_cmdline.as_deref())
            .unwrap_or("console=hvc0 rdinit=/init quiet");
        let cmdline = Some(format!(
            "{} arcbox.mode=machine arcbox.setup_tag=arcbox-setup",
            base_cmdline
        ));

        // 8. Build block device and shared dir configs.
        let block_devices = vec![BlockDeviceConfig {
            path: disk_path.to_string_lossy().to_string(),
            read_only: false,
        }];

        let shared_dirs = vec![SharedDirConfig::new(
            machine_dir.to_string_lossy().to_string(),
            "arcbox-setup",
        )];

        Ok((
            Some(disk_path),
            Some(private_key_path),
            kernel,
            initrd,
            cmdline,
            block_devices,
            shared_dirs,
        ))
    }

    /// Starts a machine.
    ///
    /// For machine VMs with a distro, this also waits for the guest agent to
    /// become ready and discovers the guest IP address via vsock.
    ///
    /// # Errors
    ///
    /// Returns an error if the machine cannot be started.
    pub async fn start(&self, name: &str) -> Result<()> {
        let (vm_id, cid) = self.assign_cid_for_start(name)?;

        // Check if this is a distro-based machine VM.
        let is_machine_vm = self
            .machines
            .read()
            .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?
            .get(name)
            .and_then(|m| m.distro.as_ref())
            .is_some();

        // Start underlying VM
        self.vm_manager.start(&vm_id)?;

        // Update machine state
        {
            let mut machines = self
                .machines
                .write()
                .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?;

            if let Some(machine) = machines.get_mut(name) {
                machine.state = MachineState::Running;
                machine.cid = Some(cid);
                machine.ip_address = None;

                tracing::info!("Machine '{}' started with CID {}", name, cid);
            }
        }

        // Update persisted state
        let _ = self.persistence.update_state(name, MachineState::Running);
        let _ = self.persistence.update_ip(name, None);

        // For machine VMs, wait for agent readiness and discover IP.
        if is_machine_vm {
            self.wait_for_machine_ready(name).await.map_err(|e| {
                CoreError::Machine(format!(
                    "Machine '{}' started but readiness check failed: {}",
                    name, e
                ))
            })?;
        }

        Ok(())
    }

    /// Waits for the guest agent to become ready and discovers the IP address.
    ///
    /// Polls the agent via vsock with exponential backoff. Once the agent
    /// responds, queries SystemInfo to get the guest IP.
    async fn wait_for_machine_ready(&self, name: &str) -> Result<()> {
        const MAX_ATTEMPTS: u32 = 20;
        const INITIAL_DELAY_MS: u64 = 500;
        const MAX_DELAY_MS: u64 = 3000;

        tracing::info!("Waiting for machine '{}' agent to become ready...", name);

        let mut delay_ms = INITIAL_DELAY_MS;

        for attempt in 1..=MAX_ATTEMPTS {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;

            // Try to connect and ping.
            match self.connect_agent(name) {
                Ok(mut agent) => {
                    match agent.ping().await {
                        Ok(resp) => {
                            tracing::info!(
                                "Machine '{}' agent ready (version: {}, attempt {})",
                                name,
                                resp.version,
                                attempt
                            );

                            // Agent is up — query system info for IP.
                            match agent.get_system_info().await {
                                Ok(info) => {
                                    let selected_ip = info
                                        .ip_addresses
                                        .iter()
                                        .filter_map(|ip| ip.parse::<IpAddr>().ok())
                                        .filter(|ip| !ip.is_loopback())
                                        .max_by_key(|ip| usize::from(ip.is_ipv4()))
                                        .map(|ip| ip.to_string());

                                    if let Some(ip) = selected_ip {
                                        tracing::info!(
                                            "Machine '{}' IP: {}",
                                            name,
                                            ip
                                        );
                                        // Store IP in memory and persist.
                                        if let Ok(mut machines) = self.machines.write() {
                                            if let Some(machine) = machines.get_mut(name) {
                                                machine.ip_address = Some(ip.clone());
                                            }
                                        }
                                        let _ = self.persistence.update_ip(name, Some(&ip));
                                        return Ok(());
                                    } else {
                                        tracing::debug!(
                                            "Machine '{}' agent is up but no routable IP yet (attempt {})",
                                            name,
                                            attempt
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        "Machine '{}' agent ready but failed to get system info: {}",
                                        name,
                                        e
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::trace!(
                                "Machine '{}' ping attempt {} failed: {}",
                                name,
                                attempt,
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::trace!(
                        "Machine '{}' connect attempt {} failed: {}",
                        name,
                        attempt,
                        e
                    );
                }
            }

            // Exponential backoff with cap.
            delay_ms = (delay_ms * 3 / 2).min(MAX_DELAY_MS);
        }

        Err(CoreError::Machine(format!(
            "Machine '{}' agent did not report a routable IP within timeout",
            name
        )))
    }

    fn assign_cid_for_start(&self, name: &str) -> Result<(VmId, u32)> {
        let (vm_id, running_count) = {
            let machines = self
                .machines
                .read()
                .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?;

            let machine = machines
                .get(name)
                .ok_or_else(|| CoreError::not_found(name.to_string()))?;

            // Count running machines. CIDs 0, 1 are reserved, 2 is the host. We start from 3.
            let running_count = machines
                .values()
                .filter(|m| m.state == MachineState::Running && m.cid.is_some())
                .count() as u32;

            (machine.vm_id.clone(), running_count)
        };

        let cid = 3 + running_count;
        self.vm_manager.set_guest_cid(&vm_id, cid)?;

        Ok((vm_id, cid))
    }

    /// Returns a reference to the underlying VM manager.
    #[must_use]
    pub fn vm_manager(&self) -> &VmManager {
        &self.vm_manager
    }

    /// Gets the vsock CID for a running machine.
    #[must_use]
    pub fn get_cid(&self, name: &str) -> Option<u32> {
        self.machines.read().ok()?.get(name)?.cid
    }

    /// Connects to the agent on a running machine.
    ///
    /// Returns an `AgentClient` that can be used to communicate with the
    /// guest agent for container operations.
    ///
    /// # Errors
    /// Returns an error if the machine is not found, not running, or connection fails.
    #[cfg(target_os = "macos")]
    pub fn connect_agent(&self, name: &str) -> Result<crate::agent_client::AgentClient> {
        use crate::agent_client::{AGENT_PORT, AgentClient};

        let machines = self
            .machines
            .read()
            .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?;

        let machine = machines
            .get(name)
            .ok_or_else(|| CoreError::not_found(name.to_string()))?;

        if machine.state != MachineState::Running {
            return Err(CoreError::invalid_state(format!(
                "machine '{}' is not running",
                name
            )));
        }

        let cid = machine
            .cid
            .ok_or_else(|| CoreError::Machine("CID not assigned".to_string()))?;

        // Connect to the agent via vsock through the VM
        let fd = self.vm_manager.connect_vsock(&machine.vm_id, AGENT_PORT)?;

        AgentClient::from_fd(cid, fd)
    }

    /// Connects to the agent on a running machine (Linux).
    #[cfg(target_os = "linux")]
    pub fn connect_agent(&self, name: &str) -> Result<crate::agent_client::AgentClient> {
        use crate::agent_client::AgentClient;

        let machines = self
            .machines
            .read()
            .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?;

        let machine = machines
            .get(name)
            .ok_or_else(|| CoreError::not_found(name.to_string()))?;

        if machine.state != MachineState::Running {
            return Err(CoreError::invalid_state(format!(
                "machine '{}' is not running",
                name
            )));
        }

        let cid = machine
            .cid
            .ok_or_else(|| CoreError::Machine("CID not assigned".to_string()))?;

        // On Linux, AgentClient connects directly via AF_VSOCK
        Ok(AgentClient::new(cid))
    }

    /// Reads serial console output for a running machine (macOS only).
    #[cfg(target_os = "macos")]
    pub fn read_console_output(&self, name: &str) -> Result<String> {
        let machines = self
            .machines
            .read()
            .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?;

        let machine = machines
            .get(name)
            .ok_or_else(|| CoreError::not_found(name.to_string()))?;

        if machine.state != MachineState::Running {
            return Err(CoreError::invalid_state(format!(
                "machine '{}' is not running",
                name
            )));
        }

        self.vm_manager.read_console_output(&machine.vm_id)
    }

    /// Stops a machine.
    ///
    /// # Errors
    ///
    /// Returns an error if the machine cannot be stopped.
    pub fn stop(&self, name: &str) -> Result<()> {
        let mut machines = self
            .machines
            .write()
            .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?;

        let machine = machines
            .get_mut(name)
            .ok_or_else(|| CoreError::not_found(name.to_string()))?;

        // Stop underlying VM
        self.vm_manager.stop(&machine.vm_id)?;
        machine.state = MachineState::Stopped;

        // Update persisted state
        let _ = self.persistence.update_state(name, MachineState::Stopped);

        Ok(())
    }

    /// Gets machine information.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<MachineInfo> {
        self.machines.read().ok()?.get(name).cloned()
    }

    /// Lists all machines.
    #[must_use]
    pub fn list(&self) -> Vec<MachineInfo> {
        self.machines
            .read()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Removes a machine and all associated artifacts (disk, SSH keys, config).
    ///
    /// # Errors
    ///
    /// Returns an error if the machine cannot be removed.
    pub fn remove(&self, name: &str, force: bool) -> Result<()> {
        let mut machines = self
            .machines
            .write()
            .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?;

        let machine = machines
            .get(name)
            .ok_or_else(|| CoreError::not_found(name.to_string()))?;

        // Check if machine is running
        if machine.state == MachineState::Running && !force {
            return Err(CoreError::invalid_state(
                "cannot remove running machine (use --force)".to_string(),
            ));
        }

        // Stop if running and force is set
        if machine.state == MachineState::Running {
            let vm_id = machine.vm_id.clone();
            drop(machines); // Release lock before stopping
            self.vm_manager.stop(&vm_id)?;
            machines = self
                .machines
                .write()
                .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?;
        }

        // Get VM ID and disk path before removing from map.
        let (vm_id, disk_path) = {
            let m = machines
                .get(name)
                .ok_or_else(|| CoreError::not_found(name.to_string()))?;
            (m.vm_id.clone(), m.disk_path.clone())
        };

        // Remove from VM manager
        self.vm_manager.remove(&vm_id)?;

        // Clean up disk image.
        if let Some(ref dp) = disk_path {
            let _ = DiskManager::remove(dp);
        }

        // Remove from machines map
        machines.remove(name);

        // Remove persisted config (removes entire machine directory including SSH keys).
        let _ = self.persistence.remove(name);

        tracing::info!("Removed machine '{}'", name);
        Ok(())
    }

    /// Registers a mock machine for testing purposes.
    ///
    /// This method creates a machine entry without creating an actual VM.
    /// The machine will be in Running state with a mock CID.
    ///
    /// # Note
    /// This is intended for unit testing only and should not be used in production.
    pub fn register_mock_machine(&self, name: &str, cid: u32) -> Result<()> {
        let mut machines = self
            .machines
            .write()
            .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?;

        if machines.contains_key(name) {
            return Ok(()); // Already registered
        }

        let info = MachineInfo {
            name: name.to_string(),
            state: MachineState::Running,
            vm_id: VmId::new(), // Fake VM ID
            cid: Some(cid),
            cpus: 4,
            memory_mb: 4096,
            disk_gb: 50,
            kernel: None,
            initrd: None,
            cmdline: None,
            distro: None,
            distro_version: None,
            disk_path: None,
            ssh_key_path: None,
            ip_address: None,
            created_at: Utc::now(),
        };

        machines.insert(name.to_string(), info);
        tracing::debug!("Registered mock machine '{}' with CID {}", name, cid);
        Ok(())
    }
}
