//! Linux machine management.
//!
//! A "machine" is a high-level abstraction over a VM that provides
//! a Linux environment for running containers.

use crate::error::{CoreError, Result};
use crate::persistence::MachinePersistence;
use crate::vm::{SharedDirConfig, VmConfig, VmId, VmManager};
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
    use tempfile::tempdir;

    /// Creates a test MachineManager.
    fn test_machine_manager(data_dir: &std::path::Path) -> MachineManager {
        let vm_manager = VmManager::new();
        MachineManager::new(vm_manager, data_dir.to_path_buf())
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

    #[test]
    fn test_select_routable_ip_prefers_ipv4() {
        let ips = vec![
            "::1".to_string(),
            "fe80::1".to_string(),
            "2001:db8::10".to_string(),
            "192.168.64.2".to_string(),
        ];
        assert_eq!(select_routable_ip(&ips), Some("192.168.64.2".to_string()));
    }

    #[test]
    fn test_select_routable_ip_falls_back_to_global_ipv6() {
        let ips = vec![
            "::1".to_string(),
            "fe80::2".to_string(),
            "2001:db8::42".to_string(),
        ];
        assert_eq!(select_routable_ip(&ips), Some("2001:db8::42".to_string()));
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
    /// Block devices (for example, rootfs ext4 image).
    pub block_devices: Vec<crate::vm::BlockDeviceConfig>,
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
            block_devices: Vec::new(),
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
}

impl MachineManager {
    /// Creates a new machine manager.
    #[must_use]
    pub fn new(vm_manager: VmManager, data_dir: PathBuf) -> Self {
        let machines_dir = data_dir.join("machines");
        let persistence = MachinePersistence::new(&machines_dir);

        // Create the default shared directory config for VirtioFS.
        // "arcbox" shares the data_dir; "users" shares /Users for transparent paths.
        let mut shared_dirs = vec![SharedDirConfig::new(
            data_dir.to_string_lossy().to_string(),
            "arcbox",
        )];
        let users_dir = std::path::Path::new("/Users");
        if users_dir.is_dir() {
            shared_dirs.push(SharedDirConfig::new("/Users", "users"));
        } else if let Some(home_dir) = dirs::home_dir() {
            shared_dirs.push(SharedDirConfig::new(
                home_dir.to_string_lossy().to_string(),
                "home",
            ));
        }

        // Load persisted machines
        let mut machines = HashMap::new();
        for persisted in persistence.load_all() {
            // Reconstruct VmConfig from persisted data.
            let vm_config = VmConfig {
                cpus: persisted.cpus,
                memory_mb: persisted.memory_mb,
                kernel: persisted.kernel.clone(),
                initrd: persisted.initrd.clone(),
                cmdline: persisted.cmdline.clone(),
                shared_dirs: shared_dirs.clone(),
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

        // Set up shared directories for VirtioFS.
        // "arcbox" tag provides internal data (boot assets, logs, runtime).
        // "users" tag shares /Users so macOS paths work transparently in guest
        // (e.g. `docker run -v /Users/foo/project:/app` just works).
        let mut shared_dirs = vec![SharedDirConfig::new(
            self.data_dir.to_string_lossy().to_string(),
            "arcbox",
        )];
        let users_dir = std::path::Path::new("/Users");
        if users_dir.is_dir() {
            shared_dirs.push(SharedDirConfig::new("/Users", "users"));
        } else if let Some(home_dir) = dirs::home_dir() {
            // Fallback for non-standard macOS layouts.
            shared_dirs.push(SharedDirConfig::new(
                home_dir.to_string_lossy().to_string(),
                "home",
            ));
        }

        // Create underlying VM
        let vm_config = VmConfig {
            cpus: config.cpus,
            memory_mb: config.memory_mb,
            kernel: config.kernel.clone(),
            initrd: config.initrd.clone(),
            cmdline: config.cmdline.clone(),
            shared_dirs,
            block_devices: config.block_devices.clone(),
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
            disk_path: None,
            ssh_key_path: None,
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
                Ok(mut agent) => match agent.ping().await {
                    Ok(resp) => {
                        tracing::debug!(
                            "Machine '{}' agent reachable (version: {}, attempt {})",
                            name,
                            resp.version,
                            attempt
                        );

                        match agent.get_system_info().await {
                            Ok(info) => {
                                if let Some(ip) = select_routable_ip(&info.ip_addresses) {
                                    {
                                        let mut machines = self.machines.write().map_err(|_| {
                                            CoreError::Machine("lock poisoned".to_string())
                                        })?;
                                        if let Some(machine) = machines.get_mut(name) {
                                            machine.ip_address = Some(ip.clone());
                                        }
                                    }
                                    let _ = self.persistence.update_ip(name, Some(&ip));

                                    tracing::info!(
                                        "Machine '{}' ready with IP {} (attempt {})",
                                        name,
                                        ip,
                                        attempt
                                    );
                                    return Ok(());
                                }

                                tracing::trace!(
                                    "Machine '{}' system info has no routable IP yet (attempt {})",
                                    name,
                                    attempt
                                );
                            }
                            Err(e) => {
                                tracing::trace!(
                                    "Machine '{}' get_system_info attempt {} failed: {}",
                                    name,
                                    attempt,
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
                },
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

            if machine.state == MachineState::Running {
                return Err(CoreError::invalid_state(format!(
                    "machine '{}' is already running",
                    name
                )));
            }

            if machine.state == MachineState::Starting || machine.state == MachineState::Stopping {
                return Err(CoreError::invalid_state(format!(
                    "machine '{}' is in transition state",
                    name
                )));
            }

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
        let cid = self
            .get_cid(name)
            .ok_or_else(|| CoreError::Machine("CID not assigned".to_string()))?;
        let fd = self.connect_vsock_port(name, AGENT_PORT)?;

        AgentClient::from_fd(cid, fd)
    }

    /// Connects to a vsock port on a running machine (macOS).
    ///
    /// This is a generic helper used by agent and guest runtime proxy paths.
    #[cfg(target_os = "macos")]
    pub fn connect_vsock_port(&self, name: &str, port: u32) -> Result<std::os::unix::io::RawFd> {
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

        self.vm_manager.connect_vsock(&machine.vm_id, port)
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

    /// Connects to a vsock port on a running machine (Linux).
    #[cfg(target_os = "linux")]
    pub fn connect_vsock_port(&self, name: &str, port: u32) -> Result<std::os::unix::io::RawFd> {
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

        self.vm_manager.connect_vsock(&machine.vm_id, port)
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

        if machine.state != MachineState::Running {
            return Err(CoreError::invalid_state(format!(
                "machine '{}' is not running",
                name
            )));
        }

        // Stop underlying VM
        #[cfg(target_os = "macos")]
        self.vm_manager
            .force_stop_without_hypervisor(&machine.vm_id)?;
        #[cfg(not(target_os = "macos"))]
        self.vm_manager.stop(&machine.vm_id)?;

        machine.state = MachineState::Stopped;
        machine.cid = None;

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

        // Get VM ID before removing from map.
        let vm_id = {
            let m = machines
                .get(name)
                .ok_or_else(|| CoreError::not_found(name.to_string()))?;
            m.vm_id.clone()
        };

        // Remove from VM manager
        self.vm_manager.remove(&vm_id)?;

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

fn select_routable_ip(ips: &[String]) -> Option<String> {
    let mut ipv6_candidate = None;

    for ip in ips {
        let Ok(addr) = ip.parse::<IpAddr>() else {
            continue;
        };
        if addr.is_loopback() || addr.is_multicast() || addr.is_unspecified() {
            continue;
        }

        match addr {
            IpAddr::V4(v4) => return Some(v4.to_string()),
            IpAddr::V6(v6) => {
                if v6.is_unicast_link_local() {
                    continue;
                }
                if ipv6_candidate.is_none() {
                    ipv6_candidate = Some(v6.to_string());
                }
            }
        }
    }

    ipv6_candidate
}
