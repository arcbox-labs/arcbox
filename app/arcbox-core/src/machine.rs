//! Linux machine management.
//!
//! A "machine" is a high-level abstraction over a VM that provides
//! a Linux environment for running containers.

use crate::error::{CoreError, Result};
use crate::persistence::MachinePersistence;
use crate::vm::{SharedDirConfig, VmConfig, VmId, VmManager};
use arcbox_constants::ports::AGENT_PORT;
use arcbox_constants::virtiofs::{MOUNT_PRIVATE, MOUNT_USERS, TAG_ARCBOX, TAG_PRIVATE, TAG_USERS};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

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
mod tests;

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
    /// Kernel command line.
    pub cmdline: Option<String>,
    /// Block devices (e.g., EROFS rootfs image).
    pub block_devices: Vec<crate::vm::BlockDeviceConfig>,
    /// Distribution name (e.g., "alpine", "ubuntu").
    pub distro: Option<String>,
    /// Distribution version (e.g., "3.21", "24.04").
    pub distro_version: Option<String>,
    /// Path to the disk image.
    pub disk_path: Option<PathBuf>,
    /// Path to the SSH private key.
    pub ssh_key_path: Option<PathBuf>,
    /// Guest IP address (reported by agent via vsock).
    pub ip_address: Option<String>,
    /// macOS hypervisor backend this machine boots on.
    pub backend: arcbox_vmm::VmBackend,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

/// A pulled distro rootfs image a machine boots from.
#[derive(Debug, Clone)]
pub struct MachineRootfs {
    /// Host path of the rootfs image (from the machine image registry).
    pub path: PathBuf,
    /// Image format (`squashfs`), used for the kernel `rootfstype=`.
    pub format: String,
    /// Boot shim staging the rootfs (see
    /// `internal-docs/plans/machine-boot-shim.md`). When set, devices are
    /// vda=shim EROFS / vdb=rootfs / vdc=data and the kernel command line
    /// follows the machine-init contract; when `None`, the rootfs itself
    /// boots as vda (custom-kernel testing).
    pub shim: Option<BootShim>,
}

/// The boot-assets artifacts that stage a distro machine's boot.
#[derive(Debug, Clone)]
pub struct BootShim {
    /// Boot-assets kernel image path.
    pub kernel: PathBuf,
    /// Boot-assets EROFS rootfs path (ships `/sbin/arcbox-machine-init`).
    pub rootfs: PathBuf,
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
    /// Kernel command line.
    pub cmdline: Option<String>,
    /// Block devices (e.g., EROFS rootfs image).
    pub block_devices: Vec<crate::vm::BlockDeviceConfig>,
    /// Pulled distro rootfs image to boot from. When set, `create` attaches
    /// it read-only as the first block device (vda), provisions a sparse
    /// per-machine data disk after it, and defaults the kernel command line
    /// to mount it as root.
    pub rootfs: Option<MachineRootfs>,
    /// Distribution name (e.g., "alpine", "ubuntu").
    pub distro: Option<String>,
    /// Distribution version (e.g., "3.21", "24.04").
    pub distro_version: Option<String>,
    /// macOS hypervisor backend for this machine.
    ///
    /// `Vz` (default) runs Apple's Virtualization.framework managed execution
    /// (required for Rosetta); `Hv` runs ArcBox's custom HV-framework VMM.
    pub backend: arcbox_vmm::VmBackend,
    /// Whether to expose Apple Rosetta inside the guest for `linux/amd64`
    /// translation.
    ///
    /// Only honored when [`Self::backend`] is `Vz`; the HV path silently
    /// drops it because Hypervisor.framework does not host the Rosetta
    /// share. Defaults to `false`.
    pub enable_rosetta: bool,
}

impl Default for MachineConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            cpus: arcbox_hypervisor::default_vm_cpu_count(),
            memory_mb: 4096,
            disk_gb: 50,
            kernel: None,
            cmdline: None,
            block_devices: Vec::new(),
            rootfs: None,
            distro: None,
            distro_version: None,
            backend: arcbox_vmm::VmBackend::default(),
            enable_rosetta: false,
        }
    }
}

/// Console device for the host architecture, following the boot-assets
/// convention.
const fn boot_console() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "ttyS0"
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        "hvc0"
    }
}

/// Kernel command line for a shim-less distro machine: root on the read-only
/// rootfs image at vda (custom-kernel testing).
fn default_distro_cmdline(rootfs_format: &str) -> String {
    let console = boot_console();
    format!("console={console} root=/dev/vda ro rootfstype={rootfs_format} earlycon")
}

/// Kernel command line for the machine boot shim: the shim EROFS boots as
/// root and stages the distro rootfs + data disk named by the `arcbox.*`
/// keys (see `internal-docs/plans/machine-boot-shim.md`).
fn machine_shim_cmdline(rootfs_format: &str) -> String {
    use arcbox_constants::cmdline::{
        MACHINE_DATA_KEY, MACHINE_INIT_PATH, MACHINE_ROOTFS_KEY, MACHINE_ROOTFS_TYPE_KEY,
    };
    let console = boot_console();
    format!(
        "console={console} root=/dev/vda ro rootfstype=erofs earlycon \
         init={MACHINE_INIT_PATH} \
         {MACHINE_ROOTFS_KEY}/dev/vdb {MACHINE_ROOTFS_TYPE_KEY}{rootfs_format} \
         {MACHINE_DATA_KEY}/dev/vdc"
    )
}

/// Machine manager.
pub struct MachineManager {
    machines: RwLock<HashMap<String, MachineInfo>>,
    vm_manager: Arc<VmManager>,
    persistence: MachinePersistence,
    /// Data directory for `VirtioFS` sharing.
    data_dir: PathBuf,
    /// Machine-specific directory (`data_dir/machines`/).
    machines_dir: PathBuf,
    /// Shared DNS hosts table from NetworkManager, passed to VMM on start.
    shared_dns_hosts: Option<std::sync::Arc<arcbox_dns::LocalHostsTable>>,
}

impl MachineManager {
    /// Creates a new machine manager.
    #[must_use]
    pub fn new(
        vm_manager: Arc<VmManager>,
        data_dir: PathBuf,
        shared_dns_hosts: Option<std::sync::Arc<arcbox_dns::LocalHostsTable>>,
    ) -> Self {
        let machines_dir = data_dir.join("machines");
        let persistence = MachinePersistence::new(&machines_dir);

        // Create the default shared directory config for VirtioFS.
        // "arcbox" shares the data_dir; "users" shares /Users for transparent paths.
        let mut shared_dirs = vec![SharedDirConfig::new(
            data_dir.to_string_lossy().to_string(),
            TAG_ARCBOX,
        )];
        let users_dir = std::path::Path::new(MOUNT_USERS);
        if users_dir.is_dir() {
            shared_dirs.push(SharedDirConfig::new(MOUNT_USERS, TAG_USERS));
        }
        let private_dir = std::path::Path::new(MOUNT_PRIVATE);
        if private_dir.is_dir() {
            shared_dirs.push(SharedDirConfig::new(MOUNT_PRIVATE, TAG_PRIVATE));
        }

        // Load persisted machines
        let mut machines = HashMap::new();
        for persisted in persistence.load_all() {
            let needs_recovery = persisted.state.needs_recovery();
            if needs_recovery {
                tracing::warn!(
                    "Machine '{}' was running when daemon stopped — marking as stopped",
                    persisted.name
                );
            }

            // Reconstruct VmConfig from persisted data.
            let vm_config = VmConfig {
                cpus: persisted.cpus,
                memory_mb: persisted.memory_mb,
                kernel: persisted.kernel.clone(),
                cmdline: persisted.cmdline.clone(),
                shared_dirs: shared_dirs.clone(),
                block_devices: persisted.block_devices.clone(),
                backend: persisted.backend,
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
                    cmdline: persisted.cmdline,
                    block_devices: persisted.block_devices.clone(),
                    distro: persisted.distro.clone(),
                    distro_version: persisted.distro_version.clone(),
                    disk_path: persisted.disk_path.clone().map(PathBuf::from),
                    ssh_key_path: persisted.ssh_key_path.clone().map(PathBuf::from),
                    ip_address: persisted.ip_address.clone(),
                    backend: persisted.backend,
                    created_at: persisted.created_at,
                };
                machines.insert(persisted.name.clone(), info);
            }

            // Persist the corrected state regardless of whether VM recreation
            // succeeded — a stale Running on disk must not survive reload.
            if needs_recovery {
                if let Err(e) = persistence.update_state(&persisted.name, MachineState::Stopped) {
                    tracing::warn!(
                        "Failed to persist corrected state for '{}': {}",
                        persisted.name,
                        e
                    );
                }
            }
        }

        tracing::info!("Loaded {} persisted machines", machines.len());

        Self {
            machines: RwLock::new(machines),
            vm_manager,
            persistence,
            data_dir,
            machines_dir,
            shared_dns_hosts,
        }
    }

    /// Creates a new machine.
    ///
    /// Sets up EROFS rootfs (read-only, /dev/vda) and a Btrfs data disk
    /// (/dev/vdb) with block device and `VirtioFS` sharing configured.
    ///
    /// When `config.distro` is set, also resolves and downloads a distro
    /// rootfs tarball and generates an SSH key pair.
    ///
    /// # Errors
    ///
    /// Returns an error if the machine cannot be created.
    pub async fn create(&self, config: MachineConfig) -> Result<String> {
        // Hold the write lock for the entire create operation to prevent TOCTOU
        // races: without this, two concurrent creates with the same name could
        // both pass the existence check before either inserts. `create` is rare
        // and user-driven, so the alternative (insert a `Creating` sentinel,
        // drop the lock for I/O, then finalize/rollback) is not worth its
        // orphan-state failure mode.
        let mut machines = self.machines.write().map_err(|_| CoreError::LockPoisoned)?;

        if machines.contains_key(&config.name) {
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
            TAG_ARCBOX,
        )];
        let users_dir = std::path::Path::new(MOUNT_USERS);
        if users_dir.is_dir() {
            shared_dirs.push(SharedDirConfig::new(MOUNT_USERS, TAG_USERS));
        }
        let private_dir = std::path::Path::new(MOUNT_PRIVATE);
        if private_dir.is_dir() {
            shared_dirs.push(SharedDirConfig::new(MOUNT_PRIVATE, TAG_PRIVATE));
        }

        // Distro machines boot the pulled rootfs image (behind the boot shim
        // when configured) with a sparse per-machine data disk; plain VMs
        // keep the caller-provided kernel and block devices untouched.
        // Device contract: [shim?, rootfs, data, ..extras] so the shim's
        // vda/vdb/vdc expectations hold regardless of extra devices.
        let (kernel, block_devices, cmdline, disk_path) = match &config.rootfs {
            Some(rootfs) => {
                // A distro rootfs carries no kernel: the shim supplies the
                // boot-assets kernel; without a shim an explicit kernel is
                // required or the VM would boot with an empty kernel path.
                if rootfs.shim.is_none() && config.kernel.is_none() {
                    return Err(CoreError::config(
                        "a distro rootfs without a boot shim requires an explicit \
                         kernel (pass --kernel)",
                    ));
                }
                let data_disk = machine_dir.join("data.img");
                crate::vm_lifecycle::ensure_sparse_block_image(
                    &data_disk,
                    config.disk_gb.saturating_mul(1024 * 1024 * 1024),
                )?;
                let mut devices = Vec::new();
                if let Some(shim) = &rootfs.shim {
                    devices.push(crate::vm::BlockDeviceConfig {
                        path: shim.rootfs.to_string_lossy().into_owned(),
                        read_only: true,
                    });
                }
                devices.push(crate::vm::BlockDeviceConfig {
                    path: rootfs.path.to_string_lossy().into_owned(),
                    read_only: true,
                });
                devices.push(crate::vm::BlockDeviceConfig {
                    path: data_disk.to_string_lossy().into_owned(),
                    read_only: false,
                });
                devices.extend(config.block_devices.clone());

                let kernel = config.kernel.clone().or_else(|| {
                    rootfs
                        .shim
                        .as_ref()
                        .map(|s| s.kernel.to_string_lossy().into_owned())
                });
                let cmdline = config.cmdline.clone().or_else(|| {
                    Some(match &rootfs.shim {
                        Some(_) => machine_shim_cmdline(&rootfs.format),
                        None => default_distro_cmdline(&rootfs.format),
                    })
                });
                (kernel, devices, cmdline, Some(data_disk))
            }
            None => (
                config.kernel.clone(),
                config.block_devices.clone(),
                config.cmdline.clone(),
                None,
            ),
        };

        // Create underlying VM
        let vm_config = VmConfig {
            cpus: config.cpus,
            memory_mb: config.memory_mb,
            kernel: kernel.clone(),
            cmdline: cmdline.clone(),
            shared_dirs,
            block_devices: block_devices.clone(),
            rosetta: config.enable_rosetta,
            backend: config.backend,
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
            kernel,
            cmdline,
            block_devices,
            distro: config.distro,
            distro_version: config.distro_version,
            disk_path,
            ssh_key_path: None,
            ip_address: None,
            backend: config.backend,
            created_at: Utc::now(),
        };

        // Persist the machine config
        self.persistence.save(&info)?;

        machines.insert(config.name.clone(), info);

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
            .map_err(|_| CoreError::LockPoisoned)?
            .get(name)
            .and_then(|m| m.distro.as_ref())
            .is_some();

        // Start underlying VM
        self.vm_manager
            .start(&vm_id, self.shared_dns_hosts.clone())?;

        // Update machine state
        {
            let mut machines = self.machines.write().map_err(|_| CoreError::LockPoisoned)?;

            if let Some(machine) = machines.get_mut(name) {
                machine.state = MachineState::Running;
                machine.cid = Some(cid);
                machine.ip_address = None;

                tracing::info!("Machine '{}' started with CID {}", name, cid);
            }
        }

        // Update persisted state (single read-modify-write)
        if let Err(e) = self.persistence.update(name, |m| {
            m.state = MachineState::Running.into();
            m.ip_address = None;
        }) {
            tracing::warn!("Failed to persist state for machine '{}': {}", name, e);
        }

        // For machine VMs, wait for agent readiness and discover IP.
        if is_machine_vm {
            self.wait_for_machine_ready(name).await.map_err(|e| {
                CoreError::Machine(format!(
                    "Machine '{name}' started but readiness check failed: {e}"
                ))
            })?;
        }

        Ok(())
    }

    /// Waits for the guest agent to become ready and discovers the IP address.
    ///
    /// Polls the agent via vsock with exponential backoff. Once the agent
    /// responds, queries `SystemInfo` to get the guest IP. The probe follows
    /// the transport the backend hands out: async (VZ) attempts run on the
    /// runtime; blocking (HV) attempts run inside `block_in_place`, because
    /// the HV socketpair's rapid fd teardown stalls the tokio reactor (same
    /// rationale as `wait_for_agent` in `vm_lifecycle`) — a per-attempt
    /// blocking region, bounded by one RPC round-trip.
    ///
    /// Probe before the first sleep: failed probes are ~1ms (vsock RST via
    /// the event-driven RX path), while sleeping first puts a full backoff
    /// interval on every start even when the agent is already up.
    async fn wait_for_machine_ready(&self, name: &str) -> Result<()> {
        const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
        const INITIAL_DELAY_MS: u64 = 50;
        const MAX_DELAY_MS: u64 = 500;

        tracing::info!("Waiting for machine '{}' agent to become ready...", name);

        let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
        let mut delay_ms = INITIAL_DELAY_MS;
        let mut attempt: u32 = 0;

        let ip = loop {
            attempt += 1;

            let probed = match self.connect_agent(name) {
                Ok(agent) if agent.is_blocking() => {
                    tokio::task::block_in_place(|| probe_ip_blocking(agent, name, attempt))?
                }
                Ok(agent) => probe_ip_async(agent, name, attempt).await?,
                Err(e) => {
                    tracing::trace!("Machine '{}' connect failed (attempt {attempt}): {e}", name);
                    None
                }
            };
            if let Some(ip) = probed {
                break ip;
            }

            if std::time::Instant::now() >= deadline {
                return Err(CoreError::Machine(format!(
                    "Machine '{name}' agent did not report a routable IP within timeout"
                )));
            }
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            delay_ms = (delay_ms * 3 / 2).min(MAX_DELAY_MS);
        };

        // Back on async context — update state.
        {
            let mut machines = self.machines.write().map_err(|_| CoreError::LockPoisoned)?;
            if let Some(machine) = machines.get_mut(name) {
                machine.ip_address = Some(ip.clone());
            }
        }
        if let Err(e) = self.persistence.update_ip(name, Some(&ip)) {
            tracing::warn!("Failed to persist IP for machine '{}': {}", name, e);
        }
        tracing::info!("Machine '{}' ready with IP {}", name, ip);
        Ok(())
    }

    fn assign_cid_for_start(&self, name: &str) -> Result<(VmId, u32)> {
        let (vm_id, running_count) = {
            let machines = self.machines.read().map_err(|_| CoreError::LockPoisoned)?;

            let machine = machines
                .get(name)
                .ok_or_else(|| CoreError::not_found(name.to_string()))?;

            if machine.state == MachineState::Running {
                return Err(CoreError::invalid_state(format!(
                    "machine '{name}' is already running"
                )));
            }

            if machine.state == MachineState::Starting || machine.state == MachineState::Stopping {
                return Err(CoreError::invalid_state(format!(
                    "machine '{name}' is in transition state"
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

    /// Returns the vmnet bridge interface name for a machine's VM.
    ///
    /// Only available when the `vmnet` feature is enabled and the VM is running.
    #[cfg(all(target_os = "macos", feature = "vmnet"))]
    pub fn vmnet_bridge_name(&self, name: &str) -> Option<String> {
        let machines = self.machines.read().ok()?;
        let machine = machines.get(name)?;
        self.vm_manager.vmnet_bridge_name(&machine.vm_id)
    }

    /// Returns the bridge NIC MAC address for a machine's VM.
    pub fn bridge_mac(&self, name: &str) -> Option<String> {
        let machines = self.machines.read().ok()?;
        let machine = machines.get(name)?;
        Some(crate::vm::bridge_nic_mac_for_vm_id(&machine.vm_id))
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
        use crate::agent_client::AgentClient;
        let cid = self
            .get_cid(name)
            .ok_or_else(|| CoreError::invalid_state("CID not assigned"))?;
        let backend = {
            let machines = self.machines.read().map_err(|_| CoreError::LockPoisoned)?;
            let machine = machines
                .get(name)
                .ok_or_else(|| CoreError::not_found(name.to_string()))?;
            self.vm_manager.backend(&machine.vm_id)?
        };
        let fd = self.connect_vsock_port(name, AGENT_PORT)?;
        // The transport must follow the backend, not the fd's socket domain:
        // both backends hand over unnamed AF_UNIX fds, but only the HV
        // socketpair needs the blocking transport (tokio/kqueue stalls on
        // rapid connect/teardown cycles), and only the async transport
        // supports the streaming sandbox RPCs VZ clients rely on.
        match backend {
            arcbox_vmm::VmBackend::Hv => AgentClient::from_fd_blocking(cid, fd),
            arcbox_vmm::VmBackend::Vz => AgentClient::from_fd_async(cid, fd),
        }
    }

    /// Connects to a vsock port on a running machine (macOS).
    ///
    /// This is a generic helper used by agent and guest runtime proxy paths.
    #[cfg(target_os = "macos")]
    pub fn connect_vsock_port(&self, name: &str, port: u32) -> Result<std::os::unix::io::RawFd> {
        let machines = self.machines.read().map_err(|_| CoreError::LockPoisoned)?;

        let machine = machines
            .get(name)
            .ok_or_else(|| CoreError::not_found(name.to_string()))?;

        if machine.state != MachineState::Running {
            return Err(CoreError::invalid_state(format!(
                "machine '{name}' is not running"
            )));
        }

        self.vm_manager.connect_vsock(&machine.vm_id, port)
    }

    /// Connects to the agent on a running machine (Linux).
    #[cfg(target_os = "linux")]
    pub fn connect_agent(&self, name: &str) -> Result<crate::agent_client::AgentClient> {
        use crate::agent_client::AgentClient;

        let machines = self.machines.read().map_err(|_| CoreError::LockPoisoned)?;

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
            .ok_or_else(|| CoreError::invalid_state("CID not assigned"))?;

        // On Linux, AgentClient connects directly via AF_VSOCK
        Ok(AgentClient::new(cid))
    }

    /// Connects to a vsock port on a running machine (Linux).
    #[cfg(target_os = "linux")]
    pub fn connect_vsock_port(&self, name: &str, port: u32) -> Result<std::os::unix::io::RawFd> {
        let machines = self.machines.read().map_err(|_| CoreError::LockPoisoned)?;

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
        let machines = self.machines.read().map_err(|_| CoreError::LockPoisoned)?;

        let machine = machines
            .get(name)
            .ok_or_else(|| CoreError::not_found(name.to_string()))?;

        if machine.state != MachineState::Running {
            return Err(CoreError::invalid_state(format!(
                "machine '{name}' is not running"
            )));
        }

        self.vm_manager.read_console_output(&machine.vm_id)
    }

    /// Reads agent log output (hvc1) for a running machine (macOS only).
    #[cfg(target_os = "macos")]
    pub fn read_agent_log_output(&self, name: &str) -> Result<String> {
        let machines = self.machines.read().map_err(|_| CoreError::LockPoisoned)?;

        let machine = machines
            .get(name)
            .ok_or_else(|| CoreError::not_found(name.to_string()))?;

        if machine.state != MachineState::Running {
            return Err(CoreError::invalid_state(format!(
                "machine '{name}' is not running"
            )));
        }

        self.vm_manager.read_agent_log_output(&machine.vm_id)
    }

    /// Captures a debug snapshot (virtio queues + vCPU exit counters)
    /// for a machine.
    ///
    /// Deliberately not gated on `MachineState::Running`: a machine
    /// stuck booting (state still Starting) is this snapshot's main
    /// diagnostic target. The VM manager errors if no VMM exists yet.
    ///
    /// # Errors
    ///
    /// Returns an error if the machine is not found or its VMM has not
    /// been created.
    pub fn debug_snapshot(&self, name: &str) -> Result<arcbox_vmm::VmDebugSnapshot> {
        let machines = self.machines.read().map_err(|_| CoreError::LockPoisoned)?;

        let machine = machines
            .get(name)
            .ok_or_else(|| CoreError::not_found(name.to_string()))?;

        self.vm_manager.debug_snapshot(&machine.vm_id)
    }

    /// Stops a machine.
    ///
    /// # Errors
    ///
    /// Returns an error if the machine cannot be stopped.
    pub fn stop(&self, name: &str) -> Result<()> {
        let mut machines = self.machines.write().map_err(|_| CoreError::LockPoisoned)?;

        let machine = machines
            .get_mut(name)
            .ok_or_else(|| CoreError::not_found(name.to_string()))?;

        if machine.state != MachineState::Running {
            return Err(CoreError::invalid_state(format!(
                "machine '{name}' is not running"
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
        if let Err(e) = self.persistence.update_state(name, MachineState::Stopped) {
            tracing::warn!(
                "Failed to persist stopped state for machine '{}': {}",
                name,
                e
            );
        }

        Ok(())
    }

    /// Reports whether a machine's VM stopped on its own (guest-driven), and if
    /// so whether it was a reboot request. See [`VmManager::vm_self_stopped`].
    #[must_use]
    pub fn vm_self_stopped(&self, name: &str) -> Option<bool> {
        let machines = self.machines.read().ok()?;
        let vm_id = machines.get(name)?.vm_id.clone();
        drop(machines);
        self.vm_manager.vm_self_stopped(&vm_id)
    }

    /// Reboots a machine's VM in place (guest PSCI SYSTEM_RESET): a full
    /// teardown then a fresh boot, leaving the machine record Running. The
    /// caller re-establishes agent readiness afterward.
    ///
    /// # Errors
    ///
    /// Returns an error if the machine is unknown or the reboot fails.
    pub fn reboot(&self, name: &str) -> Result<()> {
        let vm_id = {
            let machines = self.machines.read().map_err(|_| CoreError::LockPoisoned)?;
            machines
                .get(name)
                .ok_or_else(|| CoreError::not_found(name.to_string()))?
                .vm_id
                .clone()
        };
        // Reboot is a slow teardown+reboot; do it without holding the registry
        // lock so concurrent reads stay responsive.
        self.vm_manager.reboot(&vm_id)?;
        tracing::info!("Rebooted machine '{}'", name);
        Ok(())
    }

    /// Switches a stopped machine's hypervisor backend.
    ///
    /// Updates the lazily-built VM config and the in-memory and persisted
    /// records; `set_backend` itself does not touch the machine's disks. The
    /// machine must be stopped; the new backend takes effect on the next start,
    /// when the `Vmm` is rebuilt from `VmConfig`. Note that for the System VM
    /// the kernel command line differs between backends, so that next start
    /// detects config drift and recreates the machine record (the persistent
    /// data image survives; SSH host keys are regenerated).
    ///
    /// # Errors
    ///
    /// Returns an error if the machine is not found, is running/starting, or
    /// the persisted config cannot be updated.
    pub fn set_backend(&self, name: &str, backend: arcbox_vmm::VmBackend) -> Result<()> {
        // Validate and capture the VM id without mutating anything yet.
        let vm_id = {
            let machines = self.machines.read().map_err(|_| CoreError::LockPoisoned)?;
            let machine = machines
                .get(name)
                .ok_or_else(|| CoreError::not_found(name.to_string()))?;
            if matches!(
                machine.state,
                MachineState::Running | MachineState::Starting
            ) {
                return Err(CoreError::invalid_state(format!(
                    "cannot switch backend while machine '{name}' is {:?}",
                    machine.state
                )));
            }
            machine.vm_id.clone()
        };

        // Update the runtime views first, then commit the durable record last.
        // The persisted backend is what seeds the lifecycle after a daemon
        // restart, so writing it only once the in-memory updates have succeeded
        // means a failed switch never leaves a backend on disk that the running
        // system did not actually apply (which a later restart would then boot).
        self.vm_manager.set_backend(&vm_id, backend)?;
        if let Some(machine) = self
            .machines
            .write()
            .map_err(|_| CoreError::LockPoisoned)?
            .get_mut(name)
        {
            machine.backend = backend;
        }
        self.persistence.update(name, |m| m.backend = backend)?;
        Ok(())
    }

    /// Attempts graceful machine shutdown via guest ACPI stop request.
    ///
    /// Returns `Ok(true)` if the machine stopped, `Ok(false)` if graceful
    /// shutdown timed out or is unavailable.
    pub fn graceful_stop(&self, name: &str, timeout: Duration) -> Result<bool> {
        let vm_id = {
            let mut machines = self.machines.write().map_err(|_| CoreError::LockPoisoned)?;

            let machine = machines
                .get_mut(name)
                .ok_or_else(|| CoreError::not_found(name.to_string()))?;

            if machine.state != MachineState::Running {
                return Err(CoreError::invalid_state(format!(
                    "machine '{name}' is not running"
                )));
            }

            machine.state = MachineState::Stopping;
            machine.vm_id.clone()
        };

        match self.vm_manager.graceful_stop(&vm_id, timeout) {
            Ok(true) => {
                let mut machines = self.machines.write().map_err(|_| CoreError::LockPoisoned)?;

                let machine = machines
                    .get_mut(name)
                    .ok_or_else(|| CoreError::not_found(name.to_string()))?;
                machine.state = MachineState::Stopped;
                machine.cid = None;

                if let Err(e) = self.persistence.update_state(name, MachineState::Stopped) {
                    tracing::warn!(
                        "Failed to persist stopped state for machine '{}': {}",
                        name,
                        e
                    );
                }
                Ok(true)
            }
            Ok(false) => {
                if let Ok(mut machines) = self.machines.write() {
                    if let Some(machine) = machines.get_mut(name) {
                        machine.state = MachineState::Running;
                    }
                }
                Ok(false)
            }
            Err(e) => {
                if let Ok(mut machines) = self.machines.write() {
                    if let Some(machine) = machines.get_mut(name) {
                        machine.state = MachineState::Running;
                    }
                }
                Err(e)
            }
        }
    }

    /// Gets machine information.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<MachineInfo> {
        self.machines.read().ok()?.get(name).cloned()
    }

    /// Returns whether a machine with `name` is registered.
    #[must_use]
    pub fn exists(&self, name: &str) -> bool {
        self.machines
            .read()
            .is_ok_and(|machines| machines.contains_key(name))
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
        let mut machines = self.machines.write().map_err(|_| CoreError::LockPoisoned)?;

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
            machines = self.machines.write().map_err(|_| CoreError::LockPoisoned)?;
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
        // This must succeed — if it doesn't, the machine will reappear on daemon
        // restart even though VM and in-memory state are already gone.
        self.persistence.remove(name)?;

        tracing::info!("Removed machine '{}'", name);
        Ok(())
    }

    /// Takes the inbound listener manager from a running machine's VM (Darwin only).
    ///
    /// Returns `None` if the machine is not found, not running, or the manager
    /// has already been taken.
    #[cfg(target_os = "macos")]
    pub fn take_inbound_listener_manager(
        &self,
        name: &str,
    ) -> Option<arcbox_net::darwin::inbound_relay::InboundListenerManager> {
        let vm_id = {
            let machines = self.machines.read().ok()?;
            let machine = machines.get(name)?;
            if machine.state != MachineState::Running {
                return None;
            }
            machine.vm_id.clone()
        };
        self.vm_manager.take_inbound_listener_manager(&vm_id)
    }

    /// Registers a mock machine for testing purposes.
    ///
    /// This method creates a machine entry without creating an actual VM.
    /// The machine will be in Running state with a mock CID.
    ///
    /// # Note
    /// This is intended for unit testing only and should not be used in production.
    pub fn register_mock_machine(&self, name: &str, cid: u32) -> Result<()> {
        let mut machines = self.machines.write().map_err(|_| CoreError::LockPoisoned)?;

        if machines.contains_key(name) {
            return Ok(()); // Already registered
        }

        let info = MachineInfo {
            name: name.to_string(),
            state: MachineState::Running,
            vm_id: VmId::new(), // Fake VM ID
            cid: Some(cid),
            cpus: arcbox_hypervisor::default_vm_cpu_count(),
            memory_mb: 4096,
            disk_gb: 50,
            kernel: None,
            cmdline: None,
            block_devices: Vec::new(),
            distro: None,
            distro_version: None,
            disk_path: None,
            ssh_key_path: None,
            ip_address: None,
            backend: arcbox_vmm::VmBackend::default(),
            created_at: Utc::now(),
        };

        machines.insert(name.to_string(), info);
        tracing::debug!("Registered mock machine '{}' with CID {}", name, cid);
        Ok(())
    }
}

/// One readiness attempt over the blocking (HV) transport: ping, protocol
/// check, then IP discovery. `Ok(None)` means "not ready yet, retry";
/// a protocol mismatch is fatal so stale agents fail machine start loudly
/// instead of misbehaving under proto field skew.
fn probe_ip_blocking(
    mut agent: crate::agent_client::AgentClient,
    name: &str,
    attempt: u32,
) -> Result<Option<String>> {
    let resp = match agent.ping_blocking() {
        Ok(resp) => resp,
        Err(e) => {
            tracing::trace!("Machine '{}' ping failed (attempt {attempt}): {e}", name);
            return Ok(None);
        }
    };
    crate::agent_client::AgentClient::check_agent_protocol(&resp)?;
    tracing::debug!(
        "Machine '{}' agent reachable (version: {}, attempt {})",
        name,
        resp.version,
        attempt,
    );
    match agent.get_system_info_blocking() {
        Ok(info) => Ok(select_routable_ip(&info.ip_addresses)),
        Err(e) => {
            tracing::trace!(
                "Machine '{}' get_system_info failed (attempt {attempt}): {e}",
                name,
            );
            Ok(None)
        }
    }
}

/// One readiness attempt over the async (VZ) transport; same contract as
/// [`probe_ip_blocking`].
async fn probe_ip_async(
    mut agent: crate::agent_client::AgentClient,
    name: &str,
    attempt: u32,
) -> Result<Option<String>> {
    let resp = match agent.ping().await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::trace!("Machine '{}' ping failed (attempt {attempt}): {e}", name);
            return Ok(None);
        }
    };
    crate::agent_client::AgentClient::check_agent_protocol(&resp)?;
    tracing::debug!(
        "Machine '{}' agent reachable (version: {}, attempt {})",
        name,
        resp.version,
        attempt,
    );
    match agent.get_system_info().await {
        Ok(info) => Ok(select_routable_ip(&info.ip_addresses)),
        Err(e) => {
            tracing::trace!(
                "Machine '{}' get_system_info failed (attempt {attempt}): {e}",
                name,
            );
            Ok(None)
        }
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
