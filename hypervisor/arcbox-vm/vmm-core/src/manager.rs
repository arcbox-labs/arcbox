use std::collections::HashMap;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use fc_sdk::VmBuilder;
use fc_sdk::process::{FirecrackerProcessBuilder, JailerProcessBuilder};
use fc_sdk::types::{
    Balloon, BootSource, Drive, EntropyDevice, MemoryHotplugConfig, MmdsConfig, NetworkInterface,
    NetworkOverride, PartialDrive, PartialNetworkInterface, SerialDevice, Vsock,
};
use tracing::info;
use uuid::Uuid;

use crate::config::{RateLimitSpec, RestoreSpec, SnapshotRequest, SnapshotType, VmSpec, VmmConfig};
use crate::error::{Result, VmmError};
use crate::instance::{VmId, VmInfo, VmInstance, VmMetrics, VmState, VmSummary};
use crate::network::NetworkManager;
use crate::snapshot::{SnapshotCatalog, SnapshotInfo};
use crate::store::VmStore;

/// Top-level orchestrator that manages the full lifecycle of multiple VMs.
pub struct VmmManager {
    /// Live VM registry.
    instances: Arc<RwLock<HashMap<VmId, Arc<Mutex<VmInstance>>>>>,
    /// Disk-backed persistence.
    store: Arc<VmStore>,
    /// TAP / IP pool manager.
    network: Arc<NetworkManager>,
    /// Snapshot catalog.
    snapshots: Arc<SnapshotCatalog>,
    /// Daemon configuration.
    config: VmmConfig,
}

impl VmmManager {
    /// Create a new manager from the given configuration.
    pub fn new(config: VmmConfig) -> Result<Self> {
        let store = Arc::new(VmStore::new(&config.firecracker.data_dir));
        let network = Arc::new(NetworkManager::new(
            &config.network.bridge,
            &config.network.cidr,
            &config.network.gateway,
            config.network.dns.clone(),
        )?);
        let snapshots = Arc::new(SnapshotCatalog::new(&config.firecracker.data_dir));

        Ok(Self {
            instances: Arc::new(RwLock::new(HashMap::new())),
            store,
            network,
            snapshots,
            config,
        })
    }

    // =========================================================================
    // VM lifecycle
    // =========================================================================

    /// Allocate resources, spawn Firecracker, configure, and boot the VM.
    pub async fn create_vm(&self, mut spec: VmSpec) -> Result<VmId> {
        // Apply config defaults for fields not supplied by the caller.
        if spec.kernel.is_empty() {
            spec.kernel = self.config.defaults.kernel.clone();
        }
        if spec.rootfs.is_empty() {
            spec.rootfs = self.config.defaults.rootfs.clone();
        }
        if spec.boot_args.is_empty() {
            spec.boot_args = self.config.defaults.boot_args.clone();
        }
        if spec.vcpus == 0 {
            spec.vcpus = self.config.defaults.vcpus;
        }
        if spec.memory_mib == 0 {
            spec.memory_mib = self.config.defaults.memory_mib;
        }

        // Ensure name uniqueness.
        {
            let instances = self.instances.read().unwrap();
            if instances
                .values()
                .any(|i| i.lock().unwrap().name == spec.name)
            {
                return Err(VmmError::AlreadyExists(spec.name.clone()));
            }
        }

        let id = Uuid::new_v4().to_string();
        let vm_dir = self.store.vm_dir(&id);
        std::fs::create_dir_all(&vm_dir).map_err(VmmError::Io)?;

        let log_path = vm_dir.join("firecracker.log");
        let metrics_path = vm_dir.join("firecracker.metrics");

        // Allocate network.
        let net_alloc = self.network.allocate(&id)?;

        // Create instance record (pre-boot).
        let mut instance = VmInstance::new(
            id.clone(),
            spec.name.clone(),
            spec.clone(),
            vm_dir.join("firecracker.sock"),
        );
        instance.network = Some(net_alloc.clone());
        self.store.save(&instance)?;

        // Build and spawn the Firecracker process (direct or via jailer).
        let fc_cfg = &self.config.firecracker;
        let (process, socket_path) = if let Some(ref jc) = fc_cfg.jailer {
            // --- Jailer mode ---
            let mut jb = JailerProcessBuilder::new(&jc.binary, &fc_cfg.binary, &id, jc.uid, jc.gid);
            if let Some(ref base) = jc.chroot_base_dir {
                jb = jb.chroot_base_dir(base);
            }
            if let Some(ref ns) = jc.netns {
                jb = jb.netns(ns);
            }
            if jc.new_pid_ns {
                jb = jb.new_pid_ns(true);
            }
            if let Some(ref ver) = jc.cgroup_version {
                jb = jb.cgroup_version(ver);
            }
            if let Some(ref parent) = jc.parent_cgroup {
                jb = jb.parent_cgroup(parent);
            }
            for limit in &jc.resource_limits {
                jb = jb.resource_limit(limit);
            }
            if let Some(secs) = fc_cfg.socket_timeout_secs {
                jb = jb.socket_timeout(Duration::from_secs(secs));
            }
            let sock = jb.socket_path();
            let proc = jb
                .spawn()
                .await
                .map_err(|e| VmmError::Process(e.to_string()))?;
            (proc, sock)
        } else {
            // --- Direct mode ---
            let sock = vm_dir.join("firecracker.sock");
            let mut fb = FirecrackerProcessBuilder::new(&fc_cfg.binary, &sock).id(&id);
            fb = fb.log_path(&log_path).metrics_path(&metrics_path);
            if let Some(ref level) = fc_cfg.log_level {
                fb = fb.log_level(level);
            }
            if fc_cfg.no_seccomp {
                fb = fb.no_seccomp(true);
            }
            if let Some(ref filter) = fc_cfg.seccomp_filter {
                fb = fb.seccomp_filter(filter);
            }
            if let Some(size) = fc_cfg.http_api_max_payload_size {
                fb = fb.http_api_max_payload_size(size);
            }
            if let Some(size) = fc_cfg.mmds_size_limit {
                fb = fb.mmds_size_limit(size);
            }
            if let Some(secs) = fc_cfg.socket_timeout_secs {
                fb = fb.socket_timeout(Duration::from_secs(secs));
            }
            let proc = fb
                .spawn()
                .await
                .map_err(|e| VmmError::Process(e.to_string()))?;
            (proc, sock)
        };

        // Configure and boot the VM.
        let vcpu_count = NonZeroU64::new(spec.vcpus.max(1))
            .ok_or_else(|| VmmError::Config("vcpus must be > 0".into()))?;

        let vsock_path = vm_dir.join("vsock.sock");

        let mut builder = VmBuilder::new(&socket_path)
            .boot_source(BootSource {
                kernel_image_path: spec.kernel.clone(),
                boot_args: Some(spec.boot_args.clone()),
                initrd_path: spec.initrd.clone(),
            })
            .machine_config(fc_sdk::types::MachineConfiguration {
                vcpu_count,
                mem_size_mib: spec.memory_mib as i64,
                smt: spec.smt,
                track_dirty_pages: spec.track_dirty_pages,
                cpu_template: spec.cpu_template.map(Into::into),
                huge_pages: spec.huge_pages.map(Into::into),
            })
            .drive(Drive {
                drive_id: "rootfs".into(),
                path_on_host: Some(spec.rootfs.clone()),
                is_root_device: true,
                is_read_only: Some(spec.root_readonly),
                partuuid: spec.root_partuuid.clone(),
                cache_type: spec.root_cache_type.into(),
                rate_limiter: spec.root_rate_limit.clone().map(Into::into),
                io_engine: spec.root_io_engine.into(),
                socket: None,
            })
            .network_interface(NetworkInterface {
                iface_id: "eth0".into(),
                guest_mac: Some(net_alloc.mac_address.clone()),
                host_dev_name: net_alloc.tap_name.clone(),
                rx_rate_limiter: spec.net_rx_rate_limit.clone().map(Into::into),
                tx_rate_limiter: spec.net_tx_rate_limit.clone().map(Into::into),
            });

        // Extra block devices.
        for d in &spec.extra_drives {
            builder = builder.drive(Drive {
                drive_id: d.drive_id.clone(),
                path_on_host: Some(d.path.clone()),
                is_root_device: false,
                is_read_only: Some(d.readonly),
                partuuid: d.partuuid.clone(),
                cache_type: d.cache_type.into(),
                rate_limiter: d.rate_limit.clone().map(Into::into),
                io_engine: d.io_engine.into(),
                socket: None,
            });
        }

        // Optional devices.
        if let Some(ref b) = spec.balloon {
            builder = builder.balloon(Balloon {
                amount_mib: b.amount_mib,
                deflate_on_oom: b.deflate_on_oom,
                stats_polling_interval_s: b.stats_polling_interval_s,
                free_page_hinting: b.free_page_hinting,
                free_page_reporting: b.free_page_reporting,
            });
        }

        if let Some(ref v) = spec.vsock {
            builder = builder.vsock(Vsock {
                guest_cid: v.guest_cid,
                uds_path: vsock_path.to_string_lossy().into_owned(),
                vsock_id: None,
            });
        }

        if spec.entropy_device {
            builder = builder.entropy(EntropyDevice { rate_limiter: None });
        }

        if let Some(ref path) = spec.serial_out {
            builder = builder.serial(SerialDevice {
                serial_out_path: Some(path.clone()),
            });
        }

        if let Some(ref mh) = spec.memory_hotplug {
            builder = builder.memory_hotplug(MemoryHotplugConfig {
                total_size_mib: Some(mh.total_size_mib),
                slot_size_mib: mh.slot_size_mib.unwrap_or(128),
                block_size_mib: mh.block_size_mib.unwrap_or(2),
            });
        }

        if let Some(ref mmds) = spec.mmds {
            builder = builder.mmds_config(MmdsConfig {
                network_interfaces: mmds.network_interfaces.clone(),
                version: mmds.version.into(),
                ipv4_address: mmds
                    .ipv4_address
                    .clone()
                    .unwrap_or_else(|| "169.254.169.254".into()),
                imds_compat: mmds.imds_compat,
            });
            if let Some(ref data) = mmds.initial_data {
                builder = builder.mmds_data(data.clone());
            }
        }

        let vm = Arc::new(builder.start().await.map_err(VmmError::Sdk)?);

        // Update instance to Running.
        {
            let mut instances = self.instances.write().unwrap();
            let entry = instances.entry(id.clone()).or_insert_with(|| {
                Arc::new(Mutex::new(VmInstance::new(
                    id.clone(),
                    spec.name.clone(),
                    spec.clone(),
                    socket_path.clone(),
                )))
            });
            let mut inst = entry.lock().unwrap();
            inst.process = Some(process);
            inst.vm = Some(vm);
            inst.state = VmState::Running;
            inst.started_at = Some(chrono::Utc::now());
            inst.network = Some(net_alloc);
            self.store.save(&inst)?;
        }

        info!(vm_id = %id, "VM created and running");
        Ok(id)
    }

    /// Resume a stopped VM.
    pub async fn start_vm(&self, id: &VmId) -> Result<()> {
        let vm_handle = {
            let instance = self.get_instance(id)?;
            let inst = instance.lock().unwrap();
            match inst.state {
                VmState::Stopped => {}
                s => {
                    return Err(VmmError::WrongState {
                        id: id.clone(),
                        expected: "Stopped".into(),
                        actual: s.to_string(),
                    });
                }
            }
            inst.vm.as_ref().map(Arc::clone)
        };

        if let Some(vm) = vm_handle {
            vm.resume().await.map_err(VmmError::Sdk)?;
        }

        let instance = self.get_instance(id)?;
        let mut inst = instance.lock().unwrap();
        inst.state = VmState::Running;
        inst.started_at = Some(chrono::Utc::now());
        self.store.save(&inst)?;
        info!(vm_id = %id, "VM started");
        Ok(())
    }

    /// Stop a running VM.
    ///
    /// `force = true` sends SIGKILL to the Firecracker process;
    /// `force = false` sends Ctrl+Alt+Del to the guest.
    pub async fn stop_vm(&self, id: &VmId, force: bool) -> Result<()> {
        let (vm_handle, has_process) = {
            let instance = self.get_instance(id)?;
            let inst = instance.lock().unwrap();
            match inst.state {
                VmState::Running | VmState::Paused => {}
                s => {
                    return Err(VmmError::WrongState {
                        id: id.clone(),
                        expected: "Running or Paused".into(),
                        actual: s.to_string(),
                    });
                }
            }
            (inst.vm.as_ref().map(Arc::clone), inst.process.is_some())
        };

        if force && has_process {
            let instance = self.get_instance(id)?;
            let mut inst = instance.lock().unwrap();
            if let Some(ref mut process) = inst.process
                && let Some(pid) = process.pid()
            {
                // SAFETY: pid is a valid process ID obtained from the spawned child.
                unsafe { libc::kill(pid as i32, libc::SIGKILL) };
            }
        } else if let Some(vm) = vm_handle {
            vm.send_ctrl_alt_del().await.map_err(VmmError::Sdk)?;
        }

        let instance = self.get_instance(id)?;
        let mut inst = instance.lock().unwrap();
        inst.state = VmState::Stopped;
        self.store.save(&inst)?;
        info!(vm_id = %id, force, "VM stopped");
        Ok(())
    }

    /// Stop and clean up all resources for a VM.
    pub async fn remove_vm(&self, id: &VmId, force: bool) -> Result<()> {
        let _ = self.stop_vm(id, force).await;

        let instance = {
            let mut instances = self.instances.write().unwrap();
            instances.remove(id)
        };

        if let Some(instance) = instance {
            let inst = instance.lock().unwrap();
            if let Some(net) = &inst.network {
                self.network.release(net);
            }
            if inst.socket_path.exists() {
                let _ = std::fs::remove_file(&inst.socket_path);
            }
        }

        self.store.delete(id)?;
        info!(vm_id = %id, "VM removed");
        Ok(())
    }

    /// List VMs.  `all = false` returns only running VMs.
    pub fn list_vms(&self, all: bool) -> Result<Vec<VmSummary>> {
        let instances = self.instances.read().unwrap();
        let summaries = instances
            .values()
            .filter_map(|arc| {
                let inst = arc.lock().unwrap();
                if !all && inst.state != VmState::Running {
                    return None;
                }
                Some(VmSummary {
                    id: inst.id.clone(),
                    name: inst.name.clone(),
                    state: inst.state,
                    vcpus: inst.spec.vcpus,
                    memory_mib: inst.spec.memory_mib,
                    ip_address: inst.network.as_ref().map(|n| n.ip_address.to_string()),
                    created_at: inst.created_at,
                })
            })
            .collect();
        Ok(summaries)
    }

    /// Full detail for a single VM.
    pub fn inspect_vm(&self, id: &VmId) -> Result<VmInfo> {
        let instance = self.get_instance(id)?;
        let inst = instance.lock().unwrap();
        Ok(VmInfo {
            id: inst.id.clone(),
            name: inst.name.clone(),
            state: inst.state,
            spec: inst.spec.clone(),
            network: inst.network.clone(),
            socket_path: inst.socket_path.clone(),
            created_at: inst.created_at,
            started_at: inst.started_at,
        })
    }

    // =========================================================================
    // Pause / Resume / Snapshot
    // =========================================================================

    /// Pause a running VM.
    pub async fn pause_vm(&self, id: &VmId) -> Result<()> {
        let vm = self.get_vm_handle(id)?;
        vm.pause().await.map_err(VmmError::Sdk)?;
        self.set_state(id, VmState::Paused)?;
        info!(vm_id = %id, "VM paused");
        Ok(())
    }

    /// Resume a paused VM.
    pub async fn resume_vm(&self, id: &VmId) -> Result<()> {
        let vm = self.get_vm_handle(id)?;
        vm.resume().await.map_err(VmmError::Sdk)?;
        self.set_state(id, VmState::Running)?;
        info!(vm_id = %id, "VM resumed");
        Ok(())
    }

    /// Pause, snapshot, and resume a VM.
    pub async fn snapshot_vm(&self, id: &VmId, req: SnapshotRequest) -> Result<SnapshotInfo> {
        let was_running = {
            let instance = self.get_instance(id)?;
            let inst = instance.lock().unwrap();
            inst.state == VmState::Running
        };

        if was_running {
            self.pause_vm(id).await?;
        }

        let snapshot_id = Uuid::new_v4().to_string();
        let snap_dir = self.snapshots.prepare_dir(id, &snapshot_id)?;
        let vmstate_path = snap_dir.join("vmstate");
        let mem_path = snap_dir.join("mem");

        let vm = self.get_vm_handle(id)?;
        match req.snapshot_type {
            SnapshotType::Full => {
                vm.create_snapshot(vmstate_path.to_str().unwrap(), mem_path.to_str().unwrap())
                    .await
                    .map_err(VmmError::Sdk)?;
            }
            SnapshotType::Diff => {
                vm.create_diff_snapshot(vmstate_path.to_str().unwrap(), mem_path.to_str().unwrap())
                    .await
                    .map_err(VmmError::Sdk)?;
            }
        }

        let meta = self.snapshots.register(
            id,
            req.name,
            req.snapshot_type,
            vmstate_path,
            Some(mem_path),
            None,
        )?;

        if was_running {
            self.resume_vm(id).await?;
        }

        info!(vm_id = %id, snapshot_id = %meta.id, "snapshot created");
        Ok(SnapshotInfo::from(&meta))
    }

    /// Restore a VM from a snapshot.
    pub async fn restore_vm(&self, spec: RestoreSpec) -> Result<VmId> {
        let id = Uuid::new_v4().to_string();
        let vm_dir = self.store.vm_dir(&id);
        std::fs::create_dir_all(&vm_dir).map_err(VmmError::Io)?;
        let socket_path = vm_dir.join("firecracker.sock");

        let net_alloc = if spec.network_override {
            Some(self.network.allocate(&id)?)
        } else {
            None
        };

        let process = FirecrackerProcessBuilder::new(&self.config.firecracker.binary, &socket_path)
            .id(&id)
            .spawn()
            .await
            .map_err(|e| VmmError::Process(e.to_string()))?;

        let snap_dir = PathBuf::from(&spec.snapshot_dir);
        let vmstate_path = snap_dir.join("vmstate").to_str().unwrap().to_owned();
        let mem_path = snap_dir.join("mem");
        let mem_file_path = if mem_path.exists() {
            Some(mem_path.to_str().unwrap().to_owned())
        } else {
            None
        };

        let mut load_params = fc_sdk::types::SnapshotLoadParams {
            snapshot_path: vmstate_path,
            mem_file_path,
            mem_backend: None,
            enable_diff_snapshots: None,
            track_dirty_pages: None,
            resume_vm: Some(true),
            network_overrides: vec![],
        };

        if let Some(ref net) = net_alloc {
            load_params.network_overrides = vec![NetworkOverride {
                iface_id: "eth0".into(),
                host_dev_name: net.tap_name.clone(),
            }];
        }

        let vm = Arc::new(
            fc_sdk::restore(socket_path.to_str().unwrap(), load_params)
                .await
                .map_err(VmmError::Sdk)?,
        );

        let mut instance = VmInstance::new(
            id.clone(),
            spec.name.clone(),
            VmSpec {
                name: spec.name.clone(),
                ..Default::default()
            },
            socket_path,
        );
        instance.process = Some(process);
        instance.vm = Some(vm);
        instance.state = VmState::Running;
        instance.started_at = Some(chrono::Utc::now());
        instance.network = net_alloc;
        self.store.save(&instance)?;

        {
            let mut instances = self.instances.write().unwrap();
            instances.insert(id.clone(), Arc::new(Mutex::new(instance)));
        }

        info!(vm_id = %id, snapshot_dir = %spec.snapshot_dir, "VM restored");
        Ok(id)
    }

    /// List snapshots for a VM.
    pub fn list_snapshots(&self, id: &VmId) -> Result<Vec<SnapshotInfo>> {
        self.snapshots.list(id)
    }

    /// Delete a snapshot.
    pub fn delete_snapshot(&self, vm_id: &VmId, snapshot_id: &str) -> Result<()> {
        self.snapshots.delete(vm_id, snapshot_id)
    }

    // =========================================================================
    // Metrics / Live Updates
    // =========================================================================

    /// Retrieve balloon metrics for a VM.
    pub async fn get_metrics(&self, id: &VmId) -> Result<VmMetrics> {
        let vm = self.get_vm_handle(id)?;
        let (target, actual) = match vm.balloon_config().await {
            Ok(b) => {
                let stats = vm.balloon_stats().await.ok();
                (Some(b.amount_mib), stats.map(|s| s.actual_mib))
            }
            Err(_) => (None, None),
        };
        Ok(VmMetrics {
            vm_id: id.clone(),
            balloon_target_mib: target,
            balloon_actual_mib: actual,
        })
    }

    /// Adjust the memory balloon target.
    pub async fn update_balloon(&self, id: &VmId, amount_mib: i64) -> Result<()> {
        let vm = self.get_vm_handle(id)?;
        vm.update_balloon(amount_mib).await.map_err(VmmError::Sdk)?;
        Ok(())
    }

    /// Update the balloon statistics polling interval.
    pub async fn update_balloon_stats_interval(&self, id: &VmId, interval_s: i64) -> Result<()> {
        let vm = self.get_vm_handle(id)?;
        vm.update_balloon_stats_interval(interval_s)
            .await
            .map_err(VmmError::Sdk)?;
        Ok(())
    }

    /// Update the hotpluggable memory region size.
    pub async fn update_memory(&self, id: &VmId, size_mib: i64) -> Result<()> {
        let vm = self.get_vm_handle(id)?;
        vm.update_memory_hotplug(Some(size_mib))
            .await
            .map_err(VmmError::Sdk)?;
        Ok(())
    }

    /// Hot-swap a drive path or update its rate limiter.
    pub async fn update_drive(
        &self,
        id: &VmId,
        drive_id: &str,
        path_on_host: Option<String>,
        rate_limit: Option<RateLimitSpec>,
    ) -> Result<()> {
        let vm = self.get_vm_handle(id)?;
        vm.update_drive(
            drive_id,
            PartialDrive {
                drive_id: drive_id.to_owned(),
                path_on_host,
                rate_limiter: rate_limit.map(Into::into),
            },
        )
        .await
        .map_err(VmmError::Sdk)?;
        Ok(())
    }

    /// Update the rate limiters on a network interface.
    pub async fn update_network_interface(
        &self,
        id: &VmId,
        iface_id: &str,
        rx: Option<RateLimitSpec>,
        tx: Option<RateLimitSpec>,
    ) -> Result<()> {
        let vm = self.get_vm_handle(id)?;
        vm.update_network_interface(
            iface_id,
            PartialNetworkInterface {
                iface_id: iface_id.to_owned(),
                rx_rate_limiter: rx.map(Into::into),
                tx_rate_limiter: tx.map(Into::into),
            },
        )
        .await
        .map_err(VmmError::Sdk)?;
        Ok(())
    }

    /// Flush Firecracker metrics to disk immediately.
    pub async fn flush_metrics(&self, id: &VmId) -> Result<()> {
        let vm = self.get_vm_handle(id)?;
        vm.flush_metrics().await.map_err(VmmError::Sdk)?;
        Ok(())
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    fn get_instance(&self, id: &VmId) -> Result<Arc<Mutex<VmInstance>>> {
        self.instances
            .read()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| VmmError::NotFound(id.clone()))
    }

    /// Return a shared `fc_sdk::Vm` handle for the given VM.
    fn get_vm_handle(&self, id: &VmId) -> Result<Arc<fc_sdk::Vm>> {
        let instance = self.get_instance(id)?;
        let inst = instance.lock().unwrap();
        inst.vm
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| VmmError::WrongState {
                id: id.clone(),
                expected: "Running or Paused".into(),
                actual: inst.state.to_string(),
            })
    }

    fn set_state(&self, id: &VmId, state: VmState) -> Result<()> {
        let instance = self.get_instance(id)?;
        let mut inst = instance.lock().unwrap();
        inst.state = state;
        self.store.save(&inst)?;
        Ok(())
    }
}
