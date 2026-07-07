//! Main VMM implementation.
//!
//! The VMM (Virtual Machine Monitor) orchestrates all components needed to run
//! a virtual machine: hypervisor, vCPUs, memory, and devices.
//!
//! Platform-specific logic lives in submodules:
//! - `darwin`: macOS (Virtualization.framework) managed execution
//! - `linux`: Linux (KVM) manual execution

#[cfg(target_os = "macos")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::device::DeviceManager;
use crate::error::{Result, VmmError};
use crate::event::EventLoop;
use crate::irq::IrqChip;
use crate::memory::MemoryManager;
#[cfg(target_os = "linux")]
use crate::vcpu::VcpuManager;

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "macos")]
mod darwin_hv;
#[cfg(target_os = "linux")]
mod linux;

mod config;
mod event_handlers;
mod helpers;
#[cfg(test)]
mod tests;

pub use config::{BlockDeviceConfig, SharedDirConfig, VmBackend, VmmConfig, VmmState};
use helpers::placeholder_vcpu_snapshots;

/// Virtual Machine Monitor.
///
/// Manages the complete lifecycle of a virtual machine including
/// vCPUs, memory, and devices.
///
/// # Example
///
/// ```ignore
/// use arcbox_vmm::{Vmm, VmmConfig};
/// use std::path::PathBuf;
///
/// let config = VmmConfig {
///     vcpu_count: 2,
///     memory_size: 1024 * 1024 * 1024, // 1GB
///     kernel_path: PathBuf::from("/path/to/vmlinux"),
///     kernel_cmdline: "console=ttyS0".to_string(),
///     guest_cid: Some(3),
///     ..Default::default()
/// };
///
/// let mut vmm = Vmm::new(config)?;
/// vmm.start()?;
/// ```
pub struct Vmm {
    /// Configuration.
    config: VmmConfig,
    /// Current state.
    state: VmmState,
    /// Running flag for graceful shutdown.
    running: Arc<AtomicBool>,
    /// vCPU manager (Linux only — KVM uses manual execution).
    #[cfg(target_os = "linux")]
    vcpu_manager: Option<VcpuManager>,
    /// Memory manager.
    memory_manager: Option<MemoryManager>,
    /// Device manager.
    device_manager: Option<DeviceManager>,
    /// IRQ chip (Arc for sharing with callback).
    irq_chip: Option<Arc<IrqChip>>,
    /// Event loop.
    event_loop: Option<EventLoop>,
    /// When true, Drop will skip calling into the hypervisor stop path.
    /// Used when the guest has already halted (e.g. ACPI shutdown) and the
    /// hypervisor teardown would crash. FDs and other resources are still freed.
    skip_hypervisor_stop: bool,
    /// Typed VM handle — Virtualization.framework managed VM.
    #[cfg(target_os = "macos")]
    darwin_vm: Option<arcbox_hypervisor::darwin::DarwinVm>,
    /// Typed VM handle — KVM VM (Arc for sharing with IRQ callback).
    #[cfg(target_os = "linux")]
    linux_vm: Option<Arc<std::sync::Mutex<arcbox_hypervisor::linux::KvmVm>>>,
    /// Cancellation token for the network datapath task (Darwin only).
    #[cfg(target_os = "macos")]
    net_cancel: Option<tokio_util::sync::CancellationToken>,
    /// VZ side network fd for `VZFileHandleNetworkDeviceAttachment` lifecycle.
    /// Kept open while the VM is running and closed on stop.
    #[cfg(target_os = "macos")]
    net_vz_fd: Option<OwnedFd>,
    /// Inbound listener manager for port forwarding (Darwin only).
    #[cfg(target_os = "macos")]
    inbound_listener_manager: Option<arcbox_net::darwin::inbound_relay::InboundListenerManager>,
    /// Shared DNS hosts table from NetworkManager.
    #[cfg(target_os = "macos")]
    shared_dns_hosts: Option<std::sync::Arc<arcbox_dns::LocalHostsTable>>,
    /// Kernel entry address for the custom HV VMM path (stored during
    /// `initialize_darwin_hv`, consumed by `start_darwin_hv`).
    #[cfg(target_os = "macos")]
    hv_kernel_entry: Option<u64>,
    /// FDT load address for the custom HV VMM path.
    #[cfg(target_os = "macos")]
    hv_fdt_addr: Option<u64>,
    /// vCPU thread join handles for the custom HV VMM path.
    #[cfg(target_os = "macos")]
    hv_vcpu_threads: Vec<std::thread::JoinHandle<()>>,
    /// Shared vCPU thread handle registry for WFI unparking (custom HV).
    #[cfg(target_os = "macos")]
    hv_vcpu_thread_handles: Option<darwin_hv::VcpuThreadHandles>,
    /// Shared registry of Hypervisor.framework vCPU IDs (custom HV).
    /// Populated by each vCPU thread after it creates its `HvVcpu`. Used
    /// by `pause`/`stop` to target `hv_vcpus_exit` correctly on arm64.
    #[cfg(target_os = "macos")]
    hv_vcpu_ids: Option<darwin_hv::HvVcpuIds>,
    /// PSCI CPU_ON channel senders for secondary vCPUs (custom HV).
    #[cfg(target_os = "macos")]
    #[allow(clippy::type_complexity)]
    hv_cpu_on_senders: Option<
        std::sync::Arc<
            std::sync::Mutex<Vec<Option<std::sync::mpsc::Sender<darwin_hv::CpuOnRequest>>>>,
        >,
    >,
    /// vmnet bridge interface for the bridge NIC (`vmnet` feature only).
    #[cfg(all(target_os = "macos", feature = "vmnet"))]
    vmnet_bridge: Option<std::sync::Arc<arcbox_vmnet::Vmnet>>,
    /// Cancellation token for the vmnet relay task.
    #[cfg(all(target_os = "macos", feature = "vmnet"))]
    vmnet_relay_cancel: Option<tokio_util::sync::CancellationToken>,
    /// VZ-side fd for the vmnet bridge NIC attachment.
    #[cfg(all(target_os = "macos", feature = "vmnet"))]
    vmnet_bridge_fd: Option<OwnedFd>,
    /// Shared DeviceManager reference for HV backend (set during start_darwin_hv).
    /// Used by connect_vsock_hv to inject OP_REQUEST packets after VM starts.
    ///
    /// Declared before `hv_vm` so it drops first: `FsServer` inside the
    /// DeviceManager holds `Arc<HvDaxMapper>` handles that call
    /// `hv_vm_unmap` on drop. Those must complete before `hv_vm_destroy`.
    #[cfg(target_os = "macos")]
    hv_device_manager: Option<std::sync::Arc<DeviceManager>>,
    /// vsock-io worker thread handle (custom HV). Owns host→guest vsock
    /// injection; joined in `stop_darwin_hv` before guest memory drops.
    #[cfg(target_os = "macos")]
    hv_vsock_worker: Option<std::thread::JoinHandle<()>>,
    /// Debug-console RX worker thread handle (custom HV). Only present when
    /// `debug_console_socket` is configured; joined in `stop_darwin_hv`.
    #[cfg(target_os = "macos")]
    hv_console_worker: Option<std::thread::JoinHandle<()>>,
    /// HV-side network fd (NIC1). Paired with the NetworkDatapath fd.
    /// Kept alive so the socketpair stays open while the VM runs.
    #[cfg(target_os = "macos")]
    hv_net_fd: Option<OwnedFd>,
    /// HV-side bridge network fd (NIC2). Paired with the VmnetRelay fd.
    /// Kept alive so the vmnet socketpair stays open while the VM runs.
    #[cfg(target_os = "macos")]
    hv_bridge_net_fd: Option<OwnedFd>,
    /// Block device info captured during initialize for worker thread spawn.
    #[cfg(target_os = "macos")]
    /// (DeviceId, raw_fd, blk_size, capacity_sectors, read_only, device_id_string, num_queues)
    hv_blk_devices: Vec<(crate::device::DeviceId, i32, u32, u64, bool, String, u16)>,
    /// Block I/O worker thread handles for join on shutdown.
    #[cfg(target_os = "macos")]
    hv_blk_worker_threads: Vec<std::thread::JoinHandle<()>>,
    /// HVC fast path: device_idx → (raw_fd, blk_size, capacity_sectors). Shared with vCPU threads.
    #[cfg(target_os = "macos")]
    hvc_blk_fds: Arc<Vec<(i32, u32, u64)>>,
    /// Per-VirtioFS-share DAX mappers (concrete type).
    ///
    /// One `Arc<HvDaxMapper>` per configured shared directory, in the
    /// same order as `config.shared_dirs`. The mapper itself is also
    /// handed to the `FsServer` as a `dyn DaxMapper` trait object —
    /// both Arcs point to the same underlying counters, so
    /// `dax_stats(share_idx)` reports live values as the guest issues
    /// `FUSE_SETUPMAPPING` / `FUSE_REMOVEMAPPING` requests.
    ///
    /// Declared before `hv_vm` so implicit Drop order is safe: any
    /// remaining `Arc<HvDaxMapper>` refs call `hv_vm_unmap` before
    /// `hv_vm_destroy` runs. `stop_darwin_hv` explicitly calls
    /// `drain_all` first, making implicit drop a no-op for the normal path.
    #[cfg(target_os = "macos")]
    hv_dax_mappers: Vec<std::sync::Arc<crate::dax::HvDaxMapper>>,
    /// HV backend balloon device handle (ABX-363).
    ///
    /// `None` until `initialize_darwin_hv` registers the device (only
    /// happens when `config.balloon` is true). Used by the HV dispatch
    /// path in `darwin.rs` for `set_balloon_target` / `get_balloon_stats`.
    #[cfg(target_os = "macos")]
    hv_balloon: Option<std::sync::Arc<std::sync::Mutex<arcbox_virtio::balloon::VirtioBalloon>>>,
    /// GICv3 handle (custom VMM path, macOS 15+).
    ///
    /// **Drop order — must be declared before `hv_vm`.**
    /// Rust drops struct fields in declaration order (top to bottom). The GIC
    /// interrupt controller holds internal references into the VM; its FFI
    /// destroy/release routines must run while the VM is still alive.
    /// Declaring `hv_gic` before `hv_vm` guarantees that on any exit path
    /// (both the normal `stop_darwin_hv` and the panic / implicit-drop path),
    /// the GIC is torn down before `hv_vm_destroy` is called.
    #[cfg(all(target_os = "macos", feature = "gic"))]
    hv_gic: Option<std::sync::Arc<arcbox_hv::Gic>>,
    /// Hypervisor.framework VM handle (custom VMM path).
    ///
    /// **Drop order — must be declared after `hv_gic`, `hv_dax_mappers`,
    /// and `hv_device_manager`.**
    /// Rust drops fields in declaration order (top to bottom), so fields
    /// declared above this one drop first. This ordering ensures:
    ///   1. `hv_device_manager` (FsServer → Arc<HvDaxMapper> → hv_vm_unmap)
    ///   2. `hv_dax_mappers` (remaining mapper refs → hv_vm_unmap)
    ///   3. `hv_gic` (GIC FFI teardown referencing the live VM)
    ///   4. `hv_vm` → `hv_vm_destroy`
    ///   5. `hv_guest_mem` (mmap'd pages — must outlive the VM)
    ///
    /// `stop_darwin_hv` also calls `drain_all` explicitly for the normal
    /// path; this declaration ordering is the safety net for panic paths.
    #[cfg(target_os = "macos")]
    hv_vm: Option<arcbox_hv::HvVm>,
    /// Guest memory backing (vm-memory mmap, custom VMM path).
    ///
    /// **Drop order — must be declared after `hv_vm`.**
    /// The mmap'd pages must remain accessible until after `hv_vm_destroy`
    /// releases all stage-2 mappings. Declaring this last ensures the host
    /// VA range is freed only after the VM no longer references it.
    #[cfg(target_os = "macos")]
    hv_guest_mem: Option<darwin_hv::HvGuestMem>,
    /// Cooperative pause flag for the HV backend.
    ///
    /// When set to `true`, every vCPU thread parks itself after its next
    /// `vcpu.run()` return instead of re-entering guest execution. `resume`
    /// clears the flag and unparks the threads. Orthogonal to `running`
    /// (which is a terminal stop signal).
    #[cfg(target_os = "macos")]
    hv_paused: Arc<AtomicBool>,
}

impl Vmm {
    /// Creates a new VMM with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    pub fn new(config: VmmConfig) -> Result<Self> {
        // Validate configuration
        if config.vcpu_count == 0 {
            return Err(VmmError::config("vcpu_count must be > 0".to_string()));
        }

        if config.memory_size < 64 * 1024 * 1024 {
            return Err(VmmError::config("memory_size must be >= 64MB".to_string()));
        }

        if !config.kernel_path.as_os_str().is_empty() && !config.kernel_path.exists() {
            return Err(VmmError::config(format!(
                "kernel not found: {}",
                config.kernel_path.display()
            )));
        }
        if config.vsock && config.guest_cid.is_none() {
            return Err(VmmError::config(
                "guest_cid must be set when vsock is enabled".to_string(),
            ));
        }

        tracing::info!(
            "Creating VMM: vcpus={}, memory={}MB",
            config.vcpu_count,
            config.memory_size / (1024 * 1024)
        );

        Ok(Self {
            config,
            state: VmmState::Created,
            running: Arc::new(AtomicBool::new(false)),
            #[cfg(target_os = "linux")]
            vcpu_manager: None,
            memory_manager: None,
            device_manager: None,
            irq_chip: None,
            event_loop: None,
            skip_hypervisor_stop: false,
            #[cfg(target_os = "macos")]
            darwin_vm: None,
            #[cfg(target_os = "linux")]
            linux_vm: None,
            #[cfg(target_os = "macos")]
            net_cancel: None,
            #[cfg(target_os = "macos")]
            net_vz_fd: None,
            #[cfg(target_os = "macos")]
            inbound_listener_manager: None,
            #[cfg(target_os = "macos")]
            shared_dns_hosts: None,
            #[cfg(target_os = "macos")]
            hv_kernel_entry: None,
            #[cfg(target_os = "macos")]
            hv_fdt_addr: None,
            #[cfg(target_os = "macos")]
            hv_vcpu_threads: Vec::new(),
            #[cfg(target_os = "macos")]
            hv_vcpu_thread_handles: None,
            #[cfg(target_os = "macos")]
            hv_vcpu_ids: None,
            #[cfg(target_os = "macos")]
            hv_cpu_on_senders: None,
            #[cfg(all(target_os = "macos", feature = "vmnet"))]
            vmnet_bridge: None,
            #[cfg(all(target_os = "macos", feature = "vmnet"))]
            vmnet_relay_cancel: None,
            #[cfg(all(target_os = "macos", feature = "vmnet"))]
            vmnet_bridge_fd: None,
            #[cfg(all(target_os = "macos", feature = "gic"))]
            hv_gic: None,
            #[cfg(target_os = "macos")]
            hv_vm: None,
            #[cfg(target_os = "macos")]
            hv_guest_mem: None,
            #[cfg(target_os = "macos")]
            hv_device_manager: None,
            #[cfg(target_os = "macos")]
            hv_vsock_worker: None,
            #[cfg(target_os = "macos")]
            hv_console_worker: None,
            #[cfg(target_os = "macos")]
            hv_net_fd: None,
            hv_bridge_net_fd: None,
            #[cfg(target_os = "macos")]
            hv_blk_devices: Vec::new(),
            #[cfg(target_os = "macos")]
            hv_blk_worker_threads: Vec::new(),
            #[cfg(target_os = "macos")]
            hvc_blk_fds: Arc::new(Vec::new()),
            #[cfg(target_os = "macos")]
            hv_dax_mappers: Vec::new(),
            #[cfg(target_os = "macos")]
            hv_balloon: None,
            #[cfg(target_os = "macos")]
            hv_paused: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Returns the current VMM state.
    #[must_use]
    pub const fn state(&self) -> VmmState {
        self.state
    }

    /// Returns whether the VMM is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Returns a clone of the running flag for external monitoring.
    #[must_use]
    pub fn running_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.running)
    }

    /// Sets the shared DNS hosts table from the host-side `NetworkManager`.
    ///
    /// Must be called before `initialize()`. When set, the VMM-side
    /// `DnsForwarder` (in the network datapath) shares this table so that
    /// host-side `register_dns()` calls are visible to guest DNS queries.
    #[cfg(target_os = "macos")]
    pub fn set_shared_dns_hosts(&mut self, table: std::sync::Arc<arcbox_dns::LocalHostsTable>) {
        self.shared_dns_hosts = Some(table);
    }

    /// Returns vmnet interface info for the bridge NIC, if available.
    ///
    /// Only populated when `vmnet` feature is enabled and interface started.
    #[cfg(all(target_os = "macos", feature = "vmnet"))]
    #[must_use]
    pub fn vmnet_interface_info(&self) -> Option<arcbox_vmnet::VmnetInterfaceInfo> {
        self.vmnet_bridge
            .as_ref()
            .and_then(|v| v.interface_info().cloned())
    }

    /// Initializes the VMM components.
    ///
    /// This sets up the hypervisor, VM, memory, devices, and vCPUs.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub fn initialize(&mut self) -> Result<()> {
        if self.state != VmmState::Created {
            return Err(VmmError::invalid_state(format!(
                "cannot initialize from state {:?}",
                self.state
            )));
        }

        self.state = VmmState::Initializing;
        tracing::info!("Initializing VMM");

        // Platform-specific initialization
        #[cfg(target_os = "macos")]
        {
            tracing::info!("VM backend: {:?}", self.config.backend);
            match self.config.backend {
                VmBackend::Hv => self.initialize_darwin_hv()?,
                VmBackend::Vz => self.initialize_darwin()?,
            }
        }

        #[cfg(target_os = "linux")]
        {
            self.initialize_linux()?;
        }

        tracing::info!("VMM initialized successfully");
        Ok(())
    }

    /// Starts the VMM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VMM cannot be started.
    pub fn start(&mut self) -> Result<()> {
        // Initialize if not already done
        if self.state == VmmState::Created {
            self.initialize()?;
        }

        if self.state != VmmState::Initializing && self.state != VmmState::Stopped {
            return Err(VmmError::invalid_state(format!(
                "cannot start from state {:?}",
                self.state
            )));
        }

        tracing::info!("Starting VMM");

        // Darwin: dispatch to the resolved backend.
        // Linux: start vCPU threads for manual execution.
        #[cfg(target_os = "macos")]
        {
            match self.config.backend {
                VmBackend::Hv => self.start_darwin_hv()?,
                VmBackend::Vz => self.start_darwin_vm()?,
            }
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(ref mut vcpu_manager) = self.vcpu_manager {
                vcpu_manager.start()?;
            }
        }

        // Start event loop
        if let Some(ref mut event_loop) = self.event_loop {
            event_loop.start()?;
        }

        self.running.store(true, Ordering::SeqCst);
        self.state = VmmState::Running;

        tracing::info!("VMM started");
        Ok(())
    }

    /// Pauses the VMM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VMM cannot be paused.
    pub fn pause(&mut self) -> Result<()> {
        if self.state != VmmState::Running {
            return Err(VmmError::invalid_state(format!(
                "cannot pause from state {:?}",
                self.state
            )));
        }

        tracing::info!("Pausing VMM");

        #[cfg(target_os = "macos")]
        {
            match self.config.backend {
                VmBackend::Hv => self.pause_darwin_hv()?,
                VmBackend::Vz => self.pause_darwin_vm()?,
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(ref mut vcpu_manager) = self.vcpu_manager {
            vcpu_manager.pause()?;
        }

        self.state = VmmState::Paused;
        tracing::info!("VMM paused");
        Ok(())
    }

    /// Resumes a paused VMM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VMM cannot be resumed.
    pub fn resume(&mut self) -> Result<()> {
        if self.state != VmmState::Paused {
            return Err(VmmError::invalid_state(format!(
                "cannot resume from state {:?}",
                self.state
            )));
        }

        tracing::info!("Resuming VMM");

        #[cfg(target_os = "macos")]
        {
            match self.config.backend {
                VmBackend::Hv => self.resume_darwin_hv()?,
                VmBackend::Vz => self.resume_darwin_vm()?,
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(ref mut vcpu_manager) = self.vcpu_manager {
            vcpu_manager.resume()?;
        }

        self.state = VmmState::Running;
        tracing::info!("VMM resumed");
        Ok(())
    }

    /// Stops the VMM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VMM cannot be stopped.
    pub fn stop(&mut self) -> Result<()> {
        if self.state == VmmState::Stopped {
            return Ok(());
        }

        tracing::info!("Stopping VMM");
        self.state = VmmState::Stopping;
        self.running.store(false, Ordering::SeqCst);

        // Stop event loop first
        if let Some(ref mut event_loop) = self.event_loop {
            event_loop.stop();
        }

        // Darwin: stop the resolved backend before canceling the network datapath.
        // Linux: stop vCPU threads.
        #[cfg(target_os = "macos")]
        {
            match self.config.backend {
                VmBackend::Hv => self.stop_darwin_hv()?,
                VmBackend::Vz => self.stop_darwin_vm()?,
            }
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(ref mut vcpu_manager) = self.vcpu_manager {
                vcpu_manager.stop()?;
            }
        }

        // Cancel custom file-handle network datapath after VM stop.
        #[cfg(target_os = "macos")]
        self.stop_network();

        self.state = VmmState::Stopped;
        tracing::info!("VMM stopped");
        Ok(())
    }

    /// Returns the configured memory size for this VM.
    ///
    /// This is the maximum memory the guest can use when the balloon is fully deflated.
    #[must_use]
    pub const fn configured_memory(&self) -> u64 {
        self.config.memory_size
    }

    /// Returns whether a balloon device is configured for this VM.
    #[must_use]
    pub const fn has_balloon(&self) -> bool {
        self.config.balloon
    }

    /// Returns a snapshot of DAX counters for the given VirtioFS share
    /// index (0-based, in the order of `config.shared_dirs`). Only
    /// meaningful on the HV backend — the VZ path does not use
    /// `HvDaxMapper`. Returns `None` if the index is out of range or
    /// DAX mappers have not been initialized yet.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn dax_stats(&self, share_idx: usize) -> Option<crate::dax::DaxStats> {
        self.hv_dax_mappers.get(share_idx).map(|m| m.stats())
    }

    /// Captures a VM snapshot context from the running hypervisor VM.
    ///
    /// The returned context contains device state and full guest memory.
    /// vCPU register snapshots are currently placeholder values based on
    /// configured vCPU count.
    ///
    /// # Errors
    ///
    /// Returns an error if VM state is not snapshotable or VM handles are missing.
    pub fn capture_snapshot_context(&self) -> Result<crate::snapshot::VmSnapshotContext> {
        if self.state != VmmState::Running && self.state != VmmState::Paused {
            return Err(VmmError::invalid_state(format!(
                "cannot capture snapshot from state {:?}",
                self.state
            )));
        }

        #[cfg(target_os = "linux")]
        if let Some(result) = self.capture_snapshot_linux() {
            return result;
        }

        #[cfg(target_os = "macos")]
        {
            if matches!(self.config.backend, VmBackend::Hv) {
                return Err(VmmError::Unsupported(
                    "snapshot capture is not yet implemented for the HV backend".to_string(),
                ));
            }
            if let Some(result) = self.capture_snapshot_darwin() {
                return result;
            }
        }

        Err(VmmError::invalid_state(
            "hypervisor VM handle is unavailable for snapshot".to_string(),
        ))
    }

    /// Applies restored device + memory state to the running VM.
    ///
    /// # Errors
    ///
    /// Returns an error if restore cannot be applied.
    pub fn restore_from_snapshot_data(
        &mut self,
        restore_data: &crate::snapshot::VmRestoreData,
    ) -> Result<()> {
        if self.state != VmmState::Running && self.state != VmmState::Paused {
            return Err(VmmError::invalid_state(format!(
                "cannot restore snapshot from state {:?}",
                self.state
            )));
        }

        let expected_memory_len = usize::try_from(restore_data.memory_size()).map_err(|_| {
            VmmError::Memory(format!(
                "snapshot memory size {} does not fit in usize",
                restore_data.memory_size()
            ))
        })?;

        if restore_data.memory().len() != expected_memory_len {
            return Err(VmmError::Memory(format!(
                "snapshot memory length mismatch: expected {}, got {}",
                expected_memory_len,
                restore_data.memory().len()
            )));
        }

        #[cfg(target_os = "linux")]
        if let Some(result) = self.restore_snapshot_linux(restore_data) {
            return result;
        }

        #[cfg(target_os = "macos")]
        {
            if matches!(self.config.backend, VmBackend::Hv) {
                return Err(VmmError::Unsupported(
                    "snapshot restore is not yet implemented for the HV backend".to_string(),
                ));
            }
            if let Some(result) = self.restore_snapshot_darwin(restore_data) {
                return result;
            }
        }

        Err(VmmError::invalid_state(
            "hypervisor VM handle is unavailable for restore".to_string(),
        ))
    }

    /// Runs the VMM until it exits.
    ///
    /// This is the main event loop that blocks until the VM exits.
    ///
    /// # Errors
    ///
    /// Returns an error if the VMM encounters a fatal error.
    pub async fn run(&mut self) -> Result<()> {
        // Start if not already running
        if self.state != VmmState::Running {
            self.start()?;
        }

        tracing::info!("VMM running, waiting for exit");

        // Main event loop
        while self.is_running() {
            // Poll event loop
            if let Some(ref mut event_loop) = self.event_loop {
                if let Some(event) = event_loop.poll().await {
                    self.handle_event(event);
                }
            }

            // Small yield to prevent busy spinning
            tokio::task::yield_now().await;
        }

        tracing::info!("VMM exited");
        Ok(())
    }
}

impl Vmm {
    /// Marks this VMM to skip the Virtualization.framework stop path on drop.
    ///
    /// macOS-only: the VF stop call can crash when the guest has already
    /// halted via ACPI. FDs and network resources are still cleaned up.
    /// Must only be called after ACPI shutdown.
    #[cfg(target_os = "macos")]
    pub fn set_skip_hypervisor_stop(&mut self) {
        self.skip_hypervisor_stop = true;
        self.mark_darwin_vm_skip_stop();
    }
}

impl Drop for Vmm {
    fn drop(&mut self) {
        if self.state != VmmState::Stopped && self.state != VmmState::Created {
            if self.skip_hypervisor_stop {
                // The hypervisor stop path is unsafe (VF may crash when guest
                // already halted). Only clean up network resources.
                #[cfg(target_os = "macos")]
                self.stop_network();
                self.state = VmmState::Stopped;
            } else {
                let _ = self.stop();
            }
        }
    }
}
