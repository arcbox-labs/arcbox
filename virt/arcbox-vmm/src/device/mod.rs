//! Device registry and MMIO dispatch for the custom VMM.
//!
//! `DeviceManager` owns a registry of `RegisteredDevice` entries (one per
//! virtio-mmio device) and routes guest MMIO accesses to the right
//! `VirtioDevice` implementation. Per-device hot paths (TX descriptor
//! drain, RX injection, vsock connection state) live on the device
//! structs in `arcbox-virtio` itself; the manager only handles the
//! transport-level dispatch and a few typed shortcuts (`primary_net`,
//! `bridge_net`, `vsock`) for VMM-driven setup and bookkeeping.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

#[cfg(test)]
use arcbox_virtio::net::VirtioNetHeader;
use arcbox_virtio::{DeviceStatus, QueueConfig, VirtioDevice};

use crate::error::{Result, VmmError};
use crate::irq::{Irq, IrqChip};
use crate::memory::MemoryManager;

mod checksum;
mod mmio_state;
pub(crate) mod net_worker;

use checksum::finalize_virtio_net_checksum;
pub use mmio_state::{MmioDevice, VirtioMmioState, virtio_mmio};

/// Device identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(u32);

impl DeviceId {
    /// Creates a new device ID.
    #[must_use]
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the raw ID value.
    #[must_use]
    pub const fn raw(&self) -> u32 {
        self.0
    }
}

/// Device type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// Serial port.
    Serial,
    /// `VirtIO` block device.
    VirtioBlock,
    /// `VirtIO` network device.
    VirtioNet,
    /// `VirtIO` console.
    VirtioConsole,
    /// `VirtIO` filesystem.
    VirtioFs,
    /// `VirtIO` vsock.
    VirtioVsock,
    /// `VirtIO` entropy (RNG).
    VirtioRng,
    /// `VirtIO` memory balloon.
    VirtioBalloon,
    /// Other device.
    Other,
}

/// Device information.
#[derive(Debug)]
pub struct DeviceInfo {
    /// Device ID.
    pub id: DeviceId,
    /// Device type.
    pub device_type: DeviceType,
    /// Device name.
    pub name: String,
    /// MMIO base address.
    pub mmio_base: Option<u64>,
    /// MMIO size.
    pub mmio_size: u64,
    /// Assigned IRQ.
    pub irq: Option<Irq>,
}

/// A registered device with MMIO state and `VirtIO` device implementation.
pub struct RegisteredDevice {
    pub info: DeviceInfo,
    pub mmio_state: Option<Arc<RwLock<VirtioMmioState>>>,
    /// The actual `VirtIO` device implementation.
    pub virtio_device: Option<Arc<Mutex<dyn VirtioDevice>>>,
}

/// IRQ trigger callback type for device-initiated interrupts.
pub type DeviceIrqCallback = Arc<dyn Fn(Irq, bool) -> Result<()> + Send + Sync>;

/// Manages devices attached to the VM.
pub struct DeviceManager {
    devices: HashMap<DeviceId, RegisteredDevice>,
    next_id: u32,
    /// MMIO address to device mapping.
    mmio_map: HashMap<u64, DeviceId>,
    /// Base pointer to guest physical memory (set by custom HV path).
    guest_ram_base: Option<*mut u8>,
    /// Size of guest physical memory in bytes.
    guest_ram_size: usize,
    /// GPA where the guest RAM region starts (e.g. 0x40000000).
    /// Used to translate descriptor GPAs to memory slice offsets.
    guest_ram_gpa: u64,
    /// IRQ trigger callback for injecting interrupts into the guest.
    irq_callback: Option<DeviceIrqCallback>,
    /// DeviceId of the primary VirtioNet (NIC1) for targeted IRQ delivery
    /// and worker-spawn dispatch. Required because
    /// `raise_interrupt_for(DeviceType::VirtioNet)` uses HashMap iteration
    /// which is non-deterministic — with two VirtioNet devices it could
    /// match the bridge NIC instead of the primary NIC.
    primary_net_device_id: Option<DeviceId>,
    /// Typed handle to the primary VirtioNet (NIC1 — NAT datapath).
    /// Shares the same `Arc<Mutex<_>>` as the generic entry in `devices`;
    /// exposes the concrete device so QUEUE_NOTIFY dispatch can call
    /// inherent hot-path methods without dyn dispatch. Host fd and TX
    /// avail-index cursor live on the device via `NetPort`.
    primary_net: Option<Arc<Mutex<arcbox_virtio::net::VirtioNet>>>,
    /// DeviceId of the bridge VirtioNet so QUEUE_NOTIFY can dispatch correctly
    /// to `bridge_net` without a HashMap lookup.
    bridge_net_device_id: Option<DeviceId>,
    /// Typed handle to the bridge VirtioNet (NIC2 — vmnet bridge). Shares
    /// the same `Arc<Mutex<_>>` as the generic entry in `devices`; exposes
    /// the concrete device so DeviceManager can call inherent hot-path
    /// methods (`handle_tx`, `poll_rx`) without dyn dispatch. Host fd and
    /// TX avail-index cursor live on the device itself via `NetPort`.
    bridge_net: Option<Arc<Mutex<arcbox_virtio::net::VirtioNet>>>,
    /// Host-side vsock connection manager (HV backend only). Same `Arc`
    /// is also bound onto the `vsock` typed shortcut's device via
    /// `bind_connections`, so the device's `process_queue` can read it
    /// directly without `QueueConfig` plumbing.
    vsock_connections:
        std::sync::Arc<std::sync::Mutex<crate::vsock_manager::VsockConnectionManager>>,
    /// Typed handle to the VirtioVsock device. Shares the same `Arc`
    /// stored in `devices`. Used by `set_vsock` to bind the device's
    /// `DeviceCtx` and connection manager at registration time.
    vsock: Option<Arc<Mutex<arcbox_virtio::vsock::VirtioVsock>>>,
    /// Per-block-device async I/O worker handles. When present, QUEUE_NOTIFY
    /// for block devices is dispatched to the worker instead of processing
    /// synchronously on the vCPU thread.
    /// Block-I/O worker senders (one queue per `BlkWorkerHandle`).
    ///
    /// Wrapped in a `Mutex` so `stop_darwin_hv` can drop all senders
    /// during shutdown (`clear_blk_workers`) from an `Arc<DeviceManager>`
    /// handle. Dropping the senders is what lets `rx.recv()` in
    /// `blk_io_worker_loop` return `Err(RecvError)` and the worker thread
    /// exit promptly — see ABX-364.
    blk_workers: Mutex<HashMap<DeviceId, crate::blk_worker::BlkWorkerHandle>>,
    /// Network RX worker lifecycle (resource collection + spawn + join).
    net_rx_worker: net_worker::NetRxWorkerSlot,
}

// SAFETY: `DeviceManager` contains several types that are not `Send`/`Sync`
// by default; we assert it manually because the actual access discipline is:
//
// * `guest_ram_base: *mut u8` — initialized once at VM start, then treated
//   as read-only from the struct's perspective. All mutation of the pointee
//   happens through slice views reconstructed per-call under either the
//   vCPU thread's exclusive lock or the per-device `mmio_state`/`virtio_dev`
//   lock. No pointer arithmetic escapes the struct.
//
// * `primary_net` / `bridge_net` / `vsock: Option<Arc<Mutex<...>>>` —
//   typed shortcuts; the same `Arc` is stored in the `devices` HashMap
//   via type erasure. Hot paths read OnceLock-guarded `NetPort` and
//   atomics directly — no mutex contention on the TX fast path.
//
// * `vsock_connections`, `blk_workers`, `net_rx_worker` — each uses its
//   own `Arc<Mutex<...>>` / `Mutex<...>` / crossbeam channel, providing
//   per-field thread safety.
//
// Cross-thread invariant: the raw `*mut u8` in `guest_ram_base` must never
// be used to produce two overlapping `&mut [u8]` slices live at the same
// time. This is upheld by construction — each caller builds a fresh slice
// under the appropriate lock, uses it briefly, then drops it.
unsafe impl Send for DeviceManager {}
unsafe impl Sync for DeviceManager {}

impl DeviceManager {
    /// Creates a new device manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
            next_id: 0,
            mmio_map: HashMap::new(),
            guest_ram_base: None,
            guest_ram_size: 0,
            guest_ram_gpa: 0,
            irq_callback: None,
            primary_net_device_id: None,
            primary_net: None,
            bridge_net_device_id: None,
            bridge_net: None,
            vsock_connections: std::sync::Arc::new(std::sync::Mutex::new(
                crate::vsock_manager::VsockConnectionManager::new(),
            )),
            vsock: None,
            blk_workers: Mutex::new(HashMap::new()),
            net_rx_worker: net_worker::NetRxWorkerSlot::new(),
        }
    }

    /// Provides guest physical memory access for queue processing.
    ///
    /// # Safety
    ///
    /// The caller must guarantee all of the following for the entire
    /// lifetime of this `DeviceManager`:
    ///
    /// * `base` is non-null and points to an allocation of at least `size`
    ///   bytes (the backing guest RAM mapping returned by the hypervisor).
    /// * The allocation is not unmapped, moved, or freed until after this
    ///   `DeviceManager` is dropped.
    /// * No other Rust reference produces a `&mut [u8]` over the same
    ///   region concurrently — internal code only constructs fresh slices
    ///   under device or vCPU locks.
    /// * `gpa_base` is the guest physical address where `base` is mapped;
    ///   descriptor GPAs are translated by subtracting `gpa_base`.
    pub unsafe fn set_guest_memory(&mut self, base: *mut u8, size: usize, gpa_base: u64) {
        self.guest_ram_base = Some(base);
        self.guest_ram_size = size;
        self.guest_ram_gpa = gpa_base;
    }

    /// Sets the callback used to inject interrupts into the guest.
    pub fn set_irq_callback(&mut self, callback: DeviceIrqCallback) {
        self.irq_callback = Some(callback);
    }

    /// Sets the host-side network fd for HV path frame exchange (NIC1).
    ///
    /// The fd is (a) bound onto the primary `VirtioNet` itself via
    /// `NetPort` so the device's TX hot path can write to it directly,
    /// and (b) copied into `net_host_fd_slot` so the DRIVER_OK handler
    /// can still take ownership for the net-io worker thread.
    pub fn set_net_host_fd(&mut self, fd: std::os::unix::io::RawFd, device_id: DeviceId) {
        use arcbox_virtio::net::NetPort;
        self.primary_net_device_id = Some(device_id);
        self.net_rx_worker.set_host_fd(fd);

        if let Some(primary) = self.primary_net.as_ref() {
            let port = NetPort {
                host_fd: fd,
                last_avail_tx: std::sync::atomic::AtomicU16::new(0),
            };
            if let Ok(dev) = primary.lock() {
                if dev.bind_port(port).is_err() {
                    tracing::warn!("primary_net port already bound — ignoring rebind");
                }
            }
        } else {
            tracing::error!("set_net_host_fd called before set_primary_net");
        }
    }

    /// Registers a typed handle to the primary VirtioNet (NIC1) and binds
    /// its `DeviceCtx`. Must be called after `set_guest_memory` +
    /// `set_irq_callback` so both ingredients exist, and before
    /// `set_net_host_fd` so the fd binding can reach the concrete device.
    pub fn set_primary_net(
        &mut self,
        device_id: DeviceId,
        device: Arc<Mutex<arcbox_virtio::net::VirtioNet>>,
    ) {
        self.primary_net_device_id = Some(device_id);

        if let Some(ctx) = self.build_device_ctx(device_id) {
            if let Ok(mut dev) = device.lock() {
                dev.bind_ctx(ctx);
            }
        } else {
            tracing::warn!(
                "set_primary_net: DeviceCtx not built (guest_mem or irq_callback missing) — \
                 primary NIC hot paths will be no-ops"
            );
        }

        self.primary_net = Some(device);
    }

    /// Returns the primary NIC device ID (for targeted IRQ delivery).
    pub fn primary_net_device_id(&self) -> Option<DeviceId> {
        self.primary_net_device_id
    }

    /// Returns the typed handle to the primary VirtioNet if one was registered.
    pub fn primary_net(&self) -> Option<&Arc<Mutex<arcbox_virtio::net::VirtioNet>>> {
        self.primary_net.as_ref()
    }

    /// Registers a typed handle to the VirtioVsock device and binds its
    /// `DeviceCtx` plus the host-side connection manager. Must be called
    /// after `set_guest_memory` + `set_irq_callback`.
    pub fn set_vsock(
        &mut self,
        device_id: DeviceId,
        device: Arc<Mutex<arcbox_virtio::vsock::VirtioVsock>>,
    ) {
        if let Some(ctx) = self.build_device_ctx(device_id) {
            if let Ok(mut dev) = device.lock() {
                dev.bind_ctx(ctx);
                // Bind both views in one shot: trait-object for TX
                // (`process_queue`) and concrete for RX injection
                // (`poll_rx_injection`).
                dev.bind_connection_manager(self.vsock_connections.clone());
            }
        } else {
            tracing::warn!(
                "set_vsock: DeviceCtx not built (guest_mem or irq_callback missing) — \
                 vsock TX hot path will fall back to QueueConfig plumbing"
            );
        }
        self.vsock = Some(device);
    }

    /// Returns the typed handle to the VirtioVsock device if registered.
    pub fn vsock(&self) -> Option<&Arc<Mutex<arcbox_virtio::vsock::VirtioVsock>>> {
        self.vsock.as_ref()
    }

    /// Registers a typed handle to the bridge VirtioNet (NIC2) and binds
    /// its `DeviceCtx` (guest memory + IRQ trigger). Must be called after
    /// `set_guest_memory` + `set_irq_callback` so both ingredients exist,
    /// and before `set_bridge_host_fd` so the fd binding can reach the
    /// concrete device.
    pub fn set_bridge_net(
        &mut self,
        device_id: DeviceId,
        device: Arc<Mutex<arcbox_virtio::net::VirtioNet>>,
    ) {
        self.bridge_net_device_id = Some(device_id);

        if let Some(ctx) = self.build_device_ctx(device_id) {
            if let Ok(mut dev) = device.lock() {
                dev.bind_ctx(ctx);
            }
        } else {
            tracing::warn!(
                "set_bridge_net: DeviceCtx not built (guest_mem or irq_callback missing) — \
                 bridge hot paths will be no-ops"
            );
        }

        self.bridge_net = Some(device);
    }

    /// Constructs a `DeviceCtx` for a given device: a `GuestMemWriter`
    /// over guest RAM plus a `raise_irq` closure pre-bound to this
    /// device's GSI and MMIO state. Returns `None` if prerequisites are
    /// missing — caller decides whether to tolerate the absence.
    fn build_device_ctx(&self, device_id: DeviceId) -> Option<arcbox_virtio::DeviceCtx> {
        let ram_base = self.guest_ram_base?;
        if self.guest_ram_size == 0 {
            return None;
        }
        let device = self.devices.get(&device_id)?;
        let irq = device.info.irq?;
        let mmio_arc = device.mmio_state.as_ref()?.clone();
        let irq_callback = self.irq_callback.as_ref()?.clone();

        // SAFETY: `ram_base` is the host mapping returned by the platform
        // hypervisor and is valid for `guest_ram_size` bytes for the
        // lifetime of the DeviceManager (same contract as the other
        // GuestMemWriter constructions in this crate).
        let mem = unsafe {
            arcbox_virtio::GuestMemWriter::new(
                ram_base,
                self.guest_ram_size,
                self.guest_ram_gpa as usize,
            )
        };

        let raise_irq: Arc<dyn Fn(u32) + Send + Sync> = Arc::new(move |reason: u32| {
            if let Ok(mut s) = mmio_arc.write() {
                s.trigger_interrupt(reason);
            }
            let _ = irq_callback(irq, true);
        });

        Some(arcbox_virtio::DeviceCtx {
            mem: Arc::new(mem),
            raise_irq,
        })
    }

    /// Sets the bridge NIC host fd (NIC2 — vmnet bridge). The fd is stored
    /// on the bridge `VirtioNet` itself via `NetPort`; DeviceManager no
    /// longer owns it.
    pub fn set_bridge_host_fd(&mut self, fd: std::os::unix::io::RawFd, _device_id: DeviceId) {
        use arcbox_virtio::net::NetPort;
        let Some(bridge) = self.bridge_net.as_ref() else {
            tracing::error!("set_bridge_host_fd called before set_bridge_net");
            return;
        };
        let port = NetPort {
            host_fd: fd,
            last_avail_tx: std::sync::atomic::AtomicU16::new(0),
        };
        if let Ok(dev) = bridge.lock() {
            if dev.bind_port(port).is_err() {
                tracing::warn!("bridge_net port already bound — ignoring rebind");
            }
        }
    }

    /// Returns the typed handle to the bridge VirtioNet if one was registered.
    pub fn bridge_net(&self) -> Option<&Arc<Mutex<arcbox_virtio::net::VirtioNet>>> {
        self.bridge_net.as_ref()
    }

    /// Returns the guest RAM base pointer (for worker thread context).
    pub fn guest_ram_base_ptr(&self) -> Option<*mut u8> {
        self.guest_ram_base
    }

    /// Returns the guest RAM size.
    pub fn guest_ram_size(&self) -> usize {
        self.guest_ram_size
    }

    /// Returns the guest RAM GPA base.
    pub fn guest_ram_gpa(&self) -> u64 {
        self.guest_ram_gpa
    }

    /// Returns a reference to a registered device by ID.
    pub fn get_registered_device(&self, id: DeviceId) -> Option<&RegisteredDevice> {
        self.devices.get(&id)
    }

    /// Registers an async block I/O worker set for a device (one per queue).
    pub fn set_blk_worker(&self, device_id: DeviceId, handle: crate::blk_worker::BlkWorkerHandle) {
        self.blk_workers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(device_id, handle);
    }

    /// Drops all block-I/O worker senders so the worker threads can exit.
    ///
    /// Each `BlkWorkerHandle` owns `mpsc::Sender`s; dropping them makes the
    /// corresponding `rx.recv()` in `blk_io_worker_loop` return
    /// `Err(RecvError)`. Called from `stop_darwin_hv` right before the
    /// worker threads are joined — see ABX-364.
    pub fn clear_blk_workers(&self) {
        self.blk_workers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    /// Stores the hooks that the net-io worker thread needs for interrupt
    /// injection and vCPU cancellation. Called once from `start_darwin_hv`
    /// before the `DeviceManager` Arc is shared.
    pub fn set_net_rx_hooks(
        &mut self,
        irq_callback: Arc<dyn Fn(crate::irq::Irq, bool) -> crate::error::Result<()> + Send + Sync>,
        exit_vcpus: Arc<dyn Fn() + Send + Sync>,
    ) {
        self.net_rx_worker.set_hooks(irq_callback, exit_vcpus);
    }

    /// Stores the VM-wide `running` flag so the DRIVER_OK handler can
    /// pass it to the net-io worker context.
    pub fn set_running(&mut self, running: Arc<std::sync::atomic::AtomicBool>) {
        self.net_rx_worker.set_running(running);
    }

    /// Stores the RX inject channel so the DRIVER_OK handler can take it
    /// and spawn the `RxInjectThread`.
    pub fn set_rx_inject_channel(&mut self, rx: crossbeam_channel::Receiver<Vec<u8>>) {
        self.net_rx_worker.set_rx_inject_channel(rx);
    }

    /// Stores the inline connection channel so the DRIVER_OK handler can
    /// pass it to the `RxInjectThread`.
    pub fn set_inline_conn_channel(
        &mut self,
        rx: crossbeam_channel::Receiver<arcbox_net_inject::inline_conn::InlineConn>,
    ) {
        self.net_rx_worker.set_inline_conn_channel(rx);
    }

    /// Takes the net-io worker thread handle for join on shutdown.
    pub fn take_net_rx_worker_handle(&self) -> Option<std::thread::JoinHandle<()>> {
        self.net_rx_worker.take_handle()
    }

    /// Spawns the net-io worker thread if `device_id` is the primary VirtioNet
    /// and the worker has not already been spawned. Called from the DRIVER_OK
    /// handler (which only has `&self`).
    fn maybe_spawn_net_rx_worker(
        &self,
        device_id: DeviceId,
        mmio_arc: &Arc<RwLock<VirtioMmioState>>,
    ) {
        // Only spawn for the primary VirtioNet device.
        if self.primary_net_device_id != Some(device_id) {
            return;
        }
        let device = match self.devices.get(&device_id) {
            Some(d) if d.info.device_type == DeviceType::VirtioNet => d,
            _ => return,
        };
        let Some(irq) = device.info.irq else {
            tracing::warn!("net-io: device has no IRQ");
            return;
        };
        let Some(guest_base) = self.guest_ram_base else {
            tracing::warn!("net-io: guest_ram_base not set");
            return;
        };

        self.net_rx_worker.try_spawn(
            mmio_arc,
            irq,
            guest_base,
            self.guest_ram_size,
            self.guest_ram_gpa,
        );
    }

    /// Returns a clone of the IRQ callback Arc (if set).
    pub fn irq_callback_clone(&self) -> Option<DeviceIrqCallback> {
        self.irq_callback.clone()
    }

    /// Returns a clone of the vsock connection manager Arc.
    pub fn vsock_connections(
        &self,
    ) -> std::sync::Arc<std::sync::Mutex<crate::vsock_manager::VsockConnectionManager>> {
        self.vsock_connections.clone()
    }

    /// Sets the GIC SPI level to match a device's interrupt_status.
    ///
    /// For level-triggered SPIs, the line must reflect whether interrupt_status
    /// has any bits set. Call this after ANY mutation of interrupt_status
    /// (trigger_interrupt or INTERRUPT_ACK).
    ///
    /// Skips devices that haven't reached DRIVER_OK to avoid "nobody cared"
    /// in the guest kernel before the IRQ handler is installed.
    pub fn sync_irq_level(&self, device_id: DeviceId) {
        let Some(device) = self.devices.get(&device_id) else {
            return;
        };
        let Some(irq) = device.info.irq else {
            return;
        };
        let Some(ref mmio_arc) = device.mmio_state else {
            return;
        };
        let Ok(mmio) = mmio_arc.read() else {
            return;
        };

        // Don't inject IRQs before the guest driver is ready.
        if mmio.status & DeviceStatus::DRIVER_OK == 0 {
            tracing::trace!(
                "sync_irq_level: device {:?} not DRIVER_OK (status={:#x}), skipping",
                device.info.device_type,
                mmio.status,
            );
            return;
        }

        let level = mmio.interrupt_status != 0;
        tracing::trace!(
            "sync_irq_level: device {:?} irq={} interrupt_status={} -> SPI level={}",
            device.info.device_type,
            irq,
            mmio.interrupt_status,
            level,
        );
        if let Some(ref cb) = self.irq_callback {
            let _ = cb(irq, level);
        }
    }

    /// Triggers an IRQ through the configured callback (if set).
    ///
    /// Only fires if the device owning this IRQ has reached DRIVER_OK status.
    pub fn trigger_irq_callback(&self, irq: Irq, level: bool) {
        // Guard: check that the device owning this IRQ is activated.
        let device_ready = self.devices.values().any(|d| {
            d.info.irq == Some(irq)
                && d.mmio_state
                    .as_ref()
                    .and_then(|s| s.read().ok())
                    .is_some_and(|s| s.status & DeviceStatus::DRIVER_OK != 0)
        });
        if !device_ready {
            return;
        }
        if let Some(ref cb) = self.irq_callback {
            let _ = cb(irq, level);
        }
    }

    /// Registers a new device.
    ///
    /// # Errors
    ///
    /// Returns an error if device registration fails.
    pub fn register(
        &mut self,
        device_type: DeviceType,
        name: impl Into<String>,
    ) -> Result<DeviceId> {
        let id = DeviceId::new(self.next_id);
        self.next_id += 1;

        let info = DeviceInfo {
            id,
            device_type,
            name: name.into(),
            mmio_base: None,
            mmio_size: 0,
            irq: None,
        };

        self.devices.insert(
            id,
            RegisteredDevice {
                info,
                mmio_state: None,
                virtio_device: None,
            },
        );

        Ok(id)
    }

    /// Registers a `VirtIO` device with MMIO transport (without actual device).
    ///
    /// Use `register_virtio_device` to register with an actual `VirtIO` device implementation.
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails.
    pub fn register_virtio(
        &mut self,
        device_type: DeviceType,
        name: impl Into<String>,
        virtio_device_id: u32,
        features: u64,
        memory_manager: &mut MemoryManager,
        irq_chip: &IrqChip,
    ) -> Result<DeviceId> {
        let id = DeviceId::new(self.next_id);
        self.next_id += 1;

        // Allocate MMIO region
        let mmio_base = memory_manager.allocate_mmio(virtio_mmio::MMIO_SIZE, &name.into())?;
        let irq = irq_chip.allocate_level_irq()?;

        let name_str = format!("{}", id.0);
        let info = DeviceInfo {
            id,
            device_type,
            name: name_str,
            mmio_base: Some(mmio_base),
            mmio_size: virtio_mmio::MMIO_SIZE,
            irq: Some(irq),
        };

        let mmio_state = Arc::new(RwLock::new(VirtioMmioState::new(
            virtio_device_id,
            features,
        )));

        self.mmio_map.insert(mmio_base, id);
        self.devices.insert(
            id,
            RegisteredDevice {
                info,
                mmio_state: Some(mmio_state),
                virtio_device: None,
            },
        );

        tracing::info!(
            "Registered VirtIO device {} at MMIO {:#x}, IRQ {}",
            id.0,
            mmio_base,
            irq
        );

        Ok(id)
    }

    /// Registers a `VirtIO` device with MMIO transport and device implementation.
    ///
    /// This is the preferred method for registering `VirtIO` devices as it connects
    /// the MMIO transport layer with the actual device logic.
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails.
    pub fn register_virtio_device<D: VirtioDevice + 'static>(
        &mut self,
        device_type: DeviceType,
        name: impl Into<String>,
        device: D,
        memory_manager: &mut MemoryManager,
        irq_chip: &IrqChip,
    ) -> Result<(DeviceId, Arc<Mutex<D>>)> {
        let id = DeviceId::new(self.next_id);
        self.next_id += 1;

        let virtio_device_id = device.device_id() as u32;
        let features = device.features();
        let name_str = name.into();

        // Allocate MMIO region
        let mmio_base = memory_manager.allocate_mmio(virtio_mmio::MMIO_SIZE, &name_str)?;
        let irq = irq_chip.allocate_level_irq()?;

        let info = DeviceInfo {
            id,
            device_type,
            name: name_str.clone(),
            mmio_base: Some(mmio_base),
            mmio_size: virtio_mmio::MMIO_SIZE,
            irq: Some(irq),
        };

        let mmio_state = Arc::new(RwLock::new(VirtioMmioState::new(
            virtio_device_id,
            features,
        )));
        // Keep the concrete `Arc<Mutex<D>>` so the caller can hold a typed
        // handle (needed for hot-path shortcuts like `bridge_net` /
        // `primary_net` on DeviceManager). The trait-object form goes into
        // the generic HashMap used for MMIO dispatch.
        let virtio_device: Arc<Mutex<D>> = Arc::new(Mutex::new(device));
        let virtio_device_erased: Arc<Mutex<dyn VirtioDevice>> = virtio_device.clone();

        self.mmio_map.insert(mmio_base, id);
        self.devices.insert(
            id,
            RegisteredDevice {
                info,
                mmio_state: Some(mmio_state),
                virtio_device: Some(virtio_device_erased),
            },
        );

        tracing::info!(
            "Registered VirtIO device '{}' (type {:?}) at MMIO {:#x}, IRQ {}",
            name_str,
            device_type,
            mmio_base,
            irq
        );

        Ok((id, virtio_device))
    }

    /// Gets device info by ID.
    #[must_use]
    pub fn get(&self, id: DeviceId) -> Option<&DeviceInfo> {
        self.devices.get(&id).map(|d| &d.info)
    }

    /// Gets the MMIO state for a device.
    #[must_use]
    pub fn get_mmio_state(&self, id: DeviceId) -> Option<Arc<RwLock<VirtioMmioState>>> {
        self.devices.get(&id).and_then(|d| d.mmio_state.clone())
    }

    /// Gets the `VirtIO` device for a device ID.
    #[must_use]
    pub fn get_virtio_device(&self, id: DeviceId) -> Option<Arc<Mutex<dyn VirtioDevice>>> {
        self.devices.get(&id).and_then(|d| d.virtio_device.clone())
    }

    /// Triggers an interrupt for a device.
    ///
    /// # Errors
    ///
    /// Returns an error if the device doesn't exist or interrupt fails.
    pub fn trigger_interrupt(&self, id: DeviceId, reason: u32) -> Result<()> {
        let device = self
            .devices
            .get(&id)
            .ok_or_else(|| VmmError::Device(format!("Device {} not found", id.0)))?;

        if let Some(state) = &device.mmio_state {
            let mut state = state
                .write()
                .map_err(|e| VmmError::Device(format!("Failed to lock device state: {e}")))?;
            state.trigger_interrupt(reason);
        }

        Ok(())
    }

    /// Sets interrupt_status and syncs the GIC SPI level for a device type.
    /// Used by the vCPU polling paths (vsock RX, net RX) after injecting data.
    /// Note: matches the FIRST device of the given type. For bridge NIC, use
    /// `raise_interrupt_for_device` with the specific device ID.
    pub fn raise_interrupt_for(&self, device_type: DeviceType, reason: u32) {
        for (id, dev) in &self.devices {
            if dev.info.device_type == device_type {
                if let Some(ref mmio_arc) = dev.mmio_state {
                    if let Ok(mut s) = mmio_arc.write() {
                        s.trigger_interrupt(reason);
                    }
                }
                self.sync_irq_level(*id);
                break;
            }
        }
    }

    /// Raises interrupt for a specific device ID. Used for the bridge NIC
    /// which shares `DeviceType::VirtioNet` with the primary NIC.
    pub fn raise_interrupt_for_device(&self, device_id: DeviceId, reason: u32) {
        if let Some(dev) = self.devices.get(&device_id) {
            if let Some(ref mmio_arc) = dev.mmio_state {
                if let Ok(mut s) = mmio_arc.write() {
                    s.trigger_interrupt(reason);
                }
            }
            self.sync_irq_level(device_id);
        }
    }

    /// Returns the bridge NIC device ID (if configured).
    pub fn bridge_device_id(&self) -> Option<DeviceId> {
        self.bridge_net_device_id
    }

    /// Finds device by MMIO address.
    #[must_use]
    pub fn find_by_mmio(&self, addr: u64) -> Option<DeviceId> {
        for (base, id) in &self.mmio_map {
            if let Some(device) = self.devices.get(id) {
                if addr >= *base && addr < *base + device.info.mmio_size {
                    return Some(*id);
                }
            }
        }
        None
    }

    /// Handles MMIO read.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    pub fn handle_mmio_read(&self, addr: u64, size: usize) -> Result<u64> {
        let device_id = self
            .find_by_mmio(addr)
            .ok_or_else(|| VmmError::Device(format!("No device at MMIO address {addr:#x}")))?;

        let device = self
            .devices
            .get(&device_id)
            .ok_or_else(|| VmmError::Device(format!("Device {} not found", device_id.0)))?;

        let base = device.info.mmio_base.unwrap_or(0);
        let offset = addr - base;

        if let Some(state) = &device.mmio_state {
            let state = state
                .read()
                .map_err(|e| VmmError::Device(format!("Failed to lock device state: {e}")))?;

            // Handle config space reads - forward to actual device
            if offset >= virtio_mmio::regs::CONFIG {
                let config_offset = offset - virtio_mmio::regs::CONFIG;
                if let Some(virtio_dev) = &device.virtio_device {
                    let dev = virtio_dev.lock().map_err(|e| {
                        VmmError::Device(format!("Failed to lock virtio device: {e}"))
                    })?;
                    let mut data = vec![0u8; size];
                    dev.read_config(config_offset, &mut data);
                    tracing::trace!(
                        "Config read: device={} offset={:#x} size={} data={:?}",
                        device_id.0,
                        config_offset,
                        size,
                        &data[..size.min(8)]
                    );
                    return Ok(match size {
                        1 => u64::from(data[0]),
                        2 => u64::from(u16::from_le_bytes([data[0], data[1]])),
                        4 => u64::from(u32::from_le_bytes([data[0], data[1], data[2], data[3]])),
                        8 => u64::from_le_bytes([
                            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                        ]),
                        _ => 0,
                    });
                }
                return Ok(0);
            }

            let value = state.read(offset);
            let result = match size {
                1 => u64::from(value as u8),
                2 => u64::from(value as u16),
                4 => u64::from(value),
                _ => u64::from(value),
            };

            Ok(result)
        } else {
            Ok(0)
        }
    }

    /// Handles MMIO write.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    pub fn handle_mmio_write(&self, addr: u64, size: usize, value: u64) -> Result<()> {
        let device_id = self
            .find_by_mmio(addr)
            .ok_or_else(|| VmmError::Device(format!("No device at MMIO address {addr:#x}")))?;

        let device = self
            .devices
            .get(&device_id)
            .ok_or_else(|| VmmError::Device(format!("Device {} not found", device_id.0)))?;

        let base = device.info.mmio_base.unwrap_or(0);
        let offset = addr - base;

        if let Some(state) = &device.mmio_state {
            let old_status = {
                let s = state
                    .read()
                    .map_err(|e| VmmError::Device(format!("Failed to lock device state: {e}")))?;
                s.status
            };

            // Handle config space writes - forward to actual device
            if offset >= virtio_mmio::regs::CONFIG {
                let config_offset = offset - virtio_mmio::regs::CONFIG;
                if let Some(virtio_dev) = &device.virtio_device {
                    let mut dev = virtio_dev.lock().map_err(|e| {
                        VmmError::Device(format!("Failed to lock virtio device: {e}"))
                    })?;
                    let data: Vec<u8> = match size {
                        1 => vec![value as u8],
                        2 => (value as u16).to_le_bytes().to_vec(),
                        4 => (value as u32).to_le_bytes().to_vec(),
                        8 => value.to_le_bytes().to_vec(),
                        _ => return Ok(()),
                    };
                    dev.write_config(config_offset, &data);
                }
                return Ok(());
            }

            let value32 = match size {
                1 => value as u32 & 0xFF,
                2 => value as u32 & 0xFFFF,
                4 | 8 => value as u32,
                _ => value as u32,
            };

            // Write to MMIO state
            {
                let mut state = state
                    .write()
                    .map_err(|e| VmmError::Device(format!("Failed to lock device state: {e}")))?;
                state.write(offset, value32);
            }

            // Handle special cases after write
            match offset {
                virtio_mmio::regs::STATUS => {
                    let new_status = value32 as u8;

                    // Handle feature acknowledgment
                    if new_status & DeviceStatus::FEATURES_OK != 0
                        && old_status & DeviceStatus::FEATURES_OK == 0
                    {
                        if let Some(virtio_dev) = &device.virtio_device {
                            let mmio_state = state.read().map_err(|e| {
                                VmmError::Device(format!("Failed to lock device state: {e}"))
                            })?;
                            let mut dev = virtio_dev.lock().map_err(|e| {
                                VmmError::Device(format!("Failed to lock virtio device: {e}"))
                            })?;
                            dev.ack_features(mmio_state.driver_features);
                            tracing::debug!(
                                "Device {} acknowledged features: {:#x}",
                                device_id.0,
                                mmio_state.driver_features
                            );
                        }
                    }

                    // Handle device activation
                    if new_status & DeviceStatus::DRIVER_OK != 0
                        && old_status & DeviceStatus::DRIVER_OK == 0
                    {
                        if let Some(virtio_dev) = &device.virtio_device {
                            let mut dev = virtio_dev.lock().map_err(|e| {
                                VmmError::Device(format!("Failed to lock virtio device: {e}"))
                            })?;
                            dev.activate().map_err(|e| {
                                VmmError::Device(format!("Failed to activate device: {e}"))
                            })?;
                            tracing::info!("Device {} activated", device_id.0);
                        }

                        // Spawn the net-io worker for the primary VirtioNet device.
                        self.maybe_spawn_net_rx_worker(device_id, state);
                    }

                    // Handle device reset
                    if new_status == 0 {
                        if let Some(virtio_dev) = &device.virtio_device {
                            let mut dev = virtio_dev.lock().map_err(|e| {
                                VmmError::Device(format!("Failed to lock virtio device: {e}"))
                            })?;
                            dev.reset();
                            tracing::info!("Device {} reset", device_id.0);
                        }
                    }
                }
                virtio_mmio::regs::QUEUE_NOTIFY => {
                    let queue_idx = value32 as u16;
                    // Log vsock TX notifications at trace level (per-kick hot path).
                    if device.info.device_type == DeviceType::VirtioVsock && queue_idx == 1 {
                        tracing::trace!("QUEUE_NOTIFY: vsock TX queue 1 kicked by guest!",);
                    }
                    tracing::trace!(
                        "QUEUE_NOTIFY: device {} ({:?}) queue {}",
                        device_id.0,
                        device.info.device_type,
                        queue_idx,
                    );

                    if let Some(virtio_dev) = &device.virtio_device {
                        // Build QueueConfig from current MMIO state for the
                        // notified queue index.
                        let qcfg = {
                            let mmio_state = state.read().map_err(|e| {
                                VmmError::Device(format!("Failed to lock state: {e}"))
                            })?;
                            let qi = queue_idx as usize;
                            if qi < 8 {
                                QueueConfig {
                                    desc_addr: mmio_state.queue_desc[qi],
                                    avail_addr: mmio_state.queue_driver[qi],
                                    used_addr: mmio_state.queue_device[qi],
                                    size: mmio_state.queue_num[qi],
                                    ready: mmio_state.queue_ready[qi],
                                    gpa_base: self.guest_ram_gpa,
                                }
                            } else {
                                QueueConfig::default()
                            }
                        };

                        if let (Some(ram_base), ram_size) =
                            (self.guest_ram_base, self.guest_ram_size)
                        {
                            // Build a guest memory slice covering the guest RAM region.
                            // The host pointer `ram_base` maps to GPA `guest_ram_gpa`.
                            // All GPA-based indices must subtract `gpa_base` to obtain
                            // the correct offset within this slice.
                            //
                            // SAFETY: `ram_base` is the host mapping returned by
                            // Virtualization.framework and is valid for `ram_size` bytes.
                            let gpa_base = self.guest_ram_gpa as usize;
                            let guest_mem =
                                unsafe { std::slice::from_raw_parts_mut(ram_base, ram_size) };

                            // VirtioBlock async path: dispatch to worker thread
                            // instead of blocking the vCPU with synchronous I/O.
                            if device.info.device_type == DeviceType::VirtioBlock {
                                let workers = self
                                    .blk_workers
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                if let Some(handle) = workers.get(&device_id) {
                                    tracing::trace!(
                                        "blk async dispatch for device {}",
                                        device_id.0
                                    );
                                    handle.dispatch(guest_mem, &qcfg, queue_idx);
                                }
                            }
                            // VirtioNet TX (queue 1): extract ethernet frames
                            // from guest memory and write to the network host fd.
                            // This bypasses the generic process_queue — the
                            // concrete `VirtioNet` owns its fd + TX cursor via
                            // `NetPort` and implements the hot path itself.
                            else if device.info.device_type == DeviceType::VirtioNet
                                && queue_idx == 1
                                && (self.primary_net.is_some() || self.bridge_net.is_some())
                            {
                                let is_bridge = self
                                    .bridge_net_device_id
                                    .is_some_and(|bid| bid == device_id);
                                let typed = if is_bridge {
                                    self.bridge_net.as_ref()
                                } else {
                                    self.primary_net.as_ref()
                                };
                                let net_completions = match typed {
                                    Some(arc) => arc
                                        .lock()
                                        .map(|d| {
                                            d.drain_tx_queue(&qcfg, finalize_virtio_net_checksum)
                                        })
                                        .unwrap_or_default(),
                                    None => Vec::new(),
                                };
                                let _ = guest_mem; // unused on this branch now

                                if !net_completions.is_empty() {
                                    // Update used ring for completed TX descriptors.
                                    // Translate GPAs to slice offsets (checked).
                                    let Some(used_off) =
                                        (qcfg.used_addr as usize).checked_sub(gpa_base)
                                    else {
                                        tracing::warn!(
                                            "invalid used GPA {:#x} below ram base {:#x}",
                                            qcfg.used_addr,
                                            gpa_base
                                        );
                                        return Ok(());
                                    };
                                    let q_size = qcfg.size as usize;
                                    let used_idx_off = used_off + 2;
                                    let mut used_idx = u16::from_le_bytes([
                                        guest_mem[used_idx_off],
                                        guest_mem[used_idx_off + 1],
                                    ]);
                                    for &(head, len) in &net_completions {
                                        let entry =
                                            used_off + 4 + ((used_idx as usize) % q_size) * 8;
                                        if entry + 8 <= guest_mem.len() {
                                            guest_mem[entry..entry + 4]
                                                .copy_from_slice(&(head as u32).to_le_bytes());
                                            guest_mem[entry + 4..entry + 8]
                                                .copy_from_slice(&len.to_le_bytes());
                                            used_idx = used_idx.wrapping_add(1);
                                        }
                                    }
                                    std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
                                    guest_mem[used_idx_off..used_idx_off + 2]
                                        .copy_from_slice(&used_idx.to_le_bytes());

                                    // Write avail_event in the used ring to request
                                    // kicks from the guest on future TX submissions.
                                    // With VIRTIO_F_EVENT_IDX, the guest checks
                                    // vring_need_event(avail_event, new, old) before
                                    // kicking. Setting avail_event = current avail_idx
                                    // ensures the guest kicks on the next submission.
                                    if let Some(avail_off) =
                                        (qcfg.avail_addr as usize).checked_sub(gpa_base)
                                    {
                                        let avail_idx = u16::from_le_bytes([
                                            guest_mem[avail_off + 2],
                                            guest_mem[avail_off + 3],
                                        ]);
                                        let avail_event_off = used_off + 4 + q_size * 8;
                                        if avail_event_off + 2 <= guest_mem.len() {
                                            guest_mem[avail_event_off..avail_event_off + 2]
                                                .copy_from_slice(&avail_idx.to_le_bytes());
                                        }
                                    }

                                    if let Some(_irq) = device.info.irq {
                                        {
                                            let mut s = state.write().map_err(|e| {
                                                VmmError::Device(format!(
                                                    "Failed to lock state: {e}"
                                                ))
                                            })?;
                                            s.trigger_interrupt(virtio_mmio::INT_VRING);
                                        }
                                        self.sync_irq_level(device_id);
                                    }
                                }
                            } else {
                                // Generic process_queue for all other devices.
                                let mut dev = virtio_dev.lock().map_err(|e| {
                                    VmmError::Device(format!("Failed to lock device: {e}"))
                                })?;
                                // Log vsock TX processing at trace level (per-kick hot path).
                                let is_vsock_tx = device.info.device_type
                                    == DeviceType::VirtioVsock
                                    && queue_idx == 1;
                                match dev.process_queue(queue_idx, guest_mem, &qcfg) {
                                    Ok(completions) if !completions.is_empty() => {
                                        if is_vsock_tx {
                                            tracing::trace!(
                                                "Vsock QUEUE_NOTIFY TX: {} completions processed!",
                                                completions.len(),
                                            );
                                        }
                                        tracing::trace!(
                                            "Device {} queue {} processed {} completions",
                                            device_id.0,
                                            queue_idx,
                                            completions.len()
                                        );
                                        // Console TX completions don't need interrupts —
                                        // the guest doesn't wait for host ACK on console output.
                                        // Skipping avoids interrupt storms with level-triggered SPIs.
                                        let skip_irq = device.info.device_type
                                            == DeviceType::VirtioConsole
                                            && queue_idx == 1;
                                        if !skip_irq {
                                            {
                                                let mut s = state.write().map_err(|e| {
                                                    VmmError::Device(format!(
                                                        "Failed to lock state: {e}"
                                                    ))
                                                })?;
                                                s.trigger_interrupt(virtio_mmio::INT_VRING);
                                            }
                                            self.sync_irq_level(device_id);
                                        }
                                    }
                                    Ok(_) => {
                                        if is_vsock_tx {
                                            tracing::trace!(
                                                "Vsock QUEUE_NOTIFY TX: kicked but 0 completions \
                                                 (last_avail_idx_tx may already be current)",
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Device {} queue {} error: {e}",
                                            device_id.0,
                                            queue_idx
                                        );
                                    }
                                }
                            } // end else (non-VirtioNet)
                        } else {
                            tracing::trace!(
                                "Device {} queue {} notified but no guest memory set",
                                device_id.0,
                                queue_idx
                            );
                        }
                    } else {
                        tracing::trace!(
                            "Device {} queue {} notified (no device impl)",
                            device_id.0,
                            queue_idx
                        );
                    }
                }
                virtio_mmio::regs::INTERRUPT_ACK => {
                    // Sync the GIC SPI level with the updated interrupt_status.
                    // If all bits are cleared, the SPI goes low; if bits remain
                    // (from a concurrent completion), the SPI stays high.
                    self.sync_irq_level(device_id);
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Returns an iterator over all devices.
    pub fn iter(&self) -> impl Iterator<Item = &DeviceInfo> {
        self.devices.values().map(|d| &d.info)
    }

    /// Returns device tree entries for all `VirtIO` devices.
    #[must_use]
    pub fn device_tree_entries(&self) -> Vec<DeviceTreeEntry> {
        // Sort by MMIO base address so the FDT node order is deterministic.
        // Linux discovers virtio-mmio devices in FDT order, so the first
        // virtio-blk node becomes vda, the second vdb, etc. Without sorting,
        // HashMap iteration order is arbitrary and block device naming becomes
        // non-deterministic (root=/dev/vda may point at the wrong disk).
        let mut entries: Vec<DeviceTreeEntry> = self
            .devices
            .values()
            .filter_map(|d| {
                if let (Some(base), Some(irq)) = (d.info.mmio_base, d.info.irq) {
                    Some(DeviceTreeEntry {
                        compatible: "virtio,mmio".to_string(),
                        reg_base: base,
                        reg_size: d.info.mmio_size,
                        irq,
                    })
                } else {
                    None
                }
            })
            .collect();
        entries.sort_by_key(|e| e.reg_base);
        entries
    }

    /// Polls the bridge (vmnet) host fd for inbound frames and injects
    /// them into the bridge VirtioNet RX queue. Thin shim that reads the
    /// device's current MMIO-transport queue configuration, hands it to
    /// `VirtioNet::poll_rx`, and returns whether any frame was injected.
    /// Caller fires the used-ring interrupt on `true`.
    pub fn poll_bridge_rx(&self) -> bool {
        let Some(bridge_arc) = self.bridge_net.as_ref() else {
            return false;
        };
        let Some(bridge_id) = self.bridge_net_device_id else {
            return false;
        };
        let Some(device) = self.devices.get(&bridge_id) else {
            return false;
        };
        let Some(mmio_arc) = device.mmio_state.as_ref() else {
            return false;
        };

        // Build a snapshot of the RX queue (idx 0) from MMIO state.
        let rx_qcfg = {
            let Ok(mmio) = mmio_arc.read() else {
                return false;
            };
            let qi = 0usize;
            if !mmio.queue_ready[qi] || mmio.queue_num[qi] == 0 {
                return false;
            }
            QueueConfig {
                desc_addr: mmio.queue_desc[qi],
                avail_addr: mmio.queue_driver[qi],
                used_addr: mmio.queue_device[qi],
                size: mmio.queue_num[qi],
                ready: true,
                gpa_base: self.guest_ram_gpa,
            }
        };

        let Ok(dev) = bridge_arc.lock() else {
            return false;
        };
        dev.poll_rx(&rx_qcfg)
    }

    /// Called from the vCPU run loop during WFI (guest idle). Returns
    /// true if any data was injected (caller should trigger interrupt).
    /// Thin shim that builds RX + TX `QueueConfig` snapshots from the
    /// vsock device's MMIO state and forwards to
    /// `VirtioVsock::poll_rx_injection`. The 400-line body that was here
    /// previously now lives on the device.
    pub fn poll_vsock_rx(&self) -> bool {
        let Some(vsock_arc) = self.vsock.as_ref() else {
            return false;
        };
        let Some(device) = self
            .devices
            .values()
            .find(|d| d.info.device_type == DeviceType::VirtioVsock)
        else {
            return false;
        };
        let Some(mmio_arc) = device.mmio_state.as_ref() else {
            return false;
        };

        let (rx_qcfg, tx_qcfg) = {
            let Ok(mmio) = mmio_arc.read() else {
                return false;
            };
            let rxi = 0usize;
            if !mmio.queue_ready[rxi] || mmio.queue_num[rxi] == 0 {
                return false;
            }
            let rx = QueueConfig {
                desc_addr: mmio.queue_desc[rxi],
                avail_addr: mmio.queue_driver[rxi],
                used_addr: mmio.queue_device[rxi],
                size: mmio.queue_num[rxi],
                ready: true,
                gpa_base: self.guest_ram_gpa,
            };
            let txi = 1usize;
            let tx = if mmio.queue_ready[txi] && mmio.queue_num[txi] > 0 {
                Some(QueueConfig {
                    desc_addr: mmio.queue_desc[txi],
                    avail_addr: mmio.queue_driver[txi],
                    used_addr: mmio.queue_device[txi],
                    size: mmio.queue_num[txi],
                    ready: true,
                    gpa_base: self.guest_ram_gpa,
                })
            } else {
                None
            };
            (rx, tx)
        };

        let Ok(mut dev) = vsock_arc.lock() else {
            return false;
        };
        dev.poll_rx_injection(&rx_qcfg, tx_qcfg.as_ref())
    }
}

/// Device tree entry for FDT generation.
#[derive(Debug, Clone)]
pub struct DeviceTreeEntry {
    /// Compatible string.
    pub compatible: String,
    /// Register base address.
    pub reg_base: u64,
    /// Register region size.
    pub reg_size: u64,
    /// IRQ number.
    pub irq: Irq,
}

impl Default for DeviceManager {
    fn default() -> Self {
        Self::new()
    }
}

// Verify that DeviceManager can still be shared across threads despite
// containing a raw pointer (Send + Sync are implemented above).
#[cfg(test)]
const _: () = {
    #[allow(dead_code)]
    fn assert_send<T: Send>() {}
    #[allow(dead_code)]
    fn assert_sync<T: Sync>() {}
    fn _check() {
        assert_send::<DeviceManager>();
        assert_sync::<DeviceManager>();
    }
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use arcbox_net::ethernet::{TcpFrameParams, build_tcp_ack_frame, build_udp_ip_ethernet};
    use arcbox_net::nat_engine::checksum::{tcp_checksum, udp_checksum};

    #[test]
    fn test_device_registration() {
        let mut manager = DeviceManager::new();
        let id = manager.register(DeviceType::Serial, "serial0").unwrap();

        let info = manager.get(id);
        assert!(info.is_some());
        assert_eq!(info.unwrap().name, "serial0");
    }

    #[test]
    fn test_virtio_mmio_state() {
        let state = VirtioMmioState::new(2, 0x1234_5678);

        assert_eq!(
            state.read(virtio_mmio::regs::MAGIC),
            virtio_mmio::MAGIC_VALUE
        );
        assert_eq!(state.read(virtio_mmio::regs::VERSION), virtio_mmio::VERSION);
        assert_eq!(state.read(virtio_mmio::regs::DEVICE_ID), 2);
    }

    #[test]
    fn test_virtio_mmio_features() {
        let mut state = VirtioMmioState::new(2, 0xDEAD_BEEF_CAFE_BABE);

        // Read low 32 bits
        assert_eq!(state.read(virtio_mmio::regs::DEVICE_FEATURES), 0xCAFE_BABE);

        // Select high 32 bits
        state.write(virtio_mmio::regs::DEVICE_FEATURES_SEL, 1);
        assert_eq!(state.read(virtio_mmio::regs::DEVICE_FEATURES), 0xDEAD_BEEF);
    }

    #[test]
    fn test_finalize_virtio_net_checksum_repairs_ipv4_tcp_frame() {
        let params = TcpFrameParams {
            src_ip: Ipv4Addr::new(10, 0, 2, 2),
            dst_ip: Ipv4Addr::new(198, 18, 30, 95),
            src_port: 36402,
            dst_port: 443,
            seq: 1234,
            ack: 0,
            window: 64240,
            src_mac: [0x52, 0x54, 0xAB, 0xFA, 0x2A, 0x70],
            dst_mac: [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x01],
        };
        let mut frame = build_tcp_ack_frame(&params);
        let tcp_start = 14 + 20;
        frame[tcp_start + 13] = 0x02;
        frame[tcp_start + 16..tcp_start + 18].fill(0);

        let header = VirtioNetHeader {
            flags: VirtioNetHeader::FLAG_NEEDS_CSUM,
            gso_type: VirtioNetHeader::GSO_NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start: tcp_start as u16,
            csum_offset: 16,
            num_buffers: 1,
        };
        let mut packet_data = header.to_bytes().to_vec();
        packet_data.extend_from_slice(&frame);

        finalize_virtio_net_checksum(&mut packet_data);

        let frame = &packet_data[VirtioNetHeader::SIZE..];
        let stored = u16::from_be_bytes([frame[tcp_start + 16], frame[tcp_start + 17]]);
        let mut tcp_segment = frame[tcp_start..].to_vec();
        tcp_segment[16..18].fill(0);

        assert_ne!(stored, 0);
        assert_eq!(
            stored,
            tcp_checksum(params.src_ip.octets(), params.dst_ip.octets(), &tcp_segment)
        );
    }

    #[test]
    fn test_finalize_virtio_net_checksum_repairs_ipv4_udp_frame() {
        let src_ip = Ipv4Addr::new(10, 0, 2, 2);
        let dst_ip = Ipv4Addr::new(10, 0, 2, 1);
        let payload = b"hello dns";
        let src_mac = [0x52, 0x54, 0xAB, 0xFA, 0x2A, 0x70];
        let dst_mac = [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x01];
        let mut frame = build_udp_ip_ethernet(src_ip, dst_ip, 49152, 53, payload, src_mac, dst_mac);
        let udp_start = 14 + 20;
        frame[udp_start + 6..udp_start + 8].fill(0);

        let header = VirtioNetHeader {
            flags: VirtioNetHeader::FLAG_NEEDS_CSUM,
            gso_type: VirtioNetHeader::GSO_NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start: udp_start as u16,
            csum_offset: 6,
            num_buffers: 1,
        };
        let mut packet_data = header.to_bytes().to_vec();
        packet_data.extend_from_slice(&frame);

        finalize_virtio_net_checksum(&mut packet_data);

        let frame = &packet_data[VirtioNetHeader::SIZE..];
        let stored = u16::from_be_bytes([frame[udp_start + 6], frame[udp_start + 7]]);
        let mut udp_datagram = frame[udp_start..].to_vec();
        udp_datagram[6..8].fill(0);

        assert_ne!(stored, 0);
        assert_eq!(
            stored,
            udp_checksum(src_ip.octets(), dst_ip.octets(), &udp_datagram)
        );
    }
}
