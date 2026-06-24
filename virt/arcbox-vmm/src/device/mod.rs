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

use arcbox_virtio::{DeviceStatus, QueueConfig, VirtioDevice};

use crate::error::{Result, VmmError};
use crate::irq::{Irq, IrqChip};
use crate::memory::MemoryManager;

mod checksum;
mod dispatch;
mod mmio_state;
pub(crate) mod net_worker;
mod poll;
mod tree;

#[cfg(test)]
mod tests;

use checksum::finalize_virtio_net_checksum;
pub use mmio_state::{MmioDevice, VirtioMmioState, virtio_mmio};
pub use tree::DeviceTreeEntry;

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
    pub(super) fn maybe_spawn_net_rx_worker(
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

    /// Returns an iterator over all devices.
    pub fn iter(&self) -> impl Iterator<Item = &DeviceInfo> {
        self.devices.values().map(|d| &d.info)
    }
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
