//! Network RX worker lifecycle management.
//!
//! `NetRxWorkerSlot` collects the resources needed to spawn the net-io
//! worker thread (IRQ callback, vCPU exit handle, channels, host fd) and
//! spawns it exactly once when the primary VirtioNet device reaches
//! DRIVER_OK. This isolates the worker lifecycle from `DeviceManager`,
//! which only needs to hold a single `NetRxWorkerSlot` field.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};

use crate::device::mmio_state::VirtioMmioState;
use crate::irq::Irq;

/// IRQ callback type matching the DeviceManager convention.
type IrqCallback = Arc<dyn Fn(Irq, bool) -> crate::error::Result<()> + Send + Sync>;

/// Collects resources for the net-io worker thread and manages its lifecycle.
///
/// Resources are deposited one-by-one via `set_*` methods (order does not
/// matter) and consumed exactly once by [`try_spawn`] at DRIVER_OK time.
/// The thread handle is stored internally and can be taken for join on
/// shutdown.
pub struct NetRxWorkerSlot {
    /// Thread handle. Spawned once; taken on shutdown for join.
    handle: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// IRQ callback for the net-io worker thread.
    irq_callback: Option<IrqCallback>,
    /// Force-exit all vCPUs closure for the net-io worker thread.
    exit_vcpus: Option<Arc<dyn Fn() + Send + Sync>>,
    /// VM-wide running flag shared with worker threads.
    running: Option<Arc<AtomicBool>>,
    /// Primary NIC host fd for legacy (kqueue) fallback path.
    host_fd: Mutex<Option<i32>>,
    /// Channel receiving frames from the datapath loop for direct guest
    /// memory injection. Taken once to construct the `RxInjectThread`.
    rx_inject_channel: Mutex<Option<crossbeam_channel::Receiver<Vec<u8>>>>,
    /// Channel for promoted inline (vhost-style) TCP connections.
    inline_conn_channel:
        Mutex<Option<crossbeam_channel::Receiver<arcbox_net_inject::inline_conn::InlineConn>>>,
}

impl NetRxWorkerSlot {
    pub fn new() -> Self {
        Self {
            handle: Mutex::new(None),
            irq_callback: None,
            exit_vcpus: None,
            running: None,
            host_fd: Mutex::new(None),
            rx_inject_channel: Mutex::new(None),
            inline_conn_channel: Mutex::new(None),
        }
    }

    /// Stores the IRQ callback and vCPU exit closure.
    pub fn set_hooks(
        &mut self,
        irq_callback: IrqCallback,
        exit_vcpus: Arc<dyn Fn() + Send + Sync>,
    ) {
        self.irq_callback = Some(irq_callback);
        self.exit_vcpus = Some(exit_vcpus);
    }

    /// Stores the VM-wide `running` flag.
    pub fn set_running(&mut self, running: Arc<AtomicBool>) {
        self.running = Some(running);
    }

    /// Stores the primary NIC host fd (for the legacy kqueue fallback).
    pub fn set_host_fd(&self, fd: i32) {
        *self
            .host_fd
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(fd);
    }

    /// Returns the stored host fd without removing it.
    fn get_host_fd(&self) -> Option<i32> {
        *self
            .host_fd
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Stores the RX inject channel.
    pub fn set_rx_inject_channel(&self, rx: crossbeam_channel::Receiver<Vec<u8>>) {
        *self
            .rx_inject_channel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(rx);
    }

    /// Stores the inline connection channel.
    pub fn set_inline_conn_channel(
        &self,
        rx: crossbeam_channel::Receiver<arcbox_net_inject::inline_conn::InlineConn>,
    ) {
        *self
            .inline_conn_channel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(rx);
    }

    /// Takes the thread handle for join on shutdown.
    pub fn take_handle(&self) -> Option<std::thread::JoinHandle<()>> {
        self.handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    /// Attempts to spawn the net-io worker thread.
    ///
    /// Called from the DRIVER_OK handler (which only has `&self`). Returns
    /// immediately if prerequisites are missing or the worker was already
    /// spawned. Prefers the `RxInjectThread` path (channel-based) when
    /// `rx_inject_channel` is set; falls back to the legacy `net_rx_worker`
    /// (kqueue on socketpair fd).
    pub fn try_spawn(
        &self,
        mmio_arc: &Arc<RwLock<VirtioMmioState>>,
        irq: Irq,
        guest_ram_base: *mut u8,
        guest_ram_size: usize,
        guest_ram_gpa: u64,
    ) {
        // Guard: only spawn once.
        {
            let guard = self
                .handle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if guard.is_some() {
                return;
            }
        }

        let Some(irq_callback) = self.irq_callback.clone() else {
            tracing::warn!("net-io: irq_callback not set");
            return;
        };
        let Some(exit_vcpus) = self.exit_vcpus.clone() else {
            tracing::warn!("net-io: exit_vcpus not set");
            return;
        };
        let Some(running) = self.running.clone() else {
            tracing::warn!("net-io: running flag not set");
            return;
        };

        let mmio = match mmio_arc.read() {
            Ok(m) => m,
            Err(_) => return,
        };

        let qi = 0; // RX queue index.

        // Try the new RxInjectThread path (channel-based, HV backend).
        let rx_channel = self
            .rx_inject_channel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();

        if let Some(rx_channel) = rx_channel {
            // SAFETY: `guest_ram_base` is the host mapping returned by
            // the hypervisor, valid for `guest_ram_size` bytes for the
            // lifetime of the VM.
            let guest_mem = unsafe {
                arcbox_net_inject::guest_mem::GuestMemWriter::new(
                    guest_ram_base,
                    guest_ram_size,
                    guest_ram_gpa as usize,
                )
            };

            let queue = arcbox_net_inject::queue::RxQueueConfig {
                desc_gpa: mmio.queue_desc[qi],
                avail_gpa: mmio.queue_driver[qi],
                used_gpa: mmio.queue_device[qi],
                size: mmio.queue_num[qi],
            };
            // Capture whether VIRTIO_F_EVENT_IDX was negotiated. This is
            // valid here because try_spawn runs from the DRIVER_OK path,
            // after feature negotiation has completed.
            let event_idx_enabled =
                (mmio.driver_features & arcbox_virtio::queue::VIRTIO_F_EVENT_IDX) != 0;
            drop(mmio);

            // Wrap the VMM IRQ callback to match the inject crate's type.
            let vmm_callback = irq_callback;
            let inject_callback: Arc<arcbox_net_inject::irq::IrqCallback> =
                Arc::new(move |gsi, level| {
                    vmm_callback(gsi, level)
                        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
                });

            let mmio_arc_clone = mmio_arc.clone();
            let set_interrupt_status: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                if let Ok(mut s) = mmio_arc_clone.write() {
                    s.trigger_interrupt(1); // INT_VRING
                }
            });

            // Take the inline connection channel if available; otherwise
            // create an unbounded channel with a dummy sender that is
            // immediately dropped (the receiver will never yield items).
            let conn_rx = self
                .inline_conn_channel
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .unwrap_or_else(|| {
                    let (_tx, rx) = crossbeam_channel::unbounded();
                    rx
                });

            let inject_thread = arcbox_net_inject::inject::RxInjectThread {
                rx: rx_channel,
                conn_rx,
                guest_mem,
                queue,
                irq: arcbox_net_inject::irq::IrqHandle {
                    callback: inject_callback,
                    exit_vcpus,
                    irq,
                },
                set_interrupt_status,
                running,
                event_idx_enabled,
            };

            match std::thread::Builder::new()
                .name("rx-inject".to_string())
                .spawn(move || inject_thread.run())
            {
                Ok(handle) => {
                    *self
                        .handle
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handle);
                    tracing::info!(
                        "Spawned rx-inject thread for primary VirtioNet (channel-based)"
                    );
                }
                Err(e) => {
                    tracing::error!("Failed to spawn rx-inject thread: {e}");
                }
            }
            return;
        }

        // Fallback: legacy net_rx_worker (kqueue on socketpair fd).
        let Some(net_fd) = self.get_host_fd() else {
            tracing::warn!("net-io: no host fd available for primary VirtioNet");
            return;
        };

        let rx_queue = crate::net_rx_worker::RxQueueConfig {
            desc_gpa: mmio.queue_desc[qi],
            avail_gpa: mmio.queue_driver[qi],
            used_gpa: mmio.queue_device[qi],
            size: mmio.queue_num[qi],
        };
        drop(mmio);

        // SAFETY: `guest_ram_base` is the host mapping returned by
        // the hypervisor, valid for `guest_ram_size` bytes for the
        // lifetime of the VM.
        let guest_mem = unsafe {
            crate::blk_worker::GuestMemWriter::new(
                guest_ram_base,
                guest_ram_size,
                guest_ram_gpa as usize,
            )
        };

        let ctx = crate::net_rx_worker::NetRxWorkerContext {
            net_host_fd: net_fd,
            guest_mem,
            rx_queue,
            mmio_state: mmio_arc.clone(),
            irq_callback,
            irq,
            exit_vcpus,
            running,
        };

        match std::thread::Builder::new()
            .name("net-io".to_string())
            .spawn(move || crate::net_rx_worker::net_rx_worker_loop(ctx))
        {
            Ok(handle) => {
                *self
                    .handle
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handle);
                tracing::info!("Spawned net-io worker thread for primary VirtioNet (legacy)");
            }
            Err(e) => {
                tracing::error!("Failed to spawn net-io worker thread: {e}");
            }
        }
    }
}
