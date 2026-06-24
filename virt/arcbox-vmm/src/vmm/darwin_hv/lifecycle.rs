use std::sync::{Arc, Mutex, mpsc};

use crate::error::{Result, VmmError};

use super::pl011::Pl011;
use super::psci::{CpuOnRequest, CpuOnSenders};
use super::vcpu_loop::{VcpuContext, vcpu_run_loop};
use super::*;

impl Vmm {
    /// Starts the custom HV VMM by spawning vCPU threads.
    ///
    /// The BSP (vCPU 0) runs immediately. Secondary vCPUs (1..N) are spawned
    /// in a "parked" state and wait on a channel for a PSCI CPU_ON request
    /// from the BSP before entering their run loop.
    pub(in crate::vmm) fn start_darwin_hv(&mut self) -> Result<()> {
        let kernel_entry = self
            .hv_kernel_entry
            .ok_or_else(|| VmmError::config("HV kernel entry not set".to_string()))?;
        let fdt_addr = self
            .hv_fdt_addr
            .ok_or_else(|| VmmError::config("HV FDT address not set".to_string()))?;

        // Both registries are created during initialize_darwin_hv. Callers
        // must not invoke start before initialize — guard against that here.
        if self.hv_vcpu_ids.is_none() {
            return Err(VmmError::invalid_state(
                "hv_vcpu_ids not initialized; call initialize() first".to_string(),
            ));
        }
        if self.hv_vcpu_thread_handles.is_none() {
            return Err(VmmError::invalid_state(
                "hv_vcpu_thread_handles not initialized; call initialize() first".to_string(),
            ));
        }

        // `running` gates every thread spawned below (vsock-io worker, vCPU
        // loops, blk/net workers). The generic `Vmm::start` only stores it
        // after this function returns, which is too late: a freshly spawned
        // thread that checks the flag before then exits immediately.
        self.running
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let mut device_manager = Arc::new(
            self.device_manager
                .take()
                .ok_or_else(|| VmmError::config("device manager not initialized".to_string()))?,
        );

        // Spawn async block I/O worker threads (one per block device).
        // Uses device info captured during initialize_darwin_hv.
        // Must happen before Arc is cloned to other threads.
        {
            let dm = Arc::get_mut(&mut device_manager).expect("single Arc ref");
            let (guest_ptr, guest_len, guest_gpa_base) = if let (Some(base), size, gpa) = (
                dm.guest_ram_base_ptr(),
                dm.guest_ram_size(),
                dm.guest_ram_gpa(),
            ) {
                (base, size, gpa as usize)
            } else {
                (std::ptr::null_mut(), 0, 0)
            };

            // Collect IRQ info for each block device before spawning workers.
            let blk_infos = std::mem::take(&mut self.hv_blk_devices)
                .into_iter()
                .filter_map(
                    |(dev_id, raw_fd, blk_size, read_only, dev_id_str, num_queues)| {
                        let dev = dm.get_registered_device(dev_id)?;
                        let irq = dev.info.irq?;
                        let mmio_state = dev.mmio_state.as_ref()?.clone();
                        Some((
                            dev_id, raw_fd, blk_size, read_only, dev_id_str, num_queues, irq,
                            mmio_state,
                        ))
                    },
                )
                .collect::<Vec<_>>();

            for (dev_id, raw_fd, blk_size, read_only, dev_id_str, num_queues, irq, mmio_state) in
                blk_infos
            {
                let irq_cb = dm.irq_callback_clone().unwrap_or_else(|| {
                    Arc::new(|_: crate::irq::Irq, _: bool| -> crate::error::Result<()> { Ok(()) })
                });
                let flush_barrier = Arc::new(crate::blk_worker::FlushBarrier::new());
                let mut queue_workers = Vec::with_capacity(num_queues as usize);

                for qi in 0..num_queues {
                    let (tx, rx) = std::sync::mpsc::channel::<crate::blk_worker::BlkWorkItem>();

                    let worker_ctx = crate::blk_worker::BlkWorkerContext {
                        // SAFETY: `guest_ptr` is the host mapping returned by
                        // Virtualization.framework, valid for `guest_len` bytes
                        // for the lifetime of the VM.
                        guest_mem: unsafe {
                            crate::blk_worker::GuestMemWriter::new(
                                guest_ptr,
                                guest_len,
                                guest_gpa_base,
                            )
                        },
                        raw_fd,
                        blk_size,
                        read_only,
                        device_id: dev_id_str.clone(),
                        mmio_state: mmio_state.clone(),
                        irq_callback: irq_cb.clone(),
                        irq,
                        running: self.running.clone(),
                        flush_barrier: flush_barrier.clone(),
                    };

                    let thread_name = format!("blk-io-{}-q{}", dev_id_str, qi);
                    match std::thread::Builder::new()
                        .name(thread_name.clone())
                        .spawn(move || {
                            crate::blk_worker::blk_io_worker_loop(worker_ctx, rx);
                        }) {
                        Ok(t) => {
                            self.hv_blk_worker_threads.push(t);
                            queue_workers.push(crate::blk_worker::BlkQueueWorker {
                                tx,
                                last_avail_idx: std::sync::atomic::AtomicU16::new(0),
                            });
                        }
                        Err(e) => {
                            tracing::warn!("Failed to spawn {}: {}", thread_name, e);
                        }
                    }
                }

                if !queue_workers.is_empty() {
                    dm.set_blk_worker(
                        dev_id,
                        crate::blk_worker::BlkWorkerHandle {
                            queues: queue_workers,
                        },
                    );
                    tracing::info!(
                        "Spawned {} async block I/O workers for {}",
                        num_queues,
                        dev_id_str,
                    );
                }
            }
        }

        // Wire net-io worker hooks before the Arc is shared.
        // The net-io thread will be spawned later at DRIVER_OK time.
        {
            let dm = Arc::get_mut(&mut device_manager).expect("single Arc ref for net-rx hooks");

            // Build IRQ callback for the net-io thread (same GIC + unpark logic).
            #[cfg(feature = "gic")]
            if let Some(ref gic_ref) = self.hv_gic {
                let gic_clone = Arc::clone(gic_ref);
                let threads_clone = self
                    .hv_vcpu_thread_handles
                    .clone()
                    .expect("hv_vcpu_thread_handles asserted Some above");
                let net_irq_cb: crate::device::DeviceIrqCallback =
                    Arc::new(move |gsi: crate::irq::Gsi, level: bool| {
                        gic_clone.set_spi(gsi, level).map_err(|e| {
                            VmmError::Irq(format!("GIC set_spi({gsi}, {level}) failed: {e}"))
                        })?;
                        if level {
                            if let Ok(handles) = threads_clone.lock() {
                                for t in handles.iter() {
                                    t.unpark();
                                }
                            }
                        }
                        Ok(())
                    });
                // Force-exit closure used by the net-rx worker to wake a
                // guest that is idle in WFI for interrupt delivery (ABX-367).
                let exit_fn = make_exit_vcpus_fn(
                    self.hv_vcpu_ids
                        .clone()
                        .expect("hv_vcpu_ids asserted Some above"),
                );
                dm.set_net_rx_hooks(net_irq_cb, exit_fn);
            }

            dm.set_running(self.running.clone());
        }

        // Store a shared reference for connect_vsock_hv to use after start.
        self.hv_device_manager = Some(Arc::clone(&device_manager));

        // --- vsock-io worker: event-driven host→guest injection ---
        // Without it, packets enqueued by the daemon wait for the BSP's
        // next natural VM exit (~100 ms on an idle guest). The doorbell
        // pipe is rung by the connection manager on new RX work; the
        // worker also watches every connected socketpair fd for data.
        self.spawn_vsock_rx_worker(&device_manager)?;

        let running = self.running.clone();
        let paused = self.hv_paused.clone();
        // Ensure a fresh start always begins unpaused, even if a prior
        // session was stopped while paused.
        paused.store(false, std::sync::atomic::Ordering::SeqCst);
        let vcpu_count = self.config.vcpu_count;
        let pl011 = Arc::new(std::sync::Mutex::new(Pl011::new()));

        let vcpu_thread_handles = self
            .hv_vcpu_thread_handles
            .clone()
            .expect("hv_vcpu_thread_handles asserted Some above");
        let hv_vcpu_ids = self
            .hv_vcpu_ids
            .clone()
            .expect("hv_vcpu_ids asserted Some above");

        // --- Set up PSCI CPU_ON channels for secondary vCPUs ---
        let cpu_on_senders: Option<CpuOnSenders> = if vcpu_count > 1 {
            let mut senders_vec: Vec<Option<mpsc::Sender<CpuOnRequest>>> = Vec::new();
            senders_vec.push(None); // Slot 0 = BSP

            for i in 1..vcpu_count {
                let (tx, rx) = mpsc::channel::<CpuOnRequest>();
                senders_vec.push(Some(tx));

                let r = running.clone();
                let p = paused.clone();
                let dm = device_manager.clone();
                let th = vcpu_thread_handles.clone();
                let ids = hv_vcpu_ids.clone();
                let uart = pl011.clone();
                let hvc_fds_clone = self.hvc_blk_fds.clone();
                let senders_placeholder: Option<CpuOnSenders> = None;

                let t = std::thread::Builder::new()
                    .name(format!("hv-vcpu-{i}"))
                    .spawn(move || match rx.recv() {
                        Ok(req) => {
                            tracing::info!(
                                "vCPU {i}: received CPU_ON, starting at {:#x}",
                                req.entry_point
                            );
                            vcpu_run_loop(
                                i,
                                req.entry_point,
                                req.context_id,
                                VcpuContext {
                                    device_manager: dm,
                                    running: r,
                                    paused: p,
                                    pl011: uart,
                                    cpu_on_senders: senders_placeholder,
                                    vcpu_thread_handles: th,
                                    hv_vcpu_ids: ids,
                                    hvc_blk_fds: hvc_fds_clone,
                                },
                            );
                        }
                        Err(_) => {
                            tracing::debug!("vCPU {i}: channel closed, never started");
                        }
                    })
                    .map_err(|e| VmmError::Vcpu(format!("spawn vcpu-{i}: {e}")))?;
                self.hv_vcpu_threads.push(t);
            }

            let senders = Arc::new(Mutex::new(senders_vec));
            self.hv_cpu_on_senders = Some(senders.clone());
            Some(senders)
        } else {
            None
        };

        // --- Spawn BSP (vCPU 0) ---
        let hvc_blk_fds = self.hvc_blk_fds.clone();
        let bsp_hv_vcpu_ids = hv_vcpu_ids;
        {
            let t = std::thread::Builder::new()
                .name("hv-vcpu-0".to_string())
                .spawn(move || {
                    vcpu_run_loop(
                        0,
                        kernel_entry,
                        fdt_addr,
                        VcpuContext {
                            device_manager,
                            running,
                            paused,
                            pl011,
                            cpu_on_senders,
                            vcpu_thread_handles,
                            hv_vcpu_ids: bsp_hv_vcpu_ids,
                            hvc_blk_fds,
                        },
                    );
                })
                .map_err(|e| VmmError::Vcpu(format!("spawn vcpu-0: {e}")))?;
            self.hv_vcpu_threads.push(t);
        }

        tracing::info!(
            "Custom HV VMM started: {} vCPU(s) (BSP running, {} secondary parked)",
            vcpu_count,
            vcpu_count.saturating_sub(1)
        );
        Ok(())
    }

    /// Stops the HV backend by signaling vCPU threads and cleaning up resources.
    #[allow(clippy::unnecessary_wraps)]
    pub(in crate::vmm) fn stop_darwin_hv(&mut self) -> Result<()> {
        // Signal all vCPU threads to exit.
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);

        // Drop the PSCI CPU_ON channel senders. Secondary vCPU threads
        // spawn with `rx.recv()` waiting for a CPU_ON request; when the
        // guest only brought up the BSP they stay parked indefinitely.
        // Dropping the senders makes their `recv()` return `Err(RecvError)`
        // so they exit the recv and hit the `running=false` check. See
        // ABX-364 — before this drop the secondary vCPU join could take
        // 20+ seconds.
        self.hv_cpu_on_senders.take();

        // Drop block-I/O worker senders so `rx.recv()` in
        // `blk_io_worker_loop` returns `Err(RecvError)` and the workers
        // exit cleanly. The senders live on the `DeviceManager` via
        // `BlkWorkerHandle`; clearing the map releases our last
        // reference. ABX-364.
        if let Some(ref dm) = self.hv_device_manager {
            dm.clear_blk_workers();
        }

        // Drive every vCPU thread to exit. `hv_vcpus_exit` needs a concrete
        // list of vCPU IDs on arm64 (see ABX-367); we snapshot the ID
        // registry once up front because all vCPUs have been created by the
        // time stop runs. A single well-formed cancel is normally enough,
        // but we loop until threads self-exit or a deadline trips, since a
        // vCPU observed outside `vcpu.run()` will pick up the cancel on its
        // next re-entry.
        let vcpu_ids_snapshot: Vec<u64> = self
            .hv_vcpu_ids
            .as_ref()
            .map(|ids| {
                ids.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            })
            .unwrap_or_default();

        // Warn if the snapshot is empty while threads are still alive: this
        // means vCPU threads were spawned before they registered their IDs,
        // so `hv_vcpus_exit` will be a no-op and the loop may spin until the
        // deadline. See ABX-367 regression class.
        if vcpu_ids_snapshot.is_empty() && self.hv_vcpu_threads.iter().any(|t| !t.is_finished()) {
            tracing::warn!(
                "stop_darwin_hv: vCPU ID registry empty; threads may not exit cleanly (ABX-367 regression class)"
            );
        }

        let stop_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut iterations: u32 = 0;
        loop {
            if self
                .hv_vcpu_threads
                .iter()
                .all(std::thread::JoinHandle::is_finished)
            {
                tracing::debug!(
                    "stop_darwin_hv: all vCPU threads finished after {iterations} cancel iterations"
                );
                break;
            }
            if std::time::Instant::now() >= stop_deadline {
                let alive = self
                    .hv_vcpu_threads
                    .iter()
                    .filter(|t| !t.is_finished())
                    .count();
                tracing::warn!(
                    "stop_darwin_hv: {alive} vCPU thread(s) did not exit within 5s after {iterations} cancel iterations, proceeding to join (may block)"
                );
                break;
            }

            iterations += 1;
            if let Some(ref vm) = self.hv_vm {
                if let Err(e) = vm.exit_vcpus(&vcpu_ids_snapshot) {
                    tracing::warn!("hv_vcpus_exit failed (iter {iterations}): {e}");
                }
            }
            if let Some(ref handles) = self.hv_vcpu_thread_handles {
                let guard = handles
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for t in guard.iter() {
                    t.unpark();
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        // Join all vCPU threads — the loop above has either confirmed they
        // are `is_finished()` (join is instant) or we timed out and accept a
        // possible block.
        for t in self.hv_vcpu_threads.drain(..) {
            if let Err(e) = t.join() {
                tracing::warn!("vCPU thread join failed: {e:?}");
            }
        }

        // Join all block I/O worker threads before dropping guest memory.
        // Workers hold GuestMemWriter which references the guest RAM mapping;
        // dropping guest memory first would create a use-after-free.
        for t in self.hv_blk_worker_threads.drain(..) {
            if let Err(e) = t.join() {
                tracing::warn!("blk worker thread join failed: {e:?}");
            }
        }

        // Join the net RX worker (rx-inject or legacy net-io) for the same
        // reason: it also holds GuestMemWriter. The thread polls `running`
        // every POLL_TIMEOUT (1 ms) so it will observe the store above and
        // exit promptly, but we must still wait for it before unmapping
        // guest memory.
        if let Some(ref dm) = self.hv_device_manager {
            if let Some(t) = dm.take_net_rx_worker_handle() {
                if let Err(e) = t.join() {
                    tracing::warn!("net rx worker thread join failed: {e:?}");
                }
            }
        }

        // Join the vsock-io worker for the same reason: it injects into
        // guest memory via the DeviceManager. It observes `running=false`
        // within its kevent backstop timeout (10 ms).
        if let Some(t) = self.hv_vsock_worker.take() {
            if let Err(e) = t.join() {
                tracing::warn!("vsock-io worker thread join failed: {e:?}");
            }
        }

        // Cleanup in correct order: DAX → GIC → VM → guest memory.
        //
        // DAX mappers must be drained first because `hv_vm_unmap` must be
        // called while the VM is still alive. `drain_all` calls `hv_vm_unmap`
        // + `munmap` for every active mapping and marks the mapper drained so
        // its `Drop` impl becomes a no-op. After this point it is safe to
        // call `hv_vm_destroy` (via `hv_vm.take()`).
        for mapper in &self.hv_dax_mappers {
            mapper.drain_all();
        }
        self.hv_dax_mappers.clear();

        #[cfg(feature = "gic")]
        {
            self.hv_gic.take();
        }
        self.hv_vm.take();

        // Guest memory must outlive hv_vm so the mapped pages remain valid
        // until hv_vm_destroy completes (taken above).
        self.hv_guest_mem.take();

        tracing::info!("Custom VMM stopped");
        Ok(())
    }

    /// Cooperatively pauses every vCPU thread in the HV backend.
    ///
    /// Sets `hv_paused` and calls `hv_vcpus_exit` to kick all vCPUs out of
    /// their in-progress `vcpu.run()` calls. Each vCPU observes the flag on
    /// its next loop iteration and parks itself. Block, net, and vsock
    /// worker threads are left running — their virtqueue state lives in
    /// guest memory and naturally quiesces once no vCPU is executing.
    ///
    /// Returns immediately after the exit kick; parking is best-effort and
    /// there is no explicit "all vCPUs parked" acknowledgement. Callers
    /// needing synchronous pause semantics must rely on the fact that the
    /// guest cannot observe any externally-visible change once all vCPU
    /// threads are parked.
    #[allow(clippy::unnecessary_wraps)]
    pub(in crate::vmm) fn pause_darwin_hv(&self) -> Result<()> {
        self.hv_paused
            .store(true, std::sync::atomic::Ordering::SeqCst);

        // Snapshot the registered vCPU IDs and issue a targeted
        // `hv_vcpus_exit`. On arm64 the NULL/0 form is a no-op, so without
        // an explicit list no vCPU actually leaves `vcpu.run()` and pause
        // becomes best-effort in the worst sense — observable pause latency
        // matches the time to the guest's next natural exit (timer tick,
        // MMIO, …). See ABX-367.
        let ids: Vec<u64> = self
            .hv_vcpu_ids
            .as_ref()
            .map(|ids| {
                ids.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            })
            .unwrap_or_default();
        if let Some(ref vm) = self.hv_vm {
            if let Err(e) = vm.exit_vcpus(&ids) {
                tracing::warn!("hv_vcpus_exit during pause failed: {e}");
            }
        }

        tracing::info!("HV VMM paused");
        Ok(())
    }

    /// Resumes every vCPU thread paused by `pause_darwin_hv`.
    ///
    /// Clears `hv_paused` and unparks every registered vCPU thread via
    /// `hv_vcpu_thread_handles`. Each thread wakes from `park()`, re-checks
    /// the flag, and re-enters the run loop.
    #[allow(clippy::unnecessary_wraps)]
    pub(in crate::vmm) fn resume_darwin_hv(&self) -> Result<()> {
        self.hv_paused
            .store(false, std::sync::atomic::Ordering::SeqCst);

        if let Some(ref handles) = self.hv_vcpu_thread_handles {
            let guard = handles
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for t in guard.iter() {
                t.unpark();
            }
        }

        tracing::info!("HV VMM resumed");
        Ok(())
    }
}
