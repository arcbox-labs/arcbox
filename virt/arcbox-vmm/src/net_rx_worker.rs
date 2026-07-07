//! Dedicated net-io worker thread for VirtIO-net RX injection.
//!
//! Decouples network frame injection from the BSP vCPU run loop.
//! The BSP previously polled `net_host_fd` only at the top of each
//! `hv_vcpu_run` iteration and in the WFI handler. While inside
//! `hv_vcpu_run` (1-10ms), no polling happened — causing the
//! SOCK_DGRAM socketpair buffer to fill and stall the entire
//! host→guest data path.
//!
//! This worker thread continuously drains `net_host_fd` via kqueue,
//! injects frames into the guest virtio-net RX queue through the
//! unified `SplitQueue` (sharing `arcbox_net_inject::queue::
//! inject_one_frame` with the channel-based inject thread), and
//! coalesces interrupts to minimize VM exit overhead.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use arcbox_virtio::{GuestMemWriter, QueueConfig, SplitQueue};

use crate::device::VirtioMmioState;
use crate::irq::Irq;

/// Maximum frames to inject per kqueue wakeup before checking
/// interrupt coalescing thresholds.
const BATCH_SIZE: usize = 64;

/// Interrupt coalescing: fire after this many frames.
const COALESCE_COUNT: u16 = 64;

/// Interrupt coalescing: fire after this duration since first
/// un-notified frame (latency bound).
const COALESCE_TIMEOUT: Duration = Duration::from_micros(50);

/// kqueue poll timeout — bounds the shutdown check frequency.
const POLL_TIMEOUT: Duration = Duration::from_millis(1);

/// Shared context for the net-io worker thread.
pub struct NetRxWorkerContext {
    /// Raw fd of the HV-side socketpair end (non-blocking, SOCK_DGRAM).
    pub net_host_fd: i32,
    /// Guest memory (Send + Sync, VM-lifetime pointer). Backs the
    /// worker-owned `SplitQueue`.
    pub guest_mem: Arc<GuestMemWriter>,
    /// RX queue layout (queue index 0 of primary VirtioNet).
    pub rx_queue: QueueConfig,
    /// Whether `VIRTIO_F_EVENT_IDX` was negotiated with the guest.
    pub event_idx: bool,
    /// MMIO state for setting interrupt_status (INT_VRING).
    pub mmio_state: Arc<RwLock<VirtioMmioState>>,
    /// IRQ callback for GIC SPI injection (thread-safe).
    pub irq_callback: Arc<dyn Fn(Irq, bool) -> crate::error::Result<()> + Send + Sync>,
    /// IRQ number for the primary VirtioNet device.
    pub irq: Irq,
    /// Force-exit all vCPUs from hv_vcpu_run (thread-safe).
    pub exit_vcpus: Arc<dyn Fn() + Send + Sync>,
    /// VM shutdown flag.
    pub running: Arc<AtomicBool>,
}

/// Triggers a virtio-net RX interrupt: sets MMIO interrupt_status,
/// fires the GIC SPI, and kicks all vCPUs out of hv_vcpu_run.
fn trigger_net_irq(ctx: &NetRxWorkerContext) {
    // Set interrupt_status on MMIO state.
    if let Ok(mut s) = ctx.mmio_state.write() {
        s.trigger_interrupt(1); // INT_VRING
    }
    // Fire GIC SPI (thread-safe — hv_gic_set_spi is global).
    let _ = (ctx.irq_callback)(ctx.irq, true);
    // Force-exit vCPUs so they pick up the pending interrupt.
    (ctx.exit_vcpus)();
}

/// Flushes a batch: republishes `avail_event` (EVENT_IDX only) and fires
/// the IRQ when any push since the last flush requested one.
fn flush_batch(ctx: &NetRxWorkerContext, queue: &SplitQueue, fire: bool) {
    if ctx.event_idx {
        // RX semantics: publish the guest's current avail.idx (widest kick
        // suppression window for a polling consumer), not the consumed cursor.
        queue.write_avail_event_current();
    }
    if fire {
        trigger_net_irq(ctx);
    }
}

/// Main loop for the net-io worker thread.
///
/// Uses kqueue to wait on `net_host_fd` readability. On each wakeup,
/// drains up to `BATCH_SIZE` frames, injects them into the guest RX
/// virtqueue, then coalesces the interrupt.
pub fn net_rx_worker_loop(ctx: NetRxWorkerContext) {
    tracing::info!(
        "net-io worker started (fd={}, queue_size={})",
        ctx.net_host_fd,
        ctx.rx_queue.size
    );

    // Create kqueue for monitoring net_host_fd.
    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        tracing::error!(
            "net-io: kqueue creation failed: {}",
            std::io::Error::last_os_error()
        );
        return;
    }

    // Register net_host_fd for EVFILT_READ.
    let changelist = libc::kevent {
        ident: ctx.net_host_fd as usize,
        filter: libc::EVFILT_READ,
        flags: libc::EV_ADD | libc::EV_ENABLE,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    let ret = unsafe {
        libc::kevent(
            kq,
            &raw const changelist,
            1,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    };
    if ret < 0 {
        tracing::error!(
            "net-io: kevent registration failed: {}",
            std::io::Error::last_os_error()
        );
        unsafe { libc::close(kq) };
        return;
    }

    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: POLL_TIMEOUT.as_nanos() as i64,
    };

    let mut queue = SplitQueue::new(Arc::clone(&ctx.guest_mem), 0, &ctx.rx_queue, ctx.event_idx);
    // Resume from where poll_net_rx left off: RX consumes one avail entry
    // per used entry published, so the avail cursor starts at used.idx.
    queue.set_last_avail_idx(ctx.guest_mem.read_u16(ctx.rx_queue.used_addr as usize + 2));

    let mut pending_frames: u16 = 0;
    let mut batch_start: Option<Instant> = None;
    // Whether any push since the last flush requested an interrupt.
    let mut fire = false;

    loop {
        if !ctx.running.load(Ordering::Relaxed) {
            break;
        }

        // Wait for data on net_host_fd (or timeout for shutdown check).
        let mut event = libc::kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        let nev = unsafe {
            libc::kevent(
                kq,
                std::ptr::null(),
                0,
                &raw mut event,
                1,
                &raw const timeout,
            )
        };

        if nev > 0 {
            // net_host_fd is readable — drain frames.
            let mut frame_buf = [0u8; 2048];

            for _ in 0..BATCH_SIZE {
                let n = unsafe {
                    libc::read(
                        ctx.net_host_fd,
                        frame_buf.as_mut_ptr().cast::<libc::c_void>(),
                        frame_buf.len(),
                    )
                };
                if n <= 0 {
                    break; // No more data (EAGAIN) or error.
                }

                let frame = &frame_buf[..n as usize];
                if let Some(notify) = arcbox_net_inject::queue::inject_one_frame(&mut queue, frame)
                {
                    fire |= notify;
                    pending_frames += 1;
                    if batch_start.is_none() {
                        batch_start = Some(Instant::now());
                    }
                } else {
                    // No RX descriptors available. Flush pending interrupt
                    // so the guest can process and repost, then back off.
                    // The frame just read is lost — TCP retransmission from
                    // the host will recover it after the guest reposts.
                    if pending_frames > 0 {
                        flush_batch(&ctx, &queue, fire);
                        pending_frames = 0;
                        batch_start = None;
                        fire = false;
                    }
                    // 100μs gives the vCPU enough time to process the
                    // interrupt and repost descriptors.
                    std::thread::sleep(Duration::from_micros(100));
                    break;
                }

                // Check count threshold.
                if pending_frames >= COALESCE_COUNT {
                    flush_batch(&ctx, &queue, fire);
                    pending_frames = 0;
                    batch_start = None;
                    fire = false;
                }
            }
        }

        // Check time threshold for pending un-notified frames.
        if pending_frames > 0 {
            if let Some(start) = batch_start {
                if start.elapsed() >= COALESCE_TIMEOUT {
                    flush_batch(&ctx, &queue, fire);
                    pending_frames = 0;
                    batch_start = None;
                    fire = false;
                }
            }
        }
    }

    // Flush any remaining pending frames on shutdown.
    if pending_frames > 0 {
        if ctx.event_idx {
            queue.write_avail_event_current();
        }
        trigger_net_irq(&ctx); // Always notify on shutdown.
    }

    unsafe { libc::close(kq) };
    tracing::info!("net-io worker stopped");
}
