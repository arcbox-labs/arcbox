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
//! injects frames directly into the guest virtio-net RX queue, and
//! coalesces interrupts to minimize VM exit overhead.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::blk_worker::GuestMemWriter;
use crate::device::VirtioMmioState;
use crate::irq::Irq;
use crate::virtqueue_util;

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

/// VirtIO-net header size (all zeros for simple RX passthrough).
const VIRTIO_NET_HDR_SIZE: usize = 12;

/// Immutable RX queue layout, captured once at DRIVER_OK time.
/// All GPAs are absolute guest physical addresses, translated to
/// host offsets by `GuestMemWriter::gpa_to_offset`.
pub struct RxQueueConfig {
    pub desc_gpa: u64,
    pub avail_gpa: u64,
    pub used_gpa: u64,
    pub size: u16,
}

/// Shared context for the net-io worker thread.
pub struct NetRxWorkerContext {
    /// Raw fd of the HV-side socketpair end (non-blocking, SOCK_DGRAM).
    pub net_host_fd: i32,
    /// Guest memory writer (Send + Sync, VM-lifetime pointer).
    pub guest_mem: GuestMemWriter,
    /// RX queue layout (queue index 0 of primary VirtioNet).
    pub rx_queue: RxQueueConfig,
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

// SAFETY: All fields are either Send+Sync or raw pointers wrapped in
// GuestMemWriter which is Send+Sync. The irq_callback and exit_vcpus
// closures capture only thread-safe types (Arc<Gic>, weak refs).
unsafe impl Send for NetRxWorkerContext {}

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

/// Conditionally triggers an interrupt based on EVENT_IDX suppression.
/// Only fires set_spi + hv_vcpus_exit when the guest actually wants
/// a notification (used_event crossed). Reduces VM exits significantly.
fn maybe_notify(ctx: &NetRxWorkerContext, old_used: u16, new_used: u16) {
    if virtqueue_util::should_notify(
        &ctx.guest_mem,
        ctx.rx_queue.avail_gpa,
        ctx.rx_queue.size,
        old_used,
        new_used,
    ) {
        trigger_net_irq(ctx);
    }
}

/// Injects a single frame into the guest RX queue.
///
/// Returns `true` if the frame was successfully injected, `false`
/// if no RX descriptors are available or the frame couldn't be written.
fn inject_one_frame(ctx: &NetRxWorkerContext, frame: &[u8], used_idx: &mut u16) -> bool {
    let q_size = ctx.rx_queue.size as usize;
    if q_size == 0 {
        return false;
    }

    // Read avail_idx from guest memory.
    std::sync::atomic::fence(Ordering::Acquire);
    let avail_idx = ctx.guest_mem.read_u16(ctx.rx_queue.avail_gpa as usize + 2);
    if *used_idx == avail_idx {
        return false; // No RX descriptors available.
    }

    // Pop available descriptor.
    let ring_off = ctx.rx_queue.avail_gpa as usize + 4 + 2 * ((*used_idx as usize) % q_size);
    let head_idx = ctx.guest_mem.read_u16(ring_off) as usize;

    // Build packet: virtio-net header (zeroed) + ethernet frame.
    let total_len = VIRTIO_NET_HDR_SIZE + frame.len();

    // Walk descriptor chain and write the packet.
    let mut written = 0;
    let mut idx = head_idx;
    let desc_base = ctx.rx_queue.desc_gpa as usize;

    for _ in 0..q_size {
        let d_off = desc_base + idx * 16;
        let Some(desc_slice) = ctx.guest_mem.slice(d_off, 16) else {
            break;
        };

        let addr_gpa = u64::from_le_bytes(desc_slice[0..8].try_into().unwrap()) as usize;
        let len = u32::from_le_bytes(desc_slice[8..12].try_into().unwrap()) as usize;
        let flags = u16::from_le_bytes(desc_slice[12..14].try_into().unwrap());
        let next = u16::from_le_bytes(desc_slice[14..16].try_into().unwrap());

        // RX descriptors are device-writable (flag bit 1).
        if flags & 2 != 0 && len > 0 {
            // SAFETY: VirtIO descriptor buffers are device-owned during
            // injection. The guest will not access them until used_idx
            // advances (after Release fence below).
            let Some(buf) = (unsafe { ctx.guest_mem.slice_mut(addr_gpa, len) }) else {
                continue;
            };

            let remaining = total_len.saturating_sub(written);
            let to_write = remaining.min(len);

            if written < VIRTIO_NET_HDR_SIZE {
                // Write virtio-net header (or partial header).
                // With MRG_RXBUF, num_buffers (bytes 10-11) must be 1.
                let hdr_remaining = VIRTIO_NET_HDR_SIZE - written;
                let hdr_bytes = hdr_remaining.min(to_write);
                buf[..hdr_bytes].fill(0);
                if written <= 10 && written + hdr_bytes > 10 {
                    let nb_off = 10 - written;
                    if nb_off + 2 <= hdr_bytes {
                        buf[nb_off..nb_off + 2].copy_from_slice(&1u16.to_le_bytes());
                    }
                }
                // GSO for large TCP/IPv4 frames with NEEDS_CSUM.
                if written == 0
                    && hdr_bytes >= 10
                    && frame.len() > 1500
                    && frame.len() >= 54
                    && frame[12] == 0x08
                    && frame[13] == 0x00
                    && frame[23] == 6
                    && frame[14] & 0x0F == 5
                {
                    buf[0] = 1; // NEEDS_CSUM
                    buf[1] = 1; // GSO_TCPV4
                    buf[2..4].copy_from_slice(&54u16.to_le_bytes()); // hdr_len: ETH(14)+IP(20)+TCP(20)
                    buf[4..6].copy_from_slice(&1460u16.to_le_bytes()); // gso_size
                    buf[6..8].copy_from_slice(&34u16.to_le_bytes()); // csum_start: offset to TCP hdr
                    buf[8..10].copy_from_slice(&16u16.to_le_bytes()); // csum_offset: TCP checksum
                }
                // Write frame data after header.
                let frame_bytes = to_write - hdr_bytes;
                if frame_bytes > 0 {
                    buf[hdr_bytes..hdr_bytes + frame_bytes].copy_from_slice(&frame[..frame_bytes]);
                }
            } else {
                // Pure frame data.
                let frame_off = written - VIRTIO_NET_HDR_SIZE;
                buf[..to_write].copy_from_slice(&frame[frame_off..frame_off + to_write]);
            }
            written += to_write;
        }

        if flags & 1 == 0 || written >= total_len {
            break;
        }
        idx = next as usize;
    }

    if written == 0 {
        return false;
    }

    // Update used ring entry.
    let used_entry_off = ctx.rx_queue.used_gpa as usize + 4 + ((*used_idx as usize) % q_size) * 8;
    ctx.guest_mem.write_u32(used_entry_off, head_idx as u32);
    ctx.guest_mem.write_u32(used_entry_off + 4, written as u32);

    // Release fence: ensure descriptor data is visible before used_idx.
    std::sync::atomic::fence(Ordering::Release);
    *used_idx = used_idx.wrapping_add(1);
    ctx.guest_mem
        .write_u16(ctx.rx_queue.used_gpa as usize + 2, *used_idx);

    true
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

    // Read used_idx from guest memory (resume from where poll_net_rx left off).
    let mut used_idx = ctx.guest_mem.read_u16(ctx.rx_queue.used_gpa as usize + 2);
    let mut pending_frames: u16 = 0;
    let mut batch_start: Option<Instant> = None;
    let mut old_used = used_idx;

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
            old_used = used_idx;

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
                if inject_one_frame(&ctx, frame, &mut used_idx) {
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
                        write_avail_event(&ctx, used_idx);
                        maybe_notify(&ctx, old_used, used_idx);
                        pending_frames = 0;
                        batch_start = None;
                        old_used = used_idx;
                    }
                    // 100μs gives the vCPU enough time to process the
                    // interrupt and repost descriptors.
                    std::thread::sleep(Duration::from_micros(100));
                    break;
                }

                // Check count threshold.
                if pending_frames >= COALESCE_COUNT {
                    write_avail_event(&ctx, used_idx);
                    maybe_notify(&ctx, old_used, used_idx);
                    pending_frames = 0;
                    batch_start = None;
                    old_used = used_idx;
                }
            }
        }

        // Check time threshold for pending un-notified frames.
        if pending_frames > 0 {
            if let Some(start) = batch_start {
                if start.elapsed() >= COALESCE_TIMEOUT {
                    write_avail_event(&ctx, used_idx);
                    maybe_notify(&ctx, old_used, used_idx);
                    pending_frames = 0;
                    batch_start = None;
                }
            }
        }
    }

    // Flush any remaining pending frames on shutdown.
    if pending_frames > 0 {
        write_avail_event(&ctx, used_idx);
        trigger_net_irq(&ctx); // Always notify on shutdown.
    }

    unsafe { libc::close(kq) };
    tracing::info!("net-io worker stopped");
}

/// Writes avail_event into the used ring so the guest knows when
/// to kick us for new RX buffer submissions (EVENT_IDX).
fn write_avail_event(ctx: &NetRxWorkerContext, used_idx: u16) {
    let q_size = ctx.rx_queue.size as usize;
    let avail_event_off = ctx.rx_queue.used_gpa as usize + 4 + q_size * 8;
    // Request notification when guest posts the next batch of buffers.
    let avail_idx = ctx.guest_mem.read_u16(ctx.rx_queue.avail_gpa as usize + 2);
    // Release fence: ensure prior used-ring writes are globally visible
    // before the guest observes the new avail_event value. On ARM64 plain
    // stores are not ordered across threads without this.
    std::sync::atomic::fence(Ordering::Release);
    ctx.guest_mem.write_u16(avail_event_off, avail_idx);
    let _ = used_idx; // Suppress unused warning; used_idx is for future should_notify.
}
