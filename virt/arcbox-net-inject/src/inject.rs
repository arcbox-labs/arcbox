//! Dedicated OS thread for RX frame injection.
//!
//! Supports two input paths:
//!   1. **Channel frames** (`rx`): pre-constructed Ethernet frames from the
//!      classifier / DHCP / DNS / ARP / handshake synthesizer.
//!   2. **Inline connections** (`conn_rx`): promoted fast-path TCP sockets that
//!      read directly into guest descriptor buffers (zero intermediate copies).

use std::io::{IoSliceMut, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError};

use crate::guest_mem::GuestMemWriter;
use crate::inline_conn::{self, InlineConn};
use crate::irq::IrqHandle;
use crate::queue::{self, RxQueueConfig};

/// Maximum frames to inject per batch before checking interrupt thresholds.
///
/// At line-rate (~9 Gbps, 500k fps), a batch of 64 frames means the inject
/// thread fires IRQ ~8000 times/second. Each IRQ entails an MMIO trap and
/// guest-side RX soft-irq processing. Raising to 256 cuts IRQ rate to
/// ~2000/s while the 50 µs `COALESCE_TIMEOUT` still bounds latency.
const BATCH_SIZE: usize = 256;

/// Interrupt coalescing timeout.
///
/// With GSO on the RX path the average frame size is ~30 KiB, so at
/// 10 Gbps we're at ~37 kfps — a 50 µs timeout only batches ~2 frames
/// before firing an IRQ, so the `BATCH_SIZE` ceiling is never reached.
/// 200 µs raises the effective batch to ~7 frames without noticeably
/// hurting ACK latency (Linux NAPI poll is typically 200 µs anyway).
const COALESCE_TIMEOUT: Duration = Duration::from_micros(200);

/// Backoff duration when RX descriptors are exhausted.
const DESCRIPTOR_BACKOFF: Duration = Duration::from_micros(100);

/// Context for the RX injection thread.
pub struct RxInjectThread {
    /// Channel receiving raw Ethernet frames from the producer.
    pub rx: Receiver<Vec<u8>>,
    /// Channel for receiving promoted fast-path connections.
    pub conn_rx: Receiver<InlineConn>,
    /// Guest memory writer (Send + Sync, VM-lifetime pointer).
    pub guest_mem: GuestMemWriter,
    /// RX queue layout (queue index 0 of primary VirtioNet).
    pub queue: RxQueueConfig,
    /// Interrupt delivery handle.
    pub irq: IrqHandle,
    /// MMIO state for setting interrupt_status. Wrapped for &self access.
    /// The inject thread needs to set interrupt_status |= INT_VRING
    /// before firing the GIC SPI.
    pub set_interrupt_status: Arc<dyn Fn() + Send + Sync>,
    /// VM shutdown flag.
    pub running: Arc<AtomicBool>,
    /// Whether `VIRTIO_F_EVENT_IDX` was negotiated with the guest. When
    /// true, `flush_interrupt` consults the guest's `used_event_idx`
    /// before firing the IRQ and skips the GIC SPI / vCPU exit / pthread
    /// wakeup chain when the driver isn't waiting. Profiling showed this
    /// path dominating rx-inject CPU under multi-flow load.
    pub event_idx_enabled: bool,
}

// SAFETY: All fields are either Send+Sync or raw pointers wrapped
// in GuestMemWriter which is Send+Sync.
unsafe impl Send for RxInjectThread {}

impl RxInjectThread {
    /// Runs the injection loop until `running` is set to false or
    /// the channel is disconnected.
    pub fn run(self) {
        tracing::info!(
            "rx-inject thread started (queue_size={}, event_idx={})",
            self.queue.size,
            self.event_idx_enabled,
        );

        let mut used_idx = self.guest_mem.read_u16(self.queue.used_gpa as usize + 2);
        let mut old_used = used_idx;
        let mut inline_conns: Vec<InlineConn> = Vec::new();

        loop {
            if !self.running.load(Ordering::Relaxed) {
                break;
            }

            // Phase 1: Accept new inline connections (non-blocking).
            while let Ok(conn) = self.conn_rx.try_recv() {
                tracing::info!(
                    "inline conn added: {}:{} -> {}:{}",
                    conn.remote_ip,
                    conn.remote_port,
                    conn.guest_ip,
                    conn.guest_port,
                );
                inline_conns.push(conn);
            }

            let mut batch = 0u16;
            let loop_start = Instant::now();

            // Phase 2: Poll inline connections (direct socket -> guest buffer).
            if !inline_conns.is_empty() {
                self.poll_inline_conns(&mut inline_conns, &mut used_idx, &mut batch);
            }

            // Phase 3: Drain channel frames (classifier / DHCP / DNS / ARP).
            // Use the remaining coalescing timeout after inline polling.
            let elapsed = loop_start.elapsed();
            let remaining = COALESCE_TIMEOUT.saturating_sub(elapsed);

            while (batch as usize) < BATCH_SIZE {
                // Use the remaining timeout for the first recv, then zero
                // for subsequent ones to drain without blocking.
                let timeout = if batch == 0 && inline_conns.is_empty() {
                    // No inline conns and nothing batched yet — block for
                    // the full coalescing timeout.
                    COALESCE_TIMEOUT
                } else if remaining.is_zero() {
                    // Timeout already consumed by inline polling — try_recv only.
                    Duration::ZERO
                } else {
                    remaining
                };

                let frame = match self.rx.recv_timeout(timeout) {
                    Ok(f) => f,
                    Err(RecvTimeoutError::Timeout) => break,
                    Err(RecvTimeoutError::Disconnected) => {
                        tracing::info!("rx-inject: channel disconnected, shutting down");
                        if batch > 0 {
                            self.flush_interrupt(old_used, used_idx);
                        }
                        return;
                    }
                };

                if queue::inject_one_frame(&self.guest_mem, &self.queue, &frame, &mut used_idx) {
                    batch += 1;
                } else {
                    // Descriptor exhaustion: flush interrupt so guest can
                    // process and repost, then backoff.
                    if batch > 0 {
                        self.flush_interrupt(old_used, used_idx);
                        old_used = used_idx;
                        batch = 0;
                    }
                    std::thread::sleep(DESCRIPTOR_BACKOFF);

                    // Retry this frame once.
                    if queue::inject_one_frame(&self.guest_mem, &self.queue, &frame, &mut used_idx)
                    {
                        batch += 1;
                    }
                    // If still fails, frame is lost (TCP retransmit recovers).
                }
            }

            if batch > 0 {
                self.flush_interrupt(old_used, used_idx);
                old_used = used_idx;
            }
        }

        // Final flush on shutdown.
        if old_used != used_idx {
            self.flush_interrupt(old_used, used_idx);
        }

        tracing::info!(
            "rx-inject thread stopped ({} inline conns remaining)",
            inline_conns.len(),
        );
    }

    /// Polls all active inline connections, reading from host sockets
    /// directly into guest descriptor buffers. Connections that reach
    /// EOF or error are marked and pruned at the start of the next call.
    ///
    /// Uses VIRTIO_NET_F_MRG_RXBUF to coalesce up to `MAX_MERGE` descriptors
    /// into a single logical Ethernet frame per `readv()` syscall. This
    /// amortizes per-frame header cost and IRQ delivery over a much larger
    /// payload (up to ~60 KB), letting one GSO_TCPV4 frame fan out into
    /// dozens of MSS-sized guest segments.
    fn poll_inline_conns(
        &self,
        inline_conns: &mut Vec<InlineConn>,
        used_idx: &mut u16,
        batch: &mut u16,
    ) {
        let q_size = self.queue.size as usize;
        if q_size == 0 {
            return;
        }

        // Prune closed connections from previous iteration.
        inline_conns.retain(|c| !c.host_eof);

        // Fair-share pass: each conn gets at most PER_CONN_READS `readv`
        // calls per outer iteration. Each call can span up to MAX_MERGE
        // descriptors, so a busy conn can still move ~PER_CONN_READS ×
        // (MAX_MERGE × per-desc) bytes between IRQ flushes, while leaving
        // budget for other conns.
        const PER_CONN_READS: u16 = 16;

        // Max descriptors per `readv` (upper bound on num_buffers stamped
        // into the first descriptor's virtio-net header).
        const MAX_MERGE: usize = 16;

        // Cap on total payload per frame so the IPv4 total_length field
        // (u16) doesn't overflow. 60000 = 60040 with Eth/IP/TCP headers,
        // leaving ~5 KB of headroom under the 65535 limit.
        const MAX_FRAME_PAYLOAD: usize = 60000;

        let desc_base = self.queue.desc_gpa as usize;

        // Scratch buffers reused across iterations (stack-allocated).
        let mut head_indices: [u16; MAX_MERGE] = [0; MAX_MERGE];
        let mut desc_ptrs: [*mut u8; MAX_MERGE] = [std::ptr::null_mut(); MAX_MERGE];
        let mut desc_lens: [usize; MAX_MERGE] = [0; MAX_MERGE];

        for conn in inline_conns.iter_mut() {
            let mut per_conn = 0u16;
            loop {
                if (*batch as usize) >= BATCH_SIZE {
                    break;
                }
                if per_conn >= PER_CONN_READS {
                    break;
                }

                // How many descriptors has the guest posted that we haven't
                // consumed yet? Wrapping subtraction on u16 gives the correct
                // count even across the 65536 boundary.
                std::sync::atomic::fence(Ordering::Acquire);
                let avail_idx = self.guest_mem.read_u16(self.queue.avail_gpa as usize + 2);
                let available = avail_idx.wrapping_sub(*used_idx) as usize;
                if available == 0 {
                    return;
                }

                // Gather up to MAX_MERGE descriptors into the scratch arrays.
                // No mutation of guest memory yet — we only commit after
                // readv succeeds.
                let want = available.min(MAX_MERGE);
                let mut count = 0usize;
                let mut total_iov_cap = 0usize;

                for i in 0..want {
                    let slot = (*used_idx).wrapping_add(i as u16) as usize % q_size;
                    let ring_off = self.queue.avail_gpa as usize + 4 + 2 * slot;
                    let head_idx = self.guest_mem.read_u16(ring_off);

                    let d_off = desc_base + (head_idx as usize) * 16;
                    let Some(desc_slice) = self.guest_mem.slice(d_off, 16) else {
                        break;
                    };
                    let addr_gpa =
                        u64::from_le_bytes(desc_slice[0..8].try_into().unwrap()) as usize;
                    let buf_len =
                        u32::from_le_bytes(desc_slice[8..12].try_into().unwrap()) as usize;
                    let flags = u16::from_le_bytes(desc_slice[12..14].try_into().unwrap());

                    if flags & 2 == 0 {
                        // Not device-writable — we can't use this chain. Stop
                        // here; we'll revisit on the next pass once the guest
                        // reposts.
                        break;
                    }
                    let min_len = if i == 0 {
                        inline_conn::TOTAL_HDR_LEN + 1
                    } else {
                        1
                    };
                    if buf_len < min_len {
                        break;
                    }

                    let Some(off) = self.guest_mem.gpa_to_offset(addr_gpa, buf_len) else {
                        break;
                    };
                    // SAFETY: gpa_to_offset validated bounds. Each descriptor
                    // buffer is exclusive to the device until the used ring
                    // is advanced past it.
                    let ptr = unsafe { self.guest_mem.ptr().add(off) };

                    let iov_cap = if i == 0 {
                        buf_len - inline_conn::TOTAL_HDR_LEN
                    } else {
                        buf_len
                    };
                    // Stop growing the frame if the next descriptor would
                    // push us past MAX_FRAME_PAYLOAD. Always admit the first
                    // descriptor so we can at least emit a 1-byte frame.
                    if i > 0 && total_iov_cap + iov_cap > MAX_FRAME_PAYLOAD {
                        break;
                    }

                    head_indices[i] = head_idx;
                    desc_ptrs[i] = ptr;
                    desc_lens[i] = buf_len;
                    total_iov_cap += iov_cap;
                    count += 1;
                }

                if count == 0 {
                    break;
                }

                // Build iovecs from raw pointers. We constructed each slice
                // from a distinct descriptor buffer region, so the slices
                // are non-overlapping even though the borrow checker can't
                // see that.
                let mut iovs: [IoSliceMut<'_>; MAX_MERGE] = std::array::from_fn(|_| {
                    // Placeholder — overwritten below for slots < count.
                    IoSliceMut::new(&mut [])
                });
                for i in 0..count {
                    let (start, cap) = if i == 0 {
                        (
                            inline_conn::TOTAL_HDR_LEN,
                            desc_lens[i] - inline_conn::TOTAL_HDR_LEN,
                        )
                    } else {
                        (0, desc_lens[i])
                    };
                    // SAFETY: desc_ptrs[i] points into the VM-lifetime
                    // guest mmap (bounds checked by gpa_to_offset above).
                    // The buffer is device-owned until we advance used_idx,
                    // and each pointer addresses a distinct descriptor.
                    let slice =
                        unsafe { std::slice::from_raw_parts_mut(desc_ptrs[i].add(start), cap) };
                    iovs[i] = IoSliceMut::new(slice);
                }

                let read_result = conn.stream.read_vectored(&mut iovs[..count]);
                match read_result {
                    Ok(0) => {
                        tracing::debug!(
                            "inline {}:{}->{}:{} host EOF",
                            conn.remote_ip,
                            conn.remote_port,
                            conn.guest_ip,
                            conn.guest_port
                        );
                        conn.host_eof = true;

                        // Consume only the first descriptor for the FIN frame.
                        // SAFETY: first descriptor buffer is exclusive to us.
                        let first_buf =
                            unsafe { std::slice::from_raw_parts_mut(desc_ptrs[0], desc_lens[0]) };
                        inline_conn::write_fin_headers(first_buf, conn);
                        conn.our_seq.fetch_add(1, Ordering::Relaxed);

                        let used_entry_off =
                            self.queue.used_gpa as usize + 4 + ((*used_idx as usize) % q_size) * 8;
                        self.guest_mem
                            .write_u32(used_entry_off, head_indices[0] as u32);
                        self.guest_mem
                            .write_u32(used_entry_off + 4, inline_conn::TOTAL_HDR_LEN as u32);

                        std::sync::atomic::fence(Ordering::Release);
                        *used_idx = used_idx.wrapping_add(1);
                        self.guest_mem
                            .write_u16(self.queue.used_gpa as usize + 2, *used_idx);

                        *batch += 1;
                        break;
                    }
                    Ok(n) => {
                        // Distribute the n bytes across the iovecs. readv
                        // fills iov[0] to capacity before spilling into
                        // iov[1], etc.
                        let mut remaining = n;
                        let mut num_used = 0usize;
                        let mut per_desc_len = [0usize; MAX_MERGE];
                        for i in 0..count {
                            if remaining == 0 {
                                break;
                            }
                            let cap = if i == 0 {
                                desc_lens[i] - inline_conn::TOTAL_HDR_LEN
                            } else {
                                desc_lens[i]
                            };
                            let filled = remaining.min(cap);
                            per_desc_len[i] = filled;
                            remaining -= filled;
                            num_used = i + 1;
                        }

                        // Stamp the first descriptor's header with
                        // num_buffers = num_used and payload_len = n.
                        // SAFETY: first descriptor is exclusive to us.
                        let first_buf =
                            unsafe { std::slice::from_raw_parts_mut(desc_ptrs[0], desc_lens[0]) };
                        inline_conn::write_inline_headers(first_buf, conn, n, num_used as u16);

                        // Advance the shared atomic so ACK frames emitted by
                        // the datapath carry the correct seq value.
                        conn.our_seq.fetch_add(n as u32, Ordering::Relaxed);

                        // Post used-ring entries: one per descriptor used.
                        // The first entry also accounts for the 66-byte
                        // header written in-place.
                        for i in 0..num_used {
                            let slot = (*used_idx).wrapping_add(i as u16) as usize % q_size;
                            let used_entry_off = self.queue.used_gpa as usize + 4 + slot * 8;
                            let entry_len = if i == 0 {
                                inline_conn::TOTAL_HDR_LEN + per_desc_len[0]
                            } else {
                                per_desc_len[i]
                            };
                            self.guest_mem
                                .write_u32(used_entry_off, head_indices[i] as u32);
                            self.guest_mem
                                .write_u32(used_entry_off + 4, entry_len as u32);
                        }

                        // Release fence, then publish the new used_idx.
                        std::sync::atomic::fence(Ordering::Release);
                        *used_idx = used_idx.wrapping_add(num_used as u16);
                        self.guest_mem
                            .write_u16(self.queue.used_gpa as usize + 2, *used_idx);

                        *batch += num_used as u16;
                        per_conn += 1;
                        // Continue — try another readv on this conn.
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        break;
                    }
                    Err(e) => {
                        tracing::debug!("inline conn error: {e}");
                        conn.host_eof = true;
                        break;
                    }
                }
            }
        }
    }

    /// Fires interrupt after a batch of injections, subject to EVENT_IDX
    /// suppression when the feature is negotiated.
    ///
    /// Profiling under multi-flow load showed the unconditional fire path
    /// (`hv_vcpus_exit` + `hv_gic_set_spi` + `pthread_cond_signal`) eating
    /// ~15× more CPU than under single-flow — because GSO can't merge
    /// across flows, dual-flow roughly doubles the frame count per Gbps,
    /// and every extra frame pays the full IRQ delivery cost. With
    /// EVENT_IDX, we consult the guest's `used_event_idx` and skip the
    /// whole chain when the driver is already polling past our update
    /// range.
    fn flush_interrupt(&self, old_used: u16, used_idx: u16) {
        let q_size = self.queue.size as usize;

        // Publish avail_event at the tail of the used ring. Lets the guest
        // suppress its own MMIO kicks when the device has buffer slack.
        // Release ordering here pairs with the guest's Acquire on the
        // used-ring: prior used-entry writes must be visible before this
        // value.
        let avail_event_off = self.queue.used_gpa as usize + 4 + q_size * 8;
        let avail_idx = self.guest_mem.read_u16(self.queue.avail_gpa as usize + 2);
        std::sync::atomic::fence(Ordering::Release);
        self.guest_mem.write_u16(avail_event_off, avail_idx);

        // Decide whether to raise an interrupt. Re-read of `used_event`
        // inside `should_notify` needs to see the driver's most recent
        // publish — AcqRel ensures our used-ring updates are visible to
        // the guest before we sample the threshold it writes in response.
        let fire = if self.event_idx_enabled {
            std::sync::atomic::fence(Ordering::AcqRel);
            crate::notify::should_notify(
                &self.guest_mem,
                self.queue.avail_gpa,
                q_size as u16,
                old_used,
                used_idx,
            )
        } else {
            old_used != used_idx
        };

        if fire {
            (self.set_interrupt_status)();
            self.irq.trigger();
        }
    }
}
