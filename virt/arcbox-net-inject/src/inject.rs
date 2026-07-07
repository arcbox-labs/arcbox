//! Dedicated OS thread for RX frame injection.
//!
//! Supports two input paths:
//!   1. **Channel frames** (`rx`): pre-constructed Ethernet frames from the
//!      classifier / DHCP / DNS / ARP / handshake synthesizer.
//!   2. **Inline connections** (`conn_rx`): promoted fast-path TCP sockets that
//!      read directly into guest descriptor buffers (zero intermediate copies).
//!
//! All virtqueue access goes through the unified [`SplitQueue`]: the thread
//! owns one queue instance for the VM's lifetime, and the RX invariant
//! `last_avail_idx == used.idx` (one used entry per consumed avail entry)
//! holds across both input paths.

use std::io::{IoSliceMut, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use arcbox_virtio::{GuestMemWriter, QueueConfig, SplitQueue};
use crossbeam_channel::{Receiver, RecvTimeoutError};

use crate::inline_conn::{self, InlineConn};
use crate::irq::IrqHandle;
use crate::queue;

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
    /// Guest memory (Send + Sync, VM-lifetime pointer). Backs the
    /// thread-owned [`SplitQueue`] built in [`Self::run`].
    pub guest_mem: Arc<GuestMemWriter>,
    /// RX queue layout (queue index 0 of primary VirtioNet), captured at
    /// DRIVER_OK time.
    pub queue: QueueConfig,
    /// Interrupt delivery handle.
    pub irq: IrqHandle,
    /// MMIO state for setting interrupt_status. Wrapped for &self access.
    /// The inject thread needs to set interrupt_status |= INT_VRING
    /// before firing the GIC SPI.
    pub set_interrupt_status: Arc<dyn Fn() + Send + Sync>,
    /// VM shutdown flag.
    pub running: Arc<AtomicBool>,
    /// Whether `VIRTIO_F_EVENT_IDX` was negotiated with the guest. When
    /// true, the used-ring pushes consult the guest's `used_event`
    /// before requesting the IRQ and skip the GIC SPI / vCPU exit /
    /// pthread wakeup chain when the driver isn't waiting. Profiling
    /// showed this path dominating rx-inject CPU under multi-flow load.
    pub event_idx_enabled: bool,
}

impl RxInjectThread {
    /// Runs the injection loop until `running` is set to false or
    /// the channel is disconnected.
    pub fn run(self) {
        tracing::info!(
            "rx-inject thread started (queue_size={}, event_idx={})",
            self.queue.size,
            self.event_idx_enabled,
        );

        let mut queue = SplitQueue::new(
            Arc::clone(&self.guest_mem),
            0,
            &self.queue,
            self.event_idx_enabled,
        );
        // RX consumes one avail entry per used entry published, so the avail
        // cursor resumes from the guest-visible used.idx (0 on a fresh ring).
        queue.set_last_avail_idx(self.guest_mem.read_u16(self.queue.used_addr as usize + 2));

        let mut inline_conns: Vec<InlineConn> = Vec::new();
        // Whether any push since the last flush requested an interrupt.
        let mut fire = false;

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
                self.poll_inline_conns(&mut queue, &mut inline_conns, &mut batch, &mut fire);
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
                            self.flush_interrupt(&queue, fire);
                        }
                        return;
                    }
                };

                if let Some(notify) = queue::inject_one_frame(&mut queue, &frame) {
                    fire |= notify;
                    batch += 1;
                } else {
                    // Descriptor exhaustion: flush interrupt so guest can
                    // process and repost, then backoff.
                    if batch > 0 {
                        self.flush_interrupt(&queue, fire);
                        fire = false;
                        batch = 0;
                    }
                    std::thread::sleep(DESCRIPTOR_BACKOFF);

                    // Retry this frame once.
                    if let Some(notify) = queue::inject_one_frame(&mut queue, &frame) {
                        fire |= notify;
                        batch += 1;
                    }
                    // If still fails, frame is lost (TCP retransmit recovers).
                }
            }

            if batch > 0 {
                self.flush_interrupt(&queue, fire);
                fire = false;
            }
        }

        // Final flush on shutdown.
        if fire {
            self.flush_interrupt(&queue, fire);
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
    ///
    /// Buffers are gathered speculatively with [`SplitQueue::next_avail_head`]
    /// and the avail cursor is rewound to `gather_start + consumed` after each
    /// `readv`, so a short read, `WouldBlock`, or EOF never strands an avail
    /// entry the guest still owns.
    fn poll_inline_conns(
        &self,
        queue: &mut SplitQueue,
        inline_conns: &mut Vec<InlineConn>,
        batch: &mut u16,
        fire: &mut bool,
    ) {
        if queue.size() == 0 {
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

        // Scratch buffers reused across iterations (stack-allocated).
        let mut head_indices: [u16; MAX_MERGE] = [0; MAX_MERGE];
        let mut desc_ptrs: [*mut u8; MAX_MERGE] = [std::ptr::null_mut(); MAX_MERGE];
        let mut desc_lens: [usize; MAX_MERGE] = [0; MAX_MERGE];
        let mut completions: [(u16, u32); MAX_MERGE] = [(0, 0); MAX_MERGE];

        for conn in inline_conns.iter_mut() {
            let mut per_conn = 0u16;
            loop {
                if (*batch as usize) >= BATCH_SIZE {
                    break;
                }
                if per_conn >= PER_CONN_READS {
                    break;
                }

                // Gather up to MAX_MERGE buffers into the scratch arrays.
                // The pops advance the avail cursor speculatively; guest
                // memory stays untouched, and the cursor is rewound to
                // exactly what the readv consumed before publishing.
                let gather_start = queue.last_avail_idx();
                let mut count = 0usize;
                let mut total_iov_cap = 0usize;

                while count < MAX_MERGE {
                    let cursor_before = queue.last_avail_idx();
                    let Some(head_idx) = queue.next_avail_head() else {
                        break;
                    };

                    // Only the head descriptor of each avail entry is used:
                    // under MRG_RXBUF the frame spans whole entries, and the
                    // guest posts single-descriptor RX buffers.
                    let Some(desc) = queue.chain_iter(head_idx).next() else {
                        queue.set_last_avail_idx(cursor_before);
                        break;
                    };
                    let buf_len = desc.len as usize;
                    let min_len = if count == 0 {
                        inline_conn::TOTAL_HDR_LEN + 1
                    } else {
                        1
                    };
                    // Not device-writable or too small — we can't use this
                    // entry. Leave it for the guest; we'll revisit on the
                    // next pass once it reposts.
                    if !desc.is_write() || buf_len < min_len {
                        queue.set_last_avail_idx(cursor_before);
                        break;
                    }
                    let Some(off) = queue.mem().gpa_to_offset(desc.addr as usize, buf_len) else {
                        queue.set_last_avail_idx(cursor_before);
                        break;
                    };

                    let iov_cap = if count == 0 {
                        buf_len - inline_conn::TOTAL_HDR_LEN
                    } else {
                        buf_len
                    };
                    // Stop growing the frame if the next descriptor would
                    // push us past MAX_FRAME_PAYLOAD. Always admit the first
                    // descriptor so we can at least emit a 1-byte frame.
                    if count > 0 && total_iov_cap + iov_cap > MAX_FRAME_PAYLOAD {
                        queue.set_last_avail_idx(cursor_before);
                        break;
                    }

                    // SAFETY: gpa_to_offset validated bounds. Each descriptor
                    // buffer is exclusive to the device until the used ring
                    // is advanced past it.
                    let ptr = unsafe { queue.mem().ptr().add(off) };

                    head_indices[count] = head_idx;
                    desc_ptrs[count] = ptr;
                    desc_lens[count] = buf_len;
                    total_iov_cap += iov_cap;
                    count += 1;
                }

                if count == 0 {
                    if !queue.has_avail() {
                        // Ring fully drained — nothing for any conn.
                        return;
                    }
                    // Head entry unusable; try the next conn.
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

                        // Consume only the first buffer for the FIN frame;
                        // the rest of the gather goes back to the guest.
                        queue.set_last_avail_idx(gather_start.wrapping_add(1));

                        // SAFETY: first descriptor buffer is exclusive to us.
                        let first_buf =
                            unsafe { std::slice::from_raw_parts_mut(desc_ptrs[0], desc_lens[0]) };
                        inline_conn::write_fin_headers(first_buf, conn);
                        conn.our_seq.fetch_add(1, Ordering::Relaxed);

                        *fire |=
                            queue.push_used(head_indices[0], inline_conn::TOTAL_HDR_LEN as u32);
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

                        // Return the gathered-but-unfilled buffers, then
                        // publish one used entry per consumed buffer. The
                        // first entry also accounts for the 66-byte header
                        // written in-place.
                        queue.set_last_avail_idx(gather_start.wrapping_add(num_used as u16));
                        for i in 0..num_used {
                            let entry_len = if i == 0 {
                                inline_conn::TOTAL_HDR_LEN + per_desc_len[0]
                            } else {
                                per_desc_len[i]
                            };
                            completions[i] = (head_indices[i], entry_len as u32);
                        }
                        *fire |= queue.push_used_batch(&completions[..num_used]);

                        *batch += num_used as u16;
                        per_conn += 1;
                        // Continue — try another readv on this conn.
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        queue.set_last_avail_idx(gather_start);
                        break;
                    }
                    Err(e) => {
                        tracing::debug!("inline conn error: {e}");
                        queue.set_last_avail_idx(gather_start);
                        conn.host_eof = true;
                        break;
                    }
                }
            }
        }
    }

    /// Fires the coalesced interrupt for a batch of injections.
    ///
    /// `fire` is the OR of the per-push suppression decisions from
    /// [`SplitQueue::push_used`] / [`SplitQueue::push_used_batch`] since the
    /// last flush — with EVENT_IDX negotiated the pushes consult the guest's
    /// `used_event` (skipping the `hv_vcpus_exit` + `hv_gic_set_spi` +
    /// `pthread_cond_signal` chain when the driver is already polling, which
    /// profiling showed dominating rx-inject CPU under multi-flow load);
    /// without it they honor `VRING_AVAIL_F_NO_INTERRUPT`.
    ///
    /// Also republishes `avail_event = the guest's current avail.idx`: this
    /// thread polls and never needs a guest kick, so the widest suppression
    /// window is correct — unlike drain-then-sleep consumers, which publish
    /// their consumed cursor via `write_avail_event`.
    fn flush_interrupt(&self, queue: &SplitQueue, fire: bool) {
        if self.event_idx_enabled {
            queue.write_avail_event_current();
        }

        if fire {
            (self.set_interrupt_status)();
            self.irq.trigger();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::sync::atomic::AtomicU32;

    use super::*;

    const RAM: usize = 0x4_0000; // 256 KiB
    const SIZE: u16 = 8;
    const DESC_OFF: usize = 0x1000;
    const AVAIL_OFF: usize = 0x2000;
    const USED_OFF: usize = 0x3000;
    const DATA_OFF: usize = 0x8000;

    struct TestRam {
        buf: Vec<u8>,
    }

    impl TestRam {
        fn new() -> Self {
            Self {
                buf: vec![0u8; RAM],
            }
        }

        fn cfg(&self) -> QueueConfig {
            QueueConfig {
                desc_addr: DESC_OFF as u64,
                avail_addr: AVAIL_OFF as u64,
                used_addr: USED_OFF as u64,
                size: SIZE,
                ready: true,
                gpa_base: 0,
            }
        }

        fn mem(&mut self) -> Arc<GuestMemWriter> {
            // SAFETY: buf outlives every queue/thread built in these tests;
            // access is single-threaded.
            unsafe {
                Arc::new(GuestMemWriter::new(
                    self.buf.as_mut_ptr(),
                    self.buf.len(),
                    0,
                ))
            }
        }

        /// Posts a writable single-descriptor RX buffer of `len` bytes at
        /// avail position `pos` using descriptor index `pos`.
        fn post_rx_buffer(&mut self, pos: u16, len: u32) {
            let data_gpa = (DATA_OFF + pos as usize * 0x1000) as u64;
            let base = DESC_OFF + pos as usize * 16;
            self.buf[base..base + 8].copy_from_slice(&data_gpa.to_le_bytes());
            self.buf[base + 8..base + 12].copy_from_slice(&len.to_le_bytes());
            self.buf[base + 12..base + 14].copy_from_slice(&2u16.to_le_bytes()); // WRITE
            self.buf[base + 14..base + 16].copy_from_slice(&0u16.to_le_bytes());
            let ring = AVAIL_OFF + 4 + pos as usize * 2;
            self.buf[ring..ring + 2].copy_from_slice(&pos.to_le_bytes());
        }

        fn set_avail_idx(&mut self, idx: u16) {
            self.buf[AVAIL_OFF + 2..AVAIL_OFF + 4].copy_from_slice(&idx.to_le_bytes());
        }

        fn used_idx(&self) -> u16 {
            u16::from_le_bytes([self.buf[USED_OFF + 2], self.buf[USED_OFF + 3]])
        }

        fn used_entry(&self, slot: usize) -> (u32, u32) {
            let base = USED_OFF + 4 + slot * 8;
            (
                u32::from_le_bytes(self.buf[base..base + 4].try_into().unwrap()),
                u32::from_le_bytes(self.buf[base + 4..base + 8].try_into().unwrap()),
            )
        }

        fn buffer(&self, pos: u16, len: usize) -> &[u8] {
            let off = DATA_OFF + pos as usize * 0x1000;
            &self.buf[off..off + len]
        }
    }

    /// Connected loopback TCP pair; the read side is non-blocking like a
    /// promoted fast-path socket.
    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = TcpStream::connect(addr).unwrap();
        let (reader, _) = listener.accept().unwrap();
        reader.set_nonblocking(true).unwrap();
        (writer, reader)
    }

    fn inline_conn(reader: TcpStream) -> InlineConn {
        InlineConn {
            stream: reader,
            remote_ip: Ipv4Addr::new(93, 184, 216, 34),
            guest_ip: Ipv4Addr::new(192, 168, 66, 2),
            remote_port: 443,
            guest_port: 50000,
            our_seq: Arc::new(AtomicU32::new(1000)),
            last_ack: Arc::new(AtomicU32::new(2000)),
            gw_mac: [0x02, 0, 0, 0, 0, 1],
            guest_mac: [0x02, 0, 0, 0, 0, 2],
            host_eof: false,
        }
    }

    fn inject_thread(ram: &mut TestRam, event_idx: bool) -> RxInjectThread {
        let (_frame_tx, frame_rx) = crossbeam_channel::unbounded();
        let (_conn_tx, conn_rx) = crossbeam_channel::unbounded();
        RxInjectThread {
            rx: frame_rx,
            conn_rx,
            guest_mem: ram.mem(),
            queue: ram.cfg(),
            irq: IrqHandle {
                callback: Arc::new(|_, _| Ok(())),
                exit_vcpus: Arc::new(|| {}),
                irq: 32,
            },
            set_interrupt_status: Arc::new(|| {}),
            running: Arc::new(AtomicBool::new(true)),
            event_idx_enabled: event_idx,
        }
    }

    /// Waits until the reader side has the full payload buffered so a single
    /// `readv` consumes it deterministically.
    fn wait_buffered(reader: &TcpStream, len: usize) {
        let mut probe = vec![0u8; len];
        for _ in 0..500 {
            if let Ok(n) = reader.peek(&mut probe) {
                if n >= len {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("payload never fully buffered on loopback");
    }

    #[test]
    fn inline_read_spans_buffers_and_publishes_batch() {
        let mut ram = TestRam::new();
        // Buffers: 100 (34 payload after the 66-byte header), 200, 300, and a
        // spare that must stay unconsumed.
        ram.post_rx_buffer(0, 100);
        ram.post_rx_buffer(1, 200);
        ram.post_rx_buffer(2, 300);
        ram.post_rx_buffer(3, 4096);
        ram.set_avail_idx(4);

        let thread = inject_thread(&mut ram, false);
        let mut queue = SplitQueue::new(
            Arc::clone(&thread.guest_mem),
            0,
            &thread.queue,
            thread.event_idx_enabled,
        );

        let (mut writer, reader) = tcp_pair();
        let payload: Vec<u8> = (0..500u16).map(|i| i as u8).collect();
        writer.write_all(&payload).unwrap();
        writer.flush().unwrap();
        wait_buffered(&reader, payload.len());

        let mut conns = vec![inline_conn(reader)];
        let (mut batch, mut fire) = (0u16, false);
        thread.poll_inline_conns(&mut queue, &mut conns, &mut batch, &mut fire);

        // 500 bytes over caps [34, 200, 300] -> per-desc [34, 200, 266].
        assert_eq!(batch, 3);
        assert!(fire, "no EVENT_IDX: completed pushes request the IRQ");
        assert_eq!(ram.used_idx(), 3);
        assert_eq!(ram.used_entry(0), (0, 66 + 34));
        assert_eq!(ram.used_entry(1), (1, 200));
        assert_eq!(ram.used_entry(2), (2, 266));
        assert_eq!(queue.last_avail_idx(), 3, "spare buffer stays available");

        // First buffer: 66-byte header, then the first 34 payload bytes.
        let first = ram.buffer(0, 100);
        assert_eq!(
            u16::from_le_bytes([first[10], first[11]]),
            3,
            "num_buffers spans the merge"
        );
        assert_eq!(&first[66..100], &payload[..34]);
        assert_eq!(ram.buffer(1, 200), &payload[34..234]);
        assert_eq!(&ram.buffer(2, 300)[..266], &payload[234..500]);

        // seq advanced by the payload length.
        assert_eq!(
            conns[0].our_seq.load(Ordering::Relaxed),
            1000 + payload.len() as u32
        );

        // Nothing more buffered: a second poll consumes nothing.
        let (mut batch2, mut fire2) = (0u16, false);
        thread.poll_inline_conns(&mut queue, &mut conns, &mut batch2, &mut fire2);
        assert_eq!(batch2, 0);
        assert!(!fire2);
        assert_eq!(ram.used_idx(), 3);
        assert_eq!(queue.last_avail_idx(), 3);
    }

    #[test]
    fn eof_emits_fin_and_returns_extra_gathered_buffers() {
        let mut ram = TestRam::new();
        ram.post_rx_buffer(0, 4096);
        ram.post_rx_buffer(1, 4096);
        ram.set_avail_idx(2);

        let thread = inject_thread(&mut ram, false);
        let mut queue = SplitQueue::new(
            Arc::clone(&thread.guest_mem),
            0,
            &thread.queue,
            thread.event_idx_enabled,
        );

        let (writer, reader) = tcp_pair();
        drop(writer); // immediate EOF
        // Wait until the FIN is visible (peek returns Ok(0)) so the poll
        // below deterministically takes the EOF path.
        let mut probe = [0u8; 1];
        for _ in 0..500 {
            match reader.peek(&mut probe) {
                Ok(0) => break,
                _ => std::thread::sleep(Duration::from_millis(1)),
            }
        }

        let mut conns = vec![inline_conn(reader)];
        let (mut batch, mut fire) = (0u16, false);
        thread.poll_inline_conns(&mut queue, &mut conns, &mut batch, &mut fire);

        assert!(conns[0].host_eof);
        assert_eq!(batch, 1);
        assert_eq!(ram.used_idx(), 1, "only the FIN frame was published");
        assert_eq!(
            queue.last_avail_idx(),
            1,
            "the second gathered buffer went back to the guest"
        );
        assert_eq!(
            ram.used_entry(0),
            (0, inline_conn::TOTAL_HDR_LEN as u32),
            "FIN is a headers-only frame"
        );
        // FIN consumed one sequence number.
        assert_eq!(conns[0].our_seq.load(Ordering::Relaxed), 1001);
        // TCP flags byte in the injected frame: FIN | ACK.
        let first = ram.buffer(0, inline_conn::TOTAL_HDR_LEN);
        assert_eq!(first[12 + 14 + 20 + 13], 0x11);
    }
}
