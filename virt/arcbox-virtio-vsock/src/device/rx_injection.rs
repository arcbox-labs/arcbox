use arcbox_virtio_core::{QueueConfig, VirtioDevice};

use super::*;

impl VirtioVsock {
    // `poll_rx_injection` was previously `DeviceManager::poll_vsock_rx`.
    // It is the device side of the vsock RX loop the BSP vCPU drives
    // each iteration: peek host fds, drain the backend RX queue into
    // guest descriptors, and opportunistically process the TX queue.
    // Requires `bind_ctx` and `bind_connections` to have been called.

    /// Drives one round of vsock RX/TX maintenance:
    /// 1. Peek every connected host fd; on data → enqueue RW; on EOF →
    ///    enqueue RST.
    /// 2. Pop entries from the backend RX queue, build vsock packets
    ///    (REQUEST/RESPONSE/RW/SHUTDOWN/CREDIT_*), and write them into
    ///    available guest RX descriptors via `write_to_rx_descriptor`.
    /// 3. If `tx_qcfg` is supplied, drain the TX virtqueue via
    ///    `process_queue(1, ...)` so guest→host responses are picked up
    ///    on the same poll cycle.
    ///
    /// Returns `true` when anything was injected (caller fires
    /// INT_VRING). Returns `false` if the device isn't fully bound or
    /// nothing was pending.
    #[allow(clippy::too_many_lines)]
    pub fn poll_rx_injection(
        &mut self,
        rx_qcfg: &QueueConfig,
        tx_qcfg: Option<&QueueConfig>,
    ) -> bool {
        use std::os::fd::AsRawFd;

        use crate::manager::{RxOps, TX_BUFFER_SIZE};

        let Some(ctx) = self.ctx.clone() else {
            return false;
        };
        let Some(conns) = self.conn_mgr.clone() else {
            return false;
        };
        let mem_arc = ctx.mem.clone();
        let gpa_base_usize = mem_arc.gpa_base();
        let mem_len = mem_arc.len();

        let mut injected = false;

        // ------------------------------------------------------------------
        // Phase 1: peek every connected fd → enqueue RW or RST
        // ------------------------------------------------------------------
        {
            let connected_fds = conns
                .lock()
                .map(|mgr| mgr.connected_fds())
                .unwrap_or_default();

            // Log at INFO once per unique count change to avoid spam.
            static LAST_COUNT: std::sync::atomic::AtomicUsize =
                std::sync::atomic::AtomicUsize::new(0);
            let count = connected_fds.len();
            if count != LAST_COUNT.swap(count, std::sync::atomic::Ordering::Relaxed) {
                tracing::info!("vsock Phase 1: {} connected fds", count);
            }

            for (conn_id, fd) in &connected_fds {
                let mut peek_buf = [0u8; 1];
                // SAFETY: `*fd` is owned by the connection manager and
                // stays live for the duration of this peek. `peek_buf` is
                // a valid mutable slice. MSG_DONTWAIT keeps it non-blocking.
                let n = unsafe {
                    libc::recv(
                        *fd,
                        peek_buf.as_mut_ptr().cast::<libc::c_void>(),
                        1,
                        libc::MSG_PEEK | libc::MSG_DONTWAIT,
                    )
                };
                if n > 0 {
                    tracing::trace!(
                        "vsock Phase 1: data on fd {} for {:?} — enqueue RW",
                        fd,
                        conn_id,
                    );
                    if let Ok(mut mgr) = conns.lock() {
                        mgr.enqueue_rw(*conn_id);
                    }
                } else if n == 0 {
                    tracing::debug!(
                        "vsock Phase 1: EOF on fd {} for {:?} — enqueue RST",
                        fd,
                        conn_id,
                    );
                    if let Ok(mut mgr) = conns.lock() {
                        mgr.enqueue_reset(*conn_id);
                    }
                }
                // n < 0 with EAGAIN/EWOULDBLOCK = no data, skip.
            }
        }

        // ------------------------------------------------------------------
        // Phase 2: drain backend_rxq → fill RX descriptors
        // ------------------------------------------------------------------
        if !rx_qcfg.ready || rx_qcfg.size == 0 {
            return injected;
        }
        let Some(rx_desc) = (rx_qcfg.desc_addr as usize).checked_sub(gpa_base_usize) else {
            return injected;
        };
        let Some(rx_avail) = (rx_qcfg.avail_addr as usize).checked_sub(gpa_base_usize) else {
            return injected;
        };
        let Some(rx_used) = (rx_qcfg.used_addr as usize).checked_sub(gpa_base_usize) else {
            return injected;
        };
        let q_size = rx_qcfg.size as usize;

        // SAFETY: `mem_arc` was constructed from the VM-lifetime guest RAM
        // mmap. The slice we derive is short-lived (dropped before phase 3
        // re-derives its own slice) and used only by code that follows the
        // VirtIO descriptor-ownership discipline.
        let Some(guest_mem) = (unsafe { mem_arc.slice_mut(gpa_base_usize, mem_len) }) else {
            return injected;
        };

        if rx_avail + 4 > guest_mem.len() {
            return injected;
        }

        // Process backend_rxq: pop connections, fill RX descriptors. If we
        // run out of guest descriptors while backend_rxq still has entries,
        // we set `injected = true` so the caller raises INT_VRING — that
        // wakes the guest's rx_work, which refills descriptors, and the
        // next poll cycle drains the stalled entries.
        let mut rxq_starved = false;
        loop {
            let avail_idx =
                u16::from_le_bytes([guest_mem[rx_avail + 2], guest_mem[rx_avail + 3]]) as usize;
            let used_idx_off = rx_used + 2;
            let used_idx =
                u16::from_le_bytes([guest_mem[used_idx_off], guest_mem[used_idx_off + 1]]) as usize;

            if avail_idx == used_idx {
                if let Ok(mgr) = conns.lock() {
                    if !mgr.backend_rxq.is_empty() {
                        rxq_starved = true;
                    }
                }
                break;
            }

            let conn_id = {
                let Ok(mut mgr) = conns.lock() else {
                    break;
                };
                mgr.backend_rxq.pop_front()
            };
            let Some(conn_id) = conn_id else {
                break; // No pending connections.
            };

            // Build the packet for this connection's highest-priority op.
            let packet = {
                let Ok(mut mgr) = conns.lock() else {
                    break;
                };
                let Some(conn) = mgr.get_mut(&conn_id) else {
                    continue; // Connection removed while queued.
                };

                if conn.rx_queue.peek() == RxOps::RESET {
                    conn.rx_queue.dequeue();
                    let hdr = VsockHeader::new(
                        VsockAddr::host(conn_id.host_port),
                        VsockAddr::new(conn.guest_cid, conn_id.guest_port),
                        VsockOp::Rst,
                    );
                    let pkt = hdr.to_bytes().to_vec();
                    mgr.remove(&conn_id);
                    pkt
                } else {
                    let op = conn.rx_queue.dequeue();
                    if op == 0 {
                        continue; // Spurious entry — no pending ops.
                    }

                    match op {
                        RxOps::REQUEST => {
                            let hdr = VsockHeader::new(
                                VsockAddr::host(conn_id.host_port),
                                VsockAddr::new(conn.guest_cid, conn_id.guest_port),
                                VsockOp::Request,
                            );
                            tracing::debug!(
                                "Vsock RX: OP_REQUEST guest_port={} host_port={}",
                                conn_id.guest_port,
                                conn_id.host_port,
                            );
                            hdr.to_bytes().to_vec()
                        }
                        RxOps::RESPONSE => {
                            conn.connect = true;
                            let hdr = VsockHeader::new(
                                VsockAddr::host(conn_id.host_port),
                                VsockAddr::new(conn.guest_cid, conn_id.guest_port),
                                VsockOp::Response,
                            );
                            tracing::debug!(
                                "Vsock RX: OP_RESPONSE guest_port={} host_port={}",
                                conn_id.guest_port,
                                conn_id.host_port,
                            );
                            hdr.to_bytes().to_vec()
                        }
                        RxOps::RW => {
                            if conn.peer_no_recv() {
                                // Peer half-closed its receive side. Drop the
                                // RW silently; the fd stays open so the peer's
                                // own sends still drain via the TX path.
                                tracing::trace!(
                                    "Vsock RX: skipping RW for half-closed conn guest_port={} host_port={}",
                                    conn_id.guest_port,
                                    conn_id.host_port,
                                );
                                continue;
                            }
                            if !conn.connect {
                                let hdr = VsockHeader::new(
                                    VsockAddr::host(conn_id.host_port),
                                    VsockAddr::new(conn.guest_cid, conn_id.guest_port),
                                    VsockOp::Rst,
                                );
                                mgr.remove(&conn_id);
                                hdr.to_bytes().to_vec()
                            } else {
                                let credit = conn.peer_avail_credit();
                                if credit == 0 {
                                    let mut hdr = VsockHeader::new(
                                        VsockAddr::host(conn_id.host_port),
                                        VsockAddr::new(conn.guest_cid, conn_id.guest_port),
                                        VsockOp::CreditRequest,
                                    );
                                    hdr.buf_alloc = TX_BUFFER_SIZE;
                                    hdr.fwd_cnt = conn.fwd_cnt.0;
                                    // Re-queue the RW so we retry once the peer
                                    // refreshes our view; mark the request as
                                    // pending so maybe_request_credit below
                                    // doesn't also enqueue a duplicate.
                                    conn.rx_queue.enqueue(RxOps::RW);
                                    conn.note_credit_request_sent();
                                    hdr.to_bytes().to_vec()
                                } else {
                                    let fd = conn.internal_fd.as_raw_fd();
                                    let max_read = credit.min(4096);
                                    let mut buf = vec![0u8; max_read];
                                    // SAFETY: `fd` is borrowed from
                                    // `conn.internal_fd`, live for the call.
                                    // `buf` is a valid mutable allocation.
                                    let n = unsafe {
                                        libc::read(
                                            fd,
                                            buf.as_mut_ptr().cast::<libc::c_void>(),
                                            max_read,
                                        )
                                    };
                                    if n <= 0 {
                                        if n == 0 {
                                            let mut hdr = VsockHeader::new(
                                                VsockAddr::host(conn_id.host_port),
                                                VsockAddr::new(conn.guest_cid, conn_id.guest_port),
                                                VsockOp::Shutdown,
                                            );
                                            hdr.flags = 3; // RCV | SEND
                                            hdr.buf_alloc = TX_BUFFER_SIZE;
                                            hdr.fwd_cnt = conn.fwd_cnt.0;
                                            hdr.to_bytes().to_vec()
                                        } else {
                                            continue; // EAGAIN
                                        }
                                    } else {
                                        let data = &buf[..n as usize];
                                        let mut hdr = VsockHeader::new(
                                            VsockAddr::host(conn_id.host_port),
                                            VsockAddr::new(conn.guest_cid, conn_id.guest_port),
                                            VsockOp::Rw,
                                        );
                                        hdr.len = data.len() as u32;
                                        hdr.buf_alloc = TX_BUFFER_SIZE;
                                        hdr.fwd_cnt = conn.fwd_cnt.0;

                                        conn.record_rx(data.len() as u32);
                                        // After sending, our view of the
                                        // peer's free buffer has shrunk.
                                        // Ask for a refresh if we've crossed
                                        // the half-window mark.
                                        conn.maybe_request_credit();

                                        let hdr_bytes = hdr.to_bytes();
                                        let mut pkt =
                                            Vec::with_capacity(VsockHeader::SIZE + data.len());
                                        pkt.extend_from_slice(&hdr_bytes[..VsockHeader::SIZE]);
                                        pkt.extend_from_slice(data);

                                        tracing::debug!(
                                            "Vsock RX: OP_RW {} bytes guest_port={} host_port={} fwd_cnt={}",
                                            data.len(),
                                            conn_id.guest_port,
                                            conn_id.host_port,
                                            conn.fwd_cnt.0,
                                        );
                                        pkt
                                    }
                                }
                            }
                        }
                        RxOps::CREDIT_UPDATE => {
                            let mut hdr = VsockHeader::new(
                                VsockAddr::host(conn_id.host_port),
                                VsockAddr::new(conn.guest_cid, conn_id.guest_port),
                                VsockOp::CreditUpdate,
                            );
                            hdr.buf_alloc = TX_BUFFER_SIZE;
                            hdr.fwd_cnt = conn.fwd_cnt.0;
                            conn.mark_credit_sent();
                            hdr.to_bytes().to_vec()
                        }
                        RxOps::CREDIT_REQUEST => {
                            // Ask the peer for their current fwd_cnt. The
                            // pending flag is already set — it stays set
                            // until the peer answers with CREDIT_UPDATE,
                            // which clears it via update_peer_credit.
                            let mut hdr = VsockHeader::new(
                                VsockAddr::host(conn_id.host_port),
                                VsockAddr::new(conn.guest_cid, conn_id.guest_port),
                                VsockOp::CreditRequest,
                            );
                            hdr.buf_alloc = TX_BUFFER_SIZE;
                            hdr.fwd_cnt = conn.fwd_cnt.0;
                            tracing::debug!(
                                "Vsock RX: OP_CREDIT_REQUEST guest_port={} host_port={}",
                                conn_id.guest_port,
                                conn_id.host_port,
                            );
                            hdr.to_bytes().to_vec()
                        }
                        _ => continue,
                    }
                }
            };

            // Write the packet into an available RX descriptor.
            let written = Self::write_to_rx_descriptor(
                guest_mem,
                rx_desc,
                rx_avail,
                rx_used,
                q_size,
                gpa_base_usize,
                &packet,
            );

            if written > 0 {
                injected = true;

                // Fire injected_notify for REQUEST ops — unblocks any
                // daemon-side connect waiting in `connect_vsock_hv`.
                if let Ok(mut mgr) = conns.lock() {
                    if let Some(conn) = mgr.get_mut(&conn_id) {
                        if let Some(tx) = conn.injected_notify.take() {
                            let _ = tx.send(());
                        }
                    }
                }
            }

            // If the connection still has pending ops, re-push it.
            if let Ok(mut mgr) = conns.lock() {
                if let Some(conn) = mgr.get(&conn_id) {
                    if conn.rx_queue.pending() {
                        mgr.backend_rxq.push_back(conn_id);
                    }
                }
            }
        }

        if rxq_starved {
            injected = true;
        }

        // Drop the phase-2 slice borrow before phase 3 re-derives one
        // (and before we hand a fresh `&mut [u8]` to `process_queue`,
        // which takes `&mut self`). `let _ = ...` for clippy.
        let _ = guest_mem;

        // ------------------------------------------------------------------
        // Phase 3: TX poll — drain TX queue for guest→host responses
        // ------------------------------------------------------------------
        if let Some(tx_qcfg) = tx_qcfg {
            // SAFETY: same as above — short-lived slice, descriptor-scoped
            // access discipline holds.
            let Some(tx_mem) = (unsafe { mem_arc.slice_mut(gpa_base_usize, mem_len) }) else {
                return injected;
            };
            // Use `VirtioDevice::process_queue` directly on `&mut self`.
            // `tx_mem` borrows `mem_arc` (a clone), not `self`, so the
            // borrows are disjoint.
            match <Self as VirtioDevice>::process_queue(self, 1, tx_mem, tx_qcfg) {
                Ok(completions) if !completions.is_empty() => {
                    tracing::trace!("Vsock TX poll: {} completions", completions.len());
                    injected = true;

                    // After TX processing, re-queue any connections whose
                    // RX state advanced (e.g. CreditUpdate after OP_RW).
                    if let Ok(mut mgr) = conns.lock() {
                        let ids: Vec<_> = mgr.connections_with_pending_rx();
                        for id in ids {
                            mgr.backend_rxq.push_back(id);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Vsock TX poll error: {e}");
                }
                _ => {}
            }
        }

        injected
    }

    /// Writes `packet` into the next available RX descriptor chain.
    ///
    /// `desc_addr`, `avail_addr`, `used_addr` are slice offsets (already
    /// translated from GPA by subtracting `gpa_base`). Returns the number
    /// of bytes written, or 0 if no RX descriptor was available or the
    /// descriptor chain ran out of writable buffer space.
    #[allow(clippy::too_many_arguments)]
    fn write_to_rx_descriptor(
        guest_mem: &mut [u8],
        desc_addr: usize,
        avail_addr: usize,
        used_addr: usize,
        q_size: usize,
        gpa_base: usize,
        packet: &[u8],
    ) -> usize {
        // Reconstruct a GPA-based QueueConfig from the offset arguments so the
        // queue resolves every address through GuestMemWriter exactly once.
        let cfg = QueueConfig {
            desc_addr: (desc_addr + gpa_base) as u64,
            avail_addr: (avail_addr + gpa_base) as u64,
            used_addr: (used_addr + gpa_base) as u64,
            size: q_size as u16,
            ready: true,
            gpa_base: gpa_base as u64,
        };
        // SAFETY: `guest_mem` is the guest RAM slice; the queue accesses it only
        // through the GuestMemWriter built here, and `guest_mem` is not touched
        // directly while the queue is alive.
        let mem = std::sync::Arc::new(unsafe {
            arcbox_virtio_core::GuestMemWriter::new(
                guest_mem.as_mut_ptr(),
                guest_mem.len(),
                gpa_base,
            )
        });
        let mut queue = arcbox_virtio_core::SplitQueue::new(mem, 0, &cfg, false);
        // RX consumes one avail entry per injected packet, tracked by the
        // guest's used.idx; an empty write leaves the entry for the next call.
        let used0 = queue.mem().read_u16(cfg.used_addr as usize + 2);
        queue.set_last_avail_idx(used0);

        let Some(chain) = queue.pop_avail() else {
            return 0; // No available descriptors.
        };

        // Walk the chain, scattering the packet into the write-only buffers.
        let mut written = 0usize;
        for desc in &chain.descriptors {
            if desc.is_write() {
                let remaining = packet.len().saturating_sub(written);
                let to_write = remaining.min(desc.len as usize);
                if to_write > 0 {
                    // SAFETY: write-only descriptor buffers are device-owned.
                    if let Some(buf) =
                        unsafe { queue.mem().slice_mut(desc.addr as usize, to_write) }
                    {
                        buf.copy_from_slice(&packet[written..written + to_write]);
                        written += to_write;
                    }
                }
            }
            if written >= packet.len() {
                break;
            }
        }

        if written == 0 {
            // The chain had no writable capacity, but it was already popped off
            // the avail ring — return it to the used ring so the guest reclaims
            // the descriptor instead of leaking it (which drains the RX ring).
            queue.push_used(chain.head_idx, 0);
            return 0;
        }

        queue.push_used(chain.head_idx, written as u32);
        written
    }
}
