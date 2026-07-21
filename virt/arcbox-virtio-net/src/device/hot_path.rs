use std::sync::atomic::Ordering;

use arcbox_virtio_core::QueueConfig;

use crate::header::VirtioNetHeader;

use super::VirtioNet;

impl VirtioNet {
    /// Drains the TX virtqueue: walks descriptor chains starting from the
    /// current TX cursor up to the guest's latest `avail_idx`, concatenates
    /// each chain's read-flagged descriptors into a packet, runs `finalize`
    /// to complete any guest-requested checksum offload, strips the
    /// virtio-net header, and writes the raw Ethernet frame to the bound
    /// host fd. Publishes completions to the used ring itself and returns
    /// whether any chain was drained, so the caller can fire the IRQ.
    ///
    /// `finalize` is injected so arcbox-virtio doesn't depend on
    /// arcbox-net's checksum helpers.
    pub fn drain_tx_queue<F>(&self, qcfg: &QueueConfig, finalize: F) -> bool
    where
        F: Fn(&mut [u8]),
    {
        let Some(port) = self.port.get() else {
            return false;
        };
        let Some(ctx) = self.ctx.as_ref() else {
            return false;
        };
        if !qcfg.ready || qcfg.size == 0 {
            return false;
        }
        let host_fd = port.host_fd;
        let event_idx = (self.acked_features & arcbox_virtio_core::queue::VIRTIO_F_EVENT_IDX) != 0;

        // The queue is the sole accessor of these rings for this call; `ctx.mem`
        // wraps the VM-lifetime guest RAM mapping.
        let mut queue = arcbox_virtio_core::SplitQueue::new(ctx.mem.clone(), 1, qcfg, event_idx);
        queue.set_last_avail_idx(port.last_avail_tx.load(Ordering::Relaxed));

        let mut notify = false;
        // Drain in a TOCTOU loop: after publishing avail_event the guest may
        // have queued more and suppressed its kick on the stale value, so
        // re-check the avail ring and drain again.
        loop {
            let mut completions = Vec::new();
            while let Some(chain) = queue.pop_avail() {
                // TX descriptors are read-only (guest → host data).
                let mut packet_data = Vec::new();
                for desc in &chain.descriptors {
                    if !desc.is_write() {
                        if let Some(data) = queue.mem().slice(desc.addr as usize, desc.len as usize)
                        {
                            packet_data.extend_from_slice(data);
                        }
                    }
                }

                let total_len = packet_data.len() as u32;
                finalize(&mut packet_data);

                // Strip the virtio-net header (after checksum offload), then
                // write the frame to the host fd with a brief EAGAIN/ENOBUFS
                // retry: the datapath peer can lag a few frames under bulk
                // bursts, and silent loss collapses guest TCP throughput.
                if packet_data.len() > VirtioNetHeader::SIZE {
                    let frame = &packet_data[VirtioNetHeader::SIZE..];
                    let mut retries = 0;
                    loop {
                        // SAFETY: `host_fd` is owned via `NetPort`; `frame` is a
                        // valid slice of `packet_data` for the write's duration.
                        let n = unsafe {
                            libc::write(host_fd, frame.as_ptr().cast::<libc::c_void>(), frame.len())
                        };
                        if n >= 0 {
                            break;
                        }
                        let err = std::io::Error::last_os_error();
                        match err.raw_os_error() {
                            Some(libc::EAGAIN | libc::ENOBUFS) if retries < 64 => {
                                std::thread::yield_now();
                                retries += 1;
                            }
                            Some(libc::EAGAIN | libc::ENOBUFS) => break,
                            _ => {
                                tracing::warn!("VirtioNet TX write failed: {err}");
                                break;
                            }
                        }
                    }
                }

                completions.push((chain.head_idx, total_len));
            }

            // Publish the completions to the used ring (push_used_batch carries a
            // full StoreLoad barrier). Net interrupts on any completed TX buffer.
            if !completions.is_empty() {
                notify = true;
            }
            queue.push_used_batch(&completions);

            // Refresh avail_event even on an empty drain — the ABX-386 fix so a
            // stale value can't make an EVENT_IDX guest suppress its TX kick.
            // Only when negotiated: the field sits past the used ring otherwise.
            if event_idx {
                queue.write_avail_event();
            }

            // Close the TOCTOU window: SeqCst orders the avail_event store before
            // re-reading avail.idx; if the guest queued more, drain again.
            std::sync::atomic::fence(Ordering::SeqCst);
            if !queue.has_avail() {
                break;
            }
        }

        port.last_avail_tx
            .store(queue.last_avail_idx(), Ordering::Relaxed);
        notify
    }

    /// Writes a raw Ethernet frame (without virtio-net header) directly to
    /// the bound host fd. Intended for out-of-band injection paths; no-op
    /// if the port is unbound.
    pub fn write_tx_frame(&self, frame: &[u8]) {
        let Some(port) = self.port.get() else {
            return;
        };
        // SAFETY: `port.host_fd` is live for as long as `self.port` holds
        // the `NetPort`; `frame` is a caller-provided valid slice.
        let n = unsafe {
            libc::write(
                port.host_fd,
                frame.as_ptr().cast::<libc::c_void>(),
                frame.len(),
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EAGAIN) {
                tracing::warn!("VirtioNet::write_tx_frame failed: {err}");
            }
        }
    }

    /// Polls the bound host fd for inbound Ethernet frames and injects up
    /// to 64 of them into the RX virtqueue described by `rx_qcfg`. Prepends
    /// a zeroed 12-byte virtio-net header to each frame. Returns `true` if
    /// any frame was injected, so the caller can fire the used-ring IRQ.
    ///
    /// The caller is responsible for building `rx_qcfg` from the device's
    /// MMIO state and gating on DRIVER_OK.
    #[allow(clippy::too_many_lines)]
    pub fn poll_rx(&self, rx_qcfg: &QueueConfig) -> bool {
        let Some(port) = self.port.get() else {
            return false;
        };
        let Some(ctx) = self.ctx.as_ref() else {
            return false;
        };
        if !rx_qcfg.ready || rx_qcfg.size == 0 {
            return false;
        }
        let host_fd = port.host_fd;
        let event_idx = (self.acked_features & arcbox_virtio_core::queue::VIRTIO_F_EVENT_IDX) != 0;

        // RX consumes one avail entry per injected frame, tracked by the guest's
        // used.idx (which SplitQueue seeds); the queue is the sole accessor here.
        let mut queue = arcbox_virtio_core::SplitQueue::new(ctx.mem.clone(), 0, rx_qcfg, event_idx);
        let used0 = queue.mem().read_u16(rx_qcfg.used_addr as usize + 2);
        queue.set_last_avail_idx(used0);

        // "Published" = we advanced the used ring and the guest must be
        // interrupted so it reclaims the descriptors — true both for a real
        // frame injection and for a zero-length completion of an unusable
        // chain. Returning only on injection would leak the interrupt for a
        // chain we consumed but couldn't fill, stalling RX.
        let mut published = false;
        let hdr_len = VirtioNetHeader::SIZE;
        for _ in 0..64 {
            // Stop when the guest has no RX buffer posted.
            if !queue.has_avail() {
                break;
            }

            // Non-blocking read from the bound fd.
            let mut buf = [0u8; 9216]; // MAX_FRAME_SIZE
            // SAFETY: `host_fd` is owned by the bound `NetPort`; `buf` is a valid
            // mutable stack slice; MSG_DONTWAIT keeps it non-blocking.
            let n = unsafe {
                libc::recv(
                    host_fd,
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n <= 0 {
                break;
            }
            let frame = &buf[..n as usize];
            // The injected buffer is a zeroed virtio-net header followed by the
            // frame, scattered across the chain's write-only descriptors.
            let total = hdr_len + frame.len();

            let Some(chain) = queue.pop_avail() else {
                break;
            };
            let mut written = 0usize;
            for desc in &chain.descriptors {
                if !desc.is_write() {
                    continue;
                }
                if written >= total {
                    break;
                }
                let to_write = (total - written).min(desc.len as usize);
                if to_write == 0 {
                    continue;
                }
                // SAFETY: write-only descriptor buffers are device-owned.
                if let Some(out) = unsafe { queue.mem().slice_mut(desc.addr as usize, to_write) } {
                    for (k, slot) in out.iter_mut().enumerate() {
                        let pos = written + k;
                        // virtio-net header is all zeros; frame follows it.
                        *slot = if pos < hdr_len {
                            0
                        } else {
                            frame[pos - hdr_len]
                        };
                    }
                    written += to_write;
                }
            }

            if written == 0 {
                // A chain with no writable capacity can't carry the frame, but
                // it was already popped off the avail ring — return it to the
                // used ring (zero length) so the guest reclaims the descriptor
                // instead of leaking it forever (which drains the RX ring dry).
                // This advances the used ring, so the guest still needs the
                // interrupt below. The frame is dropped; TCP retransmits.
                queue.push_used(chain.head_idx, 0);
                published = true;
                continue;
            }

            queue.push_used(chain.head_idx, written as u32);
            published = true;
        }

        // Publish avail_event for an EVENT_IDX guest (gated: the field sits past
        // the used ring when EVENT_IDX is not negotiated). RX publishes the
        // current avail.idx (not the consumed cursor): the host polls for frames
        // so it only wants a kick for RX buffers posted beyond what it has seen.
        if published && event_idx {
            let avail_idx_now = queue.mem().read_u16(rx_qcfg.avail_addr as usize + 2);
            let avail_event_off = rx_qcfg.used_addr as usize + 4 + rx_qcfg.size as usize * 8;
            queue.mem().write_u16(avail_event_off, avail_idx_now);
        }

        published
    }
}
