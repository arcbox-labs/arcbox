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
    /// host fd. Returns `(head_idx, total_len_including_header)` for each
    /// drained chain so the caller can advance the used ring.
    ///
    /// `finalize` is injected so arcbox-virtio doesn't depend on
    /// arcbox-net's checksum helpers.
    pub fn drain_tx_queue<F>(&self, qcfg: &QueueConfig, finalize: F) -> Vec<(u16, u32)>
    where
        F: Fn(&mut [u8]),
    {
        let Some(port) = self.port.get() else {
            return Vec::new();
        };
        let Some(ctx) = self.ctx.as_ref() else {
            return Vec::new();
        };
        if !qcfg.ready || qcfg.size == 0 {
            return Vec::new();
        }
        let host_fd = port.host_fd;

        // Translate GPAs to slice offsets (checked against ram base).
        let gpa_base = qcfg.gpa_base as usize;
        let Some(desc_addr) = (qcfg.desc_addr as usize).checked_sub(gpa_base) else {
            tracing::warn!(
                "VirtioNet::handle_tx: desc GPA {:#x} below ram base {:#x}",
                qcfg.desc_addr,
                gpa_base
            );
            return Vec::new();
        };
        let Some(avail_addr) = (qcfg.avail_addr as usize).checked_sub(gpa_base) else {
            tracing::warn!(
                "VirtioNet::handle_tx: avail GPA {:#x} below ram base {:#x}",
                qcfg.avail_addr,
                gpa_base
            );
            return Vec::new();
        };
        let q_size = qcfg.size as usize;

        // SAFETY: `ctx.mem` was constructed from the VM-lifetime guest RAM
        // mmap. Each slice view is short-lived and never escapes this
        // function; the wider aliasing concern is documented on the
        // `GuestMemWriter` type.
        let Some(memory) = (unsafe { ctx.mem.slice_mut(gpa_base, ctx.mem.len()) }) else {
            return Vec::new();
        };

        if avail_addr + 4 > memory.len() {
            return Vec::new();
        }
        let avail_idx = u16::from_le_bytes([memory[avail_addr + 2], memory[avail_addr + 3]]);

        let mut current_avail = port.last_avail_tx.load(Ordering::Relaxed);
        let mut completions = Vec::new();

        while current_avail != avail_idx {
            let ring_off = avail_addr + 4 + 2 * ((current_avail as usize) % q_size);
            if ring_off + 2 > memory.len() {
                break;
            }
            let head_idx = u16::from_le_bytes([memory[ring_off], memory[ring_off + 1]]) as usize;

            let mut packet_data = Vec::new();
            let mut idx = head_idx;
            for _ in 0..q_size {
                let d_off = desc_addr + idx * 16;
                if d_off + 16 > memory.len() {
                    break;
                }
                let addr = match (u64::from_le_bytes(memory[d_off..d_off + 8].try_into().unwrap())
                    as usize)
                    .checked_sub(gpa_base)
                {
                    Some(a) => a,
                    None => continue,
                };
                let len =
                    u32::from_le_bytes(memory[d_off + 8..d_off + 12].try_into().unwrap()) as usize;
                let flags = u16::from_le_bytes(memory[d_off + 12..d_off + 14].try_into().unwrap());
                let next = u16::from_le_bytes(memory[d_off + 14..d_off + 16].try_into().unwrap());

                // WRITE flag clear = read-only (guest → host). TX descriptors
                // are always read-only.
                if flags & 2 == 0 && addr + len <= memory.len() {
                    packet_data.extend_from_slice(&memory[addr..addr + len]);
                }
                if flags & 1 == 0 {
                    break;
                }
                idx = next as usize;
            }

            let total_len = packet_data.len() as u32;
            finalize(&mut packet_data);

            // Strip the virtio-net header after applying checksum offload.
            if packet_data.len() > VirtioNetHeader::SIZE {
                let frame = &packet_data[VirtioNetHeader::SIZE..];
                // Retry briefly on EAGAIN/ENOBUFS: the host-side socketpair
                // peer (datapath classifier) might be behind by a few frames
                // under bulk bursts (iperf3 -R and similar). Without this
                // retry, guest TCP sees silent packet loss and retransmits,
                // collapsing throughput to under 1 MB/s while the fast-path
                // can do ~1 GB/s.
                let mut retries = 0;
                loop {
                    // SAFETY: `host_fd` is owned by the caller via `NetPort`;
                    // `frame` is a valid slice borrowed from `packet_data`
                    // for the duration of the write.
                    let n = unsafe {
                        libc::write(host_fd, frame.as_ptr().cast::<libc::c_void>(), frame.len())
                    };
                    if n >= 0 {
                        break;
                    }
                    let err = std::io::Error::last_os_error();
                    match err.raw_os_error() {
                        Some(libc::EAGAIN | libc::ENOBUFS) if retries < 64 => {
                            // Yield so the peer thread can drain, then retry.
                            std::thread::yield_now();
                            retries += 1;
                        }
                        Some(libc::EAGAIN | libc::ENOBUFS) => {
                            // Peer is persistently slow — drop the frame.
                            // Guest TCP will retransmit.
                            break;
                        }
                        _ => {
                            tracing::warn!("VirtioNet TX write failed: {err}");
                            break;
                        }
                    }
                }
            }

            completions.push((head_idx as u16, total_len));
            current_avail = current_avail.wrapping_add(1);
        }

        port.last_avail_tx.store(current_avail, Ordering::Relaxed);
        completions
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
        let gpa_base = rx_qcfg.gpa_base as usize;

        // SAFETY: `ctx.mem` was constructed from the VM-lifetime guest RAM
        // mmap. Each slice view is short-lived.
        let Some(guest_mem) = (unsafe { ctx.mem.slice_mut(gpa_base, ctx.mem.len()) }) else {
            return false;
        };

        // Translate GPAs to slice offsets (checked against ram base).
        let Some(desc_addr) = (rx_qcfg.desc_addr as usize).checked_sub(gpa_base) else {
            return false;
        };
        let Some(avail_addr) = (rx_qcfg.avail_addr as usize).checked_sub(gpa_base) else {
            return false;
        };
        let Some(used_addr) = (rx_qcfg.used_addr as usize).checked_sub(gpa_base) else {
            return false;
        };
        let q_size = rx_qcfg.size as usize;

        if avail_addr + 4 > guest_mem.len() {
            return false;
        }

        let mut injected = false;
        let used_idx_off = used_addr + 2;
        let mut used_idx =
            u16::from_le_bytes([guest_mem[used_idx_off], guest_mem[used_idx_off + 1]]);

        for _ in 0..64 {
            // Re-read avail_idx each iteration so newly posted buffers are
            // picked up without waiting for the next poll cycle.
            std::sync::atomic::fence(Ordering::Acquire);
            let avail_idx =
                u16::from_le_bytes([guest_mem[avail_addr + 2], guest_mem[avail_addr + 3]]);

            if avail_idx == used_idx {
                break;
            }

            // Non-blocking read from the bound fd.
            let mut buf = [0u8; 9216]; // MAX_FRAME_SIZE
            // SAFETY: `host_fd` is owned by the bound `NetPort`. `buf` is a
            // valid mutable stack slice of `buf.len()` bytes. MSG_DONTWAIT
            // ensures non-blocking.
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

            // Prepend 12-byte virtio-net header (all zeros = no offload).
            let virtio_hdr = [0u8; 12];
            let total = virtio_hdr.len() + frame.len();

            // Pop an available RX descriptor and write header + frame.
            let ring_off = avail_addr + 4 + 2 * ((used_idx as usize) % q_size);
            if ring_off + 2 > guest_mem.len() {
                break;
            }
            let head_idx =
                u16::from_le_bytes([guest_mem[ring_off], guest_mem[ring_off + 1]]) as usize;

            let mut written = 0;
            let mut idx = head_idx;
            for _ in 0..q_size {
                let d_off = desc_addr + idx * 16;
                if d_off + 16 > guest_mem.len() {
                    break;
                }
                let addr_gpa =
                    u64::from_le_bytes(guest_mem[d_off..d_off + 8].try_into().unwrap()) as usize;
                let len = u32::from_le_bytes(guest_mem[d_off + 8..d_off + 12].try_into().unwrap())
                    as usize;
                let flags =
                    u16::from_le_bytes(guest_mem[d_off + 12..d_off + 14].try_into().unwrap());
                let next =
                    u16::from_le_bytes(guest_mem[d_off + 14..d_off + 16].try_into().unwrap());
                let Some(addr) = addr_gpa.checked_sub(gpa_base) else {
                    continue;
                };

                if flags & 2 != 0 && addr + len <= guest_mem.len() {
                    // Scatter from [virtio_hdr | frame] combined.
                    let remaining = total.saturating_sub(written);
                    let to_write = remaining.min(len);
                    if to_write > 0 {
                        let hdr_remaining = virtio_hdr.len().saturating_sub(written);
                        if hdr_remaining > 0 {
                            let hdr_write = hdr_remaining.min(to_write);
                            guest_mem[addr..addr + hdr_write]
                                .copy_from_slice(&virtio_hdr[written..written + hdr_write]);
                            if to_write > hdr_write {
                                let frame_write = to_write - hdr_write;
                                guest_mem[addr + hdr_write..addr + hdr_write + frame_write]
                                    .copy_from_slice(&frame[..frame_write]);
                            }
                        } else {
                            let frame_off = written - virtio_hdr.len();
                            guest_mem[addr..addr + to_write]
                                .copy_from_slice(&frame[frame_off..frame_off + to_write]);
                        }
                        written += to_write;
                    }
                }

                if flags & 1 == 0 || written >= total {
                    break;
                }
                idx = next as usize;
            }

            if written == 0 {
                continue;
            }

            // Update used ring.
            let used_entry = used_addr + 4 + ((used_idx as usize) % q_size) * 8;
            if used_entry + 8 <= guest_mem.len() {
                guest_mem[used_entry..used_entry + 4]
                    .copy_from_slice(&(head_idx as u32).to_le_bytes());
                guest_mem[used_entry + 4..used_entry + 8]
                    .copy_from_slice(&(written as u32).to_le_bytes());
                std::sync::atomic::fence(Ordering::Release);
                used_idx = used_idx.wrapping_add(1);
                guest_mem[used_idx_off..used_idx_off + 2].copy_from_slice(&used_idx.to_le_bytes());
            }

            injected = true;
        }

        // Write avail_event for EVENT_IDX.
        if injected {
            let avail_idx_now =
                u16::from_le_bytes([guest_mem[avail_addr + 2], guest_mem[avail_addr + 3]]);
            let avail_event_off = used_addr + 4 + q_size * 8;
            if avail_event_off + 2 <= guest_mem.len() {
                guest_mem[avail_event_off..avail_event_off + 2]
                    .copy_from_slice(&avail_idx_now.to_le_bytes());
            }
        }

        injected
    }
}
