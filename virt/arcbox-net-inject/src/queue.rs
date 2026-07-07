//! Single-frame RX injection through the unified [`SplitQueue`].

use arcbox_virtio::SplitQueue;

/// Virtio-net header size (all zeros for RX passthrough).
pub const VIRTIO_NET_HDR_SIZE: usize = 12;

/// Injects a single Ethernet frame into the guest RX queue.
///
/// Prepends a 12-byte virtio-net header, walks the descriptor chain
/// (scatter-gather within one avail entry, so `num_buffers` is always 1),
/// and publishes the completion to the used ring.
///
/// Returns `Some(notify)` when the frame was injected — `notify` is the
/// interrupt-suppression decision from [`SplitQueue::push_used`] — or
/// `None` when no RX descriptor was available or nothing could be
/// written (the avail entry is left unconsumed for a later retry).
pub fn inject_one_frame(queue: &mut SplitQueue, frame: &[u8]) -> Option<bool> {
    if queue.size() == 0 {
        return None;
    }

    let cursor_before = queue.last_avail_idx();
    let head_idx = queue.next_avail_head()?;

    // Build packet: virtio-net header (zeroed) + ethernet frame.
    let total_len = VIRTIO_NET_HDR_SIZE + frame.len();
    let mut written = 0;

    for desc in queue.chain_iter(head_idx) {
        // RX descriptors are device-writable; skip anything else.
        if desc.is_write() && desc.len > 0 {
            let len = desc.len as usize;
            // SAFETY: VirtIO descriptor buffers are device-owned during
            // injection. The guest will not access them until used.idx
            // advances (inside `push_used`, after a Release fence).
            let Some(buf) = (unsafe { queue.mem().slice_mut(desc.addr as usize, len) }) else {
                // Bounds violation — treat as a malformed ring and stop
                // walking the chain.
                break;
            };

            let remaining = total_len.saturating_sub(written);
            let to_write = remaining.min(len);

            if written < VIRTIO_NET_HDR_SIZE {
                // Write virtio-net header (or partial header).
                //
                // num_buffers semantics under MRG_RXBUF: it is the count of
                // avail-ring entries ("buffers") the device consumed for
                // this packet, NOT the number of linked descriptors in the
                // chain. This function writes exactly one complete packet
                // into one popped avail entry (spilling into linked NEXT
                // descriptors within that chain as needed), so num_buffers
                // is always 1 here. The multi-buffer RX-coalescing path
                // lives in `inject::poll_inline_conns`, which stamps the
                // actual span count via `write_inline_headers`.
                let hdr_remaining = VIRTIO_NET_HDR_SIZE - written;
                let hdr_bytes = hdr_remaining.min(to_write);
                buf[..hdr_bytes].fill(0);
                // Set num_buffers = 1 at offset 10-11 (MRG_RXBUF).
                if written <= 10 && written + hdr_bytes > 10 {
                    let nb_off = 10 - written;
                    if nb_off + 2 <= hdr_bytes {
                        buf[nb_off..nb_off + 2].copy_from_slice(&1u16.to_le_bytes());
                    }
                }
                // GSO offload: for large TCP/IPv4 frames with standard headers
                // (IHL=5, no options), set NEEDS_CSUM + GSO fields so the
                // guest kernel segments at MSS boundaries.
                // Requires the frame to have a partial (pseudo-header) checksum
                // in the TCP checksum field — build_tcp_data_frame_partial_csum
                // provides this.
                if written == 0
                    && hdr_bytes >= 10
                    && frame.len() > 1500
                    && frame.len() >= 54
                    && frame[12] == 0x08
                    && frame[13] == 0x00 // IPv4
                    && frame[23] == 6 // TCP
                    && frame[14] & 0x0F == 5
                // IHL=5, no IP options
                {
                    buf[0] = 1; // flags = VIRTIO_NET_HDR_F_NEEDS_CSUM
                    buf[1] = 1; // gso_type = VIRTIO_NET_HDR_GSO_TCPV4
                    // hdr_len = L2+L3+L4 total header = Eth14+IP20+TCP20 = 54.
                    buf[2..4].copy_from_slice(&54u16.to_le_bytes());
                    buf[4..6].copy_from_slice(&1460u16.to_le_bytes()); // gso_size
                    buf[6..8].copy_from_slice(&34u16.to_le_bytes()); // csum_start (Eth14+IP20)
                    buf[8..10].copy_from_slice(&16u16.to_le_bytes()); // csum_offset (TCP csum field)
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

        if written >= total_len {
            break;
        }
    }

    if written == 0 {
        // Nothing written — return the avail entry so a later attempt (or
        // repost by the guest) can use it, matching the legacy behavior.
        queue.set_last_avail_idx(cursor_before);
        return None;
    }

    Some(queue.push_used(head_idx, written as u32))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arcbox_virtio::{GuestMemWriter, QueueConfig, SplitQueue};

    use super::*;

    const RAM: usize = 0x2_0000; // 128 KiB
    const SIZE: u16 = 8;
    const DESC_OFF: usize = 0x1000;
    const AVAIL_OFF: usize = 0x2000;
    const USED_OFF: usize = 0x3000;
    const DATA_OFF: usize = 0x4000;

    struct TestRam {
        buf: Vec<u8>,
    }

    impl TestRam {
        fn new() -> Self {
            Self {
                buf: vec![0u8; RAM],
            }
        }

        fn queue(&mut self, event_idx: bool) -> SplitQueue {
            let cfg = QueueConfig {
                desc_addr: DESC_OFF as u64,
                avail_addr: AVAIL_OFF as u64,
                used_addr: USED_OFF as u64,
                size: SIZE,
                ready: true,
                gpa_base: 0,
            };
            // SAFETY: buf outlives every queue built in these tests; access
            // is single-threaded.
            let mem = unsafe {
                Arc::new(GuestMemWriter::new(
                    self.buf.as_mut_ptr(),
                    self.buf.len(),
                    0,
                ))
            };
            SplitQueue::new(mem, 0, &cfg, event_idx)
        }

        fn write_desc(&mut self, idx: u16, addr: u64, len: u32, flags: u16, next: u16) {
            let base = DESC_OFF + idx as usize * 16;
            self.buf[base..base + 8].copy_from_slice(&addr.to_le_bytes());
            self.buf[base + 8..base + 12].copy_from_slice(&len.to_le_bytes());
            self.buf[base + 12..base + 14].copy_from_slice(&flags.to_le_bytes());
            self.buf[base + 14..base + 16].copy_from_slice(&next.to_le_bytes());
        }

        fn post_avail(&mut self, pos: u16, head: u16) {
            let off = AVAIL_OFF + 4 + pos as usize * 2;
            self.buf[off..off + 2].copy_from_slice(&head.to_le_bytes());
        }

        fn set_avail_idx(&mut self, idx: u16) {
            self.buf[AVAIL_OFF + 2..AVAIL_OFF + 4].copy_from_slice(&idx.to_le_bytes());
        }

        fn set_used_event(&mut self, v: u16) {
            let off = AVAIL_OFF + 4 + SIZE as usize * 2;
            self.buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
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

        fn data(&self, off: usize, len: usize) -> &[u8] {
            &self.buf[DATA_OFF + off..DATA_OFF + off + len]
        }
    }

    const WRITE: u16 = 2;
    const NEXT: u16 = 1;

    #[test]
    fn injects_header_and_frame_into_single_descriptor() {
        let mut ram = TestRam::new();
        ram.write_desc(0, DATA_OFF as u64, 2048, WRITE, 0);
        ram.post_avail(0, 0);
        ram.set_avail_idx(1);
        let mut q = ram.queue(false);

        let frame = [0xAAu8; 100];
        let notify = inject_one_frame(&mut q, &frame);

        assert_eq!(notify, Some(true)); // no EVENT_IDX, no NO_INTERRUPT
        assert_eq!(ram.used_idx(), 1);
        assert_eq!(ram.used_entry(0), (0, (VIRTIO_NET_HDR_SIZE + 100) as u32));
        // 12-byte header: zeroed except num_buffers = 1 at bytes 10-11.
        assert_eq!(ram.data(0, 10), &[0u8; 10]);
        assert_eq!(ram.data(10, 2), &1u16.to_le_bytes());
        assert_eq!(ram.data(VIRTIO_NET_HDR_SIZE, 100), &frame);
    }

    #[test]
    fn frame_spills_across_chained_descriptors() {
        let mut ram = TestRam::new();
        // Two 64-byte writable descriptors chained: 12-byte header + 100-byte
        // frame = 112 bytes spans both.
        ram.write_desc(0, DATA_OFF as u64, 64, WRITE | NEXT, 1);
        ram.write_desc(1, (DATA_OFF + 64) as u64, 64, WRITE, 0);
        ram.post_avail(0, 0);
        ram.set_avail_idx(1);
        let mut q = ram.queue(false);

        let frame: Vec<u8> = (0..100u8).collect();
        let notify = inject_one_frame(&mut q, &frame);

        assert_eq!(notify, Some(true));
        assert_eq!(ram.used_entry(0), (0, 112));
        // First descriptor: header + first 52 frame bytes; second: the rest.
        assert_eq!(ram.data(VIRTIO_NET_HDR_SIZE, 52), &frame[..52]);
        assert_eq!(ram.data(64, 48), &frame[52..]);
    }

    #[test]
    fn returns_none_when_ring_is_empty() {
        let mut ram = TestRam::new();
        let mut q = ram.queue(false);
        assert_eq!(inject_one_frame(&mut q, &[0u8; 64]), None);
        assert_eq!(ram.used_idx(), 0);
    }

    #[test]
    fn unusable_chain_is_left_unconsumed() {
        let mut ram = TestRam::new();
        // A read-only descriptor: nothing can be written.
        ram.write_desc(0, DATA_OFF as u64, 2048, 0, 0);
        ram.post_avail(0, 0);
        ram.set_avail_idx(1);
        let mut q = ram.queue(false);

        assert_eq!(inject_one_frame(&mut q, &[0u8; 64]), None);
        assert_eq!(ram.used_idx(), 0, "no completion published");
        // The avail entry was not consumed: a repost by the guest (same slot,
        // now writable) succeeds without the entry having been lost.
        ram.write_desc(0, DATA_OFF as u64, 2048, WRITE, 0);
        assert_eq!(inject_one_frame(&mut q, &[0u8; 64]), Some(true));
        assert_eq!(ram.used_idx(), 1);
    }

    #[test]
    fn large_tcp_frame_gets_gso_stamped() {
        let mut ram = TestRam::new();
        ram.write_desc(0, DATA_OFF as u64, 4096, WRITE, 0);
        ram.post_avail(0, 0);
        ram.set_avail_idx(1);
        let mut q = ram.queue(false);

        // Minimal >1500-byte TCP/IPv4 frame: EtherType 0x0800, IHL=5, proto 6.
        let mut frame = vec![0u8; 2000];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x45;
        frame[23] = 6;

        assert!(inject_one_frame(&mut q, &frame).is_some());
        let hdr = ram.data(0, VIRTIO_NET_HDR_SIZE);
        assert_eq!(hdr[0], 1, "NEEDS_CSUM");
        assert_eq!(hdr[1], 1, "GSO_TCPV4");
        assert_eq!(u16::from_le_bytes([hdr[2], hdr[3]]), 54); // hdr_len
        assert_eq!(u16::from_le_bytes([hdr[4], hdr[5]]), 1460); // gso_size
        assert_eq!(u16::from_le_bytes([hdr[6], hdr[7]]), 34); // csum_start
        assert_eq!(u16::from_le_bytes([hdr[8], hdr[9]]), 16); // csum_offset
        assert_eq!(u16::from_le_bytes([hdr[10], hdr[11]]), 1); // num_buffers
    }

    #[test]
    fn event_idx_suppresses_notify_until_crossed() {
        let mut ram = TestRam::new();
        for i in 0..2u16 {
            ram.write_desc(i, (DATA_OFF + i as usize * 4096) as u64, 4096, WRITE, 0);
            ram.post_avail(i, i);
        }
        ram.set_avail_idx(2);
        // Guest asks for a notification when used.idx reaches 2.
        ram.set_used_event(1);
        let mut q = ram.queue(true);

        assert_eq!(inject_one_frame(&mut q, &[1u8; 32]), Some(false));
        assert_eq!(inject_one_frame(&mut q, &[2u8; 32]), Some(true));
    }
}
