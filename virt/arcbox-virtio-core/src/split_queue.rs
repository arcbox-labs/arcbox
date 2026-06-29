//! Unified split-virtqueue over guest physical memory.
//!
//! `SplitQueue` is the single queue abstraction every ArcBox VirtIO device and
//! worker uses to walk the available ring, parse descriptor chains, publish to
//! the used ring, and decide whether to interrupt the guest. It replaces the
//! previously-duplicated implementations (`queue::VirtQueue` local rings,
//! `queue_guest::GuestMemoryVirtQueue` raw pointers, the per-device inline GPA
//! walks, `arcbox-vmm::virtqueue_util`, and the net-TX inline used-ring write).
//!
//! All addresses are guest physical addresses (GPAs); the backing
//! [`GuestMemWriter`] performs the single `gpa_base` translation, so devices
//! never subtract `gpa_base` themselves.
//!
//! Three correctness properties live here exactly once:
//! - **Cycle-safe chain walk** — bounded by `size`, so a malformed/malicious
//!   `next` cycle cannot spin the host thread.
//! - **Acquire on consume** — the `Acquire` fence is placed *after* reading
//!   `avail.idx` and *before* reading the ring/descriptors, pairing with the
//!   guest's `Release` on `avail.idx`.
//! - **Spec-correct notification suppression** — a full `SeqCst` fence between
//!   publishing `used.idx` and reading `used_event` closes the StoreLoad race
//!   that otherwise lets the device read a stale `used_event`, suppress a
//!   needed IRQ, and leave the guest asleep in WFI forever.

use std::sync::Arc;
use std::sync::atomic::{Ordering, fence};

use virtio_bindings::virtio_ring;

use crate::QueueConfig;
use crate::guest_mem::GuestMemWriter;
use crate::queue::flags;

/// Available-ring flag: the guest requests no interrupt on used-buffer
/// consumption (honored only when EVENT_IDX is not negotiated).
const VRING_AVAIL_F_NO_INTERRUPT: u16 = virtio_ring::VRING_AVAIL_F_NO_INTERRUPT as u16;

/// A single descriptor read from the descriptor table. `addr` is a GPA.
#[derive(Debug, Clone, Copy)]
pub struct VirtqDesc {
    /// Guest physical address of the buffer.
    pub addr: u64,
    /// Buffer length in bytes.
    pub len: u32,
    /// Descriptor flags (NEXT / WRITE / INDIRECT).
    pub flags: u16,
    /// Index of the next descriptor in the chain (valid iff NEXT is set).
    pub next: u16,
}

impl VirtqDesc {
    /// Whether the device may write this buffer (guest read buffer).
    #[must_use]
    pub const fn is_write(&self) -> bool {
        self.flags & flags::WRITE != 0
    }

    /// Whether the chain continues at [`Self::next`].
    #[must_use]
    pub const fn has_next(&self) -> bool {
        self.flags & flags::NEXT != 0
    }
}

/// A popped descriptor chain: the head index (used as the used-ring id) and the
/// descriptors walked from it.
#[derive(Debug)]
pub struct DescChain {
    /// Head descriptor index — the id written back to the used ring.
    pub head_idx: u16,
    /// Descriptors in chain order.
    pub descriptors: Vec<VirtqDesc>,
}

/// A VirtIO split virtqueue backed by guest physical memory.
pub struct SplitQueue {
    mem: Arc<GuestMemWriter>,
    queue_idx: u16,
    size: u16,
    desc_gpa: u64,
    avail_gpa: u64,
    used_gpa: u64,
    /// Next available-ring index the device will consume.
    last_avail_idx: u16,
    /// Device's view of `used.idx` (the device is the sole writer).
    used_idx: u16,
    /// Whether VIRTIO_F_EVENT_IDX was negotiated.
    event_idx: bool,
}

impl SplitQueue {
    /// Builds a queue from the MMIO-configured ring addresses. Called at
    /// `QUEUE_READY` time; `last_avail_idx`/`used_idx` start fresh (the guest
    /// sets up zeroed rings before marking the queue ready).
    #[must_use]
    pub fn new(
        mem: Arc<GuestMemWriter>,
        queue_idx: u16,
        cfg: &QueueConfig,
        event_idx: bool,
    ) -> Self {
        Self {
            mem,
            queue_idx,
            size: cfg.size,
            desc_gpa: cfg.desc_addr,
            avail_gpa: cfg.avail_addr,
            used_gpa: cfg.used_addr,
            last_avail_idx: 0,
            used_idx: 0,
            event_idx,
        }
    }

    /// Queue index within the device.
    #[must_use]
    pub const fn queue_idx(&self) -> u16 {
        self.queue_idx
    }

    /// Queue size (number of descriptors).
    #[must_use]
    pub const fn size(&self) -> u16 {
        self.size
    }

    /// Guest memory accessor for reading/writing descriptor buffers by GPA.
    #[must_use]
    pub fn mem(&self) -> &GuestMemWriter {
        &self.mem
    }

    /// Enable or disable EVENT_IDX notification suppression.
    pub fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
    }

    /// Reads `avail.idx` (the guest's published producer index).
    fn avail_idx(&self) -> u16 {
        // avail layout: flags(2) | idx(2) | ring[size] | used_event(2)
        self.mem.read_u16(self.avail_gpa as usize + 2)
    }

    /// Reads the available-ring entry (a descriptor head index) at `pos`.
    fn avail_ring_entry(&self, pos: u16) -> u16 {
        let off = self.avail_gpa as usize + 4 + (pos % self.size) as usize * 2;
        self.mem.read_u16(off)
    }

    /// Reads descriptor `idx` from the descriptor table.
    fn read_descriptor(&self, idx: u16) -> VirtqDesc {
        // Each descriptor is 16 bytes: addr(8) | len(4) | flags(2) | next(2).
        let base = self.desc_gpa as usize + idx as usize * 16;
        VirtqDesc {
            addr: self.mem.read_u64(base),
            len: self.mem.read_u32(base + 8),
            flags: self.mem.read_u16(base + 12),
            next: self.mem.read_u16(base + 14),
        }
    }

    /// Whether there are available descriptors to process.
    #[must_use]
    pub fn has_avail(&self) -> bool {
        self.avail_idx() != self.last_avail_idx
    }

    /// Pops the next available descriptor chain, or `None` if the ring is empty.
    ///
    /// The chain walk is bounded by `size`: a cyclic `next` chain from a
    /// malformed or malicious guest terminates instead of spinning.
    pub fn pop_avail(&mut self) -> Option<DescChain> {
        let avail_idx = self.avail_idx();
        if avail_idx == self.last_avail_idx {
            return None;
        }
        // Acquire pairs with the guest's Release on avail.idx: read the index
        // first, then fence, then read the ring entry and descriptors so they
        // observe the guest's writes. (queue_guest fenced before the idx read —
        // the wrong side — which ordered nothing useful.)
        fence(Ordering::Acquire);

        let head_idx = self.avail_ring_entry(self.last_avail_idx);
        self.last_avail_idx = self.last_avail_idx.wrapping_add(1);

        let mut descriptors = Vec::new();
        let mut idx = head_idx;
        for _ in 0..self.size {
            if idx >= self.size {
                break; // out-of-range next index
            }
            let desc = self.read_descriptor(idx);
            descriptors.push(desc);
            if !desc.has_next() {
                break;
            }
            idx = desc.next;
        }
        Some(DescChain {
            head_idx,
            descriptors,
        })
    }

    /// Writes one used-ring entry at the current `used.idx` slot (no idx bump).
    fn write_used_entry(&self, head_idx: u16, len: u32) {
        // used layout: flags(2) | idx(2) | ring[size]{id(4),len(4)} | avail_event(2)
        let off = self.used_gpa as usize + 4 + (self.used_idx % self.size) as usize * 8;
        self.mem.write_u32(off, u32::from(head_idx));
        self.mem.write_u32(off + 4, len);
    }

    /// Publishes a single completion. Returns whether the guest must be
    /// interrupted (see [`Self::should_notify`]).
    pub fn push_used(&mut self, head_idx: u16, len: u32) -> bool {
        let old_used = self.used_idx;
        self.write_used_entry(head_idx, len);
        self.used_idx = self.used_idx.wrapping_add(1);
        // Release: the entry data must be visible before the guest observes the
        // advanced used.idx.
        fence(Ordering::Release);
        self.mem
            .write_u16(self.used_gpa as usize + 2, self.used_idx);
        self.should_notify(old_used, self.used_idx)
    }

    /// Publishes a batch of completions with a single `used.idx` update and one
    /// suppression check. Returns whether to interrupt the guest.
    pub fn push_used_batch(&mut self, completions: &[(u16, u32)]) -> bool {
        if completions.is_empty() {
            return false;
        }
        let old_used = self.used_idx;
        for &(head_idx, len) in completions {
            self.write_used_entry(head_idx, len);
            self.used_idx = self.used_idx.wrapping_add(1);
        }
        fence(Ordering::Release);
        self.mem
            .write_u16(self.used_gpa as usize + 2, self.used_idx);
        self.should_notify(old_used, self.used_idx)
    }

    /// Publishes `avail_event = last consumed avail index` into the used ring,
    /// so an EVENT_IDX guest kicks on its very next available entry. Call after
    /// draining a guest→host queue so an isolated late entry can't sit
    /// undrained behind kick suppression.
    pub fn write_avail_event(&self) {
        let off = self.used_gpa as usize + 4 + self.size as usize * 8;
        self.mem.write_u16(off, self.last_avail_idx);
    }

    /// Decides whether to interrupt the guest after advancing `used.idx` from
    /// `old_used` to `new_used`.
    fn should_notify(&self, old_used: u16, new_used: u16) -> bool {
        if old_used == new_used {
            return false;
        }
        if self.event_idx {
            // Full barrier: order the `used.idx` store (in push_used*) before
            // the `used_event` load below. Without this StoreLoad barrier the
            // load may be reordered ahead of the store on weakly-ordered ISAs
            // (ARM64) and read a *stale* used_event, suppressing a needed IRQ —
            // the guest then sleeps in WFI forever waiting for a completion it
            // already received. This is the root-cause class of the HV
            // cold-boot completion-notification hang.
            fence(Ordering::SeqCst);
            let used_event = self
                .mem
                .read_u16(self.avail_gpa as usize + 4 + self.size as usize * 2);
            vring_need_event(used_event, new_used, old_used)
        } else {
            // No EVENT_IDX: honor the avail ring's NO_INTERRUPT flag.
            let avail_flags = self.mem.read_u16(self.avail_gpa as usize);
            avail_flags & VRING_AVAIL_F_NO_INTERRUPT == 0
        }
    }
}

// SAFETY: `mem` is an `Arc<GuestMemWriter>`, which is itself `Send + Sync` over
// a VM-lifetime mapping; the remaining fields are plain integers. A given queue
// is only ever driven by one thread at a time (the vCPU thread that took the
// QUEUE_NOTIFY exit, or the device's dedicated worker).
unsafe impl Send for SplitQueue {}
unsafe impl Sync for SplitQueue {}

/// VirtIO spec §2.7.7.2: the device should notify iff `event_idx` lies in the
/// half-open interval `(old_idx, new_idx]` (modulo 2^16).
fn vring_need_event(event_idx: u16, new_idx: u16, old_idx: u16) -> bool {
    new_idx.wrapping_sub(event_idx).wrapping_sub(1) < new_idx.wrapping_sub(old_idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAM: usize = 0x1_0000; // 64 KiB
    const SIZE: u16 = 8;

    // Ring layout within the test RAM (offsets from gpa_base).
    const DESC_OFF: u64 = 0x1000;
    const AVAIL_OFF: u64 = 0x2000;
    const USED_OFF: u64 = 0x3000;
    const DATA_OFF: u64 = 0x4000;

    /// Backing RAM plus the GPA base it is mapped at. Keeps the buffer alive
    /// for the lifetime of any `SplitQueue` built over it.
    struct TestRam {
        buf: Vec<u8>,
        gpa_base: u64,
    }

    impl TestRam {
        fn new(gpa_base: u64) -> Self {
            Self {
                buf: vec![0u8; RAM],
                gpa_base,
            }
        }

        fn mem(&mut self) -> Arc<GuestMemWriter> {
            // SAFETY: buf outlives every queue built in these tests; access is
            // single-threaded.
            unsafe {
                Arc::new(GuestMemWriter::new(
                    self.buf.as_mut_ptr(),
                    self.buf.len(),
                    self.gpa_base as usize,
                ))
            }
        }

        fn cfg(&self) -> QueueConfig {
            QueueConfig {
                desc_addr: self.gpa_base + DESC_OFF,
                avail_addr: self.gpa_base + AVAIL_OFF,
                used_addr: self.gpa_base + USED_OFF,
                size: SIZE,
                ready: true,
                gpa_base: self.gpa_base,
            }
        }

        fn off(&self, gpa: u64) -> usize {
            (gpa - self.gpa_base) as usize
        }

        fn w16(&mut self, gpa: u64, v: u16) {
            let o = self.off(gpa);
            self.buf[o..o + 2].copy_from_slice(&v.to_le_bytes());
        }

        fn r16(&self, gpa: u64) -> u16 {
            let o = (gpa - self.gpa_base) as usize;
            u16::from_le_bytes([self.buf[o], self.buf[o + 1]])
        }

        fn r32(&self, gpa: u64) -> u32 {
            let o = (gpa - self.gpa_base) as usize;
            u32::from_le_bytes([
                self.buf[o],
                self.buf[o + 1],
                self.buf[o + 2],
                self.buf[o + 3],
            ])
        }

        fn write_desc(&mut self, idx: u16, addr: u64, len: u32, flags: u16, next: u16) {
            let base = self.gpa_base + DESC_OFF + u64::from(idx) * 16;
            let o = self.off(base);
            self.buf[o..o + 8].copy_from_slice(&addr.to_le_bytes());
            self.buf[o + 8..o + 12].copy_from_slice(&len.to_le_bytes());
            self.buf[o + 12..o + 14].copy_from_slice(&flags.to_le_bytes());
            self.buf[o + 14..o + 16].copy_from_slice(&next.to_le_bytes());
        }

        fn set_avail(&mut self, pos: u16, head: u16) {
            self.w16(self.gpa_base + AVAIL_OFF + 4 + u64::from(pos) * 2, head);
        }

        fn set_avail_idx(&mut self, idx: u16) {
            self.w16(self.gpa_base + AVAIL_OFF + 2, idx);
        }

        fn set_used_event(&mut self, v: u16) {
            self.w16(self.gpa_base + AVAIL_OFF + 4 + u64::from(SIZE) * 2, v);
        }

        fn set_avail_flags(&mut self, v: u16) {
            self.w16(self.gpa_base + AVAIL_OFF, v);
        }

        fn used_idx(&self) -> u16 {
            self.r16(self.gpa_base + USED_OFF + 2)
        }

        fn used_entry(&self, slot: u16) -> (u32, u32) {
            let base = self.gpa_base + USED_OFF + 4 + u64::from(slot) * 8;
            (self.r32(base), self.r32(base + 4))
        }

        fn avail_event(&self) -> u16 {
            self.r16(self.gpa_base + USED_OFF + 4 + u64::from(SIZE) * 8)
        }
    }

    fn queue(ram: &mut TestRam, event_idx: bool) -> SplitQueue {
        let cfg = ram.cfg();
        SplitQueue::new(ram.mem(), 0, &cfg, event_idx)
    }

    #[test]
    fn pop_single_descriptor() {
        let mut ram = TestRam::new(0);
        ram.write_desc(0, ram.gpa_base + DATA_OFF, 256, 0, 0);
        ram.set_avail(0, 0);
        ram.set_avail_idx(1);

        let mut q = queue(&mut ram, false);
        assert!(q.has_avail());
        let chain = q.pop_avail().unwrap();
        assert_eq!(chain.head_idx, 0);
        assert_eq!(chain.descriptors.len(), 1);
        assert_eq!(chain.descriptors[0].addr, ram.gpa_base + DATA_OFF);
        assert_eq!(chain.descriptors[0].len, 256);
        assert!(!q.has_avail());
    }

    #[test]
    fn pop_descriptor_chain() {
        let mut ram = TestRam::new(0);
        ram.write_desc(0, ram.gpa_base + DATA_OFF, 16, flags::NEXT, 1);
        ram.write_desc(
            1,
            ram.gpa_base + DATA_OFF + 16,
            16,
            flags::NEXT | flags::WRITE,
            2,
        );
        ram.write_desc(2, ram.gpa_base + DATA_OFF + 32, 16, flags::WRITE, 0);
        ram.set_avail(0, 0);
        ram.set_avail_idx(1);

        let mut q = queue(&mut ram, false);
        let chain = q.pop_avail().unwrap();
        assert_eq!(chain.descriptors.len(), 3);
        assert!(!chain.descriptors[0].is_write());
        assert!(chain.descriptors[1].is_write());
        assert!(!chain.descriptors[2].has_next());
    }

    #[test]
    fn cyclic_chain_terminates() {
        // 0 -> 1 -> 0, both with NEXT set. A bounded walk must terminate.
        let mut ram = TestRam::new(0);
        ram.write_desc(0, ram.gpa_base + DATA_OFF, 16, flags::NEXT, 1);
        ram.write_desc(1, ram.gpa_base + DATA_OFF + 16, 16, flags::NEXT, 0);
        ram.set_avail(0, 0);
        ram.set_avail_idx(1);

        let mut q = queue(&mut ram, false);
        let chain = q.pop_avail().unwrap();
        assert!(chain.descriptors.len() <= SIZE as usize);
    }

    #[test]
    fn out_of_range_next_stops_walk() {
        let mut ram = TestRam::new(0);
        ram.write_desc(0, ram.gpa_base + DATA_OFF, 16, flags::NEXT, 99);
        ram.set_avail(0, 0);
        ram.set_avail_idx(1);

        let mut q = queue(&mut ram, false);
        let chain = q.pop_avail().unwrap();
        assert_eq!(chain.descriptors.len(), 1);
    }

    #[test]
    fn push_used_writes_entry_and_idx() {
        let mut ram = TestRam::new(0);
        let mut q = queue(&mut ram, false);
        let notify = q.push_used(5, 1024);
        assert!(notify); // no EVENT_IDX, no NO_INTERRUPT -> always notify
        assert_eq!(ram.used_idx(), 1);
        assert_eq!(ram.used_entry(0), (5, 1024));
    }

    #[test]
    fn push_used_batch_single_idx_update() {
        let mut ram = TestRam::new(0);
        let mut q = queue(&mut ram, false);
        let notify = q.push_used_batch(&[(0, 100), (1, 200), (2, 300)]);
        assert!(notify);
        assert_eq!(ram.used_idx(), 3);
        assert_eq!(ram.used_entry(0), (0, 100));
        assert_eq!(ram.used_entry(2), (2, 300));
    }

    #[test]
    fn push_used_batch_empty_is_noop() {
        let mut ram = TestRam::new(0);
        let mut q = queue(&mut ram, false);
        assert!(!q.push_used_batch(&[]));
        assert_eq!(ram.used_idx(), 0);
    }

    #[test]
    fn no_interrupt_flag_suppresses_without_event_idx() {
        let mut ram = TestRam::new(0);
        ram.set_avail_flags(VRING_AVAIL_F_NO_INTERRUPT);
        let mut q = queue(&mut ram, false);
        assert!(!q.push_used(0, 16));
    }

    #[test]
    fn event_idx_suppresses_until_event_reached() {
        let mut ram = TestRam::new(0);
        // Guest: "notify me when used.idx reaches 3".
        ram.set_used_event(2);
        let mut q = queue(&mut ram, true);
        // used.idx 0 -> 1: event 2 not in (0,1] -> suppress.
        assert!(!q.push_used(0, 16));
        // 1 -> 2: event 2 not in (1,2] -> suppress.
        assert!(!q.push_used(1, 16));
        // 2 -> 3: event 2 in (2,3] -> notify.
        assert!(q.push_used(2, 16));
    }

    #[test]
    fn write_avail_event_publishes_last_avail() {
        let mut ram = TestRam::new(0);
        ram.write_desc(0, ram.gpa_base + DATA_OFF, 16, 0, 0);
        ram.set_avail(0, 0);
        ram.set_avail_idx(1);
        let mut q = queue(&mut ram, true);
        let _ = q.pop_avail();
        q.write_avail_event();
        assert_eq!(ram.avail_event(), 1); // consumed avail index
    }

    /// The bug `queue_guest::GuestMemoryVirtQueue` had: assuming GPA 0 maps to
    /// `ram_base`. `SplitQueue` resolves every GPA through `GuestMemWriter`, so
    /// a non-zero `gpa_base` (the ARM RAM layout) round-trips correctly.
    #[test]
    fn nonzero_gpa_base_resolves_correctly() {
        let mut ram = TestRam::new(0x4000_0000);
        ram.write_desc(0, ram.gpa_base + DATA_OFF, 512, 0, 0);
        ram.set_avail(0, 0);
        ram.set_avail_idx(1);

        let mut q = queue(&mut ram, false);
        let chain = q.pop_avail().unwrap();
        assert_eq!(chain.descriptors[0].addr, 0x4000_0000 + DATA_OFF);
        assert_eq!(chain.descriptors[0].len, 512);

        q.push_used(0, 512);
        assert_eq!(ram.used_idx(), 1);
        assert_eq!(ram.used_entry(0), (0, 512));
    }

    #[test]
    fn vring_need_event_formula() {
        // event just completed -> notify
        assert!(vring_need_event(0, 1, 0));
        // already past event -> no notify
        assert!(!vring_need_event(3, 6, 5));
        // wrap-around
        assert!(vring_need_event(65535, 0, 65534));
    }
}
