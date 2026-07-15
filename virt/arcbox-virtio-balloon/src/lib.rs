//! VirtIO traditional memory balloon device (virtio-balloon).
//!
//! Implements the traditional-balloon subset of VirtIO 1.2 §5.5:
//!
//! - Two virtqueues: `inflateq` (0) and `deflateq` (1).
//! - Feature bit `VIRTIO_BALLOON_F_DEFLATE_ON_OOM` (bit 2) — the guest may
//!   reclaim balloon pages on OOM without host permission. Safe for us
//!   because we use `madvise(MADV_DONTNEED)` which does not unmap the
//!   guest-visible region; reclaimed pages simply re-fault zero-filled,
//!   matching the balloon contract.
//! - Two config-space fields: `num_pages` (host → guest target, read-only
//!   from the guest) and `actual` (guest → host current, written by the
//!   guest as pages are inflated/deflated).
//!
//! - Free page reporting (`VIRTIO_BALLOON_F_REPORTING`, bit 5) — the guest
//!   kernel periodically hands batches of currently-free pages to the host
//!   on `reporting_vq` (transport index computed from the negotiated
//!   feature set — see [`reporting_queue_index`]); the host
//!   `madvise(MADV_DONTNEED)`s the ranges and completes the buffers.
//!   Combined with
//!   `DEFLATE_ON_OOM` this lets the guest kernel self-manage: idle memory
//!   drains back to the host with no balloon-target policy at all.
//!
//! Not implemented (all optional per spec):
//! - Stats virtqueue (`VIRTIO_BALLOON_F_STATS_VQ`)
//! - Free-page hinting (`VIRTIO_BALLOON_F_FREE_PAGE_HINT` — the migration
//!   aid, distinct from reporting)
//! - Page poisoning
//!
//! ## Inflate semantics
//!
//! When the guest inflates the balloon, it writes a descriptor chain
//! containing `u32` PFNs (4 KiB granularity) into the inflate queue.
//! For each PFN, the host calls `madvise(MADV_DONTNEED)` on the
//! corresponding page of the guest RAM mapping. The physical page is
//! released back to the kernel's free pool. A subsequent access from
//! the guest will re-fault a zero page — acceptable per §5.5.1: the
//! guest has promised not to use the page until it tells the host via
//! the deflate queue.
//!
//! ## Deflate semantics
//!
//! Deflate requests are no-ops on our side: because we used
//! `MADV_DONTNEED` (not `munmap`), the pages remain mapped and re-fault
//! automatically on guest access. We still consume the descriptors and
//! write the used ring so the guest's queue does not stall.

use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};

use arcbox_virtio_core::{QueueConfig, VirtioDevice, VirtioDeviceId, virtio_bindings};

/// VIRTIO balloon feature: guest may deflate on its own OOM.
const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u64 = 1 << 2;

/// VIRTIO balloon feature: free page reporting virtqueue.
const VIRTIO_BALLOON_F_REPORTING: u64 = 1 << 5;

/// Inflate queue index.
const QUEUE_INFLATE: u16 = 0;
/// Deflate queue index.
const QUEUE_DEFLATE: u16 = 1;
/// Stats virtqueue feature bit — not advertised, but its bit position
/// participates in [`reporting_queue_index`].
const VIRTIO_BALLOON_F_STATS_VQ: u64 = 1 << 1;
/// Free-page-hinting feature bit — not advertised; see above.
const VIRTIO_BALLOON_F_FREE_PAGE_HINT: u64 = 1 << 3;

/// Transport-level index of the reporting queue for a negotiated feature
/// set.
///
/// The driver-side `VIRTIO_BALLOON_VQ_*` enum is only an array position:
/// the MMIO transport numbers queues *densely* over the virtqueues that
/// actually exist (`vm_find_vqs` skips NULL-named entries without
/// consuming an index). With neither stats nor free-page hinting
/// negotiated, reporting is queue 2, right after inflate/deflate.
const fn reporting_queue_index(features: u64) -> u16 {
    let mut idx = 2;
    if features & VIRTIO_BALLOON_F_STATS_VQ != 0 {
        idx += 1;
    }
    if features & VIRTIO_BALLOON_F_FREE_PAGE_HINT != 0 {
        idx += 1;
    }
    idx
}

/// Number of per-queue cursor slots (the reporting queue is the highest,
/// at most index 4 with every optional queue negotiated).
const QUEUE_SLOTS: usize = 5;

/// Traditional-balloon page size — fixed 4 KiB per spec §5.5.6.
const BALLOON_PFN_SHIFT: u32 = 12;
const BALLOON_PAGE_SIZE: u64 = 1 << BALLOON_PFN_SHIFT;

/// Traditional VirtIO memory balloon device.
///
/// Host-side knobs live in atomics so callers outside the vCPU thread
/// (e.g. the daemon's idle monitor) can adjust `num_pages` without
/// taking a lock. The queue processing itself runs on the vCPU thread
/// via [`VirtioDevice::process_queue`].
pub struct VirtioBalloon {
    /// Negotiated features. Starts as advertised features; narrowed by
    /// `ack_features`.
    features: u64,
    /// Whether the guest driver has signalled `DRIVER_OK`.
    active: bool,
    /// Last processed `avail_idx` per queue slot (indexed by queue index;
    /// stats/hinting slots stay unused). Wraps at u16 per VirtIO ring
    /// semantics.
    last_avail: [u16; QUEUE_SLOTS],
    /// Host-requested target in 4 KiB pages. Set by
    /// [`Self::set_num_pages`]; read by guest via config space.
    num_pages: AtomicU32,
    /// Guest-reported current inflated count in 4 KiB pages. Written by
    /// the guest via config-space writes at offset 4..8.
    actual: AtomicU32,
    /// Advisory counter of total pages reclaimed via `MADV_DONTNEED`
    /// since the device was created. Purely observational.
    inflated_total: AtomicU32,
    /// Lightweight bump counter to flag config-space updates to the
    /// MMIO transport. The transport queries this to know when to
    /// increment `VIRTIO_MMIO_CONFIG_GENERATION`.
    config_generation: AtomicU16,
}

impl VirtioBalloon {
    /// VirtIO 1.0 feature — required.
    pub const FEATURE_VERSION_1: u64 = 1 << virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;

    /// Creates a new balloon device in the reset state.
    ///
    /// Advertises `VIRTIO_F_VERSION_1`, `VIRTIO_BALLOON_F_DEFLATE_ON_OOM`
    /// and `VIRTIO_BALLOON_F_REPORTING`.
    pub fn new() -> Self {
        Self {
            features: Self::FEATURE_VERSION_1
                | VIRTIO_BALLOON_F_DEFLATE_ON_OOM
                | VIRTIO_BALLOON_F_REPORTING,
            active: false,
            last_avail: [0; QUEUE_SLOTS],
            num_pages: AtomicU32::new(0),
            actual: AtomicU32::new(0),
            inflated_total: AtomicU32::new(0),
            config_generation: AtomicU16::new(0),
        }
    }

    /// Sets the target balloon size, in 4 KiB pages. The guest observes
    /// this via config-space reads and asynchronously inflates or
    /// deflates toward it.
    pub fn set_num_pages(&self, pages: u32) {
        self.num_pages.store(pages, Ordering::Release);
        self.config_generation.fetch_add(1, Ordering::AcqRel);
    }

    /// Returns the host-requested target in pages.
    pub fn num_pages(&self) -> u32 {
        self.num_pages.load(Ordering::Acquire)
    }

    /// Returns the guest-reported current inflation in pages.
    pub fn actual(&self) -> u32 {
        self.actual.load(Ordering::Acquire)
    }

    /// Returns the cumulative number of pages reclaimed via madvise
    /// since this device was created.
    pub fn inflated_total(&self) -> u32 {
        self.inflated_total.load(Ordering::Acquire)
    }
}

impl Default for VirtioBalloon {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioDevice for VirtioBalloon {
    fn device_id(&self) -> VirtioDeviceId {
        VirtioDeviceId::Balloon
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, features: u64) {
        self.features &= features;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Config layout per VirtIO 1.2 §5.5.4:
        //   offset 0..4   num_pages (u32 LE) — RO from guest
        //   offset 4..8   actual    (u32 LE) — written by guest
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&self.num_pages.load(Ordering::Acquire).to_le_bytes());
        buf[4..8].copy_from_slice(&self.actual.load(Ordering::Acquire).to_le_bytes());
        let off = offset as usize;
        for (i, b) in data.iter_mut().enumerate() {
            let idx = off + i;
            *b = if idx < buf.len() { buf[idx] } else { 0 };
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        // Only `actual` (offset 4..8) is writable by the guest.
        // Build the new 4-byte value atomically by merging the write
        // into the current stored bytes.
        let end = offset + data.len() as u64;
        if end <= 4 || offset >= 8 {
            return;
        }
        let mut bytes = self.actual.load(Ordering::Acquire).to_le_bytes();
        for (i, b) in data.iter().enumerate() {
            let abs = offset + i as u64;
            if (4..8).contains(&abs) {
                bytes[(abs - 4) as usize] = *b;
            }
        }
        self.actual
            .store(u32::from_le_bytes(bytes), Ordering::Release);
    }

    fn activate(&mut self) -> arcbox_virtio_core::Result<()> {
        self.active = true;
        tracing::info!("virtio-balloon activated");
        Ok(())
    }

    fn reset(&mut self) {
        self.active = false;
        self.last_avail = [0; QUEUE_SLOTS];
        self.num_pages.store(0, Ordering::Release);
        self.actual.store(0, Ordering::Release);
    }

    fn process_queue(
        &mut self,
        queue_idx: u16,
        memory: &mut [u8],
        queue_config: &QueueConfig,
    ) -> arcbox_virtio_core::Result<Vec<(u16, u32)>> {
        if !queue_config.ready || queue_config.size == 0 {
            return Ok(Vec::new());
        }
        let reporting_negotiated = self.features & VIRTIO_BALLOON_F_REPORTING != 0;
        let queue_reporting = reporting_queue_index(self.features);
        let known = queue_idx == QUEUE_INFLATE
            || queue_idx == QUEUE_DEFLATE
            || (queue_idx == queue_reporting && reporting_negotiated);
        if !known {
            return Ok(Vec::new());
        }

        let gpa_base = queue_config.gpa_base as usize;
        // SAFETY: `memory` is the guest RAM slice; the queue accesses it only
        // through the GuestMemWriter built here, and `memory` is not touched
        // directly while the queue is alive.
        let mem = std::sync::Arc::new(unsafe {
            arcbox_virtio_core::GuestMemWriter::new(memory.as_mut_ptr(), memory.len(), gpa_base)
        });
        let mut queue = arcbox_virtio_core::SplitQueue::new(mem, queue_idx, queue_config, false);
        let idx_slot = queue_idx as usize;
        queue.set_last_avail_idx(self.last_avail[idx_slot]);

        let mut completions = Vec::new();
        while let Some(chain) = queue.pop_avail() {
            let mut chain_pages_handled = 0u32;
            for desc in &chain.descriptors {
                match queue_idx {
                    // Each read-only descriptor carries a little-endian u32
                    // PFN array.
                    QUEUE_INFLATE if !desc.is_write() => {
                        // Copy the PFN bytes out before madvise so the
                        // immutable borrow on guest memory is released before
                        // we take the raw pointer.
                        let Some(buf) = queue.mem().slice(desc.addr as usize, desc.len as usize)
                        else {
                            continue;
                        };
                        let pfn_bytes = buf.to_vec();
                        let ram_ptr = queue.mem().ptr();
                        let ram_len = queue.mem().len();
                        chain_pages_handled +=
                            handle_pfn_list(&pfn_bytes, ram_ptr, ram_len, gpa_base);
                    }
                    // Reporting buffers ARE the free pages: each
                    // device-writable descriptor directly addresses a free
                    // range the guest promises not to touch until the chain
                    // completes. Release the backing and complete.
                    q if q == queue_reporting && desc.is_write() => {
                        let ram_ptr = queue.mem().ptr();
                        let ram_len = queue.mem().len();
                        chain_pages_handled +=
                            handle_reported_range(desc.addr, desc.len, ram_ptr, ram_len, gpa_base);
                    }
                    _ => {}
                }
            }
            // Balloon completions write 0 bytes (nothing is written into the
            // descriptor buffer). Deflate just completes the descriptor —
            // MADV_DONTNEED pages re-fault naturally, so no explicit remap.
            queue.push_used(chain.head_idx, 0);
            completions.push((chain.head_idx, 0));
            if chain_pages_handled > 0 {
                self.inflated_total
                    .fetch_add(chain_pages_handled, Ordering::AcqRel);
            }
        }

        self.last_avail[idx_slot] = queue.last_avail_idx();
        Ok(completions)
    }
}

/// Walks a byte buffer as a little-endian `u32` PFN array and calls
/// `madvise(MADV_DONTNEED)` on each corresponding guest page. Returns
/// the number of pages successfully advised. Bad PFNs (out of range or
/// below `gpa_base`) are logged and skipped — a malicious or buggy
/// guest cannot affect host memory outside the guest RAM mapping.
fn handle_pfn_list(buf: &[u8], ram_base: *mut u8, ram_len: usize, gpa_base: usize) -> u32 {
    let mut handled = 0u32;
    for chunk in buf.chunks_exact(4) {
        let pfn = u32::from_le_bytes(chunk.try_into().unwrap());
        let gpa = (u64::from(pfn)) << BALLOON_PFN_SHIFT;
        let Some(offset) = (gpa as usize).checked_sub(gpa_base) else {
            tracing::warn!("virtio-balloon: PFN {pfn:#x} below ram base");
            continue;
        };
        let page_size = BALLOON_PAGE_SIZE as usize;
        if offset + page_size > ram_len {
            tracing::warn!(
                "virtio-balloon: PFN {pfn:#x} (offset {offset:#x}) beyond ram ({ram_len:#x})"
            );
            continue;
        }
        // SAFETY: ram_base points to a live host mapping of the guest
        // RAM region, valid for ram_len bytes. offset..offset+page_size
        // was bounds-checked above. madvise on a host mapping with
        // MADV_DONTNEED is documented to release physical backing
        // without invalidating the virtual mapping; subsequent access
        // re-faults zero-filled pages — which is exactly the balloon
        // contract (§5.5.1).
        let ret =
            unsafe { libc::madvise(ram_base.add(offset).cast(), page_size, libc::MADV_DONTNEED) };
        if ret != 0 {
            tracing::warn!(
                "virtio-balloon: madvise(MADV_DONTNEED) at offset {:#x} failed: {}",
                offset,
                std::io::Error::last_os_error()
            );
            continue;
        }
        handled += 1;
    }
    handled
}

/// Releases one guest-reported free range via `madvise(MADV_DONTNEED)`,
/// returning the number of 4 KiB pages released. The range is
/// guest-controlled: it must be page-aligned, non-empty, and fully inside
/// the guest RAM mapping, or it is logged and skipped.
fn handle_reported_range(
    addr: u64,
    len: u32,
    ram_base: *mut u8,
    ram_len: usize,
    gpa_base: usize,
) -> u32 {
    let len = len as usize;
    let page_size = BALLOON_PAGE_SIZE as usize;
    if len == 0 || len % page_size != 0 || addr % BALLOON_PAGE_SIZE != 0 {
        tracing::warn!("virtio-balloon: misaligned reported range {addr:#x}+{len:#x}");
        return 0;
    }
    let Some(offset) = (addr as usize).checked_sub(gpa_base) else {
        tracing::warn!("virtio-balloon: reported range {addr:#x} below ram base");
        return 0;
    };
    let Some(end) = offset.checked_add(len) else {
        tracing::warn!("virtio-balloon: reported range {addr:#x}+{len:#x} overflows");
        return 0;
    };
    if end > ram_len {
        tracing::warn!(
            "virtio-balloon: reported range {addr:#x}+{len:#x} beyond ram ({ram_len:#x})"
        );
        return 0;
    }
    // SAFETY: ram_base points to a live host mapping of the guest RAM
    // region, valid for ram_len bytes; offset..end was bounds-checked
    // above. MADV_DONTNEED releases the physical backing without
    // invalidating the mapping; the guest re-faults zero pages, which is
    // the free-page-reporting contract (the pages are free right now and
    // the guest keeps them off-limits until the buffer completes).
    let ret = unsafe { libc::madvise(ram_base.add(offset).cast(), len, libc::MADV_DONTNEED) };
    if ret != 0 {
        tracing::warn!(
            "virtio-balloon: madvise(MADV_DONTNEED) on reported range {:#x}+{:#x} failed: {}",
            offset,
            len,
            std::io::Error::last_os_error()
        );
        return 0;
    }
    (len / page_size) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_is_balloon() {
        assert_eq!(VirtioBalloon::new().device_id(), VirtioDeviceId::Balloon);
    }

    #[test]
    fn advertises_required_features() {
        let b = VirtioBalloon::new();
        assert!(b.features() & VirtioBalloon::FEATURE_VERSION_1 != 0);
        assert!(b.features() & VIRTIO_BALLOON_F_DEFLATE_ON_OOM != 0);
    }

    #[test]
    fn ack_features_narrows_advertised_set() {
        let mut b = VirtioBalloon::new();
        b.ack_features(VirtioBalloon::FEATURE_VERSION_1);
        assert_eq!(b.features(), VirtioBalloon::FEATURE_VERSION_1);
    }

    #[test]
    fn read_config_returns_num_pages_then_actual() {
        let b = VirtioBalloon::new();
        b.set_num_pages(0x1234);
        let mut out = [0u8; 8];
        b.read_config(0, &mut out);
        assert_eq!(u32::from_le_bytes(out[0..4].try_into().unwrap()), 0x1234);
        assert_eq!(u32::from_le_bytes(out[4..8].try_into().unwrap()), 0);
    }

    #[test]
    fn write_config_updates_only_actual_field() {
        let mut b = VirtioBalloon::new();
        b.set_num_pages(999);
        // Write 0x42 to offset 4 (lowest byte of `actual`).
        b.write_config(4, &[0x42, 0x00, 0x00, 0x00]);
        assert_eq!(b.actual(), 0x42);
        // num_pages must not be affected.
        assert_eq!(b.num_pages(), 999);
    }

    #[test]
    fn write_config_ignores_out_of_range_offset() {
        let mut b = VirtioBalloon::new();
        b.set_num_pages(5);
        b.write_config(0, &[0xAA; 4]);
        assert_eq!(b.num_pages(), 5);
        b.write_config(100, &[0xBB; 4]);
        assert_eq!(b.num_pages(), 5);
    }

    #[test]
    fn set_num_pages_bumps_config_generation() {
        let b = VirtioBalloon::new();
        let before = b.config_generation.load(Ordering::Acquire);
        b.set_num_pages(128);
        let after = b.config_generation.load(Ordering::Acquire);
        assert_eq!(after, before + 1);
    }

    #[test]
    fn reset_clears_state() {
        let mut b = VirtioBalloon::new();
        b.set_num_pages(42);
        b.write_config(4, &[7, 0, 0, 0]);
        b.activate().unwrap();
        b.reset();
        assert_eq!(b.num_pages(), 0);
        assert_eq!(b.actual(), 0);
        assert!(!b.active);
    }

    /// Page-aligned guest RAM for ring-level tests (madvise requires
    /// page alignment, which a plain `Vec` does not guarantee).
    struct TestRam {
        ptr: *mut u8,
        len: usize,
        gpa_base: u64,
    }

    // Ring layout within the test RAM (offsets from gpa_base).
    const DESC_OFF: u64 = 0x1000;
    const AVAIL_OFF: u64 = 0x2000;
    const USED_OFF: u64 = 0x3000;
    const DATA_OFF: u64 = 0x4000;
    const RING_SIZE: u16 = 8;

    impl TestRam {
        fn new(gpa_base: u64) -> Self {
            let len = 0x1_0000;
            // SAFETY: fresh anonymous private mapping owned by this struct.
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(ptr, libc::MAP_FAILED);
            Self {
                ptr: ptr.cast(),
                len,
                gpa_base,
            }
        }

        fn slice(&mut self) -> &mut [u8] {
            // SAFETY: ptr/len describe the live private mapping above.
            unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
        }

        fn cfg(&self) -> QueueConfig {
            QueueConfig {
                desc_addr: self.gpa_base + DESC_OFF,
                avail_addr: self.gpa_base + AVAIL_OFF,
                used_addr: self.gpa_base + USED_OFF,
                size: RING_SIZE,
                ready: true,
                gpa_base: self.gpa_base,
            }
        }

        fn off(&self, gpa: u64) -> usize {
            (gpa - self.gpa_base) as usize
        }

        fn write_desc(&mut self, idx: u16, addr: u64, len: u32, flags: u16, next: u16) {
            let o = self.off(self.gpa_base + DESC_OFF) + usize::from(idx) * 16;
            let ram = self.slice();
            ram[o..o + 8].copy_from_slice(&addr.to_le_bytes());
            ram[o + 8..o + 12].copy_from_slice(&len.to_le_bytes());
            ram[o + 12..o + 14].copy_from_slice(&flags.to_le_bytes());
            ram[o + 14..o + 16].copy_from_slice(&next.to_le_bytes());
        }

        fn publish_avail(&mut self, pos: u16, head: u16) {
            let ao = self.off(self.gpa_base + AVAIL_OFF);
            let entry = ao + 4 + usize::from(pos % RING_SIZE) * 2;
            let ram = self.slice();
            ram[entry..entry + 2].copy_from_slice(&head.to_le_bytes());
            let idx = pos + 1;
            ram[ao + 2..ao + 4].copy_from_slice(&idx.to_le_bytes());
        }

        fn used_idx(&mut self) -> u16 {
            let uo = self.off(self.gpa_base + USED_OFF);
            let ram = self.slice();
            u16::from_le_bytes([ram[uo + 2], ram[uo + 3]])
        }
    }

    impl Drop for TestRam {
        fn drop(&mut self) {
            // SAFETY: mapping created in new() with this exact len.
            unsafe { libc::munmap(self.ptr.cast(), self.len) };
        }
    }

    /// Device-writable descriptor flag (VIRTQ_DESC_F_WRITE).
    const F_WRITE: u16 = 2;

    const GPA_BASE: u64 = 0x4000_0000;

    fn reporting_device() -> VirtioBalloon {
        let mut b = VirtioBalloon::new();
        b.ack_features(b.features());
        b
    }

    /// The queue index the driver will use for reporting under this
    /// device's advertised feature set (no stats, no hinting → dense 2).
    const QUEUE_REPORTING: u16 = 2;

    #[test]
    fn reporting_queue_index_is_dense() {
        // Transport numbering skips queues whose features were not
        // negotiated (vm_find_vqs does not consume an index for them).
        assert_eq!(reporting_queue_index(VirtioBalloon::new().features()), 2);
        assert_eq!(
            reporting_queue_index(VIRTIO_BALLOON_F_REPORTING | VIRTIO_BALLOON_F_STATS_VQ),
            3
        );
        assert_eq!(
            reporting_queue_index(
                VIRTIO_BALLOON_F_REPORTING
                    | VIRTIO_BALLOON_F_STATS_VQ
                    | VIRTIO_BALLOON_F_FREE_PAGE_HINT
            ),
            4
        );
    }

    #[test]
    fn reporting_releases_valid_range_and_completes() {
        let mut ram = TestRam::new(GPA_BASE);
        let mut b = reporting_device();
        let cfg = ram.cfg();

        // One device-writable descriptor covering two free pages.
        ram.write_desc(
            0,
            GPA_BASE + DATA_OFF,
            2 * BALLOON_PAGE_SIZE as u32,
            F_WRITE,
            0,
        );
        ram.publish_avail(0, 0);

        let completions = b.process_queue(QUEUE_REPORTING, ram.slice(), &cfg).unwrap();
        assert_eq!(completions, vec![(0, 0)]);
        assert_eq!(ram.used_idx(), 1, "chain must be returned to the guest");
        assert_eq!(b.inflated_total(), 2, "two pages released");
    }

    #[test]
    fn reporting_rejects_hostile_ranges_but_completes_chains() {
        let mut ram = TestRam::new(GPA_BASE);
        let mut b = reporting_device();
        let cfg = ram.cfg();

        // Beyond RAM, misaligned, zero-length, address-overflow: all must be
        // skipped without touching host memory — and every chain must still
        // complete so the guest queue cannot wedge.
        ram.write_desc(
            0,
            GPA_BASE + 0x10_0000,
            BALLOON_PAGE_SIZE as u32,
            F_WRITE,
            0,
        );
        ram.write_desc(
            1,
            GPA_BASE + DATA_OFF + 3,
            BALLOON_PAGE_SIZE as u32,
            F_WRITE,
            0,
        );
        ram.write_desc(2, GPA_BASE + DATA_OFF, 0, F_WRITE, 0);
        ram.write_desc(3, u64::MAX - 0xFFF, BALLOON_PAGE_SIZE as u32, F_WRITE, 0);
        for (pos, head) in [(0u16, 0u16), (1, 1), (2, 2), (3, 3)] {
            ram.publish_avail(pos, head);
        }

        let completions = b.process_queue(QUEUE_REPORTING, ram.slice(), &cfg).unwrap();
        assert_eq!(completions.len(), 4, "all chains complete");
        assert_eq!(ram.used_idx(), 4);
        assert_eq!(b.inflated_total(), 0, "no hostile range may be released");
    }

    #[test]
    fn reporting_ignores_read_only_descriptors() {
        let mut ram = TestRam::new(GPA_BASE);
        let mut b = reporting_device();
        let cfg = ram.cfg();

        ram.write_desc(0, GPA_BASE + DATA_OFF, BALLOON_PAGE_SIZE as u32, 0, 0);
        ram.publish_avail(0, 0);

        let completions = b.process_queue(QUEUE_REPORTING, ram.slice(), &cfg).unwrap();
        assert_eq!(completions, vec![(0, 0)]);
        assert_eq!(b.inflated_total(), 0);
    }

    #[test]
    fn reporting_queue_inert_when_feature_not_negotiated() {
        let mut ram = TestRam::new(GPA_BASE);
        let mut b = VirtioBalloon::new();
        // Driver acks everything except reporting.
        b.ack_features(VirtioBalloon::FEATURE_VERSION_1 | VIRTIO_BALLOON_F_DEFLATE_ON_OOM);
        let cfg = ram.cfg();

        ram.write_desc(0, GPA_BASE + DATA_OFF, BALLOON_PAGE_SIZE as u32, F_WRITE, 0);
        ram.publish_avail(0, 0);

        let completions = b.process_queue(QUEUE_REPORTING, ram.slice(), &cfg).unwrap();
        assert!(completions.is_empty(), "unnegotiated queue must be inert");
        assert_eq!(ram.used_idx(), 0);
    }

    #[test]
    fn advertises_reporting_feature() {
        let b = VirtioBalloon::new();
        assert!(b.features() & VIRTIO_BALLOON_F_REPORTING != 0);
    }

    #[test]
    fn process_queue_returns_empty_when_queue_not_ready() {
        let mut b = VirtioBalloon::new();
        let mut ram = vec![0u8; 4096];
        let qc = QueueConfig {
            desc_addr: 0,
            avail_addr: 0,
            used_addr: 0,
            size: 0,
            ready: false,
            gpa_base: 0,
        };
        let c = b.process_queue(QUEUE_INFLATE, &mut ram, &qc).unwrap();
        assert!(c.is_empty());
    }

    #[test]
    fn process_queue_ignores_unknown_queue_index() {
        let mut b = VirtioBalloon::new();
        let mut ram = vec![0u8; 4096];
        let qc = QueueConfig {
            desc_addr: 0,
            avail_addr: 0,
            used_addr: 0,
            size: 8,
            ready: true,
            gpa_base: 0,
        };
        let c = b.process_queue(42, &mut ram, &qc).unwrap();
        assert!(c.is_empty());
    }
}
