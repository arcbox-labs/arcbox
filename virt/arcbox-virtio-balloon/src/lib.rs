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
//! Not implemented (all optional per spec):
//! - Stats virtqueue (`VIRTIO_BALLOON_F_STATS_VQ`)
//! - Free-page hinting
//! - Page poisoning, reporting
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

/// Inflate queue index.
const QUEUE_INFLATE: u16 = 0;
/// Deflate queue index.
const QUEUE_DEFLATE: u16 = 1;

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
    /// Last processed `avail_idx` per queue (inflate, deflate). Wraps at
    /// u16 per VirtIO ring semantics.
    last_avail: [u16; 2],
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
    /// Advertises `VIRTIO_F_VERSION_1` and `VIRTIO_BALLOON_F_DEFLATE_ON_OOM`.
    pub fn new() -> Self {
        Self {
            features: Self::FEATURE_VERSION_1 | VIRTIO_BALLOON_F_DEFLATE_ON_OOM,
            active: false,
            last_avail: [0, 0],
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
        self.last_avail = [0, 0];
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
        if queue_idx != QUEUE_INFLATE && queue_idx != QUEUE_DEFLATE {
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
            // Each read-only descriptor carries a little-endian u32 PFN array.
            let mut chain_pages_handled = 0u32;
            for desc in &chain.descriptors {
                // Only read-only descriptors on the inflate queue carry PFNs.
                if desc.is_write() || queue_idx != QUEUE_INFLATE {
                    continue;
                }
                // Copy the PFN bytes out before madvise so the immutable borrow
                // on guest memory is released before we take the raw pointer.
                let Some(buf) = queue.mem().slice(desc.addr as usize, desc.len as usize) else {
                    continue;
                };
                let pfn_bytes = buf.to_vec();
                let ram_ptr = queue.mem().ptr();
                let ram_len = queue.mem().len();
                chain_pages_handled += handle_pfn_list(&pfn_bytes, ram_ptr, ram_len, gpa_base);
            }
            // Balloon completions write 0 bytes (nothing is written into the
            // descriptor buffer). Deflate just completes the descriptor —
            // MADV_DONTNEED pages re-fault naturally, so no explicit remap.
            queue.push_used(chain.head_idx, 0);
            completions.push((chain.head_idx, 0));
            if queue_idx == QUEUE_INFLATE && chain_pages_handled > 0 {
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
