//! Async block I/O worker for the HV (Hypervisor.framework) backend.
//!
//! Decouples VirtIO block I/O from the vCPU thread. The vCPU parses
//! descriptor chains and submits work items to a channel; a dedicated
//! worker thread performs the actual pread/pwrite and writes completions
//! directly to the guest's used ring, then triggers an IRQ.

use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

use crate::device::VirtioMmioState;
use crate::irq::Irq;

/// A single block I/O request parsed from a VirtIO descriptor chain.
pub struct BlkWorkItem {
    /// Descriptor head index — used as the ID in the used ring completion.
    pub head_idx: u16,
    /// Request type.
    pub request_type: BlkRequestType,
    /// Starting sector for read/write.
    pub sector: u64,
    /// Data buffers: (GPA, length, is_write_only).
    /// For reads: write-only buffers to fill with disk data.
    /// For writes: read-only buffers containing data to write to disk.
    pub buffers: Vec<(u64, u32, bool)>,
    /// GPA of the status byte (last byte of last writable descriptor).
    pub status_gpa: u64,
    /// Total byte length across all data descriptors (excluding header/status).
    pub total_data_len: u32,
    /// Used ring GPA (from current QueueConfig, may change after reset).
    pub used_addr: u64,
    /// Avail ring GPA (for EVENT_IDX used_event check).
    pub avail_addr: u64,
    /// Queue size.
    pub queue_size: u16,
}

/// Block request types matching VirtIO spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlkRequestType {
    Read,
    Write,
    Flush,
    GetId,
    /// DISCARD — deallocate (hole-punch) the listed ranges from the backing
    /// image. The range list travels in the read-only data descriptors.
    Discard,
    /// WRITE_ZEROES — make the listed ranges read back as zeros. Same range-list
    /// layout as DISCARD, but the device must guarantee the zero read.
    WriteZeroes,
}

// ============================================================================
// Guest Memory Writer
// ============================================================================

/// Safe wrapper around a raw guest memory pointer for the worker thread.
///
/// The pointer is valid for the lifetime of the VM. The worker only writes
/// to device-owned descriptor buffers and the used ring — regions that the
/// VirtIO spec guarantees the guest will not touch until completion.
///
/// All public methods accept guest physical addresses (GPAs) and translate
/// them to slice offsets by subtracting `gpa_base`.
pub struct GuestMemWriter {
    ptr: *mut u8,
    len: usize,
    /// GPA of the start of guest RAM. Subtracted from every GPA argument
    /// to obtain the host pointer offset within `ptr..ptr+len`.
    gpa_base: usize,
}

// SAFETY: The pointer originates from a VM-lifetime mmap. The worker
// thread writes only to descriptor buffers (device-owned) and the used
// ring (with Release fences). No concurrent mutation from the guest is
// possible for device-owned buffers per the VirtIO spec.
unsafe impl Send for GuestMemWriter {}
unsafe impl Sync for GuestMemWriter {}

impl GuestMemWriter {
    /// Creates a new writer from the DeviceManager's guest memory.
    ///
    /// `ptr` must point to the host mapping of guest RAM, which starts
    /// at GPA `gpa_base`. `len` is the size of that mapping in bytes.
    ///
    /// # Safety
    /// `ptr` must be valid for `len` bytes for the lifetime of the VM.
    pub unsafe fn new(ptr: *mut u8, len: usize, gpa_base: usize) -> Self {
        Self { ptr, len, gpa_base }
    }

    /// Translates a GPA to a host pointer offset, returning `None` if the
    /// GPA falls below `gpa_base` (invalid) or the range exceeds the
    /// mapped region.
    fn gpa_to_offset(&self, gpa: usize, access_len: usize) -> Option<usize> {
        let off = gpa.checked_sub(self.gpa_base)?;
        let end = off.checked_add(access_len)?;
        if end > self.len {
            return None;
        }
        Some(off)
    }

    /// Returns a mutable slice into guest memory at the given GPA range.
    ///
    /// # Safety
    /// Caller must ensure no other reference (mutable or shared) to the
    /// same GPA range exists for the lifetime of the returned slice.
    /// In practice, VirtIO descriptor ownership guarantees this — each
    /// descriptor buffer is exclusive to the device that owns it.
    #[allow(clippy::mut_from_ref)] // intentional: unsafe fn documents the aliasing contract
    pub unsafe fn slice_mut(&self, gpa: usize, len: usize) -> Option<&mut [u8]> {
        let off = self.gpa_to_offset(gpa, len)?;
        // SAFETY: `gpa_to_offset` validated bounds within the allocation.
        unsafe { Some(std::slice::from_raw_parts_mut(self.ptr.add(off), len)) }
    }

    pub fn slice(&self, gpa: usize, len: usize) -> Option<&[u8]> {
        let off = self.gpa_to_offset(gpa, len)?;
        // SAFETY: `gpa_to_offset` validated bounds within the allocation.
        unsafe { Some(std::slice::from_raw_parts(self.ptr.add(off), len)) }
    }

    pub(crate) fn read_u16(&self, gpa: usize) -> u16 {
        let Some(off) = self.gpa_to_offset(gpa, 2) else {
            return 0;
        };
        // SAFETY: `gpa_to_offset` validated bounds within the allocation.
        unsafe {
            let p = self.ptr.add(off);
            u16::from_le_bytes([*p, *p.add(1)])
        }
    }

    pub(crate) fn write_u16(&self, gpa: usize, val: u16) {
        let Some(off) = self.gpa_to_offset(gpa, 2) else {
            return;
        };
        let bytes = val.to_le_bytes();
        // SAFETY: `gpa_to_offset` validated bounds within the allocation.
        unsafe {
            let p = self.ptr.add(off);
            *p = bytes[0];
            *p.add(1) = bytes[1];
        }
    }

    pub(crate) fn write_u32(&self, gpa: usize, val: u32) {
        let Some(off) = self.gpa_to_offset(gpa, 4) else {
            return;
        };
        let bytes = val.to_le_bytes();
        // SAFETY: `gpa_to_offset` validated bounds within the allocation.
        unsafe {
            let p = self.ptr.add(off);
            *p = bytes[0];
            *p.add(1) = bytes[1];
            *p.add(2) = bytes[2];
            *p.add(3) = bytes[3];
        }
    }

    fn write_byte(&self, gpa: usize, val: u8) {
        let Some(off) = self.gpa_to_offset(gpa, 1) else {
            return;
        };
        // SAFETY: `gpa_to_offset` validated bounds within the allocation.
        unsafe { *self.ptr.add(off) = val };
    }
}

// ============================================================================
// Worker Context
// ============================================================================

/// Shared context for the block I/O worker thread.
pub struct BlkWorkerContext {
    /// Guest memory (VM-lifetime pointer). GPA translation is handled
    /// internally by `GuestMemWriter::gpa_to_offset`.
    pub guest_mem: GuestMemWriter,
    /// Raw fd for pread/pwrite (owned by VirtioBlock's File handle).
    pub raw_fd: i32,
    /// Block size (typically 512).
    pub blk_size: u32,
    /// Whether the device is read-only.
    pub read_only: bool,
    /// Device ID string for GetId requests.
    pub device_id: String,
    /// MMIO state for setting interrupt_status.
    pub mmio_state: Arc<RwLock<VirtioMmioState>>,
    /// IRQ trigger callback.
    pub irq_callback: Arc<dyn Fn(Irq, bool) -> crate::error::Result<()> + Send + Sync>,
    /// IRQ number for this block device.
    pub irq: Irq,
    /// VM shutdown flag.
    pub running: Arc<AtomicBool>,
    /// Shared flush barrier for multi-queue flush synchronization.
    pub flush_barrier: Arc<FlushBarrier>,
}

// SAFETY: All fields are either Send+Sync or raw pointers wrapped in
// GuestMemWriter which is Send+Sync.
unsafe impl Send for BlkWorkerContext {}

// ============================================================================
// Worker Loop
// ============================================================================

/// Main loop for the block I/O worker thread.
///
/// Receives work items from the vCPU thread, performs pread/pwrite,
/// writes completions to the used ring, and triggers IRQs.
pub fn blk_io_worker_loop(ctx: BlkWorkerContext, rx: std::sync::mpsc::Receiver<BlkWorkItem>) {
    tracing::info!(
        "blk-io-worker started (fd={}, blk_size={})",
        ctx.raw_fd,
        ctx.blk_size
    );

    while let Ok(first) = rx.recv() {
        if !ctx.running.load(Ordering::Relaxed) {
            break;
        }

        let used_addr = first.used_addr;
        let avail_addr = first.avail_addr;
        let queue_size = first.queue_size;
        let old_used = read_used_idx(&ctx.guest_mem, used_addr);

        // Collect batch: first item + up to 31 more from try_recv.
        let mut batch = Vec::with_capacity(32);
        batch.push(first);
        while batch.len() < 32 {
            match rx.try_recv() {
                Ok(item) => batch.push(item),
                Err(_) => break,
            }
        }

        // Process batch in segments split at Flush/GetId boundaries.
        // Within each segment, Read/Write items are sorted by (type, sector)
        // for merge-friendly ordering. Flush/GetId items are processed after
        // all preceding Read/Write items complete, preserving durability
        // semantics: a Flush must not overtake a Write from the same batch.
        process_batch(&ctx, &mut batch);

        let new_used = read_used_idx(&ctx.guest_mem, used_addr);

        if should_notify(&ctx.guest_mem, avail_addr, queue_size, old_used, new_used) {
            trigger_irq(&ctx);
        }

        if batch.len() > 1 {
            tracing::trace!("blk-io-worker: batch of {} items", batch.len());
        }
    }

    tracing::info!("blk-io-worker exiting");
}

/// Processes a batch of work items, splitting at Flush/GetId boundaries.
///
/// Within each segment of Read/Write items, we sort by (type, sector) for
/// merge-friendly ordering. Flush/GetId items execute only after all
/// preceding Read/Write items in the batch have completed, preserving the
/// guest's durability invariant: `[Write, Flush]` must not be reordered.
fn process_batch(ctx: &BlkWorkerContext, batch: &mut [BlkWorkItem]) {
    let mut start = 0;
    while start < batch.len() {
        // Find the end of this Read/Write segment (up to next Flush/GetId).
        let mut seg_end = start;
        while seg_end < batch.len()
            && matches!(
                batch[seg_end].request_type,
                BlkRequestType::Read | BlkRequestType::Write
            )
        {
            seg_end += 1;
        }

        // Sort the Read/Write segment by (type, sector) for merging.
        if seg_end - start > 1 {
            batch[start..seg_end].sort_unstable_by(|a, b| {
                let type_ord = |t: &BlkRequestType| match t {
                    BlkRequestType::Read => 0u8,
                    BlkRequestType::Write => 1,
                    _ => 2,
                };
                type_ord(&a.request_type)
                    .cmp(&type_ord(&b.request_type))
                    .then(a.sector.cmp(&b.sector))
            });
        }

        // Process the sorted Read/Write segment with merging.
        let mut i = start;
        while i < seg_end {
            let item = &batch[i];
            let mut end = i + 1;
            while end < seg_end
                && batch[end].request_type == item.request_type
                && batch[end].sector
                    == batch[end - 1].sector
                        + u64::from(batch[end - 1].total_data_len) / u64::from(ctx.blk_size)
            {
                end += 1;
            }
            if end == i + 1 {
                process_item(ctx, item);
            } else {
                process_merged(ctx, &batch[i..end]);
            }
            i = end;
        }

        // Process any Flush/GetId items that follow (one by one).
        start = seg_end;
        while start < batch.len()
            && !matches!(
                batch[start].request_type,
                BlkRequestType::Read | BlkRequestType::Write
            )
        {
            process_item(ctx, &batch[start]);
            start += 1;
        }
    }
}

/// Processes a single block I/O work item.
fn process_item(ctx: &BlkWorkerContext, item: &BlkWorkItem) {
    // WRITE_ZEROES mutates data like a write, so a following Flush must wait for
    // it. DISCARD is advisory and excluded from the flush barrier.
    let is_io = matches!(
        item.request_type,
        BlkRequestType::Read | BlkRequestType::Write | BlkRequestType::WriteZeroes
    );

    if is_io {
        ctx.flush_barrier.in_flight.fetch_add(1, Ordering::Relaxed);
    }

    let status = match item.request_type {
        BlkRequestType::Read => process_read(ctx, item),
        BlkRequestType::Write => process_write(ctx, item),
        BlkRequestType::Flush => {
            // Wait for all in-flight I/O across all queues to complete.
            // This is a spin-wait; in practice flush is rare and in-flight
            // drains quickly once no new I/O is submitted.
            while ctx.flush_barrier.in_flight.load(Ordering::Acquire) > 0 {
                std::hint::spin_loop();
            }
            process_flush(ctx)
        }
        BlkRequestType::GetId => process_get_id(ctx, item),
        BlkRequestType::Discard => process_discard(ctx, item),
        BlkRequestType::WriteZeroes => process_write_zeroes(ctx, item),
    };

    if is_io {
        ctx.flush_barrier.in_flight.fetch_sub(1, Ordering::Release);
    }

    // Write status byte.
    ctx.guest_mem.write_byte(item.status_gpa as usize, status);

    // Compute total bytes for the used ring entry.
    let total_bytes = if status == 0 {
        item.total_data_len + 1 // data + status byte
    } else {
        1 // just status byte
    };

    // Write used ring entry.
    write_used_entry(
        &ctx.guest_mem,
        item.used_addr,
        item.queue_size,
        item.head_idx,
        total_bytes,
    );
}

/// Reads using preadv — single syscall for scatter-gather buffers.
fn process_read(ctx: &BlkWorkerContext, item: &BlkWorkItem) -> u8 {
    let mut iovecs: Vec<libc::iovec> = Vec::new();
    for &(gpa, len, is_write) in &item.buffers {
        if !is_write || len <= 1 {
            continue;
        }
        // SAFETY: VirtIO descriptor buffers are device-owned — no concurrent access
        // to the same GPA range from other workers or the guest.
        let buf = unsafe { ctx.guest_mem.slice_mut(gpa as usize, len as usize) };
        let Some(buf) = buf else {
            tracing::warn!("blk read: GPA {:#x} len {} out of bounds", gpa, len);
            return 1;
        };
        iovecs.push(libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        });
    }
    if iovecs.is_empty() {
        return 0;
    }
    #[allow(clippy::cast_possible_wrap)]
    let offset = (item.sector * u64::from(ctx.blk_size)) as libc::off_t;
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let n = unsafe { libc::preadv(ctx.raw_fd, iovecs.as_ptr(), iovecs.len() as i32, offset) };
    if n < 0 {
        tracing::warn!(
            "blk preadv failed at sector {}: {}",
            item.sector,
            std::io::Error::last_os_error()
        );
        return 1;
    }
    0
}

/// Writes using pwritev — single syscall for scatter-gather buffers.
fn process_write(ctx: &BlkWorkerContext, item: &BlkWorkItem) -> u8 {
    if ctx.read_only {
        return 1;
    }
    let mut iovecs: Vec<libc::iovec> = Vec::new();
    for &(gpa, len, is_write) in &item.buffers {
        if is_write {
            continue;
        }
        let Some(buf) = ctx.guest_mem.slice(gpa as usize, len as usize) else {
            tracing::warn!("blk write: GPA {:#x} len {} out of bounds", gpa, len);
            return 1;
        };
        iovecs.push(libc::iovec {
            iov_base: buf.as_ptr().cast_mut().cast(),
            iov_len: buf.len(),
        });
    }
    if iovecs.is_empty() {
        return 0;
    }
    #[allow(clippy::cast_possible_wrap)]
    let offset = (item.sector * u64::from(ctx.blk_size)) as libc::off_t;
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let n = unsafe { libc::pwritev(ctx.raw_fd, iovecs.as_ptr(), iovecs.len() as i32, offset) };
    if n < 0 {
        tracing::warn!(
            "blk pwritev failed at sector {}: {}",
            item.sector,
            std::io::Error::last_os_error()
        );
        return 1;
    }
    0
}

/// Processes a merged run of same-type items with contiguous sectors
/// using a single preadv/pwritev syscall. Each item still gets its own
/// used ring completion.
fn process_merged(ctx: &BlkWorkerContext, items: &[BlkWorkItem]) {
    let is_read = items[0].request_type == BlkRequestType::Read;
    let start_sector = items[0].sector;

    // Track in-flight for all items in the merge group.
    ctx.flush_barrier
        .in_flight
        .fetch_add(items.len() as u32, Ordering::Relaxed);

    // Build combined iovec from all items.
    let mut iovecs: Vec<libc::iovec> = Vec::new();
    for item in items {
        for &(gpa, len, is_write_flag) in &item.buffers {
            // For reads: use write-only descriptors. For writes: use read-only.
            let want = if is_read {
                is_write_flag
            } else {
                !is_write_flag
            };
            if !want || len <= 1 {
                continue;
            }
            if is_read {
                // SAFETY: VirtIO descriptor buffers are device-owned.
                if let Some(buf) = unsafe { ctx.guest_mem.slice_mut(gpa as usize, len as usize) } {
                    iovecs.push(libc::iovec {
                        iov_base: buf.as_mut_ptr().cast(),
                        iov_len: buf.len(),
                    });
                }
            } else if let Some(buf) = ctx.guest_mem.slice(gpa as usize, len as usize) {
                iovecs.push(libc::iovec {
                    iov_base: buf.as_ptr().cast_mut().cast(),
                    iov_len: buf.len(),
                });
            }
        }
    }

    // Single merged I/O syscall.
    #[allow(clippy::cast_possible_wrap)]
    let offset = (start_sector * u64::from(ctx.blk_size)) as libc::off_t;
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let n = if is_read {
        unsafe { libc::preadv(ctx.raw_fd, iovecs.as_ptr(), iovecs.len() as i32, offset) }
    } else {
        unsafe { libc::pwritev(ctx.raw_fd, iovecs.as_ptr(), iovecs.len() as i32, offset) }
    };

    let status: u8 = if n < 0 {
        tracing::warn!(
            "blk merged {} failed at sector {}: {}",
            if is_read { "preadv" } else { "pwritev" },
            start_sector,
            std::io::Error::last_os_error()
        );
        1
    } else {
        0
    };

    // Write individual used ring entries for each item.
    for item in items {
        ctx.guest_mem.write_byte(item.status_gpa as usize, status);
        let total_bytes = if status == 0 {
            item.total_data_len + 1
        } else {
            1
        };
        write_used_entry(
            &ctx.guest_mem,
            item.used_addr,
            item.queue_size,
            item.head_idx,
            total_bytes,
        );
    }

    ctx.flush_barrier
        .in_flight
        .fetch_sub(items.len() as u32, Ordering::Release);

    tracing::trace!(
        "blk merged {} items: sector {}..+{}, {} iovecs, {} bytes",
        items.len(),
        start_sector,
        items.last().map_or(0, |i| i.sector
            + u64::from(i.total_data_len) / u64::from(ctx.blk_size))
            - start_sector,
        iovecs.len(),
        n,
    );
}

fn process_flush(ctx: &BlkWorkerContext) -> u8 {
    let ret = unsafe { libc::fsync(ctx.raw_fd) };
    if ret < 0 {
        tracing::warn!("blk fsync failed: {}", std::io::Error::last_os_error());
        1
    } else {
        0
    }
}

fn process_get_id(ctx: &BlkWorkerContext, item: &BlkWorkItem) -> u8 {
    let id_bytes = ctx.device_id.as_bytes();
    for &(gpa, len, is_write) in &item.buffers {
        if !is_write || len <= 1 {
            continue;
        }
        // SAFETY: VirtIO descriptor buffers are device-owned.
        let buf = unsafe { ctx.guest_mem.slice_mut(gpa as usize, len as usize) };
        if let Some(buf) = buf {
            let copy_len = id_bytes.len().min(buf.len());
            buf[..copy_len].copy_from_slice(&id_bytes[..copy_len]);
        }
        break;
    }
    0
}

/// DISCARD — punch holes for the listed ranges so the host reclaims disk for
/// blocks the guest freed via `fstrim` / `discard=async`. DISCARD is advisory
/// under the virtio-blk spec, so a read-only device or a punch failure is
/// reported as a successful no-op rather than an I/O error.
fn process_discard(ctx: &BlkWorkerContext, item: &BlkWorkItem) -> u8 {
    if !ctx.read_only {
        punch_discard_ranges(&ctx.guest_mem, ctx.raw_fd, ctx.blk_size, &item.buffers);
    }
    0 // VIRTIO_BLK_S_OK
}

/// WRITE_ZEROES — make the listed ranges read back as zeros. Same range-list
/// layout as DISCARD; unlike DISCARD it must be honored, so a read-only device
/// is an I/O error (and we don't advertise the feature for one).
fn process_write_zeroes(ctx: &BlkWorkerContext, item: &BlkWorkItem) -> u8 {
    if ctx.read_only {
        return 1; // VIRTIO_BLK_S_IOERR
    }
    zero_ranges(&ctx.guest_mem, ctx.raw_fd, ctx.blk_size, &item.buffers)
}

/// Calls `f(start_byte, end_byte)` for each range in a DISCARD / WRITE_ZEROES
/// request's read-only payload descriptors: 16-byte entries of (sector le64,
/// num_sectors le32, flags le32). The device-writable 1-byte status descriptor
/// is skipped.
fn for_each_range(
    guest_mem: &GuestMemWriter,
    blk_size: u32,
    buffers: &[(u64, u32, bool)],
    mut f: impl FnMut(u64, u64),
) {
    let block_size = u64::from(blk_size);
    for &(gpa, len, is_write) in buffers {
        if is_write {
            continue;
        }
        let Some(bytes) = guest_mem.slice(gpa as usize, len as usize) else {
            continue;
        };
        for entry in bytes.chunks_exact(16) {
            let sector = u64::from_le_bytes(entry[0..8].try_into().unwrap());
            let num_sectors = u32::from_le_bytes(entry[8..12].try_into().unwrap());
            // entry[12..16] = flags (UNMAP/reserved); ignored.
            let start = sector * block_size;
            let end = start + u64::from(num_sectors) * block_size;
            f(start, end);
        }
    }
}

/// Punches holes for every DISCARD range. Factored out so it can be tested
/// without a full `BlkWorkerContext`.
fn punch_discard_ranges(
    guest_mem: &GuestMemWriter,
    raw_fd: i32,
    blk_size: u32,
    buffers: &[(u64, u32, bool)],
) {
    use arcbox_virtio::blk::{aligned_punch_range, punch_hole};

    for_each_range(guest_mem, blk_size, buffers, |start, end| {
        if let Some((offset, hole_len)) = aligned_punch_range(start, end) {
            if let Err(e) = punch_hole(raw_fd, offset, hole_len) {
                tracing::warn!(
                    start,
                    end,
                    error = %e,
                    "discard hole-punch failed (HV worker); range left allocated"
                );
            }
        }
    });
}

/// Zeroes every WRITE_ZEROES range via the shared sparse-aware primitive
/// (hole-punch the aligned interior, write zeros on the edges). Returns the
/// virtio status (0 = OK, 1 = an I/O error occurred on some range).
fn zero_ranges(
    guest_mem: &GuestMemWriter,
    raw_fd: i32,
    blk_size: u32,
    buffers: &[(u64, u32, bool)],
) -> u8 {
    let mut status = 0u8;
    for_each_range(guest_mem, blk_size, buffers, |start, end| {
        if let Err(e) = arcbox_virtio::blk::zero_range(raw_fd, start, end) {
            tracing::warn!(start, end, error = %e, "write_zeroes failed (HV worker)");
            status = 1;
        }
    });
    status
}

// Shared VirtIO queue helpers — extracted to virtqueue_util.rs.
use crate::virtqueue_util::{read_used_idx, should_notify, write_used_entry};

fn trigger_irq(ctx: &BlkWorkerContext) {
    // Set interrupt_status on MMIO state.
    if let Ok(mut s) = ctx.mmio_state.write() {
        s.trigger_interrupt(1); // INT_VRING
    }
    // Fire GIC SPI.
    let _ = (ctx.irq_callback)(ctx.irq, true);
}

// ============================================================================
// Per-device async state (stored on DeviceManager)
// ============================================================================

/// Per-queue I/O worker handle.
pub struct BlkQueueWorker {
    pub tx: std::sync::mpsc::Sender<BlkWorkItem>,
    pub last_avail_idx: AtomicU16,
}

/// Per-block-device async I/O state. Holds one worker per queue.
pub struct BlkWorkerHandle {
    /// Workers indexed by queue_idx.
    pub queues: Vec<BlkQueueWorker>,
}

impl BlkWorkerHandle {
    /// Returns the worker for a given queue index, or None.
    pub fn get_queue(&self, queue_idx: u16) -> Option<&BlkQueueWorker> {
        self.queues.get(queue_idx as usize)
    }

    /// Parses available descriptors from the virtqueue and dispatches them
    /// as `BlkWorkItem`s to the worker thread.
    ///
    /// Returns `true` if any items were dispatched.
    pub fn dispatch(
        &self,
        memory: &mut [u8],
        qcfg: &arcbox_virtio::QueueConfig,
        queue_idx: u16,
    ) -> bool {
        let Some(worker) = self.get_queue(queue_idx) else {
            return false;
        };

        if !qcfg.ready || qcfg.size == 0 {
            return false;
        }

        // Translate GPAs to slice offsets (checked against ram base).
        let gpa_base = qcfg.gpa_base as usize;
        let Some(desc_addr) = (qcfg.desc_addr as usize).checked_sub(gpa_base) else {
            tracing::warn!(
                "blk dispatch: desc GPA {:#x} below ram base {:#x}",
                qcfg.desc_addr,
                gpa_base
            );
            return false;
        };
        let Some(avail_addr) = (qcfg.avail_addr as usize).checked_sub(gpa_base) else {
            tracing::warn!(
                "blk dispatch: avail GPA {:#x} below ram base {:#x}",
                qcfg.avail_addr,
                gpa_base
            );
            return false;
        };
        let Some(used_addr) = (qcfg.used_addr as usize).checked_sub(gpa_base) else {
            tracing::warn!(
                "blk dispatch: used GPA {:#x} below ram base {:#x}",
                qcfg.used_addr,
                gpa_base
            );
            return false;
        };
        let q_size = qcfg.size as usize;

        if avail_addr + 4 > memory.len() {
            return false;
        }
        let avail_idx = u16::from_le_bytes([memory[avail_addr + 2], memory[avail_addr + 3]]);

        let last_avail = worker.last_avail_idx.load(Ordering::Relaxed);
        let mut current = last_avail;
        let mut dispatched = false;

        while current != avail_idx {
            let ring_off = avail_addr + 4 + 2 * ((current as usize) % q_size);
            if ring_off + 2 > memory.len() {
                break;
            }
            let head_idx = u16::from_le_bytes([memory[ring_off], memory[ring_off + 1]]);

            // Walk descriptor chain.
            let mut buffers = Vec::new();
            let mut status_gpa: u64 = 0;
            let mut total_data_len: u32 = 0;
            let mut request_type = BlkRequestType::Read;
            let mut sector: u64 = 0;
            let mut first_desc = true;
            let mut idx = head_idx as usize;

            loop {
                let d_off = desc_addr + idx * 16;
                if d_off + 16 > memory.len() {
                    break;
                }
                let addr = u64::from_le_bytes(memory[d_off..d_off + 8].try_into().unwrap());
                let len = u32::from_le_bytes(memory[d_off + 8..d_off + 12].try_into().unwrap());
                let flags = u16::from_le_bytes(memory[d_off + 12..d_off + 14].try_into().unwrap());
                let next = u16::from_le_bytes(memory[d_off + 14..d_off + 16].try_into().unwrap());
                let is_write = flags & 2 != 0;

                if first_desc {
                    // First descriptor = block request header (16 bytes).
                    first_desc = false;
                    if len >= 16 {
                        let Some(hdr_off) = (addr as usize).checked_sub(gpa_base) else {
                            break;
                        };
                        if hdr_off + 16 <= memory.len() {
                            let req_type = u32::from_le_bytes(
                                memory[hdr_off..hdr_off + 4].try_into().unwrap(),
                            );
                            sector = u64::from_le_bytes(
                                memory[hdr_off + 8..hdr_off + 16].try_into().unwrap(),
                            );
                            request_type = match req_type {
                                0 => BlkRequestType::Read,
                                1 => BlkRequestType::Write,
                                4 => BlkRequestType::Flush,
                                8 => BlkRequestType::GetId,
                                11 => BlkRequestType::Discard,
                                13 => BlkRequestType::WriteZeroes,
                                _ => BlkRequestType::Read,
                            };
                        }
                    }
                } else {
                    buffers.push((addr, len, is_write));
                    // Last writable descriptor's last byte = status byte.
                    if is_write && len > 0 {
                        status_gpa = addr + u64::from(len) - 1;
                    }
                    // Count data bytes (exclude 1-byte status descriptor).
                    if len > 1 {
                        total_data_len += len;
                    }
                }

                if flags & 1 == 0 {
                    break; // No NEXT flag.
                }
                idx = next as usize;
                if idx >= q_size {
                    break;
                }
            }

            let item = BlkWorkItem {
                head_idx,
                request_type,
                sector,
                buffers,
                status_gpa,
                total_data_len,
                used_addr: qcfg.used_addr,
                avail_addr: qcfg.avail_addr,
                queue_size: qcfg.size,
            };

            if worker.tx.send(item).is_err() {
                tracing::warn!("blk worker channel closed, falling back to sync");
                break;
            }
            dispatched = true;
            current = current.wrapping_add(1);
        }

        worker.last_avail_idx.store(current, Ordering::Relaxed);

        // Update avail_event for EVENT_IDX.
        if dispatched {
            let avail_event_off = used_addr + 4 + q_size * 8;
            if avail_event_off + 2 <= memory.len() {
                memory[avail_event_off..avail_event_off + 2]
                    .copy_from_slice(&current.to_le_bytes());
            }
        }

        dispatched
    }
}

/// Shared flush barrier across all queues of a device.
/// Used to implement VIRTIO_BLK_T_FLUSH correctly with multi-queue:
/// flush must wait for all in-flight I/O across all queues to complete.
pub struct FlushBarrier {
    pub in_flight: AtomicU32,
}

impl Default for FlushBarrier {
    fn default() -> Self {
        Self {
            in_flight: AtomicU32::new(0),
        }
    }
}

impl FlushBarrier {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The HV worker's DISCARD path must actually reclaim host blocks — this is
    /// the path the macOS backend uses, where DISCARD previously fell through to
    /// a no-op `Read`.
    #[cfg(unix)]
    #[test]
    fn punch_discard_ranges_reclaims_blocks() {
        use std::io::Write;
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::AsRawFd;

        // Backing file with 1 MiB of real (non-zero) data.
        let mut temp = tempfile::NamedTempFile::new().unwrap();
        temp.write_all(&vec![0xEEu8; 1024 * 1024]).unwrap();
        temp.as_file().sync_all().unwrap();
        let fd = temp.as_file().as_raw_fd();

        // Guest memory holding one 16-byte discard entry for sectors [0, 2048)
        // — the whole 1 MiB — followed by where the 1-byte status would live.
        let mut mem = vec![0u8; 4096];
        mem[0..8].copy_from_slice(&0u64.to_le_bytes()); // sector
        mem[8..12].copy_from_slice(&2048u32.to_le_bytes()); // num_sectors (1 MiB)
        mem[12..16].copy_from_slice(&0u32.to_le_bytes()); // flags
        // SAFETY: `mem` outlives `gm`; gpa_base 0 means gpa == buffer offset.
        let gm = unsafe { GuestMemWriter::new(mem.as_mut_ptr(), mem.len(), 0) };

        // Descriptors: the read-only range list, then the write-only status byte
        // (which must be skipped, not parsed as a range).
        let buffers = vec![(0u64, 16u32, false), (16u64, 1u32, true)];
        punch_discard_ranges(&gm, fd, 512, &buffers);
        temp.as_file().sync_all().unwrap();

        let after = std::fs::metadata(temp.path()).unwrap().blocks() * 512;
        assert!(
            after < 64 * 1024,
            "worker discard should have punched the backing file, still {after} allocated"
        );
    }

    /// The HV worker's WRITE_ZEROES path must actually zero the target sectors —
    /// previously it fell through to a no-op `Read` and silently left stale data.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::cast_possible_wrap)] // pread-return comparison on a small test buffer
    fn zero_ranges_zeroes_backing_file() {
        use std::io::Write;
        use std::os::unix::io::AsRawFd;

        let mut temp = tempfile::NamedTempFile::new().unwrap();
        temp.write_all(&vec![0xCDu8; 16 * 1024]).unwrap();
        temp.as_file().sync_all().unwrap();
        let fd = temp.as_file().as_raw_fd();

        // One write-zeroes entry for sectors [0, 16) — the first 8 KiB.
        let mut mem = vec![0u8; 4096];
        mem[0..8].copy_from_slice(&0u64.to_le_bytes()); // sector
        mem[8..12].copy_from_slice(&16u32.to_le_bytes()); // num_sectors (8 KiB)
        mem[12..16].copy_from_slice(&0u32.to_le_bytes()); // flags
        // SAFETY: `mem` outlives `gm`; gpa_base 0 means gpa == buffer offset.
        let gm = unsafe { GuestMemWriter::new(mem.as_mut_ptr(), mem.len(), 0) };
        let buffers = vec![(0u64, 16u32, false), (16u64, 1u32, true)];

        assert_eq!(zero_ranges(&gm, fd, 512, &buffers), 0);
        temp.as_file().sync_all().unwrap();

        // The first 8 KiB now reads back as zeros; the rest is untouched.
        let mut buf = vec![0xFFu8; 8 * 1024];
        // SAFETY: reading our own file into a sized buffer.
        let n = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        assert_eq!(n, buf.len() as isize);
        assert!(
            buf.iter().all(|&b| b == 0),
            "write_zeroes range must read as zeros"
        );

        let mut rest = [0xFFu8; 512];
        // SAFETY: reading our own file into a sized buffer.
        let n = unsafe { libc::pread(fd, rest.as_mut_ptr().cast(), rest.len(), 8 * 1024) };
        assert_eq!(n, 512);
        assert!(
            rest.iter().all(|&b| b == 0xCD),
            "data past the range is intact"
        );
    }
}
