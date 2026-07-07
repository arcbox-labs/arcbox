//! Async block I/O worker for the HV (Hypervisor.framework) backend.
//!
//! Decouples VirtIO block I/O from the vCPU thread with a doorbell model:
//! on QUEUE_NOTIFY the vCPU only rings the owning worker's doorbell. The
//! per-queue worker consumes the avail ring, parses descriptor chains,
//! performs the pread/pwrite, publishes completions to the used ring, and
//! triggers the IRQ — a single thread owns the whole queue (the
//! libkrun/virtio-queue model).

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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
}

/// Block request types matching VirtIO spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlkRequestType {
    Read,
    Write,
    Flush,
    GetId,
    Unsupported,
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

    /// Raw host pointer to the start of the guest RAM mapping.
    pub(crate) fn ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Total length of the guest RAM mapping in bytes.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// GPA that maps to the start of the host mapping.
    pub(crate) fn gpa_base(&self) -> usize {
        self.gpa_base
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
    /// Device capacity in `blk_size` sectors. I/O and range requests past
    /// this bound are rejected instead of growing the backing file.
    pub capacity_sectors: u64,
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
    /// Force-exits all vCPUs from `hv_vcpu_run`. Injecting the completion IRQ
    /// alone does not wake a WFI-parked vCPU on this HV backend — the guest only
    /// services it on the next VM exit. A guest blocked in WFI waiting for this
    /// very block read (e.g. an early-boot fault on the EROFS rootfs) would
    /// otherwise stall until an unrelated exit. Mirrors the net/vsock RX workers
    /// (ABX-367).
    pub exit_vcpus: Arc<dyn Fn() + Send + Sync>,
    /// Index of the virtqueue this worker owns. The worker reads the queue's
    /// live config from `mmio_state[queue_idx]` each drain.
    pub queue_idx: u16,
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
pub fn blk_io_worker_loop(ctx: BlkWorkerContext, doorbell: std::sync::mpsc::Receiver<()>) {
    tracing::info!(
        "blk-io worker started (fd={}, q={})",
        ctx.raw_fd,
        ctx.queue_idx
    );

    // The avail cursor persists across kicks. This worker is the SOLE owner of
    // its queue — it consumes avail, performs I/O, publishes used, and raises
    // the IRQ, all in one thread (the libkrun/virtio-queue model). The vCPU only
    // rings the doorbell on QUEUE_NOTIFY; it no longer touches the ring.
    let mut last_avail: u16 = 0;
    while doorbell.recv().is_ok() {
        if !ctx.running.load(Ordering::Relaxed) {
            break;
        }
        // Coalesce kicks that piled up while we were busy: one drain handles
        // them all, and a spurious extra wake just finds the ring empty.
        while doorbell.try_recv().is_ok() {}
        drain_queue(&ctx, &mut last_avail);
    }

    tracing::info!("blk-io worker exiting (q={})", ctx.queue_idx);
}

/// Drains this worker's virtqueue end to end: pop each available chain, perform
/// its I/O, publish the completion, and interrupt the guest — wrapped in the
/// virtio-queue/libkrun `process → enable_notification(recheck) → loop` pattern.
///
/// Owning both halves of the queue in one thread (rather than splitting
/// avail-consume onto the vCPU and completion onto a separate worker) is what
/// closes the EVENT_IDX kick-suppression race that wedged guest page-in
/// (`folio_wait_bit_common`) on cold boot — ABX-386.
fn drain_queue(ctx: &BlkWorkerContext, last_avail: &mut u16) {
    let qi = ctx.queue_idx as usize;
    let cfg = {
        let Ok(mmio) = ctx.mmio_state.read() else {
            return;
        };
        if qi >= mmio.queue_ready.len() || !mmio.queue_ready[qi] || mmio.queue_num[qi] == 0 {
            return;
        }
        arcbox_virtio::QueueConfig {
            desc_addr: mmio.queue_desc[qi],
            avail_addr: mmio.queue_driver[qi],
            used_addr: mmio.queue_device[qi],
            size: mmio.queue_num[qi],
            ready: true,
            gpa_base: ctx.guest_mem.gpa_base() as u64,
        }
    };

    // SAFETY: the VM-lifetime guest RAM mapping. This worker is the sole writer
    // of the queue's used ring and only touches device-owned descriptor buffers.
    let mem = std::sync::Arc::new(unsafe {
        arcbox_virtio::GuestMemWriter::new(
            ctx.guest_mem.ptr(),
            ctx.guest_mem.len(),
            ctx.guest_mem.gpa_base(),
        )
    });
    let mut queue = arcbox_virtio::SplitQueue::new(mem, ctx.queue_idx, &cfg, true);
    queue.set_last_avail_idx(*last_avail);

    loop {
        while let Some(chain) = queue.pop_avail() {
            let (head, len) = match parse_chain(ctx, &chain) {
                Some(item) => process_item(ctx, &item),
                // Malformed chain: complete it (len 0) so the descriptor isn't
                // leaked, rather than wedging the ring.
                None => (chain.head_idx, 0),
            };
            if queue.push_used(head, len) {
                trigger_irq(ctx);
            }
        }
        // Re-arm notifications and re-check: loop if the guest added more (and
        // suppressed its kick) while we were draining.
        if !queue.enable_notification() {
            break;
        }
    }

    *last_avail = queue.last_avail_idx();
}

/// Parses a block request from an available descriptor chain. The first
/// descriptor is the 16-byte request header (type + sector); the remaining
/// descriptors are data buffers, with the last writable descriptor's final byte
/// reserved for the status code.
fn parse_chain(ctx: &BlkWorkerContext, chain: &arcbox_virtio::DescChain) -> Option<BlkWorkItem> {
    let header = chain.descriptors.first()?;
    let hdr = ctx.guest_mem.slice(header.addr as usize, 16)?;
    let req_type = u32::from_le_bytes(hdr[0..4].try_into().ok()?);
    let sector = u64::from_le_bytes(hdr[8..16].try_into().ok()?);
    let request_type = match req_type {
        0 => BlkRequestType::Read,
        1 => BlkRequestType::Write,
        4 => BlkRequestType::Flush,
        8 => BlkRequestType::GetId,
        11 => BlkRequestType::Discard,
        13 => BlkRequestType::WriteZeroes,
        _ => BlkRequestType::Unsupported,
    };

    let mut buffers = Vec::new();
    let mut status_gpa = 0u64;
    let mut total_data_len = 0u32;
    for desc in chain.descriptors.iter().skip(1) {
        let is_write = desc.is_write();
        buffers.push((desc.addr, desc.len, is_write));
        if is_write && desc.len > 0 {
            status_gpa = desc.addr + u64::from(desc.len) - 1;
        }
        if desc.len > 1 {
            total_data_len += desc.len;
        }
    }

    Some(BlkWorkItem {
        head_idx: chain.head_idx,
        request_type,
        sector,
        buffers,
        status_gpa,
        total_data_len,
    })
}

/// Processes a single block I/O work item, returning its `(head_idx, bytes)`
/// used-ring completion.
fn process_item(ctx: &BlkWorkerContext, item: &BlkWorkItem) -> (u16, u32) {
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
        BlkRequestType::Unsupported => 2, // VIRTIO_BLK_S_UNSUPP
        BlkRequestType::Discard => process_discard(ctx, item),
        BlkRequestType::WriteZeroes => process_write_zeroes(ctx, item),
    };

    if is_io {
        ctx.flush_barrier.in_flight.fetch_sub(1, Ordering::Release);
    }

    // Write status byte.
    ctx.guest_mem.write_byte(item.status_gpa as usize, status);

    // Compute total bytes for the used ring entry; the worker loop publishes it.
    let total_bytes = if status == 0 {
        item.total_data_len + 1 // data + status byte
    } else {
        1 // just status byte
    };
    (item.head_idx, total_bytes)
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
    let expected_len = iovecs.iter().map(|iov| iov.iov_len).sum::<usize>();
    let Ok((byte_offset, _)) = arcbox_virtio::blk::checked_io_byte_range(
        item.sector,
        expected_len,
        ctx.blk_size,
        ctx.capacity_sectors,
    ) else {
        tracing::warn!("blk read: range out of capacity at sector {}", item.sector);
        return 1;
    };
    #[allow(clippy::cast_possible_wrap)]
    let offset = byte_offset as libc::off_t;
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
    if n as usize != expected_len {
        tracing::warn!(
            "blk preadv short read at sector {}: {} < {}",
            item.sector,
            n,
            expected_len
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
    let expected_len = iovecs.iter().map(|iov| iov.iov_len).sum::<usize>();
    let Ok((byte_offset, _)) = arcbox_virtio::blk::checked_io_byte_range(
        item.sector,
        expected_len,
        ctx.blk_size,
        ctx.capacity_sectors,
    ) else {
        tracing::warn!("blk write: range out of capacity at sector {}", item.sector);
        return 1;
    };
    #[allow(clippy::cast_possible_wrap)]
    let offset = byte_offset as libc::off_t;
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
    if n as usize != expected_len {
        tracing::warn!(
            "blk pwritev short write at sector {}: {} < {}",
            item.sector,
            n,
            expected_len
        );
        return 1;
    }
    0
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
        return punch_discard_ranges(
            &ctx.guest_mem,
            ctx.raw_fd,
            ctx.blk_size,
            ctx.capacity_sectors,
            &item.buffers,
        );
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
    zero_ranges(
        &ctx.guest_mem,
        ctx.raw_fd,
        ctx.blk_size,
        ctx.capacity_sectors,
        &item.buffers,
    )
}

/// Parses a DISCARD / WRITE_ZEROES request's read-only payload descriptors. The
/// device-writable 1-byte status descriptor is skipped. Payload descriptors are
/// concatenated before parsing so legal scatter-gather layouts with a 16-byte
/// range split across descriptors behave exactly like the generic path.
fn parse_ranges_from_buffers(
    guest_mem: &GuestMemWriter,
    buffers: &[(u64, u32, bool)],
    log_context: &str,
) -> Result<Vec<arcbox_virtio::blk::DiscardWriteZeroesRange>, ()> {
    let mut payload = Vec::new();
    for &(gpa, len, is_write) in buffers {
        if is_write {
            continue;
        }
        let Some(bytes) = guest_mem.slice(gpa as usize, len as usize) else {
            tracing::warn!("{log_context}: range payload GPA {gpa:#x} len {len} out of bounds");
            return Err(());
        };
        payload.extend_from_slice(bytes);
    }
    arcbox_virtio::blk::parse_range_list(&payload).map_err(|e| {
        tracing::warn!(error = %e, "{log_context}: malformed range list");
    })
}

fn checked_range_bytes(
    range: arcbox_virtio::blk::DiscardWriteZeroesRange,
    blk_size: u32,
    capacity_sectors: u64,
    max_sectors: u32,
    log_context: &str,
) -> Result<(u64, u64), ()> {
    if range.num_sectors > max_sectors {
        tracing::warn!(
            sector = range.sector,
            num_sectors = range.num_sectors,
            max_sectors,
            "{log_context}: range exceeds advertised maximum"
        );
        return Err(());
    }
    range
        .checked_byte_range(blk_size, capacity_sectors)
        .map_err(|e| {
            tracing::warn!(sector = range.sector, num_sectors = range.num_sectors, error = %e, "{log_context}: invalid range");
        })
}

fn validate_discard_flags(
    range: arcbox_virtio::blk::DiscardWriteZeroesRange,
    log_context: &str,
) -> Result<(), ()> {
    if range.flags != 0 {
        tracing::warn!(
            flags = range.flags,
            "{log_context}: discard reserved flags set"
        );
        return Err(());
    }
    Ok(())
}

fn validate_write_zeroes_flags(
    range: arcbox_virtio::blk::DiscardWriteZeroesRange,
    log_context: &str,
) -> Result<(), ()> {
    if range.flags & !arcbox_virtio::blk::WRITE_ZEROES_FLAG_UNMAP != 0 {
        tracing::warn!(
            flags = range.flags,
            "{log_context}: write_zeroes reserved flags set"
        );
        return Err(());
    }
    Ok(())
}

fn discard_byte_ranges(
    guest_mem: &GuestMemWriter,
    blk_size: u32,
    capacity_sectors: u64,
    buffers: &[(u64, u32, bool)],
) -> Result<Vec<(u64, u64)>, ()> {
    let ranges = parse_ranges_from_buffers(guest_mem, buffers, "discard")?;
    let mut byte_ranges = Vec::with_capacity(ranges.len());
    for range in ranges {
        validate_discard_flags(range, "discard")?;
        byte_ranges.push(checked_range_bytes(
            range,
            blk_size,
            capacity_sectors,
            arcbox_virtio::blk::VirtioBlock::MAX_DISCARD_SECTORS,
            "discard",
        )?);
    }
    Ok(byte_ranges)
}

fn write_zeroes_byte_ranges(
    guest_mem: &GuestMemWriter,
    blk_size: u32,
    capacity_sectors: u64,
    buffers: &[(u64, u32, bool)],
) -> Result<Vec<(u64, u64)>, ()> {
    let ranges = parse_ranges_from_buffers(guest_mem, buffers, "write_zeroes")?;
    let mut byte_ranges = Vec::with_capacity(ranges.len());
    for range in ranges {
        validate_write_zeroes_flags(range, "write_zeroes")?;
        byte_ranges.push(checked_range_bytes(
            range,
            blk_size,
            capacity_sectors,
            arcbox_virtio::blk::VirtioBlock::MAX_WRITE_ZEROES_SECTORS,
            "write_zeroes",
        )?);
    }
    Ok(byte_ranges)
}

/// Punches holes for every DISCARD range. Factored out so it can be tested
/// without a full `BlkWorkerContext`.
fn punch_discard_ranges(
    guest_mem: &GuestMemWriter,
    raw_fd: i32,
    blk_size: u32,
    capacity_sectors: u64,
    buffers: &[(u64, u32, bool)],
) -> u8 {
    use arcbox_virtio::blk::{aligned_punch_range, punch_hole};

    let Ok(ranges) = discard_byte_ranges(guest_mem, blk_size, capacity_sectors, buffers) else {
        return 1;
    };
    for (start, end) in ranges {
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
    }
    0
}

/// Zeroes every WRITE_ZEROES range via the shared sparse-aware primitive
/// (hole-punch the aligned interior, write zeros on the edges). Returns the
/// virtio status (0 = OK, 1 = an I/O error occurred on some range).
fn zero_ranges(
    guest_mem: &GuestMemWriter,
    raw_fd: i32,
    blk_size: u32,
    capacity_sectors: u64,
    buffers: &[(u64, u32, bool)],
) -> u8 {
    let mut status = 0u8;
    let Ok(ranges) = write_zeroes_byte_ranges(guest_mem, blk_size, capacity_sectors, buffers)
    else {
        return 1;
    };
    for (start, end) in ranges {
        if let Err(e) = arcbox_virtio::blk::zero_range(raw_fd, start, end) {
            tracing::warn!(start, end, error = %e, "write_zeroes failed (HV worker)");
            status = 1;
        }
    }
    status
}

fn trigger_irq(ctx: &BlkWorkerContext) {
    // Set interrupt_status on MMIO state.
    if let Ok(mut s) = ctx.mmio_state.write() {
        s.trigger_interrupt(1); // INT_VRING
    }
    // Fire GIC SPI.
    let _ = (ctx.irq_callback)(ctx.irq, true);
    // Kick vCPUs out of WFI so a guest blocked waiting for this completion
    // services the IRQ immediately instead of at the next unrelated exit.
    (ctx.exit_vcpus)();
}

// ============================================================================
// Per-device async state (stored on DeviceManager)
// ============================================================================

/// Per-queue I/O worker handle.
pub struct BlkQueueWorker {
    /// Doorbell: the vCPU rings this (sends `()`) on QUEUE_NOTIFY to wake the
    /// owning worker. The worker — not the vCPU — consumes the avail ring,
    /// performs the I/O, and publishes completions, so a single thread owns the
    /// whole queue (the libkrun/virtio-queue model).
    pub doorbell: std::sync::mpsc::Sender<()>,
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

    /// Rings the doorbell for `queue_idx`, waking the owning worker to drain the
    /// queue. Called by the vCPU on a QUEUE_NOTIFY MMIO exit; the worker does
    /// all ring work (avail-consume, I/O, completion, IRQ), so this never
    /// touches guest memory.
    pub fn ring(&self, queue_idx: u16) {
        if let Some(worker) = self.get_queue(queue_idx) {
            // Unbounded channel: send never blocks. A closed receiver means the
            // worker exited during teardown — nothing to wake.
            let _ = worker.doorbell.send(());
        }
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

    fn test_context(mem: &mut [u8], raw_fd: i32, capacity_sectors: u64) -> BlkWorkerContext {
        BlkWorkerContext {
            // SAFETY: test memory outlives the returned context.
            guest_mem: unsafe { GuestMemWriter::new(mem.as_mut_ptr(), mem.len(), 0) },
            raw_fd,
            blk_size: 512,
            capacity_sectors,
            read_only: false,
            device_id: "test-blk".to_string(),
            mmio_state: Arc::new(RwLock::new(VirtioMmioState::new(2, 0))),
            irq_callback: Arc::new(|_, _| Ok(())),
            irq: 32,
            running: Arc::new(AtomicBool::new(true)),
            flush_barrier: Arc::new(FlushBarrier::new()),
            exit_vcpus: Arc::new(|| {}),
            queue_idx: 0,
        }
    }

    fn work_item(
        request_type: BlkRequestType,
        sector: u64,
        buffers: Vec<(u64, u32, bool)>,
        status_gpa: u64,
    ) -> BlkWorkItem {
        let total_data_len = buffers
            .iter()
            .filter(|(_, len, _)| *len > 1)
            .map(|(_, len, _)| *len)
            .sum();
        BlkWorkItem {
            head_idx: status_gpa as u16,
            request_type,
            sector,
            buffers,
            status_gpa,
            total_data_len,
        }
    }

    #[test]
    fn write_past_capacity_is_rejected() {
        use std::io::Write;
        use std::os::unix::io::AsRawFd;

        let mut temp = tempfile::NamedTempFile::new().unwrap();
        temp.write_all(&vec![0u8; 4096]).unwrap();
        temp.as_file().sync_all().unwrap();

        let mut mem = vec![0xCCu8; 4096];
        let ctx = test_context(&mut mem, temp.as_file().as_raw_fd(), 8);
        let item = work_item(BlkRequestType::Write, 7, vec![(0, 1024, false)], 1500);

        assert_eq!(process_write(&ctx, &item), 1);
        assert_eq!(std::fs::metadata(temp.path()).unwrap().len(), 4096);
    }

    #[test]
    fn unsupported_request_completes_unsupp() {
        let mut mem = vec![0u8; 4096];
        let ctx = test_context(&mut mem, -1, 8);
        let item = work_item(BlkRequestType::Unsupported, 0, Vec::new(), 1500);

        let (_, total_bytes) = process_item(&ctx, &item);

        assert_eq!(total_bytes, 1, "failed request completes with status only");
        assert_eq!(mem[1500], 2);
    }

    /// The HV worker's DISCARD path must actually reclaim host blocks — this is
    /// the path the macOS backend uses, where DISCARD previously fell through to
    /// a no-op `Read`.
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
        assert_eq!(punch_discard_ranges(&gm, fd, 512, 2048, &buffers), 0);
        temp.as_file().sync_all().unwrap();

        let after = std::fs::metadata(temp.path()).unwrap().blocks() * 512;
        assert!(
            after < 64 * 1024,
            "worker discard should have punched the backing file, still {after} allocated"
        );
    }

    /// The HV worker's WRITE_ZEROES path must actually zero the target sectors —
    /// previously it fell through to a no-op `Read` and silently left stale data.
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

        assert_eq!(zero_ranges(&gm, fd, 512, 32, &buffers), 0);
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

    #[test]
    fn range_parser_concatenates_split_payload_descriptors() {
        let mut mem = vec![0u8; 4096];
        mem[0..8].copy_from_slice(&8u64.to_le_bytes());
        mem[8..12].copy_from_slice(&8u32.to_le_bytes());
        mem[12..16].copy_from_slice(&0u32.to_le_bytes());
        // SAFETY: `mem` outlives `gm`; gpa_base 0 means gpa == buffer offset.
        let gm = unsafe { GuestMemWriter::new(mem.as_mut_ptr(), mem.len(), 0) };

        let buffers = vec![
            (0u64, 8u32, false),
            (8u64, 8u32, false),
            (16u64, 1u32, true),
        ];
        let ranges = discard_byte_ranges(&gm, 512, 32, &buffers).unwrap();

        assert_eq!(ranges, vec![(4096, 8192)]);
    }

    #[test]
    fn write_zeroes_rejects_trailing_payload_bytes() {
        let mut mem = vec![0u8; 4096];
        mem[0..8].copy_from_slice(&0u64.to_le_bytes());
        mem[8..12].copy_from_slice(&8u32.to_le_bytes());
        mem[12..16].copy_from_slice(&0u32.to_le_bytes());
        // SAFETY: `mem` outlives `gm`; gpa_base 0 means gpa == buffer offset.
        let gm = unsafe { GuestMemWriter::new(mem.as_mut_ptr(), mem.len(), 0) };

        let buffers = vec![(0u64, 17u32, false), (17u64, 1u32, true)];

        assert!(write_zeroes_byte_ranges(&gm, 512, 32, &buffers).is_err());
    }

    #[test]
    fn write_zeroes_rejects_ranges_past_capacity() {
        let mut mem = vec![0u8; 4096];
        mem[0..8].copy_from_slice(&31u64.to_le_bytes());
        mem[8..12].copy_from_slice(&2u32.to_le_bytes());
        mem[12..16].copy_from_slice(&0u32.to_le_bytes());
        // SAFETY: `mem` outlives `gm`; gpa_base 0 means gpa == buffer offset.
        let gm = unsafe { GuestMemWriter::new(mem.as_mut_ptr(), mem.len(), 0) };

        let buffers = vec![(0u64, 16u32, false), (16u64, 1u32, true)];

        assert!(write_zeroes_byte_ranges(&gm, 512, 32, &buffers).is_err());
    }
}
