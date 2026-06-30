//! Async block I/O worker for the HV (Hypervisor.framework) backend.
//!
//! Decouples VirtIO block I/O from the vCPU thread. The vCPU parses
//! descriptor chains and submits work items to a channel; a dedicated
//! worker thread performs the actual pread/pwrite and writes completions
//! directly to the guest's used ring, then triggers an IRQ.

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
        _ => BlkRequestType::Read,
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
    let is_io = matches!(
        item.request_type,
        BlkRequestType::Read | BlkRequestType::Write
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
