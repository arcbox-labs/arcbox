//! Pre-allocated packet buffer pool.
//!
//! This module provides a pool of pre-allocated packet buffers to avoid
//! runtime memory allocation in the hot path.

use std::cell::UnsafeCell;
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU32, Ordering};

use crate::error::{NetError, Result};

use super::ring::MpmcRing;
use super::{DEFAULT_POOL_CAPACITY, MAX_PACKET_SIZE};

/// A single packet buffer with header space.
#[repr(C, align(64))]
pub struct PacketBuffer {
    /// Buffer data.
    data: [u8; MAX_PACKET_SIZE],
    /// Current data length.
    len: u32,
    /// Buffer index in the pool.
    index: u32,
    /// Reference count.
    refcount: AtomicU32,
}

impl PacketBuffer {
    /// Creates a new empty buffer.
    #[inline]
    #[allow(clippy::large_stack_arrays)] // 64 KB array — the temporary may briefly touch the stack during Box::new, but the buffer is immediately moved into the heap-backed pool
    const fn new(index: u32) -> Self {
        Self {
            data: [0; MAX_PACKET_SIZE],
            len: 0,
            index,
            refcount: AtomicU32::new(0),
        }
    }

    /// Returns the buffer index.
    #[inline]
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Returns the current data length.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns true if the buffer is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Sets the data length.
    #[inline]
    pub fn set_len(&mut self, len: usize) {
        self.len = len.min(MAX_PACKET_SIZE) as u32;
    }

    /// Returns the buffer data as a slice.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }

    /// Returns the buffer data as a mutable slice.
    #[inline]
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len as usize]
    }

    /// Returns the full buffer capacity.
    #[inline]
    #[must_use]
    pub fn as_full_slice(&self) -> &[u8] {
        &self.data
    }

    /// Returns the full buffer as mutable.
    #[inline]
    #[must_use]
    pub fn as_full_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Returns a pointer to the buffer data.
    #[inline]
    #[must_use]
    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    /// Returns a mutable pointer to the buffer data.
    #[inline]
    #[must_use]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }

    /// Increments the reference count.
    #[inline]
    pub fn add_ref(&self) {
        self.refcount.fetch_add(1, Ordering::AcqRel);
    }

    /// Decrements the reference count and returns true if it reached zero.
    #[inline]
    pub fn release(&self) -> bool {
        self.refcount.fetch_sub(1, Ordering::AcqRel) == 1
    }

    /// Returns the current reference count.
    #[inline]
    #[must_use]
    pub fn refcount(&self) -> u32 {
        self.refcount.load(Ordering::Acquire)
    }

    /// Resets the buffer for reuse.
    #[inline]
    pub fn reset(&mut self) {
        self.len = 0;
        self.refcount.store(0, Ordering::Release);
    }

    /// Copies data into the buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the data is too large.
    pub fn copy_from_slice(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_PACKET_SIZE {
            return Err(NetError::PacketPool(format!(
                "data too large: {} > {}",
                data.len(),
                MAX_PACKET_SIZE
            )));
        }
        self.data[..data.len()].copy_from_slice(data);
        self.len = data.len() as u32;
        Ok(())
    }
}

#[allow(clippy::missing_fields_in_debug)] // data omitted intentionally (hot-path buffer, not useful in debug output)
impl std::fmt::Debug for PacketBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketBuffer")
            .field("len", &self.len)
            .field("index", &self.index)
            .field("refcount", &self.refcount.load(Ordering::Relaxed))
            .finish()
    }
}

/// Owned handle to a [`PacketBuffer`] allocated from a [`PacketPool`].
///
/// Provides `Deref`/`DerefMut` access to the underlying buffer and
/// automatically returns it to the pool on drop. Use [`into_index`](Self::into_index)
/// when the buffer must be handed off by index (e.g. to a ring buffer)
/// without triggering the auto-free.
pub struct PacketRef<'pool> {
    pool: &'pool PacketPool,
    idx: u32,
}

impl PacketRef<'_> {
    /// Returns the buffer's index in the pool.
    #[inline]
    #[must_use]
    pub fn index(&self) -> u32 {
        self.idx
    }

    /// Consumes the handle and returns the raw buffer index **without**
    /// freeing the buffer back to the pool.
    ///
    /// The caller is responsible for eventually freeing the buffer
    /// (e.g. via [`PacketPool::free_by_index`]).
    #[inline]
    #[must_use]
    pub fn into_index(self) -> u32 {
        let md = ManuallyDrop::new(self);
        md.idx
    }
}

impl Deref for PacketRef<'_> {
    type Target = PacketBuffer;

    #[inline]
    fn deref(&self) -> &PacketBuffer {
        // SAFETY: The CAS in `alloc` guarantees this buffer is not on the
        // free-list, and only one `PacketRef` exists per index at a time,
        // so no other code holds a mutable reference.
        unsafe { &*self.pool.buffers[self.idx as usize].get() }
    }
}

impl DerefMut for PacketRef<'_> {
    #[inline]
    fn deref_mut(&mut self) -> &mut PacketBuffer {
        // SAFETY: `&mut self` guarantees we are the sole accessor of this
        // `PacketRef`, and the CAS in `alloc` guarantees the buffer is not
        // on the free-list.
        unsafe { &mut *self.pool.buffers[self.idx as usize].get() }
    }
}

impl Drop for PacketRef<'_> {
    fn drop(&mut self) {
        // SAFETY: The buffer at `self.idx` belongs to `self.pool` and is
        // not on the free-list (guaranteed by the allocation protocol).
        unsafe { self.pool.free_by_index(self.idx) };
    }
}

impl std::fmt::Debug for PacketRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketRef")
            .field("idx", &self.idx)
            .field("buffer", &**self)
            .finish()
    }
}

/// Pre-allocated packet buffer pool.
///
/// Uses an [`MpmcRing`] of free indices for lock-free allocation and
/// deallocation. The Vyukov bounded MPMC algorithm used by `MpmcRing`
/// provides ABA safety via per-slot sequence numbers, so no custom
/// tagged pointers or Treiber stacks are needed.
///
/// All buffers are pre-allocated at construction time to avoid
/// runtime memory allocation in the hot path.
pub struct PacketPool {
    /// Pre-allocated buffers wrapped in UnsafeCell for interior mutability.
    buffers: Box<[UnsafeCell<PacketBuffer>]>,
    /// Lock-free queue of free buffer indices (ABA-safe via Vyukov seq numbers).
    free_indices: MpmcRing<u32>,
    /// Total capacity.
    capacity: usize,
}

impl PacketPool {
    /// Creates a new packet pool with the specified capacity.
    ///
    /// # Errors
    ///
    /// Returns an error if allocation fails.
    pub fn new(capacity: usize) -> Result<Self> {
        let capacity = capacity.max(1);

        let buffers: Vec<UnsafeCell<PacketBuffer>> = (0..capacity)
            .map(|i| UnsafeCell::new(PacketBuffer::new(i as u32)))
            .collect();

        // Seed the free-index ring with all buffer indices.
        let free_indices = MpmcRing::new(capacity);
        for i in 0..capacity {
            let _ = free_indices.enqueue(i as u32);
        }

        Ok(Self {
            buffers: buffers.into_boxed_slice(),
            free_indices,
            capacity,
        })
    }

    /// Creates a new pool with the default capacity.
    ///
    /// # Errors
    ///
    /// Returns an error if allocation fails.
    pub fn with_default_capacity() -> Result<Self> {
        Self::new(DEFAULT_POOL_CAPACITY)
    }

    /// Returns the pool capacity.
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of free buffers.
    #[inline]
    #[must_use]
    pub fn free_count(&self) -> usize {
        self.free_indices.len()
    }

    /// Returns the number of allocated buffers.
    #[inline]
    #[must_use]
    pub fn allocated_count(&self) -> usize {
        self.capacity - self.free_indices.len()
    }

    /// Allocates a buffer from the pool.
    ///
    /// Returns `None` if the pool is empty. The returned [`PacketRef`]
    /// auto-frees the buffer on drop; use [`PacketRef::into_index`] to
    /// transfer ownership by index without auto-freeing.
    pub fn alloc(&self) -> Option<PacketRef<'_>> {
        let idx = self.free_indices.dequeue()?;
        // SAFETY: `idx` was on the free list, so no other thread has access.
        unsafe {
            (*self.buffers[idx as usize].get())
                .refcount
                .store(1, Ordering::Release);
        }
        Some(PacketRef { pool: self, idx })
    }

    /// Allocates a buffer and returns its index.
    ///
    /// Returns `None` if the pool is empty.
    pub fn alloc_index(&self) -> Option<u32> {
        let idx = self.free_indices.dequeue()?;
        // SAFETY: `idx` was on the free list, so no other thread has access.
        unsafe {
            (*self.buffers[idx as usize].get())
                .refcount
                .store(1, Ordering::Release);
        }
        Some(idx)
    }

    /// Allocates a buffer and initializes it with data.
    ///
    /// # Errors
    ///
    /// Returns an error if the pool is empty or data is too large.
    pub fn alloc_with_data(&self, data: &[u8]) -> Result<PacketRef<'_>> {
        let mut pkt = self
            .alloc()
            .ok_or_else(|| NetError::PacketPool("pool exhausted".to_string()))?;
        pkt.copy_from_slice(data)?;
        Ok(pkt)
    }

    /// Returns a buffer to the pool.
    ///
    /// Prefer dropping a [`PacketRef`] or calling [`free_by_index`](Self::free_by_index)
    /// instead of using this method directly.
    ///
    /// # Safety
    ///
    /// The buffer must belong to this pool and not be in use elsewhere
    /// (no live [`PacketRef`] or `&mut PacketBuffer` for the same index).
    pub(crate) unsafe fn free(&self, buffer: &mut PacketBuffer) {
        let idx = buffer.index;
        debug_assert!((idx as usize) < self.capacity);
        buffer.reset();
        // Spin-retry: under high contention the Vyukov MPMC ring may
        // transiently report full while another producer's sequence-store
        // is still in flight. The ring is sized to hold all indices, so
        // this will always succeed after a brief spin.
        while self.free_indices.enqueue(idx).is_err() {
            std::hint::spin_loop();
        }
    }

    /// Returns a buffer to the pool by index.
    ///
    /// # Safety
    ///
    /// The buffer at this index must not be in use elsewhere.
    pub unsafe fn free_by_index(&self, idx: u32) {
        debug_assert!((idx as usize) < self.capacity);

        // SAFETY: Caller guarantees the buffer is not in use elsewhere.
        let buffer = unsafe { &mut *self.buffers[idx as usize].get() };
        // SAFETY: Same precondition forwarded from caller.
        unsafe { self.free(buffer) };
    }

    /// Gets a buffer by index.
    ///
    /// # Safety
    ///
    /// The caller must ensure the buffer is allocated.
    #[must_use]
    pub unsafe fn get(&self, idx: u32) -> &PacketBuffer {
        debug_assert!((idx as usize) < self.capacity);
        // SAFETY: Caller guarantees the buffer at `idx` is allocated.
        unsafe { &*self.buffers[idx as usize].get() }
    }

    /// Gets a mutable buffer by index.
    ///
    /// # Safety
    ///
    /// The caller must ensure the buffer is allocated, has exclusive access,
    /// **and no [`PacketRef`] exists for the same index**. Violating this
    /// creates aliasing `&mut` references, which is instant UB.
    #[must_use]
    #[allow(clippy::mut_from_ref)] // Soundness relies on caller-guaranteed exclusivity; this is an inherently unsafe operation
    pub unsafe fn get_mut(&self, idx: u32) -> &mut PacketBuffer {
        debug_assert!((idx as usize) < self.capacity);
        // SAFETY: Caller guarantees exclusive access per function contract.
        unsafe { &mut *self.buffers[idx as usize].get() }
    }

    /// Allocates multiple buffer indices at once.
    ///
    /// Returns the number of indices actually allocated.
    pub fn alloc_batch_indices(&self, out: &mut [u32]) -> usize {
        let mut count = 0;
        for slot in out.iter_mut() {
            if let Some(idx) = self.alloc_index() {
                *slot = idx;
                count += 1;
            } else {
                break;
            }
        }
        count
    }
}

#[allow(clippy::missing_fields_in_debug)] // buffers omitted intentionally (large array, not useful in debug output)
impl std::fmt::Debug for PacketPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketPool")
            .field("capacity", &self.capacity)
            .field("free_count", &self.free_count())
            .field("allocated_count", &self.allocated_count())
            .finish()
    }
}

// Safety: The pool uses atomic operations for synchronization.
unsafe impl Send for PacketPool {}
unsafe impl Sync for PacketPool {}

// Compile-time assertion: PacketRef must be Send (buffers are handed off
// between threads via ring buffers) and need not be Sync (no shared access).
#[allow(dead_code)]
const _ASSERT_PACKET_REF_SEND: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<PacketRef<'_>>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_size() {
        // Buffer should be cache-line aligned
        assert_eq!(std::mem::align_of::<PacketBuffer>(), 64);
    }

    #[test]
    fn test_pool_creation() {
        let pool = PacketPool::new(100).unwrap();
        assert_eq!(pool.capacity(), 100);
        assert_eq!(pool.free_count(), 100);
        assert_eq!(pool.allocated_count(), 0);
    }

    #[test]
    fn test_pool_alloc_drop() {
        let pool = PacketPool::new(10).unwrap();

        // Allocate a buffer.
        let buf = pool.alloc().unwrap();
        assert_eq!(buf.refcount(), 1);
        assert_eq!(pool.free_count(), 9);
        assert_eq!(pool.allocated_count(), 1);

        // Drop auto-frees the buffer back to the pool.
        drop(buf);
        assert_eq!(pool.free_count(), 10);
        assert_eq!(pool.allocated_count(), 0);

        // The buffer should be reusable (FIFO — not necessarily the same index).
        let buf2 = pool.alloc().unwrap();
        assert!(buf2.index() < 10);
    }

    #[test]
    fn test_packet_ref_into_index() {
        let pool = PacketPool::new(4).unwrap();

        let buf = pool.alloc().unwrap();
        let idx = buf.index();

        // into_index consumes the ref without freeing.
        let extracted = buf.into_index();
        assert_eq!(extracted, idx);
        // Buffer is still allocated (not returned to pool).
        assert_eq!(pool.free_count(), 3);

        // Manual free via index.
        unsafe { pool.free_by_index(extracted) };
        assert_eq!(pool.free_count(), 4);
    }

    #[test]
    fn test_pool_exhaustion() {
        let pool = PacketPool::new(2).unwrap();

        let _buf1 = pool.alloc().unwrap();
        let _buf2 = pool.alloc().unwrap();

        // Pool should be exhausted
        assert!(pool.alloc().is_none());
        assert_eq!(pool.free_count(), 0);
    }

    #[test]
    fn test_buffer_copy() {
        let pool = PacketPool::new(1).unwrap();
        let mut buf = pool.alloc().unwrap();

        let data = [1u8, 2, 3, 4, 5];
        buf.copy_from_slice(&data).unwrap();

        assert_eq!(buf.len(), 5);
        assert_eq!(buf.as_slice(), &data);
    }

    #[test]
    fn test_alloc_with_data() {
        let pool = PacketPool::new(1).unwrap();
        let data = [0xAB; 100];

        let buf = pool.alloc_with_data(&data).unwrap();
        assert_eq!(buf.len(), 100);
        assert_eq!(buf.as_slice(), &data);
    }

    #[test]
    fn test_batch_alloc_indices() {
        let pool = PacketPool::new(5).unwrap();
        let mut indices = [0u32; 10];

        let count = pool.alloc_batch_indices(&mut indices);
        assert_eq!(count, 5);
        assert_eq!(pool.free_count(), 0);

        // First 5 should be valid indices (0-4)
        for idx in &indices[..5] {
            assert!(*idx < 5);
        }
    }

    #[test]
    fn test_concurrent_alloc_drop() {
        use std::sync::Arc;

        let pool = Arc::new(PacketPool::new(64).unwrap());
        let iterations = 1000;
        let threads = 4;

        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let pool = Arc::clone(&pool);
                std::thread::spawn(move || {
                    for _ in 0..iterations {
                        // Allocate a buffer, write to it, then drop (auto-free).
                        if let Some(mut pkt) = pool.alloc() {
                            pkt.set_len(4);
                            pkt.as_full_mut_slice()[..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
                            assert_eq!(pkt.as_slice(), &[0xDE, 0xAD, 0xBE, 0xEF]);
                            // pkt dropped here — returned to pool
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // All buffers should be returned to the pool.
        assert_eq!(pool.free_count(), 64);
        assert_eq!(pool.allocated_count(), 0);
    }

    #[test]
    fn test_concurrent_alloc_into_index_free() {
        use std::sync::Arc;

        let pool = Arc::new(PacketPool::new(32).unwrap());
        let iterations = 500;
        let threads = 4;

        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let pool = Arc::clone(&pool);
                std::thread::spawn(move || {
                    for _ in 0..iterations {
                        if let Some(pkt) = pool.alloc() {
                            // Simulate ring buffer handoff: into_index, then manual free.
                            let idx = pkt.into_index();
                            assert!(idx < 32);
                            unsafe { pool.free_by_index(idx) };
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(pool.free_count(), 32);
    }
}
