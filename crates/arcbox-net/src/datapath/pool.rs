//! Pre-allocated packet buffer pool.
//!
//! This module provides a pool of pre-allocated packet buffers to avoid
//! runtime memory allocation in the hot path.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use crate::error::{NetError, Result};

use super::{CachePadded, DEFAULT_POOL_CAPACITY, MAX_PACKET_SIZE};

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

impl std::fmt::Debug for PacketBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketBuffer")
            .field("len", &self.len)
            .field("index", &self.index)
            .field("refcount", &self.refcount.load(Ordering::Relaxed))
            .finish()
    }
}

/// Free list entry for the packet pool.
#[repr(C)]
struct FreeListEntry {
    /// Index of the next free buffer, or u32::MAX if none.
    next: AtomicU32,
}

/// Pre-allocated packet buffer pool.
///
/// Uses a lock-free free list for allocation and deallocation.
/// All buffers are pre-allocated at construction time to avoid
/// runtime memory allocation in the hot path.
pub struct PacketPool {
    /// Pre-allocated buffers wrapped in UnsafeCell for interior mutability.
    buffers: Box<[UnsafeCell<PacketBuffer>]>,
    /// Free list head index (u32::MAX means empty).
    free_head: CachePadded<AtomicU32>,
    /// Free list entries (one per buffer).
    free_list: Box<[FreeListEntry]>,
    /// Number of free buffers.
    free_count: CachePadded<AtomicUsize>,
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

        // Pre-allocate buffers wrapped in UnsafeCell
        let buffers: Vec<UnsafeCell<PacketBuffer>> = (0..capacity)
            .map(|i| UnsafeCell::new(PacketBuffer::new(i as u32)))
            .collect();

        // Initialize free list - all buffers are initially free
        let free_list: Vec<FreeListEntry> = (0..capacity)
            .map(|i| {
                let next = if i + 1 < capacity {
                    (i + 1) as u32
                } else {
                    u32::MAX
                };
                FreeListEntry {
                    next: AtomicU32::new(next),
                }
            })
            .collect();

        Ok(Self {
            buffers: buffers.into_boxed_slice(),
            free_head: CachePadded::new(AtomicU32::new(0)),
            free_list: free_list.into_boxed_slice(),
            free_count: CachePadded::new(AtomicUsize::new(capacity)),
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
        self.free_count.0.load(Ordering::Acquire)
    }

    /// Returns the number of allocated buffers.
    #[inline]
    #[must_use]
    pub fn allocated_count(&self) -> usize {
        self.capacity - self.free_count()
    }

    /// Allocates a buffer from the pool.
    ///
    /// Returns `None` if the pool is empty.
    pub fn alloc(&self) -> Option<&mut PacketBuffer> {
        loop {
            let head = self.free_head.0.load(Ordering::Acquire);
            if head == u32::MAX {
                return None; // Pool is empty
            }

            let next = self.free_list[head as usize].next.load(Ordering::Acquire);

            // Try to update the head
            if self
                .free_head
                .0
                .compare_exchange_weak(head, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.free_count.0.fetch_sub(1, Ordering::AcqRel);

                // Safety: We have exclusive access to this buffer now via CAS success.
                // UnsafeCell::get() returns *mut T which is the correct way to get mutable access.
                let buffer = unsafe { &mut *self.buffers[head as usize].get() };
                buffer.refcount.store(1, Ordering::Release);
                return Some(buffer);
            }
            // CAS failed, retry
            std::hint::spin_loop();
        }
    }

    /// Allocates a buffer and returns its index.
    ///
    /// Returns `None` if the pool is empty.
    pub fn alloc_index(&self) -> Option<u32> {
        loop {
            let head = self.free_head.0.load(Ordering::Acquire);
            if head == u32::MAX {
                return None; // Pool is empty
            }

            let next = self.free_list[head as usize].next.load(Ordering::Acquire);

            // Try to update the head
            if self
                .free_head
                .0
                .compare_exchange_weak(head, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.free_count.0.fetch_sub(1, Ordering::AcqRel);
                // Safety: We have exclusive access via CAS success.
                unsafe {
                    (*self.buffers[head as usize].get())
                        .refcount
                        .store(1, Ordering::Release)
                };
                return Some(head);
            }
            // CAS failed, retry
            std::hint::spin_loop();
        }
    }

    /// Allocates a buffer and initializes it with data.
    ///
    /// # Errors
    ///
    /// Returns an error if the pool is empty or data is too large.
    pub fn alloc_with_data(&self, data: &[u8]) -> Result<&mut PacketBuffer> {
        let buffer = self
            .alloc()
            .ok_or_else(|| NetError::PacketPool("pool exhausted".to_string()))?;
        buffer.copy_from_slice(data)?;
        Ok(buffer)
    }

    /// Returns a buffer to the pool.
    ///
    /// # Safety
    ///
    /// The buffer must belong to this pool and not be in use elsewhere.
    pub unsafe fn free(&self, buffer: &mut PacketBuffer) {
        let idx = buffer.index;
        debug_assert!((idx as usize) < self.capacity);

        buffer.reset();

        loop {
            let head = self.free_head.0.load(Ordering::Acquire);
            self.free_list[idx as usize]
                .next
                .store(head, Ordering::Release);

            if self
                .free_head
                .0
                .compare_exchange_weak(head, idx, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.free_count.0.fetch_add(1, Ordering::AcqRel);
                return;
            }
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

        // Safety: caller guarantees buffer is not in use per function contract.
        // UnsafeCell::get() is the correct way to get mutable access.
        let buffer = unsafe { &mut *self.buffers[idx as usize].get() };
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
        // Safety: caller guarantees buffer is allocated.
        unsafe { &*self.buffers[idx as usize].get() }
    }

    /// Gets a mutable buffer by index.
    ///
    /// # Safety
    ///
    /// The caller must ensure the buffer is allocated and have exclusive access.
    #[must_use]
    pub unsafe fn get_mut(&self, idx: u32) -> &mut PacketBuffer {
        debug_assert!((idx as usize) < self.capacity);
        // Safety: caller guarantees exclusive access per function contract.
        // UnsafeCell::get() is the correct way to get mutable access.
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
    fn test_pool_alloc_free() {
        let pool = PacketPool::new(10).unwrap();

        // Allocate a buffer
        let buf = pool.alloc().unwrap();
        assert_eq!(buf.refcount(), 1);
        assert_eq!(pool.free_count(), 9);
        assert_eq!(pool.allocated_count(), 1);

        let idx = buf.index();

        // Free the buffer
        unsafe { pool.free(buf) };
        assert_eq!(pool.free_count(), 10);
        assert_eq!(pool.allocated_count(), 0);

        // The buffer should be reusable
        let buf2 = pool.alloc().unwrap();
        // Might get the same buffer back (LIFO)
        assert_eq!(buf2.index(), idx);
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
        let buf = pool.alloc().unwrap();

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
        for i in 0..5 {
            assert!(indices[i] < 5);
        }
    }
}
