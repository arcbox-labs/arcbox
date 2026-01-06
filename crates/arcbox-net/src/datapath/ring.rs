//! Lock-free ring buffer for high-performance packet passing.
//!
//! This module implements a Single-Producer Single-Consumer (SPSC) ring buffer
//! optimized for packet passing between threads without locks.

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{next_power_of_two, CachePadded, DEFAULT_RING_CAPACITY};

/// Lock-free SPSC ring buffer.
///
/// This ring buffer is designed for Single-Producer Single-Consumer scenarios,
/// where one thread enqueues items and another dequeues them. It uses atomic
/// operations for synchronization without any locks.
///
/// # Performance
///
/// - Enqueue: O(1) amortized
/// - Dequeue: O(1) amortized
/// - Batch operations amortize atomic overhead
///
/// # Cache Optimization
///
/// - Head and tail indices are cache-line padded to prevent false sharing
/// - Buffer capacity is always a power of 2 for fast modulo via bitwise AND
pub struct LockFreeRing<T> {
    /// Ring buffer storage.
    buffer: Box<[UnsafeCell<MaybeUninit<T>>]>,
    /// Capacity (always power of 2).
    capacity: usize,
    /// Capacity mask for fast modulo: index & mask == index % capacity.
    mask: usize,
    /// Producer index (next slot to write).
    head: CachePadded<AtomicUsize>,
    /// Consumer index (next slot to read).
    tail: CachePadded<AtomicUsize>,
}

// Safety: The ring uses atomic operations for synchronization.
// Only one producer and one consumer should access it.
unsafe impl<T: Send> Send for LockFreeRing<T> {}
unsafe impl<T: Send> Sync for LockFreeRing<T> {}

impl<T> LockFreeRing<T> {
    /// Creates a new ring buffer with the specified capacity.
    ///
    /// The actual capacity will be rounded up to the next power of 2.
    ///
    /// # Panics
    ///
    /// Panics if capacity is 0 or allocation fails.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "capacity must be > 0");

        let capacity = next_power_of_two(capacity);
        let mask = capacity - 1;

        // Allocate uninitialized buffer
        let buffer: Vec<UnsafeCell<MaybeUninit<T>>> = (0..capacity)
            .map(|_| UnsafeCell::new(MaybeUninit::uninit()))
            .collect();

        Self {
            buffer: buffer.into_boxed_slice(),
            capacity,
            mask,
            head: CachePadded::new(AtomicUsize::new(0)),
            tail: CachePadded::new(AtomicUsize::new(0)),
        }
    }

    /// Creates a ring buffer with the default capacity.
    #[must_use]
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_RING_CAPACITY)
    }

    /// Returns the ring capacity.
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of items currently in the ring.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        let head = self.head.0.load(Ordering::Acquire);
        let tail = self.tail.0.load(Ordering::Acquire);
        head.wrapping_sub(tail)
    }

    /// Returns true if the ring is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns true if the ring is full.
    #[inline]
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.len() >= self.capacity
    }

    /// Returns the number of free slots.
    #[inline]
    #[must_use]
    pub fn free_slots(&self) -> usize {
        self.capacity - self.len()
    }

    /// Enqueues a single item.
    ///
    /// Returns `Err(item)` if the ring is full.
    #[inline]
    pub fn enqueue(&self, item: T) -> Result<(), T> {
        let head = self.head.0.load(Ordering::Relaxed);
        let tail = self.tail.0.load(Ordering::Acquire);

        // Check if full
        if head.wrapping_sub(tail) >= self.capacity {
            return Err(item);
        }

        // Write the item
        let idx = head & self.mask;
        unsafe {
            (*self.buffer[idx].get()).write(item);
        }

        // Publish the write
        self.head.0.store(head.wrapping_add(1), Ordering::Release);

        Ok(())
    }

    /// Dequeues a single item.
    ///
    /// Returns `None` if the ring is empty.
    #[inline]
    pub fn dequeue(&self) -> Option<T> {
        let tail = self.tail.0.load(Ordering::Relaxed);
        let head = self.head.0.load(Ordering::Acquire);

        // Check if empty
        if tail == head {
            return None;
        }

        // Read the item
        let idx = tail & self.mask;
        let item = unsafe { (*self.buffer[idx].get()).assume_init_read() };

        // Publish the read
        self.tail.0.store(tail.wrapping_add(1), Ordering::Release);

        Some(item)
    }

    /// Enqueues multiple items in a batch.
    ///
    /// Returns the number of items successfully enqueued.
    /// Items that couldn't be enqueued remain in the slice.
    pub fn enqueue_batch(&self, items: &[T]) -> usize
    where
        T: Copy,
    {
        let head = self.head.0.load(Ordering::Relaxed);
        let tail = self.tail.0.load(Ordering::Acquire);

        let free = self.capacity - head.wrapping_sub(tail);
        let count = items.len().min(free);

        if count == 0 {
            return 0;
        }

        // Write items
        for (i, item) in items.iter().take(count).enumerate() {
            let idx = (head + i) & self.mask;
            unsafe {
                (*self.buffer[idx].get()).write(*item);
            }
        }

        // Publish all writes at once
        self.head.0.store(head.wrapping_add(count), Ordering::Release);

        count
    }

    /// Dequeues multiple items in a batch.
    ///
    /// Returns the number of items dequeued.
    pub fn dequeue_batch(&self, out: &mut [T]) -> usize
    where
        T: Copy,
    {
        let tail = self.tail.0.load(Ordering::Relaxed);
        let head = self.head.0.load(Ordering::Acquire);

        let available = head.wrapping_sub(tail);
        let count = out.len().min(available);

        if count == 0 {
            return 0;
        }

        // Read items
        for i in 0..count {
            let idx = (tail + i) & self.mask;
            out[i] = unsafe { (*self.buffer[idx].get()).assume_init_read() };
        }

        // Publish all reads at once
        self.tail.0.store(tail.wrapping_add(count), Ordering::Release);

        count
    }

    /// Tries to enqueue an item, returning immediately if full.
    #[inline]
    pub fn try_enqueue(&self, item: T) -> Result<(), T> {
        self.enqueue(item)
    }

    /// Tries to dequeue an item, returning immediately if empty.
    #[inline]
    pub fn try_dequeue(&self) -> Option<T> {
        self.dequeue()
    }

    /// Peeks at the next item to be dequeued without removing it.
    ///
    /// # Safety
    ///
    /// The returned reference is only valid until the next dequeue operation.
    #[inline]
    pub unsafe fn peek(&self) -> Option<&T> {
        let tail = self.tail.0.load(Ordering::Relaxed);
        let head = self.head.0.load(Ordering::Acquire);

        if tail == head {
            return None;
        }

        let idx = tail & self.mask;
        // Safety: index is valid and item was initialized per SPSC protocol.
        Some(unsafe { (*self.buffer[idx].get()).assume_init_ref() })
    }

    /// Clears all items from the ring.
    ///
    /// # Safety
    ///
    /// This should only be called when no concurrent operations are in progress.
    pub unsafe fn clear(&self) {
        while self.dequeue().is_some() {}
    }
}

impl<T> Drop for LockFreeRing<T> {
    fn drop(&mut self) {
        // Drop any remaining items
        while self.dequeue().is_some() {}
    }
}

impl<T> std::fmt::Debug for LockFreeRing<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockFreeRing")
            .field("capacity", &self.capacity)
            .field("len", &self.len())
            .field("head", &self.head.0.load(Ordering::Relaxed))
            .field("tail", &self.tail.0.load(Ordering::Relaxed))
            .finish()
    }
}

/// Multi-producer multi-consumer ring buffer.
///
/// Uses compare-and-swap operations for thread-safe access from multiple
/// producers and consumers. Slower than SPSC but more flexible.
pub struct MpmcRing<T> {
    /// Ring buffer storage.
    buffer: Box<[UnsafeCell<MaybeUninit<T>>]>,
    /// Capacity (always power of 2).
    capacity: usize,
    /// Capacity mask.
    mask: usize,
    /// Producer index.
    head: CachePadded<AtomicUsize>,
    /// Consumer index.
    tail: CachePadded<AtomicUsize>,
}

unsafe impl<T: Send> Send for MpmcRing<T> {}
unsafe impl<T: Send> Sync for MpmcRing<T> {}

impl<T> MpmcRing<T> {
    /// Creates a new MPMC ring buffer.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "capacity must be > 0");

        let capacity = next_power_of_two(capacity);
        let mask = capacity - 1;

        let buffer: Vec<UnsafeCell<MaybeUninit<T>>> = (0..capacity)
            .map(|_| UnsafeCell::new(MaybeUninit::uninit()))
            .collect();

        Self {
            buffer: buffer.into_boxed_slice(),
            capacity,
            mask,
            head: CachePadded::new(AtomicUsize::new(0)),
            tail: CachePadded::new(AtomicUsize::new(0)),
        }
    }

    /// Returns the capacity.
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the approximate length.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        let head = self.head.0.load(Ordering::Acquire);
        let tail = self.tail.0.load(Ordering::Acquire);
        head.wrapping_sub(tail)
    }

    /// Returns true if approximately empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Enqueues an item using CAS.
    pub fn enqueue(&self, item: T) -> Result<(), T> {
        let mut head = self.head.0.load(Ordering::Relaxed);

        loop {
            let tail = self.tail.0.load(Ordering::Acquire);

            if head.wrapping_sub(tail) >= self.capacity {
                return Err(item);
            }

            match self.head.0.compare_exchange_weak(
                head,
                head.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let idx = head & self.mask;
                    unsafe {
                        (*self.buffer[idx].get()).write(item);
                    }
                    return Ok(());
                }
                Err(h) => {
                    head = h;
                    std::hint::spin_loop();
                }
            }
        }
    }

    /// Dequeues an item using CAS.
    pub fn dequeue(&self) -> Option<T> {
        let mut tail = self.tail.0.load(Ordering::Relaxed);

        loop {
            let head = self.head.0.load(Ordering::Acquire);

            if tail == head {
                return None;
            }

            let idx = tail & self.mask;
            let item = unsafe { (*self.buffer[idx].get()).assume_init_read() };

            match self.tail.0.compare_exchange_weak(
                tail,
                tail.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(item),
                Err(t) => {
                    tail = t;
                    std::hint::spin_loop();
                }
            }
        }
    }
}

impl<T> Drop for MpmcRing<T> {
    fn drop(&mut self) {
        while self.dequeue().is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_spsc_basic() {
        let ring = LockFreeRing::<u32>::new(4);

        assert!(ring.is_empty());
        assert_eq!(ring.capacity(), 4);

        // Enqueue
        ring.enqueue(1).unwrap();
        ring.enqueue(2).unwrap();
        ring.enqueue(3).unwrap();
        ring.enqueue(4).unwrap();

        assert!(ring.is_full());
        assert!(ring.enqueue(5).is_err());

        // Dequeue
        assert_eq!(ring.dequeue(), Some(1));
        assert_eq!(ring.dequeue(), Some(2));
        assert_eq!(ring.dequeue(), Some(3));
        assert_eq!(ring.dequeue(), Some(4));

        assert!(ring.is_empty());
        assert_eq!(ring.dequeue(), None);
    }

    #[test]
    fn test_spsc_batch() {
        let ring = LockFreeRing::<u32>::new(8);

        let items = [1, 2, 3, 4, 5];
        let count = ring.enqueue_batch(&items);
        assert_eq!(count, 5);
        assert_eq!(ring.len(), 5);

        let mut out = [0u32; 10];
        let count = ring.dequeue_batch(&mut out);
        assert_eq!(count, 5);
        assert_eq!(&out[..5], &items);
    }

    #[test]
    fn test_spsc_wrap() {
        let ring = LockFreeRing::<u32>::new(4);

        // Fill and empty multiple times to test wrapping
        for round in 0..10 {
            for i in 0..4 {
                ring.enqueue(round * 4 + i).unwrap();
            }
            for i in 0..4 {
                assert_eq!(ring.dequeue(), Some(round * 4 + i));
            }
        }
    }

    #[test]
    fn test_spsc_threaded() {
        let ring = Arc::new(LockFreeRing::<u64>::new(1024));
        let ring_producer = Arc::clone(&ring);
        let ring_consumer = Arc::clone(&ring);

        let count = 100_000u64;

        let producer = thread::spawn(move || {
            for i in 0..count {
                while ring_producer.enqueue(i).is_err() {
                    std::hint::spin_loop();
                }
            }
        });

        let consumer = thread::spawn(move || {
            let mut received = 0u64;
            let mut last = 0u64;
            while received < count {
                if let Some(v) = ring_consumer.dequeue() {
                    // Values should be in order
                    assert!(v >= last, "out of order: {} < {}", v, last);
                    last = v;
                    received += 1;
                } else {
                    std::hint::spin_loop();
                }
            }
        });

        producer.join().unwrap();
        consumer.join().unwrap();
    }

    #[test]
    fn test_capacity_rounding() {
        let ring = LockFreeRing::<u32>::new(3);
        assert_eq!(ring.capacity(), 4); // Rounded to next power of 2

        let ring = LockFreeRing::<u32>::new(5);
        assert_eq!(ring.capacity(), 8);

        let ring = LockFreeRing::<u32>::new(1024);
        assert_eq!(ring.capacity(), 1024);
    }

    #[test]
    fn test_peek() {
        let ring = LockFreeRing::<u32>::new(4);

        unsafe {
            assert!(ring.peek().is_none());
        }

        ring.enqueue(42).unwrap();

        unsafe {
            assert_eq!(ring.peek(), Some(&42));
            assert_eq!(ring.peek(), Some(&42)); // Peek doesn't consume
        }

        assert_eq!(ring.dequeue(), Some(42));
    }

    #[test]
    fn test_mpmc_basic() {
        let ring = MpmcRing::<u32>::new(4);

        ring.enqueue(1).unwrap();
        ring.enqueue(2).unwrap();

        assert_eq!(ring.dequeue(), Some(1));
        assert_eq!(ring.dequeue(), Some(2));
        assert_eq!(ring.dequeue(), None);
    }
}
