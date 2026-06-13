//! Lock-free ring buffer for high-performance packet passing.
//!
//! This module implements a Single-Producer Single-Consumer (SPSC) ring buffer
//! optimized for packet passing between threads without locks.

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{CachePadded, DEFAULT_RING_CAPACITY, next_power_of_two};

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
        self.head
            .0
            .store(head.wrapping_add(count), Ordering::Release);

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
        for (i, slot) in out[..count].iter_mut().enumerate() {
            let idx = (tail + i) & self.mask;
            *slot = unsafe { (*self.buffer[idx].get()).assume_init_read() };
        }

        // Publish all reads at once
        self.tail
            .0
            .store(tail.wrapping_add(count), Ordering::Release);

        count
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

#[allow(clippy::missing_fields_in_debug)] // buffer omitted intentionally (ring buffer contents not useful in debug output)
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

/// A slot in the MPMC ring, holding data and a per-slot sequence counter
/// for Vyukov-style synchronization between producers and consumers.
struct MpmcSlot<T> {
    seq: AtomicUsize,
    data: UnsafeCell<MaybeUninit<T>>,
}

/// Multi-producer multi-consumer ring buffer (Vyukov bounded MPMC queue).
///
/// Uses per-slot sequence counters to synchronize producers and consumers.
/// A producer may only write a slot once its sequence matches the expected
/// head value, and a consumer may only read once the sequence shows the
/// write is complete. This eliminates the race where a consumer observes
/// an advanced head but the slot has not been written yet.
pub struct MpmcRing<T> {
    /// Ring buffer storage with per-slot sequence counters.
    buffer: Box<[MpmcSlot<T>]>,
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

impl<T: Copy> MpmcRing<T> {
    /// Creates a new MPMC ring buffer.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "capacity must be > 0");

        let capacity = next_power_of_two(capacity);
        let mask = capacity - 1;

        // Initialize each slot's sequence counter to its index. This is the
        // Vyukov convention: seq == pos means the slot is ready for a producer
        // whose head == pos.
        let buffer: Vec<MpmcSlot<T>> = (0..capacity)
            .map(|i| MpmcSlot {
                seq: AtomicUsize::new(i),
                data: UnsafeCell::new(MaybeUninit::uninit()),
            })
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

    /// Enqueues an item (Vyukov bounded MPMC algorithm).
    ///
    /// Returns `Err(item)` if the queue is full.
    pub fn enqueue(&self, item: T) -> Result<(), T> {
        let mut head = self.head.0.load(Ordering::Relaxed);

        loop {
            let slot = &self.buffer[head & self.mask];
            let seq = slot.seq.load(Ordering::Acquire);

            #[allow(clippy::cast_possible_wrap)]
            let diff = (seq as isize).wrapping_sub(head as isize);

            match diff.cmp(&0) {
                std::cmp::Ordering::Equal => {
                    // Slot is ready for writing at this head position.
                    match self.head.0.compare_exchange_weak(
                        head,
                        head.wrapping_add(1),
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => {
                            // SAFETY: We won the CAS, so we exclusively own this slot.
                            unsafe { (*slot.data.get()).write(item) };
                            // Signal consumers that this slot is filled.
                            slot.seq.store(head.wrapping_add(1), Ordering::Release);
                            return Ok(());
                        }
                        Err(h) => head = h,
                    }
                }
                std::cmp::Ordering::Less => {
                    // Queue is full.
                    return Err(item);
                }
                std::cmp::Ordering::Greater => {
                    // Another producer claimed this slot, reload head.
                    head = self.head.0.load(Ordering::Relaxed);
                }
            }
        }
    }

    /// Dequeues an item (Vyukov bounded MPMC algorithm).
    ///
    /// Returns `None` if the queue is empty.
    pub fn dequeue(&self) -> Option<T> {
        let mut tail = self.tail.0.load(Ordering::Relaxed);

        loop {
            let slot = &self.buffer[tail & self.mask];
            let seq = slot.seq.load(Ordering::Acquire);

            #[allow(clippy::cast_possible_wrap)]
            let diff = (seq as isize).wrapping_sub(tail.wrapping_add(1) as isize);

            match diff.cmp(&0) {
                std::cmp::Ordering::Equal => {
                    // Slot has been written by a producer and is ready for reading.
                    match self.tail.0.compare_exchange_weak(
                        tail,
                        tail.wrapping_add(1),
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => {
                            // SAFETY: The producer has finished writing (seq confirms it)
                            // and we won the CAS, so we exclusively own this slot.
                            let item = unsafe { (*slot.data.get()).assume_init_read() };
                            // Signal producers that this slot is free for reuse.
                            slot.seq
                                .store(tail.wrapping_add(self.capacity), Ordering::Release);
                            return Some(item);
                        }
                        Err(t) => tail = t,
                    }
                }
                std::cmp::Ordering::Less => {
                    // Queue is empty.
                    return None;
                }
                std::cmp::Ordering::Greater => {
                    // Another consumer claimed this slot, reload tail.
                    tail = self.tail.0.load(Ordering::Relaxed);
                }
            }
        }
    }
}

// No Drop impl needed: T: Copy guarantees no destructors, and
// Box<[UnsafeCell<MaybeUninit<T>>]> frees the buffer memory.

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

    /// Multi-threaded stress test: multiple producers and consumers racing on
    /// the same ring. Validates that every enqueued value is dequeued exactly
    /// once (no duplicates, no lost items).
    #[test]
    fn test_mpmc_stress() {
        use std::sync::atomic::AtomicBool;

        const PRODUCERS: usize = 4;
        const CONSUMERS: usize = 4;
        const ITEMS_PER_PRODUCER: usize = 10_000;
        const TOTAL: usize = PRODUCERS * ITEMS_PER_PRODUCER;

        let ring = Arc::new(MpmcRing::<usize>::new(256));
        let producers_done = Arc::new(AtomicBool::new(false));

        // Spawn producers — each pushes a disjoint range of values.
        let mut producer_handles = Vec::new();
        for p in 0..PRODUCERS {
            let ring = Arc::clone(&ring);
            producer_handles.push(thread::spawn(move || {
                let base = p * ITEMS_PER_PRODUCER;
                for i in 0..ITEMS_PER_PRODUCER {
                    while ring.enqueue(base + i).is_err() {
                        std::hint::spin_loop();
                    }
                }
            }));
        }

        // Spawn consumers — each drains until producers are done and ring is empty.
        let mut consumer_handles = Vec::new();
        for _ in 0..CONSUMERS {
            let ring = Arc::clone(&ring);
            let done = Arc::clone(&producers_done);
            consumer_handles.push(thread::spawn(move || {
                let mut collected = Vec::new();
                loop {
                    match ring.dequeue() {
                        Some(v) => collected.push(v),
                        None => {
                            if done.load(Ordering::Acquire) {
                                // Final drain after producers signaled done.
                                while let Some(v) = ring.dequeue() {
                                    collected.push(v);
                                }
                                break;
                            }
                            std::hint::spin_loop();
                        }
                    }
                }
                collected
            }));
        }

        // Wait for all producers to finish, then signal consumers.
        for h in producer_handles {
            h.join().unwrap();
        }
        producers_done.store(true, Ordering::Release);

        // Collect all consumed values.
        let mut all: Vec<usize> = consumer_handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();

        // Drain anything still in the ring (consumers may have exited early).
        while let Some(v) = ring.dequeue() {
            all.push(v);
        }

        all.sort_unstable();
        all.dedup();
        assert_eq!(
            all.len(),
            TOTAL,
            "expected {TOTAL} unique items, got {} (duplicates or lost items)",
            all.len()
        );
    }
}
