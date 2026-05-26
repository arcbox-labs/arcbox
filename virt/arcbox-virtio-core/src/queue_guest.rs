//! VirtQueue operations over guest physical memory.
//!
//! When running with a manual-execution hypervisor (KVM, Hypervisor.framework),
//! VirtIO queues live in guest RAM. This module provides zero-copy access to
//! descriptor tables, available rings, and used rings via direct host pointer
//! arithmetic.

use std::sync::atomic::{Ordering, fence};

/// A VirtIO split virtqueue backed by guest physical memory.
///
/// The queue addresses (desc, avail, used) are guest physical addresses
/// set by the guest driver during device initialization. The `ram_base`
/// pointer is the host virtual address corresponding to GPA 0.
pub struct GuestMemoryVirtQueue {
    /// Queue index within the device.
    queue_idx: u16,
    /// Queue size (number of descriptors).
    size: u16,
    /// GPA of the descriptor table.
    desc_gpa: u64,
    /// GPA of the available ring.
    avail_gpa: u64,
    /// GPA of the used ring.
    used_gpa: u64,
    /// Host base pointer (GPA 0 maps here).
    ram_base: *mut u8,
    /// Total guest RAM size (for bounds checking).
    ram_size: usize,
    /// Last processed available ring index.
    last_avail_idx: u16,
    /// Current used ring index.
    used_idx: u16,
    /// Whether event index feature is negotiated.
    event_idx: bool,
}

// SAFETY: The ram_base pointer is valid for the lifetime of the VM and
// synchronized through the vCPU exit/enter barrier. Only one thread
// processes a given queue at a time (the vCPU thread that received
// the QUEUE_NOTIFY exit).
unsafe impl Send for GuestMemoryVirtQueue {}
unsafe impl Sync for GuestMemoryVirtQueue {}

/// A descriptor from the virtqueue descriptor table.
#[derive(Debug, Clone, Copy)]
pub struct VirtqDesc {
    /// Guest physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer.
    pub len: u32,
    /// Descriptor flags (NEXT, WRITE, INDIRECT).
    pub flags: u16,
    /// Next descriptor index (if NEXT flag set).
    pub next: u16,
}

impl VirtqDesc {
    /// Whether this descriptor is writable by the device.
    pub fn is_write(&self) -> bool {
        self.flags & crate::queue::flags::WRITE != 0
    }

    /// Whether there is a next descriptor in the chain.
    pub fn has_next(&self) -> bool {
        self.flags & crate::queue::flags::NEXT != 0
    }
}

/// A chain of descriptors representing a single I/O request.
pub struct DescriptorChain {
    /// Index of the head descriptor.
    pub head_idx: u16,
    /// All descriptors in the chain.
    pub descriptors: Vec<VirtqDesc>,
}

impl GuestMemoryVirtQueue {
    /// Creates a new guest memory virtqueue.
    ///
    /// # Safety
    ///
    /// `ram_base` must point to a valid allocation of at least `ram_size` bytes
    /// that remains valid for the lifetime of this queue.
    pub unsafe fn new(
        queue_idx: u16,
        size: u16,
        desc_gpa: u64,
        avail_gpa: u64,
        used_gpa: u64,
        ram_base: *mut u8,
        ram_size: usize,
    ) -> Self {
        Self {
            queue_idx,
            size,
            desc_gpa,
            avail_gpa,
            used_gpa,
            ram_base,
            ram_size,
            last_avail_idx: 0,
            used_idx: 0,
            event_idx: false,
        }
    }

    /// Enables event index feature (VIRTIO_F_EVENT_IDX).
    pub fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
    }

    /// Returns the queue index.
    pub fn queue_idx(&self) -> u16 {
        self.queue_idx
    }

    /// Translates a GPA to a host pointer. Returns None if out of bounds.
    fn gpa_to_ptr(&self, gpa: u64) -> Option<*mut u8> {
        let offset = gpa as usize;
        if offset < self.ram_size {
            Some(unsafe { self.ram_base.add(offset) })
        } else {
            None
        }
    }

    /// Reads a u16 from guest memory at the given GPA.
    fn read_u16(&self, gpa: u64) -> Option<u16> {
        let ptr = self.gpa_to_ptr(gpa)?;
        if gpa as usize + 2 > self.ram_size {
            return None;
        }
        // SAFETY: bounds checked above, alignment not required for MMIO memory.
        Some(unsafe { (ptr as *const u16).read_unaligned() })
    }

    /// Reads a u32 from guest memory.
    fn read_u32(&self, gpa: u64) -> Option<u32> {
        let ptr = self.gpa_to_ptr(gpa)?;
        if gpa as usize + 4 > self.ram_size {
            return None;
        }
        Some(unsafe { (ptr as *const u32).read_unaligned() })
    }

    /// Reads a u64 from guest memory.
    fn read_u64(&self, gpa: u64) -> Option<u64> {
        let ptr = self.gpa_to_ptr(gpa)?;
        if gpa as usize + 8 > self.ram_size {
            return None;
        }
        Some(unsafe { (ptr as *const u64).read_unaligned() })
    }

    /// Writes a u16 to guest memory.
    fn write_u16(&self, gpa: u64, val: u16) -> bool {
        if let Some(ptr) = self.gpa_to_ptr(gpa) {
            if gpa as usize + 2 <= self.ram_size {
                unsafe { (ptr as *mut u16).write_unaligned(val) };
                return true;
            }
        }
        false
    }

    /// Writes a u32 to guest memory.
    fn write_u32(&self, gpa: u64, val: u32) -> bool {
        if let Some(ptr) = self.gpa_to_ptr(gpa) {
            if gpa as usize + 4 <= self.ram_size {
                unsafe { (ptr as *mut u32).write_unaligned(val) };
                return true;
            }
        }
        false
    }

    /// Reads a descriptor from the descriptor table.
    fn read_descriptor(&self, idx: u16) -> Option<VirtqDesc> {
        if idx >= self.size {
            return None;
        }
        // Each descriptor is 16 bytes: addr(8) + len(4) + flags(2) + next(2)
        let desc_offset = self.desc_gpa + u64::from(idx) * 16;
        Some(VirtqDesc {
            addr: self.read_u64(desc_offset)?,
            len: self.read_u32(desc_offset + 8)?,
            flags: self.read_u16(desc_offset + 12)?,
            next: self.read_u16(desc_offset + 14)?,
        })
    }

    /// Reads the available ring index.
    fn avail_idx(&self) -> u16 {
        // avail ring layout: flags(2) + idx(2) + ring[size](2*size) + used_event(2)
        self.read_u16(self.avail_gpa + 2).unwrap_or(0)
    }

    /// Reads the available ring entry at position `pos`.
    fn avail_ring_entry(&self, pos: u16) -> u16 {
        let offset = self.avail_gpa + 4 + u64::from(pos % self.size) * 2;
        self.read_u16(offset).unwrap_or(0)
    }

    /// Returns whether there are available descriptors to process.
    pub fn has_avail(&self) -> bool {
        fence(Ordering::Acquire);
        self.avail_idx() != self.last_avail_idx
    }

    /// Pops the next available descriptor chain.
    pub fn pop_avail(&mut self) -> Option<DescriptorChain> {
        fence(Ordering::Acquire);

        let avail_idx = self.avail_idx();
        if avail_idx == self.last_avail_idx {
            return None;
        }

        let head_idx = self.avail_ring_entry(self.last_avail_idx);
        self.last_avail_idx = self.last_avail_idx.wrapping_add(1);

        // Walk the descriptor chain
        let mut descriptors = Vec::new();
        let mut idx = head_idx;
        let mut count = 0u16;

        loop {
            if count >= self.size {
                tracing::warn!("Descriptor chain loop detected in queue {}", self.queue_idx);
                break;
            }

            let desc = self.read_descriptor(idx)?;
            descriptors.push(desc);
            count += 1;

            if !desc.has_next() {
                break;
            }
            idx = desc.next;
        }

        Some(DescriptorChain {
            head_idx,
            descriptors,
        })
    }

    /// Pushes a used buffer notification.
    pub fn push_used(&mut self, head_idx: u16, len: u32) {
        // used ring layout: flags(2) + idx(2) + ring[size](id(4)+len(4)*size) + avail_event(2)
        let used_ring_offset = self.used_gpa + 4 + u64::from(self.used_idx % self.size) * 8;
        self.write_u32(used_ring_offset, u32::from(head_idx));
        self.write_u32(used_ring_offset + 4, len);

        self.used_idx = self.used_idx.wrapping_add(1);

        fence(Ordering::Release);
        // Write the used index
        self.write_u16(self.used_gpa + 2, self.used_idx);
    }

    /// Pushes multiple used buffers with a single index update.
    pub fn push_used_batch(&mut self, completions: &[(u16, u32)]) {
        for &(head_idx, len) in completions {
            let used_ring_offset = self.used_gpa + 4 + u64::from(self.used_idx % self.size) * 8;
            self.write_u32(used_ring_offset, u32::from(head_idx));
            self.write_u32(used_ring_offset + 4, len);
            self.used_idx = self.used_idx.wrapping_add(1);
        }

        fence(Ordering::Release);
        self.write_u16(self.used_gpa + 2, self.used_idx);
    }

    /// Reads bytes from a guest buffer into a host Vec.
    pub fn read_buffer(&self, gpa: u64, len: u32) -> Option<Vec<u8>> {
        let len = len as usize;
        let ptr = self.gpa_to_ptr(gpa)?;
        if gpa as usize + len > self.ram_size {
            return None;
        }
        let mut buf = vec![0u8; len];
        unsafe {
            std::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), len);
        }
        Some(buf)
    }

    /// Writes bytes from a host buffer into guest memory.
    pub fn write_buffer(&self, gpa: u64, data: &[u8]) -> bool {
        if let Some(ptr) = self.gpa_to_ptr(gpa) {
            if gpa as usize + data.len() <= self.ram_size {
                unsafe {
                    std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
                }
                return true;
            }
        }
        false
    }

    /// Returns a raw host pointer for zero-copy access to a guest buffer.
    ///
    /// # Safety
    ///
    /// The caller must ensure no concurrent modifications to the same guest
    /// memory region and that the returned pointer is not used after the
    /// queue (and its backing RAM) is dropped.
    pub unsafe fn guest_slice(&self, gpa: u64, len: usize) -> Option<&[u8]> {
        let ptr = self.gpa_to_ptr(gpa)?;
        if gpa as usize + len > self.ram_size {
            return None;
        }
        // SAFETY: bounds checked above, caller guarantees no concurrent writes.
        Some(unsafe { std::slice::from_raw_parts(ptr, len) })
    }

    /// Returns a mutable raw host pointer for zero-copy write access.
    ///
    /// # Safety
    ///
    /// Same requirements as `guest_slice`, plus exclusive access guarantee.
    pub unsafe fn guest_slice_mut(&mut self, gpa: u64, len: usize) -> Option<&mut [u8]> {
        let ptr = self.gpa_to_ptr(gpa)?;
        if gpa as usize + len > self.ram_size {
            return None;
        }
        // SAFETY: bounds checked above, caller guarantees exclusive access.
        Some(unsafe { std::slice::from_raw_parts_mut(ptr, len) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{Layout, alloc_zeroed, dealloc};

    /// Size of our fake guest RAM for tests (64 KiB).
    const TEST_RAM_SIZE: usize = 64 * 1024;
    /// Queue size used in tests.
    const TEST_QUEUE_SIZE: u16 = 16;

    // Layout constants for the virtqueue structures within the test RAM.
    // Descriptor table starts at GPA 0x1000.
    const DESC_TABLE_GPA: u64 = 0x1000;
    // Available ring starts at GPA 0x2000.
    const AVAIL_RING_GPA: u64 = 0x2000;
    // Used ring starts at GPA 0x3000.
    const USED_RING_GPA: u64 = 0x3000;
    // Data buffer region starts at GPA 0x4000.
    const DATA_BUFFER_GPA: u64 = 0x4000;

    /// RAII wrapper for test guest memory allocation.
    struct TestGuestMemory {
        ptr: *mut u8,
        layout: Layout,
    }

    impl TestGuestMemory {
        fn new() -> Self {
            let layout = Layout::from_size_align(TEST_RAM_SIZE, 4096).unwrap();
            let ptr = unsafe { alloc_zeroed(layout) };
            assert!(!ptr.is_null(), "Failed to allocate test guest memory");
            Self { ptr, layout }
        }

        fn as_mut_ptr(&self) -> *mut u8 {
            self.ptr
        }

        /// Writes a u16 at the given GPA offset within the test RAM.
        fn write_u16(&self, gpa: u64, val: u16) {
            let offset = gpa as usize;
            assert!(offset + 2 <= TEST_RAM_SIZE);
            unsafe {
                (self.ptr.add(offset) as *mut u16).write_unaligned(val);
            }
        }

        /// Writes a u32 at the given GPA offset.
        fn write_u32(&self, gpa: u64, val: u32) {
            let offset = gpa as usize;
            assert!(offset + 4 <= TEST_RAM_SIZE);
            unsafe {
                (self.ptr.add(offset) as *mut u32).write_unaligned(val);
            }
        }

        /// Writes a u64 at the given GPA offset.
        fn write_u64(&self, gpa: u64, val: u64) {
            let offset = gpa as usize;
            assert!(offset + 8 <= TEST_RAM_SIZE);
            unsafe {
                (self.ptr.add(offset) as *mut u64).write_unaligned(val);
            }
        }

        /// Reads a u16 from the given GPA offset.
        fn read_u16(&self, gpa: u64) -> u16 {
            let offset = gpa as usize;
            assert!(offset + 2 <= TEST_RAM_SIZE);
            unsafe { (self.ptr.add(offset) as *const u16).read_unaligned() }
        }

        /// Reads a u32 from the given GPA offset.
        fn read_u32(&self, gpa: u64) -> u32 {
            let offset = gpa as usize;
            assert!(offset + 4 <= TEST_RAM_SIZE);
            unsafe { (self.ptr.add(offset) as *const u32).read_unaligned() }
        }

        /// Writes a descriptor into the descriptor table at the given index.
        fn write_descriptor(&self, idx: u16, addr: u64, len: u32, flags: u16, next: u16) {
            let base = DESC_TABLE_GPA + u64::from(idx) * 16;
            self.write_u64(base, addr);
            self.write_u32(base + 8, len);
            self.write_u16(base + 12, flags);
            self.write_u16(base + 14, next);
        }

        /// Sets the available ring index.
        fn set_avail_idx(&self, idx: u16) {
            // avail ring: flags(2) + idx(2)
            self.write_u16(AVAIL_RING_GPA + 2, idx);
        }

        /// Sets an entry in the available ring.
        fn set_avail_ring_entry(&self, pos: u16, desc_idx: u16) {
            let offset = AVAIL_RING_GPA + 4 + u64::from(pos % TEST_QUEUE_SIZE) * 2;
            self.write_u16(offset, desc_idx);
        }

        /// Writes data bytes at a GPA.
        fn write_bytes(&self, gpa: u64, data: &[u8]) {
            let offset = gpa as usize;
            assert!(offset + data.len() <= TEST_RAM_SIZE);
            unsafe {
                std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(offset), data.len());
            }
        }

        /// Reads data bytes from a GPA.
        fn read_bytes(&self, gpa: u64, len: usize) -> Vec<u8> {
            let offset = gpa as usize;
            assert!(offset + len <= TEST_RAM_SIZE);
            let mut buf = vec![0u8; len];
            unsafe {
                std::ptr::copy_nonoverlapping(self.ptr.add(offset), buf.as_mut_ptr(), len);
            }
            buf
        }
    }

    impl Drop for TestGuestMemory {
        fn drop(&mut self) {
            unsafe {
                dealloc(self.ptr, self.layout);
            }
        }
    }

    /// Creates a GuestMemoryVirtQueue backed by the test memory.
    fn create_test_queue(mem: &TestGuestMemory) -> GuestMemoryVirtQueue {
        unsafe {
            GuestMemoryVirtQueue::new(
                0,
                TEST_QUEUE_SIZE,
                DESC_TABLE_GPA,
                AVAIL_RING_GPA,
                USED_RING_GPA,
                mem.as_mut_ptr(),
                TEST_RAM_SIZE,
            )
        }
    }

    // ======================================================================
    // Descriptor chain walking
    // ======================================================================

    #[test]
    fn test_single_descriptor_chain() {
        let mem = TestGuestMemory::new();

        // Write a single descriptor (no NEXT flag)
        mem.write_descriptor(0, DATA_BUFFER_GPA, 256, 0, 0);

        // Make it available
        mem.set_avail_ring_entry(0, 0);
        mem.set_avail_idx(1);

        let mut queue = create_test_queue(&mem);

        assert!(queue.has_avail());
        let chain = queue.pop_avail().unwrap();
        assert_eq!(chain.head_idx, 0);
        assert_eq!(chain.descriptors.len(), 1);
        assert_eq!(chain.descriptors[0].addr, DATA_BUFFER_GPA);
        assert_eq!(chain.descriptors[0].len, 256);
        assert!(!chain.descriptors[0].has_next());
    }

    #[test]
    fn test_chained_descriptors() {
        let mem = TestGuestMemory::new();

        // Chain: desc 0 -> desc 1 -> desc 2
        let next_flag = crate::queue::flags::NEXT;
        mem.write_descriptor(0, DATA_BUFFER_GPA, 128, next_flag, 1);
        mem.write_descriptor(1, DATA_BUFFER_GPA + 128, 256, next_flag, 2);
        mem.write_descriptor(2, DATA_BUFFER_GPA + 384, 512, 0, 0);

        mem.set_avail_ring_entry(0, 0);
        mem.set_avail_idx(1);

        let mut queue = create_test_queue(&mem);
        let chain = queue.pop_avail().unwrap();

        assert_eq!(chain.head_idx, 0);
        assert_eq!(chain.descriptors.len(), 3);
        assert_eq!(chain.descriptors[0].addr, DATA_BUFFER_GPA);
        assert_eq!(chain.descriptors[0].len, 128);
        assert!(chain.descriptors[0].has_next());
        assert_eq!(chain.descriptors[1].addr, DATA_BUFFER_GPA + 128);
        assert_eq!(chain.descriptors[1].len, 256);
        assert!(chain.descriptors[1].has_next());
        assert_eq!(chain.descriptors[2].addr, DATA_BUFFER_GPA + 384);
        assert_eq!(chain.descriptors[2].len, 512);
        assert!(!chain.descriptors[2].has_next());
    }

    #[test]
    fn test_write_descriptor_flag() {
        let mem = TestGuestMemory::new();

        // Descriptor with WRITE flag (device-writable buffer)
        let write_flag = crate::queue::flags::WRITE;
        mem.write_descriptor(0, DATA_BUFFER_GPA, 1024, write_flag, 0);

        mem.set_avail_ring_entry(0, 0);
        mem.set_avail_idx(1);

        let mut queue = create_test_queue(&mem);
        let chain = queue.pop_avail().unwrap();

        assert!(chain.descriptors[0].is_write());
        assert!(!chain.descriptors[0].has_next());
    }

    // ======================================================================
    // pop_avail / push_used ring operations
    // ======================================================================

    #[test]
    fn test_pop_avail_empty() {
        let mem = TestGuestMemory::new();
        let mut queue = create_test_queue(&mem);

        // No descriptors available
        assert!(!queue.has_avail());
        assert!(queue.pop_avail().is_none());
    }

    #[test]
    fn test_pop_avail_multiple() {
        let mem = TestGuestMemory::new();

        // Set up 3 independent descriptors
        mem.write_descriptor(0, DATA_BUFFER_GPA, 100, 0, 0);
        mem.write_descriptor(1, DATA_BUFFER_GPA + 0x100, 200, 0, 0);
        mem.write_descriptor(2, DATA_BUFFER_GPA + 0x200, 300, 0, 0);

        mem.set_avail_ring_entry(0, 0);
        mem.set_avail_ring_entry(1, 1);
        mem.set_avail_ring_entry(2, 2);
        mem.set_avail_idx(3);

        let mut queue = create_test_queue(&mem);

        // Pop all three
        for i in 0..3 {
            assert!(queue.has_avail());
            let chain = queue.pop_avail().unwrap();
            assert_eq!(chain.head_idx, i);
            assert_eq!(chain.descriptors.len(), 1);
        }

        // No more available
        assert!(!queue.has_avail());
        assert!(queue.pop_avail().is_none());
    }

    #[test]
    fn test_push_used_single() {
        let mem = TestGuestMemory::new();
        let mut queue = create_test_queue(&mem);

        queue.push_used(5, 1024);

        // Verify used ring: used index should be 1
        let used_idx = mem.read_u16(USED_RING_GPA + 2);
        assert_eq!(used_idx, 1);

        // Verify used ring entry: id=5, len=1024
        let used_id = mem.read_u32(USED_RING_GPA + 4);
        let used_len = mem.read_u32(USED_RING_GPA + 8);
        assert_eq!(used_id, 5);
        assert_eq!(used_len, 1024);
    }

    #[test]
    fn test_push_used_wrapping() {
        let mem = TestGuestMemory::new();
        let mut queue = create_test_queue(&mem);

        // Push more than queue size entries to verify wrapping
        for i in 0..TEST_QUEUE_SIZE + 2 {
            queue.push_used(i, i as u32 * 100);
        }

        let used_idx = mem.read_u16(USED_RING_GPA + 2);
        assert_eq!(used_idx, TEST_QUEUE_SIZE + 2);
    }

    #[test]
    fn test_pop_and_push_roundtrip() {
        let mem = TestGuestMemory::new();

        // Set up a descriptor
        mem.write_descriptor(3, DATA_BUFFER_GPA, 512, 0, 0);
        mem.set_avail_ring_entry(0, 3);
        mem.set_avail_idx(1);

        let mut queue = create_test_queue(&mem);

        // Pop the available descriptor
        let chain = queue.pop_avail().unwrap();
        assert_eq!(chain.head_idx, 3);

        // Push it to the used ring
        queue.push_used(chain.head_idx, 512);

        // Verify used ring
        let used_idx = mem.read_u16(USED_RING_GPA + 2);
        assert_eq!(used_idx, 1);
        let used_id = mem.read_u32(USED_RING_GPA + 4);
        assert_eq!(used_id, 3);
    }

    // ======================================================================
    // Batch push
    // ======================================================================

    #[test]
    fn test_push_used_batch() {
        let mem = TestGuestMemory::new();
        let mut queue = create_test_queue(&mem);

        let completions = [(0, 100), (1, 200), (2, 300)];
        queue.push_used_batch(&completions);

        // Verify used index
        let used_idx = mem.read_u16(USED_RING_GPA + 2);
        assert_eq!(used_idx, 3);

        // Verify each entry
        for (i, &(id, len)) in completions.iter().enumerate() {
            let entry_offset = USED_RING_GPA + 4 + (i as u64) * 8;
            let entry_id = mem.read_u32(entry_offset);
            let entry_len = mem.read_u32(entry_offset + 4);
            assert_eq!(entry_id, u32::from(id));
            assert_eq!(entry_len, len);
        }
    }

    #[test]
    fn test_push_used_batch_empty() {
        let mem = TestGuestMemory::new();
        let mut queue = create_test_queue(&mem);

        queue.push_used_batch(&[]);

        // Used index should still be 0
        let used_idx = mem.read_u16(USED_RING_GPA + 2);
        assert_eq!(used_idx, 0);
    }

    // ======================================================================
    // Bounds checking
    // ======================================================================

    #[test]
    fn test_gpa_out_of_bounds_read_buffer() {
        let mem = TestGuestMemory::new();
        let queue = create_test_queue(&mem);

        // Try to read from a GPA beyond RAM size
        let result = queue.read_buffer(TEST_RAM_SIZE as u64, 100);
        assert!(result.is_none());
    }

    #[test]
    fn test_gpa_out_of_bounds_write_buffer() {
        let mem = TestGuestMemory::new();
        let queue = create_test_queue(&mem);

        // Try to write to a GPA beyond RAM size
        let data = [0xAA; 100];
        let result = queue.write_buffer(TEST_RAM_SIZE as u64, &data);
        assert!(!result);
    }

    #[test]
    fn test_gpa_partial_out_of_bounds() {
        let mem = TestGuestMemory::new();
        let queue = create_test_queue(&mem);

        // Start within bounds, but extends beyond
        let gpa = (TEST_RAM_SIZE - 10) as u64;
        let result = queue.read_buffer(gpa, 100);
        assert!(result.is_none());
    }

    #[test]
    fn test_guest_slice_out_of_bounds() {
        let mem = TestGuestMemory::new();
        let mut queue = create_test_queue(&mem);

        let result = unsafe { queue.guest_slice(TEST_RAM_SIZE as u64, 1) };
        assert!(result.is_none());

        let result = unsafe { queue.guest_slice_mut(TEST_RAM_SIZE as u64, 1) };
        assert!(result.is_none());
    }

    // ======================================================================
    // read_buffer / write_buffer
    // ======================================================================

    #[test]
    fn test_read_buffer() {
        let mem = TestGuestMemory::new();
        let queue = create_test_queue(&mem);

        // Write test data into guest memory
        let test_data = b"Hello, VirtIO!";
        mem.write_bytes(DATA_BUFFER_GPA, test_data);

        // Read it back via the queue
        let result = queue.read_buffer(DATA_BUFFER_GPA, test_data.len() as u32);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), test_data);
    }

    #[test]
    fn test_write_buffer() {
        let mem = TestGuestMemory::new();
        let queue = create_test_queue(&mem);

        // Write data via the queue
        let test_data = b"Device response";
        let success = queue.write_buffer(DATA_BUFFER_GPA, test_data);
        assert!(success);

        // Verify by reading from the raw memory
        let readback = mem.read_bytes(DATA_BUFFER_GPA, test_data.len());
        assert_eq!(readback, test_data);
    }

    #[test]
    fn test_read_write_buffer_roundtrip() {
        let mem = TestGuestMemory::new();
        let queue = create_test_queue(&mem);

        // Write some data
        let original = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let success = queue.write_buffer(DATA_BUFFER_GPA, &original);
        assert!(success);

        // Read it back
        let readback = queue.read_buffer(DATA_BUFFER_GPA, original.len() as u32);
        assert_eq!(readback.unwrap(), original);
    }

    #[test]
    fn test_guest_slice_read() {
        let mem = TestGuestMemory::new();
        let queue = create_test_queue(&mem);

        let test_data = b"zero-copy read";
        mem.write_bytes(DATA_BUFFER_GPA, test_data);

        let slice = unsafe { queue.guest_slice(DATA_BUFFER_GPA, test_data.len()) };
        assert!(slice.is_some());
        assert_eq!(slice.unwrap(), test_data);
    }

    #[test]
    fn test_guest_slice_mut_write() {
        let mem = TestGuestMemory::new();
        let mut queue = create_test_queue(&mem);

        let slice = unsafe { queue.guest_slice_mut(DATA_BUFFER_GPA, 5) };
        assert!(slice.is_some());
        let slice = slice.unwrap();
        slice.copy_from_slice(b"ABCDE");

        // Verify via raw memory read
        let readback = mem.read_bytes(DATA_BUFFER_GPA, 5);
        assert_eq!(readback, b"ABCDE");
    }

    // ======================================================================
    // Queue index and event_idx accessors
    // ======================================================================

    #[test]
    fn test_queue_idx_accessor() {
        let mem = TestGuestMemory::new();
        let queue = unsafe {
            GuestMemoryVirtQueue::new(
                7,
                TEST_QUEUE_SIZE,
                DESC_TABLE_GPA,
                AVAIL_RING_GPA,
                USED_RING_GPA,
                mem.as_mut_ptr(),
                TEST_RAM_SIZE,
            )
        };
        assert_eq!(queue.queue_idx(), 7);
    }

    #[test]
    fn test_event_idx_toggle() {
        let mem = TestGuestMemory::new();
        let mut queue = create_test_queue(&mem);

        assert!(!queue.event_idx);
        queue.set_event_idx(true);
        assert!(queue.event_idx);
        queue.set_event_idx(false);
        assert!(!queue.event_idx);
    }

    // ======================================================================
    // Descriptor chain loop detection
    // ======================================================================

    #[test]
    fn test_descriptor_chain_loop_terminates() {
        let mem = TestGuestMemory::new();

        // Create a loop: desc 0 -> desc 1 -> desc 0
        let next_flag = crate::queue::flags::NEXT;
        mem.write_descriptor(0, DATA_BUFFER_GPA, 64, next_flag, 1);
        mem.write_descriptor(1, DATA_BUFFER_GPA + 64, 64, next_flag, 0);

        mem.set_avail_ring_entry(0, 0);
        mem.set_avail_idx(1);

        let mut queue = create_test_queue(&mem);
        let chain = queue.pop_avail().unwrap();

        // Should stop after at most `size` descriptors (loop detection)
        assert!(chain.descriptors.len() <= TEST_QUEUE_SIZE as usize);
    }
}
