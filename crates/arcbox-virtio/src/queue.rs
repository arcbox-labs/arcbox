//! VirtIO queue (virtqueue) implementation.
//!
//! This module provides the core virtqueue data structures used for
//! communication between the guest driver and host device.

use crate::error::{Result, VirtioError};

/// Descriptor flags.
pub mod flags {
    /// Descriptor continues via next field.
    pub const NEXT: u16 = 1;
    /// Buffer is write-only (for device).
    pub const WRITE: u16 = 2;
    /// Buffer contains a list of descriptors.
    pub const INDIRECT: u16 = 4;
}

/// A single descriptor in the descriptor table.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Descriptor {
    /// Guest physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer.
    pub len: u32,
    /// Descriptor flags.
    pub flags: u16,
    /// Next descriptor index (if NEXT flag is set).
    pub next: u16,
}

impl Descriptor {
    /// Checks if this descriptor has the NEXT flag.
    #[must_use]
    pub fn has_next(&self) -> bool {
        self.flags & flags::NEXT != 0
    }

    /// Checks if this descriptor is write-only.
    #[must_use]
    pub fn is_write_only(&self) -> bool {
        self.flags & flags::WRITE != 0
    }

    /// Checks if this descriptor is indirect.
    #[must_use]
    pub fn is_indirect(&self) -> bool {
        self.flags & flags::INDIRECT != 0
    }
}

/// Available ring structure.
#[derive(Debug)]
pub struct AvailRing {
    /// Flags (e.g., no interrupt).
    pub flags: u16,
    /// Index of the next entry to add.
    pub idx: u16,
    /// Ring of descriptor indices.
    pub ring: Vec<u16>,
    /// Used event (for event suppression).
    pub used_event: u16,
}

impl AvailRing {
    /// Creates a new available ring.
    #[must_use]
    pub fn new(size: u16) -> Self {
        Self {
            flags: 0,
            idx: 0,
            ring: vec![0; size as usize],
            used_event: 0,
        }
    }
}

/// Used ring element.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct UsedElement {
    /// Descriptor chain head index.
    pub id: u32,
    /// Number of bytes written to the descriptor chain.
    pub len: u32,
}

/// Used ring structure.
#[derive(Debug)]
pub struct UsedRing {
    /// Flags (e.g., no notify).
    pub flags: u16,
    /// Index of the next entry to add.
    pub idx: u16,
    /// Ring of used elements.
    pub ring: Vec<UsedElement>,
    /// Avail event (for event suppression).
    pub avail_event: u16,
}

impl UsedRing {
    /// Creates a new used ring.
    #[must_use]
    pub fn new(size: u16) -> Self {
        Self {
            flags: 0,
            idx: 0,
            ring: vec![UsedElement::default(); size as usize],
            avail_event: 0,
        }
    }
}

/// VirtIO queue implementation.
#[derive(Debug)]
pub struct VirtQueue {
    /// Queue size (number of descriptors).
    size: u16,
    /// Descriptor table.
    desc_table: Vec<Descriptor>,
    /// Available ring.
    avail: AvailRing,
    /// Used ring.
    used: UsedRing,
    /// Last seen available index.
    last_avail_idx: u16,
    /// Whether the queue is ready.
    ready: bool,
}

impl VirtQueue {
    /// Creates a new virtqueue with the given size.
    ///
    /// # Errors
    ///
    /// Returns an error if the size is not a power of 2 or exceeds limits.
    pub fn new(size: u16) -> Result<Self> {
        if size == 0 || !size.is_power_of_two() {
            return Err(VirtioError::InvalidQueue(
                "size must be a power of 2".to_string(),
            ));
        }

        if size > 32768 {
            return Err(VirtioError::InvalidQueue(
                "size must not exceed 32768".to_string(),
            ));
        }

        Ok(Self {
            size,
            desc_table: vec![Descriptor::default(); size as usize],
            avail: AvailRing::new(size),
            used: UsedRing::new(size),
            last_avail_idx: 0,
            ready: false,
        })
    }

    /// Returns the queue size.
    #[must_use]
    pub fn size(&self) -> u16 {
        self.size
    }

    /// Returns whether the queue is ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    /// Sets the queue ready state.
    pub fn set_ready(&mut self, ready: bool) {
        self.ready = ready;
    }

    /// Checks if there are available descriptors.
    #[must_use]
    pub fn has_available(&self) -> bool {
        self.avail.idx != self.last_avail_idx
    }

    /// Pops the next available descriptor chain.
    ///
    /// Returns the head descriptor index and the descriptor chain.
    pub fn pop_avail(&mut self) -> Option<(u16, DescriptorChain)> {
        if !self.has_available() {
            return None;
        }

        let avail_idx = self.last_avail_idx;
        let head_idx = self.avail.ring[(avail_idx % self.size) as usize];
        self.last_avail_idx = self.last_avail_idx.wrapping_add(1);

        Some((
            head_idx,
            DescriptorChain {
                queue: self,
                current: Some(head_idx),
            },
        ))
    }

    /// Adds a used descriptor to the used ring.
    pub fn push_used(&mut self, head_idx: u16, len: u32) {
        let used_idx = self.used.idx;
        self.used.ring[(used_idx % self.size) as usize] = UsedElement {
            id: head_idx as u32,
            len,
        };
        self.used.idx = self.used.idx.wrapping_add(1);
    }

    /// Returns a reference to a descriptor.
    #[must_use]
    pub fn get_descriptor(&self, idx: u16) -> Option<&Descriptor> {
        self.desc_table.get(idx as usize)
    }
}

/// Iterator over a descriptor chain.
pub struct DescriptorChain<'a> {
    queue: &'a VirtQueue,
    current: Option<u16>,
}

impl<'a> Iterator for DescriptorChain<'a> {
    type Item = &'a Descriptor;

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.current?;
        let desc = self.queue.get_descriptor(idx)?;

        self.current = if desc.has_next() {
            Some(desc.next)
        } else {
            None
        };

        Some(desc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // Descriptor Tests
    // ==========================================================================

    #[test]
    fn test_descriptor_default() {
        let desc = Descriptor::default();
        assert_eq!(desc.addr, 0);
        assert_eq!(desc.len, 0);
        assert_eq!(desc.flags, 0);
        assert_eq!(desc.next, 0);
    }

    #[test]
    fn test_descriptor_has_next() {
        let mut desc = Descriptor::default();
        assert!(!desc.has_next());

        desc.flags = flags::NEXT;
        assert!(desc.has_next());
    }

    #[test]
    fn test_descriptor_is_write_only() {
        let mut desc = Descriptor::default();
        assert!(!desc.is_write_only());

        desc.flags = flags::WRITE;
        assert!(desc.is_write_only());
    }

    #[test]
    fn test_descriptor_is_indirect() {
        let mut desc = Descriptor::default();
        assert!(!desc.is_indirect());

        desc.flags = flags::INDIRECT;
        assert!(desc.is_indirect());
    }

    #[test]
    fn test_descriptor_multiple_flags() {
        let desc = Descriptor {
            addr: 0x1000,
            len: 512,
            flags: flags::NEXT | flags::WRITE,
            next: 1,
        };

        assert!(desc.has_next());
        assert!(desc.is_write_only());
        assert!(!desc.is_indirect());
    }

    #[test]
    fn test_descriptor_clone_copy() {
        let desc = Descriptor {
            addr: 0xDEADBEEF,
            len: 1234,
            flags: flags::NEXT,
            next: 42,
        };

        let cloned = desc.clone();
        let copied = desc; // Copy

        assert_eq!(cloned.addr, 0xDEADBEEF);
        assert_eq!(copied.addr, 0xDEADBEEF);
    }

    // ==========================================================================
    // Flag Constants Tests
    // ==========================================================================

    #[test]
    fn test_flag_constants() {
        assert_eq!(flags::NEXT, 1);
        assert_eq!(flags::WRITE, 2);
        assert_eq!(flags::INDIRECT, 4);
    }

    // ==========================================================================
    // AvailRing Tests
    // ==========================================================================

    #[test]
    fn test_avail_ring_new() {
        let ring = AvailRing::new(256);
        assert_eq!(ring.flags, 0);
        assert_eq!(ring.idx, 0);
        assert_eq!(ring.ring.len(), 256);
        assert_eq!(ring.used_event, 0);
    }

    #[test]
    fn test_avail_ring_small() {
        let ring = AvailRing::new(1);
        assert_eq!(ring.ring.len(), 1);
    }

    // ==========================================================================
    // UsedElement Tests
    // ==========================================================================

    #[test]
    fn test_used_element_default() {
        let elem = UsedElement::default();
        assert_eq!(elem.id, 0);
        assert_eq!(elem.len, 0);
    }

    #[test]
    fn test_used_element_clone_copy() {
        let elem = UsedElement { id: 42, len: 1024 };
        let cloned = elem.clone();
        let copied = elem; // Copy

        assert_eq!(cloned.id, 42);
        assert_eq!(copied.len, 1024);
    }

    // ==========================================================================
    // UsedRing Tests
    // ==========================================================================

    #[test]
    fn test_used_ring_new() {
        let ring = UsedRing::new(128);
        assert_eq!(ring.flags, 0);
        assert_eq!(ring.idx, 0);
        assert_eq!(ring.ring.len(), 128);
        assert_eq!(ring.avail_event, 0);
    }

    // ==========================================================================
    // VirtQueue Tests
    // ==========================================================================

    #[test]
    fn test_virtqueue_new() {
        let queue = VirtQueue::new(256).unwrap();
        assert_eq!(queue.size(), 256);
        assert!(!queue.is_ready());
    }

    #[test]
    fn test_virtqueue_new_power_of_two() {
        // Valid sizes
        for size in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
            assert!(VirtQueue::new(size).is_ok());
        }
    }

    #[test]
    fn test_virtqueue_new_invalid_size_zero() {
        let result = VirtQueue::new(0);
        assert!(result.is_err());
        if let Err(VirtioError::InvalidQueue(msg)) = result {
            assert!(msg.contains("power of 2"));
        }
    }

    #[test]
    fn test_virtqueue_new_invalid_size_not_power_of_two() {
        for size in [3, 5, 6, 7, 9, 100, 1000] {
            let result = VirtQueue::new(size);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_virtqueue_new_too_large() {
        let result = VirtQueue::new(32768); // Max allowed
        assert!(result.is_ok());

        // This would need 65536 which exceeds u16 anyway
        // Just test max size works
    }

    #[test]
    fn test_virtqueue_ready_state() {
        let mut queue = VirtQueue::new(16).unwrap();

        assert!(!queue.is_ready());
        queue.set_ready(true);
        assert!(queue.is_ready());
        queue.set_ready(false);
        assert!(!queue.is_ready());
    }

    #[test]
    fn test_virtqueue_has_available_empty() {
        let queue = VirtQueue::new(16).unwrap();
        assert!(!queue.has_available());
    }

    #[test]
    fn test_virtqueue_pop_avail_empty() {
        let mut queue = VirtQueue::new(16).unwrap();
        assert!(queue.pop_avail().is_none());
    }

    #[test]
    fn test_virtqueue_get_descriptor() {
        let queue = VirtQueue::new(16).unwrap();

        // Valid indices
        assert!(queue.get_descriptor(0).is_some());
        assert!(queue.get_descriptor(15).is_some());

        // Invalid indices
        assert!(queue.get_descriptor(16).is_none());
        assert!(queue.get_descriptor(100).is_none());
    }

    #[test]
    fn test_virtqueue_push_used() {
        let mut queue = VirtQueue::new(16).unwrap();

        queue.push_used(0, 512);
        assert_eq!(queue.used.idx, 1);
        assert_eq!(queue.used.ring[0].id, 0);
        assert_eq!(queue.used.ring[0].len, 512);

        queue.push_used(1, 1024);
        assert_eq!(queue.used.idx, 2);
        assert_eq!(queue.used.ring[1].id, 1);
        assert_eq!(queue.used.ring[1].len, 1024);
    }

    #[test]
    fn test_virtqueue_push_used_wrap() {
        let mut queue = VirtQueue::new(4).unwrap();

        // Push more than queue size to test wrapping
        for i in 0..10 {
            queue.push_used(i, i as u32 * 100);
        }

        assert_eq!(queue.used.idx, 10);
        // Ring index wraps: 10 % 4 = 2, so last entry is at index 1
        assert_eq!(queue.used.ring[1].id, 9);
    }

    #[test]
    fn test_virtqueue_simulated_transaction() {
        let mut queue = VirtQueue::new(16).unwrap();
        queue.set_ready(true);

        // Simulate guest adding a descriptor to available ring
        queue.avail.ring[0] = 0; // Descriptor index 0
        queue.avail.idx = 1;

        // Device should see available descriptor
        assert!(queue.has_available());

        // Pop the descriptor
        let (head_idx, _chain) = queue.pop_avail().unwrap();
        assert_eq!(head_idx, 0);

        // No more available
        assert!(!queue.has_available());

        // Device adds to used ring
        queue.push_used(head_idx, 256);
        assert_eq!(queue.used.idx, 1);
    }

    #[test]
    fn test_virtqueue_multiple_descriptors() {
        let mut queue = VirtQueue::new(16).unwrap();
        queue.set_ready(true);

        // Add multiple descriptors to available ring
        for i in 0..5 {
            queue.avail.ring[i] = i as u16;
        }
        queue.avail.idx = 5;

        // Pop all
        for i in 0..5 {
            assert!(queue.has_available());
            let (head_idx, _) = queue.pop_avail().unwrap();
            assert_eq!(head_idx, i as u16);
        }

        assert!(!queue.has_available());
    }

    // ==========================================================================
    // DescriptorChain Tests
    // ==========================================================================

    #[test]
    fn test_descriptor_chain_single() {
        let mut queue = VirtQueue::new(16).unwrap();

        // Set up a single descriptor (no chain)
        queue.desc_table[0] = Descriptor {
            addr: 0x1000,
            len: 512,
            flags: 0, // No NEXT flag
            next: 0,
        };

        queue.avail.ring[0] = 0;
        queue.avail.idx = 1;

        let (head_idx, chain) = queue.pop_avail().unwrap();
        assert_eq!(head_idx, 0);

        let descs: Vec<_> = chain.collect();
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].addr, 0x1000);
        assert_eq!(descs[0].len, 512);
    }

    #[test]
    fn test_descriptor_chain_multiple() {
        let mut queue = VirtQueue::new(16).unwrap();

        // Set up a chain: 0 -> 1 -> 2
        queue.desc_table[0] = Descriptor {
            addr: 0x1000,
            len: 256,
            flags: flags::NEXT,
            next: 1,
        };
        queue.desc_table[1] = Descriptor {
            addr: 0x2000,
            len: 512,
            flags: flags::NEXT,
            next: 2,
        };
        queue.desc_table[2] = Descriptor {
            addr: 0x3000,
            len: 1024,
            flags: 0, // End of chain
            next: 0,
        };

        queue.avail.ring[0] = 0;
        queue.avail.idx = 1;

        let (_, chain) = queue.pop_avail().unwrap();
        let descs: Vec<_> = chain.collect();

        assert_eq!(descs.len(), 3);
        assert_eq!(descs[0].addr, 0x1000);
        assert_eq!(descs[1].addr, 0x2000);
        assert_eq!(descs[2].addr, 0x3000);
    }

    #[test]
    fn test_descriptor_chain_with_write_flags() {
        let mut queue = VirtQueue::new(16).unwrap();

        // Set up: read buffer -> write buffer
        queue.desc_table[0] = Descriptor {
            addr: 0x1000,
            len: 256,
            flags: flags::NEXT, // Read-only for device
            next: 1,
        };
        queue.desc_table[1] = Descriptor {
            addr: 0x2000,
            len: 512,
            flags: flags::WRITE, // Write-only for device
            next: 0,
        };

        queue.avail.ring[0] = 0;
        queue.avail.idx = 1;

        let (_, chain) = queue.pop_avail().unwrap();
        let descs: Vec<_> = chain.collect();

        assert_eq!(descs.len(), 2);
        assert!(!descs[0].is_write_only());
        assert!(descs[1].is_write_only());
    }

    // ==========================================================================
    // Edge Case Tests
    // ==========================================================================

    #[test]
    fn test_avail_idx_wrap() {
        let mut queue = VirtQueue::new(4).unwrap();

        // Simulate wrapping of avail.idx
        queue.avail.idx = u16::MAX;
        queue.last_avail_idx = u16::MAX - 1;
        queue.avail.ring[(queue.last_avail_idx % 4) as usize] = 0;

        assert!(queue.has_available());

        let (head_idx, _) = queue.pop_avail().unwrap();
        assert_eq!(head_idx, 0);
        assert_eq!(queue.last_avail_idx, u16::MAX);

        // Add one more
        queue.avail.ring[(queue.avail.idx % 4) as usize] = 1;
        queue.avail.idx = 0; // Wraps

        assert!(queue.has_available());
        let (head_idx, _) = queue.pop_avail().unwrap();
        assert_eq!(head_idx, 1);
    }

    #[test]
    fn test_used_idx_wrap() {
        let mut queue = VirtQueue::new(4).unwrap();
        queue.used.idx = u16::MAX;

        queue.push_used(0, 100);
        assert_eq!(queue.used.idx, 0); // Wrapped

        // Value should be at index (u16::MAX % 4) = 3
        assert_eq!(queue.used.ring[3].id, 0);
        assert_eq!(queue.used.ring[3].len, 100);
    }

    #[test]
    fn test_queue_min_size() {
        let queue = VirtQueue::new(1).unwrap();
        assert_eq!(queue.size(), 1);
        assert_eq!(queue.desc_table.len(), 1);
        assert_eq!(queue.avail.ring.len(), 1);
        assert_eq!(queue.used.ring.len(), 1);
    }

    #[test]
    fn test_queue_max_size() {
        let queue = VirtQueue::new(32768).unwrap();
        assert_eq!(queue.size(), 32768);
        assert_eq!(queue.desc_table.len(), 32768);
    }

    #[test]
    fn test_descriptor_chain_out_of_bounds() {
        let mut queue = VirtQueue::new(4).unwrap();

        // Set up descriptor pointing to out-of-bounds next
        queue.desc_table[0] = Descriptor {
            addr: 0x1000,
            len: 256,
            flags: flags::NEXT,
            next: 100, // Out of bounds
        };

        queue.avail.ring[0] = 0;
        queue.avail.idx = 1;

        let (_, chain) = queue.pop_avail().unwrap();
        let descs: Vec<_> = chain.collect();

        // Should only get first descriptor, chain stops at invalid next
        assert_eq!(descs.len(), 1);
    }
}
