//! Guest memory implementation for macOS.
//!
//! Virtualization.framework does not provide dirty page tracking like KVM does.
//! This module implements a software-based alternative using page checksums.
//!
//! # Memory Allocation
//!
//! Guest memory is allocated using mmap directly, as this is a low-level
//! operation not related to Virtualization.framework. The arcbox-vz crate
//! does not expose memory allocation APIs since it focuses on VZ-specific
//! functionality.

use std::collections::HashMap;
use std::ptr;
use std::sync::RwLock;

use crate::{
    error::HypervisorError,
    memory::{GuestAddress, MemoryRegion, PAGE_SIZE},
    traits::GuestMemory,
    types::DirtyPageInfo,
};

// ============================================================================
// Memory Allocation (using mmap directly)
// ============================================================================

/// Allocates guest memory using mmap.
///
/// This is a low-level operation that allocates anonymous memory pages
/// for use as guest physical memory.
fn allocate_memory(size: u64) -> Result<*mut u8, HypervisorError> {
    unsafe {
        let ptr = libc::mmap(
            ptr::null_mut(),
            size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );

        if ptr == libc::MAP_FAILED {
            let errno = *libc::__error();
            return Err(HypervisorError::MemoryError(format!(
                "mmap failed: errno={}",
                errno
            )));
        }

        libc::memset(ptr, 0, size as usize);
        tracing::debug!("Allocated {}MB of guest memory", size / (1024 * 1024));

        Ok(ptr.cast::<u8>())
    }
}

/// Frees guest memory previously allocated with `allocate_memory`.
fn free_memory(ptr: *mut u8, size: u64) {
    if !ptr.is_null() {
        unsafe {
            libc::munmap(ptr.cast(), size as usize);
        }
    }
}

/// Guest memory implementation for Darwin (macOS).
///
/// This manages the guest physical address space using mmap'd memory
/// that is shared with the Virtualization.framework VM.
///
/// ## Dirty Page Tracking
///
/// Since Virtualization.framework doesn't expose dirty page tracking,
/// we implement a software-based solution using page checksums (xxHash).
/// When tracking is enabled:
/// 1. `enable_dirty_tracking()` computes and stores checksums for all pages
/// 2. `get_dirty_pages()` recomputes checksums and compares with stored values
/// 3. Pages with different checksums are reported as dirty
///
/// This is less efficient than hardware-based tracking but provides the
/// necessary functionality for incremental snapshots on macOS.
pub struct DarwinMemory {
    /// Memory regions.
    regions: RwLock<Vec<MappedRegion>>,
    /// Total memory size.
    total_size: u64,
    /// Whether dirty page tracking is enabled.
    dirty_tracking_enabled: std::sync::atomic::AtomicBool,
    /// Page checksums for dirty tracking (guest_addr -> checksum).
    /// Only populated when dirty tracking is enabled.
    page_checksums: RwLock<HashMap<u64, u64>>,
}

/// A mapped memory region with its host backing.
struct MappedRegion {
    /// Guest physical address.
    guest_addr: GuestAddress,
    /// Size in bytes.
    size: u64,
    /// Host virtual address.
    host_addr: *mut u8,
}

// Safety: The host_addr pointer points to mmap'd memory that is valid
// for the lifetime of the DarwinMemory instance.
unsafe impl Send for MappedRegion {}
unsafe impl Sync for MappedRegion {}

impl DarwinMemory {
    /// Creates a new guest memory region.
    ///
    /// # Errors
    ///
    /// Returns an error if memory allocation fails.
    pub fn new(size: u64) -> Result<Self, HypervisorError> {
        // Allocate the main memory region at guest address 0
        let host_addr = allocate_memory(size)?;

        let region = MappedRegion {
            guest_addr: GuestAddress::new(0),
            size,
            host_addr,
        };

        tracing::debug!("Created guest memory: {}MB", size / (1024 * 1024));

        Ok(Self {
            regions: RwLock::new(vec![region]),
            total_size: size,
            dirty_tracking_enabled: std::sync::atomic::AtomicBool::new(false),
            page_checksums: RwLock::new(HashMap::new()),
        })
    }

    /// Computes a fast hash of a memory page using FNV-1a.
    ///
    /// FNV-1a is chosen for its simplicity and reasonable performance.
    /// It processes 8 bytes at a time for efficiency.
    #[inline]
    fn hash_page(data: &[u8]) -> u64 {
        const FNV_OFFSET: u64 = 0xcbf29ce484222325;
        const FNV_PRIME: u64 = 0x100000001b3;

        let mut hash = FNV_OFFSET;

        // Process 8 bytes at a time for better performance.
        let chunks = data.chunks_exact(8);
        let remainder = chunks.remainder();

        for chunk in chunks {
            let word = u64::from_le_bytes(chunk.try_into().unwrap());
            hash ^= word;
            hash = hash.wrapping_mul(FNV_PRIME);
        }

        // Handle remaining bytes.
        for &byte in remainder {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }

        hash
    }

    /// Computes checksums for all pages and stores them.
    ///
    /// This is called when dirty tracking is enabled to establish a baseline.
    fn compute_all_checksums(&self) -> Result<HashMap<u64, u64>, HypervisorError> {
        let regions = self
            .regions
            .read()
            .map_err(|_| HypervisorError::MemoryError("Lock poisoned".to_string()))?;

        let mut checksums = HashMap::new();
        let page_size = PAGE_SIZE as usize;

        for region in regions.iter() {
            let num_pages = (region.size as usize + page_size - 1) / page_size;

            for page_idx in 0..num_pages {
                let page_offset = page_idx * page_size;
                let guest_addr = region.guest_addr.raw() + page_offset as u64;

                // Calculate actual bytes in this page (last page might be partial).
                let bytes_in_page = std::cmp::min(page_size, region.size as usize - page_offset);

                // Read page data and compute hash.
                let page_data = unsafe {
                    std::slice::from_raw_parts(region.host_addr.add(page_offset), bytes_in_page)
                };

                let hash = Self::hash_page(page_data);
                checksums.insert(guest_addr, hash);
            }
        }

        tracing::debug!("Computed checksums for {} pages", checksums.len());

        Ok(checksums)
    }

    /// Adds an additional memory region.
    ///
    /// # Errors
    ///
    /// Returns an error if the region overlaps with existing regions.
    pub fn add_region(&self, guest_addr: GuestAddress, size: u64) -> Result<(), HypervisorError> {
        let host_addr = allocate_memory(size)?;

        let new_region = MappedRegion {
            guest_addr,
            size,
            host_addr,
        };

        let mut regions = self
            .regions
            .write()
            .map_err(|_| HypervisorError::MemoryError("Lock poisoned".to_string()))?;

        // Check for overlaps
        let new_end = guest_addr.raw() + size;
        for region in regions.iter() {
            let existing_end = region.guest_addr.raw() + region.size;
            if guest_addr.raw() < existing_end && new_end > region.guest_addr.raw() {
                // Free the allocated memory before returning error
                free_memory(host_addr, size);
                return Err(HypervisorError::MemoryError(
                    "Region overlaps with existing region".to_string(),
                ));
            }
        }

        regions.push(new_region);

        tracing::debug!(
            "Added memory region at {}: {}MB",
            guest_addr,
            size / (1024 * 1024)
        );

        Ok(())
    }

    /// Finds the region containing the given address.
    fn find_region(&self, addr: GuestAddress) -> Result<(*mut u8, u64), HypervisorError> {
        let regions = self
            .regions
            .read()
            .map_err(|_| HypervisorError::MemoryError("Lock poisoned".to_string()))?;

        for region in regions.iter() {
            if addr.raw() >= region.guest_addr.raw()
                && addr.raw() < region.guest_addr.raw() + region.size
            {
                let offset = addr.raw() - region.guest_addr.raw();
                let remaining = region.size - offset;
                let ptr = unsafe { region.host_addr.add(offset as usize) };
                return Ok((ptr, remaining));
            }
        }

        Err(HypervisorError::MemoryError(format!(
            "Address {} not mapped",
            addr
        )))
    }

    /// Returns an iterator over all memory regions.
    pub fn regions(&self) -> Result<Vec<MemoryRegion>, HypervisorError> {
        let regions = self
            .regions
            .read()
            .map_err(|_| HypervisorError::MemoryError("Lock poisoned".to_string()))?;

        Ok(regions
            .iter()
            .map(|r| MemoryRegion {
                guest_addr: r.guest_addr,
                size: r.size,
                host_addr: Some(r.host_addr),
                read_only: false,
            })
            .collect())
    }
}

impl GuestMemory for DarwinMemory {
    fn read(&self, addr: GuestAddress, buf: &mut [u8]) -> Result<(), HypervisorError> {
        let (ptr, remaining) = self.find_region(addr)?;

        if buf.len() as u64 > remaining {
            return Err(HypervisorError::MemoryError(format!(
                "Read of {} bytes at {} exceeds region bounds",
                buf.len(),
                addr
            )));
        }

        unsafe {
            std::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), buf.len());
        }

        Ok(())
    }

    fn write(&self, addr: GuestAddress, buf: &[u8]) -> Result<(), HypervisorError> {
        let (ptr, remaining) = self.find_region(addr)?;

        if buf.len() as u64 > remaining {
            return Err(HypervisorError::MemoryError(format!(
                "Write of {} bytes at {} exceeds region bounds",
                buf.len(),
                addr
            )));
        }

        unsafe {
            std::ptr::copy_nonoverlapping(buf.as_ptr(), ptr, buf.len());
        }

        Ok(())
    }

    fn get_host_address(&self, addr: GuestAddress) -> Result<*mut u8, HypervisorError> {
        let (ptr, _) = self.find_region(addr)?;
        Ok(ptr)
    }

    fn size(&self) -> u64 {
        self.total_size
    }

    fn enable_dirty_tracking(&mut self) -> Result<(), HypervisorError> {
        if self
            .dirty_tracking_enabled
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            // Already enabled.
            return Ok(());
        }

        // Compute checksums for all pages to establish a baseline.
        // This is necessary because Virtualization.framework doesn't provide
        // hardware-based dirty page tracking like KVM does.
        tracing::info!(
            "Enabling software-based dirty tracking (checksum method) for {} bytes",
            self.total_size
        );

        let checksums = self.compute_all_checksums()?;

        // Store the checksums.
        let mut stored = self
            .page_checksums
            .write()
            .map_err(|_| HypervisorError::MemoryError("Lock poisoned".to_string()))?;
        *stored = checksums;

        self.dirty_tracking_enabled
            .store(true, std::sync::atomic::Ordering::SeqCst);

        tracing::info!(
            "Dirty tracking enabled with {} page checksums",
            stored.len()
        );

        Ok(())
    }

    fn disable_dirty_tracking(&mut self) -> Result<(), HypervisorError> {
        self.dirty_tracking_enabled
            .store(false, std::sync::atomic::Ordering::SeqCst);

        // Clear stored checksums to free memory.
        if let Ok(mut checksums) = self.page_checksums.write() {
            checksums.clear();
        }

        tracing::info!("Dirty tracking disabled");
        Ok(())
    }

    fn get_dirty_pages(&mut self) -> Result<Vec<DirtyPageInfo>, HypervisorError> {
        if !self
            .dirty_tracking_enabled
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(HypervisorError::SnapshotError(
                "Dirty tracking not enabled".to_string(),
            ));
        }

        // Compute current checksums.
        let current_checksums = self.compute_all_checksums()?;

        // Compare with stored checksums to find dirty pages.
        let stored_checksums = self
            .page_checksums
            .read()
            .map_err(|_| HypervisorError::MemoryError("Lock poisoned".to_string()))?;

        let mut dirty_pages = Vec::new();

        for (guest_addr, current_hash) in &current_checksums {
            let is_dirty = match stored_checksums.get(guest_addr) {
                Some(stored_hash) => current_hash != stored_hash,
                None => true, // New page, consider dirty.
            };

            if is_dirty {
                dirty_pages.push(DirtyPageInfo {
                    guest_addr: *guest_addr,
                    size: PAGE_SIZE,
                });
            }
        }

        tracing::debug!(
            "get_dirty_pages: found {} dirty pages out of {} total",
            dirty_pages.len(),
            current_checksums.len()
        );

        // Update stored checksums with current values.
        // This "clears" the dirty log for the next call.
        drop(stored_checksums);
        let mut stored = self
            .page_checksums
            .write()
            .map_err(|_| HypervisorError::MemoryError("Lock poisoned".to_string()))?;
        *stored = current_checksums;

        Ok(dirty_pages)
    }

    fn dump_all(&self, buf: &mut [u8]) -> Result<(), HypervisorError> {
        if (buf.len() as u64) < self.total_size {
            return Err(HypervisorError::MemoryError(format!(
                "Buffer too small: {} bytes, need {} bytes",
                buf.len(),
                self.total_size
            )));
        }

        let regions = self
            .regions
            .read()
            .map_err(|_| HypervisorError::MemoryError("Lock poisoned".to_string()))?;

        // Copy each region to the appropriate offset in the buffer.
        // Regions are assumed to be non-overlapping and cover guest physical addresses.
        for region in regions.iter() {
            let offset = region.guest_addr.raw() as usize;
            let end = offset + region.size as usize;

            if end > buf.len() {
                return Err(HypervisorError::MemoryError(format!(
                    "Region at {} with size {} exceeds buffer",
                    region.guest_addr, region.size
                )));
            }

            unsafe {
                std::ptr::copy_nonoverlapping(
                    region.host_addr,
                    buf[offset..end].as_mut_ptr(),
                    region.size as usize,
                );
            }
        }

        tracing::debug!("Dumped {} bytes of guest memory", self.total_size);
        Ok(())
    }
}

impl Drop for DarwinMemory {
    fn drop(&mut self) {
        if let Ok(regions) = self.regions.write() {
            for region in regions.iter() {
                free_memory(region.host_addr, region.size);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_creation() {
        let size = 16 * 1024 * 1024; // 16MB
        let memory = DarwinMemory::new(size).unwrap();
        assert_eq!(memory.size(), size);
    }

    #[test]
    fn test_memory_read_write() {
        let size = 16 * 1024 * 1024;
        let memory = DarwinMemory::new(size).unwrap();

        // Write some data
        let data = [1u8, 2, 3, 4, 5];
        memory.write(GuestAddress::new(0x1000), &data).unwrap();

        // Read it back
        let mut buf = [0u8; 5];
        memory.read(GuestAddress::new(0x1000), &mut buf).unwrap();
        assert_eq!(buf, data);
    }

    #[test]
    fn test_memory_bounds_check() {
        let size = 1024; // 1KB
        let memory = DarwinMemory::new(size).unwrap();

        // Try to read beyond bounds
        let mut buf = [0u8; 16];
        let result = memory.read(GuestAddress::new(size - 8), &mut buf);
        assert!(result.is_err());

        // Try to read from unmapped address
        let result = memory.read(GuestAddress::new(size + 1000), &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_host_address() {
        let size = 16 * 1024 * 1024;
        let memory = DarwinMemory::new(size).unwrap();

        let ptr = memory.get_host_address(GuestAddress::new(0x1000)).unwrap();
        assert!(!ptr.is_null());

        // Write via pointer
        unsafe {
            *ptr = 42;
        }

        // Read via GuestMemory
        let mut buf = [0u8; 1];
        memory.read(GuestAddress::new(0x1000), &mut buf).unwrap();
        assert_eq!(buf[0], 42);
    }

    #[test]
    fn test_dirty_tracking_not_enabled() {
        let mut memory = DarwinMemory::new(64 * 1024).unwrap(); // 64KB = 16 pages

        // Should fail when not enabled.
        assert!(memory.get_dirty_pages().is_err());
    }

    #[test]
    fn test_dirty_tracking_no_changes() {
        let mut memory = DarwinMemory::new(64 * 1024).unwrap(); // 64KB = 16 pages

        // Enable tracking.
        memory.enable_dirty_tracking().unwrap();

        // Get dirty pages immediately (should be empty since nothing changed).
        let dirty = memory.get_dirty_pages().unwrap();
        assert!(
            dirty.is_empty(),
            "Expected no dirty pages, got {}",
            dirty.len()
        );

        // Disable tracking.
        memory.disable_dirty_tracking().unwrap();
    }

    #[test]
    fn test_dirty_tracking_with_write() {
        let mut memory = DarwinMemory::new(64 * 1024).unwrap(); // 64KB = 16 pages

        // Enable tracking.
        memory.enable_dirty_tracking().unwrap();

        // Write to a page.
        let data = [0xAAu8; 256];
        memory.write(GuestAddress::new(0x1000), &data).unwrap();

        // Get dirty pages.
        let dirty = memory.get_dirty_pages().unwrap();
        assert!(!dirty.is_empty(), "Expected dirty pages after write");

        // The written page should be dirty.
        let page_addr = (0x1000 / PAGE_SIZE) * PAGE_SIZE;
        let found = dirty.iter().any(|p| p.guest_addr == page_addr);
        assert!(found, "Written page not found in dirty list");

        // Get dirty pages again (should be empty now since checksums were updated).
        let dirty2 = memory.get_dirty_pages().unwrap();
        assert!(
            dirty2.is_empty(),
            "Expected no dirty pages after second call"
        );
    }

    #[test]
    fn test_hash_page() {
        // Test that different data produces different hashes.
        let data1 = [0u8; 4096];
        let data2 = [1u8; 4096];
        let mut data3 = [0u8; 4096];
        data3[0] = 1; // Only first byte different

        let hash1 = DarwinMemory::hash_page(&data1);
        let hash2 = DarwinMemory::hash_page(&data2);
        let hash3 = DarwinMemory::hash_page(&data3);

        assert_ne!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_ne!(hash2, hash3);

        // Same data should produce same hash.
        let hash1_again = DarwinMemory::hash_page(&data1);
        assert_eq!(hash1, hash1_again);
    }
}
