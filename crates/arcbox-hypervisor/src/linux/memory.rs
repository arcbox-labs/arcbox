//! Guest memory implementation for Linux KVM.

use std::sync::RwLock;

use crate::{
    error::HypervisorError,
    memory::{GuestAddress, MemoryRegion},
    traits::GuestMemory,
};

use super::ffi;

/// Guest memory implementation for Linux KVM.
///
/// This manages the guest physical address space using mmap'd memory
/// that is registered with KVM via KVM_SET_USER_MEMORY_REGION.
pub struct KvmMemory {
    /// Memory regions.
    regions: RwLock<Vec<MappedRegion>>,
    /// Total memory size.
    total_size: u64,
    /// Base host address (for the primary region).
    base_host_addr: *mut u8,
}

/// A mapped memory region with its host backing.
struct MappedRegion {
    /// Guest physical address.
    guest_addr: GuestAddress,
    /// Size in bytes.
    size: u64,
    /// Host virtual address.
    host_addr: *mut u8,
    /// Whether this region is read-only.
    read_only: bool,
    /// Whether this region was allocated by us (vs provided externally).
    owned: bool,
}

// Safety: The host_addr pointer points to mmap'd memory that is valid
// for the lifetime of the KvmMemory instance.
unsafe impl Send for MappedRegion {}
unsafe impl Sync for MappedRegion {}
unsafe impl Send for KvmMemory {}
unsafe impl Sync for KvmMemory {}

impl KvmMemory {
    /// Creates a new guest memory region.
    ///
    /// # Errors
    ///
    /// Returns an error if memory allocation fails.
    pub fn new(size: u64) -> Result<Self, HypervisorError> {
        // Allocate the main memory region at guest address 0
        let host_addr = ffi::allocate_memory(size).map_err(|e| {
            HypervisorError::MemoryError(format!("Failed to allocate memory: {}", e))
        })?;

        let region = MappedRegion {
            guest_addr: GuestAddress::new(0),
            size,
            host_addr,
            read_only: false,
            owned: true,
        };

        tracing::debug!("Created guest memory: {}MB", size / (1024 * 1024));

        Ok(Self {
            regions: RwLock::new(vec![region]),
            total_size: size,
            base_host_addr: host_addr,
        })
    }

    /// Returns the host address of the base memory region.
    ///
    /// This is used when registering memory with KVM.
    pub fn host_address(&self) -> *mut u8 {
        self.base_host_addr
    }

    /// Adds an additional memory region.
    ///
    /// # Errors
    ///
    /// Returns an error if the region overlaps with existing regions or
    /// memory allocation fails.
    pub fn add_region(
        &self,
        guest_addr: GuestAddress,
        size: u64,
    ) -> Result<*mut u8, HypervisorError> {
        let host_addr = ffi::allocate_memory(size).map_err(|e| {
            HypervisorError::MemoryError(format!("Failed to allocate memory: {}", e))
        })?;

        let new_region = MappedRegion {
            guest_addr,
            size,
            host_addr,
            read_only: false,
            owned: true,
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
                ffi::free_memory(host_addr, size);
                return Err(HypervisorError::MemoryError(
                    "Region overlaps with existing region".to_string(),
                ));
            }
        }

        let ptr = host_addr;
        regions.push(new_region);

        tracing::debug!(
            "Added memory region at {}: {}MB",
            guest_addr,
            size / (1024 * 1024)
        );

        Ok(ptr)
    }

    /// Adds an externally allocated memory region.
    ///
    /// The caller is responsible for ensuring the memory remains valid
    /// for the lifetime of this object.
    ///
    /// # Safety
    ///
    /// The host_addr must point to valid memory of at least `size` bytes
    /// that will remain valid for the lifetime of this KvmMemory.
    pub unsafe fn add_external_region(
        &self,
        guest_addr: GuestAddress,
        host_addr: *mut u8,
        size: u64,
        read_only: bool,
    ) -> Result<(), HypervisorError> {
        let new_region = MappedRegion {
            guest_addr,
            size,
            host_addr,
            read_only,
            owned: false, // Not owned by us
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
                return Err(HypervisorError::MemoryError(
                    "Region overlaps with existing region".to_string(),
                ));
            }
        }

        regions.push(new_region);

        tracing::debug!(
            "Added external memory region at {}: {}MB, read_only={}",
            guest_addr,
            size / (1024 * 1024),
            read_only
        );

        Ok(())
    }

    /// Finds the region containing the given address.
    fn find_region(&self, addr: GuestAddress) -> Result<(*mut u8, u64, bool), HypervisorError> {
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
                return Ok((ptr, remaining, region.read_only));
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
                read_only: r.read_only,
            })
            .collect())
    }

    /// Writes a value to guest memory at the specified address.
    pub fn write_obj<T: Copy>(&self, addr: GuestAddress, val: &T) -> Result<(), HypervisorError> {
        let bytes =
            unsafe { std::slice::from_raw_parts(val as *const T as *const u8, std::mem::size_of::<T>()) };
        self.write(addr, bytes)
    }

    /// Reads a value from guest memory at the specified address.
    pub fn read_obj<T: Copy + Default>(&self, addr: GuestAddress) -> Result<T, HypervisorError> {
        let mut val = T::default();
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(&mut val as *mut T as *mut u8, std::mem::size_of::<T>())
        };
        self.read(addr, bytes)?;
        Ok(val)
    }

    /// Fills a range of guest memory with a byte value.
    pub fn memset(&self, addr: GuestAddress, val: u8, len: usize) -> Result<(), HypervisorError> {
        let (ptr, remaining, read_only) = self.find_region(addr)?;

        if read_only {
            return Err(HypervisorError::MemoryError(
                "Cannot write to read-only region".to_string(),
            ));
        }

        if len as u64 > remaining {
            return Err(HypervisorError::MemoryError(format!(
                "Memset of {} bytes at {} exceeds region bounds",
                len, addr
            )));
        }

        unsafe {
            std::ptr::write_bytes(ptr, val, len);
        }

        Ok(())
    }
}

impl GuestMemory for KvmMemory {
    fn read(&self, addr: GuestAddress, buf: &mut [u8]) -> Result<(), HypervisorError> {
        let (ptr, remaining, _) = self.find_region(addr)?;

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
        let (ptr, remaining, read_only) = self.find_region(addr)?;

        if read_only {
            return Err(HypervisorError::MemoryError(
                "Cannot write to read-only region".to_string(),
            ));
        }

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
        let (ptr, _, _) = self.find_region(addr)?;
        Ok(ptr)
    }

    fn size(&self) -> u64 {
        self.total_size
    }
}

impl Drop for KvmMemory {
    fn drop(&mut self) {
        if let Ok(regions) = self.regions.write() {
            for region in regions.iter() {
                // Only free memory we allocated
                if region.owned {
                    ffi::free_memory(region.host_addr, region.size);
                }
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
        let memory = KvmMemory::new(size).unwrap();
        assert_eq!(memory.size(), size);
    }

    #[test]
    fn test_memory_read_write() {
        let size = 16 * 1024 * 1024;
        let memory = KvmMemory::new(size).unwrap();

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
        let memory = KvmMemory::new(size).unwrap();

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
        let memory = KvmMemory::new(size).unwrap();

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
    fn test_write_read_obj() {
        let size = 16 * 1024 * 1024;
        let memory = KvmMemory::new(size).unwrap();

        // Write a u64
        let val: u64 = 0x1234_5678_9abc_def0;
        memory.write_obj(GuestAddress::new(0x2000), &val).unwrap();

        // Read it back
        let read_val: u64 = memory.read_obj(GuestAddress::new(0x2000)).unwrap();
        assert_eq!(read_val, val);
    }

    #[test]
    fn test_memset() {
        let size = 16 * 1024 * 1024;
        let memory = KvmMemory::new(size).unwrap();

        // Fill a region
        memory.memset(GuestAddress::new(0x3000), 0xAA, 100).unwrap();

        // Verify
        let mut buf = [0u8; 100];
        memory.read(GuestAddress::new(0x3000), &mut buf).unwrap();
        for &byte in &buf {
            assert_eq!(byte, 0xAA);
        }
    }

    #[test]
    fn test_add_region() {
        let size = 16 * 1024 * 1024;
        let memory = KvmMemory::new(size).unwrap();

        // Add another region at a non-overlapping address
        let region2_addr = GuestAddress::new(0x1_0000_0000); // 4GB
        let region2_size = 8 * 1024 * 1024;
        let ptr = memory.add_region(region2_addr, region2_size).unwrap();
        assert!(!ptr.is_null());

        // Write to the new region
        let data = [0xBB; 10];
        memory.write(region2_addr, &data).unwrap();

        // Read back
        let mut buf = [0u8; 10];
        memory.read(region2_addr, &mut buf).unwrap();
        assert_eq!(buf, data);
    }

    #[test]
    fn test_overlapping_region() {
        let size = 16 * 1024 * 1024;
        let memory = KvmMemory::new(size).unwrap();

        // Try to add an overlapping region (should fail)
        let result = memory.add_region(GuestAddress::new(0x1000), 0x1000);
        assert!(result.is_err());
    }
}
