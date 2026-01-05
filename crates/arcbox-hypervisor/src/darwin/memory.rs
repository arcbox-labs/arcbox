//! Guest memory implementation for macOS.

use std::sync::RwLock;

use crate::{
    error::HypervisorError,
    memory::{GuestAddress, MemoryRegion},
    traits::GuestMemory,
};

use super::ffi;

/// Guest memory implementation for Darwin (macOS).
///
/// This manages the guest physical address space using mmap'd memory
/// that is shared with the Virtualization.framework VM.
pub struct DarwinMemory {
    /// Memory regions.
    regions: RwLock<Vec<MappedRegion>>,
    /// Total memory size.
    total_size: u64,
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
        let host_addr = ffi::allocate_memory(size).map_err(|e| {
            HypervisorError::MemoryError(format!("Failed to allocate memory: {}", e))
        })?;

        let region = MappedRegion {
            guest_addr: GuestAddress::new(0),
            size,
            host_addr,
        };

        tracing::debug!("Created guest memory: {}MB", size / (1024 * 1024));

        Ok(Self {
            regions: RwLock::new(vec![region]),
            total_size: size,
        })
    }

    /// Adds an additional memory region.
    ///
    /// # Errors
    ///
    /// Returns an error if the region overlaps with existing regions.
    pub fn add_region(
        &self,
        guest_addr: GuestAddress,
        size: u64,
    ) -> Result<(), HypervisorError> {
        let host_addr = ffi::allocate_memory(size).map_err(|e| {
            HypervisorError::MemoryError(format!("Failed to allocate memory: {}", e))
        })?;

        let new_region = MappedRegion {
            guest_addr,
            size,
            host_addr,
        };

        let mut regions = self.regions.write().map_err(|_| {
            HypervisorError::MemoryError("Lock poisoned".to_string())
        })?;

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
        let regions = self.regions.read().map_err(|_| {
            HypervisorError::MemoryError("Lock poisoned".to_string())
        })?;

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
        let regions = self.regions.read().map_err(|_| {
            HypervisorError::MemoryError("Lock poisoned".to_string())
        })?;

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
}

impl Drop for DarwinMemory {
    fn drop(&mut self) {
        if let Ok(regions) = self.regions.write() {
            for region in regions.iter() {
                ffi::free_memory(region.host_addr, region.size);
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
}
