//! Guest memory implementation for Linux KVM.

use std::os::unix::io::RawFd;
use std::sync::RwLock;

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use crate::{
    error::HypervisorError,
    memory::{GuestAddress, MemoryRegion, PAGE_SIZE},
    traits::GuestMemory,
    types::DirtyPageInfo,
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
    /// KVM VM fd for dirty logging (set by VM after creation).
    vm_fd: AtomicI32,
    /// Memory slots tracked for dirty logging.
    memory_slots: RwLock<Vec<MemorySlotInfo>>,
    /// Whether dirty page tracking is enabled.
    dirty_tracking_enabled: AtomicBool,
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

/// Memory slot tracking for dirty logging.
struct MemorySlotInfo {
    /// Slot ID.
    slot: u32,
    /// Guest physical address.
    guest_phys_addr: u64,
    /// Size in bytes.
    size: u64,
    /// Host virtual address.
    userspace_addr: u64,
    /// Base flags for the slot (e.g. read-only).
    flags: u32,
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
            vm_fd: AtomicI32::new(-1),
            memory_slots: RwLock::new(Vec::new()),
            dirty_tracking_enabled: AtomicBool::new(false),
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

    /// Attaches the KVM VM fd for dirty logging.
    pub fn attach_vm_fd(&self, vm_fd: RawFd) {
        self.vm_fd.store(vm_fd, Ordering::SeqCst);
    }

    /// Registers a memory slot for dirty logging.
    ///
    /// # Errors
    ///
    /// Returns an error if the slot list cannot be updated.
    pub fn register_slot(
        &self,
        slot: u32,
        guest_phys_addr: u64,
        size: u64,
        userspace_addr: u64,
        flags: u32,
    ) -> Result<(), HypervisorError> {
        let mut slots = self
            .memory_slots
            .write()
            .map_err(|_| HypervisorError::SnapshotError("Lock poisoned".to_string()))?;

        if let Some(existing) = slots.iter_mut().find(|s| s.slot == slot) {
            existing.guest_phys_addr = guest_phys_addr;
            existing.size = size;
            existing.userspace_addr = userspace_addr;
            existing.flags = flags;
        } else {
            slots.push(MemorySlotInfo {
                slot,
                guest_phys_addr,
                size,
                userspace_addr,
                flags,
            });
        }

        if self.dirty_tracking_enabled.load(Ordering::SeqCst) {
            let fd = self.vm_fd()?;
            let slot_info = slots.iter().find(|s| s.slot == slot).unwrap();
            self.update_dirty_logging(fd, slot_info, true)?;
        }

        Ok(())
    }

    /// Unregisters a memory slot.
    ///
    /// # Errors
    ///
    /// Returns an error if the slot list cannot be updated.
    pub fn unregister_slot(&self, slot: u32) -> Result<(), HypervisorError> {
        let mut slots = self
            .memory_slots
            .write()
            .map_err(|_| HypervisorError::SnapshotError("Lock poisoned".to_string()))?;
        slots.retain(|entry| entry.slot != slot);
        Ok(())
    }

    /// Updates the dirty tracking enabled flag from external callers.
    pub fn set_dirty_tracking_enabled(&self, enabled: bool) {
        self.dirty_tracking_enabled.store(enabled, Ordering::SeqCst);
    }

    fn vm_fd(&self) -> Result<RawFd, HypervisorError> {
        let fd = self.vm_fd.load(Ordering::SeqCst);
        if fd < 0 {
            return Err(HypervisorError::SnapshotError(
                "KVM VM fd not attached".to_string(),
            ));
        }
        Ok(fd)
    }

    fn update_dirty_logging(
        &self,
        fd: RawFd,
        slot: &MemorySlotInfo,
        enable: bool,
    ) -> Result<(), HypervisorError> {
        let flags = if enable {
            slot.flags | ffi::KVM_MEM_LOG_DIRTY_PAGES
        } else {
            slot.flags
        };

        let region = ffi::KvmUserspaceMemoryRegion {
            slot: slot.slot,
            flags,
            guest_phys_addr: slot.guest_phys_addr,
            memory_size: slot.size,
            userspace_addr: slot.userspace_addr,
        };

        let ret = unsafe {
            libc::ioctl(
                fd,
                ffi::KVM_SET_USER_MEMORY_REGION,
                &region as *const _ as libc::c_ulong,
            )
        };

        if ret < 0 {
            return Err(HypervisorError::SnapshotError(format!(
                "Failed to {} dirty logging for slot {}: {}",
                if enable { "enable" } else { "disable" },
                slot.slot,
                std::io::Error::last_os_error()
            )));
        }

        Ok(())
    }

    fn get_dirty_log(&self, fd: RawFd, slot: &MemorySlotInfo) -> Result<Vec<u64>, HypervisorError> {
        let num_pages = (slot.size + PAGE_SIZE - 1) / PAGE_SIZE;
        let bitmap_size = ((num_pages + 63) / 64) as usize;
        let mut bitmap: Vec<u64> = vec![0; bitmap_size];

        let dirty_log = ffi::KvmDirtyLog {
            slot: slot.slot,
            padding: 0,
            dirty_bitmap: bitmap.as_mut_ptr(),
        };

        let ret = unsafe {
            libc::ioctl(
                fd,
                ffi::KVM_GET_DIRTY_LOG,
                &dirty_log as *const _ as libc::c_ulong,
            )
        };

        if ret < 0 {
            return Err(HypervisorError::SnapshotError(format!(
                "Failed to get dirty log for slot {}: {}",
                slot.slot,
                std::io::Error::last_os_error()
            )));
        }

        Ok(bitmap)
    }

    fn parse_dirty_bitmap(bitmap: &[u64], base_addr: u64, size: u64) -> Vec<DirtyPageInfo> {
        let mut pages = Vec::new();
        let num_pages = size / PAGE_SIZE;

        for (word_idx, &word) in bitmap.iter().enumerate() {
            if word == 0 {
                continue;
            }

            for bit_idx in 0..64 {
                if (word >> bit_idx) & 1 != 0 {
                    let page_num = (word_idx as u64 * 64) + bit_idx as u64;
                    if page_num < num_pages {
                        pages.push(DirtyPageInfo {
                            guest_addr: base_addr + page_num * PAGE_SIZE,
                            size: PAGE_SIZE,
                        });
                    }
                }
            }
        }

        pages
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
        let bytes = unsafe {
            std::slice::from_raw_parts(val as *const T as *const u8, std::mem::size_of::<T>())
        };
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

    fn enable_dirty_tracking(&mut self) -> Result<(), HypervisorError> {
        if self.dirty_tracking_enabled.load(Ordering::SeqCst) {
            return Ok(());
        }

        let fd = self.vm_fd()?;
        let slots = self
            .memory_slots
            .read()
            .map_err(|_| HypervisorError::SnapshotError("Lock poisoned".to_string()))?;

        for slot in slots.iter() {
            self.update_dirty_logging(fd, slot, true)?;
        }

        self.dirty_tracking_enabled.store(true, Ordering::SeqCst);
        tracing::debug!("Dirty page tracking enabled");
        Ok(())
    }

    fn disable_dirty_tracking(&mut self) -> Result<(), HypervisorError> {
        if !self.dirty_tracking_enabled.load(Ordering::SeqCst) {
            return Ok(());
        }

        let fd = self.vm_fd()?;
        let slots = self
            .memory_slots
            .read()
            .map_err(|_| HypervisorError::SnapshotError("Lock poisoned".to_string()))?;

        for slot in slots.iter() {
            self.update_dirty_logging(fd, slot, false)?;
        }

        self.dirty_tracking_enabled.store(false, Ordering::SeqCst);
        tracing::debug!("Dirty page tracking disabled");
        Ok(())
    }

    fn get_dirty_pages(&mut self) -> Result<Vec<DirtyPageInfo>, HypervisorError> {
        if !self.dirty_tracking_enabled.load(Ordering::SeqCst) {
            return Err(HypervisorError::SnapshotError(
                "Dirty tracking not enabled".to_string(),
            ));
        }

        let fd = self.vm_fd()?;
        let slots = self
            .memory_slots
            .read()
            .map_err(|_| HypervisorError::SnapshotError("Lock poisoned".to_string()))?;

        let mut dirty_pages = Vec::new();
        for slot in slots.iter() {
            let bitmap = self.get_dirty_log(fd, slot)?;
            let pages = Self::parse_dirty_bitmap(&bitmap, slot.guest_phys_addr, slot.size);
            dirty_pages.extend(pages);
        }

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
