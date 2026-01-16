//! Memory management for VMM.
//!
//! This module handles guest memory allocation, mapping, and region management.

use std::collections::BTreeMap;

use arcbox_hypervisor::{GuestAddress, MemoryRegion};

use crate::error::{Result, VmmError};

/// Memory region type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRegionType {
    /// Regular RAM.
    Ram,
    /// Read-only memory (ROM, firmware).
    Rom,
    /// Memory-mapped I/O region.
    Mmio,
    /// Reserved region (not usable by guest).
    Reserved,
}

/// Extended memory region information.
#[derive(Debug, Clone)]
pub struct MemoryRegionInfo {
    /// Base guest address.
    pub guest_addr: GuestAddress,
    /// Size in bytes.
    pub size: u64,
    /// Region type.
    pub region_type: MemoryRegionType,
    /// Human-readable name.
    pub name: String,
    /// Host address (if mapped).
    pub host_addr: Option<*mut u8>,
}

// Safety: host_addr points to memory that is valid for the lifetime of the manager.
unsafe impl Send for MemoryRegionInfo {}
unsafe impl Sync for MemoryRegionInfo {}

/// Memory manager for the VMM.
///
/// Handles memory allocation, mapping, and region management.
pub struct MemoryManager {
    /// Memory regions indexed by guest address.
    regions: BTreeMap<u64, MemoryRegionInfo>,
    /// Total RAM size.
    total_ram: u64,
    /// MMIO allocator.
    mmio_allocator: MmioAllocator,
    /// Whether memory is initialized.
    initialized: bool,
}

/// MMIO address allocator.
struct MmioAllocator {
    /// Base address for MMIO.
    base: u64,
    /// Size of MMIO region.
    size: u64,
    /// Next available address.
    next: u64,
}

impl MmioAllocator {
    /// Creates a new MMIO allocator.
    fn new(base: u64, size: u64) -> Self {
        Self {
            base,
            size,
            next: base,
        }
    }

    /// Allocates an MMIO region.
    fn allocate(&mut self, size: u64) -> Option<u64> {
        // Align to 4KB
        let aligned_size = (size + 0xFFF) & !0xFFF;

        if self.next + aligned_size > self.base + self.size {
            return None;
        }

        let addr = self.next;
        self.next += aligned_size;
        Some(addr)
    }
}

impl MemoryManager {
    /// Creates a new memory manager.
    #[must_use]
    pub fn new() -> Self {
        // Default MMIO region starts at 3GB, 1GB size
        let mmio_base = 3 * 1024 * 1024 * 1024; // 3GB
        let mmio_size = 1024 * 1024 * 1024; // 1GB

        Self {
            regions: BTreeMap::new(),
            total_ram: 0,
            mmio_allocator: MmioAllocator::new(mmio_base, mmio_size),
            initialized: false,
        }
    }

    /// Initializes the memory manager with the given RAM size.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub fn initialize(&mut self, ram_size: u64) -> Result<()> {
        if self.initialized {
            return Err(VmmError::Memory("Already initialized".to_string()));
        }

        // Create main RAM region at address 0
        let ram_region = MemoryRegionInfo {
            guest_addr: GuestAddress::new(0),
            size: ram_size,
            region_type: MemoryRegionType::Ram,
            name: "ram".to_string(),
            host_addr: None, // Will be set when actually mapped
        };

        self.regions.insert(0, ram_region);
        self.total_ram = ram_size;
        self.initialized = true;

        tracing::debug!(
            "Memory manager initialized: RAM={}MB",
            ram_size / (1024 * 1024)
        );
        Ok(())
    }

    /// Returns whether memory is initialized.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns the total RAM size.
    #[must_use]
    pub fn total_ram(&self) -> u64 {
        self.total_ram
    }

    /// Allocates an MMIO region.
    ///
    /// # Errors
    ///
    /// Returns an error if MMIO space is exhausted.
    pub fn allocate_mmio(&mut self, size: u64, name: &str) -> Result<u64> {
        let addr = self
            .mmio_allocator
            .allocate(size)
            .ok_or_else(|| VmmError::Memory("MMIO space exhausted".to_string()))?;

        let region = MemoryRegionInfo {
            guest_addr: GuestAddress::new(addr),
            size: (size + 0xFFF) & !0xFFF,
            region_type: MemoryRegionType::Mmio,
            name: name.to_string(),
            host_addr: None,
        };

        self.regions.insert(addr, region);

        tracing::debug!(
            "Allocated MMIO region '{}' at {:#x}, size={}",
            name,
            addr,
            size
        );
        Ok(addr)
    }

    /// Adds a memory region.
    ///
    /// # Errors
    ///
    /// Returns an error if the region overlaps with existing regions.
    pub fn add_region(&mut self, region: MemoryRegion) -> Result<()> {
        let addr = region.guest_addr.raw();
        let end = addr + region.size;

        // Check for overlaps
        for (existing_addr, existing) in &self.regions {
            let existing_end = *existing_addr + existing.size;
            if addr < existing_end && end > *existing_addr {
                return Err(VmmError::Memory(format!(
                    "Region at {:#x} overlaps with existing region '{}'",
                    addr, existing.name
                )));
            }
        }

        let info = MemoryRegionInfo {
            guest_addr: region.guest_addr,
            size: region.size,
            region_type: if region.read_only {
                MemoryRegionType::Rom
            } else {
                MemoryRegionType::Ram
            },
            name: format!("region_{:#x}", addr),
            host_addr: region.host_addr,
        };

        self.regions.insert(addr, info);
        Ok(())
    }

    /// Finds the region containing the given address.
    #[must_use]
    pub fn find_region(&self, addr: GuestAddress) -> Option<&MemoryRegionInfo> {
        // Find the region with the largest start address <= addr
        self.regions
            .range(..=addr.raw())
            .next_back()
            .map(|(_, region)| region)
            .filter(|region| addr.raw() < region.guest_addr.raw() + region.size)
    }

    /// Returns an iterator over all memory regions.
    pub fn regions(&self) -> impl Iterator<Item = &MemoryRegionInfo> {
        self.regions.values()
    }

    /// Returns the memory layout for device tree generation.
    #[must_use]
    pub fn memory_layout(&self) -> Vec<(u64, u64)> {
        self.regions
            .values()
            .filter(|r| r.region_type == MemoryRegionType::Ram)
            .map(|r| (r.guest_addr.raw(), r.size))
            .collect()
    }
}

impl Default for MemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_manager_creation() {
        let manager = MemoryManager::new();
        assert!(!manager.is_initialized());
        assert_eq!(manager.total_ram(), 0);
    }

    #[test]
    fn test_memory_initialization() {
        let mut manager = MemoryManager::new();
        let ram_size = 512 * 1024 * 1024;

        manager.initialize(ram_size).unwrap();

        assert!(manager.is_initialized());
        assert_eq!(manager.total_ram(), ram_size);

        // Can't initialize twice
        assert!(manager.initialize(ram_size).is_err());
    }

    #[test]
    fn test_mmio_allocation() {
        let mut manager = MemoryManager::new();
        manager.initialize(512 * 1024 * 1024).unwrap();

        let addr1 = manager.allocate_mmio(4096, "device1").unwrap();
        let addr2 = manager.allocate_mmio(8192, "device2").unwrap();

        assert!(addr2 > addr1);

        // Find the regions
        let region1 = manager.find_region(GuestAddress::new(addr1));
        assert!(region1.is_some());
        assert_eq!(region1.unwrap().name, "device1");
    }

    #[test]
    fn test_region_overlap_detection() {
        let mut manager = MemoryManager::new();
        manager.initialize(512 * 1024 * 1024).unwrap();

        // Try to add overlapping region
        let region = MemoryRegion::new(GuestAddress::new(0x1000), 0x1000);
        // This overlaps with the main RAM region
        assert!(manager.add_region(region).is_err());
    }
}
