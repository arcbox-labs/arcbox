//! Guest memory types and utilities.

use std::fmt;

/// A guest physical address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct GuestAddress(pub u64);

impl GuestAddress {
    /// Creates a new guest address.
    #[must_use]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// Returns the raw address value.
    #[must_use]
    pub const fn raw(&self) -> u64 {
        self.0
    }

    /// Returns the address offset by the given amount.
    #[must_use]
    pub const fn offset(&self, offset: u64) -> Self {
        Self(self.0 + offset)
    }

    /// Aligns the address up to the given alignment.
    #[must_use]
    pub const fn align_up(&self, alignment: u64) -> Self {
        let mask = alignment - 1;
        Self((self.0 + mask) & !mask)
    }

    /// Aligns the address down to the given alignment.
    #[must_use]
    pub const fn align_down(&self, alignment: u64) -> Self {
        let mask = alignment - 1;
        Self(self.0 & !mask)
    }

    /// Checks if the address is aligned to the given alignment.
    #[must_use]
    pub const fn is_aligned(&self, alignment: u64) -> bool {
        self.0 & (alignment - 1) == 0
    }
}

impl fmt::Display for GuestAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl From<u64> for GuestAddress {
    fn from(addr: u64) -> Self {
        Self(addr)
    }
}

impl From<GuestAddress> for u64 {
    fn from(addr: GuestAddress) -> Self {
        addr.0
    }
}

/// A contiguous region of guest memory.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Guest physical address of the region start.
    pub guest_addr: GuestAddress,
    /// Size of the region in bytes.
    pub size: u64,
    /// Host virtual address (if mapped).
    pub host_addr: Option<*mut u8>,
    /// Whether the region is read-only.
    pub read_only: bool,
}

impl MemoryRegion {
    /// Creates a new memory region.
    #[must_use]
    pub const fn new(guest_addr: GuestAddress, size: u64) -> Self {
        Self {
            guest_addr,
            size,
            host_addr: None,
            read_only: false,
        }
    }

    /// Returns the end address of the region (exclusive).
    #[must_use]
    pub const fn end(&self) -> GuestAddress {
        GuestAddress(self.guest_addr.0 + self.size)
    }

    /// Checks if the region contains the given address.
    #[must_use]
    pub const fn contains(&self, addr: GuestAddress) -> bool {
        addr.0 >= self.guest_addr.0 && addr.0 < self.guest_addr.0 + self.size
    }

    /// Checks if the region contains the given range.
    #[must_use]
    pub const fn contains_range(&self, addr: GuestAddress, size: u64) -> bool {
        addr.0 >= self.guest_addr.0 && addr.0 + size <= self.guest_addr.0 + self.size
    }
}

// Safety: The host_addr pointer, if present, points to memory that is valid
// for the lifetime of the VM and is properly synchronized.
unsafe impl Send for MemoryRegion {}
unsafe impl Sync for MemoryRegion {}

/// Standard page size (4KB).
pub const PAGE_SIZE: u64 = 4096;

/// Large page size (2MB).
pub const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// Huge page size (1GB).
pub const HUGE_PAGE_SIZE: u64 = 1024 * 1024 * 1024;
