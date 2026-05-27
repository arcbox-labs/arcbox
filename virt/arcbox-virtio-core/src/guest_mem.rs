//! Guest memory accessor for direct virtqueue manipulation.
//!
//! Provides safe-ish wrappers around a raw pointer into the guest RAM
//! mmap. All methods accept guest physical addresses (GPAs) and
//! translate them to host offsets by subtracting `gpa_base`.

/// Raw pointer wrapper for guest physical memory access.
///
/// Backed by the VM-lifetime mmap of guest RAM. Device-owned descriptor
/// buffers are exclusive to the device per the VirtIO spec — the
/// guest will not touch them until the used ring advances.
///
/// All public methods accept guest physical addresses (GPAs) and translate
/// them to slice offsets by subtracting `gpa_base`.
pub struct GuestMemWriter {
    ptr: *mut u8,
    len: usize,
    /// GPA of the start of guest RAM. Subtracted from every GPA argument
    /// to obtain the host pointer offset within `ptr..ptr+len`.
    gpa_base: usize,
}

// SAFETY: The pointer originates from a VM-lifetime mmap. The worker
// thread writes only to descriptor buffers (device-owned) and the used
// ring (with Release fences). No concurrent mutation from the guest is
// possible for device-owned buffers per the VirtIO spec.
unsafe impl Send for GuestMemWriter {}
unsafe impl Sync for GuestMemWriter {}

impl GuestMemWriter {
    /// Creates a new writer from the DeviceManager's guest memory.
    ///
    /// `ptr` must point to the host mapping of guest RAM, which starts
    /// at GPA `gpa_base`. `len` is the size of that mapping in bytes.
    ///
    /// # Safety
    /// `ptr` must be valid for `len` bytes for the lifetime of the VM.
    pub unsafe fn new(ptr: *mut u8, len: usize, gpa_base: usize) -> Self {
        Self { ptr, len, gpa_base }
    }

    /// Translates a GPA to a host pointer offset, returning `None` if the
    /// GPA falls below `gpa_base` (invalid) or the range exceeds the
    /// mapped region.
    pub fn gpa_to_offset(&self, gpa: usize, access_len: usize) -> Option<usize> {
        let off = gpa.checked_sub(self.gpa_base)?;
        let end = off.checked_add(access_len)?;
        if end > self.len {
            return None;
        }
        Some(off)
    }

    /// Returns a mutable slice into guest memory at the given GPA range.
    ///
    /// # Safety
    /// Caller must ensure no other reference (mutable or shared) to the
    /// same GPA range exists for the lifetime of the returned slice.
    /// In practice, VirtIO descriptor ownership guarantees this — each
    /// descriptor buffer is exclusive to the device that owns it.
    #[allow(clippy::mut_from_ref)] // intentional: unsafe fn documents the aliasing contract
    pub unsafe fn slice_mut(&self, gpa: usize, len: usize) -> Option<&mut [u8]> {
        let off = self.gpa_to_offset(gpa, len)?;
        // SAFETY: `gpa_to_offset` validated bounds within the allocation.
        unsafe { Some(std::slice::from_raw_parts_mut(self.ptr.add(off), len)) }
    }

    /// Returns an immutable slice into guest memory at the given GPA range.
    pub fn slice(&self, gpa: usize, len: usize) -> Option<&[u8]> {
        let off = self.gpa_to_offset(gpa, len)?;
        // SAFETY: `gpa_to_offset` validated bounds within the allocation.
        unsafe { Some(std::slice::from_raw_parts(self.ptr.add(off), len)) }
    }

    /// Reads a little-endian `u16` from the given GPA. Returns 0 on
    /// out-of-bounds access.
    pub fn read_u16(&self, gpa: usize) -> u16 {
        let Some(off) = self.gpa_to_offset(gpa, 2) else {
            return 0;
        };
        // SAFETY: `gpa_to_offset` validated bounds within the allocation.
        unsafe {
            let p = self.ptr.add(off);
            u16::from_le_bytes([*p, *p.add(1)])
        }
    }

    /// Writes a little-endian `u16` to the given GPA. No-op on
    /// out-of-bounds access.
    pub fn write_u16(&self, gpa: usize, val: u16) {
        let Some(off) = self.gpa_to_offset(gpa, 2) else {
            return;
        };
        let bytes = val.to_le_bytes();
        // SAFETY: `gpa_to_offset` validated bounds within the allocation.
        unsafe {
            let p = self.ptr.add(off);
            *p = bytes[0];
            *p.add(1) = bytes[1];
        }
    }

    /// Writes a little-endian `u32` to the given GPA. No-op on
    /// out-of-bounds access.
    pub fn write_u32(&self, gpa: usize, val: u32) {
        let Some(off) = self.gpa_to_offset(gpa, 4) else {
            return;
        };
        let bytes = val.to_le_bytes();
        // SAFETY: `gpa_to_offset` validated bounds within the allocation.
        unsafe {
            let p = self.ptr.add(off);
            *p = bytes[0];
            *p.add(1) = bytes[1];
            *p.add(2) = bytes[2];
            *p.add(3) = bytes[3];
        }
    }

    /// Writes a single byte to the given GPA. No-op on out-of-bounds
    /// access.
    pub fn write_byte(&self, gpa: usize, val: u8) {
        let Some(off) = self.gpa_to_offset(gpa, 1) else {
            return;
        };
        // SAFETY: `gpa_to_offset` validated bounds within the allocation.
        unsafe { *self.ptr.add(off) = val };
    }

    /// Returns the raw pointer to the start of guest memory.
    pub fn ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Returns the total length (in bytes) of the guest memory region.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the guest memory region has zero length.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the GPA base address of the guest memory region.
    pub fn gpa_base(&self) -> usize {
        self.gpa_base
    }
}
