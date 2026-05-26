//! Page-aligned guest RAM allocation for tests.
//!
//! Superseded by `GuestMemoryMmap` in the live boot path; retained for
//! unit tests that need a raw host allocation to simulate guest memory.

use std::alloc::{Layout, alloc_zeroed, dealloc};

use crate::error::{Result, VmmError};

use super::PAGE_SIZE;

/// Holds a page-aligned host allocation that backs guest RAM.
pub(super) struct GuestRam {
    ptr: *mut u8,
    layout: Layout,
}

// SAFETY: `GuestRam` wraps a heap allocation via `alloc_zeroed` / `dealloc`.
// The raw `*mut u8` is only reached through `&mut self` (exclusive) slice
// views — raw pointer access does not alias across threads. Send/Sync are
// safe because the backing allocation is not thread-local and the mutex
// discipline is owned by the test harness.
unsafe impl Send for GuestRam {}
unsafe impl Sync for GuestRam {}

impl GuestRam {
    /// Allocates page-aligned zeroed memory for guest RAM.
    pub fn new(size: usize) -> Result<Self> {
        let layout = Layout::from_size_align(size, PAGE_SIZE)
            .map_err(|e| VmmError::Memory(format!("invalid RAM layout: {e}")))?;

        // SAFETY: Layout is valid and non-zero.
        let ptr = unsafe { alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err(VmmError::Memory(format!(
                "failed to allocate {} bytes for guest RAM",
                size
            )));
        }

        Ok(Self { ptr, layout })
    }

    /// Returns the host pointer to guest RAM.
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Returns guest RAM as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: ptr was allocated with this layout by alloc_zeroed and
        // &mut self guarantees exclusive access.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.layout.size()) }
    }

    pub fn size(&self) -> usize {
        self.layout.size()
    }
}

impl Drop for GuestRam {
    fn drop(&mut self) {
        // SAFETY: ptr was allocated with this layout by alloc_zeroed.
        unsafe { dealloc(self.ptr, self.layout) };
    }
}
