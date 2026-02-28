//! Memory allocation utilities.
//!
//! Provides functions for allocating and freeing guest memory using mmap.

use crate::error::{VZError, VZResult};
use std::ptr;

/// Allocates guest memory using mmap.
///
/// The allocated memory is zero-initialized.
///
/// # Arguments
///
/// * `size` - The size of the memory region in bytes
///
/// # Returns
///
/// A pointer to the allocated memory region.
///
/// # Errors
///
/// Returns an error if mmap fails.
pub fn allocate_memory(size: u64) -> VZResult<*mut u8> {
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
            return Err(VZError::Internal {
                code: *libc::__error(),
                message: "mmap failed".to_string(),
            });
        }

        // Zero-initialize the memory
        libc::memset(ptr, 0, size as usize);

        tracing::debug!("Allocated {}MB of guest memory", size / (1024 * 1024));

        Ok(ptr.cast::<u8>())
    }
}

/// Frees previously allocated guest memory.
///
/// # Arguments
///
/// * `ptr` - Pointer to the memory region to free
/// * `size` - Size of the memory region in bytes
///
/// # Safety
///
/// The `ptr` must be a valid pointer returned by `allocate_memory`,
/// and `size` must match the size used during allocation.
pub fn free_memory(ptr: *mut u8, size: u64) {
    if !ptr.is_null() {
        unsafe {
            libc::munmap(ptr.cast(), size as usize);
        }
        tracing::debug!("Freed {}MB of guest memory", size / (1024 * 1024));
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_and_free() {
        let size = 16 * 1024 * 1024; // 16MB
        let ptr = allocate_memory(size).expect("allocation failed");
        assert!(!ptr.is_null());

        // Test we can write to it
        unsafe {
            *ptr = 42;
            assert_eq!(*ptr, 42);
        }

        free_memory(ptr, size);
    }

    #[test]
    fn test_memory_is_zeroed() {
        let size = 4096;
        let ptr = allocate_memory(size).expect("allocation failed");

        // Verify memory is zeroed
        unsafe {
            for i in 0..size as usize {
                assert_eq!(*ptr.add(i), 0);
            }
        }

        free_memory(ptr, size);
    }
}
