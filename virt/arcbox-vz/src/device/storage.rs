//! Storage device configuration.

use crate::error::{VZError, VZResult};
use crate::shim_ffi;
use std::ffi::{CString, c_void};
use std::path::Path;
use std::ptr;

/// Configuration for a `VirtIO` block storage device.
pub struct StorageDeviceConfiguration {
    inner: *mut c_void,
}

// SAFETY: The inner pointer is an ObjC configuration object created by the
// shim; it is not mutated concurrently.
unsafe impl Send for StorageDeviceConfiguration {}

impl StorageDeviceConfiguration {
    /// Creates a storage device from a disk image file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the disk image file
    /// * `read_only` - If true, the disk is mounted read-only
    pub fn disk_image(path: impl AsRef<Path>, read_only: bool) -> VZResult<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(VZError::NotFound(path.display().to_string()));
        }
        let c_path = CString::new(path.to_string_lossy().as_bytes()).map_err(|_| {
            VZError::InvalidConfiguration(format!("path contains NUL: {}", path.display()))
        })?;

        // SAFETY: c_path is valid; on failure the shim writes a strdup'd
        // message that take_error_string frees.
        unsafe {
            let mut error: *mut std::ffi::c_char = ptr::null_mut();
            let obj =
                shim_ffi::abx_storage_disk_image_new(c_path.as_ptr(), read_only, &raw mut error);
            if obj.is_null() {
                return Err(VZError::InvalidConfiguration(shim_ffi::take_error_string(
                    error,
                )));
            }
            Ok(Self { inner: obj })
        }
    }

    /// Consumes the configuration and returns the raw pointer.
    #[must_use]
    pub(crate) fn into_ptr(self) -> *mut c_void {
        let ptr = self.inner;
        std::mem::forget(self);
        ptr
    }
}

impl Drop for StorageDeviceConfiguration {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: releasing the +1 handle returned by the shim.
            unsafe { shim_ffi::abx_object_release(self.inner.cast()) };
        }
    }
}
