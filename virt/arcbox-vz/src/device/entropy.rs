//! Entropy device configuration.

use crate::error::VZResult;
use crate::shim_ffi;
use objc2::runtime::AnyObject;

/// Configuration for a `VirtIO` entropy device.
///
/// This device provides random number generation to the guest OS.
pub struct EntropyDeviceConfiguration {
    inner: *mut AnyObject,
}

// SAFETY: The inner pointer is an ObjC configuration object created by the
// shim; it is not mutated concurrently.
unsafe impl Send for EntropyDeviceConfiguration {}

impl EntropyDeviceConfiguration {
    /// Creates a new entropy device configuration.
    pub fn new() -> VZResult<Self> {
        // SAFETY: the shim returns a +1 handle, released by Drop.
        let obj = unsafe { shim_ffi::abx_entropy_new() };
        Ok(Self {
            inner: obj as *mut AnyObject,
        })
    }

    /// Consumes the configuration and returns the raw pointer.
    #[must_use]
    pub(crate) fn into_ptr(self) -> *mut AnyObject {
        let ptr = self.inner;
        std::mem::forget(self);
        ptr
    }
}

impl Default for EntropyDeviceConfiguration {
    fn default() -> Self {
        Self::new().expect("Failed to create entropy device")
    }
}

impl Drop for EntropyDeviceConfiguration {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: releasing the +1 handle returned by the shim.
            unsafe { shim_ffi::abx_object_release(self.inner.cast()) };
        }
    }
}
