//! macOS graphics device configuration.

use crate::error::VZResult;
use crate::shim_ffi;
use std::ffi::c_void;

/// Configuration for a macOS graphics device with a single display.
///
/// A macOS guest requires at least one graphics device to start. This creates a
/// `VZMacGraphicsDeviceConfiguration` holding one `VZMacGraphicsDisplayConfiguration`.
pub struct MacGraphicsDeviceConfiguration {
    inner: *mut c_void,
}

// SAFETY: The inner pointer is an ObjC configuration object created by the
// shim; it is not mutated concurrently.
unsafe impl Send for MacGraphicsDeviceConfiguration {}

impl MacGraphicsDeviceConfiguration {
    /// Creates a graphics device with a single display of the given pixel
    /// dimensions and pixel density.
    ///
    /// # Errors
    ///
    /// Currently infallible (kept as `VZResult` for API stability).
    pub fn new(
        width_in_pixels: isize,
        height_in_pixels: isize,
        pixels_per_inch: isize,
    ) -> VZResult<Self> {
        // SAFETY: the shim returns a +1 handle, released by Drop.
        let obj = unsafe {
            shim_ffi::abx_graphics_mac_new(
                width_in_pixels as i64,
                height_in_pixels as i64,
                pixels_per_inch as i64,
            )
        };
        Ok(Self { inner: obj })
    }

    /// Consumes the configuration and returns the raw pointer.
    #[must_use]
    pub(crate) fn into_ptr(self) -> *mut c_void {
        let ptr = self.inner;
        std::mem::forget(self);
        ptr
    }
}

impl Drop for MacGraphicsDeviceConfiguration {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: releasing the +1 handle returned by the shim.
            unsafe { shim_ffi::abx_object_release(self.inner.cast()) };
        }
    }
}
