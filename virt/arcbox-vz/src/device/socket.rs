//! Socket device configuration.

use crate::error::VZResult;
use crate::shim_ffi;
use std::ffi::c_void;

/// Configuration for a `VirtIO` socket device.
///
/// This device enables vsock communication between the host and guest.
pub struct SocketDeviceConfiguration {
    inner: *mut c_void,
}

// SAFETY: The inner pointer is an ObjC configuration object created by the
// shim; it is not mutated concurrently.
unsafe impl Send for SocketDeviceConfiguration {}

impl SocketDeviceConfiguration {
    /// Creates a new socket device configuration.
    pub fn new() -> VZResult<Self> {
        // SAFETY: the shim returns a +1 handle, released by Drop.
        let obj = unsafe { shim_ffi::abx_socket_device_config_new() };
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

impl Default for SocketDeviceConfiguration {
    fn default() -> Self {
        Self::new().expect("Failed to create socket device configuration")
    }
}

impl Drop for SocketDeviceConfiguration {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: releasing the +1 handle returned by the shim.
            unsafe { shim_ffi::abx_object_release(self.inner.cast()) };
        }
    }
}
