//! Entropy device configuration.

use crate::error::{VZError, VZResult};
use crate::ffi::get_class;
use crate::msg_send;
use objc2::runtime::AnyObject;

/// Configuration for a VirtIO entropy device.
///
/// This device provides random number generation to the guest OS.
pub struct EntropyDeviceConfiguration {
    inner: *mut AnyObject,
}

unsafe impl Send for EntropyDeviceConfiguration {}

impl EntropyDeviceConfiguration {
    /// Creates a new entropy device configuration.
    pub fn new() -> VZResult<Self> {
        unsafe {
            let cls = get_class("VZVirtioEntropyDeviceConfiguration").ok_or_else(|| {
                VZError::Internal {
                    code: -1,
                    message: "VZVirtioEntropyDeviceConfiguration class not found".into(),
                }
            })?;
            let obj = msg_send!(cls, new);

            if obj.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to create entropy device".into(),
                });
            }

            // Retain
            let _: *mut AnyObject = msg_send!(obj, retain);

            Ok(Self { inner: obj })
        }
    }

    /// Consumes the configuration and returns the raw pointer.
    pub fn into_ptr(self) -> *mut AnyObject {
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
            crate::ffi::release(self.inner);
        }
    }
}
