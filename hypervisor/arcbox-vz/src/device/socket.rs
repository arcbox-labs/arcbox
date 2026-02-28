//! Socket device configuration.

use crate::error::{VZError, VZResult};
use crate::ffi::get_class;
use crate::msg_send;
use objc2::runtime::AnyObject;

/// Configuration for a VirtIO socket device.
///
/// This device enables vsock communication between the host and guest.
pub struct SocketDeviceConfiguration {
    inner: *mut AnyObject,
}

unsafe impl Send for SocketDeviceConfiguration {}

impl SocketDeviceConfiguration {
    /// Creates a new socket device configuration.
    pub fn new() -> VZResult<Self> {
        unsafe {
            let cls = get_class("VZVirtioSocketDeviceConfiguration").ok_or_else(|| {
                VZError::Internal {
                    code: -1,
                    message: "VZVirtioSocketDeviceConfiguration class not found".into(),
                }
            })?;
            let obj = msg_send!(cls, new);

            if obj.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to create socket device".into(),
                });
            }

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

impl Default for SocketDeviceConfiguration {
    fn default() -> Self {
        Self::new().expect("Failed to create socket device configuration")
    }
}

impl Drop for SocketDeviceConfiguration {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            crate::ffi::release(self.inner);
        }
    }
}
