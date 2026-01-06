//! Network device configuration.

use crate::error::{VZError, VZResult};
use crate::ffi::get_class;
use crate::{msg_send, msg_send_void};
use objc2::runtime::AnyObject;

/// Configuration for a VirtIO network device.
pub struct NetworkDeviceConfiguration {
    inner: *mut AnyObject,
}

unsafe impl Send for NetworkDeviceConfiguration {}

impl NetworkDeviceConfiguration {
    /// Creates a network device with NAT attachment.
    ///
    /// NAT allows the guest to access external networks through the host.
    pub fn nat() -> VZResult<Self> {
        let attachment = create_nat_attachment()?;
        Self::with_attachment(attachment)
    }

    /// Creates a network device with the given attachment.
    fn with_attachment(attachment: *mut AnyObject) -> VZResult<Self> {
        unsafe {
            let cls = get_class("VZVirtioNetworkDeviceConfiguration").ok_or_else(|| {
                VZError::Internal {
                    code: -1,
                    message: "VZVirtioNetworkDeviceConfiguration class not found".into(),
                }
            })?;
            let obj = msg_send!(cls, new);

            if obj.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to create network device".into(),
                });
            }

            msg_send_void!(obj, setAttachment: attachment);

            // Set random MAC address
            if let Ok(mac) = create_random_mac() {
                msg_send_void!(obj, setMACAddress: mac);
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

impl Drop for NetworkDeviceConfiguration {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            crate::ffi::release(self.inner);
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn create_nat_attachment() -> VZResult<*mut AnyObject> {
    unsafe {
        let cls = get_class("VZNATNetworkDeviceAttachment").ok_or_else(|| VZError::Internal {
            code: -1,
            message: "VZNATNetworkDeviceAttachment class not found".into(),
        })?;
        let obj = msg_send!(cls, new);

        if obj.is_null() {
            return Err(VZError::Internal {
                code: -1,
                message: "Failed to create NAT attachment".into(),
            });
        }

        Ok(obj)
    }
}

fn create_random_mac() -> VZResult<*mut AnyObject> {
    unsafe {
        let cls = get_class("VZMACAddress").ok_or_else(|| VZError::Internal {
            code: -1,
            message: "VZMACAddress class not found".into(),
        })?;
        let obj = msg_send!(cls, randomLocallyAdministeredAddress);

        if obj.is_null() {
            return Err(VZError::Internal {
                code: -1,
                message: "Failed to create random MAC".into(),
            });
        }

        Ok(obj)
    }
}
