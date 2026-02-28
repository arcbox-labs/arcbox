//! Network device configuration.

use crate::error::{VZError, VZResult};
use crate::ffi::{file_handle_for_fd, get_class};
use crate::{msg_send, msg_send_void};
use objc2::runtime::AnyObject;
use std::os::unix::io::RawFd;

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

    /// Creates a network device with file handle attachment.
    ///
    /// This gives the host direct access to raw L2 Ethernet frames from the
    /// guest via a connected datagram socket. The caller is responsible for
    /// all network processing (ARP, DHCP, DNS, NAT) on the host side.
    pub fn file_handle(fd: RawFd) -> VZResult<Self> {
        let net_handle = file_handle_for_fd(fd);

        if net_handle.is_null() {
            return Err(VZError::Internal {
                code: -1,
                message: "Failed to create NSFileHandle for network fd".into(),
            });
        }

        let attachment = create_file_handle_attachment(net_handle)?;
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

fn create_file_handle_attachment(
    file_handle: *mut AnyObject,
) -> VZResult<*mut AnyObject> {
    unsafe {
        let cls = get_class("VZFileHandleNetworkDeviceAttachment").ok_or_else(|| {
            VZError::Internal {
                code: -1,
                message: "VZFileHandleNetworkDeviceAttachment class not found".into(),
            }
        })?;

        let obj = msg_send!(cls, alloc);

        // Wrap the init call to catch ObjC exceptions (which would
        // otherwise abort the process as "foreign exceptions").
        let obj_safe = std::panic::AssertUnwindSafe(obj);
        let fh_safe = std::panic::AssertUnwindSafe(file_handle);
        let result = objc2::exception::catch(move || {
            let obj = *obj_safe;
            let fh = *fh_safe;
            msg_send!(obj, initWithFileHandle: fh)
        });

        let attachment = match result {
            Ok(ptr) => ptr,
            Err(exception) => {
                // Extract NSException description for diagnostics.
                let desc = match exception {
                    Some(exc) => {
                        let raw = &*exc as *const _ as *const AnyObject as *mut AnyObject;
                        crate::ffi::nsstring_to_string(msg_send!(raw, description))
                    }
                    None => "unknown ObjC exception (nil)".into(),
                };
                tracing::error!("VZFileHandleNetworkDeviceAttachment init threw: {}", desc);
                return Err(VZError::Internal {
                    code: -2,
                    message: format!(
                        "VZFileHandleNetworkDeviceAttachment init threw ObjC exception: {}",
                        desc
                    ),
                });
            }
        };

        if attachment.is_null() {
            return Err(VZError::Internal {
                code: -1,
                message: "Failed to create file handle network attachment".into(),
            });
        }

        Ok(attachment)
    }
}

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
