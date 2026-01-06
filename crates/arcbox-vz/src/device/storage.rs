//! Storage device configuration.

use crate::error::{VZError, VZResult};
use crate::ffi::{get_class, nsurl_file_path};
use crate::msg_send;
use objc2::runtime::{AnyObject, Bool};
use std::ffi::c_void;
use std::path::Path;
use std::ptr;

/// Configuration for a VirtIO block storage device.
pub struct StorageDeviceConfiguration {
    inner: *mut AnyObject,
}

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

        let attachment = create_disk_attachment(&path.to_string_lossy(), read_only)?;
        Self::with_attachment(attachment)
    }

    /// Creates a storage device with the given attachment.
    fn with_attachment(attachment: *mut AnyObject) -> VZResult<Self> {
        unsafe {
            let cls =
                get_class("VZVirtioBlockDeviceConfiguration").ok_or_else(|| VZError::Internal {
                    code: -1,
                    message: "VZVirtioBlockDeviceConfiguration class not found".into(),
                })?;
            let alloc = msg_send!(cls, alloc);
            let obj = msg_send!(alloc, initWithAttachment: attachment);

            if obj.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to create block device".into(),
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

impl Drop for StorageDeviceConfiguration {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            crate::ffi::release(self.inner);
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn create_disk_attachment(path: &str, read_only: bool) -> VZResult<*mut AnyObject> {
    unsafe {
        let cls =
            get_class("VZDiskImageStorageDeviceAttachment").ok_or_else(|| VZError::Internal {
                code: -1,
                message: "VZDiskImageStorageDeviceAttachment class not found".into(),
            })?;

        let url = nsurl_file_path(path);
        let mut error: *mut AnyObject = ptr::null_mut();

        let sel = objc2::sel!(initWithURL:readOnly:error:);
        let alloc = msg_send!(cls, alloc);

        let func: unsafe extern "C" fn(
            *mut AnyObject,
            objc2::runtime::Sel,
            *mut AnyObject,
            Bool,
            *mut *mut AnyObject,
        ) -> *mut AnyObject =
            std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);

        let obj = func(alloc, sel, url, Bool::new(read_only), &mut error);

        if obj.is_null() {
            return Err(crate::ffi::extract_nserror(error));
        }

        Ok(obj)
    }
}
