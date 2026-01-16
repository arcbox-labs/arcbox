//! Platform configurations.

use crate::error::{VZError, VZResult};
use crate::ffi::{get_class, release};
use crate::msg_send;
use objc2::runtime::AnyObject;

// ============================================================================
// Platform Trait
// ============================================================================

/// Trait for platform configurations.
pub trait Platform {
    /// Returns the underlying Objective-C object pointer.
    fn as_ptr(&self) -> *mut AnyObject;
}

// ============================================================================
// Generic Platform
// ============================================================================

/// A generic platform configuration for Linux VMs.
///
/// This platform works on both Apple Silicon and Intel Macs.
pub struct GenericPlatform {
    inner: *mut AnyObject,
}

unsafe impl Send for GenericPlatform {}

impl GenericPlatform {
    /// Creates a new generic platform configuration.
    pub fn new() -> VZResult<Self> {
        unsafe {
            let cls =
                get_class("VZGenericPlatformConfiguration").ok_or_else(|| VZError::Internal {
                    code: -1,
                    message: "VZGenericPlatformConfiguration class not found".into(),
                })?;
            let obj = msg_send!(cls, new);

            if obj.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to create generic platform".into(),
                });
            }

            // Retain to prevent autorelease
            let _: *mut AnyObject = msg_send!(obj, retain);

            Ok(Self { inner: obj })
        }
    }
}

impl Default for GenericPlatform {
    fn default() -> Self {
        Self::new().expect("Failed to create generic platform")
    }
}

impl Platform for GenericPlatform {
    fn as_ptr(&self) -> *mut AnyObject {
        self.inner
    }
}

impl Drop for GenericPlatform {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            release(self.inner);
        }
    }
}
