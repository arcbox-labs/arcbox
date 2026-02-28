//! Platform configurations.

use crate::error::{VZError, VZResult};
use crate::ffi::{get_class, release};
use crate::{msg_send, msg_send_bool, msg_send_void_bool};
use objc2::runtime::{AnyObject, Bool};

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

    /// Returns whether the hardware supports nested virtualization.
    ///
    /// Requires macOS 15+ and Apple M3 or later. On older systems, the
    /// selector does not exist and this returns `false`.
    pub fn is_nested_virt_supported() -> bool {
        let Some(cls) = get_class("VZGenericPlatformConfiguration") else {
            return false;
        };
        // `isNestedVirtualizationSupported` is a *class* method.
        // `AnyClass::responds_to` checks instance methods, so use
        // `class_method` which queries the metaclass instead.
        let sel = objc2::sel!(isNestedVirtualizationSupported);
        if cls.class_method(sel).is_none() {
            return false;
        }
        unsafe { msg_send_bool!(cls, isNestedVirtualizationSupported).as_bool() }
    }

    /// Enables or disables nested virtualization for this platform config.
    ///
    /// Only has effect when [`Self::is_nested_virt_supported()`] returns `true`.
    pub fn set_nested_virt_enabled(&self, enabled: bool) {
        // Guard: the setter selector only exists on macOS 15+.
        let sel = objc2::sel!(setNestedVirtualizationEnabled:);
        if !unsafe { &*(self.inner as *const AnyObject) }
            .class()
            .responds_to(sel)
        {
            return;
        }
        unsafe {
            msg_send_void_bool!(self.inner, setNestedVirtualizationEnabled: Bool::new(enabled));
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
