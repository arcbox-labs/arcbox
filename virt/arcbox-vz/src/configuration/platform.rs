//! Platform configurations.

use crate::error::VZResult;
use std::ffi::c_void;

use super::mac::{MacAuxiliaryStorage, MacHardwareModel, MacMachineIdentifier};

/// Trait for platform configurations.
pub trait Platform {
    /// Returns the underlying Objective-C object pointer.
    fn as_ptr(&self) -> *mut c_void;
}

/// A generic platform configuration for Linux VMs.
///
/// This platform works on both Apple Silicon and Intel Macs.
pub struct GenericPlatform {
    inner: *mut c_void,
}

// SAFETY: The inner pointer is an ObjC object handle created by the shim;
// all access goes through the shim.
unsafe impl Send for GenericPlatform {}

impl GenericPlatform {
    /// Creates a new generic platform configuration.
    pub fn new() -> VZResult<Self> {
        // SAFETY: the shim returns a +1 VZGenericPlatformConfiguration
        // handle, released by Drop.
        let obj = unsafe { crate::shim_ffi::abx_platform_generic_new() };
        Ok(Self { inner: obj })
    }

    /// Returns whether the hardware supports nested virtualization.
    ///
    /// Requires macOS 15+ and Apple M3 or later; the shim's `#available`
    /// guard returns `false` on older systems.
    pub fn is_nested_virt_supported() -> bool {
        // SAFETY: class-property read behind an availability guard.
        unsafe { crate::shim_ffi::abx_platform_generic_nested_supported() }
    }

    /// Enables or disables nested virtualization for this platform config.
    ///
    /// Only has effect when [`Self::is_nested_virt_supported()`] returns
    /// `true`; on older systems the shim's `#available` guard makes this a
    /// no-op.
    pub fn set_nested_virt_enabled(&self, enabled: bool) {
        // SAFETY: self.inner is a valid platform handle.
        unsafe {
            crate::shim_ffi::abx_platform_generic_set_nested(self.inner.cast(), enabled);
        }
    }
}

impl Default for GenericPlatform {
    fn default() -> Self {
        Self::new().expect("Failed to create generic platform")
    }
}

impl Platform for GenericPlatform {
    fn as_ptr(&self) -> *mut c_void {
        self.inner
    }
}

impl Drop for GenericPlatform {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: releasing the +1 handle returned by the shim.
            unsafe { crate::shim_ffi::abx_object_release(self.inner.cast()) };
        }
    }
}

/// A platform configuration for macOS guests.
///
/// Combines a hardware model, machine identifier, and auxiliary storage into the
/// platform required to boot a macOS guest. Pair it with a
/// [`MacOSBootLoader`](crate::MacOSBootLoader) on the VM configuration.
pub struct MacPlatform {
    inner: *mut c_void,
}

// SAFETY: The inner pointer is an ObjC object handle created by the shim;
// all access goes through the shim.
unsafe impl Send for MacPlatform {}

impl MacPlatform {
    /// Creates a macOS platform from its hardware model, machine identifier, and
    /// auxiliary storage.
    ///
    /// The platform retains its own references to each component (the properties are
    /// strong), so the arguments may be dropped once this returns.
    ///
    /// # Errors
    ///
    /// Returns an error if `VZMacPlatformConfiguration` is unavailable or cannot be
    /// created.
    pub fn new(
        hardware_model: &MacHardwareModel,
        machine_identifier: &MacMachineIdentifier,
        auxiliary_storage: &MacAuxiliaryStorage,
    ) -> VZResult<Self> {
        // SAFETY: all three are valid handles; the platform's properties are
        // strong, so the arguments may be dropped after this returns.
        let obj = unsafe {
            crate::shim_ffi::abx_platform_mac_new(
                hardware_model.as_ptr().cast(),
                machine_identifier.as_ptr().cast(),
                auxiliary_storage.as_ptr().cast(),
            )
        };
        Ok(Self { inner: obj })
    }
}

impl Platform for MacPlatform {
    fn as_ptr(&self) -> *mut c_void {
        self.inner
    }
}

impl Drop for MacPlatform {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: releasing the +1 handle returned by the shim.
            unsafe { crate::shim_ffi::abx_object_release(self.inner.cast()) };
        }
    }
}
