//! Memory balloon device configuration.
//!
//! The balloon device allows the host to reclaim memory from the guest
//! by "inflating" the balloon (reducing guest memory) or "deflating" it
//! (returning memory to the guest).

use crate::error::{VZError, VZResult};
use crate::ffi::get_class;
use crate::{msg_send, msg_send_u64, msg_send_void_u64};
use objc2::runtime::AnyObject;

// ============================================================================
// Balloon Device Configuration
// ============================================================================

/// Configuration for a VirtIO traditional memory balloon device.
///
/// This device allows dynamic memory management between the host and guest.
/// The host can reclaim memory from the guest by inflating the balloon,
/// or return memory to the guest by deflating it.
pub struct MemoryBalloonDeviceConfiguration {
    inner: *mut AnyObject,
}

unsafe impl Send for MemoryBalloonDeviceConfiguration {}

impl MemoryBalloonDeviceConfiguration {
    /// Creates a new memory balloon device configuration.
    pub fn new() -> VZResult<Self> {
        unsafe {
            let cls =
                get_class("VZVirtioTraditionalMemoryBalloonDeviceConfiguration").ok_or_else(
                    || VZError::Internal {
                        code: -1,
                        message: "VZVirtioTraditionalMemoryBalloonDeviceConfiguration not found"
                            .into(),
                    },
                )?;
            let obj = msg_send!(cls, new);

            if obj.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to create balloon device configuration".into(),
                });
            }

            // Retain to prevent autorelease
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

impl Default for MemoryBalloonDeviceConfiguration {
    fn default() -> Self {
        Self::new().expect("Failed to create balloon device configuration")
    }
}

impl Drop for MemoryBalloonDeviceConfiguration {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            crate::ffi::release(self.inner);
        }
    }
}

// ============================================================================
// Memory Balloon Device (Runtime)
// ============================================================================

/// A running VirtIO memory balloon device.
///
/// This represents an active balloon device on a running VM.
/// Use `set_target_memory_size()` to adjust the balloon.
pub struct MemoryBalloonDevice {
    inner: *mut AnyObject,
}

unsafe impl Send for MemoryBalloonDevice {}
unsafe impl Sync for MemoryBalloonDevice {}

impl MemoryBalloonDevice {
    /// Creates a balloon device wrapper from a raw pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `ptr` is a valid `VZVirtioTraditionalMemoryBalloonDevice`.
    pub(crate) fn from_raw(ptr: *mut AnyObject) -> Self {
        Self { inner: ptr }
    }

    /// Sets the target virtual machine memory size.
    ///
    /// The balloon device will inflate or deflate to reach the target memory size.
    /// - A smaller target means the balloon inflates (reclaims memory from guest)
    /// - A larger target means the balloon deflates (returns memory to guest)
    ///
    /// # Arguments
    ///
    /// * `bytes` - Target memory size in bytes
    pub fn set_target_memory_size(&self, bytes: u64) {
        if self.inner.is_null() {
            tracing::warn!("set_target_memory_size called on null device");
            return;
        }
        unsafe {
            msg_send_void_u64!(self.inner, setTargetVirtualMachineMemorySize: bytes);
        }
        tracing::debug!(
            "Set balloon target memory to {} bytes ({}MB)",
            bytes,
            bytes / (1024 * 1024)
        );
    }

    /// Gets the target virtual machine memory size.
    ///
    /// Returns the target memory size in bytes.
    pub fn target_memory_size(&self) -> u64 {
        if self.inner.is_null() {
            tracing::warn!("target_memory_size called on null device");
            return 0;
        }
        unsafe { msg_send_u64!(self.inner, targetVirtualMachineMemorySize) }
    }

    /// Returns the raw object pointer.
    pub fn as_ptr(&self) -> *mut AnyObject {
        self.inner
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Gets the memory balloon devices from a running VM.
///
/// # Arguments
///
/// * `vm_ptr` - Raw pointer to VZVirtualMachine
///
/// # Returns
///
/// A vector of `MemoryBalloonDevice` wrappers.
pub(crate) fn vm_memory_balloon_devices(vm_ptr: *mut AnyObject) -> Vec<MemoryBalloonDevice> {
    if vm_ptr.is_null() {
        return Vec::new();
    }

    unsafe {
        let devices: *mut AnyObject = msg_send!(vm_ptr, memoryBalloonDevices);
        if devices.is_null() {
            return Vec::new();
        }

        let count = crate::ffi::nsarray_count(devices);
        let mut result = Vec::with_capacity(count);

        for i in 0..count {
            let device = crate::ffi::nsarray_object_at_index(devices, i);
            if !device.is_null() {
                result.push(MemoryBalloonDevice::from_raw(device));
            }
        }

        result
    }
}

