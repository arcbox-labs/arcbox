//! Memory balloon device configuration.
//!
//! The balloon device allows the host to reclaim memory from the guest
//! by "inflating" the balloon (reducing guest memory) or "deflating" it
//! (returning memory to the guest).

use crate::error::VZResult;
use objc2::runtime::AnyObject;

// ============================================================================
// Balloon Device Configuration
// ============================================================================

/// Configuration for a `VirtIO` traditional memory balloon device.
///
/// This device allows dynamic memory management between the host and guest.
/// The host can reclaim memory from the guest by inflating the balloon,
/// or return memory to the guest by deflating it.
pub struct MemoryBalloonDeviceConfiguration {
    inner: *mut AnyObject,
}

// SAFETY: Inner ObjC pointer is only used via msg_send! which dispatches to the ObjC runtime.
unsafe impl Send for MemoryBalloonDeviceConfiguration {}

impl MemoryBalloonDeviceConfiguration {
    /// Creates a new memory balloon device configuration.
    pub fn new() -> VZResult<Self> {
        // SAFETY: the shim returns a +1 handle, released by Drop.
        let obj = unsafe { crate::shim_ffi::abx_balloon_config_new() };
        Ok(Self {
            inner: obj as *mut AnyObject,
        })
    }

    /// Consumes the configuration and returns the raw pointer.
    #[must_use]
    pub(crate) fn into_ptr(self) -> *mut AnyObject {
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
            // SAFETY: releasing the +1 handle returned by the shim.
            unsafe { crate::shim_ffi::abx_object_release(self.inner.cast()) };
        }
    }
}

// ============================================================================
// Memory Balloon Device (Runtime)
// ============================================================================

/// A running `VirtIO` memory balloon device.
///
/// This represents an active balloon device on a running VM.
/// Use `set_target_memory_size()` to adjust the balloon.
///
/// Every accessor dispatches onto the VM's serial queue (inside the shim):
/// Virtualization framework device objects are queue-affine, and calling
/// them from any other thread trips `dispatch_assert_queue` inside the
/// framework and aborts the process (observed on the idle-state balloon
/// shrink).
pub struct MemoryBalloonDevice {
    /// ABXBalloonBox handle pairing the device with the VM's queue.
    balloon_box: *mut std::ffi::c_void,
}

// SAFETY: The box handle is only used through the shim, which serializes
// every device access on the VM's queue as the framework requires.
unsafe impl Send for MemoryBalloonDevice {}
// SAFETY: See above — every method dispatches onto the VM's serial queue.
unsafe impl Sync for MemoryBalloonDevice {}

impl MemoryBalloonDevice {
    /// Wraps a +1 `ABXBalloonBox` handle produced by the shim.
    pub(crate) fn from_box(balloon_box: *mut std::ffi::c_void) -> Self {
        Self { balloon_box }
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
        // SAFETY: balloon_box is a valid handle; the shim queue-syncs the write.
        unsafe { crate::shim_ffi::abx_balloon_set_target(self.balloon_box, bytes) };
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
        // SAFETY: balloon_box is a valid handle; the shim queue-syncs the read.
        unsafe { crate::shim_ffi::abx_balloon_target(self.balloon_box) }
    }
}

impl Drop for MemoryBalloonDevice {
    fn drop(&mut self) {
        if !self.balloon_box.is_null() {
            // SAFETY: releasing the +1 box handle returned by the shim.
            unsafe { crate::shim_ffi::abx_object_release(self.balloon_box) };
        }
    }
}
