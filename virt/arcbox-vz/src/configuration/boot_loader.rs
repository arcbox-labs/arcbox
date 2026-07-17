//! Boot loader configurations.

use crate::error::{VZError, VZResult};
use crate::shim_ffi;
use std::ffi::{CString, c_void};
use std::path::Path;

/// Converts a path to a `CString`, rejecting interior NUL bytes.
fn path_cstring(path: &Path) -> VZResult<CString> {
    CString::new(path.to_string_lossy().as_bytes()).map_err(|_| {
        VZError::InvalidConfiguration(format!("path contains NUL: {}", path.display()))
    })
}

/// Trait for boot loader configurations.
pub trait BootLoader {
    /// Returns the underlying Objective-C object pointer.
    fn as_ptr(&self) -> *mut c_void;
}

/// A boot loader for Linux kernels.
///
/// This boot loader loads a Linux kernel image directly, without
/// requiring UEFI or other firmware.
pub struct LinuxBootLoader {
    inner: *mut c_void,
}

// SAFETY: The inner pointer is an ObjC object handle created by the shim;
// all access goes through the shim.
unsafe impl Send for LinuxBootLoader {}

impl LinuxBootLoader {
    /// Creates a new Linux boot loader with the specified kernel path.
    ///
    /// # Arguments
    ///
    /// * `kernel_path` - Path to the Linux kernel image (uncompressed ARM64 Image format)
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel path is invalid or the boot loader
    /// cannot be created.
    pub fn new(kernel_path: impl AsRef<Path>) -> VZResult<Self> {
        let path = kernel_path.as_ref();
        if !path.exists() {
            return Err(VZError::NotFound(path.display().to_string()));
        }

        let c_path = path_cstring(path)?;
        // SAFETY: c_path is a valid NUL-terminated string; the shim returns
        // a +1 VZLinuxBootLoader handle, released by Drop.
        let obj = unsafe { shim_ffi::abx_bootloader_linux_new(c_path.as_ptr()) };
        Ok(Self { inner: obj })
    }

    /// Sets the initial ramdisk (initrd) path.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the initrd/initramfs image
    pub fn set_initial_ramdisk(&mut self, path: impl AsRef<Path>) -> &mut Self {
        let path = path.as_ref();
        if path.exists()
            && let Ok(c_path) = path_cstring(path)
        {
            // SAFETY: valid handle and NUL-terminated path string.
            unsafe {
                shim_ffi::abx_bootloader_linux_set_initrd(self.inner.cast(), c_path.as_ptr());
            }
        }
        self
    }

    /// Sets the kernel command line arguments.
    ///
    /// # Arguments
    ///
    /// * `cmdline` - Kernel command line string (e.g., "console=hvc0 root=/dev/vda")
    pub fn set_command_line(&mut self, cmdline: &str) -> &mut Self {
        if let Ok(c_cmdline) = CString::new(cmdline) {
            // SAFETY: valid handle and NUL-terminated command-line string.
            unsafe {
                shim_ffi::abx_bootloader_linux_set_cmdline(self.inner.cast(), c_cmdline.as_ptr());
            }
        }
        self
    }
}

impl BootLoader for LinuxBootLoader {
    fn as_ptr(&self) -> *mut c_void {
        self.inner
    }
}

impl Drop for LinuxBootLoader {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: releasing the +1 handle returned by the shim.
            unsafe { shim_ffi::abx_object_release(self.inner.cast()) };
        }
    }
}

/// A boot loader for macOS guests.
///
/// The boot loader is parameterless; a macOS guest's identity lives in its
/// [`MacPlatform`](crate::MacPlatform) (hardware model, machine identifier, and
/// auxiliary storage). Pair this with a `MacPlatform` on the VM configuration.
pub struct MacOSBootLoader {
    inner: *mut c_void,
}

// SAFETY: The inner pointer is an ObjC object handle created by the shim;
// all access goes through the shim.
unsafe impl Send for MacOSBootLoader {}

impl MacOSBootLoader {
    /// Creates a new macOS boot loader.
    ///
    /// # Errors
    ///
    /// Returns an error if `VZMacOSBootLoader` is unavailable (non-Apple-Silicon hosts
    /// or macOS versions without macOS-guest support) or cannot be created.
    pub fn new() -> VZResult<Self> {
        // SAFETY: the shim returns a +1 VZMacOSBootLoader handle, released by
        // Drop. Construction cannot fail; guest support is checked by
        // configuration validation.
        let obj = unsafe { shim_ffi::abx_bootloader_macos_new() };
        Ok(Self { inner: obj })
    }
}

impl BootLoader for MacOSBootLoader {
    fn as_ptr(&self) -> *mut c_void {
        self.inner
    }
}

impl Drop for MacOSBootLoader {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: releasing the +1 handle returned by the shim.
            unsafe { shim_ffi::abx_object_release(self.inner.cast()) };
        }
    }
}
