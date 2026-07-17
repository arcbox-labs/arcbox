//! `VirtioFS` filesystem sharing configuration.
//!
//! This module provides types for sharing directories between the host and guest
//! using `VirtioFS` (virtio-fs).
//!
//! # Example
//!
//! ```rust,no_run
//! use arcbox_vz::{SharedDirectory, SingleDirectoryShare, VirtioFileSystemDeviceConfiguration};
//!
//! # fn example() -> Result<(), arcbox_vz::VZError> {
//! // Share a single directory
//! let shared = SharedDirectory::new("/path/to/share", false)?;
//! let share = SingleDirectoryShare::new(shared)?;
//!
//! let mut fs_config = VirtioFileSystemDeviceConfiguration::new("myshare")?;
//! fs_config.set_share(share);
//! # Ok(())
//! # }
//! ```
//!
//! # Guest Mounting
//!
//! In the guest, mount the shared directory:
//!
//! ```bash
//! mount -t virtiofs myshare /mnt/shared
//! ```

use crate::error::{VZError, VZResult};
use crate::shim_ffi;
use objc2::runtime::AnyObject;
use std::ffi::CString;
use std::path::Path;
use std::ptr;

// ============================================================================
// SharedDirectory
// ============================================================================

/// A directory to be shared with the guest.
///
/// This wraps `VZSharedDirectory` and represents a host directory
/// that can be shared with the guest VM.
///
/// # Example
///
/// ```rust,no_run
/// use arcbox_vz::SharedDirectory;
///
/// # fn example() -> Result<(), arcbox_vz::VZError> {
/// // Share a directory read-write
/// let shared = SharedDirectory::new("/home/user/projects", false)?;
///
/// // Share a directory read-only
/// let shared_ro = SharedDirectory::new("/usr/share/doc", true)?;
/// # Ok(())
/// # }
/// ```
pub struct SharedDirectory {
    inner: *mut AnyObject,
}

// SAFETY: The inner pointer is an ObjC configuration object created by the
// shim; it is not mutated concurrently.
unsafe impl Send for SharedDirectory {}

impl SharedDirectory {
    /// Creates a new shared directory configuration.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the host directory to share
    /// * `read_only` - If true, the guest can only read from the directory
    ///
    /// # Errors
    ///
    /// Returns an error if the path doesn't exist or is not a directory.
    pub fn new(path: impl AsRef<Path>, read_only: bool) -> VZResult<Self> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(VZError::NotFound(path.display().to_string()));
        }
        if !path.is_dir() {
            return Err(VZError::InvalidConfiguration(format!(
                "Path is not a directory: {}",
                path.display()
            )));
        }
        let c_path = CString::new(path.to_string_lossy().as_bytes()).map_err(|_| {
            VZError::InvalidConfiguration(format!("path contains NUL: {}", path.display()))
        })?;

        // SAFETY: c_path is a valid NUL-terminated string; the shim returns a
        // +1 handle, released by Drop.
        let obj = unsafe { shim_ffi::abx_shared_directory_new(c_path.as_ptr(), read_only) };
        tracing::debug!(
            "Created SharedDirectory for {:?} (read_only={})",
            path,
            read_only
        );
        Ok(Self {
            inner: obj as *mut AnyObject,
        })
    }
}

impl Drop for SharedDirectory {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: releasing the +1 handle returned by the shim.
            unsafe { shim_ffi::abx_object_release(self.inner.cast()) };
        }
    }
}

// ============================================================================
// DirectoryShare trait
// ============================================================================

/// Trait for directory share configurations.
///
/// This trait is implemented by different share types that can be
/// attached to a `VirtioFS` device.
pub trait DirectoryShare {
    /// Returns the raw pointer to the underlying share object.
    fn as_ptr(&self) -> *mut AnyObject;
}

// ============================================================================
// SingleDirectoryShare
// ============================================================================

/// A share configuration for a single directory.
///
/// This wraps `VZSingleDirectoryShare` and provides a simple way to
/// share a single host directory with the guest.
///
/// # Example
///
/// ```rust,no_run
/// use arcbox_vz::{SharedDirectory, SingleDirectoryShare};
///
/// # fn example() -> Result<(), arcbox_vz::VZError> {
/// let shared = SharedDirectory::new("/path/to/share", false)?;
/// let share = SingleDirectoryShare::new(shared)?;
/// # Ok(())
/// # }
/// ```
pub struct SingleDirectoryShare {
    inner: *mut AnyObject,
}

// SAFETY: The inner pointer is an ObjC configuration object created by the
// shim; it is not mutated concurrently.
unsafe impl Send for SingleDirectoryShare {}

impl SingleDirectoryShare {
    /// Creates a new single directory share.
    ///
    /// # Arguments
    ///
    /// * `directory` - The shared directory to expose
    pub fn new(directory: SharedDirectory) -> VZResult<Self> {
        // SAFETY: the share retains the directory internally, so dropping
        // `directory` (releasing its +1) after this call is correct.
        let obj = unsafe { shim_ffi::abx_single_share_new(directory.inner.cast()) };
        tracing::debug!("Created SingleDirectoryShare");
        Ok(Self {
            inner: obj as *mut AnyObject,
        })
    }
}

impl DirectoryShare for SingleDirectoryShare {
    fn as_ptr(&self) -> *mut AnyObject {
        self.inner
    }
}

impl Drop for SingleDirectoryShare {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: releasing the +1 handle returned by the shim.
            unsafe { shim_ffi::abx_object_release(self.inner.cast()) };
        }
    }
}

// ============================================================================
// VirtioFileSystemDeviceConfiguration
// ============================================================================

/// Configuration for a `VirtioFS` filesystem device.
///
/// This wraps `VZVirtioFileSystemDeviceConfiguration` and provides
/// filesystem sharing between host and guest.
///
/// # Example
///
/// ```rust,no_run
/// use arcbox_vz::{SharedDirectory, SingleDirectoryShare, VirtioFileSystemDeviceConfiguration};
///
/// # fn example() -> Result<(), arcbox_vz::VZError> {
/// // Create share
/// let shared = SharedDirectory::new("/home/user/projects", false)?;
/// let share = SingleDirectoryShare::new(shared)?;
///
/// // Create filesystem device
/// let mut fs_device = VirtioFileSystemDeviceConfiguration::new("projects")?;
/// fs_device.set_share(share);
/// # Ok(())
/// # }
/// ```
///
/// # Tag Requirements
///
/// The tag must:
/// - Not be empty
/// - Only contain alphanumeric characters and underscores
/// - Be unique among all filesystem devices in the VM
pub struct VirtioFileSystemDeviceConfiguration {
    inner: *mut AnyObject,
    tag: String,
}

// SAFETY: The inner pointer is an ObjC configuration object created by the
// shim; it is not mutated concurrently.
unsafe impl Send for VirtioFileSystemDeviceConfiguration {}

impl VirtioFileSystemDeviceConfiguration {
    /// Creates a new `VirtioFS` device configuration.
    ///
    /// # Arguments
    ///
    /// * `tag` - The mount tag used to identify this share in the guest
    ///
    /// # Errors
    ///
    /// Returns an error if the tag is invalid (empty, too long, or containing
    /// invalid characters; validated by the framework).
    pub fn new(tag: &str) -> VZResult<Self> {
        if tag.is_empty() {
            return Err(VZError::InvalidConfiguration(
                "VirtioFS tag cannot be empty".into(),
            ));
        }
        let c_tag = CString::new(tag)
            .map_err(|_| VZError::InvalidConfiguration(format!("tag contains NUL: {tag}")))?;

        // SAFETY: c_tag is valid; the shim validates the tag and on failure
        // writes a strdup'd message that take_error_string frees.
        unsafe {
            let mut error: *mut std::ffi::c_char = ptr::null_mut();
            let obj = shim_ffi::abx_virtiofs_new(c_tag.as_ptr(), &mut error);
            if obj.is_null() {
                return Err(VZError::InvalidConfiguration(shim_ffi::take_error_string(
                    error,
                )));
            }
            tracing::debug!("Created VirtioFileSystemDeviceConfiguration with tag '{tag}'");
            Ok(Self {
                inner: obj as *mut AnyObject,
                tag: tag.to_string(),
            })
        }
    }

    /// Sets the directory share for this filesystem device.
    ///
    /// # Arguments
    ///
    /// * `share` - The directory share configuration
    pub fn set_share<S: DirectoryShare>(&mut self, share: S) -> &mut Self {
        // SAFETY: both handles are valid; the config retains the share, so
        // dropping `share` (releasing its +1) after this call is correct.
        unsafe {
            shim_ffi::abx_virtiofs_set_share(self.inner.cast(), share.as_ptr().cast());
        }
        tracing::debug!("Set share for VirtioFS device '{}'", self.tag);
        self
    }

    /// Returns the tag for this filesystem device.
    #[must_use]
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// Consumes the configuration and returns the raw pointer.
    #[must_use]
    pub(crate) fn into_ptr(self) -> *mut AnyObject {
        let ptr = self.inner;
        std::mem::forget(self);
        ptr
    }
}

impl Drop for VirtioFileSystemDeviceConfiguration {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: releasing the +1 handle returned by the shim.
            unsafe { shim_ffi::abx_object_release(self.inner.cast()) };
        }
    }
}

// ============================================================================
// LinuxRosettaDirectoryShare (macOS 13+)
// ============================================================================

/// Availability status for Rosetta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosettaAvailability {
    /// Rosetta is not supported on this system.
    NotSupported,
    /// Rosetta is supported and installed.
    Supported,
    /// Rosetta needs to be installed.
    NotInstalled,
}

/// A share configuration for Linux Rosetta translation.
///
/// This wraps `VZLinuxRosettaDirectoryShare` and enables `x86_64` binary
/// translation on Apple Silicon Macs.
///
/// # Availability
///
/// This is only available on:
/// - macOS 13.0 or later
/// - Apple Silicon Macs
///
/// # Example
///
/// ```rust,no_run
/// use arcbox_vz::LinuxRosettaDirectoryShare;
///
/// # fn example() -> Result<(), arcbox_vz::VZError> {
/// if LinuxRosettaDirectoryShare::availability() == arcbox_vz::RosettaAvailability::Supported {
///     let rosetta = LinuxRosettaDirectoryShare::new()?;
///     // Add to VM configuration...
/// }
/// # Ok(())
/// # }
/// ```
pub struct LinuxRosettaDirectoryShare {
    inner: *mut AnyObject,
}

// SAFETY: The inner pointer is an ObjC configuration object created by the
// shim; it is not mutated concurrently.
unsafe impl Send for LinuxRosettaDirectoryShare {}

impl LinuxRosettaDirectoryShare {
    /// Checks the availability of Rosetta on this system.
    pub fn availability() -> RosettaAvailability {
        // SAFETY: class-property read; no preconditions.
        // VZLinuxRosettaAvailability: 0 notSupported, 1 notInstalled, 2 installed.
        match unsafe { shim_ffi::abx_rosetta_availability() } {
            2 => RosettaAvailability::Supported,
            1 => RosettaAvailability::NotInstalled,
            _ => RosettaAvailability::NotSupported,
        }
    }

    /// Creates a new Linux Rosetta directory share.
    ///
    /// # Errors
    ///
    /// Returns an error if Rosetta is not available or not installed.
    pub fn new() -> VZResult<Self> {
        let avail = Self::availability();
        if avail != RosettaAvailability::Supported {
            return Err(VZError::OperationFailed(format!(
                "Rosetta is not available: {avail:?}"
            )));
        }

        // SAFETY: on failure the shim writes a strdup'd message that
        // take_error_string frees.
        unsafe {
            let mut error: *mut std::ffi::c_char = ptr::null_mut();
            let obj = shim_ffi::abx_rosetta_share_new(&mut error);
            if obj.is_null() {
                return Err(VZError::OperationFailed(shim_ffi::take_error_string(error)));
            }
            tracing::debug!("Created LinuxRosettaDirectoryShare");
            Ok(Self {
                inner: obj as *mut AnyObject,
            })
        }
    }
}

impl DirectoryShare for LinuxRosettaDirectoryShare {
    fn as_ptr(&self) -> *mut AnyObject {
        self.inner
    }
}

impl Drop for LinuxRosettaDirectoryShare {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: releasing the +1 handle returned by the shim.
            unsafe { shim_ffi::abx_object_release(self.inner.cast()) };
        }
    }
}
