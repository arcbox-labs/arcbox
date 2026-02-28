//! VirtioFS filesystem sharing configuration.
//!
//! This module provides types for sharing directories between the host and guest
//! using VirtioFS (virtio-fs).
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
use crate::ffi::{get_class, nsstring, nsurl_file_path, release};
use crate::msg_send;
use objc2::runtime::{AnyClass, AnyObject, Bool};
use std::collections::HashMap;
use std::ffi::c_void;
use std::path::Path;

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
    /// Returns an error if:
    /// - The path doesn't exist
    /// - The path is not a directory
    /// - The VZSharedDirectory class is not available
    pub fn new(path: impl AsRef<Path>, read_only: bool) -> VZResult<Self> {
        let path = path.as_ref();

        // Validate path exists
        if !path.exists() {
            return Err(VZError::NotFound(path.display().to_string()));
        }

        // Validate it's a directory
        if !path.is_dir() {
            return Err(VZError::InvalidConfiguration(format!(
                "Path is not a directory: {}",
                path.display()
            )));
        }

        unsafe {
            let cls = get_class("VZSharedDirectory").ok_or_else(|| VZError::Internal {
                code: -1,
                message: "VZSharedDirectory class not found".into(),
            })?;

            // Create NSURL for the path
            let url = nsurl_file_path(&path.to_string_lossy());
            if url.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to create NSURL for path".into(),
                });
            }

            // [VZSharedDirectory alloc]
            let obj: *mut AnyObject = msg_send!(cls, alloc);
            if obj.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to allocate VZSharedDirectory".into(),
                });
            }

            // [obj initWithURL:url readOnly:readOnly]
            let init_sel = objc2::sel!(initWithURL:readOnly:);
            let init_fn: unsafe extern "C" fn(
                *mut AnyObject,
                objc2::runtime::Sel,
                *mut AnyObject,
                Bool,
            ) -> *mut AnyObject =
                std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
            let obj = init_fn(obj, init_sel, url, Bool::new(read_only));

            if obj.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to initialize VZSharedDirectory".into(),
                });
            }

            tracing::debug!(
                "Created SharedDirectory for {:?} (read_only={})",
                path,
                read_only
            );

            Ok(Self { inner: obj })
        }
    }

    /// Returns the raw pointer to the underlying object.
    #[allow(dead_code)]
    pub(crate) fn as_ptr(&self) -> *mut AnyObject {
        self.inner
    }

    /// Consumes the shared directory and returns the raw pointer.
    pub fn into_ptr(self) -> *mut AnyObject {
        let ptr = self.inner;
        std::mem::forget(self);
        ptr
    }
}

impl Drop for SharedDirectory {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            release(self.inner);
        }
    }
}

// ============================================================================
// DirectoryShare trait
// ============================================================================

/// Trait for directory share configurations.
///
/// This trait is implemented by different share types that can be
/// attached to a VirtioFS device.
pub trait DirectoryShare {
    /// Returns the raw pointer to the underlying share object.
    fn as_ptr(&self) -> *mut AnyObject;

    /// Consumes the share and returns the raw pointer.
    fn into_ptr(self) -> *mut AnyObject;
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

unsafe impl Send for SingleDirectoryShare {}

impl SingleDirectoryShare {
    /// Creates a new single directory share.
    ///
    /// # Arguments
    ///
    /// * `directory` - The shared directory to expose
    pub fn new(directory: SharedDirectory) -> VZResult<Self> {
        unsafe {
            let cls = get_class("VZSingleDirectoryShare").ok_or_else(|| VZError::Internal {
                code: -1,
                message: "VZSingleDirectoryShare class not found".into(),
            })?;

            // [VZSingleDirectoryShare alloc]
            let obj: *mut AnyObject = msg_send!(cls, alloc);
            if obj.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to allocate VZSingleDirectoryShare".into(),
                });
            }

            // [obj initWithDirectory:directory]
            let init_sel = objc2::sel!(initWithDirectory:);
            let init_fn: unsafe extern "C" fn(
                *mut AnyObject,
                objc2::runtime::Sel,
                *mut AnyObject,
            ) -> *mut AnyObject =
                std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
            let obj = init_fn(obj, init_sel, directory.into_ptr());

            if obj.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to initialize VZSingleDirectoryShare".into(),
                });
            }

            tracing::debug!("Created SingleDirectoryShare");

            Ok(Self { inner: obj })
        }
    }
}

impl DirectoryShare for SingleDirectoryShare {
    fn as_ptr(&self) -> *mut AnyObject {
        self.inner
    }

    fn into_ptr(self) -> *mut AnyObject {
        let ptr = self.inner;
        std::mem::forget(self);
        ptr
    }
}

impl Drop for SingleDirectoryShare {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            release(self.inner);
        }
    }
}

// ============================================================================
// MultipleDirectoryShare
// ============================================================================

/// A share configuration for multiple directories.
///
/// This wraps `VZMultipleDirectoryShare` and allows sharing multiple
/// host directories under different names.
///
/// # Example
///
/// ```rust,no_run
/// use arcbox_vz::{SharedDirectory, MultipleDirectoryShare};
///
/// # fn example() -> Result<(), arcbox_vz::VZError> {
/// let home = SharedDirectory::new("/home/user", false)?;
/// let docs = SharedDirectory::new("/usr/share/doc", true)?;
///
/// let mut share = MultipleDirectoryShare::new()?;
/// share.add("home", home);
/// share.add("docs", docs);
/// # Ok(())
/// # }
/// ```
///
/// In the guest, these would be accessible as subdirectories of the mount point.
pub struct MultipleDirectoryShare {
    inner: *mut AnyObject,
    /// Keep track of added directories (Rust ownership)
    directories: HashMap<String, *mut AnyObject>,
}

unsafe impl Send for MultipleDirectoryShare {}

impl MultipleDirectoryShare {
    /// Creates a new multiple directory share.
    pub fn new() -> VZResult<Self> {
        unsafe {
            let cls = get_class("VZMultipleDirectoryShare").ok_or_else(|| VZError::Internal {
                code: -1,
                message: "VZMultipleDirectoryShare class not found".into(),
            })?;

            let obj: *mut AnyObject = msg_send!(cls, new);
            if obj.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to create VZMultipleDirectoryShare".into(),
                });
            }

            // Retain
            let _: *mut AnyObject = msg_send!(obj, retain);

            tracing::debug!("Created MultipleDirectoryShare");

            Ok(Self {
                inner: obj,
                directories: HashMap::new(),
            })
        }
    }

    /// Adds a directory to the share.
    ///
    /// # Arguments
    ///
    /// * `name` - The name the directory will appear as in the guest
    /// * `directory` - The shared directory to add
    pub fn add(&mut self, name: &str, directory: SharedDirectory) -> &mut Self {
        unsafe {
            // Get the directories dictionary
            let dirs: *mut AnyObject = msg_send!(self.inner, directories);

            // [dirs setObject:directory forKey:name]
            let set_sel = objc2::sel!(setObject:forKey:);
            let set_fn: unsafe extern "C" fn(
                *mut AnyObject,
                objc2::runtime::Sel,
                *mut AnyObject,
                *mut AnyObject,
            ) = std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);

            let key = nsstring(name);
            let dir_ptr = directory.into_ptr();
            set_fn(dirs, set_sel, dir_ptr, key);

            self.directories.insert(name.to_string(), dir_ptr);

            tracing::debug!("Added directory '{}' to MultipleDirectoryShare", name);
        }
        self
    }

    /// Returns the number of directories in the share.
    pub fn len(&self) -> usize {
        self.directories.len()
    }

    /// Returns true if the share has no directories.
    pub fn is_empty(&self) -> bool {
        self.directories.is_empty()
    }
}

impl DirectoryShare for MultipleDirectoryShare {
    fn as_ptr(&self) -> *mut AnyObject {
        self.inner
    }

    fn into_ptr(self) -> *mut AnyObject {
        let ptr = self.inner;
        std::mem::forget(self);
        ptr
    }
}

impl Drop for MultipleDirectoryShare {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            release(self.inner);
        }
        // Note: directories are owned by the VZMultipleDirectoryShare,
        // so we don't release them separately
    }
}

// ============================================================================
// VirtioFileSystemDeviceConfiguration
// ============================================================================

/// Configuration for a VirtioFS filesystem device.
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

unsafe impl Send for VirtioFileSystemDeviceConfiguration {}

impl VirtioFileSystemDeviceConfiguration {
    /// Creates a new VirtioFS device configuration.
    ///
    /// # Arguments
    ///
    /// * `tag` - The mount tag used to identify this share in the guest
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The tag is invalid (empty or contains invalid characters)
    /// - The VZVirtioFileSystemDeviceConfiguration class is not available
    pub fn new(tag: &str) -> VZResult<Self> {
        // Validate tag is not empty
        if tag.is_empty() {
            return Err(VZError::InvalidConfiguration(
                "VirtioFS tag cannot be empty".into(),
            ));
        }

        unsafe {
            let cls = get_class("VZVirtioFileSystemDeviceConfiguration").ok_or_else(|| {
                VZError::Internal {
                    code: -1,
                    message: "VZVirtioFileSystemDeviceConfiguration class not found".into(),
                }
            })?;

            // Validate tag using [VZVirtioFileSystemDeviceConfiguration validateTag:error:]
            let tag_ns = nsstring(tag);
            let mut error: *mut AnyObject = std::ptr::null_mut();

            let validate_sel = objc2::sel!(validateTag:error:);
            let validate_fn: unsafe extern "C" fn(
                *const AnyObject,
                objc2::runtime::Sel,
                *mut AnyObject,
                *mut *mut AnyObject,
            ) -> Bool = std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);

            let valid = validate_fn(
                cls as *const AnyClass as *const AnyObject,
                validate_sel,
                tag_ns,
                &mut error,
            );

            if !valid.as_bool() {
                let error_msg = if !error.is_null() {
                    let desc: *mut AnyObject = msg_send!(error, localizedDescription);
                    crate::ffi::nsstring_to_string(desc)
                } else {
                    format!("Invalid VirtioFS tag: {}", tag)
                };
                return Err(VZError::InvalidConfiguration(error_msg));
            }

            // [VZVirtioFileSystemDeviceConfiguration alloc]
            let obj: *mut AnyObject = msg_send!(cls, alloc);
            if obj.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to allocate VZVirtioFileSystemDeviceConfiguration".into(),
                });
            }

            // [obj initWithTag:tag]
            let init_sel = objc2::sel!(initWithTag:);
            let init_fn: unsafe extern "C" fn(
                *mut AnyObject,
                objc2::runtime::Sel,
                *mut AnyObject,
            ) -> *mut AnyObject =
                std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
            let obj = init_fn(obj, init_sel, tag_ns);

            if obj.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to initialize VZVirtioFileSystemDeviceConfiguration".into(),
                });
            }

            tracing::debug!(
                "Created VirtioFileSystemDeviceConfiguration with tag '{}'",
                tag
            );

            Ok(Self {
                inner: obj,
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
        unsafe {
            let set_sel = objc2::sel!(setShare:);
            let set_fn: unsafe extern "C" fn(*mut AnyObject, objc2::runtime::Sel, *mut AnyObject) =
                std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
            set_fn(self.inner, set_sel, share.into_ptr());

            tracing::debug!("Set share for VirtioFS device '{}'", self.tag);
        }
        self
    }

    /// Returns the tag for this filesystem device.
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// Returns the raw pointer to the underlying object.
    #[allow(dead_code)]
    pub(crate) fn as_ptr(&self) -> *mut AnyObject {
        self.inner
    }

    /// Consumes the configuration and returns the raw pointer.
    pub fn into_ptr(self) -> *mut AnyObject {
        let ptr = self.inner;
        std::mem::forget(self);
        ptr
    }
}

impl Drop for VirtioFileSystemDeviceConfiguration {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            release(self.inner);
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
/// This wraps `VZLinuxRosettaDirectoryShare` and enables x86_64 binary
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

unsafe impl Send for LinuxRosettaDirectoryShare {}

impl LinuxRosettaDirectoryShare {
    /// Checks the availability of Rosetta on this system.
    pub fn availability() -> RosettaAvailability {
        unsafe {
            let cls = match get_class("VZLinuxRosettaDirectoryShare") {
                Some(c) => c,
                None => return RosettaAvailability::NotSupported,
            };

            // [VZLinuxRosettaDirectoryShare availability]
            let avail_sel = objc2::sel!(availability);
            let avail_fn: unsafe extern "C" fn(*const AnyObject, objc2::runtime::Sel) -> i64 =
                std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
            let avail = avail_fn(cls as *const AnyClass as *const AnyObject, avail_sel);

            // VZLinuxRosettaAvailability enum values:
            // 0 = VZLinuxRosettaAvailabilityNotSupported
            // 1 = VZLinuxRosettaAvailabilitySupported (installed)
            // 2 = VZLinuxRosettaAvailabilityNotInstalled
            match avail {
                0 => RosettaAvailability::NotSupported,
                1 => RosettaAvailability::Supported,
                2 => RosettaAvailability::NotInstalled,
                _ => RosettaAvailability::NotSupported,
            }
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
                "Rosetta is not available: {:?}",
                avail
            )));
        }

        unsafe {
            let cls =
                get_class("VZLinuxRosettaDirectoryShare").ok_or_else(|| VZError::Internal {
                    code: -1,
                    message: "VZLinuxRosettaDirectoryShare class not found".into(),
                })?;

            let obj: *mut AnyObject = msg_send!(cls, new);
            if obj.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to create VZLinuxRosettaDirectoryShare".into(),
                });
            }

            // Retain
            let _: *mut AnyObject = msg_send!(obj, retain);

            tracing::debug!("Created LinuxRosettaDirectoryShare");

            Ok(Self { inner: obj })
        }
    }
}

impl DirectoryShare for LinuxRosettaDirectoryShare {
    fn as_ptr(&self) -> *mut AnyObject {
        self.inner
    }

    fn into_ptr(self) -> *mut AnyObject {
        let ptr = self.inner;
        std::mem::forget(self);
        ptr
    }
}

impl Drop for LinuxRosettaDirectoryShare {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            release(self.inner);
        }
    }
}
