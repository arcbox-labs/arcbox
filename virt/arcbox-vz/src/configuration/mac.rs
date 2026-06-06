//! macOS guest platform sub-configurations: hardware model, machine identifier,
//! and auxiliary storage.
//!
//! These are the macOS-specific pieces assembled into a
//! [`MacPlatform`](crate::MacPlatform). A hardware model (and the minimum CPU/memory
//! requirements) is obtained from a restore image during installation; both the
//! hardware model and the machine identifier round-trip through an opaque data
//! representation so a base image can be reconstructed for every clone.

use std::ffi::c_void;
use std::path::Path;

use objc2::runtime::AnyObject;

use crate::error::{VZError, VZResult};
use crate::ffi::{
    extract_nserror, get_class, nsdata_from_bytes, nsdata_to_vec, nsurl_file_path, release, retain,
};
use crate::{msg_send, msg_send_bool};

/// A macOS guest hardware model.
///
/// Obtained from a restore image during installation and persisted via
/// [`data_representation`](Self::data_representation) so the same model can be
/// reconstructed for every clone of a base image.
pub struct MacHardwareModel {
    inner: *mut AnyObject,
}

// SAFETY: Inner ObjC pointer is only used via msg_send! which dispatches to the ObjC runtime.
unsafe impl Send for MacHardwareModel {}

impl MacHardwareModel {
    /// Reconstructs a hardware model from its opaque data representation.
    ///
    /// # Errors
    ///
    /// Returns an error if `VZMacHardwareModel` is unavailable or the data is not a
    /// valid representation.
    pub fn from_data(data: &[u8]) -> VZResult<Self> {
        // SAFETY: alloc/initWithDataRepresentation: on VZMacHardwareModel with an NSData
        // built from a valid slice. The temporary NSData is released after init.
        unsafe {
            let cls = get_class("VZMacHardwareModel").ok_or_else(|| VZError::Internal {
                code: -1,
                message: "VZMacHardwareModel class not found".into(),
            })?;
            let nsdata = nsdata_from_bytes(data);
            let alloc = msg_send!(cls, alloc);
            let obj = msg_send!(alloc, initWithDataRepresentation: nsdata);
            release(nsdata);
            if obj.is_null() {
                return Err(VZError::InvalidConfiguration(
                    "invalid macOS hardware model data representation".into(),
                ));
            }
            Ok(Self { inner: obj })
        }
    }

    /// Returns whether this hardware model is supported by the current host.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        // SAFETY: Sending isSupported to a valid VZMacHardwareModel.
        unsafe { msg_send_bool!(self.inner, isSupported).as_bool() }
    }

    /// Returns the opaque data representation for persistence.
    #[must_use]
    pub fn data_representation(&self) -> Vec<u8> {
        // SAFETY: dataRepresentation returns an NSData owned by the model; nsdata_to_vec only reads it.
        let data = unsafe { msg_send!(self.inner, dataRepresentation) };
        nsdata_to_vec(data)
    }

    /// Wraps a hardware-model pointer borrowed from the framework (for example a
    /// restore image's requirements), retaining it so it outlives its source.
    pub(crate) fn from_retained_ptr(ptr: *mut AnyObject) -> Option<Self> {
        if ptr.is_null() {
            return None;
        }
        // SAFETY: ptr is a valid VZMacHardwareModel; retain balances the release in Drop.
        Some(Self { inner: retain(ptr) })
    }

    pub(crate) fn as_ptr(&self) -> *mut AnyObject {
        self.inner
    }
}

impl Drop for MacHardwareModel {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            release(self.inner);
        }
    }
}

/// A macOS guest machine identifier.
///
/// A freshly [`new`](Self::new) identifier gives a clone its own identity; persist it
/// via [`data_representation`](Self::data_representation) and restore with
/// [`from_data`](Self::from_data) to keep a machine's identity stable across restarts.
pub struct MacMachineIdentifier {
    inner: *mut AnyObject,
}

// SAFETY: Inner ObjC pointer is only used via msg_send! which dispatches to the ObjC runtime.
unsafe impl Send for MacMachineIdentifier {}

impl MacMachineIdentifier {
    /// Creates a new random machine identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if `VZMacMachineIdentifier` is unavailable.
    pub fn new() -> VZResult<Self> {
        // SAFETY: ObjC alloc/init pattern on VZMacMachineIdentifier. Result checked non-null.
        unsafe {
            let cls = get_class("VZMacMachineIdentifier").ok_or_else(|| VZError::Internal {
                code: -1,
                message: "VZMacMachineIdentifier class not found".into(),
            })?;
            let alloc = msg_send!(cls, alloc);
            let obj = msg_send!(alloc, init);
            if obj.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to create VZMacMachineIdentifier".into(),
                });
            }
            Ok(Self { inner: obj })
        }
    }

    /// Reconstructs a machine identifier from its opaque data representation.
    ///
    /// # Errors
    ///
    /// Returns an error if `VZMacMachineIdentifier` is unavailable or the data is not
    /// a valid representation.
    pub fn from_data(data: &[u8]) -> VZResult<Self> {
        // SAFETY: alloc/initWithDataRepresentation: on VZMacMachineIdentifier with an
        // NSData built from a valid slice. The temporary NSData is released after init.
        unsafe {
            let cls = get_class("VZMacMachineIdentifier").ok_or_else(|| VZError::Internal {
                code: -1,
                message: "VZMacMachineIdentifier class not found".into(),
            })?;
            let nsdata = nsdata_from_bytes(data);
            let alloc = msg_send!(cls, alloc);
            let obj = msg_send!(alloc, initWithDataRepresentation: nsdata);
            release(nsdata);
            if obj.is_null() {
                return Err(VZError::InvalidConfiguration(
                    "invalid macOS machine identifier data representation".into(),
                ));
            }
            Ok(Self { inner: obj })
        }
    }

    /// Returns the opaque data representation for persistence.
    #[must_use]
    pub fn data_representation(&self) -> Vec<u8> {
        // SAFETY: dataRepresentation returns an NSData owned by the identifier; nsdata_to_vec only reads it.
        let data = unsafe { msg_send!(self.inner, dataRepresentation) };
        nsdata_to_vec(data)
    }

    pub(crate) fn as_ptr(&self) -> *mut AnyObject {
        self.inner
    }
}

impl Drop for MacMachineIdentifier {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            release(self.inner);
        }
    }
}

/// Auxiliary storage (the NVRAM-equivalent backing file) for a macOS guest.
pub struct MacAuxiliaryStorage {
    inner: *mut AnyObject,
}

// SAFETY: Inner ObjC pointer is only used via msg_send! which dispatches to the ObjC runtime.
unsafe impl Send for MacAuxiliaryStorage {}

impl MacAuxiliaryStorage {
    /// Opens existing auxiliary storage at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if `VZMacAuxiliaryStorage` is unavailable or the storage
    /// cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> VZResult<Self> {
        let path_str = path.as_ref().to_string_lossy();
        // SAFETY: ObjC alloc/initWithURL: pattern on VZMacAuxiliaryStorage with an NSURL
        // built from a valid path. Result checked non-null.
        unsafe {
            let cls = get_class("VZMacAuxiliaryStorage").ok_or_else(|| VZError::Internal {
                code: -1,
                message: "VZMacAuxiliaryStorage class not found".into(),
            })?;
            let url = nsurl_file_path(&path_str);
            let alloc = msg_send!(cls, alloc);
            let obj = msg_send!(alloc, initWithURL: url);
            if obj.is_null() {
                return Err(VZError::InvalidConfiguration(format!(
                    "failed to open macOS auxiliary storage: {path_str}"
                )));
            }
            Ok(Self { inner: obj })
        }
    }

    /// Creates new auxiliary storage at `path` for `hardware_model`.
    ///
    /// When `overwrite` is true an existing file at `path` is replaced.
    ///
    /// # Errors
    ///
    /// Returns an error if `VZMacAuxiliaryStorage` is unavailable or the storage
    /// cannot be created.
    pub fn create(
        path: impl AsRef<Path>,
        hardware_model: &MacHardwareModel,
        overwrite: bool,
    ) -> VZResult<Self> {
        let path_str = path.as_ref().to_string_lossy();
        // SAFETY: alloc + initCreatingStorageAtURL:hardwareModel:options:error: on
        // VZMacAuxiliaryStorage. The error out-parameter is written only on failure.
        unsafe {
            let cls = get_class("VZMacAuxiliaryStorage").ok_or_else(|| VZError::Internal {
                code: -1,
                message: "VZMacAuxiliaryStorage class not found".into(),
            })?;
            let url = nsurl_file_path(&path_str);
            let alloc = msg_send!(cls, alloc);
            // VZMacAuxiliaryStorageInitializationOptionAllowOverwrite = 1 << 0.
            let options: u64 = u64::from(overwrite);
            let mut error: *mut AnyObject = std::ptr::null_mut();
            let sel = objc2::sel!(initCreatingStorageAtURL:hardwareModel:options:error:);
            let func: unsafe extern "C" fn(
                *mut AnyObject,
                objc2::runtime::Sel,
                *const AnyObject,
                *const AnyObject,
                u64,
                *mut *mut AnyObject,
            ) -> *mut AnyObject =
                std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
            let obj = func(
                alloc,
                sel,
                url as *const AnyObject,
                hardware_model.as_ptr() as *const AnyObject,
                options,
                &mut error,
            );
            if obj.is_null() {
                return Err(extract_nserror(error));
            }
            Ok(Self { inner: obj })
        }
    }

    pub(crate) fn as_ptr(&self) -> *mut AnyObject {
        self.inner
    }
}

impl Drop for MacAuxiliaryStorage {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            release(self.inner);
        }
    }
}
