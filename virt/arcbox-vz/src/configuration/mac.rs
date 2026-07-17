//! macOS guest platform sub-configurations: hardware model, machine identifier,
//! and auxiliary storage.
//!
//! These are the macOS-specific pieces assembled into a
//! [`MacPlatform`](crate::MacPlatform). A hardware model (and the minimum CPU/memory
//! requirements) is obtained from a restore image during installation; both the
//! hardware model and the machine identifier round-trip through an opaque data
//! representation so a base image can be reconstructed for every clone.

use std::ffi::{CString, c_void};
use std::path::Path;
use std::ptr;

use crate::error::{VZError, VZResult};
use crate::shim_ffi;

/// Converts a path to a `CString`, rejecting interior NUL bytes.
fn path_cstring(path: &Path) -> VZResult<CString> {
    CString::new(path.to_string_lossy().as_bytes()).map_err(|_| {
        VZError::InvalidConfiguration(format!("path contains NUL: {}", path.display()))
    })
}

/// Takes ownership of a shim-malloc'd byte buffer as a `Vec<u8>`.
///
/// # Safety
///
/// `bytes` must be null (with `len == 0`) or a shim-allocated buffer of `len`
/// bytes that has not been freed yet.
unsafe fn take_bytes(bytes: *mut c_void, len: usize) -> Vec<u8> {
    if bytes.is_null() {
        return Vec::new();
    }
    // SAFETY: per contract, `bytes` points to `len` readable bytes owned by us.
    unsafe {
        let out = std::slice::from_raw_parts(bytes as *const u8, len).to_vec();
        shim_ffi::abx_bytes_free(bytes);
        out
    }
}

/// A macOS guest hardware model.
///
/// Obtained from a restore image during installation and persisted via
/// [`data_representation`](Self::data_representation) so the same model can be
/// reconstructed for every clone of a base image.
pub struct MacHardwareModel {
    inner: *mut c_void,
}

// SAFETY: The inner pointer is an immutable ObjC identity object created by
// the shim (or retained from the framework).
unsafe impl Send for MacHardwareModel {}

impl MacHardwareModel {
    /// Reconstructs a hardware model from its opaque data representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the data is not a valid representation.
    pub fn from_data(data: &[u8]) -> VZResult<Self> {
        // SAFETY: the slice is valid for the duration of the call; the shim
        // returns null for invalid representations.
        let obj = unsafe { shim_ffi::abx_mac_hw_model_from_data(data.as_ptr().cast(), data.len()) };
        if obj.is_null() {
            return Err(VZError::InvalidConfiguration(
                "invalid macOS hardware model data representation".into(),
            ));
        }
        Ok(Self { inner: obj })
    }

    /// Returns whether this hardware model is supported by the current host.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        // SAFETY: self.inner is a valid hardware-model handle.
        unsafe { shim_ffi::abx_mac_hw_model_supported(self.inner.cast()) }
    }

    /// Returns the opaque data representation for persistence.
    #[must_use]
    pub fn data_representation(&self) -> Vec<u8> {
        // SAFETY: valid handle; the shim mallocs the buffer that take_bytes frees.
        unsafe {
            let mut len: usize = 0;
            let bytes = shim_ffi::abx_mac_hw_model_data(self.inner.cast(), &raw mut len);
            take_bytes(bytes, len)
        }
    }

    /// Wraps a +1 hardware-model handle produced by the shim (for example a
    /// restore image's requirements); the handle is released by Drop.
    pub(crate) fn from_owned_handle(handle: *mut c_void) -> Option<Self> {
        if handle.is_null() {
            return None;
        }
        Some(Self { inner: handle })
    }

    pub(crate) fn as_ptr(&self) -> *mut c_void {
        self.inner
    }
}

impl Drop for MacHardwareModel {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: releasing the +1 held by this wrapper.
            unsafe { shim_ffi::abx_object_release(self.inner.cast()) };
        }
    }
}

/// A macOS guest machine identifier.
///
/// A freshly [`new`](Self::new) identifier gives a clone its own identity; persist it
/// via [`data_representation`](Self::data_representation) and restore with
/// [`from_data`](Self::from_data) to keep a machine's identity stable across restarts.
pub struct MacMachineIdentifier {
    inner: *mut c_void,
}

// SAFETY: The inner pointer is an immutable ObjC identity object created by
// the shim.
unsafe impl Send for MacMachineIdentifier {}

impl MacMachineIdentifier {
    /// Creates a new random machine identifier.
    pub fn new() -> VZResult<Self> {
        // SAFETY: the shim returns a +1 handle, released by Drop.
        let obj = unsafe { shim_ffi::abx_mac_machine_id_new() };
        Ok(Self { inner: obj })
    }

    /// Reconstructs a machine identifier from its opaque data representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the data is not a valid representation.
    pub fn from_data(data: &[u8]) -> VZResult<Self> {
        // SAFETY: the slice is valid for the duration of the call; the shim
        // returns null for invalid representations.
        let obj =
            unsafe { shim_ffi::abx_mac_machine_id_from_data(data.as_ptr().cast(), data.len()) };
        if obj.is_null() {
            return Err(VZError::InvalidConfiguration(
                "invalid macOS machine identifier data representation".into(),
            ));
        }
        Ok(Self { inner: obj })
    }

    /// Returns the opaque data representation for persistence.
    #[must_use]
    pub fn data_representation(&self) -> Vec<u8> {
        // SAFETY: valid handle; the shim mallocs the buffer that take_bytes frees.
        unsafe {
            let mut len: usize = 0;
            let bytes = shim_ffi::abx_mac_machine_id_data(self.inner.cast(), &raw mut len);
            take_bytes(bytes, len)
        }
    }

    pub(crate) fn as_ptr(&self) -> *mut c_void {
        self.inner
    }
}

impl Drop for MacMachineIdentifier {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: releasing the +1 handle returned by the shim.
            unsafe { shim_ffi::abx_object_release(self.inner.cast()) };
        }
    }
}

/// Auxiliary storage (the NVRAM-equivalent backing file) for a macOS guest.
pub struct MacAuxiliaryStorage {
    inner: *mut c_void,
}

// SAFETY: The inner pointer is an ObjC object created by the shim; it is not
// mutated concurrently.
unsafe impl Send for MacAuxiliaryStorage {}

impl MacAuxiliaryStorage {
    /// Opens existing auxiliary storage at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is not representable; whether the file is
    /// usable is checked when the VM configuration is validated.
    pub fn open(path: impl AsRef<Path>) -> VZResult<Self> {
        let c_path = path_cstring(path.as_ref())?;
        // SAFETY: c_path is valid; the shim returns a +1 handle.
        let obj = unsafe { shim_ffi::abx_aux_storage_open(c_path.as_ptr()) };
        Ok(Self { inner: obj })
    }

    /// Creates new auxiliary storage at `path` for `hardware_model`.
    ///
    /// When `overwrite` is true an existing file at `path` is replaced.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage cannot be created.
    pub fn create(
        path: impl AsRef<Path>,
        hardware_model: &MacHardwareModel,
        overwrite: bool,
    ) -> VZResult<Self> {
        let c_path = path_cstring(path.as_ref())?;
        // SAFETY: both arguments are valid; on failure the shim writes a
        // strdup'd message that take_error_string frees.
        unsafe {
            let mut error: *mut std::ffi::c_char = ptr::null_mut();
            let obj = shim_ffi::abx_aux_storage_create(
                c_path.as_ptr(),
                hardware_model.as_ptr().cast(),
                overwrite,
                &raw mut error,
            );
            if obj.is_null() {
                return Err(VZError::OperationFailed(shim_ffi::take_error_string(error)));
            }
            Ok(Self { inner: obj })
        }
    }

    pub(crate) fn as_ptr(&self) -> *mut c_void {
        self.inner
    }
}

impl Drop for MacAuxiliaryStorage {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: releasing the +1 handle returned by the shim.
            unsafe { shim_ffi::abx_object_release(self.inner.cast()) };
        }
    }
}
